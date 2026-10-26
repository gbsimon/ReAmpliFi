#!/usr/bin/env python3
"""AMPLIFi wire-protocol checksum + framing reference (static RE of libAmplifiRemoteNdk.so x86).

Run with:  python3 -I crc16.py [--lib path/to/libAmplifiRemoteNdk.so] [--symtab path/to/defaultSymbolTable.bin]

What it does
  1. CRC16_Process (Ghidra 0x113b10) re-implemented bit-exactly and identified against
     the CRC catalogue (it is CRC-16/CCITT-FALSE a.k.a. CRC-16/IBM-3740: poly 0x1021,
     init 0xFFFF (set by every caller), refin=False, refout=False, xorout=0x0000).
  2. CRC32_bs (Ghidra 0xd177c) table dumped from the binary (Ghidra 0x1cd3a0, 256 x u32 LE)
     and compared with the standard reflected CRC-32 table (zlib / CRC-32/ISO-HDLC).
  3. Builders/parsers for the RobustSerialMsgChannel (RSMC) frame and the McBsp message
     transport / stream headers, plus the example frames documented in
     analysis/notes/native_transport.md (used as unit-test vectors).

No firmware-update functionality is implemented or described here (by design).
Binary content is treated as data only.
"""
import struct
import sys
import zlib

GHIDRA_BASE = 0x10000  # Ghidra address = ELF vaddr + 0x10000


# --------------------------------------------------------------------------- CRC16
def crc16_process(crc, data):
    """Bit-exact port of CRC16_Process(ushort *crc, byte *p, int n) @ 0x113b10."""
    for b in data:
        x = (b ^ (crc >> 8)) & 0xFF
        x ^= x >> 4
        crc = ((crc << 8) ^ (x << 12) ^ (x << 5) ^ x) & 0xFFFF
    return crc


def crc16_generic(data, poly, init, refin, refout, xorout):
    def refl(v, w):
        return int('{:0{w}b}'.format(v, w=w)[::-1], 2)
    crc = init
    for b in data:
        if refin:
            b = refl(b, 8)
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    if refout:
        crc = refl(crc, 16)
    return crc ^ xorout


CATALOGUE = {
    # name: (poly, init, refin, refout, xorout, check("123456789"))
    'CRC-16/CCITT-FALSE (IBM-3740)': (0x1021, 0xFFFF, False, False, 0x0000, 0x29B1),
    'CRC-16/XMODEM': (0x1021, 0x0000, False, False, 0x0000, 0x31C3),
    'CRC-16/KERMIT': (0x1021, 0x0000, True, True, 0x0000, 0x2189),
    'CRC-16/AUG-CCITT (SPI-FUJITSU)': (0x1021, 0x1D0F, False, False, 0x0000, 0xE5CC),
    'CRC-16/GENIBUS': (0x1021, 0xFFFF, False, False, 0xFFFF, 0xD64E),
    'CRC-16/X-25': (0x1021, 0xFFFF, True, True, 0xFFFF, 0x906E),
    'CRC-16/MCRF4XX': (0x1021, 0xFFFF, True, True, 0x0000, 0x6F91),
    'CRC-16/MODBUS': (0x8005, 0xFFFF, True, True, 0x0000, 0x4B37),
    'CRC-16/ARC': (0x8005, 0x0000, True, True, 0x0000, 0xBB3D),
}


def identify_crc16():
    check = b'123456789'
    ours = crc16_process(0xFFFF, check)
    hits = []
    for name, (poly, init, ri, ro, xo, chk) in CATALOGUE.items():
        g = crc16_generic(check, poly, init, ri, ro, xo)
        assert g == chk, (name, hex(g))
        if g == ours:
            hits.append(name)
    # also confirm equality on random-ish data, not only the check string
    blob = bytes((i * 37 + 11) & 0xFF for i in range(300))
    assert crc16_process(0xFFFF, blob) == crc16_generic(blob, 0x1021, 0xFFFF, False, False, 0)
    return ours, hits


# --------------------------------------------------------------------------- CRC32
def _elf_segments(d):
    phoff = struct.unpack_from('<I', d, 0x1c)[0]
    n = struct.unpack_from('<H', d, 0x2c)[0]
    segs = []
    for i in range(n):
        t, off, va, pa, fs, ms, fl, al = struct.unpack_from('<8I', d, phoff + 32 * i)
        if t == 1:
            segs.append((va, fs, off))
    return segs


def read_ghidra(d, gaddr, n):
    va = gaddr - GHIDRA_BASE
    for sva, sfs, soff in _elf_segments(d):
        if sva <= va and va + n <= sva + sfs:
            return d[soff + va - sva: soff + va - sva + n]
    raise ValueError(hex(gaddr))


def std_crc32_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        t.append(c)
    return t


def crc32_bs(data, table=None):
    """Port of CRC32_bs(void*, unsigned) @ 0xd177c (table @ 0x1cd3a0)."""
    table = table or std_crc32_table()
    c = 0xFFFFFFFF
    for b in data:
        c = table[(b ^ c) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def l6crc32_calc(data, poly=0x04C11DB7):
    """Port of L6CRC32::calc(data, len, poly) @ 0xbf9fc: table built from `poly` with
    reflect(); init 0xFFFFFFFF, reflected update, final ~. With poly 0x04C11DB7 (the only
    value passed by its 4 callers, all in L6EdLibDIFRead/Write = tone-file container) this is
    plain CRC-32 (zlib)."""
    def refl(v, w):
        r = 0
        for i in range(1, w + 1):
            if v & 1:
                r |= 1 << (w - i)
            v >>= 1
        return r
    tab = []
    for i in range(256):
        v = refl(i, 8) << 24
        for _ in range(8):
            v = ((v << 1) ^ poly) & 0xFFFFFFFF if v & 0x80000000 else (v << 1) & 0xFFFFFFFF
        tab.append(refl(v, 32))
    c = 0xFFFFFFFF
    for b in data:
        c = tab[(c ^ b) & 0xFF] ^ (c >> 8)
    return (~c) & 0xFFFFFFFF


# --------------------------------------------------------------------------- RSMC frame
SYNC = b'\x55\x55'
RSMC_HDR_LEN = 12


def rsmc_frame(seq, ack, rx_limit, payload=b'', reserved=0):
    """Build a RobustSerialMsgChannel frame (ExecTasks @ 0x112950).

    hdr[0:2]  55 55          sync word
    hdr[2]    reserved       always 0 on TX, ignored on RX
    hdr[3]    seq            tx sequence of this packet (8-bit, first data packet = 1;
                             header-only frames carry the last sent seq)
    hdr[4]    ack            last in-order sequence delivered from the peer (cumulative)
    hdr[5]    rx_limit       highest peer seq we will accept (flow-control credit;
                             starts at rx window = 8, +1 per consumed packet)
    hdr[6:8]  len   u16 LE   payload length (sum of 4-byte-aligned messages); 0 = ack-only
    hdr[8:10] pcrc  u16 LE   CRC-16/CCITT-FALSE over payload; 0x0000 when len == 0
    hdr[10:12]hcrc  u16 LE   CRC-16/CCITT-FALSE over the 12 header bytes with hcrc = 0
    """
    assert len(payload) % 4 == 0, 'RSMC payload is a concatenation of 4-byte aligned messages'
    pcrc = crc16_process(0xFFFF, payload) if payload else 0
    hdr = bytearray(SYNC + bytes([reserved, seq & 0xFF, ack & 0xFF, rx_limit & 0xFF]) +
                    struct.pack('<HHH', len(payload), pcrc, 0))
    struct.pack_into('<H', hdr, 10, crc16_process(0xFFFF, bytes(hdr)))
    return bytes(hdr) + payload


def rsmc_parse(buf):
    """Minimal parser mirroring HandleRxData @ 0x112440. Yields dicts; raises on CRC error."""
    i = 0
    while True:
        j = buf.find(SYNC, i)
        if j < 0 or j + RSMC_HDR_LEN > len(buf):
            return
        hdr = bytearray(buf[j:j + RSMC_HDR_LEN])
        hcrc = struct.unpack_from('<H', hdr, 10)[0]
        struct.pack_into('<H', hdr, 10, 0)
        if crc16_process(0xFFFF, bytes(hdr)) != hcrc:
            i = j + 1  # NOTE: the native code instead discards the 12 bytes and re-hunts
            continue
        ln, pcrc = struct.unpack_from('<HH', hdr, 6)
        payload = bytes(buf[j + 12:j + 12 + ln])
        if ln and crc16_process(0xFFFF, payload) != pcrc:
            raise ValueError('payload CRC mismatch')
        yield dict(reserved=hdr[2], seq=hdr[3], ack=hdr[4], rx_limit=hdr[5], payload=payload)
        i = j + 12 + ln


# --------------------------------------------------------------------------- McBsp message
MSG_VERSION = 2          # bits 26-27 of word0, always 2 (MsgPort_PrepareTransportHeader)
MT_PLAIN = 1             # transport type 1: no option word (data segments, datagrams)
MT_OPTION = 2            # transport type 2: +4-byte option word (stream SYN carries MSS)

# stream segment flags (byte 3 of stream word A)
F_SYN, F_FIN, F_DATA, F_WND, F_HEARTBEAT, F_HB_ENABLE = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def transport_header(mtype, length_after_header, src, dst):
    """MsgTransportHeader_Pack @ 0x1122b0: word0 = type<<28 | ver<<26 | len16; word1 = src | dst<<16."""
    w0 = (mtype & 0xF) << 28 | (MSG_VERSION & 3) << 26 | (length_after_header & 0xFFFF)
    w1 = (src & 0xFFFF) | (dst & 0xFFFF) << 16
    return struct.pack('<II', w0, w1)


def stream_segment(src, dst, seq, flags, window_edge, data=b'', mss=None):
    """Stream segment as built by the stream TX task @ 0x110880.
    SYN segments use transport type 2 with option word (mss << 16 | hopcount 0)."""
    body = struct.pack('<II', (flags & 0xFF) << 24 | (seq & 0xFF) << 8, window_edge & 0xFFFFFFFF) + data
    if mss is not None:
        body = struct.pack('<I', (mss & 0xFFFF) << 16) + body
        msg = transport_header(MT_OPTION, len(body), src, dst) + body
    else:
        msg = transport_header(MT_PLAIN, len(body), src, dst) + body
    return msg + b'\x00' * ((-len(msg)) % 4)  # 4-byte alignment inside the RSMC payload


def service_cmd(cmd_id, payload=b''):
    """ToneMatchEdit_Remote / ToneMatchLibrarian_Remote::DoCommandCommon: u32 cmd, u32 len, payload."""
    return struct.pack('<II', cmd_id, len(payload)) + payload


# Addresses (CONFIRMED in connectWithObjHelper / L6BspMsgPort::open / AmplifiRemoteManager::Initialize)
PHONE_NODE = 0x2000
EDITOR_LOCAL, EDITOR_REMOTE = 0x2002, 0x03ED
LIBRARIAN_LOCAL, LIBRARIAN_REMOTE = 0x2003, 0x03EF


def hexs(b):
    return ' '.join('%02X' % x for x in b)


def main(argv):
    lib = symtab = None
    if '--lib' in argv:
        lib = argv[argv.index('--lib') + 1]
    if '--symtab' in argv:
        symtab = argv[argv.index('--symtab') + 1]

    ours, hits = identify_crc16()
    print('CRC16_Process(init=0xFFFF, "123456789") = 0x%04X -> matches: %s' % (ours, ', '.join(hits)))
    assert hits == ['CRC-16/CCITT-FALSE (IBM-3740)']

    if lib:
        d = open(lib, 'rb').read()
        raw = read_ghidra(d, 0x1cd3a0, 1024)
        tab = list(struct.unpack('<256I', raw))
        same = tab == std_crc32_table()
        print('CRC32_bs table @0x1cd3a0: first words %s ... equals standard reflected 0xEDB88320 table: %s'
              % (' '.join('%08X' % v for v in tab[:4]), same))
        assert same
        # sanity: the CRC16 routine has no table; show its bytes for the record
        print('CRC16_Process bytes @0x113b10:', hexs(read_ghidra(d, 0x113b10, 79)))
    assert crc32_bs(b'123456789') == 0xCBF43926 == zlib.crc32(b'123456789')
    assert l6crc32_calc(b'123456789') == 0xCBF43926

    print('\n# Example vectors')
    for s in (b'IAP x OK', b'IAP x START', b'IAP x STOP'):
        print('raw ASCII %-12r: %s' % (s.decode(), hexs(s)))
    ack0 = rsmc_frame(seq=0, ack=0, rx_limit=8)
    print('RSMC ack-only (fresh channel)  :', hexs(ack0))
    syn = stream_segment(LIBRARIAN_LOCAL, LIBRARIAN_REMOTE, seq=1, flags=F_SYN | F_HB_ENABLE,
                         window_edge=0x1000, mss=0xF0 - 12)  # device-info phase: MTU 240 (ctor)
    print('stream SYN 0x2003->0x03EF      :', hexs(syn))
    print('  in RSMC frame seq1/ack0/lim8 :', hexs(rsmc_frame(1, 0, 8, syn)))
    syn_ed = stream_segment(EDITOR_LOCAL, EDITOR_REMOTE, seq=1, flags=F_SYN | F_HB_ENABLE,
                            window_edge=0x1000, mss=0xF0 - 12)  # fw >= 2.10.1: MTU 240 (else 256)
    print('stream SYN 0x2002->0x03ED      :', hexs(syn_ed))
    print('service-mode word DEVICE_INFO  :', hexs(struct.pack('<I', 2)))
    print('service-mode word LIBRARIAN    :', hexs(struct.pack('<I', 1)))
    print('Editor GetVersion (cmd 1)      :', hexs(service_cmd(1)))
    if symtab:
        t = open(symtab, 'rb').read()
        c = crc32_bs(t)
        print('CRC32_bs(%s) = 0x%08X' % (symtab.split('/')[-1], c))
        print('Editor Handshake (cmd 4)       :', hexs(service_cmd(4, struct.pack('<I', c))))
    # round-trip check of the parser
    frames = list(rsmc_parse(b'\x00\x55' + ack0 + rsmc_frame(1, 0, 8, syn)))
    assert len(frames) == 2 and frames[1]['payload'] == syn
    print('\nself-test OK')


if __name__ == '__main__':
    main(sys.argv[1:])
