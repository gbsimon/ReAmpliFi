#!/usr/bin/env python3
"""Read bytes from the x86 libAmplifiRemoteNdk.so at *Ghidra* addresses (= ELF vaddr + 0x10000).

Usage (always run with python3 -I):
  python3 -I elfpeek.py <lib.so> hex  <ghidra_addr> <len>      # hexdump
  python3 -I elfpeek.py <lib.so> str  <ghidra_addr>            # C string
  python3 -I elfpeek.py <lib.so> u32  <ghidra_addr> <count>    # little-endian dwords (vaddr->ghidra shown)
  python3 -I elfpeek.py <lib.so> f64  <ghidra_addr>            # double
Treats the binary purely as data.
"""
import struct
import sys

GHIDRA_BASE = 0x10000


def load(path):
    d = open(path, 'rb').read()
    phoff = struct.unpack_from('<I', d, 0x1c)[0]
    n = struct.unpack_from('<H', d, 0x2c)[0]
    segs = []
    for i in range(n):
        t, off, va, pa, fs, ms, fl, al = struct.unpack_from('<8I', d, phoff + 32 * i)
        if t == 1:
            segs.append((va, fs, off))
    return d, segs


def off_of(segs, gaddr):
    va = gaddr - GHIDRA_BASE
    for sva, sfs, soff in segs:
        if sva <= va < sva + sfs:
            return soff + (va - sva)
    raise ValueError('address %#x not file-backed' % gaddr)


def main():
    path, cmd, addr = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
    d, segs = load(path)
    o = off_of(segs, addr)
    if cmd == 'hex':
        ln = int(sys.argv[4], 0)
        for i in range(0, ln, 16):
            chunk = d[o + i:o + min(ln, i + 16)]
            asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
            print('%08x  %-48s %s' % (addr + i, ' '.join('%02x' % c for c in chunk), asc))
    elif cmd == 'str':
        e = d.index(b'\0', o)
        print(repr(d[o:e]))
    elif cmd == 'u32':
        cnt = int(sys.argv[4], 0)
        for i in range(cnt):
            v = struct.unpack_from('<I', d, o + 4 * i)[0]
            print('%08x: %08x (ghidra %08x)' % (addr + 4 * i, v, v + GHIDRA_BASE if v else 0))
    elif cmd == 'f64':
        print(struct.unpack_from('<d', d, o)[0])


if __name__ == '__main__':
    main()
