#!/usr/bin/env python3
"""Read memory of the x86 .so in GHIDRA address space (vaddr+0x10000), applying REL relocations.
usage: python3 -I elfmem.py <lib.so> table <ghidra_addr_hex> <stride_words> <count> [fmt]
         fmt per word: s=string ptr, x=hex word, d=int, f=float  (e.g. 'ssx')
       python3 -I elfmem.py <lib.so> hex <ghidra_addr_hex> <len>
       python3 -I elfmem.py <lib.so> str <ghidra_addr_hex>
"""
import sys, struct
GH = 0x10000
class Elf:
    def __init__(s, p):
        d = s.d = open(p, 'rb').read()
        shoff, = struct.unpack_from('<I', d, 0x20)
        shes, shn, _ = struct.unpack_from('<HHH', d, 0x2e)
        s.secs = [struct.unpack_from('<IIIIIIIIII', d, shoff + i*shes) for i in range(shn)]
        dyn = [x for x in s.secs if x[1] == 11][0]; dstr = s.secs[dyn[6]]
        s.syms = []
        for i in range(dyn[5] // 16):
            nm, val, sz, info, oth, sh = struct.unpack_from('<IIIBBH', d, dyn[4] + i*16)
            e = d.index(b'\0', dstr[4] + nm); s.syms.append((d[dstr[4]+nm:e].decode('latin1'), val))
        s.rel = {}
        for x in s.secs:
            if x[1] == 9:
                for i in range(x[5] // 8):
                    off, info = struct.unpack_from('<II', d, x[4] + i*8); s.rel[off] = (info & 0xff, info >> 8)
    def off(s, v):
        for x in s.secs:
            if x[1] != 8 and x[3] and x[3] <= v < x[3] + x[5]: return v - x[3] + x[4]
        return None
    def word(s, g):
        v = g - GH; o = s.off(v)
        raw = struct.unpack_from('<I', s.d, o)[0] if o is not None else 0
        r = s.rel.get(v)
        if r and r[0] in (1, 6): raw = s.syms[r[1]][1] + (raw if r[0] == 1 else 0)
        return raw + GH if (r and raw) else raw
    def cstr(s, g, n=200):
        o = s.off(g - GH)
        if o is None: return None
        e = s.d.find(b'\0', o, o + n)
        return s.d[o:e].decode('latin1') if e >= 0 else None
    def raw(s, g, n):
        o = s.off(g - GH); return s.d[o:o+n]
def main():
    e = Elf(sys.argv[1]); cmd = sys.argv[2]; a = int(sys.argv[3], 16)
    if cmd == 'hex':
        b = e.raw(a, int(sys.argv[4], 0))
        for i in range(0, len(b), 16): print(f'{a+i:08x}  ' + b[i:i+16].hex(' '))
    elif cmd == 'str': print(e.cstr(a))
    elif cmd == 'table':
        st = int(sys.argv[4]); n = int(sys.argv[5]); fmt = sys.argv[6] if len(sys.argv) > 6 else 'x'*st
        for i in range(n):
            row = []
            for j in range(st):
                w = e.word(a + 4*(i*st + j)); f = fmt[j] if j < len(fmt) else 'x'
                if f == 's': row.append(repr(e.cstr(w)) if w else 'NULL')
                elif f == 'd': row.append(str(struct.unpack('<i', struct.pack('<I', w & 0xffffffff))[0]))
                elif f == 'f': row.append(str(struct.unpack('<f', struct.pack('<I', w & 0xffffffff))[0]))
                else: row.append(f'{w:#x}')
            print(f'[{i:3d}] @{a+4*i*st:08x} ' + ' | '.join(row))
if __name__ == '__main__': main()
