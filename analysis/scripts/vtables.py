#!/usr/bin/env python3
"""Dump C++ vtables (_ZTV*) of the 32-bit x86 ELF .so, resolving REL relocations.
Addresses printed in GHIDRA space (= file vaddr + 0x10000).
usage: python3 -I vtables.py <lib.so> [ClassSubstring] """
import sys, struct, subprocess
GH = 0x10000
def main():
    p = sys.argv[1]; flt = sys.argv[2] if len(sys.argv) > 2 else ''
    d = open(p, 'rb').read()
    e_shoff, = struct.unpack_from('<I', d, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', d, 0x2e)
    secs = []
    for i in range(e_shnum):
        secs.append(struct.unpack_from('<IIIIIIIIII', d, e_shoff + i*e_shentsize))
    def sec_by_type(t): return [s for s in secs if s[1] == t]
    # dynsym
    dynsym = sec_by_type(11)[0]; dynstr = secs[dynsym[6]]
    def cstr(off):
        e = d.index(b'\0', off); return d[off:e].decode('latin1')
    syms = []
    for i in range(dynsym[5] // 16):
        nm, val, sz, info, oth, shn = struct.unpack_from('<IIIBBH', d, dynsym[4] + i*16)
        syms.append((cstr(dynstr[4] + nm), val, sz))
    # relocs (SHT_REL = 9)
    rel = {}
    for s in sec_by_type(9):
        for i in range(s[5] // 8):
            off, info = struct.unpack_from('<II', d, s[4] + i*8)
            rel[off] = (info & 0xff, info >> 8)
    # vaddr -> file offset via sections
    def v2o(v):
        for s in secs:
            if s[1] != 8 and s[3] <= v < s[3] + s[5]: return v - s[3] + s[4]
        return None
    name_of = {}
    for n, v, sz in syms:
        if v and n.startswith('_Z') and not n.startswith('_ZTV'): name_of.setdefault(v, n)
    demangle_in = []
    for n, v, sz in syms:
        if not n.startswith('_ZTV') or not v: continue
        dn = subprocess.run(['c++filt', n], capture_output=True, text=True).stdout.strip()
        if flt and flt not in dn: continue
        print(f'== {dn}  @{v+GH:08x} size {sz}')
        for k in range(0, sz, 4):
            a = v + k; o = v2o(a)
            raw = struct.unpack_from('<I', d, o)[0] if o is not None else 0
            r = rel.get(a); tgt = raw; how = 'raw'
            if r:
                typ, si = r
                if typ == 8: tgt = raw; how = 'REL'
                elif typ in (1, 6): tgt = syms[si][1] + (raw if typ == 1 else 0); how = 'SYM:' + syms[si][0]
            fn = name_of.get(tgt, '')
            if fn: fn = subprocess.run(['c++filt', fn], capture_output=True, text=True).stdout.strip()
            print(f'  vp+0x{k-8:03x} [{k//4-2:3d}] {tgt+GH if tgt else 0:08x} {how[:40]:40s} {fn}')
main()
