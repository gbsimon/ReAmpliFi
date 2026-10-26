#!/usr/bin/env python3
"""Print decompiled function(s) from the Ghidra export by name substring or address.
usage: python3 -I fn.py <name-substring|0xADDR|ADDR> [--list] [--max N]
"""
import sys, os, re, glob
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'work', 'ghidra', 'decomp')
HDR = re.compile(r'^// ADDR: ([0-9a-fA-F]+)\s+SIZE: (\d+)(?:\s+NAME: (.*))?$')
def funcs():
    for f in sorted(glob.glob(os.path.join(D, '*.c'))):
        with open(f, errors='replace') as fh:
            lines = fh.readlines()
        starts = []
        for i, l in enumerate(lines):
            m = HDR.match(l.rstrip('\n'))
            if m:
                name = m.group(3)
                if name is None and i + 1 < len(lines) and lines[i+1].startswith('// NAME:'):
                    name = lines[i+1][8:].strip()
                starts.append((i, m.group(1).lower(), int(m.group(2)), (name or '').strip()))
        for k, (i, a, s, n) in enumerate(starts):
            j = starts[k+1][0] - 1 if k + 1 < len(starts) else len(lines)
            yield os.path.basename(f), a, s, n, lines[max(0, i-1):j]
def main():
    q = sys.argv[1]; lst = '--list' in sys.argv
    mx = int(sys.argv[sys.argv.index('--max')+1]) if '--max' in sys.argv else 5
    qa = q.lower().replace('0x', '')
    isaddr = re.fullmatch(r'[0-9a-f]{6,8}', qa) is not None
    n = 0
    for f, a, s, name, body in funcs():
        hit = (a.lstrip('0') == qa.lstrip('0')) if isaddr else (q in name)
        if hit:
            n += 1
            if lst: print(f'{a}\t{s}\t{name}\t{f}')
            else: sys.stdout.write(''.join(body))
            if n >= mx and not lst: break
main()
