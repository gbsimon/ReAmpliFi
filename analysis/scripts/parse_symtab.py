#!/usr/bin/env python3
"""Parse a Line 6 AMPLIFi defaultSymbolTable*.bin (static analysis helper).

Usage: python3 -I parse_symtab.py <file.bin> [--dump] [--hashcheck]

Observed layout (little-endian):
  u32 count
  u32 total_file_size
  count x { u32 str_offset (relative to string blob), u32 hash, u32 str_len }
  string blob: NUL-terminated ASCII strings
"""
import struct
import sys
import zlib


def parse(path):
    data = open(path, "rb").read()
    count, size = struct.unpack_from("<II", data, 0)
    entries = []
    blob_start = 8 + count * 12
    for i in range(count):
        off, h, ln = struct.unpack_from("<III", data, 8 + i * 12)
        s = data[blob_start + off: blob_start + off + ln]
        term = data[blob_start + off + ln: blob_start + off + ln + 1]
        entries.append((i, off, h, ln, s.decode("latin-1"), term == b"\x00"))
    return data, count, size, blob_start, entries


def candidates(s):
    b = s.encode("latin-1")
    out = {}
    out["crc32"] = zlib.crc32(b) & 0xFFFFFFFF
    h = 0x811C9DC5
    for c in b:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    out["fnv1a"] = h
    h = 0x811C9DC5
    for c in b:
        h = ((h * 0x01000193) & 0xFFFFFFFF) ^ c
    out["fnv1"] = h
    h = 5381
    for c in b:
        h = ((h * 33) + c) & 0xFFFFFFFF
    out["djb2"] = h
    h = 5381
    for c in b:
        h = ((h * 33) ^ c) & 0xFFFFFFFF
    out["djb2x"] = h
    h = 0
    for c in b:
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    out["sdbm"] = h
    h = 0
    for c in b:
        h = (h * 31 + c) & 0xFFFFFFFF
    out["java31"] = h
    return out


def main():
    path = sys.argv[1]
    data, count, size, blob_start, entries = parse(path)
    print(f"file={path} len={len(data)} count={count} size_field={size} blob_start=0x{blob_start:x}")
    ok = all(e[5] for e in entries)
    print(f"all strings NUL-terminated at declared length: {ok}")
    sorted_by_hash = all(entries[i][2] <= entries[i + 1][2] for i in range(len(entries) - 1))
    print(f"entries sorted by hash: {sorted_by_hash}")
    if "--hashcheck" in sys.argv:
        hits = {}
        for e in entries:
            for k, v in candidates(e[4]).items():
                if v == e[2]:
                    hits[k] = hits.get(k, 0) + 1
        print("hash algorithm matches:", hits or "none of the tested ones")
    if "--dump" in sys.argv:
        for e in entries:
            print(f"{e[0]:4d} off=0x{e[1]:04x} hash=0x{e[2]:08x} len={e[3]:3d} {e[4]!r}")


if __name__ == "__main__":
    main()
