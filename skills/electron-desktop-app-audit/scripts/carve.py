#!/usr/bin/env python3
"""Carve a byte range out of a large binary to stdout (fast, chunked).

Usage:  carve.py <src> <offset> [size] > out.bin
        carve.py App.exe 1003520 > payload.cab

Why this exists: `dd if=... bs=1 skip=...` on a 300 MB span takes minutes.
Installer containers (WiX Burn CABs) are reported by `7z l <exe>` as
"Offset = N" / "Type = Cab" with "data after the end of archive".
"""
import os
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    src = sys.argv[1]
    off = int(sys.argv[2])
    total = os.path.getsize(src)
    if off < 0 or off >= total:
        print(f"offset {off} outside file of {total} bytes", file=sys.stderr)
        return 1
    size = int(sys.argv[3]) if len(sys.argv) > 3 else total - off
    size = min(size, total - off)

    out = sys.stdout.buffer
    with open(src, "rb") as f:
        f.seek(off)
        rem = size
        while rem > 0:
            buf = f.read(min(1 << 22, rem))
            if not buf:
                break
            out.write(buf)
            rem -= len(buf)
    return 0


if __name__ == "__main__":
    sys.exit(main())
