#!/usr/bin/env python3
"""Extract an Electron app.asar archive losslessly.

Usage:  extract_asar.py <app.asar> <outdir>

asar layout:
    uint32 = 4
    uint32 = header_pickle_size        content_base = 8 + header_pickle_size
    uint32 = json_size_padded
    uint32 = json_length               JSON index starts at byte 16

Entries with "unpacked": true are NOT in the blob — they live in the sibling
`app.asar.unpacked/` directory shipped next to the archive, so they are skipped
here (copy that directory separately if you need the native addons).
"""
import json
import os
import struct
import sys


def walk(node, path=""):
    for name, v in node.get("files", {}).items():
        p = path + "/" + name
        if "files" in v:
            yield from walk(v, p)
        else:
            yield p, v


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    src, outdir = sys.argv[1], sys.argv[2]

    with open(src, "rb") as raw:
        head = raw.read(16)
        if len(head) < 16:
            print("file too small to be an asar", file=sys.stderr)
            return 1
        first, header_pickle, _json_padded, json_len = struct.unpack("<IIII", head)
        if first != 4:
            print(f"unexpected first uint32={first}; not an asar archive", file=sys.stderr)
            return 1
        raw.seek(16)
        index = json.loads(raw.read(json_len).decode("utf-8", "ignore"))

        content_base = 8 + header_pickle
        written = skipped = 0
        for p, v in walk(index):
            if v.get("unpacked"):
                skipped += 1
                continue
            off = int(v.get("offset", 0))
            size = int(v.get("size", 0))
            dst = os.path.join(outdir, p.lstrip("/"))
            os.makedirs(os.path.dirname(dst) or outdir, exist_ok=True)
            raw.seek(content_base + off)
            with open(dst, "wb") as fh:
                fh.write(raw.read(size))
            written += 1

    print(f"extracted {written} files ({skipped} unpacked skipped) -> {outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
