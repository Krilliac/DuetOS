#!/usr/bin/env python3
# DuetOS ZIP fuzz seed generator.
#
# WHAT  Emits a real ZIP archive (one Stored entry + one Deflate
#       entry, plus a directory entry) via stdlib zipfile, so
#       fuzz_zip starts from a valid EOCD + central directory and
#       mutation exercises the local-header chase, the
#       stored/deflate extraction, and the directory-name path —
#       not just the EOCD scan.
#
# WHY   A correct EOCD record + central-directory chain is hard
#       to reach by raw mutation; a seed lets the inflate and
#       local-header-chase paths get real coverage.
#
# USAGE  python3 gen_zip_seeds.py <out_dir>

import io
import os
import sys
import zipfile


def archive() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("hi.txt", b"hello\n", compress_type=zipfile.ZIP_STORED)
        z.writestr("data/blob.bin", b"DEFLATE-ME-" * 64,
                    compress_type=zipfile.ZIP_DEFLATED)
        zi = zipfile.ZipInfo("data/")  # explicit directory entry
        z.writestr(zi, b"")
    return buf.getvalue()


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/zip"
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "mixed.zip"), "wb").write(archive())
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
