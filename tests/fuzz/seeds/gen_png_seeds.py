#!/usr/bin/env python3
# DuetOS PNG fuzz seed generator.
#
# WHAT  Emits real 8-bit RGB and RGBA PNGs (signature + IHDR with
#       correct CRC + a single zlib-wrapped IDAT + IEND) so
#       fuzz_png clears the duetos_img_meta IHDR validator and
#       mutation reaches the C++ chunk walk, ZlibInflate, and the
#       per-scanline filter unwind.
#
# WHY   A valid 8-byte signature + an IHDR whose CRC32 matches is
#       unreachable by random mutation, so the decoder (and the
#       linked gzip/deflate/crc32/adler32) is never exercised
#       (observed: cov 6). zlib.compress emits the zlib-wrapped
#       DEFLATE the PNG IDAT requires.
#
# USAGE  python3 gen_png_seeds.py <out_dir>

import os
import struct
import sys
import zlib


def chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def png(width: int, height: int, rgba: bool) -> bytes:
    color_type = 6 if rgba else 2
    bpp = 4 if rgba else 3
    raw = b""
    for _ in range(height):
        raw += b"\x00" + (b"\x11\x22\x33\x44"[:bpp]) * width  # filter 0 + pixels
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 6))
            + chunk(b"IEND", b""))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/png"
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "rgb_4x4.png"), "wb").write(png(4, 4, False))
    open(os.path.join(out, "rgba_3x2.png"), "wb").write(png(3, 2, True))
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
