#!/usr/bin/env python3
# DuetOS BMP fuzz seed generator.
#
# WHAT  Emits a structurally-valid 32-bpp BI_RGB BMP (14-byte
#       BITMAPFILEHEADER + 40-byte BITMAPINFOHEADER + a few
#       pixels), top-down and bottom-up, so fuzz_bmp gets past
#       the duetos_img_meta header validator (signature + DIB
#       size + dimension cap) and mutation actually reaches the
#       C++ BmpParseHeader field decode.
#
# WHY   Random bytes essentially never form "BM" + a DIB header
#       >= 40 with sane dimensions, so without a seed every input
#       fails info.ok and the parser body is never exercised
#       (observed: cov 5).
#
# USAGE  python3 gen_bmp_seeds.py <out_dir>

import os
import struct
import sys


def bmp(width: int, height_field: int) -> bytes:
    rows = abs(height_field)
    pixels = b"\x10\x20\x30\xff" * width * rows
    dib = struct.pack(
        "<IiiHHIIiiII",
        40,             # biSize
        width,          # biWidth
        height_field,   # biHeight (negative => top-down)
        1,              # biPlanes
        32,             # biBitCount
        0,              # biCompression = BI_RGB
        len(pixels),    # biSizeImage
        2835, 2835,     # ppm
        0, 0,           # palette
    )
    pixel_offset = 14 + len(dib)
    fh = b"BM" + struct.pack("<IHHI", pixel_offset + len(pixels), 0, 0, pixel_offset)
    return fh + dib + pixels


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/bmp"
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "topdown_4x4.bmp"), "wb").write(bmp(4, -4))
    open(os.path.join(out, "bottomup_8x2.bmp"), "wb").write(bmp(8, 2))
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
