#!/usr/bin/env python3
# DuetOS TGA fuzz seed generator.
#
# WHAT  Emits valid uncompressed type-2 TGA images (24- and
#       32-bpp, top-down and bottom-up) so fuzz_tga clears the
#       duetos_img_meta 18-byte header validator and mutation
#       reaches TgaParseHeader + TgaDecodeUncompressed's pixel
#       copy / row-flip.
#
# WHY   Random input never forms a valid type-2 18-byte header
#       with sane dims, so the decoder body is never reached
#       (observed: cov 6).
#
# USAGE  python3 gen_tga_seeds.py <out_dir>

import os
import struct
import sys


def tga(width: int, height: int, bpp: int, top_down: bool) -> bytes:
    # id_len, colormap_type, image_type=2, cmap(5), x, y, w, h,
    # pixel_depth, image_descriptor (bit5 = top-down).
    desc = 0x20 if top_down else 0x00
    hdr = struct.pack(
        "<BBBHHBHHHHBB",
        0, 0, 2, 0, 0, 0, 0, 0, width, height, bpp, desc,
    )
    px = (b"\x10\x20\x30\xff" if bpp == 32 else b"\x10\x20\x30")
    return hdr + px * width * height


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/tga"
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "td_32_4x4.tga"), "wb").write(tga(4, 4, 32, True))
    open(os.path.join(out, "bu_24_8x2.tga"), "wb").write(tga(8, 2, 24, False))
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
