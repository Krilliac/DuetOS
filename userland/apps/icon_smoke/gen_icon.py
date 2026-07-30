#!/usr/bin/env python3
"""Generate a minimal 16x16 32bpp .ico file for the icon_smoke fixture.

The icon is a solid blue 16x16 square with full opacity — enough to
prove the RT_GROUP_ICON -> RT_ICON decode path returns valid BGRA
pixels. Art quality is not the goal.

Usage: python3 gen_icon.py <output.ico>
"""
import struct, sys

W, H = 16, 16
BPP = 32

# BITMAPINFOHEADER (40 bytes).  biHeight = H*2 (XOR + AND planes).
bih = struct.pack('<IiiHHIIiiII',
                  40,          # biSize
                  W,           # biWidth
                  H * 2,       # biHeight (XOR + AND)
                  1,           # biPlanes
                  BPP,         # biBitCount
                  0,           # biCompression (BI_RGB)
                  0,           # biSizeImage (0 for BI_RGB)
                  0, 0,        # biXPelsPerMeter, biYPelsPerMeter
                  0,           # biClrUsed
                  0)           # biClrImportant

# XOR bitmap: 16x16 BGRA, solid blue (B=0xFF, G=0x00, R=0x00, A=0xFF).
xor_data = b'\xFF\x00\x00\xFF' * (W * H)

# AND mask: 16x16 1bpp, all zeros (fully opaque).  Stride = 4 bytes
# (DWORD-aligned: ceil(16/32)*4 = 4).
and_stride = ((W + 31) // 32) * 4
and_data = b'\x00' * (and_stride * H)

image_data = bih + xor_data + and_data
image_size = len(image_data)

# ICO header (6 bytes) + 1 entry (16 bytes) + image data.
ico_header = struct.pack('<HHH', 0, 1, 1)  # reserved, type=icon, count=1
entry = struct.pack('<BBBBHHII',
                    W & 0xFF,   # bWidth (0 means 256)
                    H & 0xFF,   # bHeight
                    0,          # bColorCount (0 for >= 8bpp)
                    0,          # bReserved
                    1,          # wPlanes
                    BPP,        # wBitCount
                    image_size, # dwBytesInRes
                    6 + 16)     # dwImageOffset (after header + 1 entry)

with open(sys.argv[1], 'wb') as f:
    f.write(ico_header + entry + image_data)
