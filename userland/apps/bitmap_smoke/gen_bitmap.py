#!/usr/bin/env python3
"""Generate a minimal 8x8 24bpp .bmp file for the bitmap_smoke fixture.

The bitmap is solid green except the top-left image pixel, which is
pure red — a marker that survives the decoder's bottom-up flip, so a
wrong-way flip is visible. Art quality is not the goal.

Usage: python3 gen_bitmap.py <output.bmp>
"""
import struct, sys

W, H = 8, 8
BPP = 24

# BITMAPINFOHEADER (40 bytes). Positive biHeight = bottom-up rows.
bih = struct.pack('<IiiHHIIiiII',
                  40,          # biSize
                  W,           # biWidth
                  H,           # biHeight (positive: bottom-up)
                  1,           # biPlanes
                  BPP,         # biBitCount
                  0,           # biCompression (BI_RGB)
                  0,           # biSizeImage (0 for BI_RGB)
                  0, 0,        # biXPelsPerMeter, biYPelsPerMeter
                  0,           # biClrUsed
                  0)           # biClrImportant

# Pixel rows: 24bpp BGR, each row padded to a DWORD boundary, stored
# bottom-up — so the LAST stored row is the TOP image row, and the red
# top-left marker lives at x=0 of that last stored row.
stride = (W * 3 + 3) // 4 * 4
pad = b'\x00' * (stride - W * 3)
green = b'\x00\xFF\x00'  # B G R
red = b'\x00\x00\xFF'    # B G R

rows = []
for stored_y in range(H):
    if stored_y == H - 1:
        rows.append(red + green * (W - 1) + pad)   # top image row
    else:
        rows.append(green * W + pad)
pixel_data = b''.join(rows)

# BITMAPFILEHEADER (14 bytes). windres strips this when it stores the
# RT_BITMAP resource, leaving the packed DIB the loader decodes.
file_size = 14 + len(bih) + len(pixel_data)
bfh = struct.pack('<2sIHHI', b'BM', file_size, 0, 0, 14 + len(bih))

with open(sys.argv[1], 'wb') as f:
    f.write(bfh + bih + pixel_data)
