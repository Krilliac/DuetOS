#!/usr/bin/env python3
#
# DuetOS — PNG known-answer fixture generator for the kernel/web
# PNG decoder self-test (kernel/web/png_selftest.cpp).
#
# Emits C++ `constexpr u8 kPng...[] = { ... };` byte arrays for a
# set of tiny PNGs, one per supported colour type, using the host
# zlib (real DEFLATE — fixed/dynamic Huffman) and host CRC32. The
# decoder must reproduce these exactly. Re-run this if a fixture's
# pixels need to change; paste the output back into the self-test
# and update the asserted pixel values to match the source pixels
# printed below each fixture.
#
# Usage:  python3 tools/test/gen-png-fixtures.py
#
# No deps beyond CPython's stdlib (zlib, struct).

import zlib, struct

def chunk(typ, data):
    c = typ + data
    return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

def sig(): return bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A])

def ihdr(w,h,bd,ct,interlace=0): return chunk(b"IHDR", struct.pack(">IIBBBBB", w,h,bd,ct,0,0,interlace))

def build(w,h,ct,raw_scanlines, plte=None, trns=None, bd=8, interlace=0):
    # raw_scanlines: list of (filter_byte, bytes) per row — already the
    # full set of (possibly Adam7-pass) filtered scanlines in stream order.
    out = sig() + ihdr(w,h,bd,ct,interlace)
    if plte is not None: out += chunk(b"PLTE", plte)
    if trns is not None: out += chunk(b"tRNS", trns)
    raw = b"".join(bytes([f]) + bytes(d) for f,d in raw_scanlines)
    out += chunk(b"IDAT", zlib.compress(raw, 9))  # real DEFLATE (dynamic/fixed Huffman)
    out += chunk(b"IEND", b"")
    return out

# Adam7 pass start/step tables (x_start,y_start,x_step,y_step).
ADAM7 = [
    (0,0,8,8),(4,0,8,8),(0,4,4,8),(2,0,4,4),(0,2,2,4),(1,0,2,2),(0,1,1,2),
]

def pack_bits(samples, depth):
    # Pack a list of small integer samples MSB-first into bytes; each
    # call starts on a fresh byte (a single scanline). depth in 1/2/4.
    out = bytearray()
    acc = 0; nbits = 0
    for s in samples:
        acc = (acc << depth) | (s & ((1<<depth)-1))
        nbits += depth
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 0xFF)
    if nbits:
        out.append((acc << (8-nbits)) & 0xFF)
    return bytes(out)

def adam7_scanlines_gray8(w, h, pix):
    # pix: function (x,y)->sample byte (8-bit gray). Returns list of
    # (filter=0, rowbytes) scanlines across the 7 Adam7 passes, in
    # stream order. Each pass row is one byte per sample.
    rows = []
    for (xs,ys,xstep,ystep) in ADAM7:
        # sub-image dims
        pw = (w - xs + xstep - 1)//xstep if xs < w else 0
        ph = (h - ys + ystep - 1)//ystep if ys < h else 0
        if pw == 0 or ph == 0:
            continue
        for ry in range(ph):
            y = ys + ry*ystep
            row = bytes(pix(xs + rx*xstep, y) for rx in range(pw))
            rows.append((0, row))
    return rows

def emit_c(name, data):
    print(f"// {name} : {len(data)} bytes")
    print(f"constexpr u8 {name}[] = {{")
    for i in range(0, len(data), 12):
        row = ", ".join(f"0x{b:02X}" for b in data[i:i+12])
        print("    " + row + ",")
    print("};")
    print()

def paeth(a,b,c):
    p=a+b-c; pa=abs(p-a); pb=abs(p-b); pc=abs(p-c)
    if pa<=pb and pa<=pc: return a
    if pb<=pc: return b
    return c

# ---- Fixture 1: 2x2 RGBA, None filter
f1 = build(2,2,6,[
    (0,[0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF]),
    (0,[0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0x80]),
])
emit_c("kPng2x2Rgba", f1)
# expected RGBA at (0,0)=red FF000000FF -> packed below in test

# ---- Fixture 2: 3x2 RGB with row0 None, row1 Paeth filter
# row0 raw pixels
r0 = [10,20,30, 40,50,60, 70,80,90]
# row1 actual desired pixels
r1act = [100,110,120, 130,140,150, 160,170,180]
# encode row1 as Paeth filter (type 4), bpp=3
bpp=3
filt=[]
for i in range(len(r1act)):
    a = r1act[i-bpp] if i>=bpp else 0
    b = r0[i]
    c = r0[i-bpp] if i>=bpp else 0
    filt.append((r1act[i] - paeth(a,b,c)) & 0xFF)
f2 = build(3,2,2,[(0,r0),(4,filt)])
emit_c("kPng3x2RgbPaeth", f2)
print("// 3x2 RGB row0:", r0)
print("// 3x2 RGB row1:", r1act)

# ---- Fixture 3: 2x2 palette (type 3) + tRNS
# palette indices: row0: 0,1 ; row1: 2,1
plte = bytes([255,0,0, 0,255,0, 0,0,255])  # idx0 red, idx1 green, idx2 blue
trns = bytes([0x10, 0x80])  # idx0 alpha=0x10, idx1 alpha=0x80, idx2 -> 0xFF default
f3 = build(2,2,3,[(0,[0,1]),(0,[2,1])], plte=plte, trns=trns)
emit_c("kPng2x2Pal", f3)

# ---- Fixture 4: 2x2 grayscale+alpha (type 4), None
f4 = build(2,2,4,[
    (0,[0x11,0xFF, 0x22,0x80]),
    (0,[0x33,0x40, 0x44,0x00]),
])
emit_c("kPng2x2GrayA", f4)

# ---- Fixture 5: 2x1 grayscale (type 0)
f5 = build(2,1,0,[(0,[0x00,0xFF])])
emit_c("kPng2x1Gray", f5)

# ---- Fixture 6: 4x1 grayscale, 4-bit depth (type 0, bd=4).
# Source 4-bit samples: 0x0, 0x5, 0xA, 0xF.
# Decoder scales each up to 8-bit by raw*(255/15):
#   0x0->0x00, 0x5->0x55, 0xA->0xAA, 0xF->0xFF.
g4 = [0x0, 0x5, 0xA, 0xF]
f6 = build(4,1,0,[(0, pack_bits(g4,4))], bd=4)
emit_c("kPng4x1Gray4", f6)
print("// 4x1 gray4 samples:", g4, "-> 8-bit", [s*(255//15) for s in g4])

# ---- Fixture 7: 2x1 grayscale, 16-bit depth (type 0, bd=16).
# Source 16-bit samples: 0x1234, 0xABCD. High byte -> 0x12, 0xAB.
g16 = [0x1234, 0xABCD]
row16 = bytearray()
for s in g16:
    row16 += struct.pack(">H", s)
f7 = build(2,1,0,[(0, bytes(row16))], bd=16)
emit_c("kPng2x1Gray16", f7)
print("// 2x1 gray16 samples:", [hex(s) for s in g16], "-> high byte", [hex(s>>8) for s in g16])

# ---- Fixture 8a/8b: Adam7-interlaced 8x8 grayscale and its
# non-interlaced twin. Same source pixels, must decode identically.
# Source gradient: pixel(x,y) = (x*16 + y*2) & 0xFF, a value that
# differs across every Adam7 pass so de-interlacing is genuinely tested.
def src8(x,y): return (x*16 + y*2) & 0xFF
# Non-interlaced: one byte per pixel per row, filter None.
ni_rows = [(0, bytes(src8(x,y) for x in range(8))) for y in range(8)]
f8ni = build(8,8,0, ni_rows, bd=8, interlace=0)
emit_c("kPng8x8GrayNonInterlaced", f8ni)
# Interlaced twin.
il_rows = adam7_scanlines_gray8(8,8,src8)
f8il = build(8,8,0, il_rows, bd=8, interlace=1)
emit_c("kPng8x8GrayAdam7", f8il)
print("// 8x8 gray pixel(x,y) = (x*16 + y*2) & 0xFF")
