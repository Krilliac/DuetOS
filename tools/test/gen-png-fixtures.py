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

def ihdr(w,h,bd,ct): return chunk(b"IHDR", struct.pack(">IIBBBBB", w,h,bd,ct,0,0,0))

def build(w,h,ct,raw_scanlines, plte=None, trns=None):
    # raw_scanlines: list of (filter_byte, bytes) per row
    out = sig() + ihdr(w,h,8,ct)
    if plte is not None: out += chunk(b"PLTE", plte)
    if trns is not None: out += chunk(b"tRNS", trns)
    raw = b"".join(bytes([f]) + bytes(d) for f,d in raw_scanlines)
    out += chunk(b"IDAT", zlib.compress(raw, 0))  # level 0 = stored, but we want real deflate too
    out += chunk(b"IEND", b"")
    return out

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
