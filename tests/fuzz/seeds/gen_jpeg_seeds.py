#!/usr/bin/env python3
# DuetOS JPEG fuzz seed generator.
#
# WHAT  Emits a minimal valid baseline-DCT (SOF0) JFIF image:
#       SOI, APP0, DQT, SOF0, DHT (standard Annex-K luminance
#       tables), SOS, entropy data, EOI. This clears the
#       duetos_img_meta SOI->SOF hop and gives fuzz_jpeg's C++
#       JpegDecode (Huffman build + baseline MCU reconstruction)
#       a real starting point for mutation.
#
# WHY   A byte stream that walks SOI -> length-correct segments
#       -> a well-formed SOF0 is unreachable by random mutation,
#       so the decoder is never entered (observed: cov 6).
#
# USAGE  python3 gen_jpeg_seeds.py <out_dir>

import os
import struct
import sys

# Standard JPEG Annex-K example luminance quantisation table
# (zig-zag order) — the table every reference baseline encoder
# ships; keeps the seed a genuine decodable image.
QLUM = [
    16, 11, 12, 14, 12, 10, 16, 14, 13, 14, 18, 17, 16, 19, 24, 40,
    26, 24, 22, 22, 24, 49, 35, 37, 29, 40, 58, 51, 61, 60, 57, 51,
    56, 55, 64, 72, 92, 78, 64, 68, 87, 69, 55, 56, 80, 109, 81, 87,
    95, 98, 103, 104, 103, 62, 77, 113, 121, 112, 100, 120, 92, 101,
    103, 99,
]

# Standard Annex-K DC + AC luminance Huffman tables (BITS + HUFFVAL).
DC_BITS = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
DC_VALS = list(range(12))
AC_BITS = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7D]
AC_VALS = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41,
    0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91,
    0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24,
    0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x53,
    0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
    0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x92, 0x93,
    0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5,
    0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
    0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1,
    0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2,
    0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
]


def seg(marker: int, body: bytes) -> bytes:
    return struct.pack(">HH", marker, len(body) + 2) + body


def baseline_jpeg() -> bytes:
    out = struct.pack(">H", 0xFFD8)  # SOI
    out += seg(0xFFE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")  # APP0
    out += seg(0xFFDB, bytes([0x00]) + bytes(QLUM))  # DQT (id 0, 8-bit)
    # SOF0: 8-bit, 8x8, 1 component (Y), 1x1 sampling, qtable 0.
    out += seg(0xFFC0, struct.pack(">BHHB", 8, 8, 8, 1) + bytes([1, 0x11, 0]))
    out += seg(0xFFC4, bytes([0x00]) + bytes(DC_BITS) + bytes(DC_VALS))  # DHT DC0
    out += seg(0xFFC4, bytes([0x10]) + bytes(AC_BITS) + bytes(AC_VALS))  # DHT AC0
    # SOS: 1 component, Td/Ta = 0, Ss=0 Se=63 Ah/Al=0.
    out += seg(0xFFDA, bytes([1, 1, 0x00, 0, 63, 0]))
    # One MCU of entropy-coded data: DC category 0 (code "00")
    # then EOB (AC code "1010") => byte pattern 0b0010_1000 = 0x28,
    # padded with 1-bits. A single 0x28 byte decodes one all-zero
    # 8x8 block; FFD9 is EOI.
    out += bytes([0x28]) + struct.pack(">H", 0xFFD9)
    return out


def main():
    o = sys.argv[1] if len(sys.argv) > 1 else "corpus/jpeg"
    os.makedirs(o, exist_ok=True)
    open(os.path.join(o, "baseline_8x8.jpg"), "wb").write(baseline_jpeg())
    print(f"seeded {o}: {len(os.listdir(o))} files")


if __name__ == "__main__":
    main()
