#!/usr/bin/env python3
"""Convert QEMU's binary P6 screendump format to an RGB PNG."""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path


WHITESPACE = b" \t\r\n"


def read_token(data: bytes, offset: int) -> tuple[bytes, int]:
    while True:
        while offset < len(data) and data[offset : offset + 1] in WHITESPACE:
            offset += 1
        if offset >= len(data) or data[offset : offset + 1] != b"#":
            break
        newline = data.find(b"\n", offset)
        if newline < 0:
            raise ValueError("unterminated PPM comment")
        offset = newline + 1

    end = offset
    while end < len(data) and data[end : end + 1] not in WHITESPACE:
        end += 1
    if end == offset:
        raise ValueError("missing PPM header token")
    return data[offset:end], end


def parse_ppm(data: bytes) -> tuple[int, int, bytes]:
    magic, offset = read_token(data, 0)
    width_raw, offset = read_token(data, offset)
    height_raw, offset = read_token(data, offset)
    maxval_raw, offset = read_token(data, offset)
    if magic != b"P6":
        raise ValueError("only binary P6 PPM input is supported")

    width = int(width_raw)
    height = int(height_raw)
    maxval = int(maxval_raw)
    if width <= 0 or height <= 0:
        raise ValueError("PPM dimensions must be positive")
    if maxval != 255:
        raise ValueError("only 8-bit PPM input is supported")
    if offset >= len(data) or data[offset : offset + 1] not in WHITESPACE:
        raise ValueError("PPM header is not terminated")

    pixels = data[offset + 1 :]
    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError(f"PPM pixel payload is {len(pixels)} bytes; expected {expected}")
    return width, height, pixels


def png_chunk(tag: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(tag + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", checksum)


def encode_png(width: int, height: int, pixels: bytes) -> bytes:
    scanlines = b"".join(b"\x00" + pixels[y * width * 3 : (y + 1) * width * 3] for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(scanlines, 9))
        + png_chunk(b"IEND", b"")
    )


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} <input.ppm> <output.png>", file=sys.stderr)
        return 2
    source = Path(sys.argv[1])
    output = Path(sys.argv[2])
    try:
        width, height, pixels = parse_ppm(source.read_bytes())
        output.write_bytes(encode_png(width, height, pixels))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
