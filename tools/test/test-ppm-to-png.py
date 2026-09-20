#!/usr/bin/env python3
"""Behavioral tests for tools/qemu/ppm-to-png.py."""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONVERTER = ROOT / "tools" / "qemu" / "ppm-to-png.py"


def decode_png(path: Path) -> tuple[int, int, bytes]:
    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise AssertionError("missing PNG signature")

    offset = 8
    width = height = 0
    compressed = bytearray()
    while offset < len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        tag = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        offset += 12 + length
        if tag == b"IHDR":
            width, height = struct.unpack_from(">II", payload)
        elif tag == b"IDAT":
            compressed.extend(payload)
        elif tag == b"IEND":
            break
    return width, height, zlib.decompress(compressed)


class PpmToPngTests(unittest.TestCase):
    def test_converts_comment_bearing_p6_pixels_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_dir = Path(temp)
            source = temp_dir / "frame.ppm"
            output = temp_dir / "frame.png"
            pixels = bytes((255, 0, 0, 0, 255, 0))
            source.write_bytes(b"P6\n# qemu screendump\n2 1\n255\n" + pixels)

            subprocess.run(
                [sys.executable, str(CONVERTER), str(source), str(output)],
                check=True,
                capture_output=True,
                text=True,
            )

            width, height, scanlines = decode_png(output)
            self.assertEqual((width, height), (2, 1))
            self.assertEqual(scanlines, b"\x00" + pixels)

    def test_rejects_truncated_pixel_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_dir = Path(temp)
            source = temp_dir / "truncated.ppm"
            output = temp_dir / "frame.png"
            source.write_bytes(b"P6\n2 1\n255\n\xff\x00\x00")

            result = subprocess.run(
                [sys.executable, str(CONVERTER), str(source), str(output)],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("can't open file", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
