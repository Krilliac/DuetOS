#!/usr/bin/env python3
"""Behavior tests for the authenticated DRSH desktop client."""

from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SECURITY_TOOLS = ROOT / "tools" / "security"
sys.path.insert(0, str(SECURITY_TOOLS))

from drsh_desktop import (  # noqa: E402
    DesktopFrameAssembler,
    MAX_FRAME_PIXELS,
    encode_desktop_open,
    encode_key_event,
    encode_mouse_event,
    load_actions,
    parse_args,
    write_png,
    write_ppm,
)
from drsh_wire import DrshProtocolError  # noqa: E402


def frame_start(width: int, height: int, bpp: int = 32) -> bytes:
    return struct.pack(">BHHBBB", 1, width, height, bpp, 0, 0)


def tile(x: int, y: int, width: int, height: int, bgra: bytes) -> bytes:
    return struct.pack(">BHHHH", 0, x, y, width, height) + bgra


class DesktopFrameTests(unittest.TestCase):
    def test_assembles_split_tiles_into_one_complete_frame(self) -> None:
        assembler = DesktopFrameAssembler()
        self.assertIsNone(assembler.feed(frame_start(2, 2)))

        top = bytes.fromhex("0000ffff 00ff00ff")
        bottom = bytes.fromhex("ff0000ff ffffffff")
        self.assertIsNone(assembler.feed(tile(0, 0, 2, 1, top)))
        self.assertIsNone(assembler.feed(tile(0, 1, 2, 1, bottom)))
        frame = assembler.feed(b"\x02")

        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual((frame.width, frame.height), (2, 2))
        self.assertEqual(frame.bgra, top + bottom)

    def test_rejects_incomplete_or_out_of_bounds_frame(self) -> None:
        assembler = DesktopFrameAssembler()
        assembler.feed(frame_start(2, 2))
        assembler.feed(tile(0, 0, 2, 1, b"\x00" * 8))
        with self.assertRaisesRegex(DrshProtocolError, "incomplete"):
            assembler.feed(b"\x02")

        assembler = DesktopFrameAssembler()
        assembler.feed(frame_start(2, 2))
        with self.assertRaisesRegex(DrshProtocolError, "bounds"):
            assembler.feed(tile(1, 1, 2, 2, b"\x00" * 16))

    def test_rejects_nested_frame_starts_and_overlapping_tiles(self) -> None:
        assembler = DesktopFrameAssembler()
        assembler.feed(frame_start(2, 2))
        with self.assertRaisesRegex(DrshProtocolError, "already active"):
            assembler.feed(frame_start(2, 2))

        assembler = DesktopFrameAssembler()
        assembler.feed(frame_start(2, 2))
        assembler.feed(tile(0, 0, 1, 1, b"\x00" * 4))
        with self.assertRaisesRegex(DrshProtocolError, "overlaps"):
            assembler.feed(tile(0, 0, 1, 1, b"\x00" * 4))

    def test_frame_allocation_cap_is_no_larger_than_4k(self) -> None:
        self.assertLessEqual(MAX_FRAME_PIXELS, 3840 * 2160)

    def test_writes_dependency_free_png_with_exact_dimensions(self) -> None:
        assembler = DesktopFrameAssembler()
        assembler.feed(frame_start(1, 1))
        assembler.feed(tile(0, 0, 1, 1, bytes.fromhex("332211ff")))
        frame = assembler.feed(b"\x02")
        assert frame is not None

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "screen.png"
            digest = write_png(output, frame)
            data = output.read_bytes()

        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", data[16:24]), (1, 1))
        self.assertEqual(len(digest), 64)

    def test_writes_dependency_free_ppm_in_rgb_order(self) -> None:
        assembler = DesktopFrameAssembler()
        assembler.feed(frame_start(1, 1))
        assembler.feed(tile(0, 0, 1, 1, bytes.fromhex("332211ff")))
        frame = assembler.feed(b"\x02")
        assert frame is not None

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "screen.ppm"
            digest = write_ppm(output, frame)
            data = output.read_bytes()

        self.assertEqual(data, b"P6\n1 1\n255\n\x11\x22\x33")
        self.assertEqual(len(digest), 64)


class DesktopInputTests(unittest.TestCase):
    def test_cli_does_not_assume_the_test_password(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            args = parse_args(["--screenshot", "capture.png"])
        self.assertIsNone(args.password)

    def test_cli_uses_a_tcg_safe_connect_timeout(self) -> None:
        args = parse_args(["--screenshot", "capture.png"])
        self.assertEqual(args.connect_timeout, 15.0)

    def test_desktop_open_can_request_a_bounded_scaled_frame(self) -> None:
        self.assertEqual(encode_desktop_open(0, 0), b"\x01")
        self.assertEqual(encode_desktop_open(256, 192), b"\x01\x01\x00\x00\xc0")
        with self.assertRaises(ValueError):
            encode_desktop_open(0, 192)

    def test_key_payload_matches_kernel_wire_contract(self) -> None:
        self.assertEqual(encode_key_event(0x41, modifiers=0x05, pressed=True), b"\x03A\x00\x05\x01")
        self.assertEqual(encode_key_event(0x100, modifiers=0x02, pressed=False), b"\x03\x00\x01\x02\x00")

    def test_mouse_payload_uses_signed_big_endian_deltas(self) -> None:
        self.assertEqual(encode_mouse_event(-2, 127, buttons=3), b"\x04\xff\xfe\x00\x7f\x03")

    def test_action_plan_rejects_missing_fields_before_connecting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "actions.json"
            path.write_text('[{"type":"mouse","dx":1}]', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "action 0"):
                load_actions(path)


class DesktopServerContractTests(unittest.TestCase):
    def test_every_streamed_frame_starts_with_a_frame_header(self) -> None:
        source = (ROOT / "kernel" / "net" / "drsh" / "drsh_desktop.cpp").read_text(encoding="utf-8")
        service = source.split("bool DesktopChannelService", 1)[1]
        refresh_loop = service.split("while (true)", 1)[1]
        before_tiles = refresh_loop.split("// ----- Push a full frame", 1)[0]
        self.assertIn("SendFrameStart", before_tiles)

    def test_tile_staging_buffer_is_owned_by_each_session(self) -> None:
        source = (ROOT / "kernel" / "net" / "drsh" / "drsh_desktop.cpp").read_text(encoding="utf-8")
        self.assertNotIn("static u8 payload[kDrshMaxPayload]", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
