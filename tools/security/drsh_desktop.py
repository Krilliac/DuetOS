#!/usr/bin/env python3
"""Authenticated DRSH desktop capture and bounded input controller."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import socket
import struct
import sys
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from drsh_wire import (
    CH_DESKTOP,
    FRAME_CHANNEL_CLOSE,
    FRAME_CHANNEL_DATA,
    FRAME_DISCONNECT,
    DrshDisconnected,
    DrshProtocolError,
    DrshSession,
    KIND_DESKTOP,
)


SUB_TILE_BLIT = 0
SUB_FRAME_START = 1
SUB_FRAME_END = 2
SUB_INPUT_KEY = 3
SUB_INPUT_MOUSE = 4
SUB_RESIZE_ACK = 5
MAX_FRAME_PIXELS = 3840 * 2160


@dataclass(frozen=True)
class DesktopFrame:
    width: int
    height: int
    bgra: bytes


class DesktopFrameAssembler:
    """Validate and assemble one complete server framebuffer update."""

    def __init__(self) -> None:
        self._width = 0
        self._height = 0
        self._pixels: bytearray | None = None
        self._coverage: bytearray | None = None

    def _require_active(self) -> tuple[bytearray, bytearray]:
        if self._pixels is None or self._coverage is None:
            raise DrshProtocolError("desktop payload arrived before FrameStart")
        return self._pixels, self._coverage

    def feed(self, payload: bytes) -> DesktopFrame | None:
        if not payload:
            raise DrshProtocolError("empty desktop channel payload")
        subtype = payload[0]

        if subtype == SUB_FRAME_START:
            if self._pixels is not None:
                raise DrshProtocolError("desktop FrameStart arrived while a frame is already active")
            if len(payload) != 8:
                raise DrshProtocolError("invalid FrameStart length")
            width, height = struct.unpack(">HH", payload[1:5])
            bpp = payload[5]
            if bpp != 32 or width == 0 or height == 0:
                raise DrshProtocolError("unsupported desktop framebuffer format")
            pixels = width * height
            if pixels > MAX_FRAME_PIXELS:
                raise DrshProtocolError("desktop framebuffer dimensions exceed client limit")
            self._width = width
            self._height = height
            self._pixels = bytearray(pixels * 4)
            self._coverage = bytearray(pixels)
            return None

        if subtype == SUB_TILE_BLIT:
            pixels, coverage = self._require_active()
            if len(payload) < 9:
                raise DrshProtocolError("invalid TileBlit header length")
            x, y, width, height = struct.unpack(">HHHH", payload[1:9])
            if width == 0 or height == 0 or x + width > self._width or y + height > self._height:
                raise DrshProtocolError("TileBlit exceeds framebuffer bounds")
            expected = 9 + width * height * 4
            if len(payload) != expected:
                raise DrshProtocolError("TileBlit pixel length mismatch")
            for row in range(height):
                destination_pixel = (y + row) * self._width + x
                if any(coverage[destination_pixel : destination_pixel + width]):
                    raise DrshProtocolError("TileBlit overlaps pixels already supplied in this frame")
            source = memoryview(payload)[9:]
            for row in range(height):
                source_start = row * width * 4
                destination_pixel = (y + row) * self._width + x
                destination_start = destination_pixel * 4
                pixels[destination_start : destination_start + width * 4] = source[
                    source_start : source_start + width * 4
                ]
                coverage[destination_pixel : destination_pixel + width] = b"\x01" * width
            return None

        if subtype == SUB_FRAME_END:
            if len(payload) != 1:
                raise DrshProtocolError("invalid FrameEnd length")
            pixels, coverage = self._require_active()
            if 0 in coverage:
                raise DrshProtocolError("desktop frame is incomplete")
            frame = DesktopFrame(self._width, self._height, bytes(pixels))
            self._pixels = None
            self._coverage = None
            return frame

        raise DrshProtocolError(f"unexpected server desktop subtype {subtype}")


def encode_key_event(code: int, modifiers: int = 0, pressed: bool = True) -> bytes:
    if not 0 <= code <= 0xFFFF:
        raise ValueError("key code must fit u16")
    if not 0 <= modifiers <= 0xFF:
        raise ValueError("key modifiers must fit u8")
    if not isinstance(pressed, bool):
        raise ValueError("pressed must be boolean")
    return bytes([SUB_INPUT_KEY]) + struct.pack("<HBB", code, modifiers, int(pressed))


def encode_desktop_open(width: int = 0, height: int = 0) -> bytes:
    if width == 0 and height == 0:
        return bytes([KIND_DESKTOP])
    if not 1 <= width <= 0xFFFF or not 1 <= height <= 0xFFFF:
        raise ValueError("desktop dimensions must both be zero or fit u16")
    return bytes([KIND_DESKTOP]) + struct.pack(">HH", width, height)


def encode_mouse_event(dx: int, dy: int, buttons: int = 0) -> bytes:
    if not -32768 <= dx <= 32767 or not -32768 <= dy <= 32767:
        raise ValueError("mouse deltas must fit i16")
    if not 0 <= buttons <= 0xFF:
        raise ValueError("mouse buttons must fit u8")
    return struct.pack(">BhhB", SUB_INPUT_MOUSE, dx, dy, buttons)


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    checksum = binascii.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", checksum)


def write_png(path: Path, frame: DesktopFrame) -> str:
    rows = bytearray()
    for y in range(frame.height):
        rows.append(0)  # PNG filter type: None
        start = y * frame.width * 4
        row = frame.bgra[start : start + frame.width * 4]
        for x in range(0, len(row), 4):
            blue, green, red, alpha = row[x : x + 4]
            rows.extend((red, green, blue, alpha))
    ihdr = struct.pack(">IIBBBBB", frame.width, frame.height, 8, 6, 0, 0, 0)
    encoded = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr)
    encoded += _png_chunk(b"IDAT", zlib.compress(bytes(rows), level=6))
    encoded += _png_chunk(b"IEND", b"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def write_ppm(path: Path, frame: DesktopFrame) -> str:
    rgb = bytearray()
    for offset in range(0, len(frame.bgra), 4):
        blue, green, red, _alpha = frame.bgra[offset : offset + 4]
        rgb.extend((red, green, blue))
    encoded = f"P6\n{frame.width} {frame.height}\n255\n".encode("ascii") + bytes(rgb)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def write_screenshot(path: Path, frame: DesktopFrame) -> str:
    suffix = path.suffix.lower()
    if suffix == ".png":
        return write_png(path, frame)
    if suffix == ".ppm":
        return write_ppm(path, frame)
    raise ValueError("screenshot path must end in .png or .ppm")


def receive_frame(session: DrshSession, timeout: float) -> DesktopFrame:
    assembler = DesktopFrameAssembler()
    previous_timeout = session.sock.gettimeout()
    session.sock.settimeout(timeout)
    try:
        while True:
            frame_type, channel, payload = session.recv_authenticated()
            if frame_type == FRAME_DISCONNECT:
                raise DrshDisconnected("server disconnected during desktop frame")
            if frame_type == FRAME_CHANNEL_CLOSE:
                raise DrshDisconnected("server closed the desktop channel")
            if frame_type != FRAME_CHANNEL_DATA or channel != CH_DESKTOP:
                raise DrshProtocolError("unexpected frame on desktop channel")
            frame = assembler.feed(payload)
            if frame is not None:
                return frame
    finally:
        if not session.closed:
            session.sock.settimeout(previous_timeout)


def load_actions(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("action plan must be a JSON array")
    actions: list[dict[str, Any]] = []
    for index, action in enumerate(raw):
        if not isinstance(action, dict) or action.get("type") not in {"key", "mouse", "wait"}:
            raise ValueError(f"action {index} has an unsupported type")
        try:
            if action["type"] == "key":
                encode_key_event(
                    int(action["code"]),
                    int(action.get("modifiers", 0)),
                    action.get("pressed", True),
                )
            elif action["type"] == "mouse":
                encode_mouse_event(int(action["dx"]), int(action["dy"]), int(action.get("buttons", 0)))
            else:
                milliseconds = int(action.get("milliseconds", 0))
                if not 0 <= milliseconds <= 60_000:
                    raise ValueError("wait milliseconds must be between 0 and 60000")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"action {index} is invalid: {error}") from error
        actions.append(action)
    return actions


def action_payload(action: dict[str, Any], frame: DesktopFrame) -> tuple[bytes, float]:
    kind = action["type"]
    if kind == "key":
        return (
            encode_key_event(
                int(action["code"]),
                int(action.get("modifiers", 0)),
                action.get("pressed", True),
            ),
            0.0,
        )
    if kind == "mouse":
        return (
            encode_mouse_event(int(action["dx"]), int(action["dy"]), int(action.get("buttons", 0))),
            0.0,
        )
    milliseconds = int(action.get("milliseconds", 0))
    if not 0 <= milliseconds <= 60_000:
        raise ValueError("wait milliseconds must be between 0 and 60000")
    payload = bytes([SUB_RESIZE_ACK]) + struct.pack(">HH", frame.width, frame.height)
    return payload, milliseconds / 1000.0


def emit(jsonl: bool, event: str, **fields: Any) -> None:
    record = {"event": event, **fields}
    if jsonl:
        print(json.dumps(record, sort_keys=True), flush=True)
    else:
        details = " ".join(f"{key}={value}" for key, value in fields.items())
        print(f"[{event}] {details}".rstrip(), flush=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture and control a DuetOS desktop over authenticated DRSH")
    parser.add_argument("--host", default=os.environ.get("DRSH_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("DRSH_PORT", "4322")))
    parser.add_argument("--password", default=os.environ.get("DRSH_PASSWORD"), help=argparse.SUPPRESS)
    parser.add_argument("--screenshot", type=Path, required=True, help="PNG path for the final received frame")
    parser.add_argument("--actions", type=Path, help="bounded JSON array of key/mouse/wait actions")
    parser.add_argument("--allow-guest-control", action="store_true", help="required when --actions injects input")
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=15.0,
        help="TCP and authentication timeout; TCG guests can need several seconds",
    )
    parser.add_argument("--frame-timeout", type=float, default=30.0)
    parser.add_argument("--width", type=int, default=256, help="requested stream width; 0 with --height 0 uses native")
    parser.add_argument("--height", type=int, default=192, help="requested stream height; 0 with --width 0 uses native")
    parser.add_argument("--jsonl", action="store_true")
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    if not 1 <= args.port <= 65535 or args.connect_timeout <= 0 or args.frame_timeout <= 0:
        print("invalid port or timeout", file=sys.stderr)
        return 2
    if not args.password:
        print("DRSH password is required via DRSH_PASSWORD or --password", file=sys.stderr)
        return 2
    try:
        actions = load_actions(args.actions)
        if actions and not args.allow_guest_control:
            raise ValueError("input actions require --allow-guest-control")
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"action plan error: {error}", file=sys.stderr)
        return 2

    session: DrshSession | None = None
    try:
        session = DrshSession.connect(
            args.host,
            args.port,
            args.password.encode("utf-8"),
            timeout=args.connect_timeout,
        )
        # Keep the pure encoder and transport method on the same public wire
        # contract; encode here also validates before any channel mutation.
        encode_desktop_open(args.width, args.height)
        session.open_desktop(args.width, args.height)
        emit(args.jsonl, "login", host=args.host, port=args.port, channel="desktop")
        frame = receive_frame(session, args.frame_timeout)
        for index, action in enumerate(actions):
            payload, delay = action_payload(action, frame)
            if delay:
                time.sleep(delay)
            session.send_authenticated(FRAME_CHANNEL_DATA, CH_DESKTOP, payload)
            frame = receive_frame(session, args.frame_timeout)
            emit(args.jsonl, "action", index=index, type=action["type"], ok=True)
        digest = write_screenshot(args.screenshot, frame)
        emit(
            args.jsonl,
            "screenshot",
            path=str(args.screenshot.resolve()),
            width=frame.width,
            height=frame.height,
            sha256=digest,
        )
        return 0
    except (DrshDisconnected, DrshProtocolError, OSError, RuntimeError, ValueError, socket.timeout) as error:
        emit(args.jsonl, "error", message=str(error))
        return 1
    finally:
        if session is not None:
            session.close()


if __name__ == "__main__":
    sys.exit(main())
