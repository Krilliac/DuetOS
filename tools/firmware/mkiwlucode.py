#!/usr/bin/env python3
"""Build an iwlwifi-style .ucode TLV image from caller-supplied sections.

This emits the same outer TLV container parsed by DuetOS/Linux iwlwifi tooling:
88-byte header plus little-endian TLV records. It does not create Intel-signed
retail firmware; payload sections must come from a clean-room/open lab target
or synthetic parser/upload tests.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = 0x0A4C5749  # "IWL\n" little-endian
HEADER_BYTES = 88
HUMAN_BYTES = 64

TLV_TYPES = {
    "inst": 1,
    "data": 2,
    "init": 3,
    "init-data": 4,
    "sec-rt": 19,
    "sec-init": 20,
    "sec-wowlan": 21,
    "secure-sec-rt": 24,
    "secure-sec-init": 25,
    "secure-sec-wowlan": 26,
}

META_TLV_TYPES = {
    "flags": 18,
    "num-of-cpu": 27,
    "fw-version": 36,
}


def fixed_name(name: str) -> bytes:
    raw = name.encode("ascii")
    if not raw:
        raise ValueError("--name must not be empty")
    if len(raw) > HUMAN_BYTES:
        raise ValueError(f"--name is {len(raw)} bytes; max is {HUMAN_BYTES}")
    return raw + b"\0" * (HUMAN_BYTES - len(raw))


def tlv(tlv_type: int, payload: bytes) -> bytes:
    padded_len = (len(payload) + 3) & ~3
    return struct.pack("<II", tlv_type, len(payload)) + payload + (b"\0" * (padded_len - len(payload)))


def parse_section(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        raise ValueError(f"section '{spec}' must be TYPE=PATH")
    kind, path = spec.split("=", 1)
    if kind not in TLV_TYPES:
        raise ValueError(f"unknown section type '{kind}' (valid: {', '.join(sorted(TLV_TYPES))})")
    return kind, Path(path)


def build_image(args: argparse.Namespace) -> bytes:
    sections = [parse_section(s) for s in args.section]
    if not sections:
        raise ValueError("at least one --section TYPE=PATH is required")

    header = bytearray(HEADER_BYTES)
    struct.pack_into("<II", header, 0, 0, MAGIC)
    header[8:72] = fixed_name(args.name)
    struct.pack_into("<II", header, 72, args.version, args.build)

    body = bytearray()
    if args.flags is not None:
        body += tlv(META_TLV_TYPES["flags"], struct.pack("<I", args.flags))
    if args.num_of_cpu is not None:
        body += tlv(META_TLV_TYPES["num-of-cpu"], struct.pack("<I", args.num_of_cpu))
    if args.fw_version is not None:
        body += tlv(META_TLV_TYPES["fw-version"], struct.pack("<I", args.fw_version))

    for kind, path in sections:
        payload = path.read_bytes()
        if not payload:
            raise ValueError(f"section {kind} payload '{path}' is empty")
        body += tlv(TLV_TYPES[kind], payload)
    return bytes(header) + bytes(body)


def run_self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        inst = root / "inst.bin"
        data = root / "data.bin"
        inst.write_bytes(b"\x13\x37\xC0\xDE")
        data.write_bytes(b"\x55\xAA")
        args = argparse.Namespace(
            name="DuetOS custom unsigned lab ucode",
            version=0x00010002,
            build=0x20260508,
            flags=0xA5A50001,
            num_of_cpu=2,
            fw_version=0x00010002,
            section=[f"inst={inst}", f"data={data}"],
        )
        image = build_image(args)
        assert image[0:4] == b"\0\0\0\0"
        assert struct.unpack_from("<I", image, 4)[0] == MAGIC
        assert struct.unpack_from("<I", image, HEADER_BYTES)[0] == META_TLV_TYPES["flags"]
        assert struct.unpack_from("<I", image, HEADER_BYTES + 8)[0] == 0xA5A50001
        assert image.endswith(b"\x55\xAA\x00\x00")
    print("mkiwlucode.py self-test pass")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="DuetOS custom unsigned lab ucode")
    parser.add_argument("--version", type=lambda x: int(x, 0), default=0x00010000)
    parser.add_argument("--build", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--flags", type=lambda x: int(x, 0))
    parser.add_argument("--num-of-cpu", type=lambda x: int(x, 0))
    parser.add_argument("--fw-version", type=lambda x: int(x, 0))
    parser.add_argument(
        "--section",
        action="append",
        default=[],
        metavar="TYPE=PATH",
        help=f"append a payload TLV ({', '.join(sorted(TLV_TYPES))})",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return args
    if args.output is None:
        parser.error("--output is required unless --self-test is used")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    image = build_image(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)
    print(f"wrote {args.output} ({len(image)} bytes, {len(args.section)} section TLVs)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ValueError as exc:
        print(f"mkiwlucode.py: error: {exc}", file=sys.stderr)
        raise SystemExit(2)
