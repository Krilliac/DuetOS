#!/usr/bin/env python3
"""Build a DuetOS firmware package envelope around a raw firmware image.

The payload is not modified. This tool adds source/provenance flags and a
SHA-256 payload digest that the kernel parser validates before a driver upload
path sees the bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

MAGIC = b"DUETFWPK"
VERSION = 1
HEADER_BYTES = 160
NAME_BYTES = 32
UPSTREAM_BYTES = 64

FAMILIES = {
    "unknown": 0,
    "intel-iwlwifi": 1,
    "intel-gpu-uc": 2,
    "ath9k-htc": 3,
    "broadcom-b43": 4,
    "broadcom-fullmac": 5,
    "realtek-rtl88xx": 6,
}

SOURCE_KINDS = {
    "unknown": 0,
    "open-source": 1,
    "redistributable-binary": 2,
    "extracted-vendor-binary": 3,
    "patch-framework": 4,
}

FLAG_SOURCE_REBUILDABLE = 1 << 0
FLAG_MAY_BUNDLE_IN_TREE = 1 << 1
FLAG_REGULATORY_LOCKED = 1 << 2
FLAG_CUSTOM_LAB_IMAGE = 1 << 3
FLAG_REQUIRES_EXPLICIT_OPT_IN = 1 << 4
FLAG_OPEN_FIRMWARE = 1 << 5


def fixed_ascii(value: str, byte_count: int, field_name: str) -> bytes:
    raw = value.encode("ascii")
    if len(raw) > byte_count:
        raise ValueError(f"{field_name} is {len(raw)} bytes; max is {byte_count}")
    return raw + b"\0" * (byte_count - len(raw))


def build_package(args: argparse.Namespace, payload: bytes) -> bytes:
    if not payload:
        raise ValueError("input payload is empty")
    if args.custom_lab_image and not args.allow_lab_image:
        raise ValueError("--custom-lab-image requires --allow-lab-image so lab firmware is explicit")
    if args.may_bundle and args.source_kind != "open-source":
        raise ValueError("--may-bundle is only valid for --source-kind open-source")

    flags = 0
    if args.source_rebuildable:
        flags |= FLAG_SOURCE_REBUILDABLE
    if args.may_bundle:
        flags |= FLAG_MAY_BUNDLE_IN_TREE
    if args.regulatory_locked:
        flags |= FLAG_REGULATORY_LOCKED
    if args.custom_lab_image:
        flags |= FLAG_CUSTOM_LAB_IMAGE | FLAG_REQUIRES_EXPLICIT_OPT_IN
    if args.source_kind == "open-source":
        flags |= FLAG_OPEN_FIRMWARE

    digest = hashlib.sha256(payload).digest()
    header = bytearray(HEADER_BYTES)
    header[0:8] = MAGIC
    struct.pack_into(
        "<HHHBBIIII",
        header,
        8,
        VERSION,
        HEADER_BYTES,
        FAMILIES[args.family],
        SOURCE_KINDS[args.source_kind],
        0,
        flags,
        HEADER_BYTES,
        len(payload),
        args.build_id,
    )
    header[32:64] = digest
    header[64:96] = fixed_ascii(args.short_name, NAME_BYTES, "short name")
    header[96:160] = fixed_ascii(args.upstream, UPSTREAM_BYTES, "upstream")
    return bytes(header) + payload


def run_self_test() -> None:
    payload = b"ATH9KHTC" + bytes(range(32))
    ns = argparse.Namespace(
        family="ath9k-htc",
        source_kind="open-source",
        source_rebuildable=True,
        may_bundle=True,
        regulatory_locked=True,
        custom_lab_image=False,
        allow_lab_image=False,
        short_name="ath9k-htc-open",
        upstream="qca/open-ath9k-htc-firmware",
        build_id=0x20260508,
    )
    pkg = build_package(ns, payload)
    assert pkg[0:8] == MAGIC
    assert len(pkg) == HEADER_BYTES + len(payload)
    assert pkg[HEADER_BYTES:] == payload
    assert pkg[32:64] == hashlib.sha256(payload).digest()

    ns.custom_lab_image = True
    try:
        build_package(ns, payload)
    except ValueError as exc:
        assert "allow-lab-image" in str(exc)
    else:
        raise AssertionError("lab package built without explicit opt-in")

    ns.allow_lab_image = True
    lab = build_package(ns, payload)
    flags = struct.unpack_from("<I", lab, 16)[0]
    assert flags & FLAG_CUSTOM_LAB_IMAGE
    assert flags & FLAG_REQUIRES_EXPLICIT_OPT_IN
    print("mkduetfw.py self-test pass")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="raw firmware payload to wrap")
    parser.add_argument("--output", type=Path, help="output .duetfw package")
    parser.add_argument("--family", choices=sorted(FAMILIES), default="unknown")
    parser.add_argument("--source-kind", choices=sorted(SOURCE_KINDS), default="unknown")
    parser.add_argument("--short-name", required=False, default="")
    parser.add_argument("--upstream", required=False, default="")
    parser.add_argument("--build-id", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--source-rebuildable", action="store_true")
    parser.add_argument("--may-bundle", action="store_true")
    parser.add_argument("--regulatory-locked", action="store_true")
    parser.add_argument("--custom-lab-image", action="store_true")
    parser.add_argument("--allow-lab-image", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return args
    if args.input is None or args.output is None:
        parser.error("--input and --output are required unless --self-test is used")
    if not args.short_name:
        parser.error("--short-name is required")
    if not args.upstream:
        parser.error("--upstream is required")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0
    payload = args.input.read_bytes()
    package = build_package(args, payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(package)
    print(
        f"wrote {args.output} "
        f"({len(package)} bytes, payload {len(payload)} bytes, "
        f"sha256={hashlib.sha256(payload).hexdigest()})"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ValueError as exc:
        print(f"mkduetfw.py: error: {exc}", file=sys.stderr)
        raise SystemExit(2)
