#!/usr/bin/env python3
# DuetOS firmware-package fuzz seed generator.
#
# WHAT  Emits a valid 160-byte DuetOS firmware envelope (magic
#       "DUETFWPK", version 1, header/payload offsets, names) with
#       a correct SHA-256 of the payload, mirroring the layout
#       firmware_package.cpp's own builder writes. fuzz_fw_pkg
#       then mutates from a seed that already passes the magic +
#       version + bounds + digest gate, so the parser body and
#       FwPackageLoadAllowed are actually exercised.
#
# WHY   The 32-byte SHA-256 digest field makes a passing input
#       unreachable by random mutation (observed: cov 15 — only
#       the magic pre-screen ran).
#
# USAGE  python3 gen_fw_pkg_seeds.py <out_dir>

import hashlib
import os
import struct
import sys

HEADER = 160
MAGIC = b"DUETFWPK"


def fw_package(payload: bytes, flags: int) -> bytes:
    pkg = bytearray(HEADER + len(payload))
    pkg[0:8] = MAGIC
    struct.pack_into("<H", pkg, 8, 1)            # version
    struct.pack_into("<H", pkg, 10, HEADER)      # header_bytes
    struct.pack_into("<H", pkg, 12, 3)           # family = Ath9kHtc
    pkg[14] = 1                                  # source = OpenSource
    struct.pack_into("<I", pkg, 16, flags)       # flags
    struct.pack_into("<I", pkg, 20, HEADER)      # payload_offset
    struct.pack_into("<I", pkg, 24, len(payload))  # payload_size
    struct.pack_into("<I", pkg, 28, 0x20260508)  # build_id
    name = b"ath9k-htc-seed"
    pkg[64:64 + len(name)] = name
    up = b"qca/open-ath9k-htc-firmware"
    pkg[96:96 + len(up)] = up
    pkg[HEADER:] = payload
    pkg[32:64] = hashlib.sha256(payload).digest()
    return bytes(pkg)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/fw_pkg"
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, "open_fw.bin"), "wb").write(
        fw_package(bytes(range(16)), 0x01 | 0x02 | 0x04 | 0x20))
    open(os.path.join(out, "lab_image.bin"), "wb").write(
        fw_package(b"LAB-PAYLOAD-1234", 0x01 | 0x08 | 0x10))
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
