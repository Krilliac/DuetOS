#!/usr/bin/env python3
# DuetOS AMD GFX9+ microcode-image fuzz seed generator.
#
# WHAT  Emits synthetic AMD `gfx_firmware_header_v1_0` images
#       past the common-32-byte-header + 44-byte v1-gfx-header
#       gates. Two seeds:
#         - v1_gfx.bin: full 44-byte gfx-v1 header + jump-table
#           that fits inside the payload (common-case shape
#           every real GFX9+ microcode image has).
#         - common_only.bin: 32-byte common header only (no v1
#           gfx fields) — exercises the side-band-image path
#           that some RLC variants follow.
#
# WHY   Without seeds the fuzzer wastes most of its budget on
#       bytes that bounce off the (size_bytes vs blob_size)
#       and (ucode_array_offset within blob) gates. Both seeds
#       satisfy the gates so the fuzzer immediately drives the
#       header self-consistency + ucode bound + jump-table
#       bound walkers.
#
# USAGE  python3 gen_amd_gfx_fw_seeds.py <out_dir>

import os
import struct
import sys


COMMON_HEADER_BYTES = 32
V1_GFX_HEADER_BYTES = 44


def make_image(header_size: int, payload: bytes, jt_offset_dwords: int = 0, jt_size_dwords: int = 0) -> bytes:
    ucode_size_bytes = len(payload)
    # Round payload up to 4 bytes if not already (parser requires
    # ucode_size_bytes to be a positive multiple of 4).
    assert ucode_size_bytes % 4 == 0
    ucode_array_offset = header_size
    size_bytes = header_size + ucode_size_bytes
    # Common-firmware-header (32 bytes).
    hdr = struct.pack(
        "<IIHHHHIIII",
        size_bytes,            # 0x00 size_bytes
        header_size,           # 0x04 header_size_bytes
        1, 0,                  # 0x08 header_version_major / minor
        9, 0,                  # 0x0C ip_version_major / minor (GFX9)
        0x01020304,            # 0x10 ucode_version
        ucode_size_bytes,      # 0x14 ucode_size_bytes
        ucode_array_offset,    # 0x18 ucode_array_offset
        0xDEADBEEF,            # 0x1C crc32 (declared, not verified)
    )
    if header_size >= V1_GFX_HEADER_BYTES:
        # v1 gfx-header tail (12 bytes): feature_version + jt_offset + jt_size
        hdr += struct.pack(
            "<III",
            0x00000001,        # 0x20 ucode_feature_version
            jt_offset_dwords,  # 0x24 jt_offset_dwords
            jt_size_dwords,    # 0x28 jt_size_dwords
        )
    assert len(hdr) == header_size, f"header size mismatch: {len(hdr)} != {header_size}"
    return hdr + payload


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/amd_gfx_fw"
    os.makedirs(out, exist_ok=True)

    # Full v1 gfx header with a 256-byte (64-dword) payload and a
    # jump-table at dwords 4..8 (well inside the payload).
    payload_dwords = 64
    payload = struct.pack("<I", 0xCAFEBABE) * payload_dwords
    open(os.path.join(out, "v1_gfx.bin"), "wb").write(
        make_image(V1_GFX_HEADER_BYTES, payload, jt_offset_dwords=4, jt_size_dwords=4))

    # 32-byte common header only — exercises the side-band-image path.
    open(os.path.join(out, "common_only.bin"), "wb").write(
        make_image(COMMON_HEADER_BYTES, payload))

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
