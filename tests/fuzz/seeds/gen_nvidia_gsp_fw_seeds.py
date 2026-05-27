#!/usr/bin/env python3
# DuetOS NVIDIA GSP firmware-image fuzz seed generator.
#
# WHAT  Emits synthetic GSP container images past the 4-byte
#       bin_magic gate (0x10de) + 4-byte bin_ver gate (1) +
#       header_offset == 24 gate. Three seeds:
#         - turing_ga100.bin: 76-byte inner descriptor +
#           ELF-magic-prefixed payload (TU10x / GA100 class).
#         - ga102_plus.bin:   84-byte inner descriptor +
#           ELF-magic-prefixed payload (GA102+ / Ada / etc.).
#         - non_elf.bin:      76-byte descriptor + payload
#           that does NOT start with ELF magic — exercises
#           the `payload_looks_elf == false` branch the
#           parser must accept as still-valid.
#
# WHY   The container layout is 4 nested length-prefix gates:
#       magic + version + header_offset + data_offset/size.
#       Random mutation can't hit the 0x10de magic in any
#       reasonable budget; seeded coverage gets the
#       descriptor-classification + payload-bounds walker
#       exercised on cycle 1.
#
# USAGE  python3 gen_nvidia_gsp_fw_seeds.py <out_dir>

import os
import struct
import sys


HEADER_BYTES = 24
DESC_BYTES_TURING = 76
DESC_BYTES_GA102 = 84
MAGIC = 0x10DE


def make_image(desc_bytes: int, payload: bytes) -> bytes:
    header_offset = HEADER_BYTES
    data_offset = header_offset + desc_bytes
    data_size = len(payload)
    # Total = header + descriptor + payload, rounded up to 256.
    total = data_offset + data_size
    total_padded = (total + 0xFF) & ~0xFF
    hdr = struct.pack("<IIIIII",
                      MAGIC,         # bin_magic
                      1,             # bin_ver
                      total_padded,  # bin_size
                      header_offset, # header_offset
                      data_offset,   # data_offset
                      data_size)     # data_size
    # Descriptor: opaque payload of `desc_bytes` zero bytes.
    desc = b"\x00" * desc_bytes
    blob = hdr + desc + payload
    # Pad up to the declared total_padded so the parser's
    # `data_offset + data_size <= blob_size` check passes
    # against the actual blob length.
    blob += b"\x00" * (total_padded - len(blob))
    return blob


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/nvidia_gsp_fw"
    os.makedirs(out, exist_ok=True)

    # ELF-magic-prefixed payload — what real GSP images carry.
    elf_payload = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 200

    # Turing / GA100 (76-byte descriptor).
    open(os.path.join(out, "turing_ga100.bin"), "wb").write(
        make_image(DESC_BYTES_TURING, elf_payload))

    # GA102+ / Ada / Hopper / Blackwell (84-byte descriptor).
    open(os.path.join(out, "ga102_plus.bin"), "wb").write(
        make_image(DESC_BYTES_GA102, elf_payload))

    # Non-ELF payload — exercises payload_looks_elf == false branch.
    non_elf = b"COMPRESSED" + b"\x00" * 200
    open(os.path.join(out, "non_elf.bin"), "wb").write(
        make_image(DESC_BYTES_TURING, non_elf))

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
