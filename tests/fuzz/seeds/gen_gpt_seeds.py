#!/usr/bin/env python3
# DuetOS GPT fuzz seed generator.
#
# WHAT  Emits a structurally-valid GPT disk image (Protective MBR
#       + primary header with correct CRC32 + 128x128 entry array
#       with correct CRC32 + one real partition) so fuzz_gpt gets
#       past the "EFI PART" magic and the two CRC gates and
#       actually exercises gpt.cpp's partition-entry loop and
#       LBA-range validation on mutated input.
#
# WHY   Without a seed every random input fails the 0xAA55 / 0xEE
#       PMBR check or the header CRC, so the entry parser is never
#       reached. zlib.crc32 is CRC32-IEEE, the same the kernel
#       validates against (gpt.h §"CRC32-IEEE validation").
#
# USAGE  python3 gen_gpt_seeds.py <out_dir>

import os
import struct
import sys
import zlib

SS = 512               # sector size the fuzz block shim reports
NSEC = 128             # total sectors in the seed disk (64 KiB)
HDR_SIZE = 92
ENTRY_COUNT = 128
ENTRY_SIZE = 128
ENTRIES_BYTES = ENTRY_COUNT * ENTRY_SIZE  # 16384 = 32 sectors
SIG = b"EFI PART"
REV = 0x00010000


def pmbr():
    s = bytearray(SS)
    # One protective entry at offset 446: type byte (+4) = 0xEE.
    s[446 + 4] = 0xEE
    struct.pack_into("<I", s, 446 + 8, 1)            # first LBA
    struct.pack_into("<I", s, 446 + 12, NSEC - 1)    # sector count
    s[510] = 0x55
    s[511] = 0xAA
    return bytes(s)


def entry_array():
    buf = bytearray(ENTRIES_BYTES)
    # One real partition in slot 0: nonzero type GUID, in-range LBAs.
    type_guid = bytes(range(1, 17))
    uniq_guid = bytes(range(17, 33))
    e = bytearray(ENTRY_SIZE)
    e[0:16] = type_guid
    e[16:32] = uniq_guid
    struct.pack_into("<Q", e, 32, 34)            # first_lba
    struct.pack_into("<Q", e, 40, NSEC - 34)     # last_lba (< NSEC)
    struct.pack_into("<Q", e, 48, 0)             # attributes
    e[56:56 + 8] = "part0".encode("utf-16-le").ljust(8, b"\0")
    buf[0:ENTRY_SIZE] = e
    return bytes(buf)


def header(entries_crc):
    h = bytearray(HDR_SIZE)
    h[0:8] = SIG
    struct.pack_into("<I", h, 8, REV)
    struct.pack_into("<I", h, 12, HDR_SIZE)
    struct.pack_into("<I", h, 16, 0)             # header_crc32 (zeroed for calc)
    struct.pack_into("<I", h, 20, 0)             # reserved
    struct.pack_into("<Q", h, 24, 1)             # my_lba
    struct.pack_into("<Q", h, 32, NSEC - 1)      # alternate_lba
    struct.pack_into("<Q", h, 40, 34)            # first_usable_lba
    struct.pack_into("<Q", h, 48, NSEC - 34)     # last_usable_lba (< NSEC)
    h[56:72] = bytes(range(33, 49))              # disk_guid
    struct.pack_into("<Q", h, 72, 2)             # partition_entry_lba
    struct.pack_into("<I", h, 80, ENTRY_COUNT)   # num_partition_entries
    struct.pack_into("<I", h, 84, ENTRY_SIZE)    # partition_entry_size
    struct.pack_into("<I", h, 88, entries_crc)   # partition_entries_crc32
    hcrc = zlib.crc32(bytes(h)) & 0xFFFFFFFF     # crc field already zero
    struct.pack_into("<I", h, 16, hcrc)
    return bytes(h)


def build():
    img = bytearray(NSEC * SS)
    ents = entry_array()
    ecrc = zlib.crc32(ents) & 0xFFFFFFFF
    hdr = header(ecrc)
    img[0:SS] = pmbr()
    img[SS:SS + HDR_SIZE] = hdr           # LBA 1
    img[2 * SS:2 * SS + len(ents)] = ents  # LBA 2..33
    return bytes(img)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/gpt"
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "valid.gpt"), "wb") as fh:
        fh.write(build())
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
