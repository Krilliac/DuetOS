#!/usr/bin/env python3
#
# Build a 16 MiB GPT-formatted raw disk image for the NVMe scratch
# drive that `tools/qemu/run.sh` attaches to QEMU. Layout:
#
#   LBA 0        : Protective MBR (one 0xEE partition spanning the disk)
#   LBA 1        : Primary GPT header
#   LBA 2..33    : Partition entry array (128 x 128 = 16 KiB)
#   LBA 2048..end: Data partition (Linux-filesystem type GUID).
#                  First 8 bytes = "CUSTOMOS" marker so the kernel's
#                  post-GPT probe has a well-known string to assert.
#   last-33..    : (not written) backup GPT header + entries.
#
# CRCs are IEEE 802.3 (the Python `zlib.crc32` default), which matches
# what the kernel's `fs/gpt::Crc32` computes.
#
# Invocation:
#   tools/qemu/make-gpt-image.py <output-path>

import struct
import sys
import uuid
import zlib

SECTOR = 512
TOTAL_SECTORS = 32768  # 16 MiB
FIRST_LBA = 2048       # 1 MiB alignment, the conventional start
LAST_LBA = TOTAL_SECTORS - 34  # leave room for backup GPT (33 sectors)

# Stable GUIDs so diffs stay deterministic across rebuilds.
DISK_GUID = uuid.UUID("AABBCCDD-EEFF-1122-3344-556677889900")
PART_GUID = uuid.UUID("12345678-1234-5678-9ABC-DEF012345678")
# Linux filesystem data type GUID (not ESP — we want a plain data part).
PART_TYPE = uuid.UUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4")

MARKER = b"CUSTOMOS"


def build_pmbr() -> bytearray:
    sec = bytearray(SECTOR)
    # Single partition entry at offset 446, type 0xEE, spanning LBA 1..end.
    sec[446 + 0] = 0x00                             # boot indicator
    sec[446 + 1:446 + 4] = b"\x00\x02\x00"          # CHS start
    sec[446 + 4] = 0xEE                             # GPT protective
    sec[446 + 5:446 + 8] = b"\xff\xff\xff"          # CHS end
    struct.pack_into("<I", sec, 446 + 8, 1)         # LBA start
    struct.pack_into(
        "<I", sec, 446 + 12, min(TOTAL_SECTORS - 1, 0xFFFFFFFF)
    )
    sec[510] = 0x55
    sec[511] = 0xAA
    return sec


def build_entries() -> bytearray:
    entries = bytearray(128 * 128)
    entry = bytearray(128)
    entry[0:16] = PART_TYPE.bytes_le
    entry[16:32] = PART_GUID.bytes_le
    struct.pack_into("<Q", entry, 32, FIRST_LBA)
    struct.pack_into("<Q", entry, 40, LAST_LBA)
    struct.pack_into("<Q", entry, 48, 0)            # attrs
    name_utf16 = "CUSTOMOS-TEST".encode("utf-16-le")
    entry[56:56 + len(name_utf16)] = name_utf16
    entries[0:128] = entry
    return entries


def build_header(entries_crc: int) -> bytearray:
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 8, 0x00010000)       # revision 1.0
    struct.pack_into("<I", hdr, 12, 92)              # header size
    struct.pack_into("<I", hdr, 16, 0)               # CRC (patched)
    struct.pack_into("<I", hdr, 20, 0)               # reserved
    struct.pack_into("<Q", hdr, 24, 1)               # my_lba
    struct.pack_into("<Q", hdr, 32, TOTAL_SECTORS - 1)   # alternate_lba
    struct.pack_into("<Q", hdr, 40, 34)              # first_usable
    struct.pack_into("<Q", hdr, 48, TOTAL_SECTORS - 34)  # last_usable
    hdr[56:72] = DISK_GUID.bytes_le
    struct.pack_into("<Q", hdr, 72, 2)               # entry_array LBA
    struct.pack_into("<I", hdr, 80, 128)             # num entries
    struct.pack_into("<I", hdr, 84, 128)             # entry size
    struct.pack_into("<I", hdr, 88, entries_crc)
    crc = zlib.crc32(hdr) & 0xFFFFFFFF
    struct.pack_into("<I", hdr, 16, crc)
    return hdr


def main(out_path: str) -> None:
    img = bytearray(TOTAL_SECTORS * SECTOR)
    img[0:SECTOR] = build_pmbr()

    entries = build_entries()
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF

    hdr = build_header(entries_crc)
    img[1 * SECTOR:1 * SECTOR + len(hdr)] = hdr
    img[2 * SECTOR:2 * SECTOR + len(entries)] = entries

    # Marker at the first LBA of the data partition.
    img[FIRST_LBA * SECTOR:FIRST_LBA * SECTOR + len(MARKER)] = MARKER

    with open(out_path, "wb") as f:
        f.write(img)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: make-gpt-image.py <output-path>", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])
