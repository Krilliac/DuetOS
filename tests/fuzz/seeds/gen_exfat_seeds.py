#!/usr/bin/env python3
# DuetOS exFAT fuzz seed generator.
#
# WHAT  Emits a structurally-valid exFAT boot sector + reachable
#       (empty) root directory so fuzz_exfat gets past the
#       duetos_exfat Rust boot-sector parse + geometry derive and
#       exercises the C++ root-dir read + the Rust dirent-set
#       decoder on mutated input.
#
# WHY   Random bytes never carry the "EXFAT   " OEM id + 0xAA55
#       sig + the sane shift fields, so without a seed the
#       geometry / dirent path is never reached.
#
# USAGE  python3 gen_exfat_seeds.py <out_dir>

import os
import struct
import sys

SS = 512
NSEC = 128                       # 64 KiB image
CLUSTER_HEAP_OFF = 64            # sectors
ROOT_CLUSTER = 2                 # first data cluster


def boot_sector():
    s = bytearray(SS)
    s[0:3] = b"\xeb\x76\x90"                       # jump boot
    s[3:11] = b"EXFAT   "                           # OEM id (required)
    struct.pack_into("<Q", s, 0x40, 0)              # partition_offset
    struct.pack_into("<Q", s, 0x48, NSEC)           # volume_length (sectors)
    struct.pack_into("<I", s, 0x50, 32)             # fat_offset (sectors)
    struct.pack_into("<I", s, 0x54, 16)             # fat_length
    struct.pack_into("<I", s, 0x58, CLUSTER_HEAP_OFF)  # cluster_heap_offset
    struct.pack_into("<I", s, 0x5C, 32)             # cluster_count
    struct.pack_into("<I", s, 0x60, ROOT_CLUSTER)   # root_dir_first_cluster
    struct.pack_into("<I", s, 0x64, 0x12345678)     # volume_serial
    s[0x6C] = 9                                      # bytes_per_sector_shift (512)
    s[0x6D] = 0                                      # sectors_per_cluster_shift (1)
    s[0x6E] = 1                                      # number_of_fats
    s[510] = 0x55
    s[511] = 0xAA
    return bytes(s)


def root_dirent_set():
    # FILE (0x85) + StreamExt (0xC0) + FileName (0xC1) — the
    # canonical 3-slot set, so the Rust dirent decoder's secondary
    # walk + name accumulation is exercised, not just the
    # empty-dir early-out.
    blk = bytearray(SS)
    file_e = bytearray(32)
    file_e[0] = 0x85           # EXFAT_DIRENT_FILE, in-use (bit7 set)
    file_e[1] = 2              # secondary_count: StreamExt + 1 FileName
    file_e[4] = 0x20           # attributes (archive)
    stream_e = bytearray(32)
    stream_e[0] = 0xC0         # EXFAT_DIRENT_STREAM_EXT
    stream_e[0x03] = 4         # name_length (UTF-16 units)
    struct.pack_into("<I", stream_e, 0x14, 0)   # first_cluster
    struct.pack_into("<Q", stream_e, 0x18, 0)   # size_bytes
    name_e = bytearray(32)
    name_e[0] = 0xC1           # EXFAT_DIRENT_FILE_NAME
    name_e[2:10] = "test".encode("utf-16-le")
    blk[0:32] = file_e
    blk[32:64] = stream_e
    blk[64:96] = name_e
    # blk[96] stays 0x00 -> end of directory
    return bytes(blk)


def build(rich):
    img = bytearray(NSEC * SS)
    img[0:SS] = boot_sector()
    # Root dir lives at cluster_heap_offset + (root-2)*spc = sector
    # CLUSTER_HEAP_OFF. Empty (zero-filled) seed = EOD at byte 0;
    # the rich seed carries a real FILE/Stream/Name dirent set.
    if rich:
        off = CLUSTER_HEAP_OFF * SS
        img[off:off + SS] = root_dirent_set()
    return bytes(img)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/exfat"
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "empty.exfat"), "wb") as fh:
        fh.write(build(rich=False))
    with open(os.path.join(out, "withfile.exfat"), "wb") as fh:
        fh.write(build(rich=True))
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
