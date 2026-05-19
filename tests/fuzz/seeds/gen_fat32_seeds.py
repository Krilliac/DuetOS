#!/usr/bin/env python3
# DuetOS FAT32 fuzz seed generator.
#
# WHAT  Emits a structurally-valid FAT32 volume image so fuzz_fat32
#       gets past the BPB sanity gate (0xAA55 sig, "FAT32" marker,
#       512-B sectors, non-zero geometry, root_cluster >= 2) and
#       actually exercises gpt.cpp's... err, fat32.cpp's FAT-chain
#       walk + root-directory snapshot loop on mutated input.
#
# WHY   Random bytes never form a valid BPB, so without a seed the
#       FAT/dir walker (the part with cluster-index arithmetic over
#       attacker offsets) is never reached.
#
# USAGE  python3 gen_fat32_seeds.py <out_dir>

import os
import struct
import sys

SS = 512
RESERVED = 32
NUM_FATS = 2
FAT_SECTORS = 1
ROOT_CLUSTER = 2
NSEC = 64                       # 32 KiB image
DATA_START = RESERVED + NUM_FATS * FAT_SECTORS  # 34
EOC = 0x0FFFFFFF


def boot_sector():
    s = bytearray(SS)
    s[0:3] = b"\xeb\x58\x90"                      # jmp + nop
    s[3:11] = b"DUETOS  "                          # OEM
    struct.pack_into("<H", s, 11, SS)              # bytes_per_sector
    s[13] = 1                                      # sectors_per_cluster
    struct.pack_into("<H", s, 14, RESERVED)        # reserved_sectors
    s[16] = NUM_FATS                               # num_fats
    struct.pack_into("<H", s, 17, 0)               # root entries (0 on FAT32)
    struct.pack_into("<H", s, 19, 0)               # total16 (0 -> use total32)
    s[21] = 0xF8                                   # media
    struct.pack_into("<I", s, 32, NSEC)            # total_sectors_32
    struct.pack_into("<I", s, 36, FAT_SECTORS)     # fat_size_32
    struct.pack_into("<I", s, 44, ROOT_CLUSTER)    # root_cluster
    s[82:90] = b"FAT32   "                          # fs type marker
    s[510] = 0x55
    s[511] = 0xAA
    return bytes(s)


def fat_sector():
    f = bytearray(SS)
    struct.pack_into("<I", f, 0, 0x0FFFFFF8)        # FAT[0] media
    struct.pack_into("<I", f, 4, EOC)               # FAT[1]
    struct.pack_into("<I", f, 8, EOC)               # FAT[2] = root, single cluster
    return bytes(f)


def root_dir_cluster():
    # One short 8.3 entry then an end-of-directory marker (0x00).
    c = bytearray(SS)
    c[0:11] = b"HELLO   TXT"
    c[11] = 0x20                                    # ATTR_ARCHIVE
    struct.pack_into("<H", c, 26, 0)                # first cluster lo
    struct.pack_into("<I", c, 28, 0)                # file size
    # c[32] stays 0x00 -> end of directory
    return bytes(c)


def build():
    img = bytearray(NSEC * SS)
    img[0:SS] = boot_sector()
    img[RESERVED * SS:(RESERVED + 1) * SS] = fat_sector()                  # FAT0 @ LBA 32
    img[(RESERVED + 1) * SS:(RESERVED + 2) * SS] = fat_sector()            # FAT1 @ LBA 33
    img[DATA_START * SS:(DATA_START + 1) * SS] = root_dir_cluster()        # cluster 2 @ LBA 34
    return bytes(img)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/fat32"
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "valid.fat32"), "wb") as fh:
        fh.write(build())
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
