#!/usr/bin/env python3
# DuetOS NTFS fuzz seed generator.
#
# WHAT  Emits a structurally-valid NTFS boot sector + one valid
#       1024-byte MFT FILE record (with a resident $FILE_NAME
#       attribute) at the MFT LCN, so fuzz_ntfs gets past the
#       duetos_ntfs boot-sector parse and exercises the MFT
#       record-header + attribute walker on mutated input.
#
# WHY   Random bytes never carry the "NTFS    " OEM id + 0xAA55
#       sig + sane geometry, so without a seed the MFT/attr path
#       (the part with attribute-length / value-offset arithmetic
#       over attacker fields) is never reached. The FILE record
#       mirrors the Rust crate's make_mft_record() fixture.
#
# USAGE  python3 gen_ntfs_seeds.py <out_dir>

import os
import struct
import sys

SS = 512
NSEC = 128                       # 64 KiB image
SPC = 1                          # sectors_per_cluster
MFT_LCN = 32                     # MFT start cluster
MFT_REC_SIZE = 1024              # clusters_per_mft_record = -10 -> 2^10
ATTR_TYPE_FILE_NAME = 0x30
ATTR_TYPE_END = 0xFFFFFFFF


def boot_sector():
    s = bytearray(SS)
    s[0:3] = b"\xeb\x52\x90"
    s[3:11] = b"NTFS    "                            # OEM id (required)
    struct.pack_into("<H", s, 11, SS)                 # bytes_per_sector
    s[13] = SPC                                       # sectors_per_cluster
    struct.pack_into("<Q", s, 0x28, NSEC)             # total_sectors
    struct.pack_into("<Q", s, 0x30, MFT_LCN)          # mft_lcn
    struct.pack_into("<Q", s, 0x38, MFT_LCN + 16)     # mft_mirror_lcn
    # clusters_per_mft_record = -10 (i8) -> record size 2^10 = 1024
    s[0x40] = (256 - 10) & 0xFF
    s[0x44] = 1                                       # clusters_per_index_block
    struct.pack_into("<Q", s, 0x48, 0x0123456789ABCDEF)  # volume_serial
    s[510] = 0x55
    s[511] = 0xAA
    return bytes(s)


def mft_file_record():
    rec = bytearray(MFT_REC_SIZE)
    rec[0:4] = b"FILE"                                 # magic
    struct.pack_into("<H", rec, 4, 0x002A)             # USA offset
    struct.pack_into("<H", rec, 6, 0x0003)             # USA size
    struct.pack_into("<H", rec, 0x14, 0x0038)          # first-attribute offset
    struct.pack_into("<H", rec, 0x16, 0x0001)          # flags: in-use
    attr_off = 0x38
    struct.pack_into("<I", rec, attr_off, ATTR_TYPE_FILE_NAME)
    attr_len = 104
    struct.pack_into("<I", rec, attr_off + 4, attr_len)
    rec[attr_off + 8] = 0                              # resident
    struct.pack_into("<I", rec, attr_off + 0x10, 0x42 + 10)  # value length
    val_off = 24
    struct.pack_into("<H", rec, attr_off + 0x14, val_off)    # value offset
    body = attr_off + val_off
    rec[body + 0x40] = 5                               # name length (UTF-16 units)
    for i, ch in enumerate("DUETS"):
        struct.pack_into("<H", rec, body + 0x42 + i * 2, ord(ch))
    term = attr_off + attr_len
    struct.pack_into("<I", rec, term, ATTR_TYPE_END)   # attribute terminator
    return bytes(rec)


def build():
    img = bytearray(NSEC * SS)
    img[0:SS] = boot_sector()
    # MFT starts at LBA = mft_lcn * sectors_per_cluster.
    mft_lba = MFT_LCN * SPC
    off = mft_lba * SS
    img[off:off + MFT_REC_SIZE] = mft_file_record()
    return bytes(img)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/ntfs"
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "valid.ntfs"), "wb") as fh:
        fh.write(build())
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
