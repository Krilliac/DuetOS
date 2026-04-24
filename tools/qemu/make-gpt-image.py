#!/usr/bin/env python3
#
# Build a 16 MiB GPT-formatted raw disk image for the NVMe scratch
# drive that `tools/qemu/run.sh` attaches to QEMU. Layout:
#
#   LBA 0        : Protective MBR (one 0xEE partition spanning the disk)
#   LBA 1        : Primary GPT header
#   LBA 2..33    : Partition entry array (128 x 128 = 16 KiB)
#   LBA 2048..end: Data partition (Linux-filesystem type GUID).
#                  First 8 bytes = "DUETOS" marker so the kernel's
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

MARKER = b"DUETOS"

# ----- FAT32 layout written into the data partition -----------------------
# All values are sectors-within-the-partition. Partition starts at
# absolute LBA FIRST_LBA, so partition-LBA 0 == absolute LBA FIRST_LBA.
#
# Microsoft FAT32 spec minimum useful layout (15 MiB partition):
#   reserved sectors       : 32
#   FAT count              : 2
#   FAT size (each)        : 64 sectors = 8192 entries
#   sectors per cluster    : 8 (= 4 KiB clusters)
#   root dir cluster       : 2
#
# Data region (cluster N) absolute sector =
#     FIRST_LBA + reserved + num_fats*fat_size + (N-2)*sectors_per_cluster
#
# Seeds the root directory with one file, HELLO.TXT, containing a short
# ASCII string. The kernel's FAT32 self-test reads LBA 0 of the partition,
# parses the BPB, walks the root, and logs each entry — the test succeeds
# iff "HELLO   TXT" appears in that listing.

FAT_RESERVED = 32
FAT_NUM_FATS = 2
FAT_FATSZ = 64  # sectors per FAT
FAT_SPC = 8     # sectors per cluster (4 KiB)
FAT_ROOT_CLUSTER = 2
FAT_FILE_CLUSTER = 3
FAT_FILE_NAME = b"HELLO   TXT"  # 8.3, space-padded, no dot
FAT_FILE_BODY = b"hello from fat32\n"

# Subdirectory seed so the kernel's multi-level path walk has
# something to resolve. Layout:
#   /SUB/          (directory, cluster 4)
#   /SUB/INNER.TXT (file, cluster 5)
FAT_SUBDIR_CLUSTER = 4
FAT_SUBDIR_NAME = b"SUB        "
FAT_INNER_CLUSTER = 5
FAT_INNER_NAME = b"INNER   TXT"
FAT_INNER_BODY = b"inner file\n"

# Long-name seed so the kernel's LFN accumulator has a real entry
# to decode. SFN fallback is LONGFI~1.TXT; long name is
# LongFile.txt (12 chars, one LFN fragment).
FAT_LONG_CLUSTER = 6
FAT_LONG_SFN = b"LONGFI~1TXT"
FAT_LONG_LONGNAME = "LongFile.txt"
FAT_LONG_BODY = b"long filename file\n"

# Multi-cluster file so the kernel's streamed-read exercises the
# cluster-chain follow path. 6000 bytes spans clusters 7+8 at
# 4 KiB per cluster. Content is deterministic printable-ASCII:
# byte i = 0x20 + (i % 95). Self-test samples byte 0, byte 4095
# (end of first cluster) and byte 5999 (final byte).
FAT_BIG_CLUSTER = 7
FAT_BIG_SFN = b"BIG     TXT"
FAT_BIG_SIZE = 6000
FAT_BIG_BODY = bytes((0x20 + (i % 95)) for i in range(FAT_BIG_SIZE))

# Linux-ABI ELF binary. Exercises the "real binary off disk"
# path: kernel reads this file from FAT32, passes the bytes to
# SpawnElfLinux, which parses the ELF and creates a ring-3
# Linux-ABI task. Same payload as subsystems/linux/ring3_smoke.cpp
# — mmap 4 KiB, write "MOK\n" into it, write a static message,
# exit_group(0x42). Kept in the image at cluster 9 (first free
# cluster after the other seeded files).
FAT_ELF_CLUSTER = 9
FAT_ELF_SFN = b"LINUX   ELF"

# Inline machine code — byte-identical to kPayload in
# kernel/subsystems/linux/ring3_smoke.cpp. Any edit there must
# be mirrored here (the kernel and the on-disk binary are
# independent copies of the same bytes).
LINUX_ELF_PAYLOAD = bytes([
    # mmap(NULL, 4096, 3, 0x22, -1, 0)
    0xB8, 0x09, 0x00, 0x00, 0x00,            # mov eax, 9
    0x31, 0xFF,                              # xor edi, edi
    0xBE, 0x00, 0x10, 0x00, 0x00,            # mov esi, 0x1000
    0xBA, 0x03, 0x00, 0x00, 0x00,            # mov edx, 3
    0x41, 0xBA, 0x22, 0x00, 0x00, 0x00,      # mov r10d, 0x22
    0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,      # mov r8d, -1
    0x45, 0x31, 0xC9,                        # xor r9d, r9d
    0x0F, 0x05,                              # syscall
    0x49, 0x89, 0xC4,                        # mov r12, rax
    0x41, 0xC6, 0x04, 0x24, 0x4D,            # mov [r12],   'M'
    0x41, 0xC6, 0x44, 0x24, 0x01, 0x4F,      # mov [r12+1], 'O'
    0x41, 0xC6, 0x44, 0x24, 0x02, 0x4B,      # mov [r12+2], 'K'
    0x41, 0xC6, 0x44, 0x24, 0x03, 0x0A,      # mov [r12+3], '\n'
    # write(1, r12, 4)
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xBF, 0x01, 0x00, 0x00, 0x00,
    0x4C, 0x89, 0xE6,
    0xBA, 0x04, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    # write(1, msg, 13)
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xBF, 0x01, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x35, 0x15, 0x00, 0x00, 0x00,  # lea rsi, [rip+0x15]
    0xBA, 0x0D, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    # exit_group(0x42)
    0xB8, 0xE7, 0x00, 0x00, 0x00,
    0xBF, 0x42, 0x00, 0x00, 0x00,
    0x0F, 0x05,
    0x0F, 0x0B,                              # ud2
]) + b"hello fat32!\n"                       # msg (13 bytes, distinct from in-memory smoke)


def build_linux_elf():
    """Wrap LINUX_ELF_PAYLOAD in a minimal ELF64 image.

    Mirrors kernel/subsystems/linux/ring3_smoke.cpp::BuildLinuxElf:
      ehdr (64 B) + one PT_LOAD phdr (56 B) + payload.
    p_vaddr = 0x400078, p_offset = 120 — both mod 0x1000 == 120,
    so the kernel ElfLoader's alignment check passes without
    padding the file to a real 4 KiB boundary.
    """
    ehdr_size = 64
    phdr_size = 56
    p_offset = ehdr_size + phdr_size     # 120
    p_vaddr = 0x0000000000400078
    payload = LINUX_ELF_PAYLOAD
    buf = bytearray(ehdr_size + phdr_size + len(payload))

    # ehdr
    buf[0:4] = b"\x7FELF"
    buf[4] = 2                           # ELFCLASS64
    buf[5] = 1                           # ELFDATA2LSB
    buf[6] = 1                           # EV_CURRENT
    buf[7] = 0                           # ELFOSABI_SYSV
    struct.pack_into("<H", buf, 16, 2)   # e_type = ET_EXEC
    struct.pack_into("<H", buf, 18, 0x3E)# e_machine = EM_X86_64
    struct.pack_into("<I", buf, 20, 1)   # e_version
    struct.pack_into("<Q", buf, 24, p_vaddr)       # e_entry
    struct.pack_into("<Q", buf, 32, ehdr_size)     # e_phoff
    struct.pack_into("<Q", buf, 40, 0)             # e_shoff
    struct.pack_into("<I", buf, 48, 0)             # e_flags
    struct.pack_into("<H", buf, 52, ehdr_size)     # e_ehsize
    struct.pack_into("<H", buf, 54, phdr_size)     # e_phentsize
    struct.pack_into("<H", buf, 56, 1)             # e_phnum

    # phdr at offset ehdr_size
    base = ehdr_size
    struct.pack_into("<I", buf, base + 0,  1)      # p_type = PT_LOAD
    struct.pack_into("<I", buf, base + 4,  0x05)   # p_flags = PF_R | PF_X
    struct.pack_into("<Q", buf, base + 8,  p_offset)
    struct.pack_into("<Q", buf, base + 16, p_vaddr)
    struct.pack_into("<Q", buf, base + 24, p_vaddr)
    struct.pack_into("<Q", buf, base + 32, len(payload))  # p_filesz
    struct.pack_into("<Q", buf, base + 40, len(payload))  # p_memsz
    struct.pack_into("<Q", buf, base + 48, 0x1000)        # p_align

    # payload
    buf[p_offset:p_offset + len(payload)] = payload
    return bytes(buf)


FAT_ELF_BODY = build_linux_elf()
FAT_ELF_SIZE = len(FAT_ELF_BODY)


def sfn_checksum(sfn11: bytes) -> int:
    """FAT LFN 11-byte-SFN checksum (spec 7.2, Appendix A)."""
    chk = 0
    for b in sfn11:
        chk = ((chk & 1) << 7) | (chk >> 1)
        chk = (chk + b) & 0xFF
    return chk


def lfn_entry(ordinal: int, name_chunk: str, is_last: bool, chksum: int) -> bytes:
    """One 32-byte LFN entry. name_chunk is up to 13 chars; shorter
    chunks get a 0x0000 terminator + 0xFFFF padding per spec."""
    e = bytearray(32)
    e[0] = (ordinal | 0x40) if is_last else ordinal
    e[11] = 0x0F                        # LFN attr
    e[12] = 0                           # type
    e[13] = chksum
    e[26] = 0                           # cluster must be 0 in LFN
    e[27] = 0
    # Fill 13 UTF-16 code units at offsets (1..10), (14..25), (28..31).
    offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
    padded = False
    for i, off in enumerate(offsets):
        if i < len(name_chunk):
            wc = ord(name_chunk[i])
            e[off] = wc & 0xFF
            e[off + 1] = (wc >> 8) & 0xFF
        elif not padded and i == len(name_chunk):
            e[off] = 0x00
            e[off + 1] = 0x00
            padded = True
        else:
            e[off] = 0xFF
            e[off + 1] = 0xFF
    return bytes(e)


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
    name_utf16 = "DUETOS-TEST".encode("utf-16-le")
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


def build_fat32(part_sector_count: int) -> bytearray:
    """Build a FAT32 region `part_sector_count` sectors long.

    Returns a bytearray exactly `part_sector_count * SECTOR` bytes. Writes:
      - Boot sector (BPB) at sector 0 (+ backup at sector 6)
      - FSInfo at sector 1
      - FAT1 + FAT2 starting at sector 32
      - Root directory in cluster 2 with ONE file entry (HELLO.TXT)
      - File data at cluster 3
    """
    buf = bytearray(part_sector_count * SECTOR)

    # BPB.
    bs = bytearray(SECTOR)
    bs[0:3] = b"\xEB\x58\x90"          # JMP short + NOP
    bs[3:11] = b"DUETOS  "             # OEM name (8 bytes, space-padded)
    struct.pack_into("<H", bs, 11, SECTOR)          # bytes_per_sector
    bs[13] = FAT_SPC                                # sectors_per_cluster
    struct.pack_into("<H", bs, 14, FAT_RESERVED)    # reserved_sectors
    bs[16] = FAT_NUM_FATS                           # num_fats
    struct.pack_into("<H", bs, 17, 0)               # root_entries (0 for FAT32)
    struct.pack_into("<H", bs, 19, 0)               # total_sectors_16 (0 for FAT32)
    bs[21] = 0xF8                                   # media
    struct.pack_into("<H", bs, 22, 0)               # fat_size_16 (0 for FAT32)
    struct.pack_into("<H", bs, 24, 32)              # sectors_per_track (legacy)
    struct.pack_into("<H", bs, 26, 64)              # num_heads (legacy)
    struct.pack_into("<I", bs, 28, 0)               # hidden_sectors
    struct.pack_into("<I", bs, 32, part_sector_count)   # total_sectors_32
    struct.pack_into("<I", bs, 36, FAT_FATSZ)       # fat_size_32
    struct.pack_into("<H", bs, 40, 0)               # ext_flags
    struct.pack_into("<H", bs, 42, 0)               # fs_version
    struct.pack_into("<I", bs, 44, FAT_ROOT_CLUSTER)    # root_cluster
    struct.pack_into("<H", bs, 48, 1)               # fs_info sector
    struct.pack_into("<H", bs, 50, 6)               # backup_boot sector
    # (reserved 52..63)
    bs[64] = 0x80                                   # drive_number
    bs[65] = 0                                      # reserved
    bs[66] = 0x29                                   # boot_sig
    struct.pack_into("<I", bs, 67, 0xCAFEBABE)      # volume_id
    bs[71:82] = b"DUETOS     "                    # volume_label (11 bytes, space-padded)
    bs[82:90] = b"FAT32   "                         # fs_type (8 bytes)
    bs[510] = 0x55
    bs[511] = 0xAA
    buf[0:SECTOR] = bs
    buf[6 * SECTOR:7 * SECTOR] = bs   # backup

    # FSInfo: lead sig 0x41615252 @ 0, struct sig 0x61417272 @ 484,
    # trail sig 0xAA550000 @ 508. Free count / next free = 0xFFFFFFFF (unknown).
    fsinfo = bytearray(SECTOR)
    struct.pack_into("<I", fsinfo, 0,   0x41615252)
    struct.pack_into("<I", fsinfo, 484, 0x61417272)
    struct.pack_into("<I", fsinfo, 488, 0xFFFFFFFF)
    struct.pack_into("<I", fsinfo, 492, 0xFFFFFFFF)
    struct.pack_into("<I", fsinfo, 508, 0xAA550000)
    buf[1 * SECTOR:2 * SECTOR] = fsinfo

    # FAT table: 4 bytes per entry, little-endian, top 4 bits reserved (0).
    # Entry 0 = media | 0x0FFFFF00, entry 1 = 0x0FFFFFFF (dirty/clean trailer),
    # entry 2 = 0x0FFFFFFF (EOC for the one-cluster root directory),
    # entry 3 = 0x0FFFFFFF (EOC for the one-cluster test file).
    fat = bytearray(FAT_FATSZ * SECTOR)
    struct.pack_into("<I", fat, 0 * 4, 0x0FFFFFF8)
    struct.pack_into("<I", fat, 1 * 4, 0x0FFFFFFF)
    struct.pack_into("<I", fat, 2 * 4, 0x0FFFFFFF)  # root dir EOC
    struct.pack_into("<I", fat, 3 * 4, 0x0FFFFFFF)  # HELLO.TXT EOC
    struct.pack_into("<I", fat, 4 * 4, 0x0FFFFFFF)  # /SUB directory EOC
    struct.pack_into("<I", fat, 5 * 4, 0x0FFFFFFF)  # /SUB/INNER.TXT EOC
    struct.pack_into("<I", fat, 6 * 4, 0x0FFFFFFF)  # /LongFile.txt EOC
    struct.pack_into("<I", fat, 7 * 4, 8)           # /BIG.TXT cluster 7 -> 8
    struct.pack_into("<I", fat, 8 * 4, 0x0FFFFFFF)  # /BIG.TXT EOC
    struct.pack_into("<I", fat, 9 * 4, 0x0FFFFFFF)  # /LINUX.ELF EOC
    fat1_off = FAT_RESERVED * SECTOR
    fat2_off = fat1_off + FAT_FATSZ * SECTOR
    buf[fat1_off:fat1_off + len(fat)] = fat
    buf[fat2_off:fat2_off + len(fat)] = fat

    # Root directory (cluster 2). One 32-byte SFN entry.
    data_start_sector = FAT_RESERVED + FAT_NUM_FATS * FAT_FATSZ
    root_off = data_start_sector * SECTOR
    entry = bytearray(32)
    entry[0:11] = FAT_FILE_NAME            # 8.3 short name
    entry[11] = 0x20                       # ATTR_ARCHIVE
    entry[12] = 0                          # NTRes
    entry[13] = 0                          # CrtTimeTenth
    struct.pack_into("<H", entry, 14, 0)   # creation time
    struct.pack_into("<H", entry, 16, 0)   # creation date
    struct.pack_into("<H", entry, 18, 0)   # last access date
    struct.pack_into("<H", entry, 20, 0)   # first_cluster_high (= 0; cluster 3 fits in low)
    struct.pack_into("<H", entry, 22, 0)   # write time
    struct.pack_into("<H", entry, 24, 0)   # write date
    struct.pack_into("<H", entry, 26, FAT_FILE_CLUSTER)  # first_cluster_low
    struct.pack_into("<I", entry, 28, len(FAT_FILE_BODY))
    buf[root_off:root_off + 32] = entry

    # File data at cluster 3.
    file_cluster_sector = data_start_sector + (FAT_FILE_CLUSTER - 2) * FAT_SPC
    file_off = file_cluster_sector * SECTOR
    buf[file_off:file_off + len(FAT_FILE_BODY)] = FAT_FILE_BODY

    # /SUB directory entry in the root.
    sub_entry = bytearray(32)
    sub_entry[0:11] = FAT_SUBDIR_NAME
    sub_entry[11] = 0x10   # ATTR_DIRECTORY
    struct.pack_into("<H", sub_entry, 20, 0)                       # cluster high
    struct.pack_into("<H", sub_entry, 26, FAT_SUBDIR_CLUSTER)      # cluster low
    struct.pack_into("<I", sub_entry, 28, 0)                       # size (dirs=0)
    buf[root_off + 32:root_off + 64] = sub_entry

    # /SUB cluster: has two synthetic entries ("." and "..") and
    # the real INNER.TXT. Real FAT32 requires "." + ".." in every
    # non-root directory — without them, Windows treats the dir
    # as corrupt. Our walker skips attr & kAttrDirectory cluster 0
    # sentinels naturally, so they don't fight the enumerator.
    sub_cluster_sector = data_start_sector + (FAT_SUBDIR_CLUSTER - 2) * FAT_SPC
    sub_off = sub_cluster_sector * SECTOR

    dot = bytearray(32)
    dot[0:11] = b".          "
    dot[11] = 0x10
    struct.pack_into("<H", dot, 26, FAT_SUBDIR_CLUSTER)            # "." = self
    buf[sub_off:sub_off + 32] = dot

    dotdot = bytearray(32)
    dotdot[0:11] = b"..         "
    dotdot[11] = 0x10
    struct.pack_into("<H", dotdot, 26, 0)                          # ".." at root = 0
    buf[sub_off + 32:sub_off + 64] = dotdot

    inner = bytearray(32)
    inner[0:11] = FAT_INNER_NAME
    inner[11] = 0x20
    struct.pack_into("<H", inner, 20, 0)
    struct.pack_into("<H", inner, 26, FAT_INNER_CLUSTER)
    struct.pack_into("<I", inner, 28, len(FAT_INNER_BODY))
    buf[sub_off + 64:sub_off + 96] = inner

    # /SUB/INNER.TXT data at cluster 5.
    inner_cluster_sector = data_start_sector + (FAT_INNER_CLUSTER - 2) * FAT_SPC
    inner_off = inner_cluster_sector * SECTOR
    buf[inner_off:inner_off + len(FAT_INNER_BODY)] = FAT_INNER_BODY

    # LFN + SFN pair for LongFile.txt. LFN fragment comes FIRST in
    # physical order (highest ordinal), then the SFN. Name is 12
    # chars, fits in a single LFN entry at ordinal 1 | 0x40.
    chk = sfn_checksum(FAT_LONG_SFN)
    lfn = lfn_entry(1, FAT_LONG_LONGNAME, True, chk)
    buf[root_off + 64:root_off + 96] = lfn

    sfn = bytearray(32)
    sfn[0:11] = FAT_LONG_SFN
    sfn[11] = 0x20
    struct.pack_into("<H", sfn, 20, 0)
    struct.pack_into("<H", sfn, 26, FAT_LONG_CLUSTER)
    struct.pack_into("<I", sfn, 28, len(FAT_LONG_BODY))
    buf[root_off + 96:root_off + 128] = sfn

    # /LongFile.txt data at cluster 6.
    long_cluster_sector = data_start_sector + (FAT_LONG_CLUSTER - 2) * FAT_SPC
    long_off = long_cluster_sector * SECTOR
    buf[long_off:long_off + len(FAT_LONG_BODY)] = FAT_LONG_BODY

    # BIG.TXT SFN entry in the root (4th non-dot entry).
    big_sfn = bytearray(32)
    big_sfn[0:11] = FAT_BIG_SFN
    big_sfn[11] = 0x20
    struct.pack_into("<H", big_sfn, 20, 0)
    struct.pack_into("<H", big_sfn, 26, FAT_BIG_CLUSTER)
    struct.pack_into("<I", big_sfn, 28, FAT_BIG_SIZE)
    buf[root_off + 128:root_off + 160] = big_sfn

    # BIG.TXT data spans clusters 7 and 8.
    big_cluster_sector = data_start_sector + (FAT_BIG_CLUSTER - 2) * FAT_SPC
    big_off = big_cluster_sector * SECTOR
    buf[big_off:big_off + len(FAT_BIG_BODY)] = FAT_BIG_BODY

    # LINUX.ELF SFN entry in the root (5th non-dot entry).
    elf_sfn = bytearray(32)
    elf_sfn[0:11] = FAT_ELF_SFN
    elf_sfn[11] = 0x20
    struct.pack_into("<H", elf_sfn, 20, 0)
    struct.pack_into("<H", elf_sfn, 26, FAT_ELF_CLUSTER)
    struct.pack_into("<I", elf_sfn, 28, FAT_ELF_SIZE)
    buf[root_off + 160:root_off + 192] = elf_sfn

    # LINUX.ELF data at cluster 9.
    elf_cluster_sector = data_start_sector + (FAT_ELF_CLUSTER - 2) * FAT_SPC
    elf_off = elf_cluster_sector * SECTOR
    buf[elf_off:elf_off + FAT_ELF_SIZE] = FAT_ELF_BODY

    return buf


def main(out_path: str) -> None:
    img = bytearray(TOTAL_SECTORS * SECTOR)
    img[0:SECTOR] = build_pmbr()

    entries = build_entries()
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF

    hdr = build_header(entries_crc)
    img[1 * SECTOR:1 * SECTOR + len(hdr)] = hdr
    img[2 * SECTOR:2 * SECTOR + len(entries)] = entries

    # Format the data partition as FAT32. Blanks the DUETOS marker that
    # used to live at byte 0 of the partition — the BPB lives there now;
    # the kernel no longer needs the raw marker since it can parse the FS.
    part_sectors = LAST_LBA - FIRST_LBA + 1
    fat_region = build_fat32(part_sectors)
    img[FIRST_LBA * SECTOR:FIRST_LBA * SECTOR + len(fat_region)] = fat_region

    with open(out_path, "wb") as f:
        f.write(img)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: make-gpt-image.py <output-path>", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])
