# NTFS

> **Audience:** FS authors
>
> **Execution context:** Kernel — process context, polling-synchronous
> block reads
>
> **Maturity:** v0 — probe + $MFT system-record walk (records 0..15);
> root-directory enumeration is the next slice

## Overview

[`kernel/fs/ntfs.{h,cpp}`](../../kernel/fs/ntfs.h) reads NTFS
partitions for interoperability with Windows-formatted media. NTFS
is the "third tier" of read-only FS support after FAT32 and ext4,
and complements the native [DuetFS](DuetFS.md) for Windows-host
data exchange. A parallel Rust scaffold lives in
[`kernel/fs/ntfs_rust/`](../../kernel/fs/ntfs_rust/src/lib.rs) for
future format-sensitive paths.

## What Lives in v0

- **Signature probe.** Reads LBA 0, validates the literal `"NTFS    "`
  string at offset 3 and the 0x55AA boot signature at offset 510.
- **Boot-sector record.** Captures bytes-per-sector,
  sectors-per-cluster, MFT LCN, and the signed byte at offset 0x40
  that encodes either clusters-per-MFT-record (positive) or
  log2(bytes-per-record) (negative).
- **$MFT system-record walk.** Walks the first
  `kMaxMftRecords = 16` records — `$MFT`, `$MFTMirr`, `$LogFile`,
  `$Volume`, `$AttrDef`, `.` (root dir), `$Bitmap`, `$Boot`,
  `$BadClus`, `$Secure`, `$UpCase`, `$Extend`, … — and for each
  validates the `'FILE'` magic and decodes the first
  `$FILE_NAME` (attribute type 0x30) from UTF-16 to ASCII for
  diagnostic logging.
- **Per-volume registry.** Up to `kMaxVolumes = 8` volumes; look
  up by index via `NtfsVolumeByIndex`.

## Why Stop at 16 Records

Records 0..15 are the system files. Beyond record 15 you have to
follow `$INDEX_ROOT` and `$INDEX_ALLOCATION` to enumerate the root
directory — and `$INDEX_ALLOCATION` reads cross sector boundaries
that need NTFS's **update-sequence-array fixup** to be correct. v0
deliberately stays below that line: every read so far lives
inside a single 512-byte sector where fixup hasn't run, so we can
read raw bytes safely.

The next slice lands fixup, then $INDEX_ROOT / $INDEX_ALLOCATION
traversal, then $DATA attribute reads.

## Known Limits / GAPs

- **No update-sequence-array fixup.** Required before any read
  larger than 512 bytes (i.e. `$INDEX_ALLOCATION`, `$DATA` runs).
- **No root-directory enumeration.** `$INDEX_ROOT` /
  `$INDEX_ALLOCATION` traversal is the gating work.
- **No file-data reads.** Once fixup + index traversal land, the
  $DATA run list reader is the next piece.
- **No write path.** NTFS write is a multi-year project; we are
  not committing to it. Read-only NTFS for data import is the
  bar.
- **No reparse-point handling** (junction points, symlinks).
- **No alternate data streams** (`file.txt:hidden`).
- **No compressed / sparse / encrypted attributes;** no $LogFile
  replay; no USN journal.
- **No EFS** (Encrypted File System).

## Related Pages

- [VFS](VFS.md)
- [Mount Registry](Mount-Registry.md) — NTFS has a slot reserved
  in the per-FsType vtable; lookup is `nullptr` until reads land.
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [GPT](GPT.md)
- [DuetFS](DuetFS.md) — the native FS NTFS-typed partitions
  contrast with.
