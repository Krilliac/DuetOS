# NTFS

> **Audience:** FS authors
>
> **Execution context:** Kernel — process context, polling-synchronous
> block reads
>
> **Maturity:** Read-only — probe + USA fixup + $I30 root enumeration +
> $DATA reads (resident + single-run non-resident)

## Overview

[`kernel/fs/ntfs.{h,cpp}`](../../kernel/fs/ntfs.h) reads NTFS
partitions for interoperability with Windows-formatted media. NTFS
is the "third tier" of read-only FS support after FAT32 and ext4,
and complements the native [DuetFS](DuetFS.md) for Windows-host
data exchange. It remains **read-only** — there are no write
functions, and NTFS write is explicitly not on the roadmap.

The byte-parsing layer is Rust:
[`kernel/fs/ntfs_rust/`](../../kernel/fs/ntfs_rust/src/lib.rs) is a
**production crate** (no_std), not a scaffold — it owns the
boot-sector probe, the MFT record header decode, the resident
`$FILE_NAME` walk, and the runlist (mapping-pairs) decode, all in
safe slice traversal (`ntfs.cpp:222`). The C++ wrapper keeps block
I/O, scratch buffers, the per-volume registry, the attribute-list
walk for `$DATA` / `$INDEX_ROOT`, and the UTF-16 → ASCII glyph
filter.

## What's Implemented

- **Signature probe.** Reads LBA 0, validates the literal `"NTFS    "`
  string at offset 3 and the 0x55AA boot signature at offset 510.
- **Boot-sector record.** Captures bytes-per-sector,
  sectors-per-cluster, MFT LCN, and the signed byte at offset 0x40
  that encodes either clusters-per-MFT-record (positive) or
  log2(bytes-per-record) (negative).
- **Update-sequence-array fixup.** `ApplyFixup` (`ntfs.cpp:257`)
  applies the full USA fixup to every multi-sector record before
  the bytes are trusted, so reads larger than 512 bytes are safe.
- **$MFT system-record walk.** Walks the system records — `$MFT`,
  `$MFTMirr`, `$LogFile`, `$Volume`, `$AttrDef`, `.` (root dir),
  `$Bitmap`, `$Boot`, `$BadClus`, `$Secure`, `$UpCase`, `$Extend`,
  … — validating the `'FILE'` magic and decoding `$FILE_NAME`.
- **Root-directory enumeration.** `NtfsEnumerateRoot` /
  `NtfsFindInRoot` (`ntfs.cpp:413`) walk the root dir's `$I30`
  `$INDEX_ROOT` index and decode each entry.
- **File-data reads.** `NtfsResolveData` + `NtfsReadFile`
  (`ntfs.h:166`) resolve and read a regular file's `$DATA` —
  resident values, plus a single-run non-resident value via the
  Rust runlist decoder.
- **Per-volume registry.** Up to `kMaxVolumes = 8` volumes; look
  up by index via `NtfsVolumeByIndex`.

## Known Limits / GAPs

- **Resident `$INDEX_ROOT` only.** `ntfs.h:151` — a directory whose
  `$I30` index overflows `INDEX_ROOT` into a non-resident
  `$INDEX_ALLOCATION` b-tree is only enumerated for its resident
  slice; the b-tree blocks are not walked.
- **Single-run non-resident `$DATA` only.** `ntfs.cpp:548` — the
  non-resident reader follows only the FIRST data run, and
  `ntfs.cpp:542` rejects a run larger than the single scratch
  buffer. Resident values and one-run files read fully.
- **No write path.** NTFS write is a multi-year project; we are
  not committing to it. Read-only NTFS for data import is the
  bar.
- **No reparse-point handling** (junction points, symlinks).
- **No alternate data streams** (`file.txt:hidden`).
- **No compressed / sparse / encrypted attributes;** no $LogFile
  replay; no USN journal.
- **No EFS** (Encrypted File System).

## Capability / Privilege Surface

NTFS is read-only; reads are gated by `kCapFsRead`, enforced in the
syscall layer (see [FAT32](FAT32.md#capability--privilege-surface)
for the gate locations). There is no write surface to gate.

## Related Pages

- [VFS](VFS.md)
- [Mount Registry](Mount-Registry.md) — NTFS has an `FsType` slot
  with real `lookup` ops registered (`g_ntfs_ops` → `NtfsLookup`).
  `VfsResolve` on an NTFS mount surfaces an `Ntfs`-tagged `VfsNode`
  (mount block_handle + MFT reference + size/is-dir snapshot); the
  shell read path streams it via `NtfsReadMftRecord` →
  `NtfsResolveData` → `NtfsReadFile`. Multi-component paths
  (`/sub/file`) are walked one directory record at a time via
  `NtfsFindInDir` over each record's resident `$I30` index
  (root MFT record 5 → component → descend into the child record →
  repeat); verified by the `[ntfs-selftest]` "VFS resolve
  (single + multi-component) verified" boot gate.
  `$INDEX_ALLOCATION`-spilled large directories are not walked
  (resident `$INDEX_ROOT` only, at every level).
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [GPT](GPT.md)
- [DuetFS](DuetFS.md) — the native FS NTFS-typed partitions
  contrast with.
