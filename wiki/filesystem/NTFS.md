# NTFS

> **Audience:** FS authors
>
> **Execution context:** Kernel — process context
>
> **Maturity:** Read-only, work in progress

## Overview

`kernel/fs/ntfs/` reads NTFS partitions for interoperability with
Windows-formatted media. NTFS is the "third tier" of read-only FS
support after FAT32 and ext4.

## Status

Read-only path is in progress. The MFT (Master File Table) parser is
the gating component — once it can resolve a file record by inode
number, the per-attribute decoders (`$DATA`, `$INDEX_ROOT`,
`$INDEX_ALLOCATION`) plug into the same VFS surface FAT32 and ext4
already use.

## Known Limits / GAPs

- **No write path** (and won't ship one — NTFS write is its own
  multi-year project; future tier).
- **No reparse-point handling** (junction points, symlinks).
- **No alternate data streams** (`file.txt:hidden`).
- **No EFS** (Encrypted File System).

## Related Pages

- [VFS](VFS.md)
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [GPT](GPT.md)
