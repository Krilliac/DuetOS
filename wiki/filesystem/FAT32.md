# FAT32

> **Audience:** FS authors
>
> **Execution context:** Kernel — process context
>
> **Maturity:** Read-only v0; LFN checksum validation live

## Overview

`kernel/fs/fat32/` reads FAT32 partitions for interoperability with
Windows-formatted media. Read paths are live; writes are deferred
behind the same FS-write gap as the other on-disk backends.

## Long File Name (LFN) Walker

FAT32 stores long filenames as a chain of 32-byte LFN entries
preceding each short 8.3 entry. The walker:

1. Iterates LFN-prefix entries in order.
2. Computes the per-fragment **checksum** against the trailing SFN
   (Short File Name).
3. If the checksum matches, the LFN is canonical.
4. If the checksum mismatches (orphaned LFN run), falls back to the
   8.3 SFN.

This matches Windows' validation rule and avoids returning garbage
filenames from a corrupted directory.

## Cluster Walking

Cluster chains are walked through the FAT (file allocation table) in
the standard manner. The driver reads the FAT in 4 KiB chunks
(matching NVMe's natural granularity).

## Known Limits / GAPs

- **No write path.** Reading is fine; writing requires FAT update +
  directory entry update + cluster reservation, deferred.
- **No FAT16 / FAT12 fallback.** FAT32 only.
- **No exFAT** despite the project pillar mentioning it for
  interoperability — exFAT is a separate code path and a separate
  slice.

See the FAT32 LFN-checksum entry in
`.claude/knowledge/deferred-task-batch-2026-04-25.md`.

## Related Pages

- [VFS](VFS.md)
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [GPT](GPT.md) — partition discovery
