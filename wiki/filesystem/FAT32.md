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

- **In-place + append + create + delete + rename write paths
  shipped** — `Fat32WriteInPlace`, `Fat32AppendAtPath`,
  `Fat32CreateAtPath`, `Fat32DeleteAtPath`, `Fat32RenameAtPath`,
  exercised by Notes / Files / Screenshot / session restore.
  **Mid-file writes that grow a cluster chain are not yet
  supported** — writing into a region that would extend the
  file beyond its existing cluster count rejects with `-1`.
  Append-then-write is the workaround for grow-heavy workloads.
- **No FAT16 / FAT12 fallback.** FAT32 only.
- **exFAT lives in [`kernel/fs/exfat.{h,cpp}`](../../kernel/fs/exfat.h)**
  as a sibling backend — probe + root-directory walk are wired
  today. See the [exFAT page](exFAT.md) for that backend's scope
  and limits.
- **Cross-volume rename rejected** by `Fat32RenameAtPath` and the
  file-route layer — the operation has no atomic primitive within
  one volume's FAT, so cross-volume rename would require copy +
  delete with rollback. Same volume rename is fully supported.

See [Roadmap](../reference/Roadmap.md) for the cluster-chain
growth work.

## Durability and TRIM

`Fat32Sync(volume)` routes `BlockDeviceFlush` through to the
underlying NVMe/AHCI/virtio-blk backend so a successful return
means metadata is on non-volatile media, not just in the
controller's volatile write cache. `Fat32DeleteAtPath` and
`Fat32TruncateAtPath` call this internally on success, so a
power-cut after a successful unlink can no longer leave the
volume in a "FAT updated but dir-entry deletion lost" half-state.

`Fat32Trim(volume)` walks the FAT, coalesces contiguous runs of
free clusters, and hands each run to `BlockDeviceDiscard`. The
underlying backend turns this into an NVMe DSM Deallocate / AHCI
DATA SET MANAGEMENT TRIM / virtio-blk DISCARD command, depending
on which device is mounted. Drives the `fstrim <volume-index>`
shell command.

`FreeClusterChain` coalesces just-freed clusters into the
longest contiguous run and discards each before returning, so
even an automatic `unlink` issues the trim hint on SSDs without
the caller having to know.

## Related Pages

- [VFS](VFS.md)
- [exFAT](exFAT.md) — sibling backend for ≥ 32 GiB volumes.
- [Mount Registry](Mount-Registry.md) — FAT32 is wired into the per-FsType vtable.
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [GPT](GPT.md) — partition discovery
