# Storage (NVMe + AHCI)

> **Audience:** Driver authors, FS authors
>
> **Execution context:** Kernel — IRQ + softirq + process
>
> **Maturity:** v0 NVMe (polling); AHCI v0; both used for read paths

## Overview

DuetOS storage stack today:

```
[ VFS path resolution ]                kernel/fs/
        |
[ Filesystem backend ]                 fs/fat32/, fs/ext4/, fs/ntfs/, fs/ramfs/
        |
[ Block layer (light) ]                kernel/fs/block.{h,cpp}
        |
[ Storage driver ]                     kernel/drivers/storage/{nvme,ahci}/
        |
[ PCIe device ]
```

The block layer is intentionally thin in v0 — read paths dominate, and
each FS backend talks to the storage driver through a small "read N
sectors at LBA" interface.

## NVMe v0

`kernel/drivers/storage/nvme/`.

- Polling admin queue + I/O queue. No interrupts in v0 — the queue
  doorbell is rung and the driver spins on the completion phase bit.
- Identify Controller + Identify Namespace at probe time.
- 4 KiB block size assumption (matches every modern NVMe SSD).
- Marker self-test at boot writes a known pattern and reads it back
  through a separate I/O cycle to prove the queue path is wired.

Plenty of headroom for a real interrupt-driven path; deferred until
real workloads make polling expensive.

See `.claude/knowledge/nvme-driver-v0.md`.

## AHCI v0

`kernel/drivers/storage/ahci/`.

- Standard SATA AHCI command-list ring with a single command slot in
  use at a time.
- Read-only path live; write path deferred behind the same FS-write
  gap as the higher layers.

## GPT v0

`kernel/fs/gpt.{h,cpp}` (see `.claude/knowledge/gpt-parser-v0.md`).

- Validates the protective MBR.
- Parses the primary GPT header + entry array, CRC-validated.
- Hands each partition to the FS backend layer for FS-type
  identification.

## FS Backends Wired Today

- **FAT32**: read path live. LFN walker validates the per-fragment
  checksum against the trailing SFN (orphaned LFN runs fall back to
  the 8.3 name).
- **ext4**: read path live. Root-dir walk iterates every leaf-extent
  block; depth>0 extent-tree walk still deferred (see
  `.claude/knowledge/deferred-task-batch-2026-04-25.md`).
- **NTFS**: read-only tier in progress.
- **ramfs**: in-memory tree used as the boot root and per-process
  jail.

See [VFS](../filesystem/VFS.md), [FAT32](../filesystem/FAT32.md),
[ext4](../filesystem/ext4.md).

## Known Limits / GAPs

- **No write paths past the storage driver** for any on-disk FS yet.
  ramfs writes work; FAT32/ext4/NTFS are read-only today.
- **NVMe is polling-only.** Interrupt-driven I/O queue support
  deferred to the post-debug recommendations plan.
- **Single command slot for AHCI.** Throughput is bounded by
  round-trip latency; one outstanding command at a time is fine for
  boot-era reads.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [PCIe Enumeration](PCIe-Enumeration.md)
- [VFS](../filesystem/VFS.md)
- [FAT32](../filesystem/FAT32.md)
- [ext4](../filesystem/ext4.md)
- [GPT](../filesystem/GPT.md)
