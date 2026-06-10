# Storage (NVMe + AHCI)

> **Audience:** Driver authors, FS authors
>
> **Execution context:** Kernel — IRQ + softirq + process
>
> **Maturity:** v0 NVMe (MSI-X completion + Flush + DSM Deallocate);
> AHCI v1 (read + write + FLUSH CACHE EXT + DSM TRIM); virtio-blk
> (read + write + Flush + DISCARD; MSI-X completion + 10 in-flight
> request slots). Power-loss durability path live on every backend.

## Overview

DuetOS storage stack today:

```
[ VFS path resolution ]                kernel/fs/
        |
[ Filesystem backend ]                 fs/fat32/, fs/ext4/, fs/ntfs/, fs/ramfs/
        |
[ Block layer (light) ]                kernel/fs/block.{h,cpp}
        |
[ Storage driver ]                     kernel/drivers/storage/{nvme,ahci}.cpp
        |
[ PCIe device ]
```

The block layer is intentionally thin in v0 — read paths dominate, and
each FS backend talks to the storage driver through a small "read N
sectors at LBA" interface.

## NVMe

`kernel/drivers/storage/nvme.cpp`.

- Polling admin queue (used only during bring-up); **MSI-X
  vector for the I/O completion queue** so I/O blocks on a wait
  queue instead of burning CPU. Polling fallback preserved for
  controllers that don't expose MSI-X.
- Identify Controller + Identify Namespace at probe time. MDTS
  honoured; CAP.MPS validated against host page size; CAP.TO is
  the upper bound on every CSTS.RDY transition.
- 512-byte and 4 KiB sector support (LBA Format 0 from Identify
  Namespace).
- **NVMe Flush (opcode 0x00) wired** — `BlockDeviceFlush`
  routes through `NvmeBlockFlush`, which issues a Flush command
  on the I/O queue and waits for completion. NVMe Base Spec §5.2:
  controllers with VWC=0 complete this as a no-op, controllers
  with VWC=1 commit their volatile write cache.
- **NVMe Dataset Management Deallocate (opcode 0x09, AD=1)
  wired** — `BlockDeviceDiscard` routes through `NvmeBlockDiscard`
  with a single 16-byte range descriptor. Required for SSD
  longevity; without it write amplification destroys consumer
  SSDs in weeks of real-world use.
- Marker self-test at boot writes a known pattern and reads it
  back to prove the queue path is wired.

Pending: per-CPU queues, ZNS, multi-namespace enumeration. None
needed for "files survive a power cut" — that bar is cleared.

## AHCI

`kernel/drivers/storage/ahci.cpp`.

- Standard SATA AHCI command-list ring with command slot 0 used
  serially.
- Read DMA EXT (0x25) and Write DMA EXT (0x35) both live.
- **FLUSH CACHE EXT (0xEA) wired** — `BlockDeviceFlush` routes
  through `AhciBlockFlush`, which builds a no-PRDT command on
  slot 0 (data set is the volatile write cache, not the bus).
  ACS-4 §7.10.
- **DATA SET MANAGEMENT TRIM (0x06 with FEATURES=0x01) wired**
  — `BlockDeviceDiscard` routes through `AhciBlockDiscard`,
  which packs the requested LBA range into 8-byte descriptors
  (6-byte LBA + 2-byte count, up to 64 per 512-byte payload
  sector) and issues the command on slot 0. ACS-4 §7.11.

Pending: NCQ (slots 0..31 concurrent reads via FPDMA Queued),
hotplug, port multipliers. None needed for read+write+flush
correctness.

## virtio-blk

`kernel/drivers/virtio/virtio_blk.cpp`.

- Read + Write + Flush (VIRTIO_BLK_T_FLUSH).
- **DISCARD (VIRTIO_BLK_T_DISCARD) wired** when the host offers
  `VIRTIO_BLK_F_DISCARD` (virtio 1.2 §5.2.5). QEMU forwards the
  hint to the host filesystem's `FALLOC_FL_PUNCH_HOLE` on
  qcow2/raw backends — TRIM effectively passes through to the
  host SSD.
- **MSI-X IRQ-driven completion + 10 in-flight request slots**
  (fixed 3-descriptor slots carved from the 32-entry queue;
  IRQ-safe spinlock around slot claim / avail publish / used pop).
  Falls back to the fully-serialised polling path (per-device
  sleeping mutex) when MSI-X is unavailable. Boot self-test
  drives 3 concurrent patterned read/write lanes against `vblk0`
  and asserts the completions flowed through the ISR.

## GPT v0

`kernel/fs/gpt.{h,cpp}` — see [GPT](../filesystem/GPT.md).

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
  [Roadmap](../reference/Roadmap.md#ext4-leaf-extent-depth--0)).
- **NTFS**: read-only tier in progress.
- **ramfs**: in-memory tree used as the boot root and per-process
  jail.

See [VFS](../filesystem/VFS.md), [FAT32](../filesystem/FAT32.md),
[ext4](../filesystem/ext4.md).

## Block layer surface

`kernel/drivers/storage/block.{h,cpp}` exposes the uniform
interface every FS backend goes through:

```cpp
// Synchronous reads / writes, bounded by sector_count.
i32  BlockDeviceRead   (u32 handle, u64 lba, u32 count, void* buf);
i32  BlockDeviceWrite  (u32 handle, u64 lba, u32 count, const void* buf);

// Commit the device's volatile write cache to non-volatile media.
// NVMe Flush / AHCI FLUSH CACHE EXT / virtio-blk Flush.
i32  BlockDeviceFlush  (u32 handle);

// Hint that the named range no longer holds caller-meaningful
// data. NVMe DSM Deallocate / AHCI DSM TRIM / virtio-blk DISCARD.
// Routes through the same write-guard predicate as Write — a
// guarded LBA cannot be discarded into.
i32  BlockDeviceDiscard(u32 handle, u64 lba, u32 count);

// Predicate + counters for FS-layer discard plumbing.
bool BlockDeviceSupportsDiscard(u32 handle);
u64  BlockDiscardIssuedCount();
u64  BlockDiscardSectorsHinted();
```

The block-layer self-test exercises every op against the
RAM-backed test device on every debug boot: write, read,
out-of-range reject, discard (RAM backend implements it as
"zero the range" so the hint is observable), zero-count
reject, OOB-discard reject, hint counter advancement, flush.

## FS-layer plumbing

- `Fat32Sync(volume)` → `BlockDeviceFlush(handle)` — public API.
- `Fat32Trim(volume)` → walks the FAT for free clusters and
  hands every contiguous run to `BlockDeviceDiscard`. Drives the
  `fstrim` shell command.
- `Fat32Delete*` and `Fat32Truncate*` auto-flush on success — a
  successful return means metadata is on durable media, not just
  in the device's volatile cache.
- `FreeClusterChain` coalesces freed clusters into the longest
  physically-contiguous run and discards each run before
  returning. Non-discard backends pay no overhead.

## Known Limits / GAPs

- **ext4 and NTFS are still read-only.** Write paths for either
  are separate multi-slice efforts (T7-04 in the Roadmap).
- **DuetFS Rust-side flush is not yet exposed.** The C ABI
  `Device` struct has `read`/`write` only; a `flush` callback is
  a follow-on (DuetFS already has a journal — the missing piece
  is the FFI hook).
- **No buffer cache between VFS and block.** Every FS backend
  re-reads sectors on every metadata walk. Haiku-style
  transactional `block_cache` is the next slice (see
  `wiki/reference/Roadmap.md`).
- **AHCI uses one command slot.** Read/write/flush/discard are
  all serial. NCQ slots 0..3 is the next throughput slice.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [PCIe Enumeration](PCIe-Enumeration.md)
- [VFS](../filesystem/VFS.md)
- [FAT32](../filesystem/FAT32.md)
- [ext4](../filesystem/ext4.md)
- [GPT](../filesystem/GPT.md)
