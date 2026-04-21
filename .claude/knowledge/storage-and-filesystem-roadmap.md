# Storage + Filesystem roadmap — block layer → NVMe/AHCI → GPT → FS

**Last updated:** 2026-04-21
**Type:** Decision
**Status:** Active (stages 1–2, 4 landed; stage 3 (AHCI) + stage 5 (FAT32) remain)

## Description

CustomOS has an AHCI discovery stub and an in-memory ramfs/tmpfs
pair. There is no block-device interface, no persistent
filesystem, no NVMe driver, and no partition parser. This entry
scopes the sequence for getting from "no persistence" to
"mount a real filesystem off an SSD."

Ordering is strict — later stages assume earlier ones. Do not
jump ahead.

## Context

Applies to:

- `kernel/drivers/storage/` — new block layer + NVMe driver.
- `kernel/fs/` — VFS, will gain a mount path for on-disk FS.
- A future `fs/customfs/` or `fs/fat32/` — the first Rust crate
  in the tree per `rust-bringup-plan.md`.

Does not apply to:

- Ring-3 filesystem libraries. Filesystems stay in the kernel
  for the same reason drivers do — performance + the fact that
  the VFS is a kernel concept.
- `ramfs.cpp` / `tmpfs.cpp`. These keep working; they serve
  the boot trees and any process that wants scratch RAM FS.

## Details — stages

### Stage 1 — Block device abstraction (this session)

`kernel/drivers/storage/block.{h,cpp}`:
- `struct BlockDevice` — opaque handle with a vtable of
  `read_sector` / `write_sector` / `sector_count` /
  `sector_size`.
- `BlockDeviceRegister(desc) -> BlockDeviceHandle` — global
  registry. Flat array, no allocation.
- `BlockDeviceRead(h, lba, count, buf)` /
  `BlockDeviceWrite(h, lba, count, buf)` — synchronous,
  polling-style. IRQ-driven variants land with real hardware
  backends.
- First backend: `RamBlockDevice` — kernel-heap-backed,
  parametric sector size + count. Existence proves the shape
  of the interface without bringing up hardware, and serves
  as the test vehicle for higher layers.
- Boot self-test: register a small RAM block device, write a
  deterministic pattern at LBA 0, read it back, verify. One
  PASS/FAIL line on COM1.

### Stage 2 — NVMe driver (landed 2026-04-21)

`kernel/drivers/storage/nvme.{h,cpp}`. The modern SSD path.

- Discover via PCI class 0x01 / subclass 0x08 / prog_if 0x02.
- MapMmio BAR0 (Controller Registers).
- Reset the controller (CC.EN = 0, wait for CSTS.RDY = 0).
- Allocate Admin SQ + CQ pages (contiguous, below 4 GiB — the
  frame allocator already returns physically-contiguous
  singletons).
- Identify Controller + Identify Namespace (NSID=1 — every
  QEMU NVMe has namespace 1).
- Create one I/O SQ + CQ pair.
- Implement `NvmeRead(lba, count, buf)` via the Read command
  (opcode 0x02) with PRP1 pointing at a physically-contiguous
  scratch page.
- Register as a `BlockDevice` so every layer above (partition
  parser, FS) sees NVMe through the same interface.
- Boot self-test: if an NVMe device is present, read LBA 0
  and dump the first 32 bytes. (The MBR/GPT signature at
  offset 510 is a natural parity check for stage 3.)

### Stage 3 — AHCI real driver (next session after Stage 2)

Flesh out `drivers/storage/ahci.cpp` from discovery-only to
read-capable. Order: port reset, allocate command list + FIS
receive area, READ DMA EXT (0x25) via a single command slot,
wire polling completion. Register as `BlockDevice`.

Doing AHCI after NVMe is deliberate:
- NVMe is simpler (2 rings, no ATA command set complexity,
  no FIS framing). Cleaner first pass at queue-based I/O.
- QEMU's default `-drive if=none -device nvme` is trivial to
  test against. AHCI via QEMU's ICH9 chipset is more fiddly.
- The block layer's vtable absorbs the driver difference —
  stage 4+ doesn't care which backend served a sector.

### Stage 4 — GPT partition parser (landed 2026-04-21)

`kernel/fs/gpt.{h,cpp}`. C++ parser, not Rust — GPT is
bounded, well-defined, and we already have tight byte-parsing
discipline from the PE loader.

- Read LBA 0 (protective MBR — validate 0xAA55 signature).
- Read LBA 1 (GPT header — check "EFI PART" magic, CRC32
  the header, CRC32 the partition entries).
- Walk entries, log each partition's type GUID + byte range.
- Produce a `Partition` struct per entry: {first_lba, last_lba,
  type_guid, name}.
- Emit a log line per partition so stage 5 can grep for one.

MBR fallback for non-GPT disks stays out of scope — modern
SSDs ship GPT.

### Stage 5 — Filesystem: first Rust crate

`fs/fat32/` as the first Rust subsystem per `rust-bringup-plan.md`.

Why FAT32 first:
- Spec is small, stable, battle-tested. One week to ship a
  read-only implementation; no novel invariants.
- Every disk image format tool (mkfs.vfat) produces FAT32
  predictably, so fixturing is trivial.
- Windows PEs we want to run from disk live in FAT32-
  compatible partitions (ESP + data).

Scope for v0:
- Read-only.
- Parse BPB, locate first FAT + data region.
- Directory-entry iteration (short names only — LFN entries
  skipped for v0).
- File-cluster-chain read.
- Expose via `fs::FatMount(BlockDeviceHandle, first_lba)
  -> Mount*` — a new per-mount type that plugs into the VFS
  alongside ramfs.

Rust bring-up details (from `rust-bringup-plan.md`):
- `rust-toolchain.toml` pinned to a nightly date.
- Crate at `fs/fat32/` with `crate-type = ["staticlib"]`,
  `panic = "abort"`.
- Kernel C++ calls into `fat32_mount` / `fat32_readdir` /
  `fat32_read_file` via a hand-written C FFI header.
- No bindgen. No second toolchain dep beyond rustup.

### Stage 6 — VFS mount path

`fs::VfsMount(BlockDeviceHandle, FsType, mount_point) ->
MountId`. First consumer: the shell gains a `mount` command
that takes `/dev/nvme0p1` and attaches it at `/mnt/...`.

Per-process namespace roots continue to work — `Process::root`
stays a `const RamfsNode*` today, but grows into a generic
`VfsDir*` handle once on-disk FS is mountable. That refactor
is its own slice.

### Stage 7+ — Writable FS, native FS, NTFS read path

In order of likely priority:

1. Writable FAT32 (so the shell can create files).
2. A native CustomOS FS (our own design, journalled, ext-
   like). Done in Rust from scratch.
3. NTFS read-only. Required by the Windows-PE pillar once
   we want to load an .exe from a real NTFS partition.

Each is its own multi-session slog — scope them when their
turn comes.

## Notes

- **Don't pre-allocate for what's coming.** The block layer
  should not expose an "async submit" API today just because
  NVMe will want one — add that when a real NVMe I/O path
  forces it.
- **DMA-safe memory.** All hardware backends need
  physically-contiguous, kernel-mapped buffers. The frame
  allocator's single-frame path already gives us 4 KiB of
  contiguous physical memory with a kernel-direct mapping;
  multi-frame contiguous runs need the existing
  `AllocateFramesContiguous`. Document the DMA contract in
  `block.h` once the first hardware backend lands.
- **IRQ vs poll.** Stage 1/2 use polling. A "read + spin on
  CSTS.RDY" is enough for a functional boot. IRQ wiring
  (NVMe via MSI-X, AHCI via shared PCI INTx) lands only when
  a real workload cares about CPU time during I/O.
- **RAM block device is not throwaway.** Keep it forever —
  it's the canonical test backend for every future FS
  change. Unit tests for the Rust FAT32 crate should target
  the RAM device directly.
- **See also:**
  - `rust-bringup-plan.md` — Rust crate layout + toolchain.
  - `hardware-target-matrix.md` — which real SSDs / HBAs we
    target once discovery-only drivers become real.
