# Storage + Filesystem roadmap — block layer → NVMe/AHCI → GPT → FS

**Last updated:** 2026-04-21
**Type:** Decision
**Status:** Active (stages 1–5 landed; file-read + VFS mount follow-ups remain)

## Description

DuetOS has an AHCI discovery stub and an in-memory ramfs/tmpfs
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

### Stage 3 — AHCI real driver (landed 2026-04-21)

Promoted `drivers/storage/ahci.cpp` from discovery-only to a
working read path.

Per-port bring-up:
- Stop the engine (clear PxCMD.ST + FRE, wait for CR/FR to
  clear), then one 4 KiB DMA frame carved into:
    0..1023   command list (32 slots × 32 B)
    1024..1279 FIS receive area (256 B, 256-aligned)
    1280..1535 command table (cfis + prdt[1])
    1536..2047 IDENTIFY DEVICE reply buffer
- Program PxCLB/CLBU + PxFB/FBU to those physaddrs.
- Clear PxSERR + PxIS, re-enable FRE then ST, wait for BSY +
  DRQ to drop.
- Issue IDENTIFY DEVICE (ATA 0xEC) on slot 0, extract LBA48
  sector count from words 100..103, register as "sata0".

Read path (`BlockOps::read`):
- Build H2D Register FIS for READ DMA EXT (ATA 0x25) with
  caller LBA + count. PRD[0] = (VirtToPhys(buf), count*512 - 1).
- Poll PxCI until slot 0 clears, watching PxIS.TFES for task-
  file errors. 8-sector cap per call.

PCI wiring: enable Memory Space + Bus Master in the PCI command
register before touching MMIO/DMA. Set GHC.AE=1 on the HBA.

Multi-controller: walks every AHCI PCI match (up to 4). With
QEMU q35, controller #1 is the built-in (carries the boot
CD-ROM, skipped as ATAPI), controller #2 is our test
`ahci,id=ahci1` with one SATA disk.

Out of scope for v1 (each is a future slice): writes, NCQ,
multiple in-flight slots, MSI, hotplug, 4K native sectors.

Decision: ATAPI (CD-ROM) is deliberately unsupported. Our
pattern is "boot from ISO once, mount real FS from SATA/NVMe
after" — an ATAPI driver is a different command set (PACKET)
with its own quirks and no lasting value.

Validation: `[ahci] self-test OK (LBA 0 read + 0x55AA signature
present)` plus GPT parse `handle=0x2 name=sata0`.

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

### Stage 5 — FAT32 filesystem (landed 2026-04-21, C++ after all)

Initial shipment: `kernel/fs/fat32.{h,cpp}` as **C++**, not Rust.

Revisiting the "Rust first" plan: after implementing PE + ELF
loaders, the GPT parser, and the AHCI driver all in C++ with
tight byte-parsing and bounded static state, FAT32 was a natural
fit for the same style. No lifetime gymnastics called for a new
language surface; Rust-for-filesystems is deferred until a
genuine invariant (e.g. journaling consistency, btree concurrent
readers) demands it.

Scope landed (v0):
- `Fat32Probe(block_handle)` reads LBA 0 of a block device,
  validates 0x55AA + "FAT32" marker + BPB geometry, and logs the
  decoded fields.
- Walks the root-directory cluster chain via the FAT to enumerate
  up to `kMaxDirEntries=32` short-8.3 entries per volume. LFN
  fragments, deleted slots (0xE5), and volume-label pseudo-entries
  are skipped.
- `Fat32SelfTest()` probes every block-device handle; partitions
  that aren't FAT32 log "not FAT32" + skip.
- Image builder (`tools/qemu/make-gpt-image.py`) writes a minimal
  FAT32 layout into the data partition with one test file
  `HELLO.TXT` (17 bytes) so the self-test has a deterministic
  fixture.

Validation (on-boot):
  [fs/fat32] volume: handle=3 bps=0x200 spc=0x8 res=0x20
             fat_size=0x40 root_cluster=0x2 data_start=0xa0
  [fs/fat32]   - HELLO.TXT  attr=0x20  first_cluster=0x3  size=0x11
  [fs/fat32] self-test OK

Follow-up slices (not yet landed):
- File content read by cluster-chain walk (`Fat32ReadFile(vol,
  name, buf, max)`). Next natural commit.
- Long-filename decoding (attr == 0x0F fragments).
- Subdirectory recursion.
- VFS integration so `ls` / `cat` in the shell can reach these.
- Writes.

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
2. A native DuetOS FS (our own design, journalled, ext-
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
