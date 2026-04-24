# NVMe driver v0 — polling I/O via admin + one I/O queue

**Last updated:** 2026-04-23
**Type:** Observation
**Status:** Active (real-hardware hardening batch)

## Description

First real hardware-backed block device. `kernel/drivers/storage/nvme.cpp`
brings up an NVMe controller end-to-end from PCI discovery through
a working `BlockDevice` that the block layer can read/write sectors
against. The boot self-test asserts that LBA 0 of the QEMU scratch
image round-trips the `"DUETOS"` marker `tools/qemu/run.sh`
seeds into `build/<preset>/nvme0.img`.

Completes **stage 2** of `.claude/knowledge/storage-and-filesystem-roadmap.md`.

## Context

Applies to:

- `kernel/drivers/storage/nvme.{h,cpp}` — the driver itself.
- `kernel/drivers/storage/block.h` — the vtable the driver hooks into.
- `kernel/core/main.cpp` — `NvmeInit` + `NvmeSelfTest` boot sequencing.
- `tools/qemu/run.sh` — `-device nvme` attached to a 16 MiB scratch
  disk, marker seeded at offset 0.

Does not apply to:

- MSI-X interrupts. v0 is strict polling on the completion queue
  phase bit. IRQ wiring lands when a workload cares about CPU time
  during I/O.
- Multi-namespace controllers. v0 hardcodes NSID 1 — the only
  namespace QEMU's default `-device nvme` exposes and the
  every-day case on consumer SSDs.
- Writes from userland. The block layer registration is writable,
  but the boot path only exercises the read side against the
  marker; the write plumbing is there for the FAT32 slice.

## Details

### PCI binding + MMIO

Finds the first PCI device with class `0x01` / subclass `0x08` /
prog_if `0x02` and enables both MMIO-space and Bus Master bits in
the command register (offset `0x04`). BAR0 is the controller
registers window (hundreds of KiB on real silicon, 16 KiB in QEMU)
and is mapped through `mm::MapMmio`.

`CAP` (8 bytes at offset `0x00`) tells us:

- `MQES` (bits 0..15) — max queue entries minus 1.
- `TO` (bits 24..31) — reset/init timeout in 500 ms units.
- `DSTRD` (bits 32..35) — doorbell stride exponent; stride = `4 << DSTRD`.

QEMU reports `MQES+1 = 0x800`, `TO*500 = 7500 ms`, `stride = 4`.

### Reset + enable sequence

1. `CC.EN` cleared; spin on `CSTS.RDY == 0` with a fatal-status
   check on `CSTS.CFS` and a generous pause-loop budget.
2. Allocate admin SQ + CQ (one 4 KiB frame each via
   `mm::AllocateFrame`, both zeroed, physically contiguous by
   definition since they're single frames).
3. Write `AQA` (both SQ + CQ depth, 0-based), `ASQ`, `ACQ`
   (physical addresses).
4. `CC` programmed with `IOSQES=6` (64-byte SQ entry),
   `IOCQES=4` (16-byte CQ entry), `CSS=0` (NVM), `MPS=0`
   (4 KiB), `EN=1`.
5. Spin on `CSTS.RDY == 1`.

### Admin commands

Three commands run in the admin queue during bring-up:

- **Identify Controller** (opcode `0x06`, CNS=1). PRP1 points at a
  fresh 4 KiB frame. v0 only extracts the model-number string
  (offset 24, 20 bytes, space-padded ASCII) and logs it to COM1.
- **Identify Namespace** (opcode `0x06`, CNS=0, NSID=1). Extracts
  `NSZE` (sector count, bytes 0..7) and walks the LBAF table at
  offset 128 using `FLBAS` (byte 26 low nibble) to pick the active
  LBA Format; `LBADS` is the sector-size exponent (9 = 512,
  12 = 4096).
- **Create I/O CQ / SQ** (opcodes `0x05` / `0x01`, QID=1). Both
  physically-contiguous (PC=1), IRQs disabled on the CQ, I/O SQ
  references CQID=1.

### Completion polling

Each completion is 16 bytes; DW3 carries CID (bits 0..15), Phase
tag (bit 16), and Status (bits 17..31). A `Queue` tracks its own
`expected_phase` starting at 1 (queue memory was zero-initialized,
so the first real completion flips the phase). On wrap back to
head index 0 the expected phase flips, matching the hardware.

After consuming a completion the head doorbell is updated so the
controller knows the slot is free.

### Block layer glue

On success the controller registers a `BlockDesc` named
`"nvme0n1"` with the real reported sector size and count. Every
call into `NvmeBlockRead` / `NvmeBlockWrite` copies the caller's
buffer through a pre-allocated DMA-safe staging page
(`io_buf_phys` / `io_buf_virt`) before/after the command. That
indirection is a concession to the two-line "v0 is simple"
constraint — higher layers don't have to understand PRP or 4 KiB
alignment today. The cost is one extra memcpy per command; no
worse than any other single-bounce I/O path. When a real
workload cares, the staging page goes away and the block layer
grows a "buffer must be direct-map + 4 KiB-aligned" contract.

### Boot self-test

`NvmeSelfTest` reads LBA 0 (one sector) into a stack buffer and
asserts the first 8 bytes equal `"DUETOS"` — the marker
`tools/qemu/run.sh` seeds into `build/<preset>/nvme0.img` on
first launch. A missing controller logs `"skipped"`; a marker
mismatch logs `FAILED`.

## Notes

- **File size:** 680 lines in `nvme.cpp`. Over the 500-line
  threshold in `CLAUDE.md` but it's one coherent driver — splitting
  queue + init + I/O across three files would force a shared
  internal header for `g_ctrl` that's arguably worse. Flagged as
  a revisit if the driver grows write-coalescing, async completion,
  or a second queue pair.
- **No IRQ wiring:** the I/O path spins on the phase bit with a
  `pause`-loop budget of ~50M iterations. On QEMU each command
  completes in a few thousand cycles. On real silicon a real
  workload needs MSI-X; that lands in the same slice as async
  submission.
- **PRP1-only transfers:** each command caps at one page (4 KiB).
  The block layer's sector-count API lets callers issue multi-
  sector reads up to the per-command cap — the driver rejects
  `count * sector_size > 4 KiB` with `-1`. Larger I/O is a caller
  loop until PRP lists land.
- **Single in-flight command:** `next_cid` exists but we don't
  track in-flight commands by CID today — the driver submits one
  command and immediately polls its matching completion. A
  deeper pipeline is a follow-up.
- **Order in `kernel_main`:** after `PciEnumerate`, `AhciInit`,
  `BlockLayerInit`/`BlockLayerSelfTest`, then `NvmeInit`/
  `NvmeSelfTest`. The block layer must exist before the driver
  registers; PCI must be enumerated first.
- **See also:**
  - `storage-and-filesystem-roadmap.md` — stage 3 (real AHCI)
    follows, then stage 4 (GPT parser), then stage 5 (FAT32 in
    Rust).
  - `pci-enum-v0.md` — device discovery primitives this driver
    consumes.

## 2026-04-23 — real-hardware hardening batch

Changes in this batch make the driver viable on real NVMe silicon
rather than QEMU-only. QEMU doesn't enforce the things this fixes,
so local boots look identical; the difference shows up on a real SSD
where the controller rejects out-of-spec configuration.

- **CAP.MPSMIN / MPSMAX validation.** Controllers publish the page-
  size range they accept (`CAP.MPSMIN..CAP.MPSMAX`, both log2
  encoded relative to 4 KiB). The host-side page size — always 4 KiB
  in this codebase — is checked against that range before CC is
  programmed. `CC.MPS` is now explicitly set from
  `kHostMpsEncoding` (0 = 4 KiB) via the spec-defined bit field
  rather than being left at the post-reset default.

- **CAP.TO-driven completion deadlines.** `WaitReady` and
  `SubmitAndWait` both derive their upper bound from
  `CAP.TO * 500 ms` (the spec's wall-clock limit on controller
  responsiveness) via the HPET counter. Old code used a fixed
  `50 M` pause-loop budget that happened to be ~1 s on fast CPUs
  and indefinite on slow ones. Graceful fallback to the pause
  budget if HPET isn't online.

- **Queue depth now driven by CAP.MQES.** Admin queue stays at 8
  (only serves bring-up). I/O queue grows from 8 → 64 entries,
  clipped to `CAP.MQES + 1` when the controller reports less. Both
  still fit on a single 4 KiB page each (64-byte SQ entries /
  16-byte CQ entries).

- **PRP list support.** `NvmeDoIo` can now transfer up to 16 pages
  (64 KiB) per command:
  - `byte_count <= 4 KiB`    → PRP1 only.
  - `4 < byte_count <= 8 KiB` → PRP1 + PRP2 points at page 2.
  - `byte_count > 8 KiB`      → PRP1 + PRP2 points at a
    single-level PRP list page (up to 512 entries = 2 MiB reach).
  The staging buffer is a 16-page contiguous allocation made via
  `AllocateContiguousFrames(16)` and freed symmetrically on
  registration failure. A single PRP list page is allocated
  alongside it — always valid, populated on demand.

- **MDTS cap from Identify Controller.** Translated to bytes
  against the host page size and used as the per-command ceiling
  alongside the staging buffer size. MDTS = 0 (unlimited) leaves
  the staging cap as the only bound.

- **Status propagation.** Completion queue entries with non-zero
  status are now decoded into `SC` (status code, bits 0..7) and
  `SCT` (status code type, bits 8..10) and logged via
  `LogWith2Values`. Enough information to tell a real-disk error
  apart from a software bug without attaching a bus analyser.

- **New init-time controller fields** (on `Controller`):
  `admin_queue_entries`, `io_queue_entries`, `mps_min`, `mps_max`,
  `mdts_max_bytes`, `prp_list_phys`, `prp_list_virt`. The init log
  emits MPS/MDTS/timeout/queue-size as four bracketed lines so a
  boot-log grep for `drivers/nvme` tells you the runtime shape.

- **What this batch still doesn't do.** No MSI-X — polling remains.
  No multi-command pipelining, no per-CPU queues, no Flush
  command, no FUA flag, no namespace != 1. MSI-X comes later and
  needs a broader vector-allocation / IOAPIC-glue subsystem; the
  rest can land incrementally with concrete callers.

- **How to tell it works.** On QEMU `-device nvme` the boot log
  should now carry a `page-size support mps_min=0 mps_max=0`
  line and a `MDTS max bytes` line, and the self-test still
  round-trips LBA 0 with the `0x55AA` signature. On real hardware
  the only observable difference from QEMU is that boot no longer
  aborts on controllers that enforce MPS / MQES.
