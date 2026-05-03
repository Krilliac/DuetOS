# DMA-coherent buffer allocation v0

_Type: Decision + Pattern + Observation._
_Last updated: 2026-05-03._

## What

`mm::AllocDmaCoherent(bytes, zone) -> Result<DmaBuffer>` — the
single primitive every device driver needs for ring buffers,
descriptor lists, command queues, and shared scratch.

```cpp
namespace duetos::mm {

struct DmaBuffer
{
    PhysAddr phys;  // device-visible, page-aligned
    void* virt;     // kernel-VA alias for CPU access
    u64 bytes;      // rounded up to a multiple of kPageSize
    Zone zone;      // for FreeDmaCoherent bookkeeping
};

Result<DmaBuffer> AllocDmaCoherent(u64 bytes, Zone zone);
void FreeDmaCoherent(const DmaBuffer&);
void DmaSyncForDevice(const DmaBuffer&, u64 offset, u64 len);
void DmaSyncForCpu(const DmaBuffer&, u64 offset, u64 len);
void DmaSelfTest();

} // namespace duetos::mm
```

Lives at `kernel/mm/dma.{h,cpp}`. The frame-allocator side gained
`AllocateContiguousFramesInRange(count, max_phys)` to compose the
existing range-clamped scan with the existing contiguous-run scan.

## Why

The Wi-Fi control tier (`wireless-control-tier-v0.md`,
`iwl-fw-tlv-parser-v0.md`, `wireless-fw-parsers-v0.md`) shipped in
2026-05-01 with every per-vendor TX/RX path short-circuiting to
`Unsupported` because there was no API for asking the kernel for a
"contiguous, zone-clamped, kernel-mapped" buffer. The same gap was
sitting in front of:

- AHCI/SATA driver (P2 in `feature-gaps-end-user-v0.md`)
- USB bulk transfers for non-HID devices
- Per-vendor GPU acceleration (Intel/AMD/NVIDIA all probe-only per
  `render-drivers-v6.md`)
- Intel HDA codec/stream programming (P0 #2; CORB/RIRB rings + per-
  stream DMA buffers)

One small slice unblocks all four (and the Wi-Fi rings as the first
real consumer that uses the surface end-to-end).

## Design choice — cached direct-map alias on x86_64

`virt` is the higher-half direct-map alias of `phys` (i.e.
`PhysToVirt(phys)`), NOT a UC remap.

Why: x86_64 PCIe is cache-coherent. The CPU's caches are snooped on
device DMA writes, and the device sees CPU writes through the WB
alias on its next read. Mapping the buffer UC for the CPU would buy
nothing (the device is already coherent) and cost 50-100x slowdown
on CPU reads. This matches what Linux `dma_alloc_coherent()` returns
on x86 — also cached.

`DmaSyncForDevice` / `DmaSyncForCpu` are therefore `mfence` / `lfence`
on x86_64 (compiler + CPU memory barriers, no cache maintenance).
Drivers should still call them around every device-visible
transition: it's the only way the same source compiles correctly
on a future ARM64 port (where the same calls become `dsb ishst` +
per-line `dc cvac`, captured as a `// GAP:` marker in `dma.cpp`).

## Direct-map size constraint

The boot direct map covers the first 1 GiB of physical RAM only.
The frame-allocator bitmap reserves frames past that window as
"used" (see `kernel/mm/frame_allocator.cpp` near the
"frame past direct map" panic), so every frame the allocator
actually hands out is reachable through `PhysToVirt` already. Dma
(16 MiB) and Dma32 (4 GiB) zones sit comfortably inside this. If a
future port grows the direct map (or adds a UC-remap fallback), the
v0 cached-only path here turns into the fast path and the slow path
drops in alongside.

## First consumer — iwlwifi TFD/RBD rings

`kernel/drivers/net/iwlwifi_rings.cpp` was scaffolded in
`wireless-control-tier-v0.md` with a comment in
`iwlwifi_rings.h:22` literally citing this slice as the unblocker.
After the wire-in:

- `IwlRingsInit` allocates 4 × 32 KiB Dma32 TX descriptor rings + 1
  × 2 KiB Dma32 RX descriptor ring (one `mm::AllocDmaCoherent` call
  per ring). On any allocation failure it tears down whatever ran
  succeeded and returns the underlying `ErrorCode`.
- `IwlRingsTeardown` frees every live ring.
- The FH base registers (`kFhTfdbBaseLow/High`,
  `kFhRscsrChnl0Rbdcb`) are programmed with the real ring 0
  physical addresses — previously they were programmed with 0.
- The boot self-test now asserts `dma_addr != 0`, `virt_base !=
  nullptr`, and `dma_addr < 4 GiB` for every ring (the chip's
  descriptor-pointer registers are 32-bit). It also asserts the
  teardown leaves both fields at 0 / nullptr again.
- `IwlRingsSubmitTx` still returns `Unsupported` — the TFD
  descriptor build + doorbell program is its own slice that lands
  separately.

## Boot self-test

`mm::DmaSelfTest` runs in the `Phase::PhysMem` initcall slot,
right after `ZoneSelfTest`. Asserts:

1. `Zone::Mmio` returns `Unsupported`.
2. `bytes == 0` returns `InvalidArgument`.
3. For each viable zone (Dma, Dma32, Normal): allocate 8 KiB,
   verify `virt != nullptr`, `phys` is page-aligned, the run
   respects the zone's max-phys ceiling, and a marker pattern
   written through `virt` round-trips through the direct-map alias
   of `phys`. Free.
4. Free + re-alloc returns the same physical address (proves the
   bitmap actually reclaimed the run, and that `g_next_hint`
   updates point back at the freshly-freed slot).

## What's NOT in v0

- **Userland DMA**. v0 keeps DMA buffer ownership in the kernel;
  userland reaches devices through the device's syscall surface
  (read/write/ioctl/mmap with explicit cap gating), not by mapping
  a coherent buffer into a process directly.
- **Scatter-gather chains**. The first wave of consumers (Wi-Fi
  rings, AHCI command list, HDA CORB) all want a single contiguous
  region. S/G chains land when the second wave demands it.
- **IOMMU-isolated buffers** (Intel VT-d / AMD-Vi). v0 assumes
  identity-mapped DMA. When IOMMU support lands, the `phys` field
  becomes "device-visible address" and a separate IOVA allocator
  backs it.
- **Per-RBD data buffers** (256 × 4 KiB = 1 MiB) for iwlwifi RX —
  the rings hold pointers to data buffers that don't yet exist.
  Captured as a `// GAP:` marker in `iwlwifi_rings.cpp`.
- **kCapDma** capability gating. AllocDmaCoherent is kernel-only
  (no syscall surface), so caps don't apply yet. When/if a syscall
  fronts this, gate it on a new `kCapDma` cap.

## Files touched

| File | Change |
|------|--------|
| `kernel/mm/frame_allocator.h` | Declare `AllocateContiguousFramesInRange(count, max_phys)`. |
| `kernel/mm/frame_allocator.cpp` | Implement same — composes the existing linear-scan with the existing range clamp. |
| `kernel/mm/dma.h` | New — public `DmaBuffer` + `AllocDmaCoherent` / `FreeDmaCoherent` / `DmaSync*` / `DmaSelfTest`. |
| `kernel/mm/dma.cpp` | New — implementation + boot self-test (`DmaSelfTest`). ~190 LOC. |
| `kernel/core/main.cpp` | `#include "mm/dma.h"`; register `DmaSelfTest` initcall in `Phase::PhysMem` after `ZoneSelfTest`. |
| `kernel/drivers/net/iwlwifi_rings.cpp` | Replace "no DMA arena yet" path with real per-ring `mm::AllocDmaCoherent(Dma32)` allocation; teardown frees; self-test asserts ring buffers exist + sit below 4 GiB. |

CMake auto-picks up the new `.cpp` (the kernel uses `GLOB_RECURSE`).

## Follow-up slices unblocked

| Slice | What lands | Status |
|-------|------------|--------|
| iwlwifi TFD descriptor build + doorbell program | `IwlRingsSubmitTx` returns Ok and rings the chip's TX doorbell | not started |
| iwlwifi per-RBD data buffers (256 × 4 KiB) | RX side can actually receive | not started |
| AHCI command-list + FIS-receive area allocation | `kernel/drivers/storage/ahci.cpp` exits probe-only | not started |
| Intel HDA CORB / RIRB / per-stream BDL | `kernel/drivers/audio/audio.cpp` exits probe-only — closes P0 #2 in `feature-gaps-end-user-v0.md` | not started |
| Per-vendor GPU command-buffer allocation | unblocks the GPU-acceleration tier in `render-drivers-v6.md` | not started |

## Resume prompt

> Read `.claude/knowledge/dma-coherent-v0.md`. The DMA-coherent
> primitive is live. Pick one of the follow-up slices above —
> iwlwifi TFD-build is the most direct continuation of this work
> (it consumes the rings allocated here); HDA and AHCI are
> independent and either could land next. Each is its own bounded
> slice with its own knowledge file when complete.
