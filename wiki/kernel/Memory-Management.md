# Memory Management

> **Audience:** Kernel hackers, driver authors
>
> **Execution context:** Kernel — single CPU at boot, SMP-aware once spinlocks land
>
> **Maturity:** v0 stable; allocators SMP-safe (frame/kheap reentrant spinlock, slab per-cache mutex). Per-CPU lock-free fast-path scaling deferred (B2-followup).

## Overview

Memory management on DuetOS is structured as four cooperating layers:

```
[ application VAs ]                     ring 3
       |
[ per-process AddressSpace ]            kernel/mm/address_space.{h,cpp}
       |
[ Managed paging API ]                  kernel/mm/paging.{h,cpp}
       |
[ Physical frame allocator ]            kernel/mm/frame_allocator.{h,cpp}
       |
[ Multiboot2 memory map ]               kernel/mm/multiboot2.{h,cpp}
```

The kernel heap (`KMalloc` / `KFree`) sits over a 2 MiB pool carved out of
the frame allocator at boot, addressed through the higher-half direct
map.

## Physical Frame Allocator

Bitmap-backed, one bit per 4 KiB frame.

- Default-init = "used"; only `Available` regions from the Multiboot2 map
  are flipped to "free".
- The low 1 MiB stays reserved (real-mode IVT, BDA, EBDA, legacy video,
  SMI handlers).
- Reserved at init: kernel image (`_kernel_start_phys`..`_kernel_end_phys`),
  the bitmap itself, the Multiboot2 info struct, and frame 0 (aliases the
  `kNullFrame` sentinel).
- `AllocateFrame` is a hint-rewinding linear scan; `FreeFrame` rewinds the
  hint to the lowest freed frame.
- `AllocateContiguousFrames(count)` for the heap and any future caller
  that needs N consecutive frames.

Highest usable address ignores reserved MMIO (otherwise QEMU q35's
1 TiB pflash region would balloon the bitmap to 32 MiB).

The allocator gained `AllocateFrameInRange(PhysAddr max_phys)` for
zone-clamped allocations: a bitmap search that clamps the highest
frame considered to `max_phys >> kPageSizeLog2`. `kernel/mm/zone.cpp`'s
`AllocateZoneFrame` picks the ceiling per zone (16 MiB for `kZoneDma`,
4 GiB for `kZoneDma32`, no ceiling for `kZoneNormal`) and routes
through this API. The boot self-test panics with the offending physical
address if a Dma frame above 16 MiB or a Dma32 frame above 4 GiB ever
escapes.

## Higher-half Kernel + Direct Map

The kernel runs at `0xFFFFFFFF80000000` (the canonical higher half).
The first 1 GiB of physical RAM is aliased through that base via 2 MiB
PS pages — the **direct map**. `PhysToVirt` / `VirtToPhys` convert
within that window and panic on out-of-range input.

```
0xFFFFFFFF80000000 .. 0xFFFFFFFFC0000000   higher-half direct map (1 GiB)
0xFFFFFFFFC0000000 .. 0xFFFFFFFFE0000000   kernel MMIO arena (512 MiB)
```

## Managed Paging API

`MapPage` / `UnmapPage` / `MapMmio` walk the boot PML4 (adopted by
reading CR3 — no PML4 swap). Fresh PT pages come from the frame
allocator and are addressed through the direct map. EFER.NXE is
enabled, so `kPageNoExecute` (`PTE bit 63`) is honoured — the basis for
W^X.

`MapMmio` always sets `kPageCacheDisable` (PCD); `kKernelData` does not
(cacheable RAM is the default; opting out is the special case).

Splitting 2 MiB PS pages into 4 KiB PTEs is **not** supported in v0 —
the boot direct map never wants 4 KiB granularity, and there are no
other PS users.

## Kernel Heap

First-fit + coalescing freelist over a 2 MiB pool.

- `ChunkHeader` is 16 bytes (`size + next`), `alignas(16)`. Payload
  alignment is 16 bytes.
- For an allocated chunk, `next` overlaps the first 8 bytes of the user
  payload (deliberate — we never read `next` until the chunk is freed).
- Free + coalesce: insert in address order, merge with both neighbours
  if physically adjacent.
- `KFree` panics on pointer outside the pool, or chunk header with size
  below minimum / above pool — catches double-free and wild-pointer
  corruption immediately.

KMalloc/KFree are **IRQ-safe** (T5-04, 2026-05-10): every entry
brackets the freelist + bin mutations with a `KheapIrqOff` RAII
that disables interrupts and restores `IF` only if it was set on
entry. **SMP-safe (landed):** the frame allocator and kheap now
take a reentrant `sync::SpinLock` (`g_frame_lock` / `g_kheap_lock`)
at every public entry via `SpinLockRecursiveGuard` — `cli`/`sti`
alone gave zero cross-CPU exclusion, so concurrent
`AllocateFrame`/`KMalloc` from APs could double-allocate or corrupt
the freelist. The guard is irqsave (subsumes the old
`FramePoolIrqOff`/`KheapIrqOff`) and reentrant (the public
entries legitimately call one another, e.g.
`AllocateContiguousFrames`→`AllocateFrame`, without splitting
each into a `*Locked` worker). Slab was already SMP-safe via its
per-cache `sched::Mutex`. **Deferred (B2-followup):** restoring
the per-CPU lock-free fast paths (frame warm-pool / slab
magazine) for *scalability* — correctness is now in place; the
single global lock per allocator is the contention trade until a
profile demands the per-CPU split.

### Allocator family — context contract

| Allocator | Function | IRQ-safe | SMP-safe | Sleeps |
|-----------|----------|----------|----------|--------|
| Frame allocator | `AllocateFrame` / `FreeFrame` | yes (irqsave guard) | yes (`g_frame_lock`, reentrant) | no |
| Kernel heap | `KMalloc` / `KFree` | yes (irqsave guard; ≤512 B routes to irq-safe slabs) | yes (`g_kheap_lock`, reentrant) | no |
| Slab cache | `SlabAlloc` / `SlabFree` | yes (`IrqOff`; irq-safe mode for slow path) | yes (per-cache `sched::Mutex` or irqsave spinlock) | no |
| Kernel stacks | `KStackAlloc` | no — caller must be in process context | no | no |

Allocators that do NOT sleep are safe to call from any kernel
context: timer IRQ, IPI handler, panic path, syscall fast path.
The frame allocator + kheap + slab all qualify. The kernel-stack
allocator allocates 4 frames + page-table walk and is documented
as process-context only.

**Zero-init pattern**: every kernel struct that embeds sync primitives
(`SpinLock`, `Mutex`, etc.) must be `memset(0)` before first use. The
allocator returns potentially-dirty memory; primitives expect zeroed
storage to be unlocked. See [`Coding-Standards`](../tooling/Coding-Standards.md).

## DMA-coherent allocation

`mm::AllocDmaCoherent(bytes, zone)` returns zone-clamped contiguous
frames with a cached direct-map alias on x86_64. PCIe is HW-coherent so
no UC remap or cache flush is needed; `DmaSync*` are mfence/lfence on
x86. ARM64 will require `dsb ishst` + per-line `dc cvac` (tracked as a
`// GAP:` in `kernel/mm/dma.cpp`). Boot self-test asserts MMIO reject,
zero-byte reject, per-zone alloc, ceiling, write/read round-trip, and
reuse-after-free. First consumer: iwlwifi TFD/RBD rings (4 × 32 KiB TX
+ 1 × 2 KiB RX in `kZoneDma32`).

## Per-process Address Spaces

`mm::AddressSpace` owns a per-process PML4 with the kernel's higher
half mirrored in. CR3 is reloaded on context switch when the next
task's address space differs from the current one. Userland mappings
live in the low half; kernel mappings live in the high half and stay
identical across every address space.

`SYS_VM_ALLOCATE` (the self-path needs no capability) **probes each
target page with `AddressSpaceProbePte` before mapping** and returns
`kStatusConflictingAddresses` if any is already present — a guest can no
longer drive `AddressSpaceMapUserPage`'s present-PTE `PanicAs` into a
full kernel halt by allocating at an already-mapped hint address. On a
mid-loop allocation failure it also **unwinds the pages already mapped**
(mirroring the Linux `DoMmap` path) so a partial OOM neither leaks
frames nor leaves the cursor poised to re-panic. (Security audit
SEC-003, CWE-617/459, 2026-06-07.)

## Kernel Stack Guard Pages

Every task has an unmapped low-edge guard page on its kernel stack.
Stack overflow into the guard takes a `#PF` instead of silently
clobbering the next allocation. The boot stack additionally uses a
high-VMA alias so the early CR3 swap to a per-process PML4 doesn't
unmap the active stack mid-call.

## Leak Detection

A unified leak detector lives at
[`kernel/diag/leak_detector.h`](../../kernel/diag/leak_detector.h). It
folds the existing per-subsystem accounting (heap caller-RIP tracker,
frame allocator counters, kstack high-water, address-space refcount,
IPC handle table, Win32 fixed-size handle tables, GDI alive flags,
socket pool, scheduler `ticks_run`, GPU resource tables) into one
operator-facing surface with two trigger points:

- **Shell command — `leakcheck`** (also `leakcheck class <name>` and
  `leakcheck pid <n>`). Cheap; no allocation, no blocking. See the
  [Shell Commands](../reference/Shell-Commands.md) reference for the
  full subcommand grid.
- **Process-exit attribution.** `LeakDetectorReportProcessExit()` is
  invoked from `ProcessRelease()` after `HandleTableDrain()`. If any
  per-process resource (kobject handles, Win32 handle slots, ticks
  over budget, future GPU residue) is still live when the process's
  refcount hits zero, the detector emits one `KLOG_WARN` line and
  fires the `kLeakAttributable` probe (`diag.leak_attributable`,
  `ProbeArm::ArmedLog` by default) so an attached GDB can break at
  the moment the leak is first observed. Clean exits stay silent.

The detector is purely read-only — every counter comes from an
existing accessor. No new tracking is added inside hot allocator
paths.

GPU classes (`kGpuContext`, `kGpuSurface`, `kGpuCmdBuffer`,
`kGpuMemory`) read through
[`kernel/drivers/gpu/gpu_leak.h`](../../kernel/drivers/gpu/gpu_leak.h),
a stable contract backed by the per-class resource tables in
[`kernel/drivers/gpu/gpu_resources.h`](../../kernel/drivers/gpu/gpu_resources.h).
Drivers register / release resources against those tables;
the leak accessors are thin passthroughs over the snapshot side,
and the per-process exit hook walks them to evict orphans owned
by an exiting PID. virtio-gpu's scanout backing is the first
real registrant (kernel-owned). Vendor GPU bring-ups (Intel /
AMD / NVIDIA) wire into the same tables once their command-ring
slices land.

## Known Limits / GAPs

- **IRQ-safe `KMalloc` / `KFree` shipped** — every allocator-
  family mutation runs under `KheapIrqOff` / `FramePoolIrqOff` /
  the slab cache's `IrqOff`, which save and restore the local
  CPU's IFLAGS. The allocators are still single-lock — moving
  to per-CPU runqueue-style fan-out is the next layer once a
  profile demands it (see B2-followup in
  [Roadmap](../reference/Roadmap.md)).
- **No 2 MiB / 1 GiB PS support for new mappings** — straightforward
  add when the framebuffer driver demands it.
- **Slab allocator landed** — `kernel/mm/slab.{h,cpp}`. Each
  `SlabCache` hands out fixed-size objects from 16 KiB slabs
  carved out of the kheap, with a per-cache intrusive freelist
  and freed-object poison. Boot self-test runs in
  `Phase::Sched`. Two slow-path lock modes: the default sleeping
  `sched::Mutex`, and an irqsave-spinlock mode
  (`SlabCacheCreateIrqSafe`) for caches that must stay legal in
  IRQ context.
- **Automatic KMalloc→slab routing landed (2026-06-10)** —
  `KMalloc` calls ≤512 B route through eight `kmalloc-N` irq-safe
  caches (32…512, ×16 steps) ahead of the kheap freelist; >512 B
  and slab-OOM fall through to the classic path. Discrimination
  on free is a 16 B route header vs the kheap `ChunkHeader::next
  == nullptr` live-chunk invariant (now static_assert-pinned) —
  see `kernel/mm/kmalloc_route.h` and the 2026-06-10
  Design-Decisions entry. Stats: `mm:kmalloc_routed_live_bytes`
  / `_cached_bytes`; `heap leaks` attribution covers >512 B
  only. Boot gate: `[kmalloc-route-selftest] PASS`. See the
  [Roadmap](../reference/Roadmap.md) for the deferred real
  KASAN work.
- **No reclaim or compaction.** `FreeFrame` is the only path frames
  re-enter the pool.

## Related Pages

- [Boot Path](Boot.md) — when each MM layer comes online
- [Scheduler](Scheduler.md) — owns `Task` structs and per-task stacks
- [Process Model](Process-Model.md) — wraps `AddressSpace` per process
- [Subsystem Isolation](Subsystem-Isolation.md) — why subsystems must go
  through `mm::*` rather than touching tables directly
- [W^X / NX Enforcement](../security/WX-Enforcement.md)
