# Memory Management

> **Audience:** Kernel hackers, driver authors
>
> **Execution context:** Kernel — single CPU at boot, SMP-aware once spinlocks land
>
> **Maturity:** v0 stable (single-CPU); SMP locking pending

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

See `.claude/knowledge/frame-allocator-v0.md` for the full bring-up notes.

## Higher-half Kernel + Direct Map

The kernel runs at `0xFFFFFFFF80000000` (the canonical higher half).
The first 1 GiB of physical RAM is aliased through that base via 2 MiB
PS pages — the **direct map**. `PhysToVirt` / `VirtToPhys` convert
within that window and panic on out-of-range input.

```
0xFFFFFFFF80000000 .. 0xFFFFFFFFC0000000   higher-half direct map (1 GiB)
0xFFFFFFFFC0000000 .. 0xFFFFFFFFE0000000   kernel MMIO arena (512 MiB)
```

See `.claude/knowledge/higher-half-kernel-v0.md`.

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

See `.claude/knowledge/paging-v0.md`.

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

KMalloc/KFree are **not yet IRQ-safe and not yet SMP-safe**. SMP bring-up
will add `spin_lock_irqsave`. Until then, document on every caller.

See `.claude/knowledge/kernel-heap-v0.md` and
`.claude/knowledge/kmalloc-zero-init-pattern.md`.

## Per-process Address Spaces

`mm::AddressSpace` owns a per-process PML4 with the kernel's higher
half mirrored in. CR3 is reloaded on context switch when the next
task's address space differs from the current one. Userland mappings
live in the low half; kernel mappings live in the high half and stay
identical across every address space.

See `.claude/knowledge/per-process-address-space-v0.md`.

## Kernel Stack Guard Pages

Every task has an unmapped low-edge guard page on its kernel stack.
Stack overflow into the guard takes a `#PF` instead of silently
clobbering the next allocation. See
`.claude/knowledge/kernel-stack-guard-v0.md` and
`.claude/knowledge/boot-stack-high-vma-fix.md`.

## Known Limits / GAPs

- **No SMP locking yet** in the heap, frame allocator, or page-table
  walker. SMP bring-up will add irq-save spinlocks. Caller documents
  single-CPU assumption today.
- **No 2 MiB / 1 GiB PS support for new mappings** — straightforward
  add when the framebuffer driver demands it.
- **No buddy / slab allocator** on top of the freelist heap. Real
  per-zone allocator + slab + KASAN graduated to
  `.claude/knowledge/post-debug-recommendations-plan.md`.
- **No reclaim or compaction.** `FreeFrame` is the only path frames
  re-enter the pool.

## Related Pages

- [Boot Path](Boot.md) — when each MM layer comes online
- [Scheduler](Scheduler.md) — owns `Task` structs and per-task stacks
- [Process Model](Process-Model.md) — wraps `AddressSpace` per process
- [Subsystem Isolation](Subsystem-Isolation.md) — why subsystems must go
  through `mm::*` rather than touching tables directly
- [W^X / NX Enforcement](../security/WX-Enforcement.md)
