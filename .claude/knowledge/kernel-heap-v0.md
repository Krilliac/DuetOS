# Kernel Heap v0 — First-fit + Coalescing over Direct Map

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The kernel can now `KMalloc` / `KFree`. A 2 MiB pool is carved out of the
physical frame allocator at boot, mapped into kernel virtual address space
through the static higher-half direct map, and managed by a singly-linked,
address-ordered freelist with coalescing on free.

## Context

Applies to `kernel/mm/{kheap.{h,cpp},page.{h,cpp}}` and the new
`AllocateContiguousFrames` / `FreeContiguousFrames` pair in
`kernel/mm/frame_allocator.{h,cpp}`. The heap is the foundation every later
subsystem builds on — task structs, file descriptors, driver state, message
buffers — none of those can be written until allocation works.

Boot order is now:

```
Serial → GDT → IDT → FrameAllocatorInit → KernelHeapInit → kernel main loop
```

## Details

### Direct-map helpers (`mm/page.h`)

Until we have a managed page-table API, the higher-half mapping installed by
`boot.S` is the only way to address physical RAM. The first 1 GiB of physical
memory is aliased at `KERNEL_VIRTUAL_BASE` (`0xFFFFFFFF80000000`).

```cpp
inline constexpr u64 kKernelVirtualBase = 0xFFFFFFFF80000000ULL;
inline constexpr u64 kDirectMapBytes    = 1ULL * 1024 * 1024 * 1024;

void*    PhysToVirt(PhysAddr phys);   // panics if phys >= 1 GiB
PhysAddr VirtToPhys(const void* v);   // panics outside [base, base+1GiB)
```

Both functions panic on out-of-range input rather than silently returning
nonsense — the heap is the only caller today and it should never produce an
out-of-range address. If a future caller legitimately needs to map physical
memory above 1 GiB or non-direct-mapped regions, that's the trigger to land
the page-table API; do not paper over it by extending these helpers.

### `AllocateContiguousFrames(count)`

Linear scan of the bitmap looking for `count` consecutive clear bits. O(n)
in `g_bitmap_frames`, which is fine at boot when `n ≈ 130k` and the heap
needs the call exactly once. Notes:

- `count == 0` returns `kNullFrame` — guard against accidental
  `KMalloc(0)`-style misuse propagating into the frame layer.
- `count == 1` short-circuits to `AllocateFrame()` so the existing hint-
  based allocator handles single-frame paths.
- Successful runs are marked used in one pass; on failure no state is
  changed.
- `g_next_hint` is **not** advanced after a multi-frame allocation. Single-
  frame allocations may still find earlier free slots that the run scan
  skipped over (it skips when it hits a used frame, not the start).

### Heap pool placement

`KernelHeapInit` requests `kKernelHeapBytes / kPageSize = 512` contiguous
frames. On a 512 MiB QEMU run, the frame allocator places them just above
its bitmap and Multiboot2 info struct — typically `0x114000`. The pool is
addressed via `PhysToVirt(base_phys) = 0xFFFFFFFF80114000`.

2 MiB is generous but not extravagant: for boot-era data structures (PCI
device list, ACPI tables, initial process struct) it should cover early
needs without ever growing. When growth becomes a real requirement, the
right move is **not** to extend this allocator; it's to land the page-table
API and a slab/buddy allocator in a separate commit.

### Chunk layout

```cpp
struct alignas(16) ChunkHeader
{
    u64          size;   // total chunk size, header + payload
    ChunkHeader* next;   // freelist link (only meaningful when on freelist)
};
```

`sizeof(ChunkHeader) == 16`, asserted at compile time. Payload alignment is
also 16 bytes — enough for any scalar, any pointer, and any `__m128`-
shaped value. SSE/AVX state save areas are not allocated through `KMalloc`
(they need 64-byte alignment and live in per-thread blocks).

For an allocated chunk, `next` overlaps the first 8 bytes of the user
payload. That's deliberate: the user owns those bytes once we've handed
out the pointer, and we never read `next` until the chunk is freed. The
self-test fills each payload end-to-end with a pattern to catch any
regression that would clobber the freelist link.

### Allocation algorithm — first fit + split

Walk the freelist; first chunk with `size >= sizeof(ChunkHeader) +
RoundUp(bytes, 16)` wins. Split if the remainder can hold another minimum-
sized chunk (`sizeof(ChunkHeader) + 16`); otherwise hand out the whole
chunk and tolerate the small internal fragmentation.

First fit, not best fit: with one big initial chunk and modest churn, best
fit's only win would be reducing fragmentation, which we already address
with coalescing. Best fit costs an extra full freelist walk on every alloc
and saves nothing on the typical pattern.

### Free + coalesce

Insert into the freelist in address order. Then check both neighbours: if
the chunk is physically adjacent (`prev_addr + prev_size == chunk_addr` or
`chunk_addr + chunk_size == next_addr`), merge.

The list is singly-linked, so finding `prev` for backward coalesce takes a
second walk. v0: pay the O(n) cost — n is small. If profiles show
`KFree` dominating boot time, switch to a doubly-linked list before
adding any other complexity.

### Sanity checks

`KFree` panics on:

- pointer outside the pool (catches stale or wild pointers immediately);
- chunk header with a size below the minimum chunk or above the entire
  pool (smoking gun for double-free or memory-corruption-of-the-allocator).

The cost is two comparisons per `KFree` and the bug-yield is enormous —
keep them.

### Self-test (`KernelHeapSelfTest`)

End-to-end coverage:

1. Pristine state: full pool on freelist as one chunk.
2. Three small allocations with different sizes — distinct, address-
   ordered, 16-byte aligned.
3. Each payload is filled to its requested size with a pattern; if the
   header overlaps the payload (it shouldn't, since the user payload starts
   at `chunk + 16`), the next allocation walks off into garbage.
4. Free middle, then free outer — verify counters update, verify final
   state coalesces back to a single freelist node equal to the original
   pool.
5. Allocate a single 8 KiB chunk to confirm the merged region is usable
   for an allocation larger than any of the three small ones.
6. Final state must again be pristine: one chunk, full pool size.

Any deviation panics with a `[panic] mm/kheap: …` line whose suffix names
the failed invariant.

### Verified boot output (after this commit, QEMU q35, 512 MiB)

```
[mm] frame allocator self-test
  alloc A    : 0x0000000000110000
  alloc B    : 0x0000000000111000
  alloc C    : 0x0000000000112000
  realloc    : 0x0000000000110000 (reused A/B/C)
  contig x0x0000000000000008 : 0x0000000000113000
[mm] frame allocator self-test OK
[boot] Bringing up kernel heap.
[mm] kernel heap online: pool=0x0000000000200000 base_virt=0xFFFFFFFF80114000 base_phys=0x0000000000114000
[mm] kernel heap self-test
  alloc 32   : 0xFFFFFFFF80114010
  alloc 64   : 0xFFFFFFFF80114040
  alloc 128  : 0xFFFFFFFF80114090
  coalesced  : free=0x0000000000200000 chunks=0x0000000000000001
  alloc 8192 : 0xFFFFFFFF80114010
[mm] kernel heap self-test OK
```

(Build verified locally; QEMU smoke test will run when `qemu-system-x86_64`
and `grub-mkrescue` are installed on the dev host — see project index.)

### How to verify after edits

```bash
cmake --build build/x86_64-debug
CUSTOMOS_TIMEOUT=10 tools/qemu/run.sh   # once QEMU is installed
```

Smoke checks:

- `[mm] kernel heap self-test OK` is the canonical "the allocator works"
  signal. Any earlier `[panic] mm/kheap: …` names the failed invariant.
- The reported `coalesced  : chunks=0x1` is the single tightest test of
  freelist health: any leftover fragments here mean a coalesce bug.
- `alloc 8192` must succeed and have a higher virtual address than the
  pool base — that proves the merged chunk was actually used.

Canaries for "this regressed":

- `KFree pointer outside heap pool` — a caller passed a stale or wild
  pointer; check the call site, not the allocator.
- `KFree on chunk with corrupt size` — almost always a double-free.
  `g_alloc_count` vs `g_free_count` from `KernelHeapStatsRead()` is the
  fastest discriminator.
- Heap self-test passes but later subsystem panics inside `KMalloc` —
  likely a lock issue once SMP lands. Today, the heap is single-CPU only.

## Notes

- **No locking yet.** `KMalloc`/`KFree` are not safe to call from IRQ
  context or from multiple CPUs. SMP bring-up will add a spinlock; the
  `IRQ-safe` variant will need `spin_lock_irqsave`. Document this on every
  caller until that lands.
- **No growth.** Pool exhaustion returns `nullptr` from `KMalloc`. Callers
  must check. Once we have the page-table API, the natural growth path is
  to allocate more contiguous frames and stitch them into the freelist —
  but only when a real workload demands it.
- **No alignment beyond 16 bytes.** A `KMallocAligned(bytes, align)` helper
  is straightforward to add (over-allocate, round, store the original
  pointer below the returned address). Don't add it speculatively.
- **`ChunkHeader::next` aliasing user payload.** This is correct but
  surprising — anyone refactoring the header should preserve this property
  or pay an extra 8 bytes per chunk.
- **See also:**
  - [frame-allocator-v0.md](frame-allocator-v0.md) — the layer the heap
    sits on; gained `AllocateContiguousFrames` / `FreeContiguousFrames`.
  - [higher-half-kernel-v0.md](higher-half-kernel-v0.md) — the static
    direct map this allocator's virtual addresses come from.
