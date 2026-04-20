# Managed Page-Table API v0 — 4-level Walker over Boot PML4

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The kernel now has a managed `MapPage` / `UnmapPage` / `MapMmio` API that
sits on top of the PML4 boot.S installed. New 4 KiB-granular mappings
land in fresh PT pages allocated from the physical frame allocator and
addressed via the higher-half direct map. EFER.NXE is enabled so
`kPageNoExecute` is honoured. End-to-end self-test in QEMU: allocate a
frame, map it twice into the kernel MMIO arena, write through one alias,
read through the other, unmap.

## Context

Applies to `kernel/mm/paging.{h,cpp}`. Adopts the boot PML4 by reading
CR3 — no PML4 swap and no CR3 reload, so the higher-half direct map and
all of `.text` / `.rodata` / `.data` / `.bss` continue to work uninterrupted.
The first 1 GiB stays mapped through `boot_pdpt[0]` and
`boot_pdpt_high[510]` as 2 MiB PS pages; new mappings only touch PDPT
slots that the boot path didn't populate (PML4[511] / PDPT[511] for the
MMIO arena).

This unblocks the LAPIC bring-up (LAPIC MMIO at `0xFEE00000` is outside
the 1 GiB direct map and needs a real mapping) and any future driver
that touches MMIO.

## Details

### Kernel virtual address layout

```
0x0000000000000000 .. 0x0000000040000000   identity map (1 GiB, boot only)
...                                         (low half — userland later)
0xFFFFFFFF80000000 .. 0xFFFFFFFFC0000000   higher-half direct map (1 GiB)
0xFFFFFFFFC0000000 .. 0xFFFFFFFFE0000000   kernel MMIO arena (512 MiB)
0xFFFFFFFFE0000000 .. 0xFFFFFFFFFFFFFFFF   reserved for future use
```

The direct map and the MMIO arena live in the same PML4 slot (511) but
different PDPT slots (510 vs 511). That's deliberate: walking the MMIO
arena never touches the boot direct-map PDEs, so the v0 "panic on PS
page" guard in `WalkToPte` never fires for legitimate MMIO mappings.

### Walker shape

`WalkToPte(virt, create)` decomposes `virt` into the four 9-bit indices
(`>>39`, `>>30`, `>>21`, `>>12`) and walks PML4 → PDPT → PD → PT. At
each level:

1. If the entry's `Present` bit is clear and `create` is true, allocate
   a fresh frame from the physical allocator, zero it via the direct
   map, install it as `phys | P | RW`.
2. If the entry has `PS` set (1 GiB at PDPT level, 2 MiB at PD level),
   panic. Splitting a PS page into 4 KiB PTEs is straightforward but not
   needed yet — the boot direct map never wants 4 KiB granularity, and
   there are no other PS users.
3. Otherwise descend through `PhysToVirt(entry & kAddrMask)`.

`kAddrMask = 0x000F'FFFF'FFFF'F000` masks bits 12..51, which are the
physical-frame bits in every level of the long-mode tables.

### EFER.NXE

Without `EFER.NXE` (MSR `0xC0000080`, bit 11), the CPU treats PTE bit 63
as reserved-must-be-zero and raises `#GP` if it's set. `PagingInit` sets
the bit unconditionally — every modern x86_64 CPU we target supports NX
(it's part of x86_64 itself). Once set, `kPageNoExecute = 1ULL << 63`
on a kernel-data mapping prevents code execution from that range, which
is the basis for W^X.

### MMIO arena — bump allocator

`MapMmio(phys, bytes)`:

1. Round `phys` down to the page boundary; remember the offset within
   the page.
2. Round `bytes + offset` up to a page count.
3. Bump-allocate that many pages from the MMIO arena starting at
   `kMmioArenaBase + g_mmio_cursor`.
4. Install `kKernelMmio` mappings (`P | RW | PCD | NX`) for every page.
5. Return the base virt + offset, so the caller's pointer aliases the
   exact register address they asked for.

`UnmapMmio(virt, bytes)` calls `UnmapPage` for every page but does NOT
recycle the virtual range. Boot-time devices live forever; for hot-plug
devices the right answer is a freelist over the arena, not a "rewind"
on the bump cursor.

### Cache-disable on MMIO

MMIO mappings get `kPageCacheDisable` (`PCD = 1`). Without this, the CPU
caches device register reads and writes — fine for normal RAM,
catastrophic for an LAPIC EOI register or a NIC tx ring. The convenience
bundle `kKernelMmio` includes PCD by construction so drivers cannot
forget.

`kKernelData` deliberately does NOT include PCD. Cacheable RAM is the
default; opting OUT of caching is the special case.

### Self-test (`PagingSelfTest`)

End-to-end:

1. Allocate one physical frame.
2. Call `MapMmio(frame, kPageSize)` twice — get two distinct virtual
   aliases for the same physical page.
3. Write a 64-bit pattern through alias A at offsets 0 and 127, read
   through alias B, verify both bytes match.
4. `UnmapMmio` both aliases and free the frame.
5. Read counters.

What this proves:
- PML4 slot 511 is reachable from the adopted boot PML4.
- PDPT[511] gets allocated correctly (PD then PT cascade).
- PTE install + invlpg is consistent — the second alias sees the write
  even though it was made through a different virtual address.
- `UnmapPage` clears the PTE without disturbing the other alias before
  the second tear-down.

If this regresses, the most likely failure modes are:

- Hang or `#PF` at the first MMIO write → `MapMmio` returned a virt
  that doesn't actually walk to the requested phys. Check the entry
  values being stored at each level (low 12 bits should be flags only,
  high bits should be the destination physical frame).
- `[panic] mm/paging: WalkToPte hit a 2 MiB PS page` → caller asked
  to map an address inside the boot direct map. Check call site.
- `[panic] mm/paging: MapPage: virtual address already mapped` →
  bump cursor desynced from actual mappings (e.g., a prior `UnmapMmio`
  that "freed" a virt range some later allocation re-handed-out).
  Confirm UnmapMmio is NOT being called twice with the same address.

### Verified boot output (QEMU q35, 512 MiB)

```
[mm] paging adopted boot PML4: cr3_phys=0x0000000000110000 pml4_virt=0xFFFFFFFF80110000
[mm] paging self-test
  alias A    : 0xFFFFFFFFC0000000
  alias B    : 0xFFFFFFFFC0001000
  tables     : 0x0000000000000003 mappings_installed=0x0000000000000002 removed=0x0000000000000002
[mm] paging self-test OK
```

The "tables: 3" is exactly: one PDPT (PML4[511] new) + one PD (PDPT[511]
new) + one PT (PD[0] new). All subsequent MMIO mappings inside the same
PT cost 0 additional table allocations.

### How to verify after edits

```bash
cmake --build build/x86_64-debug
CUSTOMOS_TIMEOUT=10 tools/qemu/run.sh
```

Smoke checks:
- `[mm] paging self-test OK` is the canonical "paging works" signal.
- `tables` count after init should match the layout above (3 fresh
  tables for the first MMIO mapping; +1 PT for every additional 512
  pages of MMIO).
- `mappings_installed == mappings_removed` after the self-test — the
  test is a leak detector for `MapPage`/`UnmapPage` pair-balance.

## Notes

- **No locking yet.** Same story as `KMalloc`: SMP bring-up will need
  a mutex around page-table writes. Until then, document on every
  caller that paging is single-CPU.
- **No 2 MiB / 1 GiB PS support for new mappings.** All new mappings
  are 4 KiB. Adding PS support is straightforward (skip allocation at
  PDPT or PD level and set the PS bit) — defer until a workload needs
  it (probably the framebuffer driver).
- **No `Present`-clear of intermediate tables on `UnmapMmio`.** A
  100% empty PT could be freed and its parent entry zeroed. Add this
  when MMIO churn becomes meaningful — it's pure space optimization,
  not a correctness issue.
- **`kKernelCode` is intentionally `P` only** (RO + executable). It's
  not used yet; the kernel's own `.text` is mapped by the boot 2 MiB
  PS pages with `P | RW` — that's a correctness hole (W^X violation)
  to fix when we move kernel `.text` to managed 4 KiB mappings.
- **See also:**
  - [higher-half-kernel-v0.md](higher-half-kernel-v0.md) — the boot
    PML4 / direct map this builds on.
  - [frame-allocator-v0.md](frame-allocator-v0.md) — supplies the
    page-table frames.
  - [kernel-heap-v0.md](kernel-heap-v0.md) — already used for kernel
    data structures; paging extends what kernel virtual addresses can
    reach beyond the 1 GiB direct map.
