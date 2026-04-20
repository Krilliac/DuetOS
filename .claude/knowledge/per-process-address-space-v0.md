# Per-process address space — v0

**Type:** Observation
**Status:** Active
**Last updated:** 2026-04-20

## What

Every ring-3-bound task now runs on its own private PML4 via
`mm::AddressSpace`. The kernel half (PML4 entries 256..511) is shared
across every AS by copying the boot PML4's kernel-half entries
verbatim at AS-create time — those entries point at the same PDPT
pages, so any kernel-half mapping change (new MMIO, new heap PT
backing) propagates to every AS automatically. The user half (PML4
entries 0..255) is fully private per AS — the foundation of process
isolation.

## Files

- `kernel/mm/address_space.h` — `AddressSpace` struct + create/map/
  destroy/activate/retain/release API.
- `kernel/mm/address_space.cpp` — implementation. Self-contained PML4
  walker (deliberately duplicates a chunk of `paging.cpp`'s walker;
  the alternative would be exporting `WalkToPte` from paging just
  for one consumer).
- `kernel/mm/paging.{h,cpp}` — `WalkToPte` now takes a `u64* pml4`
  arg so it can walk any AS's tables. `IsUserRangeAccessible` reads
  CR3 to find the active PML4, so syscall-time pointer validation
  always uses the calling task's AS.
- `kernel/cpu/percpu.h` — `PerCpu::current_as` slot tracks the AS
  currently loaded in CR3 on this CPU.
- `kernel/sched/sched.{h,cpp}` — `Task::as`, `SchedCreateUser(...,
  as)`, `Schedule()` calls `AddressSpaceActivate(next->as)` before
  `ContextSwitch`. Reaper calls `AddressSpaceRelease(dead->as)`.
- `kernel/core/ring3_smoke.cpp` — spawns TWO ring-3 tasks at the
  SAME user VA (0x40000000 code, 0x40010000 stack), each in its own
  AS, demonstrating that VA collisions across processes aren't.

## Boot order requirement

`PagingInit` must run before the first `AddressSpaceCreate` —
`AddressSpaceCreate` calls `BootPml4Virt()` which is set up by
`PagingInit`. In current `kernel_main` order: PagingInit happens
before `StartRing3SmokeTask`, so this is fine.

## Same-AS fast path

`AddressSpaceActivate(as)` compares `as` against
`PerCpu::current_as` and skips the CR3 write if equal. The common
kernel→kernel context switch (worker → reaper, idle → kbd-reader,
etc.) all run on `as=nullptr` (the kernel AS), so they pay no CR3
write and no TLB flush. Only switches that cross an AS boundary
flip CR3.

## Open issues / next bites

1. **Global PTEs for the kernel half.** Without `kPageGlobal` set
   on kernel-half mappings, every CR3 flip drops every kernel-half
   TLB entry. Correctness holds, performance is sub-optimal —
   refill happens on first kernel access after the switch. Easy
   follow-up: OR in `kPageGlobal` in `kKernelData` / `kKernelMmio`
   and enable `CR4.PGE`.
2. **Region-table cap (32 entries).** Fine for the smoke task
   (code + stack = 2). Real workloads (PE loader mapping dozens of
   sections, a heap with hundreds of pages) will hit the cap and
   panic — that's the design intent: panic loud, then bump the
   cap or switch to a paged region table.
3. **No `__copy_user_fault_fixup`.** A user pointer that vanishes
   between `IsUserRangeAccessible` and the byte-by-byte copy still
   panics the kernel. Per-process AS makes this more likely
   (another task on another CPU could unmap a shared page mid-
   copy), though no AP runs user code today so the window is
   currently empty in practice.
4. **AS Stats not yet exposed.** `mm::AddressSpaceStatsRead()`
   exists but nobody prints it on a heartbeat or boot summary.
5. **VAS layout convention.** Ring3 smoke uses fixed 0x40000000 /
   0x40010000 — the PE loader will need a real address-space
   layout (heap range, mmap range, stack range) when it lands.

## What this enables

This commit is the foundation for process sandboxing:

- **Capability-table layered on top:** a `Process` struct will own
  the AS plus a capability set; cap-checked syscalls enforce that
  a process can only touch resources it has a cap for.
- **VFS namespace per process:** path lookups can be jailed inside
  a per-process root, so the EXE's `/` is the sandbox root.
- **PE loader sandbox profile:** untrusted PE images get spawned
  with an empty cap set, a jailed FS root, and no IPC ports —
  malicious code probing every byte of the canonical low half
  finds only what the loader chose to map.

The "the malicious EXE thinks its sandbox is the entire OS" goal
is implemented entirely by the page walker: a page that isn't in
this AS's PML4 doesn't exist for code running with this AS active.
No emulator, no VT-x guest, no hypervisor — just standard MMU
isolation, the same mechanism Linux/Windows use.
