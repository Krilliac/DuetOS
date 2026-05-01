# Post-recommendations follow-on plan

## Status (2026-05-01)

The 18-item kernel-debug recommendations plan closed on
2026-04-28 with every numbered item landed and most followups
absorbed. The original plan file was deleted on 2026-05-01 once
all its content was either landed or graduated to this file.
This file captures the genuinely-large work that remained at
that plan's end — items whose name was "followup" but whose
scope is a multi-commit slice on its own. Each entry below is
a future plan in miniature: what it is, what blocks it, and
what triggers it.

### Landed since this plan was opened

| Date | Item | Commit |
|------|------|--------|
| 2026-05-01 | C1-followup — Real per-zone allocator (physical-address ceiling routing in `mm/frame_allocator.{h,cpp}` + `mm/zone.cpp`, self-test now asserts the Dma 16-MiB / Dma32 4-GiB ceiling holds) | (this commit) |

## Resume prompt

> Read `.claude/knowledge/post-debug-recommendations-plan.md`
> for context. Pick one item from the list below; write its
> own slice plan if it grows past a single commit. Each item
> is bounded — the original recommendations plan already
> landed the infrastructure each one builds on. Update the
> Status table here when an item is completed; delete this
> file when every item is done AND no follow-up has been
> spawned.

## Pending work

### B2 SMP — per-CPU runqueues + work stealing

**Scope**: bring the scheduler from BSP-only to genuine SMP.
Per-CPU runqueues, AP bringup synchronisation, work-stealing
across CPUs, IPI-based reschedule.

**Blocks on**: nothing — the per-CPU shape is in place
across lockdep / soft-lockup / event-trace / perf, all keyed
on `g_per_cpu[0]` aliases that just need to index by current
CPU ID. SMP AP bringup itself (`SmpStartAps`) already exists.

**When to land**: when a workload genuinely benefits from
parallelism — typical native userland workloads or any
non-trivial PE binary.

**Cascading deferred items**:
  - D1-followup — Index `g_per_cpu` lockdep array by current-CPU ID.
  - D2-followup — Index event-trace `g_per_cpu` by current-CPU ID.
  - D4-followup — Index soft-lockup `g_per_cpu` by current-CPU ID.
  - B1-followup — SMP-stress versions of the RwLock + SeqLock + KMailbox contention self-tests (current cooperative-single-CPU forms cover the wakeup paths; AP bringup unlocks real concurrent-acquire stress).
  - A2-followup — Move LAPIC-divider + tick-frequency programming out of `arch::TimerInit` into `time::TimerConfigure(hz)` once an ARM64 / generic-timer backend justifies the abstraction (purely a portability slice; no behaviour change on x86 alone).

### E1-followup — Enable Intel CET

**Scope**: write `IA32_S_CET` / `IA32_PL0_SSP`, allocate
shadow stacks, recompile with `-fcf-protection=branch`.

**Blocks on**: kernel-image rebuild flag wiring + per-task
shadow-stack allocator + per-IDT-vector ENDBR64 prologue.

**When to land**: when a target machine in the test fleet
advertises CET-SS / CET-IBT and a workload benefits from
software-enforced CFI on top of the silicon's built-in
protection. Probe (`arch::CetGet`) is in place to gate the
enable code on a real signal.

### E2-followup — Enable KPTI / Meltdown mitigation

**Scope**: split per-process PML4 into a kernel-only and a
user-only view; trampoline syscall entry/exit through CR3
swaps; trampolines in their own page that's mapped in both.

**Blocks on**: paging-layer rework, syscall entry stub
rewrite, IST stack-switch updates, full TLB-shootdown
ordering with SMP.

**When to land**: when a `RDCL_NO=0` machine enters the test
fleet, OR when a workload demands defence-in-depth even on
silicon-safe CPUs. `arch::CpuMitigationsGet().needs_kpti` is
the live signal already in place.

See `.claude/knowledge/kpti-meltdown-investigation-v0.md` for
the project's recorded position.

### ~~C1-followup~~ Real per-zone allocator — LANDED 2026-05-01

**Was**: per-zone routing so `AllocateZoneFrame(kZoneDma)` returns
a frame whose physical address actually satisfies the zone
constraint.

**How it landed**: `kernel/mm/frame_allocator.{h,cpp}` gained
`AllocateFrameInRange(PhysAddr max_phys)` — a bitmap search that
clamps the highest frame index considered to
`max_phys >> kPageSizeLog2`, with the same direct-map zero policy
as the unrestricted `AllocateFrame`. `kernel/mm/zone.cpp`'s
`AllocateZoneFrame` now picks the ceiling per zone (16 MiB for Dma,
4 GiB for Dma32, no ceiling for Normal) and routes through the new
API. Self-test extended to assert the ceiling: a Dma frame above
16 MiB or a Dma32 frame above 4 GiB now panics with the offending
physical address.

**Note on full buddy-allocator design**: the original
"per-zone bitmaps + buddy free-lists" framing was deferred in
favour of the simpler ceiling-clamp approach because (a) the live
bitmap is already a single backing store covering all RAM, so
re-slicing it per zone would force a duplicate-bookkeeping refactor
for no behaviour benefit at v0 RAM sizes, and (b) buddy free-lists
buy contiguous-allocation speed which the existing
`AllocateContiguousFrames` already handles via a linear-scan that
nothing has yet identified as a hot path. If/when a zone genuinely
exhausts its sub-range (e.g. lots of <16 MiB DMA buffers), the
ceiling-clamp implementation already returns a clean `kNullFrame`
with a one-shot warn — the buddy refactor can land then without
changing any caller's contract.

### C2-followup — Slab freed-object poison + real KASAN

**Scope**: implement a slab allocator (currently kheap is the
only allocator), then stamp `kSlabFreedObjectPoison = 0xCC`
across freed slab objects on free + verify on alloc. Real
KASAN is a much bigger lift (shadow-memory mapping, compiler
plugin integration, per-access shadow lookup); only revisit
if the lite layer (kheap canary + frame poison + UBSAN) ever
misses something.

**Blocks on**: slab allocator existence (no slab today).

**When to land**: when a hot-path consumer demands sub-page
allocations and a slab cache is justified.

### A3-followup — Migrate ABI handle tables onto KFile / KMutex / KEvent / KSemaphore

**Scope**: route `SYS_MUTEX_*` / `SYS_EVENT_*` / `SYS_SEM_*`
through the KMutex / KEvent / KSemaphore types + per-process
`kobj_handles` table; migrate Win32 file handles and Linux
fd-table entries onto KFile.

**Blocks on**: ABI-preservation work — Win32 syscalls return
`kWaitObject0` / `kWaitTimeout` from infinite waits and
deadlock-detect callbacks; Linux fd table is exposed through
`O_*` flag bitmask + numeric fd allocation. Both surfaces
need careful preservation across the migration.

**When to land**: when handle-table audit pressure exceeds
the cost of moving each subsystem. The unified
`Process::kobj_handles` table is in place; concrete subclasses
(KMutex / KEvent / KSemaphore / KMailbox / KWaitable / KFile)
are landed. Next slice is the SYS_* surface migration itself.

### D7-followup — GDB stub completion

**Scope**:
  - **Serial RX wiring** — needs a real UART RX driver +
    IRQ handler that calls `GdbStubReceiveByte`.
  - **Resume-after-fault writeback** — copy the (potentially
    edited) `GdbRegSnapshot` back into the trap frame before
    iretq so a `G`-packet edit takes effect.
  - **Extable-wrapped `m`/`M`** — wrap the memory-access
    paths in extable-protected reads/writes so a bad address
    from GDB doesn't fault the kernel. Today the parser
    bounds the address to canonical-half + relies on the
    `#PF` recovery path.

**Blocks on**: the UART RX driver. The other two slices land
trivially once the first does.

**When to land**: when a real GDB-attach workflow becomes a
debugging priority. The protocol parser, register/memory
read+write paths, and fault-time register snapshot publishing
are all already in place.

### E3-followup — Register more drivers as fault domains

**Scope**: write teardown functions for `framebuffer`, `pci`,
`nvme`, `ahci`, `xhci`, `e1000`, `ramfs`, `fat32`,
`runtime_checker`, `breakpoints`. Currently 6 driver fault
domains are registered (soft-lockup / lockdep / event-trace
/ perf / nmi-watchdog / cleanroom-trace).

**Blocks on**: each driver's teardown story — most drivers
were written assuming run-once-at-boot semantics. Adding a
clean teardown for each is the actual work.

**When to land**: organically. Each driver gets a teardown
when a developer needs to restart it without rebooting (e.g.
hot-swap a USB device + re-probe xhci).

## What's done

The original 18-item plan (now-deleted
`kernel-debug-recommendations-plan.md`, closed 2026-04-28)
accomplished:

- **Init / register infrastructure (A1, A4)**: 11-phase
  RunPhase migration, `_init_array` invocation,
  `KERNEL_INITCALL` macro, central syscall cap-gating.
- **Synchronisation (B1, B1.4)**: SpinLock / Mutex / RwLock /
  SeqLock / RCU + lockdep-lite + canonical class IDs across
  every global sync primitive.
- **Boot ordering (A2)**: clocksource registry, HPET
  + invariant-TSC clocksources, portable tick wrapper, full
  call-site migration to `time::TickCount`.
- **Memory (C1, C2)**: zone scaffolding, kheap red-zone +
  caller-RIP tagging, shell `heap leaks watch` mode.
- **IPC (A3)**: KObject base, HandleTable, six concrete
  subclasses (Mutex / Event / Semaphore / Mailbox / Waitable
  / File).
- **Diagnostics (D1-D7)**: lockdep + soft-lockup + event
  tracer + PMU sample profiler + UBSAN runtime + heap leak
  tracker + GDB serial protocol stub. Full hot-path
  instrumentation: syscall enter, mutex acquire/release,
  IRQ, page fault, sched switch.
- **Mitigations (E1-E3)**: CPUID-based CET probe, KPTI
  investigation + needs_kpti runtime signal, per-driver
  fault-domain extension with 6 driver domains live.
- **Shell**: ~15 `inspect *` subcommands covering every
  subsystem with cheap counter accessors; `domain list` /
  `domain restart` for live driver-domain control;
  `cpufeatures` rollup; `tracer dump|kind|reset`; `perf
  dump`; `lockdep panic on|off`.

The recommendations plan met its goal: the kernel is now
reviewable end-to-end through the shell's `inspect` family,
every subsystem has a consistent reset surface for fault
domains, and the diagnostic infrastructure (event trace +
perf profile + lockdep + soft-lockup + GDB stub) is wired
into the live hot paths.
