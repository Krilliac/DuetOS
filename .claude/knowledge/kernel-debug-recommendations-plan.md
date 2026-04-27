# Kernel & Debug Design Recommendations Plan

## Status (2026-04-27)

### Landed

| Commit | Effect |
|--------|--------|
| _A1-infra_ (this commit) | `kernel/core/init.{h,cpp}` registry: `Phase` enum (13 phases), `InitcallRegister`, `RunPhase`, `InitSelfTest` (3 phases × 1 callback + bad-arg + failing-callback paths). Self-test wired into `kernel_main` after `FaultDomainSelfTest`. `KERNEL_INITCALL` macro deferred until `_init_array` is invoked at boot — registration is by direct call today. Imperative `kernel_main` body NOT migrated; see plan A1 follow-up. |

### Deferred (in priority order — see "Recommended ordering" below)

- [ ] A1-followup — Migrate `kernel_main` call sites to `RunPhase(...)` (incremental, site-by-site)
- [ ] A1-followup — Wire `_init_array` invocation at boot so `KERNEL_INITCALL` macro can use static-ctor registration
- [ ] A4 — Centralized syscall capability gate (`kSyscallCapTable`)
- [ ] C2 — Heap red zones, freed-page poison, slab freed-object poison
- [ ] B1 — Sync ladder (Mutex → RwLock → SeqLock → RCU-lite)
- [ ] A3 — `kernel/ipc/` with `KObject` + per-process handle table
- [ ] A2 — `kernel/time/` with clocksource abstraction
- [ ] B2 — Per-CPU runqueues + work stealing (real SMP)
- [ ] D1 — Lockdep-lite (locking-order graph)
- [ ] E1 — Intel CET (shadow stack + IBT)
- [ ] E2 — KPTI / Meltdown-mitigation status investigation
- [ ] C1 — Buddy allocator + memory zones (DMA / DMA32 / NORMAL / MMIO)
- [ ] D2 — Dynamic event tracer (per-CPU ring, `TRACE_EVENT(...)`)
- [ ] D7 — GDB serial stub on COM2
- [ ] D4 — Soft-lockup detector + per-CPU heartbeat
- [ ] D3 — PMU sample profiler (perf-record equivalent)
- [ ] D6 — Heap leak tracker (caller-RIP tagging)
- [ ] D5 — UBSAN klog runtime
- [ ] E3 — Per-driver fault-domain extension

## Resume prompt

> Read `.claude/knowledge/kernel-debug-recommendations-plan.md`. The "Status"
> table at the top tracks which items have landed. Pick the next unchecked
> item from the "Deferred" list (priority order matches the
> "Recommended ordering" table). Each item's section below names the files
> to touch and an associated verification step — treat those as the
> implementation contract. Mark the item landed in the Status table in the
> same commit as the work itself. A1 (formal init ordering) and A4
> (centralized capability gate) are the cheapest wins; B2 (SMP completion)
> is the largest single piece of work.

---

## Context

Recommendations for the OS itself — kernel internals and debug/diagnostic
surface — explicitly excluding subsystems (Win32 / Linux / graphics / etc.)
and excluding work that's already on the roadmap.

What's already strong in the tree (so this plan does **not** re-recommend
these): breakpoints + DR support, static `KBP_PROBE` sites, `klog` ring
with sinks + `TraceScope`, panic / crash-dump v1 with backtrace + peer-CPU
NMI snapshots, runtime invariant checker (~35 health checks), fault-domain
restartable subsystems, image guard, attack-sim, kernel stack guard pages,
`Result<T,E>`, NMI watchdog, capability bitset on `Process`, ring-3 smoke
harness.

What's structurally thin or missing (the surface this plan covers):

- `kernel/core/` has no real source — init ordering is implicit / scattered.
- `kernel/ipc/` and `kernel/time/` directories don't exist; their concerns
  live half in `arch/x86_64/`, half in `syscall/`.
- `kernel/sync/` ships **only spinlocks** — no mutex, RW lock, seqlock, RCU.
- Frame allocator is **bitmap linear-scan**; no buddy, no zones, no NUMA.
- Held-lock stacks are recorded for panic snapshots but there's no
  locking-order validator (no lockdep-equivalent).
- PMU is used **only** for NMI-watchdog overflow — no sample profiling.
- No KASAN / UBSAN / heap red zones / freed-page poisoning.
- No dynamic tracing (only static `KBP_PROBE` enum sites).
- No soft-lockup detector (NMI watchdog catches a full timer wedge, not a
  single CPU spinning in a kernel path).
- No remote-debug stub (no kgdb-style serial protocol).
- Capability checks are scattered across syscall handlers — no single gate.

Leverage scoring: **H** = high (changes how the kernel is reasoned about),
**M** = medium (large quality-of-life win for one subsystem), **L** =
lower (nice to have).

---

## A. Structural / architectural

### A1. Make `kernel/core/` real — formal init ordering   [H]

Today `kernel/core/` contains only `generated_synxtest_elf.h`. There is no
`kernel/core/init.cpp`, no `panic.cpp` lives in this directory (panic is
elsewhere), and the boot sequence is a hand-ordered list of calls in
`kernel_main`. As subsystems multiply, this hand-ordering becomes the place
where bugs hide ("driver X assumed Y was up, but on this build it wasn't").

Recommend: introduce `kernel/core/init.cpp` with an explicit
`enum class Phase { Earlycon, PhysMem, Paging, Heap, Idt, Apic, Time,
PerCpuBsp, Sched, Smp, Drivers, Vfs, Userland }` and a registration macro
`KERNEL_INITCALL(phase, fn)` that lands callbacks in a fixed-size table at
link time (no allocator at boot). `kernel_main` then becomes a single loop
over phases. Each call returns `Result<void, ErrorCode>`; a failed early
phase panics, a failed late phase marks the corresponding fault domain.

Files: new `kernel/core/init.{h,cpp}`, `kernel/core/panic.cpp` moved here
from its current home, `kernel/arch/x86_64/boot.S` keeps its job (just sets
up the C++ environment and jumps to `kernel_main`).

### A2. Promote `kernel/time/` — clocksource abstraction   [H]

Timekeeping today is split: `kernel/arch/x86_64/timer.{cpp,h}`,
`hpet.{cpp,h}`, `rtc.{cpp,h}`, plus `SYS_GETTIME_FT / SYS_NOW_NS /
SYS_SLEEP_MS` in `kernel/syscall/time_syscall.cpp`. There's no abstraction
that lets a future ARM64 port plug in a different timer, and no central
place that owns wall-clock vs. monotonic vs. boot-time.

Recommend: create `kernel/time/` with `clocksource.h` (an interface:
`u64 read_ns()`, `u64 resolution_ns()`, `bool monotonic()`),
`timekeeper.cpp` (owns CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_BOOTTIME),
`timer.cpp` (high-level periodic + one-shot), and `tick.cpp` (the per-CPU
scheduler tick). Existing HPET / TSC / LAPIC code becomes providers that
register themselves via `KERNEL_INITCALL(Phase::Time, ...)`. The syscall
layer becomes a one-line forward to `time::now_ns(clock_id)`.

### A3. Promote `kernel/ipc/` — kernel-object handle table   [H]

Today there's no `kernel/ipc/` directory. Mutexes, events, mailboxes, and
wait-queues are scattered through `kernel/syscall/syscall.cpp` (~110 KB of
mixed dispatch and impl) and `kernel/sched/sched.cpp`. As more syscalls
land this becomes unmaintainable, and the hard rule from CLAUDE.md ("one
TCP stack, one VFS, one registry, one window manager — each reachable from
multiple ABI front-ends, but with one kernel-owned implementation")
implicitly demands the same shape for IPC objects.

Recommend: introduce `kernel/ipc/` with a single per-process **handle
table**, kernel-object base type `KObject` (refcounted, type-tagged), and
concrete subclasses `KMutex`, `KEvent`, `KSemaphore`, `KMailbox`,
`KWaitable`. Native and Win32/NT and Linux ABI front-ends all bottom out at
the same `KObject` set; the handle table is what they translate to/from
their respective ABI handle shapes. This is the single biggest
"refactoring debt that compounds" item — fix it before the table gets any
bigger.

### A4. Centralize the capability gate   [H]

`Process::caps` is the source of truth, but cap checks today are sprinkled
across individual syscall handlers as ad-hoc `if (!(caps & kCapX)) return
-EPERM;` lines. The exploration noted enforcement is incomplete — easy to
forget, hard to audit.

Recommend: a single `SyscallGate(SyscallNumber n, Process* p) ->
Result<void, ErrorCode>` called by the dispatcher *before* any handler
runs, driven by a static const `kSyscallCapTable[N]` (one row per syscall
number, listing the required cap mask). Handlers stop checking caps; the
table is the audit surface. This pairs with A1 (initcall-registered) and
makes the "could a malicious PE/ELF reach this path?" review question into
a one-table grep.

Files: `kernel/syscall/syscall.cpp`, new `kernel/syscall/cap_table.def` (an
X-macro, mirroring the existing `syscall_names.def` style).

---

## B. Concurrency & SMP

### B1. Sync primitives ladder   [H]

`kernel/sync/` ships only `SpinLock`. Everything from waitqueue logic to
process-table mutation either spins (wasting cycles holding IRQs off
across long sections) or rolls a one-off pattern. The "no recursive, no
MCS, no priority inheritance" comment in `spinlock.h:23–33` is honest, but
the absence of any other primitive forces the wrong tool everywhere.

Recommend a four-step ladder:
1. **`Mutex`** (sleeping lock) — uses the existing wait-queue infrastructure
   in `sched/`. Trivial wins: anything in process / VFS / IPC that today
   spins for milliseconds.
2. **`RwLock`** (reader-writer) — the address-space already wants this
   (`AddressSpace` is described as RW-locked but rolls its own).
   Consolidate.
3. **`SeqLock`** — for read-mostly hot data (timekeeper, per-CPU stat
   counters). Cheaper than RwLock when readers vastly outnumber writers.
4. **RCU-lite** — quiescent-state RCU keyed off the scheduler tick. Worth
   it for the IPC handle table (A3) and the driver registry, both of
   which are read on every syscall and written rarely.

File: extend `kernel/sync/` — one TU per primitive, all in the same
directory. Held-lock tracking already exists per CPU
(`kPerCpuMaxHeldLocks`); extend it to record the new primitives so panic
snapshots remain useful.

### B2. Finish SMP — per-CPU runqueues + work stealing   [H]

The scaffolding is there: `arch/x86_64/smp.{cpp,h}`, `ap_trampoline.S`,
the `PerCpu` struct already holds `current_task` + `need_resched` per CPU.
What's missing is the AP bring-up call site, the per-CPU runqueue, and
the load-balancer.

Recommend: a single per-CPU `RunQueue` in `kernel/sched/runqueue.{h,cpp}`,
preserving today's "FIFO inside a priority class" shape (don't introduce
MLFQ yet — keep that for when there's a real workload to tune against).
On `SchedYield` / tick, pick locally; if local empty, steal one task from
the busiest peer (random victim with retry, not full scan, to keep
overhead O(1) on small SMP). Pin the idle task and the `kthreadd`-equivalent
to BSP only.

This unlocks: (a) the existing CPU-per-task affinity field starts meaning
something, (b) the TLB-shootdown path stops being a no-op, (c) the
soft-lockup detector (D4) becomes meaningful (today, with one CPU, "soft
lockup" and "hard lockup" are the same condition).

---

## C. Memory

### C1. Replace bitmap linear-scan with buddy + zones   [M]

`kernel/mm/frame_allocator.cpp` walks a flat bitmap to find a free frame.
That's fine for v0 (it's correct, deterministic, easy to inspect with the
runtime checker), but it scales linearly with RAM size and can't satisfy
contiguous multi-page allocations cheaply (DMA buffers, large pages, the
1 GiB MMIO arena). It also has no notion of "memory below 4 GiB for
legacy DMA" or "memory in NUMA node N".

Recommend: a buddy allocator (orders 0..10, covering 4 KiB..4 MiB) layered
**on top of** the existing bitmap (the bitmap stays as the canonical
truth so the runtime checker continues to work). Split the address space
into zones — `ZONE_DMA` (<16 MiB, only if anything actually needs it),
`ZONE_DMA32` (<4 GiB, for legacy 32-bit DMA), `ZONE_NORMAL` (everything
else), `ZONE_MMIO` (the high-half arena). NUMA nodes are an axis on top of
zones; keep it as a single node until two-socket boxes show up in the
test plan.

File: `kernel/mm/buddy.{h,cpp}` adjacent to the existing allocator;
`AllocateFrame()` becomes a thin wrapper that calls into the buddy.

### C2. Page + heap poisoning, KASAN-lite red zones   [H]

There are no memory-corruption diagnostics today beyond the post-hoc
runtime checker. A heap underrun that overwrites the next slab header
will only be caught when the next allocation trips the invariant scan —
by which point the call stack of the corruption is gone. KASAN proper is
a big lift (shadow memory, compiler instrumentation), but a 90% solution
is cheap.

Recommend three layers, gated on a single `DUETOS_MEM_DEBUG` build flag:
1. **Heap red zones** — `kheap` allocates with a 16-byte canary on each
   side; `free()` checks both. O(1) overhead per alloc/free. Catches
   linear over/underruns immediately, with the freeing call stack live.
2. **Freed-page poison** — when a frame goes back to the allocator, fill
   with `0xDE` (or zero, if cheaper to detect). Catches use-after-free
   reads of stale pages on the next allocation.
3. **Slab freed-object poison** — same idea, fill freed slab objects with
   `0xCC`. When the runtime checker walks a slab and finds a non-`0xCC`
   pattern in a freed slot, fire a HealthIssue.

This is **not** real KASAN (no shadow memory, no compiler-side
instrumentation, no fine-grained access checks), but it eats 90% of the
real bugs at a fraction of the cost. Keep real KASAN as a "later, when we
have a stable allocator" item — don't try both at once.

File: `kernel/mm/kheap.cpp`, `kernel/mm/frame_allocator.cpp`, plus a small
new `kernel/mm/poison.h` with the canary constants and check helpers.

---

## D. Observability & debugging

### D1. Lockdep-lite — locking-order validator   [H]

Held-lock stacks already exist per CPU (`kPerCpuMaxHeldLocks = 8`, used by
the panic snapshot). Today we know **what** locks a CPU holds at panic
time but not whether the order they were acquired in ever conflicts with
how another CPU acquired the same set.

Recommend: build a **locking-order graph** at runtime. Every time a lock
is acquired, record the edge "(any currently-held lock) → (this lock)".
If the graph has ever recorded the reverse edge, you have a potential
deadlock — fire a HealthIssue (don't panic; downgrade to log + flag, the
graph has false positives until lock classes are tagged). When the
graph stabilizes (no new edges for N seconds), promote violations from
"warn" to "panic" via a runtime knob. The graph is bounded — typically
< 200 lock classes in a kernel — so a fixed 256×256 bitset is enough.

This catches the entire class of "works on single CPU, deadlocks at
random under load" bugs, which is otherwise the worst kind of bug to chase
with only post-hoc panic snapshots. Pairs naturally with B1 (more lock
types) and B2 (real SMP).

File: `kernel/sync/lockdep.{h,cpp}`, hooks in each primitive's `Acquire()`.

### D2. Dynamic event tracer (ring) — beyond static `KBP_PROBE`   [M]

`KBP_PROBE` fires on a fixed enum of named sites. That's great for
documented hot spots, but useless for "what did the scheduler do in the
500 ms before this latency spike?" or "show me every page-fault on CPU 3
in the next second".

Recommend: a per-CPU lockless ring of fixed-size `TraceEvent` records
(timestamp, CPU id, event type tag, 4 inline u64 args). Event types are
declared via X-macro (mirrors `syscall_names.def`), each producing a
`TRACE_EVENT(sched_switch, prev_pid, next_pid, reason, 0)` macro. The ring
is cheap enough (10–30 cycles per event) to leave on by default with a
runtime per-event-type bitmask. Decode tooling lives host-side: dump the
ring on demand (new shell command `trace dump`) over the same crash-dump
serial framing.

This is **not** ftrace (no function-graph, no dynamic patching); it is
the tracing primitive you actually need for everyday debugging. ftrace /
kprobes can come later as a strictly bigger superset.

File: `kernel/diag/tracer.{h,cpp}`, plus 30–50 `TRACE_EVENT(...)`
sprinkles in sched, traps, syscall dispatch, paging, IPC.

### D3. PMU sample profiler ("perf record"-equivalent)   [M]

The PMU is already wired up — but only for the NMI watchdog overflow
counter. The rest of the CPU's performance-monitoring capability is
dormant. There's no way today to answer "where is the kernel spending its
cycles?" except by reading code and guessing.

Recommend: a per-CPU PMU sampler that arms a counter (cycles or
retired-instructions) to overflow every N events, and on overflow records
the trapped RIP into a per-CPU ring. A user-space tool (or a shell
command) drains the ring and a host-side script aggregates RIPs into a
flat / call-graph profile via the existing symbol table from
`kernel/util/symbols.cpp`. AMD support is bookkept differently from Intel
but the surface is small (Intel: PerfEvtSel0..3, AMD: PerfCtl0..5).

File: `kernel/arch/x86_64/pmu.{h,cpp}` (new), `kernel/diag/profiler.{h,cpp}`.
Reuses the NMI delivery path that the watchdog already set up.

### D4. Soft-lockup detector + per-CPU heartbeat   [M]

The NMI watchdog detects a fully wedged kernel (timer tick stopped). It
**doesn't** detect "CPU 1 is spinning forever inside a kernel function
with IRQs on but never voluntarily yielding" — that CPU is taking timer
ticks fine, but no useful work is happening.

Recommend: a per-CPU `last_voluntary_schedule_at` timestamp updated on
every `schedule()` / IRQ-return-to-user. A per-CPU watchdog kthread
(woken from the heartbeat that already runs every 5 s) checks each peer:
if `now - last_voluntary_schedule_at > 10 s`, log a soft-lockup warning
with the offending CPU's RIP (sampled via IPI). After 60 s of no
progress, fire a HealthIssue at `Isolate` severity (kill the offending
task if it's user mode; panic if kernel).

This pairs with B2 (per-CPU runqueues) — without real SMP, this detector
has nothing to detect.

File: `kernel/diag/softlockup.{h,cpp}`, hooks into existing `heartbeat.cpp`.

### D5. UBSAN with klog runtime   [L]

UBSAN is essentially free at compile time (`-fsanitize=undefined`) once
you have a runtime that handles the handful of `__ubsan_handle_*` symbols.
The runtime can be ~150 lines: each handler writes one structured klog
line with kind (signed-overflow, oob-array, null-deref, etc.) + source
location, then either continues (default) or panics (knob).

Recommend wiring this up as a debug-build-only feature flag. Cost: 5–10%
size, near-zero runtime hit on the hot path. Catches a class of bugs
(integer overflow in offset math, alignment violations) that the runtime
checker can't see post-hoc.

File: `kernel/diag/ubsan.{h,cpp}` (new), CMake preset
`x86_64-debug-ubsan` adds `-fsanitize=undefined -fno-sanitize-trap=all`.

### D6. Heap leak tracker — caller-RIP tagging   [L]

Today an allocator leak ("we allocated 50 MB of slab objects somewhere
and never freed them") is invisible until the allocator runs out and the
runtime checker fires `OutOfMemory`.

Recommend: tag every `kheap` allocation with the caller's RIP (cheap —
single `__builtin_return_address(0)`). A new shell command
`heap stats` walks the live-allocation table and prints the top 10
RIPs by bytes outstanding, resolved through the symbol table. Cost: 8
bytes per live allocation, no runtime overhead in the hot path.

File: `kernel/mm/kheap.cpp` extension; reuse `kernel/util/symbols.cpp`.

### D7. GDB serial stub (kgdb-equivalent over COM2)   [M]

Crash dumps are great for post-mortem; live debugging is painful (the
shell breakpoint commands are useful but limited to one CPU and require
typing into a target shell that may itself be wedged). A GDB
remote-serial-protocol stub on COM2 (COM1 is already klog) would let any
GDB connect with `target remote /dev/ttyS1` and step the kernel.

The GDB protocol is small (~10 packets handle 90% of debugging:
`g`/`G` registers, `m`/`M` memory, `c`/`s` continue/step, `Z0`/`z0`
breakpoints, `?` halt reason). The breakpoint subsystem already does the
heavy lifting (`kernel/debug/breakpoints.{h,cpp}` has int3 + DR support);
this is just an alternate UI in front of it.

Cost: ~600 lines of C++. Pays back the first time someone needs to debug
SMP corruption in flight.

File: `kernel/debug/gdb_stub.{h,cpp}` (new).

---

## E. Hardening

### E1. Intel CET — shadow stack + IBT   [M]

Stack canaries (`kernel/security/stack_canary.cpp`) catch *some* stack
smashes but only on function exit, only if the canary is between the
target and the buffer. Hardware Control-flow Enforcement Technology (CET)
on every Tiger Lake / Zen 3+ CPU gives you (a) a hardware shadow stack
that the attacker can't write to from C, and (b) Indirect Branch Tracking
that requires every indirect-call target to begin with `endbr64`.

Recommend: enable both, kernel-only first. The shadow stack is a per-task
allocation (one extra page in the task struct) and a few extra MSR
writes on context switch. IBT requires every kernel indirect-call target
to have `endbr64` as its first instruction — a Clang/GCC flag handles
this for compiled C++; the hand-written assembly entry points
(`exceptions.S`, `context_switch.S`) need explicit `endbr64` added.

This complements (does not replace) the canary; canary catches linear
overruns, CET catches ROP/JOP. Both are hardware-cheap.

File: `kernel/arch/x86_64/cet.{h,cpp}` (new), tweaks in `traps.cpp` and
`sched/context_switch.S`. CMake adds `-fcf-protection=full`.

### E2. Verify KPTI / Meltdown mitigation status   [M]

CLAUDE.md lists "W^X enforced, ASLR, stack canaries, control-flow
integrity" as goals, and the runtime checker confirms SMEP/SMAP/NXE bits.
But Meltdown (CVE-2017-5754) needs **kernel page-table isolation** —
separate kernel and user PML4s, switched on every entry/exit. This is
distinct from SMEP/SMAP and isn't in the audit checklist. The
`AddressSpace` model would need a per-process *user-only* PML4 plus a
shared *kernel-only* PML4 swapped in on syscall entry.

Recommend: explicitly verify status; if unmitigated, add it to the
roadmap as a v0.1 hardening item. The CPU report (CPUID leaf for
RDCL_NO) tells us when the host CPU doesn't need the mitigation, so a
runtime check can skip the cost on safe CPUs.

File: investigation in `kernel/arch/x86_64/cpu_features.cpp` (if it
exists; create otherwise), then implementation gated on the result.

### E3. Per-driver fault-domain extension   [L]

`kernel/security/fault_domain.cpp` already has a 16-entry registry of
restartable subsystems. Extend it: every driver registered via the
PCI/USB/etc. enumerators automatically gets a fault domain entry, and a
driver-local fault (segfault inside the driver, hung DMA) restarts that
specific driver instead of panicking the kernel.

Recommend: a `Driver` base class with `Init() / Teardown() / Probe()`
methods that the bus enumerators call, with the fault domain wired up at
registration time. This lands the "every driver must be probed" rule from
CLAUDE.md as a structural enforcement instead of a convention.

File: `kernel/drivers/driver_base.{h,cpp}` (new),
`kernel/security/fault_domain.cpp` extension. Touches every existing
driver registration site — moderate sprawl, high uniformity payoff.

---

## Recommended ordering (leverage × prerequisite chain)

| Order | Item | Theme | Score | Blocks / unblocks |
|------:|------|-------|-------|-------------------|
| 1 | A1 init ordering | Structural | H | Unblocks everything else's registration story |
| 2 | A4 capability gate | Structural | H | Closes a security-correctness gap *now*, before more syscalls land |
| 3 | C2 poison + red zones | Memory | H | Catches heap bugs from this point forward; cheap |
| 4 | B1 sync ladder | Concurrency | H | Unblocks A3 (IPC handle table) and B2 (SMP) |
| 5 | A3 IPC handle table | Structural | H | One-time; the longer it waits, the more code needs rework |
| 6 | A2 kernel/time/ | Structural | H | Modest, but unblocks a clean ARM64 port later |
| 7 | B2 SMP completion | Concurrency | H | Largest single project; do **after** B1 |
| 8 | D1 lockdep-lite | Observability | H | Pairs with B2; the moment SMP is real, you want this on |
| 9 | E1 CET | Hardening | M | Cheap once toolchain flags are set |
| 10 | E2 KPTI verification | Hardening | M | Investigation first; implementation only if needed |
| 11 | C1 buddy + zones | Memory | M | Becomes urgent once DMA drivers land |
| 12 | D2 dynamic tracer | Observability | M | High everyday-debugging value; moderate cost |
| 13 | D7 GDB stub | Observability | M | Pays for itself the first SMP race you debug |
| 14 | D4 soft-lockup | Observability | M | Only meaningful after B2 |
| 15 | D3 PMU sampler | Observability | M | Performance work; not critical until there's something to tune |
| 16 | D6 heap leak tracker | Observability | L | Small, isolated, high audit value |
| 17 | D5 UBSAN | Observability | L | Free with toolchain; runtime is ~150 lines |
| 18 | E3 driver fault domains | Hardening | L | Lands when the driver registry exists |

---

## Verification (per item)

Each item has a corresponding verification harness — none of these should
land without one:

- **A1** — `KERNEL_INITCALL` registration; build a unit test that
  registers three callbacks in different phases and confirms they fire
  in order. On-target: log every initcall name + duration; assert no
  phase reorders across boots.
- **A2** — Add a clocksource self-test in the runtime checker: read
  monotonic twice, assert non-decreasing; cross-check HPET against TSC
  drift over 1 s.
- **A3** — Existing ring-3 smoke harness exercises mutex/event syscalls;
  extend to allocate 10 000 handles, free them, assert table is empty.
- **A4** — `attack_sim` harness already simulates privileged ops without
  the cap; assert every one returns `-EPERM`. Add a fuzzer that calls
  every syscall number with empty caps and confirms `-EPERM` for all
  capped ones.
- **B1** — Per-primitive unit test (acquire/release, contention, RAII
  guard). Plus a stress test: N threads × M iterations on a counter.
- **B2** — Existing scheduler smoke; extend to N CPUs, assert tasks
  migrate, assert work-steal triggers when one CPU is idle.
- **C1** — Allocate every order 0..10, free interleaved, assert
  bitmap-of-truth still consistent. Stress: 1 M alloc/free pairs.
- **C2** — Deliberately overrun a heap allocation; assert canary check
  fires. Use-after-free read; assert poison pattern detected.
- **D1** — Synthetic AB / BA test; assert order graph fires warning.
- **D2** — `trace dump` after a known workload (10 syscalls); assert
  decoded events match expected sequence.
- **D3** — Spin a tight loop in a known function; assert profiler
  attributes >90% of samples to it.
- **D4** — Spin a kernel thread without yielding; assert detector fires
  within 10 s.
- **D5** — Deliberately trigger a signed overflow; assert UBSAN klog
  line.
- **D6** — Allocate without freeing in a known site; assert `heap stats`
  attributes the bytes to that RIP.
- **D7** — Connect GDB, set breakpoint, hit it, inspect registers,
  continue; assert kernel resumes cleanly.
- **E1** — Attack-sim adds a ROP-style indirect call to a non-`endbr64`
  target; assert CPU raises #CP.
- **E2** — Investigation produces a yes/no + a one-paragraph
  justification in `.claude/knowledge/`. If yes: add a Meltdown-style
  test (try to read kernel memory speculatively from ring 3) and
  confirm it fails post-mitigation.
- **E3** — Inject a fault into a registered driver; assert the
  driver-only fault domain restarts and the kernel survives.

---

## What this plan deliberately does **not** include

- Anything in the Win32 / Linux / POSIX subsystems (out of scope for this
  plan).
- Items already on the roadmap or in `.claude/knowledge/`: breakpoints
  phase 2a/3/4, klog overhaul, crash dump v0, attack-sim kernel v1,
  scheduler v0, Result type, kernel stack guards, fault-domain v0.
- Anything in deferred work: ARM64, CI/CD wiring, registry, signals,
  fork/exec on native ABI, 3D graphics path.
- Real KASAN with shadow memory (deliberate — C2 is the 90% solution at
  10% of the cost; do real KASAN later if telemetry shows we need it).
- ftrace / kprobes / eBPF (deliberate — D2 is the everyday-debugging
  primitive; the dynamic-instrumentation tier can come later).
- New native syscalls. Adding syscalls is an ABI commitment per
  CLAUDE.md; this plan is structural and doesn't grow the published
  surface.

