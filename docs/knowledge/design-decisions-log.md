# CustomOS — Design Decisions Log

_Last updated: 2026-04-20_

## Purpose

A **living, append-only log** of concrete design decisions made during
implementation. Each entry records what was chosen, why, what it rules
out, and **a "revisit when X" marker** so the decision can be refined
once downstream context arrives (e.g. SMP, userland, first real
peripheral).

This is a companion to:

- `roadmap-to-gui-desktop.md` — the 13-track vision and phasing.
- `security-malware-hard-stop-plan.md` — the security posture we're
  building toward.
- `track-2-platform-foundation-implementation-plan.md` — the platform-
  bring-up contract these decisions are executing against.
- `implementation-backlog-gates.md` — the gate framework every slice
  has to clear.

The entries here are the **ground truth of what actually shipped**,
which sometimes differs from what the planning docs prescribed; when
it does, the log flags the divergence so the planning doc can be
updated later.

**Format per entry:**

- **Scope & commit:** short identifier, commit hash.
- **Decision:** the thing we committed to.
- **Why:** rationale.
- **What it rules out / defers:** so we don't accidentally regress.
- **Revisit when:** the concrete trigger to come back.
- **Related roadmap track(s):** which of the 13 tracks this touches.

Append new entries at the bottom. Never delete — superseded decisions
get an inline "superseded by <commit>" note and stay.

---

## 001 — Multiboot2 as the sole boot protocol for v0

- **Scope:** `kernel/arch/x86_64/boot.S`, `boot/grub/grub.cfg`
- **Commit:** `5dd2ab3` (first buildable image) and `025fa2b` (ISO)
- **Decision:** Kernel is loaded via GRUB's Multiboot2 protocol. No
  direct UEFI `BOOTX64.EFI` entry point yet.
- **Why:** Multiboot2 is the fastest path to a bootable ELF; GRUB
  handles the UEFI-or-BIOS hand-off behind us. Writing our own UEFI
  loader before the kernel has any code to load would be wasted
  effort.
- **Rules out / defers:** A proper UEFI-direct boot path (Track 2 Phase
  A). Secure Boot chain. Framebuffer handoff (we use serial only).
- **Revisit when:** Track 2 platform-foundation plan enters the "UEFI
  handoff contract" slice — the planned `BootInfo` blob supersedes the
  raw `multiboot_info` pointer we're plumbing today.
- **Related tracks:** Track 2 (Platform), Track 13 (Security — Secure
  Boot chain).

---

## 002 — Higher-half kernel at `0xFFFFFFFF80000000`

- **Scope:** `kernel/arch/x86_64/boot.S`, `kernel/arch/x86_64/linker.ld`
- **Commit:** `76eb818`
- **Decision:** Kernel runs at virtual base `0xFFFFFFFF80000000`
  (canonical x86_64 higher-half `-2 GiB`), with the first 1 GiB of
  physical RAM directly mapped there.
- **Why:** Standard Unix-like convention. Lets userland own the low
  canonical half cleanly. `PhysToVirt` becomes a trivial offset add.
- **Rules out / defers:** Larger direct maps (we cap at 1 GiB today).
  Per-process address spaces (still using one global PML4).
- **Revisit when:** We bring up a second process-address-space during
  Track 4 (Process Model) — the direct map will need to be pinned in
  every PML4, or we'll move it behind an explicit `vmap` layer.
- **Related tracks:** Track 3 (MM), Track 4 (Process).

---

## 003 — Bitmap physical frame allocator with conservative defaults

- **Scope:** `kernel/mm/frame_allocator.cpp`
- **Commit:** `072a46a`
- **Decision:** Every bit starts "used"; only explicit Multiboot2
  "available" regions are flipped to "free". Low 1 MiB, kernel image,
  Multiboot info, and the bitmap itself stay reserved.
- **Why:** "Deny by default" for memory mirrors the posture we want
  for executable trust later (Track 13). A frame we forgot to mark
  reserved is a silent corruption; a frame we forgot to mark free is a
  noisy out-of-memory we can trace.
- **Rules out / defers:** Buddy allocator (linear scan is fine below a
  few GiB). NUMA awareness. Zone allocator for DMA32 / DMA16.
- **Revisit when:** First DMA-limited device driver needs a guaranteed
  low address (Track 6 — DMA-capable drivers), or profiles show the
  linear scan as a hot path.
- **Related tracks:** Track 3 (MM), Track 6 (Drivers).

---

## 004 — Canonical GDT/IDT with exception-vector-only scope at first

- **Scope:** `kernel/arch/x86_64/gdt.cpp`, `kernel/arch/x86_64/idt.cpp`,
  `kernel/arch/x86_64/exceptions.S`
- **Commit:** `3d64bdf`; extended to IRQ vectors 32..47 + 0xFF in
  `88a9ae1`
- **Decision:** GDT holds the minimum for long-mode kernel operation
  (null, kernel code, kernel data; user segments declared but unused
  until ring 3). IDT has 32 CPU-exception vectors; hardware IRQ
  vectors are added case-by-case.
- **Why:** Extra descriptors are load-bearing once declared (TSS,
  IST, user-mode segments) — declaring them empty is worse than not
  declaring them. Add when we cross the ring boundary.
- **Rules out / defers:** TSS. IST stacks for critical exceptions
  (#DF, #MC, #NMI — all currently share the kernel stack). Ring 3
  entry.
- **Revisit when:** First ring-3 transition (Track 4) — we'll need
  TSS, user-mode GS base, SYSCALL/SYSRET MSRs. Also revisit when SMP
  lands (Track 2) — AP bring-up needs per-CPU GDT/TSS.
- **Related tracks:** Track 2 (SMP), Track 4 (Process).

---

## 005 — 2 MiB first-fit + coalescing kernel heap

- **Scope:** `kernel/mm/kheap.{h,cpp}`
- **Commit:** `6da5245`
- **Decision:** Heap is a 2 MiB contiguous allocation from the frame
  allocator (`AllocateContiguousFrames(512)`), managed as a first-fit
  freelist with bidirectional coalesce-on-free. 16-byte `ChunkHeader`.
- **Why:** First-fit is a couple of hundred lines; buddy and slab are
  ~1000+ lines each. For boot-time allocations (Task structs, stacks,
  page tables) the allocation rate is low and fragmentation is bounded.
  Upgrade when real workloads demand it.
- **Rules out / defers:** Buddy allocator. Slab allocator. Per-CPU
  magazines. Kernel-side GC. Guard pages around each allocation.
- **Revisit when:** Profiles show heap time as a hot path, or when a
  driver needs a pool with specific alignment / size class guarantees
  (Track 6). Also revisit when we add KASAN-style poisoning (Track 13).
- **Related tracks:** Track 3 (MM), Track 13 (Security — heap hardening).

---

## 006 — Boot-PML4 adoption for the managed paging API

- **Scope:** `kernel/mm/paging.{h,cpp}`
- **Commit:** `c353a5e`
- **Decision:** `PagingInit` reads CR3 to adopt the boot-established
  PML4 rather than building a fresh one. Adds a 512 MiB MMIO arena at
  `0xFFFFFFFFC0000000` on top. EFER.NXE is enabled here.
- **Why:** Building a fresh PML4 would require either a CR3 switch
  mid-boot (with a correctly-aligned trampoline) or a careful overlay
  — both risky. The boot PML4 already has the direct map we want; we
  only need to ADD mappings, never replace.
- **Rules out / defers:** Per-process address spaces (still one global
  PML4). Splitting the boot 2 MiB PS pages into 4 KiB (we panic if you
  try to map inside [0..1 GiB)). KASLR (kernel is at a fixed virt
  address).
- **Revisit when:** Track 4 process model lands — we'll fork the PML4
  per process, which triggers the discussion of how to share the
  higher-half direct map efficiently (answer: pin PML4 entries
  511..256 across every address space).
- **Related tracks:** Track 3 (MM), Track 4 (Process), Track 13 (KASLR).

---

## 007 — MMIO arena as bump-allocator, no reclamation

- **Scope:** `kernel/mm/paging.cpp` — `MapMmio` / `UnmapMmio`
- **Commit:** `c353a5e`
- **Decision:** MMIO virtual range is handed out by a monotonic cursor
  from `kMmioArenaBase`. `UnmapMmio` tears down the PTEs but does not
  recycle the virtual range.
- **Why:** Drivers for the boot devices (LAPIC, IOAPIC, eventually HPET,
  AHCI, NIC) live for the whole uptime. Fragmentation is bounded by the
  number of distinct MMIO windows the kernel ever uses — tens, not
  thousands. 512 MiB of arena handles that indefinitely.
- **Rules out / defers:** Virtual-range recycling. Hot-unplug support
  for MMIO-backed devices.
- **Revisit when:** USB/PCIe hot-plug driver model — ephemeral MMIO
  windows churn the arena; at that point we add a freelist or a slab
  of fixed-size virtual regions.
- **Related tracks:** Track 3 (MM), Track 6 (Drivers).

---

## 008 — 8259 PIC fully masked; LAPIC is the only sink

- **Scope:** `kernel/arch/x86_64/pic.cpp`, `kernel/arch/x86_64/lapic.cpp`
- **Commit:** `88a9ae1`
- **Decision:** `PicDisable` issues ICW1..ICW4 to remap the PIC off the
  CPU exception range (vectors 0x20..0x2F), then masks every line with
  OCW1=0xFF/0xFF. From that point forward the LAPIC is the only IRQ
  target.
- **Why:** On any modern box the IOAPIC is authoritative; leaving the
  8259 enabled causes dual-deliver bugs (legacy IRQ fires twice, once
  via PIC once via IOAPIC). Remap-then-mask keeps any chipset-level
  spurious IRQ from being decoded as `#GP` or `#DF`.
- **Rules out / defers:** Legacy-only systems that don't have an APIC
  (no longer exists). Boot paths that rely on the PIT through the PIC
  (we use LAPIC timer).
- **Revisit when:** Never. This is a terminal decision for x86_64.
- **Related tracks:** Track 2 (Platform).

---

## 009 — 100 Hz LAPIC timer, PIT-calibrated

- **Scope:** `kernel/arch/x86_64/timer.cpp`
- **Commit:** `88a9ae1`
- **Decision:** LAPIC timer runs in periodic mode at 100 Hz (10 ms
  tick). Calibrated against PIT channel 2 (11932 ticks = 10 ms) once
  at boot.
- **Why:** 100 Hz is the classic Unix tick. High enough for a
  non-realtime scheduler, low enough that the IRQ cost is invisible.
  PIT calibration is portable across every x86 machine; the TSC-
  deadline fast-path needs invariant TSC + CPUID, not always safe on
  older VMs.
- **Rules out / defers:** Tickless / dyntick kernel. TSC-deadline
  mode. HPET as timer source. Per-CPU timers.
- **Revisit when:** Power management enters scope (Track 13 +
  hardware target matrix — idle-tick elimination saves battery),
  or when the scheduler grows enough to benefit from finer
  granularity.
- **Related tracks:** Track 2 (Platform), Track 13 (Power).

---

## 010 — Round-robin preemptive scheduler, single CPU

- **Scope:** `kernel/sched/sched.{h,cpp}`,
  `kernel/sched/context_switch.S`
- **Commit:** `38ac8e4`
- **Decision:** Single runqueue, FIFO, preemption driven by
  `need_resched` flag set in the timer IRQ + consumed after EOI in
  the IRQ dispatcher. 16 KiB kernel stacks, no guard pages. No
  priorities, no classes.
- **Why:** Round-robin is the smallest thing that actually schedules.
  MLFQ, CFS, and priority inheritance all come later — putting them in
  first would freeze decisions we don't have enough context for yet.
- **Rules out / defers:** Priorities. Real-time class. CPU affinity.
  Stack guard pages. Per-CPU runqueues + work-stealing.
- **Revisit when:** First interactive workload (Track 9 — compositor
  needs guaranteed wake latency), SMP lands (Track 2 — runqueue
  goes per-CPU), or stack overflows happen in practice (add guard
  pages via the paging API).
- **Related tracks:** Track 2 (SMP), Track 4 (Process), Track 9 (GUI
  responsiveness).

---

## 011 — Blocking primitives: tick-driven sleep + wait queues + mutex

- **Scope:** `kernel/sched/sched.{h,cpp}`
- **Commit:** `cb6c316` (sleep), `4239ddd` (wait queues + mutex)
- **Decision:** Three primitives share the task state machine:
  `SchedSleepTicks` parks on a sleep queue woken by the timer's
  `OnTimerTick`; `WaitQueue` is a FIFO parked by explicit wake;
  `Mutex` is built on WaitQueue with Unlock-time hand-off (owner
  assigned before wake, no thundering herd). `MutexUnlock` by
  non-owner panics.
- **Why:** Sleep, wait, and lock are the three primitives drivers need
  to block on an IRQ without busy-waiting. Hand-off gives mutexes
  deterministic FIFO fairness without building priority inheritance
  first.
- **Rules out / defers:** Condition variables (drop-mutex-and-block
  atomically). Timed waits on `WaitQueue`. Cancellable blocking.
  Priority inheritance (not needed until priorities exist).
- **Revisit when:** First driver that needs `drop-mutex-and-wait` —
  the classic producer/consumer condvar pattern. Also revisit when
  SMP lands — we'll need spinlock-guarded internals.
- **Related tracks:** Track 4 (IPC), Track 6 (Drivers).

---

## 012 — ACPI discovery via Multiboot2 tag, XSDT-preferred

- **Scope:** `kernel/acpi/acpi.{h,cpp}`
- **Commit:** `a45c4b5`
- **Decision:** RSDP is obtained from Multiboot2 tags (type 14 or 15),
  not from an EBDA scan. XSDT is preferred over RSDT. v1 checksum + v2
  extended checksum + every SDT checksum all validated and panic on
  failure. Only MADT is parsed; FADT/MCFG/HPET deferred.
- **Why:** GRUB always provides the RSDP tag; a fallback scanner adds
  code that'll rot without exercise. Checksum failure at boot is the
  firmware lying about something load-bearing — silent continuation is
  worse than a clear halt. Aligned with Track 2 planning doc §4.2
  ("strict + defensive" ACPI parser).
- **Rules out / defers:** FADT (SCI vector, reset register), MCFG
  (PCIe ECAM), HPET (high-precision timer), SRAT (NUMA). AML
  interpreter for DSDT/SSDT.
- **Revisit when:** PCI enumeration starts (needs MCFG). HPET becomes
  interesting for high-resolution timing. Power management (needs
  FADT + AML for SLP_TYP values).
- **Related tracks:** Track 2 (Platform), Track 6 (Drivers —
  discoverability).

---

## 013 — IOAPIC driver: mask-on-init, high-half-first writes, MPS overrides

- **Scope:** `kernel/arch/x86_64/ioapic.{h,cpp}`
- **Commit:** `4201c57`
- **Decision:** Every IOAPIC the MADT listed is mapped via `MapMmio`,
  VERSION is read to determine `redir_count`, every redirection entry
  is masked at init. `IoApicRoute` writes high half first (destination
  APIC ID) and low half last (vector + mask clear) so there's never a
  window where the pin is armed with a stale destination. MPS
  polarity + trigger flags from MADT overrides are applied
  automatically for ISA IRQs.
- **Why:** Chipset firmware often leaves pins enabled pointing at
  bogus vectors; mask-everything at init is defense-in-depth. High-
  half-first writes are the pattern Linux/BSD converged on after
  hitting flaky real-hardware cases where stale destinations caused
  IRQs to deliver to the wrong core. MPS override application is
  non-negotiable on QEMU q35 (PIT remaps to GSI 2; SCI is level /
  active-low on GSI 9).
- **Rules out / defers:** Multi-destination (SMP IRQ steering). MSI /
  MSI-X (device-direct, bypasses IOAPIC). PCI _PRT routing (needs
  AML). Per-pin spinlocks (SMP).
- **Revisit when:** SMP bring-up (destination != BSP). First PCIe
  device driver (needs either the legacy INTx path through _PRT, or
  direct MSI setup). MSI arrives — dramatically simpler than IOAPIC
  INTx routing and preferred when available.
- **Related tracks:** Track 2 (Platform), Track 6 (Drivers).

---

## 014 — PS/2 keyboard as the first end-to-end IRQ-driven driver

- **Scope:** `kernel/drivers/input/ps2kbd.{h,cpp}`
- **Commit:** `8b60148`
- **Decision:** First real device driver is the PS/2 keyboard on the
  8042 controller (ports 0x60 / 0x64), routed through the IOAPIC on
  the GSI that ACPI maps from ISA IRQ 1. Raw scan codes go into a
  64-byte SPSC ring buffer; a dedicated `kbd-reader` kernel thread
  blocks on a `WaitQueue` and prints each byte as `[kbd] scan=0xNN`.
  No 8042 init sequence (trust the firmware), no scan-code decoding
  (punt to a future input layer), no aux/mouse channel.
- **Why:** Smallest viable end-to-end closure of the full IRQ pipeline
  (ACPI → IOAPIC → IDT → dispatcher → driver → wait queue →
  scheduler). If every link works, a key press in QEMU produces one
  serial log line. If any link is broken, the bug is isolatable
  exactly because the driver itself is nearly trivial — leaving the
  fault in the plumbing we just built.
- **Rules out / defers:** Scan-code-to-keysym translation, modifier
  tracking (shift/ctrl/alt), key-repeat configuration, aux/mouse
  channel, 8042 controller reset + self-test sequence, USB HID
  (Track 6). Multi-reader safety on `Ps2KeyboardRead` (single
  consumer today).
- **Revisit when:** Interactive shell / debug console lands (needs
  translated key events, not raw scan codes). Real-hardware support
  (most modern boards have no PS/2 — USB HID becomes primary). The
  input layer grows a compositor-facing event stream.
- **Related tracks:** Track 6 (Drivers — input), Track 9 (Windowing —
  eventual input source for the compositor).

---

## 015 — Prefer Multiboot2 ACPI "new" tag over "old" tag

- **Scope:** `kernel/acpi/acpi.cpp` — `FindRsdpInMultiboot`
- **Commit:** `cfd2057`
- **Decision:** Scan the entire Multiboot2 tag list, remember both the
  type-14 (v1 RSDP) and type-15 (v2 RSDP) tags if present, and prefer
  the v2 one.
- **Why:** Observed in the first real QEMU boot that GRUB provides
  BOTH tags and the original "first-match returns" walker picked the
  v1 RSDP. The v1 RSDP reports `revision = 0`, forcing the RSDT
  (32-bit entries) path on a q35 machine whose XSDT (64-bit entries)
  would be authoritative. Functional but loses robustness against
  tables placed above 4 GiB (real servers).
- **Rules out / defers:** Nothing — pure bug fix.
- **Revisit when:** First machine with ACPI tables above 4 GiB
  physical — at that point we'll also need to MapMmio tables outside
  the direct map (see entry 012 deferrals).
- **Related tracks:** Track 2 (Platform).

---

## 021 — SMP discovery + IPI plumbing, AP trampoline deferred

- **Scope:** `kernel/acpi/acpi.{h,cpp}` (MADT type-0 parse),
  `kernel/arch/x86_64/smp.{h,cpp}` (discovery + `SmpSendIpi` ICR
  helper), `kernel/sched/sched.cpp` (g_current/g_need_resched already
  per-CPU via entry 017)
- **Commit:** `ec40d9f`
- **Decision:** Land the SMP discovery half — MADT processor-LAPIC
  enumeration + an IPI-send helper that wraps the LAPIC ICR dance —
  without the real→long-mode trampoline. The trampoline is ~150
  lines of GAS Intel-syntax assembly that needs iterative QEMU
  testing to get right (two-symbol-arithmetic operand restrictions,
  mode-transition far-jump encoding, etc.); separating it from the
  plumbing avoids committing non-functional code.
- **Why:** Discovery + ICR plumbing are independently useful —
  future consumers (TLB shootdown, reschedule-IPI, SMP-aware driver
  notifications) need `SmpSendIpi` regardless of whether APs are
  running. And committing the trampoline half-baked risks a broken
  boot log until the next session. Honest deferral behind a scope
  doc (`smp-ap-bringup-scope.md`) is better than a stub that
  compiles but doesn't boot.
- **Rules out / defers:** Actual AP execution — APs remain halted
  by the firmware reset state. Per-AP LAPIC, GDT, TSS, stack, and
  scheduler integration. Scheduler runqueue/sleepqueue/zombie-list
  spinlock (prerequisite for SMP scheduler). Broadcast-NMI panic
  halt (Class-A recovery gap).
- **Revisit when:** Dedicated session for Commits A-E in
  `smp-ap-bringup-scope.md`. Estimated 1.5-2 focused sessions for
  the full journey from "APs halted" to "APs running scheduled
  tasks."
- **Related tracks:** Track 2 (SMP platform foundation).

---

## 020 — Dead-task reaper: first concrete Class-C recovery path

- **Scope:** `kernel/sched/sched.{h,cpp}`,
  `kernel/core/main.cpp` calls `SchedStartReaper`
- **Commit:** `273058c`
- **Decision:** `SchedExit` now pushes the dying task onto a global
  `g_zombies` list under CLI and wakes a dedicated `reaper` kernel
  thread via a `WaitQueue`. The reaper pops zombies one at a time
  and calls `KFree` on both the stack and the `Task` struct — from
  its own stack, so the free is always safe. Adds `tasks_reaped` to
  `SchedStats` and an `[I] sched/reaper : reaped task id val=N` log
  line per reap.
- **Why:** `sched-blocking-primitives-v0.md` called out "Dead tasks
  leak" as a known issue — each `SchedExit` permanently held a
  `Task` + 16 KiB stack (~16400 bytes). Boot-era usage made it
  bounded in practice, but the pattern doesn't survive any dynamic
  task-creation workload. This is **Class C** in the recovery
  taxonomy: a task fault (or normal exit) triggers cleanup of the
  per-task resources without taking down the kernel. Full ring-3
  process-kill grows this cleanup to address-space / fds / caps /
  ipc; the stack + struct path is already in place and verified.
- **Rules out / defers:** Batched reaping (we do one per wake — 2
  lines to batch when it becomes a hot path). Cross-CPU safety
  (today's single-CPU argument is: once `Schedule` switches away
  from a `Dead` task, no code can reference it; SMP will need a
  "not currently `Running` on any CPU" check). Reaping the reaper
  itself (it never exits, so not a concern).
- **Revisit when:** SMP bring-up (add peer-CPU running check).
  Ring 3 (extend `core::OnTaskExited` to do the full process
  teardown). The reaper's log output gets noisy (gate behind a
  klog level).
- **Related tracks:** Track 2 (SMP — cross-CPU safety),
  Track 4 (Process — full teardown), Track 13 (Security — reaper
  audit log feeds the event stream).

---

## 019 — Recovery infrastructure shells (Classes B, C, D)

- **Scope:** `kernel/core/recovery.{h,cpp}`
- **Commit:** `2affa01`
- **Decision:** Expose the API shapes from the recovery taxonomy
  as a unified module before any concrete caller uses them, so the
  first driver / retry path / task-exit hook routes through the
  same audit stream. Concretely: `DriverFault(name, reason)` +
  `DriverFaultCount()` for Class B, `RetryWithBackoff<Fn>(label,
  fn, policy)` + `kRetryFastIo` / `kRetryBackground` defaults for
  Class D, `OnTaskExited()` as the Class C extension point
  (scheduler calls it in `SchedExit`).
- **Why:** Landing the API BEFORE the first real consumer means
  every subsystem hits the same audit pattern on day one. Without
  it each driver / retry path / ring-3-kill path would invent its
  own logging and counter conventions, drifting back into the
  same "every subsystem reimplements the same primitive" pattern
  we just cleaned up with `core::Panic`.
- **Rules out / defers:** Actual driver-restart dispatch (needs
  the driver model — today `DriverFault` just logs + counts).
  Retry callers (no I/O path exists today — the helper is tested
  structurally by the template instantiation path, not exercised
  at runtime).
- **Revisit when:** First driver that calls `DriverFault`. First
  I/O path that needs `RetryWithBackoff`. Ring 3 process-kill
  grows `OnTaskExited` into full teardown.
- **Related tracks:** Track 6 (Drivers — Class B),
  Track 4 (Process — Class C), Track 6 (I/O retry in block/net).

---

## 018 — Runtime recovery taxonomy: halt / restart / retry / reject

- **Scope:** `docs/knowledge/runtime-recovery-strategy.md`
- **Commit:** `af665c1`
- **Decision:** Codify, per fault class, what the kernel does:
    - Class A (kernel integrity) → **HALT** via `core::Panic`.
    - Class B (driver fault) → **RESTART** the driver behind its
      fault-isolation boundary.
    - Class C (process fault) → **KILL** the task; kernel lives.
    - Class D (transient hardware) → **RETRY** with bounded backoff.
    - Class E (bad input across trust boundary) → **REJECT** with
      typed error + audit event.
    - Class F (well-bounded object state) → **RESET + AUDIT**,
      case-by-case with written bounded-ness argument.
  Unexpected fault with no matching class defaults to **HALT**
  (secure default). Every recovery emits an audit event — silent
  self-heal is the anti-pattern, security-relevant corruption must
  be visible.
- **Why:** Prevents the two failure modes a kernel can drift into
  without a written taxonomy: (a) panicking on non-integrity issues
  (availability death) or (b) silently self-healing corrupt state
  (security death). The anti-malware posture in
  `security-malware-hard-stop-plan.md` is incompatible with (b) —
  sophisticated rootkits actively exploit self-healing code.
- **Rules out / defers:** Catch-and-swallow of kernel faults. "Reset
  to default on corruption" patterns inside kernel data structures.
  Infinite retry. Silent restart.
- **Revisit when:** First real driver fault path (tune Class B retry
  counts), ring 3 (populate Class C fully), first I/O path (put
  real numbers on Class D), Security Policy Engine (wire Class
  E/F audit events into the event stream), SMP (Class A must
  broadcast NMI-halt peers).
- **Related tracks:** Track 4 (Process — Class C),
  Track 6 (Drivers — Class B), Track 13 (Security — Class E/F
  audit path).

---

## 017 — SMP foundations: xchg spinlock + per-CPU data via GSBASE

- **Scope:** `kernel/sync/spinlock.{h,cpp}`,
  `kernel/cpu/percpu.{h,cpp}`, wire-up in `kernel_main`
- **Commit:** `ebd1102`
- **Decision:** Land two primitives without yet refactoring the
  scheduler: (1) a test-and-set spinlock with IF save/restore +
  owner-CPU tracking + RAII guard, (2) a `PerCpu` struct addressed
  via `IA32_GS_BASE` MSR, with `PerCpuInitBsp()` called after
  `IoApicInit` and before `SchedInit`. `g_current` / `g_need_resched`
  in `sched.cpp` stay global for now.
- **Why:** Bringing up APs and refactoring the scheduler to be
  MP-safe in the same commit is a megacommit guaranteed to introduce
  subtle bugs that are impossible to bisect. Landing the primitives
  first (with their own self-tests) lets the next commit focus
  cleanly on AP state machine + trampoline without also dragging in
  the runqueue-goes-per-CPU migration.
- **Rules out / defers:** Ticket / MCS locks (TAS is fine below ~8
  contended CPUs). Recursive locks (fix the design instead).
  Lockdep-style cycle detection. `rdgsbase` fast path (needs
  CPUID.EBX.FSGSBASE gate). Actually putting `g_current` into PerCpu
  (will land alongside AP bring-up).
- **Revisit when:** AP bring-up (next commit — migrate `g_current`
  and `g_need_resched` into PerCpu, add per-CPU runqueue spinlock).
  Profiles show spinlock cache-line ping-pong (switch to MCS / ticket).
  Third spinlock lands (add a lock-ordering debug annotation).
- **Related tracks:** Track 2 (SMP), Track 4 (Process model — will
  need per-process data that is today "per-CPU" as a proxy).

---

## 016 — End-to-end QEMU boot verified as baseline

- **Scope:** Whole boot path; `tools/qemu/run.sh` as the launcher
- **Commit:** _(same commit as 015)_
- **Decision:** First integration boot of the kernel captured and
  documented. All self-tests pass (frame allocator, heap, paging,
  ACPI parse, IOAPIC round-trip, scheduler-mutex counter reaching
  exactly `0x0F`, timer tick monotonic after worker exit). Boot
  task enters `IdleLoop` cleanly. Tooling baseline:
  `qemu-system-x86 + grub-pc-bin + xorriso + mtools` (now installed).
- **Why:** Every commit before this was validated only by
  compile-clean + in-boot self-tests. Running those self-tests on a
  real CPU emulator closes "builds clean but might deadlock on a
  real CPU" as a category of unknown. Baseline log shape is written
  down in `boot-verification-v0.md` for regression comparison.
- **Rules out / defers:** Automated boot-log diff in CI (cheap win —
  grep for `[panic]` at minimum). OVMF / UEFI-direct boot (still
  using GRUB + BIOS path). Real-hardware boot.
- **Revisit when:** CI lands; wire a boot-log smoke test. Also when
  bringing up a second machine profile (different CPU, different
  memory size, multicore) — the baseline log drifts and must be
  captured per profile.
- **Related tracks:** Track 1 (Build/CI), Track 2 (Platform).

---

After landing a non-trivial commit, append a new section here with
the **next sequential number**. Keep entries small. Link the commit
hash. Always write the "Revisit when" marker — that's the point of
the log: future us reading this in six months needs to know whether
the decision is still valid or whether the trigger has been reached.

Don't delete superseded entries. If a decision is replaced, add a
**new** entry that says "supersedes #N" and add an inline
`**Superseded by #M (commit hash)**` note at the top of entry #N.
Both stay in git history regardless; keeping them in the rendered
doc helps future readers audit the trail.
