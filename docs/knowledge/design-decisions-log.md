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

## 022 — PCI enumeration via legacy port IO (0xCF8/0xCFC)

- **Scope:** `kernel/drivers/pci/pci.{h,cpp}`,
  `kernel/core/main.cpp` calls `PciEnumerate` after `SmpStartAps`
- **Commit:** `9158df9`
- **Decision:** Use legacy Configuration Mechanism #1 (write 32-bit
  address to port 0xCF8, read/write 32-bit dword at 0xCFC) instead
  of MCFG/ECAM for the first PCI enumerator. Walk bus 0..3; read
  vendor_id, device_id, class/subclass/prog_if, header_type; cache
  up to `kMaxDevices = 64` records; log each. Expose raw
  `PciConfigRead32/16/8` + `PciConfigWrite32` accessors for
  driver use.
- **Why:** Legacy port-IO works on every x86 machine made in the
  last 25 years and fits in ~150 lines. MCFG/ECAM is faster and
  SMP-friendlier but requires ACPI MCFG parsing (another ~100
  lines) that we haven't needed until now — deferring bundles
  that work with the xHCI commit where the ECAM latency
  matters. Good hygiene: land the unblocking primitive minimal,
  grow it when a consumer appears.
- **Rules out / defers:** BAR sizing + allocation (destructive
  probe dance; needs driver-side convention). MSI/MSI-X setup
  (capability-list walk). INTx routing via ACPI `_PRT` (needs an
  AML interpreter). Recursive bridge walking (q35 has nothing
  interesting on bus 1+). Hot-plug. MCFG/ECAM fast path.
- **Revisit when:** First driver that needs MSI (likely xHCI),
  first ACPI `_PRT` consumer, first real bridge, first hot-
  plug-capable driver, or profiles show CONFIG_ADDRESS port
  contention on SMP.
- **Related tracks:** Track 6 (Drivers — every PCIe driver
  depends on this).

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

## 082 — Tab path completion for ls / cat

- **Scope:** `kernel/core/shell.cpp` — `ShellTabComplete`
  split into `CompleteCommandName` + `CompletePath`, with
  shared helpers `ExtendLine` / `NamePrefixMatch`. Tab on a
  buffer containing whitespace dispatches to path completion
  only when the first token is `ls` or `cat`; other commands
  keep their silent no-op behaviour.
- **Decision:** Split the partial at the last '/' to get
  parent + leaf. VfsLookup the parent, filter children by
  prefix, extend on unique match — trailing '/' for
  directories, trailing space for files so the user can
  continue typing. Ambiguous match prints the candidate list
  (dirs suffixed with '/') and re-prompts with the partial
  intact. Absolute paths only; relative paths wait on a CWD.
- **Why:** The v0 shell already exposed the ramfs via `ls` /
  `cat`, but users had to type paths blind. Tab completion
  is the single cheapest polish that makes the filesystem
  feel discoverable.
- **Rules out / defers:** Relative paths (no CWD yet). Quoted
  paths with spaces. Globbing. Completion for non-ramfs
  backends (will drop in for any backend that implements the
  `children` enumeration shape). Middle-of-line completion.
- **Revisit when:** Per-process CWD lands (relative paths).
  Second FS backend (tmpfs / on-disk) lands and needs the
  same completion shape.
- **Related tracks:** Track 7 (Userland shell), Track 5
  (VFS — completion is a read-path consumer).

---

## 081 — Right-click context menus + ambient MenuContext

- **Scope:** `kernel/drivers/video/menu.{h,cpp}` — MenuOpen
  grows `items`, `count`, `context` parameters; MenuInit is
  retired; new `MenuContext()` accessor. `kernel/core/main.cpp`
  — mouse reader detects right-button edges and opens one of
  three item sets (kStartItems / kDesktopMenuItems /
  kWindowMenuItems) with the appropriate context. Dispatch
  grows cases 5 / 10 / 11 for SWITCH-TO-TTY / RAISE / CLOSE.
- **Decision:** Menu open is stateful (single current item
  list + context), but each call replaces both atomically.
  Context is an opaque u32 the dispatcher reads via
  MenuContext() — for window menus it's the target
  WindowHandle. Action-id ranges documented in-comment:
    1..9   global / desktop
    10..19 window-targeted
  leaving room for future actions without renumbering.
- **Why:** Right-click context menus are the most iconic
  Windows interaction we hadn't done. Landing them on the
  existing menu primitive — with no new layout / hit-test /
  render code — proves the primitive was sized right. Also
  closes the "how do I close a window from a bystander POV"
  question without depending on the X close-box hit-test.
- **Rules out / defers:** Sub-menus / hover open. Right-click
  on the taskbar (deliberately skipped — no useful actions
  yet). Right-click drag / gesture. Multi-instance menus.
  Keyboard navigation of context menus.
- **Revisit when:** Taskbar grows useful context actions
  (pin window, close all, etc.). Sub-menu support needed
  (File > Open > Recent). Accessibility requires keyboard-
  only nav.
- **Related tracks:** Track 9 (Windowing — context-menu
  dispatch is an input-routing layer).

---

## 080 — Shell introspection: dmesg / stats / mem

- **Scope:** `kernel/core/shell.{h,cpp}` — new commands.
  `kernel/core/klog.{h,cpp}` — new `DumpLogRingTo(LogTee)`
  reuses the panic-path formatter with a caller-supplied sink.
- **Decision:** Three read-only views exposing existing
  diagnostic APIs:
    dmesg  → DumpLogRingTo with a ConsoleWrite lambda (klog
             ring, oldest-first).
    stats  → every counter from SchedStatsRead.
    mem    → TotalFrames / FreeFramesCount with KiB-mapped
             output.
  Added to the Tab-complete set + help listing. All zero-risk
  wrappers around state the kernel already tracks.
- **Why:** Closes the loop on "get logs from the desktop" —
  the klog ring was only visible via panic dumps until now.
  `stats` and `mem` answer "what is the kernel doing?" without
  grepping serial.
- **Rules out / defers:** `ps`-style per-task enumeration
  (needs scheduler to expose its task list). `top`-style live
  refresh. Per-PID memory accounting. Ring-filter by severity.
- **Revisit when:** First per-task enumeration API lands on
  sched. Writable FS lets `dmesg > file` land.
- **Related tracks:** Track 7 (Userland shell).

---

## 079 — Argv tokenizer + ls / cat / tab completion

- **Scope:** `kernel/core/shell.{h,cpp}` — in-place whitespace
  tokenizer with `kMaxArgs = 8`, Dispatch switches on argv[0],
  new `ls [path]` / `cat path` / `echo arg...` bound to the
  ramfs trusted root. `ShellTabComplete` adds Tab-key
  completion against the command-name set.
- **Decision:** Tokenize the edit buffer in place by writing
  NULs over separator bytes — argv pointers point into the
  original buffer, no allocation. Echo / ls / cat all follow
  POSIX-ish defaults (echo one-space, ls of file = file, cat
  newline-terminates). Tab uniquely extends; ambiguous lists
  candidates and re-prompts with the partial.
- **Why:** The v0 shell dispatched on raw strings and couldn't
  carry arguments; that was fine for `help` / `clear` but
  uninteresting. With argv + filesystem hooks, the shell now
  genuinely browses the running kernel — `ls /etc`, `cat
  /etc/version`, `ls /bin` all work out of the box.
- **Rules out / defers:** Quoted arg handling. Path completion
  (Tab only completes command names). Globbing. `cd` (no
  current-directory concept — every shell path is absolute
  against the trusted root). Redirects.
- **Revisit when:** First need for quoted args (filenames with
  spaces). Per-process CWD lands. Writable FS unlocks
  redirects.
- **Related tracks:** Track 7 (Userland shell — this is the
  interactive surface), Track 5 (VFS — first real consumer).

---

## 078 — Kernel cmdline parse + GRUB dual boot entry

- **Scope:** `kernel/mm/multiboot2.h` — `kMultibootTagCmdline
  = 1`. `kernel/core/main.cpp` — `FindBootCmdline` walker +
  `CmdlineMatches(key, want)` token-predicate helper.
  `boot/grub/grub.cfg` — two menu entries, each passing a
  different cmdline (`boot=desktop` / `boot=tty`).
- **Decision:** Parse the Multiboot2 cmdline tag at kernel
  entry, match `boot=tty` / `boot=desktop` against
  whitespace-delimited tokens. Runtime selection beats the
  compile-time `CUSTOMOS_BOOT_TTY` flag; no cmdline leaves
  the flag's default in place. 3-second GRUB timeout, default
  entry is Desktop.
- **Why:** Direct answer to "I want to boot straight into
  terminal OR desktop, and switch between them easily" —
  now the SAME binary does both and the user chooses at
  boot. Ctrl+Alt+T keeps flipping at runtime.
- **Rules out / defers:** Full cmdline parser (quotes,
  escapes). Per-token handlers (we only recognise `boot=`).
  Kernel parameter dumping to stderr for diagnostic. UEFI
  boot (still routed through GRUB's MB2 protocol).
- **Revisit when:** A second cmdline key is requested
  (debug=, console=, etc.) — graduate to a proper parser.
  UEFI-direct boot path lands.
- **Related tracks:** Track 2 (Platform — boot options),
  Track 7 (Userland framing).

---

## 077 — Shell command history + mode info command

- **Scope:** `kernel/core/shell.{h,cpp}` — 8-entry ring-buffer
  history, `ShellHistoryPrev` / `ShellHistoryNext`, dedup on
  push, `ReplaceLine` helper that repaints the edit line.
  `kernel/core/main.cpp` — kbd reader dispatches Up / Down
  arrows to the history entries. New `mode` command prints the
  current DisplayMode with the Ctrl+Alt+T reminder.
- **Decision:** Linux/macOS terminal feel closure — every
  muscle-memory interaction a user expects from an interactive
  prompt (history, cursor recall, current-mode query) now
  works. Dedup matches bash's `HISTCONTROL=ignoredups`
  default. Cursor recall uses backspace+echo rather than a
  proper line-edit primitive; fine for 64-char lines where the
  cost is invisible.
- **Why:** Without history the shell is a calculator. Up/Down
  arrows are the cheapest improvement that turns it into a
  usable terminal. The `mode` command gives the shell an
  answer to "what display am I in?" for both interactive and
  future-script use.
- **Rules out / defers:** Incremental search (Ctrl+R).
  Multi-line history. Persistent history across reboots
  (needs writable FS). Tab-complete.
- **Revisit when:** Writable FS lands (persistent ~/.history).
  First multi-line command (script / heredoc) wants history
  that's more than strictly line-based.
- **Related tracks:** Track 7 (Userland shell).

---

## 076 — CustomOS shell: interactive command line

- **Scope:** `kernel/core/shell.{h,cpp}` — new module. 64-char
  line-edit buffer, prompt, command dispatcher. Commands:
  help, about, version, clear, uptime, date, windows, echo.
  `kernel/drivers/video/console.{h,cpp}` — ConsoleWriteChar
  grows '\b' handling (back-up + overwrite-with-space).
  `kernel/core/main.cpp` — kbd reader routes printable /
  Backspace / Enter into Shell* instead of writing the
  console directly.
- **Decision:** Linux/macOS-style prompt ("$ "), one command
  per line, dispatch via string match on the first token.
  Output goes through the existing framebuffer console, which
  means the shell works identically in desktop mode and TTY
  mode — one shell, two framings.
- **Why:** The boot log + interactive prompt is the minimum
  viable terminal UX. Every later feature (tab complete,
  pipes, argv, shell scripts) builds on this dispatch shape;
  getting the primitive in now means those slices don't fork
  the interaction model.
- **Rules out / defers:** argv tokenising (each cmd parses
  raw remainder). Pipes / redirection. Environment variables.
  Shell scripts. Backgrounding (`&`). Signals (Ctrl+C). Tab
  completion. Writable FS for `cat` / `ls` on user files.
- **Revisit when:** Writable FS lands (unlocks `cat` / `ls`
  / `cd`). SYS_SPAWN lands (shell can launch ring-3 apps).
  Multi-line editing needed.
- **Related tracks:** Track 7 (Userland shell — this IS
  that track), Track 4 (Process — shell eventually spawns).

---

## 075 — TTY / Desktop display mode with Ctrl+Alt+T toggle

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` — new
  `DisplayMode` enum + accessors; DesktopCompose branches
  on mode. `kernel/drivers/video/console.{h,cpp}` —
  `ConsoleSetOrigin` / `ConsoleSetColours` re-anchor the
  console in place. `kernel/core/main.cpp` — kbd reader
  dispatches Ctrl+Alt+T to toggle; mouse reader skips UI in
  TTY mode; ui-ticker branches on mode. `kernel/CMakeLists.txt`
  — new `CUSTOMOS_BOOT_TTY` option for text-first initial boot.
- **Decision:** Two modes, one console buffer. Desktop =
  full windowed shell; TTY = fullscreen console, black bg,
  no windows / taskbar / cursor. Scrollback survives the
  flip because both modes render the same char buffer from
  different origins.
- **Why:** Direct answer to "I want to boot directly into a
  terminal OR desktop and switch between them easily."
  Ctrl+Alt+T is the universal shortcut for that kind of
  switch; the build flag gives deployments a say in the
  first-paint state without forking the binary.
- **Rules out / defers:** GRUB kernel-cmdline parser
  (runtime mode-by-string). Multiple VTs à la Linux
  (Ctrl+Alt+F1..F6). Per-mode separate consoles (we share
  one buffer). User-configurable TTY colours.
- **Revisit when:** Kernel cmdline parser lands. Multi-
  session / user-switching arrives. A second console
  instance needs to coexist (e.g. a boot-log viewer
  window alongside the shell).
- **Related tracks:** Track 2 (Platform — boot options),
  Track 7 (Userland — shell framing), Track 9 (Windowing —
  compositor / mode switching).

---

## 074 — klog teed to the on-screen console

- **Scope:** `kernel/core/klog.{h,cpp}` — new `SetLogTee`
  registers a secondary string sink. Log / LogWithValue
  forward each chunk (tag, subsystem, separator, message,
  newline) to the tee after the serial write, minus the
  timestamp prefix. `kernel/core/main.cpp` hooks the tee
  to a lambda that calls `ConsoleWrite`.
- **Decision:** Single-writer tee pattern. No timestamps
  on the framebuffer path (the serial log keeps the
  authoritative record). No DesktopCompose triggered from
  the tee — ui-ticker + user input cover that. Race is
  accepted: IRQ-time klogs can land a garbled character
  on the console buffer under concurrent typing, but the
  log ring and serial record both stay intact.
- **Why:** Direct answer to "I also want to get the logs
  from the desktop." Now every kernel subsystem's runtime
  log line appears on screen as well as serial — boot
  behaviour is visible without attaching a serial console.
- **Rules out / defers:** Per-severity colour on the tee
  (same ink colour for all). Tee filtering (e.g. only Warn+).
  Multiple tees. SMP-safe klog buffering (still sharing the
  single serial / console path today).
- **Revisit when:** Colour klog output requested (e.g.
  red for Error). Second tee needed (serial over network,
  log viewer widget). SMP user code arrives and the race
  becomes observable.
- **Related tracks:** Track 7 (Userland — shell surfaces
  the log too), Track 9 (Windowing — compositor framing
  of the log).

---

## 073 — START menu popup with action dispatch

- **Scope:** `kernel/drivers/video/menu.{h,cpp}` — new popup-
  menu primitive. `kernel/drivers/video/taskbar.{h,cpp}` —
  `TaskbarStartBounds` exposes the anchor rectangle.
  `kernel/core/main.cpp` — seeds four demo menu items and
  dispatches them from the mouse reader.
- **Decision:** Single-instance vertical item menu stored as
  `(label, action_id)` pairs. MenuOpen anchors at a caller-
  supplied (x, y) point; MenuRedraw paints last in
  DesktopCompose so it sits above the taskbar that opened
  it. Callers own id allocation + dispatch switch — the
  menu primitive is content-agnostic and has no callbacks.
- **Why:** The START button was a visual stub for several
  slices; wiring it to a popup that actually does something
  turns "looks like a GUI" into "behaves like one." The
  (label, action_id) shape maps cleanly to future context
  menus, menu bars (File / Edit / View), and right-click
  popups — all of which the same primitive will serve.
- **Rules out / defers:** Keyboard navigation (arrow keys,
  Enter / Esc). Hover highlight. Sub-menus. Separators /
  icons / shortcut hints. Multiple menus simultaneously
  open. Long-text ellipsis.
- **Revisit when:** Second menu instance needed (right-click
  menu). Menu bar lands (same primitive, multiple anchors).
  Keyboard-only navigation required for accessibility.
- **Related tracks:** Track 9 (Windowing), Track 7
  (Userland — shell launcher).

---

## 072 — Alt+Tab and Alt+F4 keyboard shortcuts

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` —
  `WindowCycleActive` walks z-order forward to the next
  alive window and raises it. `kernel/core/main.cpp` —
  kbd reader intercepts Alt+Tab / Alt+F4 before any
  text-input dispatch.
- **Decision:** Two iconic keyboard interactions land
  together because they share the Alt-modifier branch.
  Alt+Tab cycles; Alt+F4 calls WindowClose on the active
  window. Both trigger a full recompose under the
  compositor mutex so chrome + tab highlight update
  immediately.
- **Why:** Muscle memory. Keyboard window-management is
  a baseline expectation on every desktop OS; skipping
  it would invalidate the "Windows-like" framing.
  Landing both now, before more input surfaces arrive,
  keeps the dispatch ladder clean.
- **Rules out / defers:** Alt+Tab overlay (thumbnail
  preview + multi-tap cycle). Shift+Alt+Tab reverse cycle.
  Ctrl+Alt+Del handler. Meta+L / Meta+E shell launchers.
- **Revisit when:** Thumbnail overlay lands (needs
  damage-rect + held-Alt state machine). First shell-
  global shortcut (e.g. Meta+R run dialog).
- **Related tracks:** Track 9 (Windowing), Track 6
  (Drivers — KeyEvent consumer).

---

## 071 — CMOS RTC driver + HH:MM:SS in taskbar

- **Scope:** `kernel/arch/x86_64/rtc.{h,cpp}` — new MC146818-
  compatible CMOS reader. `kernel/drivers/video/taskbar.cpp`
  — taskbar clock replaces uptime-only with HH:MM:SS.
- **Decision:** Read-only wall-clock access via CMOS ports
  0x70 / 0x71. Waits out UIP (Update In Progress) before
  sampling; double-reads all six fields and retries on
  mismatch; honours firmware-set BCD/binary + 12/24-hour
  flags from Status-B. Century register deferred —
  assume 2000s through 2099.
- **Why:** First real wall-clock source in the tree. The
  scheduler uptime counter was fine for boot sanity but
  is meaningless for "what time is it." RTC is universally
  available (every chipset + every hypervisor emulates
  MC146818) and cheap to parse.
- **Rules out / defers:** Writing the RTC (needs different
  UIP handling). IRQ 8 periodic mode (LAPIC timer already
  covers periodic). Century register from FADT. Timezone
  awareness (RTC is typically UTC or local, firmware-
  dependent — no strategy yet). Drift correction vs NTP.
- **Revisit when:** Logs gain wall-clock timestamps. First
  writable FS wants mtime. NTP client lands (needs clock
  writes). Century register matters (post-2099 or pre-
  2000 dual-boot).
- **Related tracks:** Track 2 (Platform — time sources),
  Track 5 (FS — mtimes).

---

## 070 — Active window state + focus-visible chrome

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` — new
  `g_active_window` global; `WindowRaise` / `WindowRegister`
  set it; `WindowClose` promotes next alive. `WindowActive`
  accessor. Inactive windows paint with
  `kInactiveTitleRgb = 0x00506070`.
  `kernel/drivers/video/taskbar.cpp` — active window's tab
  fills with the accent colour.
- **Decision:** Raised == active — the simplest focus model,
  matches Windows 95 through 11 (without focus-follows-
  mouse). Inactive title bars use a muted global grey-blue
  instead of each window's registered colour, so the
  active/inactive distinction reads at a glance without
  per-window palette matching.
- **Why:** Every subsequent slice that cares about focus
  (keyboard routing to a window, F4 = close active, menu
  shortcuts) needs one canonical "which window is
  focused" answer. Landing it before those consumers
  arrive means they build on the right shape.
- **Rules out / defers:** Focus decoupled from raise
  (modal dialogs, focus-follows-mouse). Keyboard focus
  traversal within a window (Tab cycling). Window-level
  focus callbacks. Distinct active/inactive button
  colours.
- **Revisit when:** Modal dialogs land. Text-input
  widgets inside a window need caret blink gated on
  active state. Focus-follows-mouse option requested.
- **Related tracks:** Track 9 (Windowing), Track 7
  (Shell — keyboard shortcut routing).

---

## 069 — Clickable taskbar tabs

- **Scope:** `kernel/drivers/video/taskbar.{h,cpp}` —
  `TaskbarRedraw` records each painted tab's bounds into a
  fixed-size layout array; `TaskbarTabAt` and
  `TaskbarContains` expose hit-tests. `kernel/core/main.cpp`
  — mouse reader resolves taskbar-tab presses above every
  other priority so a buried window can be raised with
  one click on its tab.
- **Decision:** Closes the window-management loop: register,
  raise on click, drag by title, close by X, switch via
  taskbar. The layout array is rewritten by every redraw —
  tabs that overflow the strip simply stop being recorded,
  matching what the human sees.
- **Why:** Without taskbar dispatch, a window hidden
  underneath two others has no way back to the front — the
  click-to-raise slice only reaches the topmost hit. The
  taskbar is the canonical OS answer.
- **Rules out / defers:** Middle-click close, right-click
  menu, drag tabs to reorder, tab-group "flashing" on
  background events, hover-preview thumbnails.
- **Revisit when:** Second widget class (menu) wants to
  re-use the layout-record pattern. Dynamic tab
  sort/filter needed.
- **Related tracks:** Track 9 (Windowing), Track 7
  (Userland shell).

---

## 068 — Taskbar with START, tabs, uptime + ui-ticker

- **Scope:** `kernel/drivers/video/taskbar.{h,cpp}` — new
  module. `widget.{h,cpp}` — adds `WindowRegistryCount`,
  `WindowIsAlive`, `WindowTitle`. `kernel/core/main.cpp` —
  new `ui-ticker` scheduler thread re-composites at 1 Hz.
- **Decision:** A 28-pixel bottom strip painted last in
  DesktopCompose so it sits on top of everything else.
  Shows a "START" accent square, one tab per live window,
  and a right-anchored "UP NNNNs" uptime counter sourced
  from `sched::SchedNowTicks() / 100`. `ui-ticker` sleeps
  100 ticks and recomposes under the compositor mutex so
  the uptime advances without user input — first animated
  element.
- **Why:** The tree's boot story had no persistent shell
  chrome; mouse/keyboard demos landed as ephemeral
  transitions. A taskbar is the smallest thing that reads
  as a living desktop. The ticker also proves the compositor
  mutex holds up against a third concurrent writer.
- **Rules out / defers:** Real wall-clock time (needs RTC
  driver). Click dispatch on START / tabs (tabs land in
  #069). Icons. Tab overflow menu. Auto-hide. Multi-
  monitor.
- **Revisit when:** RTC driver lands (clock becomes
  meaningful). Second widget panel needed (notification
  area, system tray).
- **Related tracks:** Track 9 (Windowing — persistent
  chrome), Track 6 (Drivers — RTC).

---

## 067 — Functional close button

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` — adds
  `WindowPointInCloseBox`, `WindowClose`. `kernel/core/main.cpp`
  — mouse reader resolves close-box presses above title-bar
  drags and general window raises.
- **Decision:** Promote the decorative red square in the
  title bar corner to a real action. `WindowClose` sets the
  `alive` flag false; every subsequent draw / hit-test
  skips the slot. Handles aren't reused — `kMaxWindows=4`
  is bounded enough that leaking the slot for the rest of
  boot is acceptable.
- **Why:** Clicking X on a window and having nothing
  happen is uncanny-valley GUI. Wiring the action NOW,
  with the same priority ordering the mouse reader already
  uses, makes the window manager feel complete without
  adding a menu / keyboard shortcut layer.
- **Rules out / defers:** Handle re-use after close.
  Confirmation prompt. "Close all" on right-click. Process
  kill for ring-3-owned windows (needs SYS_SPAWN first).
- **Revisit when:** Ring-3 apps register windows
  (close = signal the owning process). Handle count grows
  past 4.
- **Related tracks:** Track 9 (Windowing), Track 4
  (Process model — once apps own their windows).

---

## 066 — Window-local widgets (owner + offsets)

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` —
  `ButtonWidget` grows an `owner` field (WindowHandle) and
  reinterprets `x, y` as offsets into the owner's origin
  when the owner is valid.
- **Decision:** Widgets that belong to a window move with
  it on drag, paint as part of its z-order, and only fire
  when the owner is topmost at the click point. Effective
  absolute bounds are resolved on the fly from the owner's
  current position — no per-widget bookkeeping during
  window motion. Freestanding widgets (owner ==
  kWindowInvalid) keep the old behaviour of floating on
  top.
- **Why:** A button that stays put while its host window
  moves is obviously wrong to any GUI user. The owner-
  offset model is the industry-standard answer (HWNDs
  parent HWNDs, NSView subviews, GTK container children)
  and the simplest one that reads correctly.
- **Rules out / defers:** Nested widget containers (a
  button inside a panel inside a window). Per-window
  clip rectangles so widgets can't escape their owner
  bounds. Relative sizing.
- **Revisit when:** Second widget class lands (text field,
  checkbox) — forces a shared container abstraction.
  Overflow clipping matters visually.
- **Related tracks:** Track 9 (Windowing — widget
  parent/child graph is the skeleton of any toolkit).

---

## 065 — Click-to-raise anywhere on a window

- **Scope:** `kernel/core/main.cpp` — mouse reader's press-
  edge branch now raises the topmost hit window even when
  the click didn't land on the title bar.
- **Decision:** Any press inside a window raises it; title-
  bar press additionally starts a drag. Matches the
  universal GUI convention — clicking a background window
  brings it forward.
- **Why:** Without this, z-order feels stuck unless users
  hunt the title bar. Landing it at one-line cost before
  the deeper window-manager slices (widgets, close, tabs)
  means those features never ship with a regressive
  "click outside title bar does nothing" behaviour.
- **Rules out / defers:** Focus model (raise != focus).
  Click-to-focus vs focus-follows-mouse policy. Modal
  windows that ignore raise-on-click.
- **Revisit when:** Keyboard focus lands and becomes
  decoupled from z-order. A modal dialog needs to block
  raise on background clicks.
- **Related tracks:** Track 9 (Windowing).

---

## 064 — Compositor mutex for cross-thread UI state

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` — new
  `CompositorLock` / `CompositorUnlock` wrapping a
  file-static `sched::Mutex`. `kernel/core/main.cpp` —
  mouse + keyboard reader threads bracket every UI-mutating
  section with the lock.
- **Decision:** Single global mutex guards every
  UI-mutable data structure (cursor backing, window
  registry, widget table, console buffer) and every
  framebuffer write sequence that crosses them. FIFO
  hand-off from the existing sched::Mutex means the
  loser parks on a WaitQueue instead of spinning — cheap
  even under heavy typing-while-dragging.
- **Why:** The previous slice (kbd → console) documented
  a latent race: both readers write to the framebuffer
  and mutate the same console / cursor / window state
  without coordination. Before SMP user code or an RT
  input task arrives, this is "transient visual artifact"
  level — but landing the fix now, on a single mutex with
  obvious brackets, is far cheaper than retrofitting
  after the first crash report.
- **Rules out / defers:** Fine-grained locking (per-
  surface, per-widget). Lock-free double-buffer compositor.
  IRQ-context painting (mutex can sleep). Multi-monitor
  lock topology.
- **Revisit when:** Contention shows up in profiles. SMP
  scheduler join (per-CPU cursors, RCU-style widget list).
  Per-window damage tracking (each window gets its own
  lock).
- **Related tracks:** Track 9 (Windowing), Track 2 (SMP).

---

## 063 — Keyboard routed into the framebuffer console

- **Scope:** `kernel/core/main.cpp` — `kbd_reader` thread
  switches from `Ps2KeyboardReadChar` to
  `Ps2KeyboardReadEvent`, filters press edges of printable
  ASCII, writes to `ConsoleWriteChar`, triggers
  DesktopCompose per keystroke. Enter and Backspace get
  line-editing semantics; modifier-only edges are silent.
- **Decision:** First closure of "keypress in hardware
  to pixel on screen" end-to-end — matches the mouse
  path's visible payoff. Each keystroke triggers one
  full-desktop repaint inside CursorHide/Show. Repaint
  cost is ~3 MB/s for a 1024x768x32 framebuffer at
  typing rates (<30 Hz), comfortably under MMIO budget.
- **Why:** A desktop with two windows, a cursor, and a
  console without an input path is a museum diorama.
  Wiring the console's input now validates the KeyEvent
  API under real use AND makes the boot-log surface
  feel alive.
- **Rules out / defers:** Line editor (cursor nav,
  word-delete, history). Proper terminal emulator (ANSI
  escapes, bold / colour). Per-console fg/bg. Real shell
  on top (needs line-editor + tokeniser + command
  dispatch). Printable input while dragging (widget
  router path is mutually exclusive during drag).
- **Revisit when:** First shell-shaped widget lands
  (wants the full edit API). Non-ASCII keyboard layout
  needed (unlocks wider keymap).
- **Related tracks:** Track 9 (Windowing — text input
  source for every future toolkit widget), Track 7
  (Userland — path to a shell).

---

## 062 — Framebuffer text console (80x40 char grid)

- **Scope:** `kernel/drivers/video/console.{h,cpp}` — new
  module. `kernel/drivers/video/widget.cpp` — DesktopCompose
  paints the console BETWEEN banner and windows.
- **Decision:** Fixed-size character grid backed by the
  bitmap font. Writes append to a char buffer at a
  tail cursor; newlines advance the row; bottom-row
  overflow scrolls everything up. Re-rendered from the
  char buffer on every ConsoleRedraw, so z-ordering
  against windows is a pure draw-order question —
  windows dragged over the console occlude, and a
  follow-up DesktopCompose restores.
- **Why:** Every interesting GUI surface eventually wants
  multi-line text: boot log, shell, chat, source editor,
  error dialogs. Landing the primitive now, on a simple
  bg-fill + per-cell char-render model, means the first
  consumer doesn't have to reinvent scrolling.
- **Rules out / defers:** ANSI escape handling. Per-char
  colour. Multiple console instances. Cursor navigation
  (back, up, page). Line editing. Proportional text.
  Thread safety (kept external via the compositor mutex).
  Variable-size grid.
- **Revisit when:** First real shell needs line editing.
  Colour boot log wanted (entry-#033 klog severity colours
  map to fg per line). Multi-console / tty tab bar lands.
- **Related tracks:** Track 9 (Windowing — scrollable text
  surface), Track 7 (Userland — shell foundation).

---

## 061 — Window registry + z-order + drag-by-title-bar

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` — window
  storage (`kMaxWindows=4`), `WindowRegister`, `WindowRaise`,
  `WindowMoveTo`, `WindowGetBounds`, `WindowTopmostAt`,
  `WindowPointInTitle`, `WindowDrawAllOrdered`,
  `DesktopCompose`. Buttons grow a `label` field so
  PaintButton survives repaint without losing text.
  `kernel/core/main.cpp` — mouse reader tracks drag state,
  triggers DesktopCompose per packet during drag.
- **Decision:** Promote windows from a one-shot
  `WindowDraw` primitive to a flat fixed-size registry
  with a z-order array. Press on a title bar raises +
  begins drag; motion repaints the full desktop each
  packet (no damage tracking — 1024x768x32 runs well
  under budget at 100 Hz); release ends drag. Button
  widgets float on top of all windows for v0 — the
  "widgets belong to a window" refactor is its own
  slice.
- **Why:** Two windows with working stacking + drag is
  the smallest thing that reads as a real window
  manager. Z-order + raise-to-front-on-click is the
  invariant every GUI converges on; landing it now
  means every future window-manipulation slice builds
  on the correct shape.
- **Rules out / defers:** Proper damage-rect compositor
  (full repaint works at current surface size). Resizing.
  Close-button action (the red square is visual-only).
  Stacking shadows. Minimise / maximise. Per-window
  widget trees. Keyboard focus + Tab cycling. Window
  deletion.
- **Revisit when:** Surface gets bigger (4K) or draw
  rate needs to hit 60 Hz with widgets — forces damage
  tracking. Second widget class (menu, list box) makes
  "widgets live in a window" a forcing refactor.
  Close-button-click lands.
- **Related tracks:** Track 9 (Windowing — core window
  manager), Track 6 (Drivers — pointer event consumer).

---

## 060 — 8x8 bitmap font + framebuffer text rendering

- **Scope:** `kernel/drivers/video/font8x8.{h,cpp}` — hand-crafted
  5x7-in-8x8 font (space, digits, uppercase A-Z, 20 punctuation).
  `framebuffer.{h,cpp}` — `DrawChar` / `DrawString` with fg/bg.
  `main.cpp` — desktop banner + window title + button label.
- **Decision:** Ship the smallest font that is coherent (all
  visible characters same design language, consistent kerning,
  full uppercase + digits + punctuation) rather than a broader
  font that's partially transcribed. Lowercase aliases to
  uppercase at lookup. Unmapped codes render as a placeholder
  box so gaps are visible rather than silent. Bit 7 is
  leftmost — classic IBM font layout, matches every open font
  tool on earth.
- **Why:** Every subsequent UI element — menus, labels,
  status bars, dialog buttons, console output — needs glyphs.
  Landing a font NOW with cleanly-defined layout (8-px cell
  advance, bg fill behind each glyph) means widget code can
  render text with one call and not worry about alpha / anti-
  aliasing yet.
- **Rules out / defers:** Lowercase glyph shapes (alias to
  uppercase for now — ugly but readable). Proportional spacing.
  Anti-aliasing / subpixel rendering. Unicode (ASCII only).
  Multiple font sizes. True italic / bold (bitmap manipulations
  only). Kerning pairs.
- **Revisit when:** First locale grows a non-ASCII character
  (unlocks an ICU-shaped translation layer). Compositor wants
  hi-DPI text rendering (forces a vector font). Real terminal
  emulator lands (wants control-char handling + scrollback).
- **Related tracks:** Track 9 (Windowing — labels / title text),
  Track 7 (Userland — shell needs glyphs too).

---

## 059 — KeyEvent API with modifiers + extended keys

- **Scope:** `kernel/drivers/input/ps2kbd.{h,cpp}` — new
  `Ps2KeyboardReadEvent` returning `KeyEvent { code, modifiers,
  is_release }`. Translator grows LCtrl / RCtrl / LAlt / RAlt /
  Meta tracking; 0xE0-prefixed arrows / Home / End / PgUp /
  PgDn / Insert / Delete lift to `KeyCode` values; F1..F12
  decoded; Esc / Tab / Enter / Backspace named.
- **Decision:** Supersede the `char`-returning
  `Ps2KeyboardReadChar` with an event-shaped API that preserves
  both press AND release edges, a modifier bitmask, and non-
  ASCII keys. Keep the old API for simple echo-style readers
  (the two share the raw ring). Modifier-only edges surface as
  `code == kKeyNone` + populated modifiers so the UI can render
  "Ctrl held" cues.
- **Why:** Closes the deferral from entry #024 — "a future
  KeyEvent interface will carry [modifiers] as a modifier
  bitmap." No shell / text input / Ctrl+C / arrow navigation
  is possible with a bare `char` return. Landing it now, before
  any compositor, means every toolkit consumer sees one shape
  from day one.
- **Rules out / defers:** Key-repeat rate config. Non-US
  layouts (AZERTY, Dvorak). Numpad / NumLock-aware numpad. IME
  composition. Print Screen / Pause / Multimedia keys. 6KRO /
  NKRO tracking (8042 reports one press at a time anyway).
- **Revisit when:** Non-US locale needed. USB HID lands
  (replaces PS/2 on real hardware; KeyEvent stays the same
  shape). Shell widget needs key-repeat semantics.
- **Related tracks:** Track 6 (Drivers — input), Track 9
  (Windowing — keyboard-event source).

---

## 058 — Window chrome primitive (title bar + client + close box)

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` — `WindowChrome`
  struct + `WindowDraw`. Paints outer 2-px border, coloured title
  bar, client area fill, 1-px divider line, and a close-button
  square in the top-right corner with its own outline.
- **Decision:** Windows are a STATIC draw primitive in v0, not a
  widget-table entry. Callers invoke `WindowDraw` once per paint
  pass; dragging / focus / z-order grow this into a real widget
  once the toolkit lands. Chrome is intentionally Windows-98-
  adjacent: recognisable to every human who's ever seen a GUI.
- **Why:** First GUI element that looks unmistakably "window-
  like" — a frame with a title bar and a close button. No
  ambiguity about what the primitive represents; any future
  toolkit can grow dragging / stacking on top of this without
  reworking the shape.
- **Rules out / defers:** Dragging. Resizing. Focus + z-order
  stack. Title text (needs font — landed in #060). Minimize /
  maximise widgets. Shadow / alpha. Non-rectangular shapes.
  Scroll bars. Non-client hit testing.
- **Revisit when:** Two windows coexist on screen (forces
  z-order + focus). First drag operation lands. Compositor
  takes over chrome rendering.
- **Related tracks:** Track 9 (Windowing — iconic primitive).

---

## 057 — Clickable button widget + mouse event router

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` —
  `ButtonWidget`, `WidgetRegisterButton`, `WidgetDrawAll`,
  `WidgetRouteMouse`. `framebuffer.{h,cpp}` — `DrawRect`
  (4-band outline primitive). `cursor.{h,cpp}` —
  `CursorHide` / `CursorShow` helpers.
- **Decision:** First UI event primitive. A button is a rect
  with normal + pressed colours + a caller-assigned id. Router
  diffs the latest `button_mask` against the prior sample and
  transitions visual state on press / release edges (no hover
  state). Redraws bracket `CursorHide / Show` so the cursor's
  backing-pixel cache stays consistent with what's beneath.
- **Why:** Clicks ARE the event primitive. Landing a router
  now, before a full compositor, gives every future toolkit
  one canonical "which widget did the user hit?" answer.
  Avoids each new widget kind reimplementing hit-test.
- **Rules out / defers:** Hover state (needs `prev_cursor_over`
  tracking + hover colour — straightforward follow-up). Drag
  & drop. Keyboard focus traversal (Tab cycling). Nested
  widgets / z-order. Accessibility / screen-reader hooks.
  Dynamic widget allocation (fixed 8-entry table).
- **Revisit when:** Second widget kind lands (forces a shared
  base class or a dispatch tag). Hover feedback needed.
  Widget count exceeds 8.
- **Related tracks:** Track 9 (Windowing — event routing
  foundation), Track 6 (Drivers — consumer of mouse packets).

---

## 056 — Shaped cursor with per-pixel save/restore

- **Scope:** `kernel/drivers/video/cursor.{h,cpp}`.
- **Decision:** Upgrade the triangle-fill cursor to a 12x20
  shaped-mask arrow with three kinds of pixel (transparent,
  outline-black, fill-white). Save every non-transparent
  pixel under the sprite on `SaveAt`; restore on `RestoreAt`.
  Framebuffer grows a file-local `ReadPixel` helper for the
  save path.
- **Why:** Entry #055's "erase to desktop colour" shortcut
  broke the moment any non-desktop content (widgets, window
  chrome) landed under the cursor. Per-pixel save/restore is
  the only correct answer short of a compositor-managed
  overlay plane. Cost is negligible (240 u32s of .bss).
- **Rules out / defers:** Hardware cursor plane (vendor-
  specific MMIO — land with each GPU driver). Animated
  cursors. Per-context cursor shapes (I-beam, resize,
  hourglass). Colour cursor themes.
- **Revisit when:** GPU drivers expose a hardware cursor.
  Toolkit needs shape-switching based on widget class.
  Compositor lands (overlay plane becomes natural).
- **Related tracks:** Track 8 (Graphics), Track 9 (Windowing).

---

## 055 — Mouse cursor overlay on the framebuffer

- **Scope:** `kernel/drivers/video/cursor.{h,cpp}` — new module:
  `CursorInit(desktop_rgb)` paints background + draws initial
  sprite at screen centre; `CursorMove(dx, dy)` erases old rect,
  clamps new position, redraws; `CursorPosition` accessor for
  future hit-testing. `kernel/core/main.cpp` — mouse reader thread
  now calls `CursorMove` on every packet.
- **Decision:** Render the cursor as a 12x20 diagonal-right-edge
  rectangle (arrow-ish without a bitmap mask), erase-then-redraw
  on every move, no per-pixel save/restore. v0's desktop is a
  solid dark-teal fill, so "restore background" is just
  "overpaint with the desktop colour" — a mask / alpha / dirty-
  rect path isn't worth the complexity until a compositor wants
  to overlap real windows under the cursor.
- **Why:** First visible interactive UI element. Ties together
  three prior slices (Multiboot2 FB parse, FB driver, PS/2 mouse
  IRQ 12) into one end-to-end chain you can SEE: physical mouse
  motion → IOAPIC → 8042 aux → packet decode → task queue →
  cursor move → pixel store. Previously every link was serial-
  log verification only; this closes the loop visually.
- **Rules out / defers:** Shaped-mask arrow sprite (needs per-
  pixel save/restore — premature without a compositor). Hardware
  cursor plane (Intel / AMD / NVIDIA cursor MMIO paths; land
  with each vendor's GPU driver). Per-display cursor (multi-
  monitor, far future). Cursor hide-on-inactive (no focus model
  yet). Double-click timing (needs a timer-wheel). Click-drag
  selection (needs widgets to drag-select).
- **Revisit when:** First compositor draws overlapping windows
  (forces pixel save/restore or a hardware cursor). Multi-display
  lands. Widget toolkit wants an API for cursor shape changes
  (I-beam, resize, hourglass).
- **Related tracks:** Track 8 (Graphics), Track 9 (Windowing —
  cursor is the root primitive of every pointer event).

---

## 054 — PS/2 mouse v0 (IRQ 12, 3-byte standard protocol)

- **Scope:** `kernel/drivers/input/ps2mouse.{h,cpp}` — new driver.
  `kernel/drivers/input/ps2kbd.cpp` — IRQ handler grows an aux-bit
  filter so mouse bytes don't get misread as scan codes.
- **Decision:** Second end-to-end IRQ-driven input device on the
  8042 aux channel. Re-enables the aux port the keyboard init
  disabled, runs port-2 self-test, sends the mouse `SetDefaults`
  (0xF6) + `EnableReporting` (0xF4), routes ISA IRQ 12 via the
  IOAPIC. Packet assembly happens in the IRQ handler; task-side
  reader consumes pre-decoded `MousePacket`s with `dx`, `dy`
  (screen-space: +y = down), and button bitmask. Sync-byte
  check on byte 0 (bit 3 = always 1) catches and recovers from
  mid-stream desync. Overflow bits saturate to ±255 rather than
  dropping the whole packet — button-state updates matter more
  than one-frame movement accuracy.
- **Why:** Pointer input is the prerequisite for any GUI. Landing
  it now (before a compositor) gives the mouse cursor overlay
  and any future widget hit-test a working event source from
  day one. Soft-failing on machines without a PS/2 aux line
  (most laptops) keeps boot clean there — USB HID will eventually
  be primary on real hardware.
- **Rules out / defers:** Wheel / 5-button IntelliMouse extension
  (needs sample-rate handshake + 4-byte packets). Absolute-
  coordinate tablets (USB HID path). Sample-rate override
  (accepting firmware default, typically 100 Hz). Coalescing
  consecutive small-delta packets (compositor can do it).
- **Revisit when:** USB HID stack lands (primary on real hardware
  — PS/2 becomes legacy fallback). First compositor needs
  absolute coordinates or high-frequency sampling. Wheel-scroll
  support becomes necessary.
- **Related tracks:** Track 6 (Drivers — input), Track 9
  (Windowing — pointer event source).

---

## 053 — Linear framebuffer v0 (Multiboot2 tag 8 → MapMmio → pixels)

- **Scope:** `kernel/arch/x86_64/boot.S` — Multiboot2 header grows
  framebuffer request tag (type 5, optional). `kernel/mm/multiboot2.h`
  — adds `kMultibootTagFramebuffer = 8` + `MultibootFramebufferTag`
  struct + framebuffer-type constants.
  `kernel/drivers/video/framebuffer.{h,cpp}` — new driver:
  `FramebufferInit`, `FramebufferClear`, `FramebufferPutPixel`,
  `FramebufferFillRect`, `FramebufferSelfTest`.
- **Decision:** First direct-to-pixel output path. Parses GRUB's
  framebuffer tag, validates direct-RGB + 32-bpp + sane pitch,
  MapMmios the surface into the kernel MMIO arena. Soft-fails
  cleanly when the loader doesn't provide a tag or the mode is
  unsupported — `Available()` stays false, boot continues on
  serial. Self-test draws black background + four corner
  swatches (R/G/B/W) + a framing rectangle so channel order
  and full-surface coverage are visually confirmable in one
  glance.
- **Why:** Every GUI element (desktop, windows, cursor, fonts)
  starts with pixels. Landing a clean FB abstraction now means
  the compositor, splash screen, panic display, and kernel
  console all build on one layer. Cache-disabled MMIO is the
  right v0 posture — write-combining needs PAT programming we
  don't have yet, and at 1024x768x32 @ 60 Hz the bandwidth is
  well under any PCIe budget.
- **Rules out / defers:** 24-bpp packed (different pixel-store
  inner loop). 15/16-bpp (channel packing). Non-classic colour
  masks (need the variable-length colour-info trailer). Back
  buffer / double buffering (compositor owns that). Write-
  combining via PAT. Dirty-rect tracking. Hardware cursor
  planes. EFI GOP (UEFI direct boot path, future).
- **Revisit when:** First real machine reports an unsupported
  depth or non-standard colour masks. Compositor lands and
  demands a back-buffer API. Performance profile shows MMIO
  stores dominating the draw path (PAT + WC is the fix).
  Intel / AMD / NVIDIA GPU drivers arrive (vendor-specific
  modeset + accelerated blit replace this path for their
  panels).
- **Related tracks:** Track 8 (Graphics Foundation — first
  slice), Track 2 (Platform — firmware handoff grows a new
  class of info beyond ACPI).

---

## 052 — Writable-bit pre-check in `CopyToUser`

- **Scope:** `kernel/mm/paging.cpp` — `PagePresentAndUser` grows a
  `need_writable` parameter, `IsUserRangeAccessible` grows the same,
  `CopyFromUser` calls with `need_writable=false`, `CopyToUser`
  calls with `need_writable=true`. No header / ABI change.
- **Decision:** Before SMAP-bracketing a user-destination copy,
  walk every 4 KiB page in the destination range and require the
  Writable bit (in addition to Present + User) on each PTE. A
  buffer whose tail crosses into a read-only user page now fails
  the pre-walk cleanly without the copy having stored any bytes.
  `CopyFromUser` keeps the pre-existing Present + User-only check
  — reading a non-writable user page is a legitimate operation
  (e.g. a ring-3 task passing an immutable string pointer).
- **Why:** Entry #049 deferred this with "No consumer today; add
  when one lands." SYS_READ and SYS_STAT both reached for
  `CopyToUser` in the VFS-namespace work — SYS_READ copies file
  bytes into a caller-supplied buffer, SYS_STAT writes a `u64`
  size into a caller-supplied slot. Both are exactly the shape the
  deferral called out: the user passes a destination pointer the
  kernel has no up-front guarantee is writable. Without this
  check, a destination that straddles the RO/RW boundary stores
  the leading bytes into the writable page, then the copy loop's
  `mov byte ptr [rdi], cl` #PFs on the first RO byte; the trap
  dispatcher's fault-fixup unwinds the kernel cleanly and returns
  `false`, but up to `page_size - 1` bytes have already landed in
  user memory. The caller sees `-1` and assumes the write was
  a no-op — a quiet TOCTOU-shaped surprise waiting for the first
  syscall that relies on "all or nothing" semantics. The walk-
  first check costs one extra PT descent per destination page
  (already paid for the Present + User check anyway — same
  descent, one more bit-mask test), and eliminates the partial-
  write window entirely.
- **Rules out / defers:** Dirty-bit check (no consumer — the
  CPU sets Dirty on its own on the first write, which is the
  right time). Copy-on-write handling for writable-but-shared
  pages (no CoW mappings yet). Writable check on the KERNEL
  side of `CopyFromUser`'s destination (`kernel_dst` is trusted
  kernel memory; validating it would be kernel-policing-kernel).
  Explicit error differentiation between "range invalid",
  "page unmapped", "page read-only", and "page not user" — all
  still collapse to `return false`; the caller gets `-1` and
  decides what it means in context. Adding a typed error enum
  is a separate ABI decision that lands with the first syscall
  that needs to disambiguate.
- **Revisit when:** First syscall that needs typed error returns
  (replaces the `bool` with `enum class UserCopyError`). CoW
  mappings land (Writable=0 then means "RW-on-fault" rather than
  "RO" — the pre-check needs to consult the VMA, not just the
  PTE). Demand paging lands — the walk might see Present=0 on a
  page the MM intends to page in; the fault-fixup path becomes
  the fast path and the pre-check becomes a filter for
  structurally-invalid pointers only.
- **Related tracks:** Track 3 (MM — user-pointer robustness),
  Track 4 (Process model — syscall ABI cleanliness), Track 13
  (Security — every kernel→user store is now strict on the
  permission side of the mapping, not just the presence side).

---

## 051 — SYS_YIELD = 3 (cooperative yield from ring 3)

- **Scope:** `kernel/core/syscall.{h,cpp}` — new enum value,
  new switch case; `kernel/core/ring3_smoke.cpp` — payload
  grew from 31 → 31+7 = 38 bytes to insert `mov eax, 3; int
  0x80` between the SYS_WRITE and SYS_EXIT calls.
- **Decision:** Expose `sched::SchedYield` to ring 3 via a
  dedicated syscall number. Cooperative-yield semantics: the
  kernel-side handler calls SchedYield (cli / Schedule / sti),
  writes 0 into frame->rax, and returns. The ring-3 side sees
  the same net effect as a `pause` loop that happens to have
  given the scheduler a chance to run other tasks. v0 returns
  a constant 0 — the reserved slot lets a future "did I
  actually get descheduled" boolean slot in without an ABI
  break.
- **Why:** The smoke payload now exercises all three non-exit
  syscalls on its happy path: WRITE (pointer + return-value
  ABI), YIELD (kernel-state-change without a return value),
  and GETPID (not yet in the payload, but dispatched end-to-
  end in the handler). Landing YIELD now also closes a latent
  ABI-design gap: "can a ring-3 task ever voluntarily give up
  its slice without exiting?" was implicitly "no" before this
  slice, which is the wrong default for any future userland
  main loop.
- **Rules out / defers:** Priority inheritance through yield
  (if a lower-prio task is holding a resource a yield caller
  wants, the yield should donate the caller's priority — not
  a thing yet, only Normal + Idle classes). Bounded-yield
  variants (`SYS_YIELD_UNTIL(deadline)`, `SYS_SLEEP(ticks)`)
  — both are natural follow-ups, but each is its own slice
  with its own ABI choices. Per-CPU yield stats in the klog
  (interesting once concurrency is real).
- **Revisit when:** First shell / userland main loop lands
  (consumer of yield). First real-time scheduling class
  (yield semantics change — "give up slice" vs "give up
  slice AND drop to end of priority band"). SYS_SLEEP /
  SYS_YIELD_UNTIL land (this gate grows siblings).
- **Related tracks:** Track 4 (Process model — cooperative
  yield is the baseline userland sees), Track 11 (Win32 —
  NtYieldExecution eventually descends from this).

---

## 050 — Per-task user-VM regions: reaper-driven unmap + free

- **Scope:** `kernel/sched/sched.{h,cpp}` — new `UserVmRegion`
  struct (vaddr + frame), Task grows a fixed-size
  `user_regions[4]` array + count field, new
  `sched::RegisterUserVmRegion(vaddr, frame)` accessor, the
  reaper drains the array before KFreeing the Task struct
  (calls `mm::UnmapPage` + `mm::FreeFrame` per entry).
  Ring-3 smoke registers its code + stack pages immediately
  after each MapPage.
- **Decision:** Store every user-VM page a task maps in a
  fixed-size on-Task-struct array. The reaper (already the
  owner of "a zombie just went off-CPU, tear it down") walks
  the array, unmaps each vaddr, and returns each frame to the
  physical allocator. Cap at 4 entries per task — comfortably
  covers code + stack + a heap page + one scratch; hitting
  the cap panics, which is the "a consumer grew without
  updating this constant" signal. Registration is lock-free
  because only the task itself writes its own region array,
  only from its own context, and the reaper only reads it
  after the task is off-CPU and flagged Dead.
- **Why:** Entry #044 noted "A way for the user task to exit
  (the ring-3 loop is genuinely infinite; the reaper never
  sees it)"; #045 closed that by landing SYS_EXIT; #047's
  smoke payload now exercises SYS_EXIT on every boot. But
  without region cleanup, each exit LEAKED one code page
  + one stack page from the global PML4 + their backing
  frames. First symptom would have been either (a) a
  restart of the smoke task panicking on "virtual address
  already mapped" in MapPage, or (b) the physical allocator
  slowly draining to exhaustion over many boots. Neither is
  a visible failure today — the smoke task runs once per
  boot — but the kernel-invariant is "no resource outlives
  its owning task," and violating it silently is exactly the
  kind of drift the anti-bloat guidelines flag.
- **Rules out / defers:** Variable-sized region lists (would
  require heap allocation tied to task lifetime — out of
  scope while 4 is the common case). Sharing a region
  between tasks (requires refcounted frames; needed the
  moment two ring-3 tasks share a library page). Lazy
  deferred free (free the frames but keep the page-table
  entries for fast re-install — a micro-optimisation with
  no consumer yet). TLB shootdown on the unmap — single-
  CPU ring 3 today, so invlpg on the local CPU in
  UnmapPage is enough.
- **Revisit when:** A second ring-3 task exists (it'll
  probably want shared read-only mappings for its code
  → refcount). Per-process address spaces land (the whole
  "region list owned by the Task struct" becomes "region
  list owned by the address space, Tasks point at an
  address space"). SMP ring 3 — TLB shootdown on unmap
  becomes necessary.
- **Related tracks:** Track 3 (MM — page-table lifecycle),
  Track 4 (Process model — resource ownership is per-Task
  until per-process address spaces land), Track 13
  (Security — leaking mappings across tasks is a
  confidentiality bug waiting for a consumer).

---

## 049 — Walk-first user-pointer mapping check in CopyFrom/ToUser

- **Scope:** `kernel/mm/paging.cpp` — new file-local
  `PagePresentAndUser(virt)` + `IsUserRangeAccessible(addr,
  len)` helpers that walk the PT via the existing
  `WalkToPte(..., create=false)`. `CopyFromUser` / `CopyToUser`
  now chain: range check → page-walk check → SMAP-bracketed
  copy.
- **Decision:** Before any SMAP-bracketed user copy, walk the
  page table for every 4 KiB page the copy will touch and
  verify both `Present` and `User` are set on the PTE. A
  page that's in-range but not mapped (or mapped but not
  user-accessible) returns `false` from the copy call
  without ever actually dereferencing it. This makes the v0
  "kernel halts on any #PF, including #PFs inside copy
  loops" posture survivable against an uncooperative
  user — a caller that passes an unmapped (but in-range)
  pointer now gets a clean -1 from SYS_WRITE instead of
  halting the whole machine.
- **Why:** SMAP tells the CPU "don't let kernel code touch
  user pages without stac," but it doesn't tell the CPU
  "don't touch unmapped pages." A user pointer that's in
  the canonical low half but points at a 4 KiB hole in the
  address space (either never mapped, or a page we haven't
  allocated) would still #PF on the copy — and today's trap
  dispatcher halts on #PF. The right long-term fix is a
  `__copy_user_fault_fixup` table (patches the fault RIP to
  a "return false" label), but that requires inline asm for
  the copy loops AND a linker-section sweep in the #PF
  handler. Walk-first achieves the same user-visible
  behaviour in pure C++ with no ABI or linker changes, at
  the cost of one PT walk per copy. That's ~4 memory reads
  per 4 KiB page — negligible for the 256-byte SYS_WRITE
  copy, irrelevant for anything smaller, and a genuinely
  bad idea for multi-megabyte copies that we don't have
  and aren't about to land.
- **Rules out / defers:** The proper fault-fixup table
  (deferred until either a) a syscall needs to copy more
  than the walk-first budget allows, or b) demand paging /
  lazy page-in lands — at which point a "page was present
  at walk time but got swapped out before the copy" race
  becomes real). Multi-range copy / scatter-gather I/O.
  Copy-on-write for forked address spaces. Concurrent-
  unmap races on SMP (no AP user code today). Writable-
  check for CopyToUser — today the walker only tests
  Present + User, not Writable; a truly robust version
  would verify the user page is writable before CopyToUser
  even starts, turning "copy half-way then #PF on a
  read-only page" into "return false up front." No
  consumer today; add when one lands.
- **Revisit when:** First consumer copying > a few KiB
  (the walk's cost becomes measurable). Demand paging
  lands. Per-process address spaces land (concurrent
  unmap from another CPU becomes possible → race window
  opens → fault-fixup becomes necessary). First CopyToUser
  caller that wants a strict pre-check on writable pages.
- **Related tracks:** Track 3 (MM — address-space
  correctness), Track 13 (Security — robust user-pointer
  handling is upstream of every syscall-level trust
  boundary).

---

## 048 — Scheduler publishes TSS.RSP0 on every switch-in

- **Scope:** `kernel/sched/sched.cpp` — `Schedule()` now calls
  `arch::TssSetRsp0(next->stack_base + next->stack_size)` right
  before `ContextSwitch`, for every task with a non-null
  `stack_base`. Include reorg in `kernel/sched/sched.cpp` +
  comment in `kernel/core/ring3_smoke.cpp` downgrading the manual
  TssSetRsp0 call there to belt-and-braces.
- **Decision:** Make "TSS.RSP0 always reflects the current task's
  kernel-stack top" an invariant the scheduler owns, not an
  invariant individual ring-3 tasks have to remember. On every
  context switch INTO a task with its own managed kernel stack
  (everyone except the boot task), publish the top of that stack
  to the BSP's TSS. The boot task is skipped because its
  `stack_base` is nullptr and it never runs in ring 3, so RSP0 is
  never consulted while it's `Current()`.
- **Why:** Entry #044 explicitly deferred this wiring with
  "single ring-3 task in v0 — TSS.rsp0 is set once and stays
  valid." That's true for exactly one user-mode-capable task;
  as soon as two coexist, the second task's trap frames would
  land on the first task's kernel stack and overwrite it. The
  correctness question doesn't depend on a SECOND task existing
  today — the invariant must hold BEFORE that lands, or the first
  second-task bug would be indistinguishable from "a trap frame
  mysteriously corrupts adjacent kernel memory." Cheap to do
  now, expensive to add later under pressure.
- **Rules out / defers:** Per-CPU TSS + per-AP RSP0 management
  (today's `arch::TssSetRsp0` writes the BSP's TSS; APs need
  their own TSS + their own TssSetRsp0 that indexes by
  `cpu::CurrentCpu()`). Lazy RSP0 update (skipping the write
  for ring-0-only tasks) — the two or three extra stores per
  context switch are negligible, and gating on "is this task
  ring-3 capable" adds a Task field we don't have yet.
- **Revisit when:** SMP scheduler join — per-CPU TSS lands. A
  dedicated "does this task enter ring 3?" flag becomes
  ergonomic to add (replaces the `stack_base != nullptr` proxy).
- **Related tracks:** Track 2 (SMP — per-CPU TSS), Track 4
  (Process model — per-task kernel stack is the central invariant
  of user-mode transitions).

---

## 047 — First pointer-arg syscall: SYS_write(fd, buf, len)

- **Scope:** `kernel/core/syscall.{h,cpp}` — `SYS_WRITE = 2`,
  `DoWrite` helper, `kSyscallWriteMax = 256` bounce buffer cap.
  Ring-3 payload update in `kernel/core/ring3_smoke.cpp` (now
  calls SYS_WRITE with "Hello from ring 3!\n" before SYS_EXIT).
- **Decision:** First syscall that consumes a pointer argument.
  Calling convention: rdi = fd, rsi = buf, rdx = len. Only fd=1
  (stdout) is recognised in v0 — anything else returns -1. The
  kernel allocates a 256-byte bounce buffer on its stack, copies
  up to `min(len, 256)` bytes from userspace via
  `mm::CopyFromUser` (which SMAP-gates the read), and emits the
  bytes one-at-a-time to COM1. Returns the byte count actually
  written (possibly truncated — standard POSIX-ish short-write
  semantics). Truncation is not an error; the caller loops if
  they care. NUL bytes inside the user buffer are forwarded
  faithfully to COM1 (via a 2-char `{b, '\0'}` scratch buffer)
  so the ABI doesn't quietly lose embedded nulls.
- **Why:** The exit syscall in #045 deliberately dodged the
  return-value half of the ABI (SchedExit never returns). This
  one exercises a pointer-arg path and completes the round-trip
  invariants: user passes a pointer, kernel validates + SMAPs +
  copies into a bounce buffer, kernel acts on a kernel-owned
  copy (no TOCTOU), kernel writes rax back, iretq delivers the
  count. A fixed 256-byte cap keeps this syscall on-stack
  without making it unbounded in kernel memory. "stdout only"
  is deliberate — introducing anything that looks like an fd
  table before VFS lands would be speculative machinery.
- **Rules out / defers:** File descriptor table (v0 has exactly
  one well-known fd: stdout=1). writev / iovec support —
  no consumer. Real short-write semantics with EINTR / partial
  progress — no signals yet. Async I/O — neither the infrastructure
  nor a consumer exists. An fd=2 (stderr) split, or any other
  well-known fd — stdout is the only sink COM1 cares about for
  now. Non-COM1 destinations (e.g. a framebuffer tty) — the
  whole tty layer is a later track. Line-buffered vs
  unbuffered write semantics — unbuffered is the right default
  for a serial console with no scroll-back concerns.
- **Revisit when:** First fd table lands — SYS_WRITE grows a
  dispatch per fd instead of its hard-coded fd==1 check.
  First bug caused by a user pointer that's in-range but
  unmapped — land `__copy_user_fault_fixup` so
  `CopyFromUser` returns false instead of #PF'ing the kernel.
  First consumer that writes > 256 bytes — either grow the
  bounce buffer (cost: kernel-stack budget) or move to a
  per-task scratch buffer allocated at SchedCreate time.
- **Related tracks:** Track 4 (Process — first consumer of the
  write syscall is the init / shell when they land),
  Track 5 (Filesystem — SYS_WRITE becomes a thin dispatch once
  VFS arrives), Track 13 (Security — SMAP is the first real
  hardware-enforced boundary on user-pointer trust).

---

## 046 — SMEP + SMAP + mm::CopyFromUser / CopyToUser

- **Scope:** `kernel/mm/paging.{h,cpp}` — CPUID-gated CR4 flips
  (`EnableKernelProtectionBits`, called from `PagingInit`) plus
  two public helpers (`CopyFromUser`, `CopyToUser`) that
  validate the user pointer's range and SMAP-gate the copy
  with stac / clac when the feature is on.
- **Decision:** Enable both kernel-protection bits as early as
  possible in the boot path — inside `PagingInit`, right after
  EFER.NXE. SMEP (CR4 bit 20) makes kernel-mode execution of
  any page with `U/S=1` #PF; SMAP (CR4 bit 21) makes kernel-mode
  DATA access to a user page #PF unless RFLAGS.AC is set.
  Both are gated on CPUID.7.0.EBX bits 7 (SMEP) and 20 (SMAP);
  older CPUs stay in the pre-protection posture without
  breaking the boot. Every user-pointer read/write the kernel
  does now goes through `mm::CopyFromUser` or `mm::CopyToUser`
  which:
    1. reject pointers outside the canonical low half
       (kUserMax = 0x00007FFF_FFFFFFFF — everything above is
       the non-canonical hole or kernel space),
    2. reject lengths that would overflow or cross into the
       high half,
    3. issue `stac` before the byte-by-byte copy and `clac`
       after, so the CPU's SMAP check grants kernel access to
       user memory only inside this one helper. Any other
       kernel code path that dereferences a user pointer
       still #PFs.
- **Why:** Enables the first pointer-arg syscall (SYS_WRITE, #047)
  safely. Without SMAP, a kernel bug that dereferences a user
  pointer anywhere (not just inside the copy helper) still
  works at the hardware level, which is how several
  high-profile Linux exploits (e.g. the wait4 pointer-confusion
  class) historically escalated. With SMAP, those same bugs
  degrade to a clean #PF in the kernel — the trap dispatcher
  records the violation and halts, which is infinitely
  preferable to silent exploitation. SMEP closes the
  complementary "spray shellcode into a user page, trick the
  kernel into jumping there" class of exploits. Both bits are
  present on any x86_64 CPU from 2014 onwards; not landing them
  now would be choosing weaker defaults for no gain. Landing
  them with the copy helpers avoids the "enable SMAP, then
  immediately crash on the first user-pointer touch because
  we forgot stac" debugging round.
- **Rules out / defers:** Fault-recovery table for the copy
  loops (`__copy_user_fault_fixup` — one entry per copy, lets
  an in-range-but-unmapped user pointer return `false` instead
  of #PF-halting the kernel). CET (shadow stack / IBT) — a
  separate CR4 bit set with its own CPUID gate; lands as its
  own slice. `mm::StrlenUser` and friends — no consumer yet.
  Per-CPU SMAP state management on context switch — AC is
  cleared by the hardware on iretq to a lower privilege, so
  preemption during a stac'd copy is safe without extra work.
- **Revisit when:** First syscall whose user pointer can
  legitimately fault (e.g. a read from a just-mmap'd file
  that's lazily populated) — land the fault-fixup table then.
  SMP bring-up — SMAP is per-CPU; each AP needs its CR4 bits
  set in its startup path. CET lands — touches the same CR4
  register, may need coordinated write.
- **Related tracks:** Track 3 (MM — the copy API is an MM
  concern), Track 13 (Security — SMEP/SMAP are hardware
  enforcement of the W^X + trust-boundary posture the
  malware-hard-stop plan relies on).

---

## 045 — First syscall gate: int 0x80 (DPL=3) + SYS_exit

- **Scope:** `kernel/arch/x86_64/exceptions.S` (new `ISR_NOERR 128`
  stub reaching `isr_common`), `kernel/arch/x86_64/idt.{h,cpp}`
  (new `IdtSetUserGate` — DPL=3 interrupt-gate installer),
  `kernel/arch/x86_64/traps.cpp` (TrapDispatch branch for
  `frame->vector == 0x80` → `core::SyscallDispatch` before the
  exception fallback), `kernel/core/syscall.{h,cpp}` (new module:
  `SyscallNumber::SYS_EXIT`, `SyscallInit`, `SyscallDispatch`),
  wiring in `kernel/core/main.cpp`, payload update in
  `kernel/core/ring3_smoke.cpp`.
- **Decision:** Land the minimum usable user→kernel ABI. A single
  vector (0x80) via legacy `int N` (not SYSCALL/SYSRET), installed
  with a DPL=3 interrupt gate so ring-3 code can issue the int
  without #GP'ing on the privilege check. Calling convention v0:
  syscall number in rax, args in rdi / rsi / rdx, return value
  written back into `frame->rax`. Exactly one syscall today —
  `SYS_EXIT = 0` — which calls `sched::SchedExit` from inside the
  dispatcher; that function is `[[noreturn]]`, so the trap frame
  on the dying task's kernel stack is simply abandoned and the
  reaper eventually KFrees both the stack and the Task struct.
  Unknown syscall numbers log at Warn and write `-1` into
  `frame->rax` — the ABI promise is that a bad number is a
  recoverable error from the caller's point of view, not a task
  kill. The ring-3 smoke payload grew from 4 bytes to 13: four
  `pause` iterations (so the 100 Hz timer actually preempts us at
  least once before exit) followed by `xor eax,eax; xor edi,edi;
  int 0x80; hlt` — the trailing `hlt` is unreachable on the happy
  path and a clean #GP signal on the unhappy one.
- **Why:** Entry #044 landed ring 3 as a one-way door — the smoke
  task had no way to exit, which meant any attempt to restart the
  scenario required a full reboot and left a zombie-ish ring-3
  task pinned forever. Landing the gate now closes that loop AND
  validates the full round-trip: user → `int 0x80` → hardware
  delivers onto RSP0 → isr_common → TrapDispatch → SyscallDispatch
  → SchedExit → reaper. Every link in that chain becomes
  regression-testable. SYS_EXIT is deliberately the first syscall
  because it's the one syscall whose return semantics are trivially
  "no return" — it avoids the entire "write frame->rax then iretq"
  half of the ABI on the first slice. The second syscall (future
  `write`/`log` or `getpid`) will exercise the return-value path.
- **Rules out / defers:** SYSCALL/SYSRET (needs STAR/LSTAR/SFMASK
  MSR plumbing + a FRED-or-classic entry stub; `int 0x80` is ~30×
  slower than SYSCALL but "good enough" while exactly one
  consumer exists). A proper syscall ABI document (names, numbers,
  argument types, errno-style return convention) — deferred until
  the 3rd-or-4th syscall when the pattern stabilises. Copy-from /
  copy-to-user helpers with SMAP + fault-tolerant user-pointer
  validation — no syscall today takes a pointer argument.
  Argument clobber rules (which regs SYSCALL-v1 trashes, which
  ones it preserves) — documented with the MSR-based path, not
  here. Interrupted-syscall restart (EINTR semantics) — no signal
  delivery yet, so the question doesn't arise. Syscall entry
  tracing (an LTTng-ish ring buffer of (task, num, args, retval,
  duration)) — belongs to observability track, not gate v0.
  Per-process syscall filters (seccomp-bpf-style) — security
  track, after the policy engine lands. fork/exec/wait — the
  whole process-lifecycle triad depends on per-process address
  spaces, which still don't exist. Batch syscalls / iovec-style
  `writev` — YAGNI.
- **Revisit when:** First syscall with a return value lands —
  verify `frame->rax = retval; return;` round-trips correctly
  through iretq. First syscall with a pointer argument —
  introduce `copy_from_user` / `copy_to_user` behind SMAP, plus
  the #PF-in-copy recovery path. First signal delivery or
  cancellation — EINTR semantics need picking. SYSCALL/SYSRET
  performance work is wanted — migrate the gate; leave `int 0x80`
  as a compat path until it can be deprecated with a clear
  consumer count. Second ring-3 task exists — TSS.rsp0 has to
  move into scheduler switch-in (already called out in #044 but
  now actually load-bearing for syscall correctness, since every
  syscall lands on RSP0).
- **Related tracks:** Track 4 (Process model — user→kernel ABI
  is the foundation every process op sits on top of), Track 11
  (Win32 subsystem — NT syscalls eventually descend from the
  same gate machinery), Track 13 (Security — syscall filtering
  and the policy engine will graft onto this dispatch point).

---

## 044 — First ring-3 slice: GDT user segments + iretq entry + smoke task

- **Scope:** `kernel/arch/x86_64/gdt.{h,cpp}` (DPL=3 user code
  + user data in slots 5–6, `TssSetRsp0` helper),
  `kernel/arch/x86_64/usermode.{h,S}` (new module:
  `EnterUserMode(rip, rsp)` — iretq into ring 3),
  `kernel/sched/sched.{h,cpp}` (`SchedCurrentKernelStackTop`
  accessor), `kernel/core/ring3_smoke.{h,cpp}` (new module:
  dedicated scheduler thread that maps a user code + stack
  page, publishes RSP0, and iretq's into ring 3), wiring in
  `kernel/core/main.cpp`.
- **Decision:** Land the minimum infrastructure to prove ring
  3 works end-to-end, without yet dragging in syscalls,
  per-process address spaces, or scheduler-aware RSP0
  updates. A single boot-time scheduler thread (`ring3-smoke`)
  does four things in order: (1) allocates one 4 KiB frame
  for user code at VA `0x40000000` and plants a 4-byte
  `pause; jmp short -4` payload, (2) allocates one 4 KiB
  frame for user stack at VA `0x40010000`, (3) sets TSS.RSP0
  to the top of its own kernel stack so the first user→kernel
  transition lands safely, (4) calls `EnterUserMode` which
  builds an iretq frame (SS / RSP / RFLAGS=0x202 / CS / RIP)
  and iretq's to ring 3. The user code loops forever with
  IF=1; timer interrupts preempt it, the trap dispatcher
  handles the IRQ, the scheduler round-robins, and every
  other kernel worker (heartbeat, keyboard reader, demo
  mutex workers, idle) continues to make forward progress
  — which is the verifiable evidence that ring 3 entry did
  not corrupt kernel state. `EnterUserMode` is
  `[[noreturn]]`; a ring-3 task returns to the kernel only
  via a trap/IRQ, never via a plain ret.
- **Why:** Entries #032 (TSS + IST) and multiple others have
  been plumbing the "when ring 3 lands" side of the house
  in anticipation of this slice. The index's current-state
  note called out "transition to ring 3 (user processes +
  syscalls)" as one of three candidate next bites. Taking
  the smallest possible first bite — GDT + iretq + a user
  payload that doesn't fault — keeps the scheduler,
  paging, and trap-handling machinery honest without
  forcing the simultaneous landing of SYSCALL/SYSRET,
  per-process page tables, and a libc stub. The pattern is:
  land ring 3 now, validate the scheduler survives it, then
  land syscalls on top of a tested foundation.
- **Rules out / defers:** Per-task RSP0 updates on context
  switch (single ring-3 task in v0 — TSS.rsp0 is set once
  and stays valid because no other task ever enters ring 3).
  SYSCALL/SYSRET (no syscall dispatch yet). Per-process
  address spaces (single global PML4 still — the user
  pages at `0x40000000` are visible to every task, kernel
  or user). A way for the user task to exit (the ring-3
  loop is genuinely infinite; the reaper never sees it).
  Syscall gate via `int 0x80` (vector stays non-present;
  a deliberate `int` from ring 3 #GPs, which is the
  correct posture until a handler exists). Signals. Page-
  table tear-down on user-task exit. `int3` / `ud2` from
  ring 3 (still halts the dispatcher — the trap frame
  would carry CS=0x1B, which is diagnostically useful but
  not yet a recoverable path). FPU/SSE user state (we
  compile `-mno-sse -mgeneral-regs-only` so user code that
  touches xmm registers #UDs cleanly). STAR/LSTAR/SFMASK
  MSRs (consumed only by SYSCALL/SYSRET; leaving them zero
  is fine).
- **Revisit when:** First syscall lands — the gate needs a
  DPL=3 IDT entry for `int 0x80`, the C++ handler consumes
  the trap frame's rax/rdi/rsi/... as argN registers, and
  the slice grows a `SchedCreateUserProcess` that replaces
  today's manual "one user task, one smoke thread" wiring.
  Second ring-3 task is created — that's when
  `arch::TssSetRsp0` must move into the scheduler's
  switch-in path (update on every context switch INTO a
  user-mode-capable task). Per-process address spaces
  land — today's single shared PML4 becomes one CR3 per
  process, which also means `g_user_code_virt` /
  `g_user_stack_virt` stop being global constants. SMP
  ring 3 — each CPU's TSS needs its own RSP0 slot (today's
  BSP-only helper doesn't generalise).
- **Related tracks:** Track 4 (Process model — first
  concrete user-mode execution), Track 11 (Win32 subsystem
  — every PE executable will end up in ring 3 via
  something descended from this entry path), Track 13
  (Security — W^X enforced on the user code mapping:
  present + user-accessible, no writable bit; stack
  mapping: present + writable + user + NX).

---

## 043 — PS/2 keyboard device reset + explicit scan-code-set-1

- **Scope:** `kernel/drivers/input/ps2kbd.cpp` — new
  `KbdSendAndAck` helper + steps 7-9 added to `ControllerInit`
- **Decision:** After the controller-level init (#027) finishes,
  drive the device directly: 0xFF (reset → 0xFA ACK → 0xAA self-
  test pass), 0xF0 0x01 (force scan code set 1), 0xF4 (enable
  scanning). Unexpected / missing ACK logs a Warn and continues
  — USB-legacy emulated keyboards routinely drop device commands
  while still producing scan codes, so panicking would refuse
  interactive input on too much hardware.
- **Why:** Closes the "device reset" and "scan-code-set
  selection" items explicitly deferred in #027. The scan-code
  translator (#024) is correct only if the device is actually
  emitting set 1. Firmware default is usually "set 2 + 8042
  translation on" (indistinguishable on 0x60), but some boards
  leave the device on set 2 with translation disabled, which
  would silently wreck the keymap.
- **Rules out / defers:** Typematic (repeat rate + delay)
  configuration — 0xF3 `<byte>` works but we don't care today.
  Caps-lock / num-lock / scroll-lock LED control (0xED
  `<mask>`) — no consumer. Port 2 / aux-channel (mouse) — no
  driver.
- **Revisit when:** First non-PS/2-primary machine where the
  device-reset path actually matters on real hardware. Typematic
  configuration becomes useful (games / terminals). USB HID
  stack lands (primary input path on modern hardware, PS/2 path
  stays as fallback).
- **Related tracks:** Track 6 (Drivers — input).

---

## 042 — HPET self-test

- **Scope:** `kernel/arch/x86_64/hpet.{h,cpp}` — new
  `HpetSelfTest`, called from `kernel_main` right after
  `HpetInit`
- **Decision:** Read the HPET main counter twice with a bounded
  busy-wait between. Panic if the counter didn't advance or
  went backwards (monotonicity invariant). No-op if ACPI didn't
  find an HPET. Runs early — before the scheduler — so the
  test uses `pause` rather than `SchedSleepTicks`.
- **Why:** HPET is a silent dependency for the log-timestamp
  path (#035) and every future fine-grained timing consumer. A
  broken counter would surface downstream as "time didn't
  advance for an hour" type mysteries; better to halt at boot
  with a named diagnostic.
- **Rules out / defers:** Verifying the reported period against
  the actual rate (would need a second clock source to cross-
  check — PIT calibration could do it, but pulls in extra
  init ordering). Catching a stuck counter that later resumes
  (would need periodic re-checks from a watchdog). Self-tests
  for individual comparators (we don't use them yet).
- **Revisit when:** HPET starts driving interrupts (the
  comparators land). First discrepancy observed between HPET
  time and wall-clock / PIT (means adding cross-check).
- **Related tracks:** Track 2 (Platform — observability).

---

## 041 — Heartbeat to SchedSleepUntil (drift-free cadence)

- **Scope:** `kernel/core/heartbeat.cpp` — replace
  `SchedSleepTicks(kHeartbeatTicks)` with
  `SchedSleepUntil(deadline); deadline += kHeartbeatTicks;`
- **Decision:** First consumer of the absolute-deadline
  primitive from #034. Period stays exactly
  `kHeartbeatTicks * 10 ms` regardless of how long the dump
  body takes to serialize — previously ~0.2% drift per beat.
- **Why:** Trivial migration, real win. Heartbeat is the
  canonical periodic kernel task; future periodic drivers
  (watchdogs, health probes) will copy this pattern as the
  default — so codifying it here sets the template.
- **Rules out / defers:** Catch-up semantics (if the CPU was
  starved for >kHeartbeatTicks, we yield once and move on;
  no multi-beat burst). Phase alignment to wall-clock
  boundaries (needs RTC).
- **Revisit when:** Second periodic kernel task lands (extract
  a `PeriodicTaskLoop` helper). Priorities grow enough that
  heartbeat needs a guaranteed-wake class.
- **Related tracks:** Track 2 (Platform — observability).

---

## 040 — Stack canaries on IST stacks

- **Scope:** `kernel/arch/x86_64/gdt.{h,cpp}` —
  `kIstStackCanary` + `IstStackCanariesIntact()`;
  `kernel/core/panic.cpp` — dumps `ist_canary : ok/CORRUPT`
  in `DumpDiagnostics`
- **Decision:** Plant the same
  `0xC0DEB0B0CAFED00D` canary at the low edge of each IST
  stack (#DF, #MC, #NMI) that per-task kernel stacks already
  carry. `TssInit` plants; crash-dump path checks. Any blown
  canary becomes a named "CORRUPT" diagnostic instead of
  silent-BSS-scribble.
- **Why:** A 4 KiB IST stack is tight — the crash-dump path
  runs near 2 KiB, leaving thin margin. Without canaries, an
  IST overflow would clobber the next BSS variable (the next
  stack, the TSS, random globals) and manifest as unrelated
  weirdness later. Mirrors the per-task stack-canary pattern
  (#010 era) so the checking discipline is uniform.
- **Rules out / defers:** Page-level guard pages below each
  IST (would need a paged stack allocator). Canaries at
  multiple depths (stack poisoning). Per-AP IST canaries —
  APs still halt in ApEntryFromTrampoline, no IST stack in use.
- **Revisit when:** First IST overflow seen in CI / real
  hardware (reduce IST stack budget? expand it? add guard
  pages?). SMP scheduler join — each AP gets its own IST
  stacks that need canaries too.
- **Related tracks:** Track 2 (Platform — stack hardening),
  Track 13 (Security — defence in depth).

---

## 039 — 2-level priority scheduling (Normal + Idle)

- **Scope:** `kernel/sched/sched.{h,cpp}` — new `TaskPriority`
  enum, two runqueues (`g_run_head_normal` /
  `g_run_head_idle`), drain-normal-first policy in
  `RunqueuePop`, `SchedCreate` grows an optional priority
  parameter
- **Decision:** Split the single FIFO runqueue into two
  priority bands. Normal-priority tasks (drivers, workers,
  reapers, kbd-reader, all SchedCreate defaults) round-robin
  on one queue; Idle-priority tasks (per-CPU idle threads
  from `SchedStartIdle`) wait on the other and only get
  picked when Normal is empty. Priority is fixed at
  SchedCreate and never changes — priority inheritance /
  real-time class are deferred.
- **Why:** First half of decision log #010's "Priorities.
  Real-time class." deferral. With the idle task on the
  Normal queue, it was round-robinning CPU time with real
  workloads — every N+1th scheduler slot went to halt,
  compressing worker throughput by ~1/(N+1). Moving idle to
  its own lower band means CPU goes to real work first.
- **Rules out / defers:** Priority inheritance (needs a
  runtime `boost_priority_to(...)` + revert hook). Real-time
  class (guaranteed-latency band). Per-priority timeslicing
  (just drain-top-first here). More bands (normal has one
  level). CPU affinity (no per-CPU runqueues).
- **Revisit when:** First interactive workload where CPU
  budget visibly suffers from round-robin fairness. Real-time
  driver (audio, input latency) needs an above-Normal band.
  SMP scheduler join — per-CPU runqueues move per-priority
  band per CPU.
- **Related tracks:** Track 2 (SMP — per-CPU runqueues),
  Track 4 (Process model — user priorities),
  Track 9 (GUI responsiveness — compositor needs real-time).

---

## 038 — PCI CONFIG_ADDRESS/DATA serialisation

- **Scope:** `kernel/drivers/pci/pci.cpp` — adds a global
  `sync::SpinLock g_pci_config_lock`, taken across the port-IO
  pair in `PciConfigRead32` and `PciConfigWrite32`
- **Decision:** Every low-level config access (32-bit read + 32-
  bit write) takes a single global lock so the CF8/CFC dance
  can't interleave across CPUs. Multi-step sequences (BAR size
  probe — read, write 0xFF, read back, restore) still release
  the lock between individual accesses. That's acceptable today:
  enumeration runs at boot before APs can meaningfully interact.
  A future atomicity pass would expose `PciConfigLock/Unlock`
  so probe callers hold the lock across all four operations.
- **Why:** `pci-enum-v0.md:145` flagged this as deferred "until
  a consumer hits it." With broadcast-NMI panic halt (#037) and
  eventual SMP scheduler join in flight, the cost of adding
  correctness now is trivial (one lock, no refactor) and the
  cost of hitting the race later is a bizarre intermittent bug
  that's hard to triage. Land while it's still cheap.
- **Rules out / defers:** `PciConfigLock / Unlock` for
  multi-step atomicity (needed for 64-bit BAR probe, MSI/MSI-X
  capability programming). ECAM fast path (still deferred until
  MCFG entry #036 has a real consumer).
- **Revisit when:** First driver that programs MSI-X with the
  device active and being probed concurrently by another CPU
  (needs full-sequence atomicity). PCIe ECAM migration (lock
  moves with the accessor).
- **Related tracks:** Track 2 (SMP), Track 6 (Drivers).

---

## 037 — Broadcast-NMI panic halt (SMP Class-A recovery)

- **Scope:** `kernel/arch/x86_64/smp.{h,cpp}` — new
  `PanicBroadcastNmi`; `kernel/arch/x86_64/traps.cpp` — vector-2
  short-circuit; `kernel/arch/x86_64/lapic.{h,cpp}` — new
  `LapicIsReady`; `kernel/core/panic.cpp` wires the broadcast into
  both Panic and PanicWithValue
- **Decision:** On panic, before writing the crash dump, the
  panicking CPU fires an "all excluding self" NMI IPI via the
  LAPIC ICR shorthand. Every peer CPU receives the NMI on its
  IST3 stack (wired by #032), enters the trap dispatcher, and is
  short-circuited to a `cli; hlt` loop. The panicking CPU then
  has exclusive use of the serial line for the dump. The
  broadcast guards on `LapicIsReady()` so early-boot panics
  (before LAPIC init) skip it gracefully.
- **Why:** Decision log #017, #018, #021, and
  smp-ap-bringup-scope.md §"Open questions" all flagged this as
  the Class-A recovery gap on SMP. Without it, a panic on one
  CPU leaves peers running against whatever corrupt shared state
  triggered the panic — exactly the wrong posture per the
  runtime-recovery strategy's "Class A → HALT, everywhere."
- **Rules out / defers:** NMI-on-AP-already-halted is a no-op
  (AP enters the IST3 handler, falls into the same short-
  circuit, halts again — wasteful but correct). Stuck-ICR
  timeout recursing into Panic is avoided by inlining the wait
  loop and logging a Warn on timeout rather than panicking.
  NMI with a real consumer (chipset error, watchdog,
  power-button) — every NMI today means "stop." Revisiting
  requires a subsystem registration API.
- **Revisit when:** First subsystem needs a real NMI handler
  (power-button or hardware watchdog). AP scheduler join lands
  — confirm NMI still fires cleanly on a CPU running scheduled
  work, not just the halt loop.
- **Related tracks:** Track 2 (SMP), Track 13 (Security /
  recovery — Class A on SMP).

---

## 036 — MCFG parse for PCIe ECAM (base + bus range)

- **Scope:** `kernel/acpi/acpi.{h,cpp}` — adds `McfgTable` /
  `McfgEntry` structs, `ParseMcfg`, and
  `McfgAddress/StartBus/EndBus` accessors
- **Decision:** Find the MCFG table, checksum-validate it, and
  cache the first segment-group-0 entry's base address + bus
  range. Multi-segment hardware is vendor-specific and no x86_64
  platform we target ships it. Optional like FADT/HPET/MCFG —
  a missing table leaves accessors at 0 so PCI drivers keep
  using legacy port IO.
- **Why:** Decision log #012 deferred "MCFG (PCIe ECAM)"
  alongside HPET and FADT. #025 and #031 both landed their
  respective table parses; MCFG is the natural third. Landing
  the parse now keeps the ECAM migration commit focused purely
  on the port-IO → MMIO swap.
- **Rules out / defers:** Actually using ECAM — PCI enumeration
  still uses CONFIG_ADDRESS/DATA (#022). Multi-segment support.
  Cross-checking the MCFG-reported base against chipset
  registers (real-hardware cross-validation).
- **Revisit when:** First PCIe device that needs >256 bytes of
  config space (legacy port IO can't reach extended capabilities).
  MSI-X vector table programming (ECAM makes the capability
  chain access much simpler). xHCI driver begins — primary
  driver that benefits from ECAM speed.
- **Related tracks:** Track 2 (Platform), Track 6 (Drivers —
  PCIe endpoints).

---

## 035 — HPET-timestamped klog lines

- **Scope:** `kernel/core/klog.cpp` — prefixes every log line
  with `[ts=0xNNNNNNNNNNNNNNNN] `
- **Decision:** Timestamp source is HPET main counter if
  available (sub-microsecond precision), scheduler tick counter
  otherwise (100 Hz). Unit is implied by the source; readers
  cross-reference the "[acpi] hpet=..." boot log. Format is raw
  hex — a printf-free kernel isn't going to format decimal
  fractional seconds. Falls back cleanly to 100 Hz tick if no
  HPET is present.
- **Why:** Makes log lines visibly ordered within a single 10
  ms tick. Previously a 10-second idle between two lines and a
  same-tick burst of 50 lines looked identical in the serial
  log. HPET primitive from #031 is now consumed by its first
  caller, closing the "built but not wired in" concern.
- **Rules out / defers:** Human-readable decimal formatting
  (needs printf-class formatting infrastructure). Per-CPU
  timestamp source (NMI broadcast uses this path, and the two
  cores might have slightly skewed HPET reads; same source
  across CPUs is fine for now). Wall-clock anchor (needs RTC
  read + leap-second handling).
- **Revisit when:** Post-mortem tool starts parsing timestamps
  (decide formatting — decimal or keep hex?). SMP scheduler
  join (HPET is globally coherent, but logs will want CPU ID
  alongside). Wall-clock support arrives (RTC init).
- **Related tracks:** Track 2 (Platform), Track 1 (CI — log
  diff tooling).

---

## 034 — SchedSleepUntil (absolute-deadline sleep)

- **Scope:** `kernel/sched/sched.{h,cpp}` — adds
  `SchedSleepUntil(deadline_tick)` and `SchedNowTicks()`
- **Decision:** Complement the existing relative sleep with an
  absolute-deadline variant. Caller reads `SchedNowTicks()`
  once to establish a base, then loops `deadline += period;
  SchedSleepUntil(deadline);` — drift-free. Reuses the existing
  sleep queue + `TickReached` wrap-safe compare; no new
  machinery.
- **Why:** Periodic kernel tasks that use `SchedSleepTicks`
  accumulate body latency into the period. `kheartbeat`
  (entry #014 adjacent) is the canonical example: "print stats
  every 5 seconds" drifts to 5+ε seconds per cycle if the
  print path takes non-trivial time. Land the primitive before
  the first caller so periodic-task patterns have a one-line
  right answer.
- **Rules out / defers:** Phase alignment to wall-clock
  boundaries (needs RTC). Catch-up scheduling (if the deadline
  is already past when the caller wakes, we Yield but don't
  fire multiple iterations back-to-back).
- **Revisit when:** First caller that shows measurable drift on
  `SchedSleepTicks`. Heartbeat thread migrates to absolute
  deadlines (cheap follow-up).
- **Related tracks:** Track 4 (IPC / sync — periodic patterns).

---

## 033 — KLog runtime severity threshold

- **Scope:** `kernel/core/klog.{h,cpp}` — adds
  `SetLogThreshold` / `GetLogThreshold` + a global
  `g_log_threshold`, evaluated alongside the compile-time
  `kKlogMinLevel` on every Log/LogWithValue call
- **Decision:** Effective log level is
  `max(kKlogMinLevel, g_log_threshold)`. The runtime knob can
  only RAISE the filter past the compile-time floor, never
  lower it — production builds compile Debug out entirely and
  no runtime call can re-enable it. Default threshold matches
  the floor so behaviour is unchanged unless a caller opts in.
- **Why:** Driver bring-up often wants Debug noise during
  init and Info-only once settled. Without a runtime knob, the
  choice was "rebuild" vs "drown in output." Same pattern
  useful for CI runs (drop to Warn+ only to keep logs compact).
- **Rules out / defers:** Per-subsystem thresholds (globally
  one knob — if a subsystem is noisy, it's a klog-call-site
  problem). Dynamic thresholds tied to heartbeat / health
  (e.g., "raise to Debug when panic is imminent"). Log-level
  introspection from a debugger.
- **Revisit when:** Per-subsystem tuning becomes necessary
  (first noisy driver). A shell lands and SetLogThreshold
  becomes invokable from user-space.
- **Related tracks:** Track 2 (Platform — observability),
  Track 1 (CI).

---

## 032 — TSS + IST stacks for #DF, #MC, #NMI

- **Scope:** `kernel/arch/x86_64/gdt.{h,cpp}` (TSS struct,
  `TssInit`, three 4 KiB IST stacks, GDT grown to 5 slots),
  `kernel/arch/x86_64/idt.{h,cpp}` (`IdtSetIst`), wiring in
  `kernel/core/main.cpp`
- **Decision:** Install a long-mode TSS with three dedicated IST
  stacks for the three critical faults where continuing on the
  currently-running task's stack is dangerous: #DF (double fault —
  caller's stack might be bad), #MC (machine check — caller's
  stack might be corrupted), #NMI (asynchronous, can fire at any
  moment including inside a locked region). Each IST stack is a
  separate 4 KiB BSS array; the TSS descriptor lives in GDT slots
  3-4 (long-mode TSS is 16 bytes = 2 slots). IDT entries for the
  three vectors get their IST field patched to 1/2/3 respectively
  via a new `IdtSetIst` helper.
- **Why:** Entry #004 called out "IST stacks for critical
  exceptions (#DF, #MC, #NMI — all currently share the kernel
  stack)" as deferred. Without IST, a double fault on a bad
  kernel stack triple-faults the machine; with IST, #DF is
  guaranteed to deliver onto a known-good stack regardless of
  what state the prior one was in. Same reasoning for #MC and
  #NMI. Landing now also wires the `RSP0` slot in the TSS so
  the descriptor is already in-place when ring 3 lands —
  user→kernel transitions consume that field.
- **Rules out / defers:** Per-AP TSS + IST stacks — APs still
  halt in `ApEntryFromTrampoline` with IF=0, so they never
  take a fault on a bad stack. Lands with SMP scheduler join
  (Commit E in smp-ap-bringup-scope.md). Per-task kernel stack
  via RSP0 (ring 3 transition's job — the slot is wired, the
  value stays 0 until the first user process runs). Guard
  pages around each IST stack (would need paging-backed
  allocations; no consumer yet). I/O-permission bitmap (disabled
  by setting `iopb_offset` past the TSS body — every ring-3
  port access will #GP, which is the posture we want).
- **Revisit when:** Ring 3 lands — RSP0 gets wired to the
  current task's kernel stack on every context switch. SMP
  scheduler join — each AP allocates its own TSS + IST stacks
  and does `ltr` in its entry. First real machine check hits —
  the panic path walks the #MC frame, which is now delivered
  on IST2.
- **Related tracks:** Track 2 (Platform — interrupt infrastructure),
  Track 4 (Process model — RSP0 becomes per-task).

---

## 031 — HPET driver: ACPI parse + main-counter enable

- **Scope:** `kernel/acpi/acpi.{h,cpp}` (HpetTable struct,
  `ParseHpet`, `HpetAddress()` / `HpetTimerCount()` /
  `HpetCounterWidth()`), `kernel/arch/x86_64/hpet.{h,cpp}` (new
  module: `HpetInit`, `HpetReadCounter`, `HpetPeriodFemtoseconds`),
  wiring in `kernel/core/main.cpp`
- **Decision:** Parse the ACPI HPET table, `MapMmio` the 1 KiB
  event-timer-block window, validate that COUNT_SIZE_CAP == 1
  (64-bit counter), zero the main counter, and set ENABLE_CNF.
  Expose a 64-bit `HpetReadCounter()` for sub-tick precision
  timing and `HpetPeriodFemtoseconds()` so callers can convert
  deltas without a second MMIO read. HPET is OPTIONAL — a missing
  table just skips init with a Warn log line. 32-bit HPETs panic
  loudly rather than getting a read+retry fallback we can't
  validate (vanishingly rare on x86_64).
- **Why:** Entry #012 deferred "HPET (high-precision timer)"
  alongside FADT. FADT landed in #025; HPET is the natural
  follow-up and brings a high-precision counter primitive into
  the tree. LAPIC timer still owns the 100 Hz scheduler tick —
  HPET is a read-only precision counter for future consumers
  (calibration, log timestamps, fine-grained driver delays).
  Landing now means the first consumer doesn't also have to
  design the parse + MMIO map.
- **Rules out / defers:** Per-timer comparator programming
  (HPET can drive its own interrupts — not needed while LAPIC
  timer is the tick source). Legacy replacement mode
  (LEG_RT_CNF — we've already moved the tick off the PIT, so
  no consumer cares). 32-bit counter fallback (panic for now).
  Multi-HPET support (the spec allows multiple blocks; every
  real chipset ships exactly one).
- **Revisit when:** Log timestamps land (read `HpetReadCounter`
  in the klog prologue). Driver code needs sub-100 Hz delays
  (use HPET spin instead of `SchedSleepTicks`). TSC calibration
  (HPET is the gold standard for deriving TSC frequency). Sleep
  states + wake-from-S3 — HPET survives, RTC does not, so it
  becomes the preferred clock.
- **Related tracks:** Track 2 (Platform — precision timing),
  Track 13 (Power management — HPET across S-states).

---

## 030 — CondvarWaitTimeout

- **Scope:** `kernel/sched/sched.{h,cpp}` — adds
  `CondvarWaitTimeout` alongside the untimed `CondvarWait`
- **Decision:** Mirror `WaitQueueBlockTimeout` (entry #026) on
  the condvar layer. Same atomicity splice as `CondvarWait`
  (mutex hand-off + self-enqueue under one sched_lock), plus
  also go onto the sleep queue so the timer path can fire.
  Returns `true` if woken by an explicit `CondvarSignal` /
  `CondvarBroadcast`, `false` if the timer won. `ticks == 0` is
  a test-and-drop: Unlock + Yield + Lock, report as timeout.
- **Why:** Entry #028 explicitly called out "Timed condvars
  (`CondvarWaitTimeout`) — trivial follow-up on top of
  `WaitQueueBlockTimeout`, but no consumer yet" as deferred.
  Now that two independent users could want it (driver
  command-completion wait with timeout, producer/consumer
  where the consumer bounds its idle time), closing the
  deferral is cheap and keeps the blocking primitive set
  uniform — every pattern has both timed and untimed variants.
- **Rules out / defers:** Wake-reason propagation beyond the
  bool return (callers don't learn whether it was Signal vs.
  Broadcast; they shouldn't care). Cancellation / interruption
  (needs the "cancel this blocked task" primitive — arrives with
  the first syscall that takes signals).
- **Revisit when:** First driver I/O path that needs
  "complete-or-timeout" semantics on a condvar. First syscall
  with signal delivery (cancellation).
- **Related tracks:** Track 4 (IPC / sync), Track 6 (Drivers —
  consumer).

---

## 029 — KernelReboot: ACPI → 0xCF9 → 8042 → triple-fault chain

- **Scope:** `kernel/core/reboot.{h,cpp}` (new module), wired into
  the build in `kernel/CMakeLists.txt`
- **Decision:** Consolidate every known x86 reset path behind a
  single `core::KernelReboot()` entry point that tries them in
  descending order of preference: (1) `acpi::AcpiReset()` — the
  firmware-defined FADT path; (2) port 0xCF9 values 0x02 then
  0x06 — the PC-AT chipset reset; (3) 8042 command 0xFE — the
  legacy keyboard-controller reset line, still honoured by most
  boards; (4) null IDT + `int3` — a guaranteed triple-fault last
  resort. Each step logs at Warn / Error so the serial log
  records which path actually fired. `[[noreturn]]`, safe from any
  context.
- **Why:** The FADT parse landed in entry #025 without a consumer —
  exactly the kind of "primitive built but not wired in" pattern
  the anti-bloat guidelines flag. Landing `KernelReboot` closes
  the loop: the first ACPI consumer is now a real, callable
  reboot path, and the fall-back chain covers the handful of
  failure modes that would otherwise leave us stuck (firmware
  without RESET_REG_SUP, chipsets that ignore ACPI reset on boot-
  era state, broken 8042 emulation). The triple-fault fall-back
  is the "physics doesn't lie" exit — a CPU cannot ignore a
  #DF + #DF + reset chain.
- **Rules out / defers:** Clean shutdown (stop-all-tasks → flush
  caches → sync filesystems → enter ACPI S5). S5 needs AML — the
  DSDT / SSDT interpreter we punted on in #012. Power-off (S5) as
  a distinct path from reset. Graceful PCI-device teardown before
  reset. Reboot-reason reporting in the log (warm reset vs. panic
  vs. user-triggered).
- **Revisit when:** First shutdown request from user-space
  arrives (syscalls land). Panic path wants to optionally reboot
  instead of halt (useful for automated CI reboots after a crash
  on real hardware). AML support lands — then this module gains
  a sibling `KernelPowerOff()` that enters S5.
- **Related tracks:** Track 2 (Platform — reset), Track 13
  (Security — crash-reboot loop is part of the recovery posture).

---

## 028 — Condition variables (drop-mutex-and-block)

- **Scope:** `kernel/sched/sched.{h,cpp}` — new `Condvar` struct,
  `CondvarWait`, `CondvarSignal`, `CondvarBroadcast`; extracts
  internal `WaitQueueWakeOneLocked` helper
- **Decision:** Land the classic producer/consumer primitive on
  top of the existing `Mutex` + `WaitQueue` foundations. The
  subtlety is atomicity: `CondvarWait` splices the mutex hand-off
  AND the self-enqueue onto `cv->waiters` under a single
  `g_sched_lock` hold, so a signal that races the release cannot
  slip through the crack. The mutex hand-off inlines
  `WaitQueueWakeOneLocked` on `m->waiters` (FIFO fairness,
  identical to `MutexUnlock` except callable with the scheduler
  lock already held). On wake the caller re-acquires via the
  standard `MutexLock` path — possibly fast (mutex free) or slow
  (blocks on `m->waiters` again).
- **Why:** Entry #011 deferred "Condition variables (drop-mutex-
  and-block atomically)" as a separate slice after the sleep /
  wait / mutex primitives. With the timed-wait primitive in from
  entry #026 and the locked-wake helper now factored out, the
  remaining work is genuinely just the glue — and condvars
  remove a whole class of awkward polling patterns from the
  driver surface. Landing it standalone means the first driver
  that needs the pattern doesn't also have to design it.
- **Rules out / defers:** Timed condvars (`CondvarWaitTimeout`) —
  trivial follow-up on top of `WaitQueueBlockTimeout`, but no
  consumer yet. Priority-donation on condvar wake (requires
  priorities). Cancellation / interruption of a condvar wait
  (needs the "cancel this blocked task" primitive, which lands
  with the first syscall that takes signals).
- **Revisit when:** First driver that needs "wake me when a
  guarded queue is non-empty" semantics. First syscall that
  carries a signal (cancellation extends both condvar and wait-
  queue blocking to `bool was_cancelled` returns). Priority
  inheritance lands (the companion `Mutex` grows PI, and condvar
  wake order honours priority).
- **Related tracks:** Track 4 (IPC / synchronisation), Track 6
  (Drivers — consumer).

---

## 027 — PS/2 8042 controller init sequence

- **Scope:** `kernel/drivers/input/ps2kbd.cpp` (new `ControllerInit`,
  `WaitInputClear`, `WaitOutputFull`, `SendCtrlCmd`, `SendCtrlData`,
  `ReadConfigByte`, `WriteConfigByte`, `Drain` helpers)
- **Decision:** Replace the bare "drain leftovers and hope" startup
  with a full 8042 bring-up: disable both channels, flush, self-test
  the controller (`0xAA` → `0x55`), test port 1 (`0xAB` → `0x00`),
  enable port 1, turn on port-1 IRQ + clock in the config byte, drain
  again. Controller self-test mismatch panics (Class A — the keyboard
  is on the critical path for any interactive console); port-1
  interface-test failures log a warning and continue (QEMU always
  passes, but real-hardware boards can flag this falsely). Every
  response wait has a bounded spin limit (~10 ms) and panics on
  timeout rather than stalling forever.
- **Why:** Entry #014 deferred "No 8042 reset / init sequence;
  trusts the firmware to have left the controller in a usable
  state." The trust assumption holds for QEMU but is fragile on
  real machines — boards ship with the controller in various
  post-BIOS states (port 2 still enabled, translation off, IRQs
  masked). Landing an explicit init makes the driver portable to
  real hardware without changing the IRQ / translator code downstream.
- **Rules out / defers:** Scan-code-set configuration via device
  command (`0xF0 0x01`) — still relying on firmware default of set 1
  + translation. Keyboard device reset (`0xFF` on port 1 data —
  some firmware leaves the device in a weird state; the OSDev wiki
  recommends it, but QEMU's ACK sequence is flaky and we don't need
  it today). Port 2 / aux channel enable (no mouse support yet).
  Typematic rate configuration. 8042 USB-legacy-mode detection (real
  hardware sometimes routes USB HID through the 8042 emulation; we
  treat it as "it works or it doesn't").
- **Revisit when:** First real-hardware boot with a chipset that
  ships the 8042 in an unusual state. USB HID stack lands (might
  then actively DISABLE the 8042 legacy path to avoid dual IRQs).
  Aux channel / mouse support (reuse the SendCtrl helpers for port
  2 commands).
- **Related tracks:** Track 6 (Drivers — input).

---

## 026 — Timed WaitQueue blocking (WaitQueueBlockTimeout)

- **Scope:** `kernel/sched/sched.{h,cpp}` — new public
  `WaitQueueBlockTimeout`, internal `SleepqueueRemove` and
  `WaitQueueUnlink` helpers, Task struct grows `sleep_next`,
  `waiting_on`, `wake_by_timeout`
- **Decision:** A task that calls `WaitQueueBlockTimeout(wq, ticks)`
  parks on the wait queue AND the sleep queue simultaneously.
  Whichever wake path fires first unlinks the task from the other
  list and resumes it; the return value tells the caller which
  won (`true` = explicit wake, `false` = timeout). The two
  intrusive queues use different Task fields (`next` for runqueue /
  waitqueue / zombie; `sleep_next` for sleep queue) so the same
  Task can sit on both without pointer aliasing. `waiting_on` is a
  back-pointer the timer path uses to unlink from whatever wait
  queue the task was on. `wake_by_timeout` is a transient flag —
  set by the timer path, cleared by the wake path, read once by
  the waiter the moment `Schedule()` returns.
- **Why:** Entry #011 deferred "Timed waits on `WaitQueue`" as a
  separate slice after the sleep + wait + mutex primitives
  landed. Closing it now unblocks the first tractable driver
  retry pattern (command-completion wait with timeout: "wait for
  this transfer to complete, but give up after 100 ms") and is
  the last scheduler primitive needed before the recovery
  Class-D retry helper has a way to block a caller for a bounded
  interval. Implementation lands the API before the first caller
  so the consumer doesn't have to co-design the sleep/wait
  coupling; that's the same pattern we used for `AcpiReset`
  (entry #025) and `SchedStartIdle` (entry #023).
- **Rules out / defers:** Condition variables (drop-mutex-and-
  block atomically — the recipient still owns the lock on wake).
  Cancellable blocking (external cancel from another task).
  Tick-precision accuracy better than ±1 tick (the timer fires on
  a 10 ms grid; deadlines between ticks round up). Mixing
  `WaitQueueBlock` and `WaitQueueBlockTimeout` readers on the
  same queue works — waiters don't know or care — but the
  timeout path only cleans up its own waiter.
- **Revisit when:** First driver `RetryWithBackoff` caller (uses
  the timeout as its per-attempt budget). First I/O command with
  hardware-completion wait (xHCI, AHCI, NVMe). Condition variable
  primitive lands (drops-mutex-and-blocks using the same wait-
  queue plus timeout machinery as its foundation).
- **Related tracks:** Track 2 (SMP — timed waits will need
  spinlock-protected list ops once the scheduler spinlock goes
  live across context switch), Track 6 (Drivers — consumer).

---

## 025 — FADT parse + AcpiReset() reboot primitive

- **Scope:** `kernel/acpi/acpi.{h,cpp}` — new FADT struct,
  `ParseFadt`, `SciVector()`, `AcpiReset()`
- **Decision:** Extend `AcpiInit` to locate the FADT (FACP
  signature), checksum-validate it, and cache the three fields we
  actually use: `RESET_REG`, `RESET_VALUE`, `SCI_INT`. FADT is
  OPTIONAL — a missing one leaves reset unsupported and SCI at
  the ACPI-default ISA IRQ 9, rather than panicking like MADT
  does. Expose `AcpiReset()` that writes the reset value to the
  reset register when supported (I/O address space only —
  memory-mapped reset is legal per spec but unused on x86 PCs;
  add when a real machine demands it). Returns `false` on "no
  FADT / register unsupported / MMIO space" so the caller can
  fall back to `Outb(0xCF9, 0x06)` or a triple fault.
- **Why:** Entry #012 deferred "FADT, MCFG, HPET, SRAT etc. are
  untouched. Add a dispatcher when a consumer needs one." FADT
  in particular is the cheapest to land and unlocks a genuinely
  useful kernel primitive: a firmware-defined reboot. Today we
  have no way to restart the machine other than triple-faulting
  it, which is an ugly signal on a real board. `AcpiReset()`
  gives us a clean one. The SCI vector cache is a side benefit
  — power-management events (thermal, battery, lid close on
  laptops) fire on this line; caching it lets a future ACPI
  interrupt handler install itself at the right place without
  another FADT parse.
- **Rules out / defers:** PM1a/PM1b event/control block parsing
  (entering S-states requires AML — DSDT/SSDT — for the SLP_TYP
  values). GPE block parsing. HPET (still untouched). MCFG /
  PCIe ECAM (the next most-wanted one; sizes the PCI space and
  unlocks MSI-X configuration-space access without port IO).
  SRAT / NUMA topology.
- **Revisit when:** First shutdown / reboot path lands (use
  `AcpiReset` as the primary, `Outb(0xCF9, 0x06)` as fallback).
  PCI enumeration switches from legacy port IO to ECAM (needs
  MCFG). High-precision-timer consumers arrive (HPET). Power-
  management work starts (SCI handler installs on the vector
  `SciVector()` returns; full S-state support then needs an AML
  interpreter).
- **Related tracks:** Track 2 (Platform — shutdown/reboot),
  Track 13 (Power management).

---

## 024 — PS/2 keyboard: scan code set 1 → ASCII translator + modifier tracking

- **Scope:** `kernel/drivers/input/ps2kbd.{h,cpp}` (adds
  `Ps2KeyboardReadChar`, keymap tables, modifier state),
  `kernel/core/main.cpp` (`kbd-reader` task now prints resolved
  characters instead of raw scan bytes)
- **Decision:** Layer an in-driver ASCII translator on top of the
  existing raw byte ring without replacing it. The IRQ path and the
  raw `Ps2KeyboardRead` API are unchanged — any future consumer that
  needs set-2 decoding, a debugger-side view, or an alternate keymap
  keeps access to un-translated bytes. The new `Ps2KeyboardReadChar`
  drains scan codes in task context, handles break (`0x80 | make`)
  vs make bytes, tracks LShift / RShift (press + release edges) and
  Caps Lock (press-to-toggle, release ignored), and consumes
  0xE0-prefixed extended scans (arrows, right-side mods) silently.
  Only returns on a real press that resolves to a printable US
  QWERTY character; letters XOR shift and caps lock, number-row and
  symbols respect shift alone.
- **Why:** Entry #014 ("PS/2 keyboard as the first end-to-end IRQ-
  driven driver") explicitly deferred "scan-code-to-keysym
  translation, modifier tracking" as a separate slice so the IRQ
  plumbing commit stayed focused on the pipeline itself. With the
  pipeline verified, closing that slice is the tractable next step:
  translator logic is small (~100 lines), has no new dependencies,
  and upgrades the boot log from "meaningless hex bytes" to "what
  the user actually typed" — a real diagnostic improvement.
  Keeping the raw API preserves optionality for a future input
  layer / compositor event stream that wants modifier bitmaps
  rather than pre-resolved chars.
- **Rules out / defers:** Ctrl / Alt / Meta chord reporting (the
  state isn't tracked yet; would require a new `KeyEvent { char,
  modifiers }` API rather than a bare `char` return). Extended-key
  reporting (arrows, Home/End, PageUp/PageDown — all 0xE0-prefixed,
  all dropped today). Alternate layouts (AZERTY, Dvorak). 8042
  scan-code-set configuration (we rely on firmware default = set 1
  with translation enabled). Key-repeat rate tuning. Multi-reader
  safety on `Ps2KeyboardReadChar` (state is per-driver, not per-
  reader — two concurrent readers would race on modifier state).
- **Revisit when:** The first interactive shell lands (needs Ctrl-C,
  Ctrl-D, arrow keys — promotes the API to `KeyEvent`). A non-US
  keymap is requested (adds a layout-selection indirection on top
  of the scan-code → keysym step). USB HID stack lands (HID
  usages → the same higher-level API, so whatever shape we pick
  here is reused). Compositor input routing begins (event stream
  replaces pull-reader model).
- **Related tracks:** Track 6 (Drivers — input), Track 9 (Windowing
  — eventual input source for the compositor).

---

## 023 — Dedicated per-CPU idle task + batched zombie reaping

- **Scope:** `kernel/sched/sched.{h,cpp}` (new `SchedStartIdle`,
  internal `IdleMain`, drained-list reaping), `kernel/core/main.cpp`
  (spawn `idle-bsp` immediately after `SchedInit`)
- **Decision:** Retire the "boot task is the fallback idle" pattern.
  `SchedStartIdle(name)` spawns a dedicated kernel thread that loops
  on `sti; hlt` forever and participates in the regular round-robin
  runqueue. The BSP calls it right after `SchedInit`, before any
  other task creation, so `Schedule()` always has at least one
  `Ready` member to pick even when the boot task (or any driver
  thread) blocks on a WaitQueue / sleep queue. Separately, the dead-
  task reaper now detaches the entire zombie list in one CLI section
  and frees the whole batch with interrupts enabled — avoiding the
  per-task wake→free→block→wake round trips that the v0 reaper took
  on a burst of exits.
- **Why:** The old layout tolerated an empty runqueue only because
  the boot task stayed `Running` while everything else slept. The
  moment `kernel_main` called `SchedSleepTicks` (first occurrence:
  `SmpStartAps`'s INIT→SIPI delay), worker-creation order became
  load-bearing for whether `Schedule()` would panic with "no
  runnable task available". A dedicated idle task moves that
  invariant out of the boot sequence and into the scheduler itself.
  It also matches what every AP will need on bring-up — each AP
  calls `SchedStartIdle("idle-apN")` from its own entry, so the
  primitive lands once and serves both sides. Batched reaping was
  explicitly flagged as a two-line win in entry #020 ("we do one
  per wake — 2 lines to batch when it becomes a hot path"); since
  both changes touch `sched.cpp` they land together rather than
  separately.
- **Rules out / defers:** Idle-task priority / CPU-accounting
  (round-robin puts it in rotation with everything else — fine for
  v0, where `hlt` releases the CPU to the next IRQ anyway).
  Per-CPU idle wiring for APs (the hook exists; actually calling
  it from AP entry lands alongside the broader scheduler SMP
  refactor). Reaper batching ceiling / rate limiting (v0 drains
  unboundedly, matching the single-shot behaviour it replaces).
- **Revisit when:** Priorities / classes land (idle becomes `IDLE`
  class, never picked if any other task is `Ready`). SMP AP entry
  wiring (each AP calls `SchedStartIdle` with its CPU index in the
  name). Profiles show reaper pause time dominating a burst-exit
  workload (cap the drain per wake and re-arm `g_reaper_wq`).
- **Related tracks:** Track 2 (SMP — AP entry reuses the idle
  primitive), Track 4 (Process model — priorities + CPU accounting
  retire the round-robin rotation).

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
