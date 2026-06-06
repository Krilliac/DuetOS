# DuetOS — Design Decisions Log

_Last updated: 2026-05-12 (skeleton Rust crates lifted to production)_

The most recent formal entries below run through 042 (HPET self-test);
slices that landed during 2026-04-25 → 2026-05-04 (windowing / GDI /
USB / network / DirectX / wireless control tier / FS-write rate guard /
crash-dump minidump / GDB server / desktop apps / build flavours / DMA
coherent / account-system v1 / etc.) are summarised in the
[`History`](../getting-started/History.md) timeline and tracked
subsystem-by-subsystem in their owning wiki page. New formal entries
get appended here when a decision genuinely rules out an alternative
the next slice could otherwise pick.

## Purpose

A **living, append-only log** of concrete design decisions made during
implementation. Each entry records what was chosen, why, what it rules
out, and **a "revisit when X" marker** so the decision can be refined
once downstream context arrives (e.g. SMP, userland, first real
peripheral).

This is a companion to:

- `security-malware-hard-stop-plan.md` — the security posture we're
  building toward.
- `smp-ap-bringup-scope.md` — the staged plan for finishing SMP.
- `runtime-recovery-strategy.md` — halt/restart/retry/reject taxonomy
  every fault path defers to.

The entries here are the **ground truth of what actually shipped**.

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

- **Scope:** [Runtime Recovery Strategy](../security/Runtime-Recovery.md)
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

## 126 — HDA verb-encoding fix + ConfigureOutputPath stitched bring-up

- **Scope:** `kernel/drivers/audio/hda.{h,cpp}` (new
  `EncodeVerb16` for the 4-bit-verb / 16-bit-payload form;
  `IssueVerbAndPoll16` wraps it through CORB / RIRB;
  `IssueVerbRawAndPoll` factored out for reuse;
  `CodecSetConverterFormat` and `CodecSetAmpGainMute` switched
  from the truncated 12+8 form to the proper 4+16 form;
  new `ConfigureOutputPath` stitches the five-verb DAC →
  amp → pin → stream-tag sequence; new
  `kAmpPayloadSetOutBothMid` / `kPinPayloadOutputEnable`
  defaults; `VerbEncodingSelfTest` exercises both encoders).
  `kernel/core/main.cpp` (added the boot self-test invocation
  + `drivers/audio/hda.h` include).
- **Decision (encoding):** keep `EncodeVerb` (12-bit-verb /
  8-bit-data) verbatim — it covers GET_PARAMETER and every
  other 12+8 verb the codec walker uses today. Add
  `EncodeVerb16` (4-bit-verb / 16-bit-payload) as a sibling
  rather than overloading the existing helper. Callers continue
  to pass verb12 in the `0x2NN` / `0x3NN` form (matches the
  numbering convention used throughout the file); the new
  encoder extracts the high nibble.
- **Why the encoding bug mattered:** SET_CONVERTER_FORMAT (verb
  0x2) and SET_AMP_GAIN_MUTE (verb 0x3) take 16-bit payloads.
  Pre-fix, only the low 8 bits reached the codec — meaning
  `CodecSetConverterFormat(format=0xABCD)` actually transmitted
  `format=0x00CD`. The format register is what tells the
  codec the sample rate / depth / channel count. Wrong format
  = the codec pulls the wrong number of bytes per frame =
  silence (or noise). Same story for amp gain.
- **Decision (ConfigureOutputPath):** ship the stitched
  sequence as one entry point so a "play system beep" caller
  doesn't have to know the verb order. Path selection
  (`dac_node`, `pin_node`) stays the caller's responsibility —
  picking the right DAC / pin pair needs codec-specific
  knowledge (Intel HDA codecs use widely different node
  numbering). Today the helper has no production consumer;
  the audio shell is the obvious first one.
- **Self-test:** verb-encoding self-test runs at boot and
  asserts canonical inputs round-trip correctly. Catches a
  future regression in either encoder before any real codec
  sees a malformed verb. Cheap (no MMIO, no DMA, no codec
  required).
- **Rules out / defers:** Real DMA buffer allocation +
  populating a BDL with sample data + flipping RUN + observing
  samples land at a codec — needs `mm::AllocDmaCoherent` calls
  threaded through the audio shell (or a system-beep
  driver) and QEMU's `-device hda-output` for byte-level
  verification. Path selection ("find a working speaker pin")
  defers to a workload that wants automatic configuration; the
  audio shell can drive `ConfigureOutputPath` with manually
  chosen nodes in the meantime.
- **Revisit when:** A workload calls `ConfigureOutputPath`
  (system beep, Settings volume slider preview, audio shell
  test-tone) — at that point the BDL allocation + RUN bit
  toggle + signal generator slot in alongside.
- **Related tracks:** Track 5 (Drivers — audio).

---

## 125 — NUMA-aware page allocator

- **Scope:** `kernel/acpi/srat.{h,cpp}` (subtype-1 Memory Affinity
  record decode + `MemoryRange` struct + `SratMemoryRangeCount`
  / `SratMemoryRange` accessors; remap path shared with the
  existing CPU-affinity walk so dense-node indices stay
  consistent across both tables). `kernel/mm/frame_allocator.{h,cpp}`
  (per-node frame ranges built from SRAT in
  `FrameAllocatorBuildNumaRanges`; `BitmapFindFreeInRange` +
  `NumaNodeRange` + `CurrentCpuNumaNode` helpers; new
  `AllocateFrameNode(node)` API; `AllocateFrame` routes through
  `AllocateFrameNode(CurrentCpuNumaNode())` on NUMA boots,
  preserves the verbatim global linear-scan path on UMA;
  shared `ProcessAndReturnFrame` tail covers the kernel-PT
  guard + zeroing + per-node hint round-robin;
  `FrameAllocatorNumaSelfTest` smoke test). `kernel/core/main.cpp`
  (calls `FrameAllocatorBuildNumaRanges` immediately after
  `AcpiInit` returns + the new self-test).
- **Decision:** Keep the bitmap a single global structure. The
  NUMA bias is a *search-start position*, not a separate per-
  node allocator. The calling CPU's local node has first dibs
  on its memory-affinity range; on local-node OOM the search
  falls through to the global linear scan. UMA boots (no SRAT)
  see the historical path byte-for-byte: `g_numa_node_count == 0`
  short-circuits the NUMA path entirely.
- **Why hint-only over per-node bitmaps:** per-node bitmaps
  would force the firmware-reported memory ranges to be the
  ground truth for every allocator-visible frame. They aren't —
  some firmware reports overlapping ranges, some leaves MMIO
  holes inside an "available" range, and our reservation pass
  (kernel image, Multiboot info, bitmap-self) crosses node
  boundaries on multi-socket systems. A unified bitmap lets
  the existing reservation logic stay verbatim; the per-node
  hint only changes WHERE the search starts.
- **Multi-range nodes:** stored as the union span (min-base,
  max-end) per node. Allocations near the node's "edge" can
  pick frames that aren't strictly inside one of the affinity
  ranges, but they're inside the union — close enough for
  locality bias. Strict per-range scanning is a follow-on if
  a workload exposes the inefficiency.
- **Lifetime:** `FrameAllocatorBuildNumaRanges` runs once after
  `AcpiInit` (which calls `SratInit` internally). Re-callable —
  resets the per-node table at the head. Idempotent on the
  same SRAT.
- **Owner-pointer / cycle concern:** none. The frame allocator
  reaches into `cpu::TopologyForCpu(CurrentCpuIdOrBsp())` per-
  call to find the local node. `TopologyForCpu` is a plain
  array read after `TopologyInitBsp` returns; safe from any
  context. The cost is one extra indexed read per
  `AllocateFrame`, well below the bitmap-scan cost on a
  populated pool.
- **OOM-injection harness:** `g_fail_after` consumed inside
  `AllocateFrameNode` so existing tests (loader-unwind in
  `diag/robustness_selftest.cpp`) drive the same OOM ladder
  as before — the NUMA bias is invisible to the test scaffold.
- **Rules out / defers:** Per-node free counters / explicit
  "interleave" / "remote-only" allocation policies — they're
  larger surface changes that need a workload calling for
  them. Strict per-range scanning (vs union span) — same
  reasoning. Migrating long-lived allocations across nodes —
  v0 frames don't move once handed out.
- **Revisit when:** a multi-socket workload demonstrates
  remote-allocation cost in a profile, or the firmware
  surfaces multi-range nodes whose union spans cross another
  node's range. At that point per-range scanning + per-node
  hint round-robin earn their complexity.
- **Related tracks:** Track 1 (Kernel — memory management),
  Track 2 (Kernel — SMP / NUMA topology).

---

## 124 — HID descriptor-driven mouse decoding (high-DPI 16-bit XY)

- **Scope:** `kernel/drivers/usb/hid_descriptor.{h,cpp}` (new
  `HidMouseField` + `HidMouseLayout` structs;
  `HidExtractMouseLayout` walker tracking Local Usage list +
  Logical Min sign + Report ID + bit cursor across Mouse
  Application collections; new self-test descriptor
  `kHighDpiMouseDescriptor` + four new `ExpectEq` blocks).
  `kernel/drivers/usb/xhci_input.cpp` (new
  `HidMouseInjectWithLayout` extracting fields at bit
  offsets + sign-extending signed axes; `ExtractBitsLE` /
  `SignExtend` helpers). `kernel/drivers/usb/xhci_internal.h`
  (`HidMouseInjectWithLayout` decl; `DeviceState` grew
  `hid_mouse_layout_valid` + `hid_mouse_layout` fields).
  `kernel/drivers/usb/xhci_init.cpp` (polling loop dispatches
  layout-aware path when valid; 16-byte buffer cap when
  layout is in use, 8-byte fallback for boot protocol).
- **Decision:** Parser produces a flat `HidMouseLayout` rather
  than a `Field[]` table. The well-known mouse fields (X / Y
  / wheel / horizontal tilt / buttons / report ID) are a
  fixed, finite set; an array shape would force every
  consumer to scan it. Direct-named slots stay O(1) for the
  inject hot path.
- **Why now:** the parser side was the heavy lift — bit-level
  walking with Logical Min sign tracking and Local Usage list
  reset semantics matches HID spec §6.2.2 verbatim. Hardware-
  fetch wiring (GET_DESCRIPTOR(Report)) is a few-line follow-on
  best validated against a real high-DPI mouse, which the test
  fleet doesn't have today. Landing the parser + injector with
  a synthetic 5-button / 16-bit-XY / wheel / AC-Pan self-test
  proves the byte-level decode and unblocks the wiring slice
  whenever a real device shows up.
- **Layout-aware vs boot-protocol:** the polling loop branches on
  `dev.hid_mouse_layout_valid`. Today the layout slot is
  always invalid (no fetch); the boot-protocol path stays
  the runtime default and every existing mouse path is
  byte-for-byte unchanged. The first commit that wires the
  fetch flips the boolean per-device, with no global behaviour
  change for boot-protocol-only devices.
- **MousePacket coverage:** vertical wheel (`dz`), buttons 1..5
  (`kMouseButtonLeft / Right / Middle / Button4 / Button5`),
  and signed X / Y deltas all flow through. Horizontal tilt /
  AC Pan is parsed but discarded — `MousePacket` has no
  horizontal-scroll field today; the layout's
  `h_tilt.present` flag is preserved so a future MousePacket
  expansion can pick it up.
- **Rules out / defers:** Digitizer / absolute-pointer
  decoding (the layout extractor refuses non-Mouse primary
  kinds; touch panels live in a separate Application
  collection). Multi-collection mice (some gaming mice expose
  multiple Application collections — keyboard mode + mouse
  mode); we capture the first Mouse collection only.
  GET_DESCRIPTOR(Report) fetch wiring stays a follow-on,
  gated on a real high-DPI mouse in the test fleet.
- **Revisit when:** a workload (or test-fleet hardware) needs
  digitizer events; or a mouse legitimately switches modes
  via a non-first Application collection; or
  `MousePacket` grows a horizontal-scroll field.
- **Related tracks:** Track 5 (Drivers — USB).

---

## 123 — VFS Stage 6 finish: cross-mount `VfsResolve` + `VfsNode`

- **Scope:** `kernel/fs/vfs.{h,cpp}` (new `VfsBackend` enum,
  `VfsNode` tagged-storage struct + accessors `VfsNodeIsValid`,
  `VfsNodeIsDir`, `VfsNodeIsFile`, `VfsNodeSize`; new
  `VfsResolve(root, path, path_max) -> VfsNode` walker;
  `VfsResolveCrossMountSelfTest()` exercising a real `/disk/0/HELLO.TXT`
  resolution post-FAT32-auto-mount). `kernel/fs/mount.{h,cpp}`
  (new `VfsBackendLookupFn` + `VfsBackendOps` vtable +
  `VfsBackendForFsType`; `Fat32Lookup` adapter wraps
  `Fat32LookupPath` into a vtable entry). `kernel/core/main.cpp`
  (new `DUETOS_BOOT_SELFTEST(VfsResolveCrossMountSelfTest())`
  immediately after FAT32 auto-mount, before the routing self-test).
- **Decision:** Add a sibling `VfsResolve` API that returns a
  generic backend-tagged `VfsNode` rather than changing
  `VfsLookup`'s `RamfsNode*` signature. The existing `VfsLookup`
  callers (sandbox enforcement against `Process::root`,
  syscall path resolution) keep their narrow ramfs-only contract
  — none of them are equipped to handle a FAT32 entry today.
  New callers that legitimately want to cross a mount point
  (the kernel shell's `cd /disk/0/SUB`, future generic
  `stat`/`open`/`readdir` syscalls that go through one
  resolver) opt into the broader API. Backend dispatch lives
  on a per-FsType vtable in `mount.cpp`; FAT32 is wired today,
  Ext4 / NTFS slots return nullptr until a backend ships.
- **Why:** Dual signatures avoid a fleet-wide refactor of every
  existing `VfsLookup` caller. The constinit ramfs trees,
  sandbox roots, and "is this path inside the jail" checks all
  rely on the `RamfsNode*` shape; rewriting them to handle a
  tagged union when none of them cross mount points would be
  pure churn. Adding `VfsResolve` separately gives the cross-
  mount story a real home and matches the original Stage 6
  plan's "per-FS-type lookup vtable" sketch.
- **Mount-registry semantics:** Ramfs mounts in the registry are
  IGNORED by `VfsResolve` (the dispatcher only fires on non-
  ramfs `FsType`s). The explicit `root` argument stays
  authoritative for the ramfs view, so a sandbox root keeps
  its jail invariant even when the global namespace has a
  ramfs entry registered. Relative paths (no leading slash)
  always go through the ramfs walker — the mount registry is
  a global-namespace facility and relative paths are anchored
  to the caller, not to `/`.
- **VfsNode storage:** `VfsNode` carries the FAT32 entry by
  value (snapshot copy mirroring `Fat32LookupPath`'s caller-
  owned-out shape), so callers don't have to track lifetime
  against any backend's internal table. Ramfs nodes stay as
  pointers into `.rodata` — the constinit trees outlive every
  caller. The struct is fixed-size; future backends can add a
  union arm without breaking ABI inside the kernel.
- **Self-test wiring:** Two layers cover the resolver. The
  in-place `VfsSelfTest` (Phase::Vfs, before FAT32 probe) runs
  the ramfs-fall-through, sandbox-jail-survives-VfsResolve,
  and `..` rejection cases. `VfsResolveCrossMountSelfTest`
  runs after FAT32 auto-mount (when `/disk/0` is in the mount
  registry pointing at a real volume) and asserts the FAT32-
  backend dispatch end-to-end against the seeded HELLO.TXT.
  SKIPs gracefully on volumes-less boots so QEMU runs without
  a disk image stay no-op.
- **Rules out / defers:** Migrating `Process::root` to a
  `VfsNode` (so a sandboxed process can be rooted in a non-
  ramfs subtree) — `Process::root` stays a `const RamfsNode*`
  for v0; today every process root is ramfs by construction.
  A unified `open`/`stat`/`readdir` syscall surface that takes
  a `VfsNode` instead of routing-layer-specific `Win32FileHandle`
  / `LinuxFd` slots — that's a much bigger refactor, gated on
  a workload that wants per-process jails on FAT32 subtrees.
  Removing the legacy "/disk/<idx>" parser fallback in
  `routing::ParseDiskPath` — kept for boots where auto-mount
  hasn't run yet (fault-domain restart cleared the registry,
  early callers).
- **Revisit when:** A workload wants to sandbox a process under
  a FAT32 subtree (e.g. running a PE image with its rootfs
  pinned to `/disk/0/SANDBOX/`). At that point the syscall
  layer's `VfsLookup`-against-`Process::root` calls migrate
  to `VfsResolve`, and `Process::root` grows from a
  `RamfsNode*` to a `VfsNode` carrying the appropriate
  backend.
- **Related tracks:** Track 3 (Storage / FS), Track 1 (Kernel —
  VFS abstraction).

---

## 122 — Dirfd (Linux state 11) on owner-aware KFile release

- **Scope:** `kernel/ipc/kfile.{h,cpp}` (new
  `KFileProcessRelease` typedef + `KFile::owner` +
  `KFile::release_pool_with_owner` fields + `KFileCreateWithOwner`
  ctor; `KFileDestroy` fires both the legacy and owner-aware
  releases; self-test grew a third round exercising the owner-
  aware shape with a sentinel `Process*`),
  `kernel/proc/process.{h,cpp}` (new helper
  `LinuxFdAttachKFileOwned` mirroring `LinuxFdAttachKFile` but
  taking `void(Process*, u32)`; `ProcessRelease` reorders
  HandleTableDrain to run **before** the `win32_dirs[]` sweep so
  dirfd KFile destroys can call `SysDirClose(p, ...)` on the
  still-live per-process table),
  `kernel/subsystems/linux/syscall_file.cpp` (DoOpen's directory
  branch attaches a KFile via `LinuxFdAttachKFileOwned` whose
  release adapter `DirfdReleaseOwnerAware(p, slot)` calls
  `SysDirClose(p, kWin32DirBase+slot)`; DoClose's legacy
  state==11 explicit-release arm is removed entirely — every
  fd kind that owns a per-pool ref is now on the unified
  KFile path),
  `kernel/subsystems/linux/syscall_clone.cpp` (comment refresh —
  dirfd is no longer "the lone hold-out").
- **Decision:** Add an owner-aware release-callback variant
  alongside the existing pool-only callback rather than
  promoting the entire `Win32DirHandle` snapshot onto KFile.
  KFile carries an optional `Process* owner` pointer set at
  attach time and pinned for the KFile's lifetime; the
  destroy callback fires `release_pool_with_owner(owner,
  pool_index)` which calls `SysDirClose(owner, slot)`. The
  win32_dirs[] table on Process stays the slot pool — Win32
  callers (FindFirstFile/FindNextFile/NtQueryDirectoryFile)
  keep using raw `kWin32DirBase + idx` handles unchanged, and
  Linux fds get a KFile sidecar that drives the same per-slot
  cleanup through KObject refcounting.
- **Why:** The roadmap offered two options ("a `void(Process*,
  u32)` callback variant in KFile, or promoting the directory
  snapshot itself onto KFile"). The variant is a 4-line struct
  delta + one new ctor + one rebuilt destroy branch; the
  promotion would touch `Win32DirHandle`, every `win32_dirs[]`
  consumer (SysDirOpenKernel/SysDirNext/SysDirRewind/SysDirClose,
  DoGetdents / DoGetdents64), and force the Win32 dir handle ABI
  through the KFile shape too. The variant is the smaller
  change and gets every Linux fd kind onto the unified handle
  table — the migration's actual goal — without dragging the
  Win32 ABI surface along for the ride.
- **Lifetime / cross-process safety:** dirfd never crosses
  processes — `pidfd_splice.cpp:207` refuses state 11 in
  `pidfd_getfd`, and `syscall_clone.cpp` (DoFork) closes every
  inherited dirfd slot in the child immediately after
  `LinuxFdInheritFromParent`. The owner pointer is therefore
  pinned to the same Process for every reference of every
  KFile. No `ProcessRetain` / refcount bump on the owner is
  needed; keeping the pointer non-owning avoids the cycle the
  full retain shape would introduce.
- **Process-exit ordering:** moved `HandleTableDrain` BEFORE
  the `win32_dirs[]` sweep in `ProcessRelease`. Drain fires
  every live KFile destroy (including dirfd's owner-aware
  release) while the per-process dir-slot table is still
  intact; the subsequent sweep only reaches slots that had no
  KFile sidecar (Win32-only FindFirstFile callers that exited
  without CloseHandle) and is idempotent — `entries == nullptr`
  short-circuits already-cleaned slots.
- **Rules out / defers:** Promoting the directory snapshot
  itself onto KFile (vnode + entries pointer with the
  `Win32DirHandle` slot pool eliminated) — still possible, but
  would need to either route Win32 raw handles through KFile
  too, or carry two parallel storage paths. Either is a bigger
  shape change than the migration needed. Cross-process dirfd
  sharing — still refused by `pidfd_splice` for the same
  semantic reason as before; the new KFile shape doesn't change
  that policy.
- **Revisit when:** A workload demonstrates a corner the slot-
  pool can't represent (per-fd dirent cursor needing >256
  entries / handle, dirfd that survives a fork on the child
  side, openat using a real dirfd as the base). At that point
  promoting the snapshot onto KFile + retiring `win32_dirs[]`
  becomes worthwhile because the slot-pool ceiling is the
  blocker, not the callback shape.
- **Related tracks:** Track 1 (Kernel — IPC + handle table),
  Track 4 (Linux subsystem — fd table + creators).

---

## 121 — kernel32 GetCommandLineA / W exports + tighten Lock* export list

- **Scope:** `userland/libs/kernel32/kernel32.c`
  (`GetCommandLineA`, `GetCommandLineW` exports backed by
  process-static empty-string buffers),
  `tools/build/build-kernel32-dll.sh` (export list grew the
  Lock*, GetCommandLine*, and *Ex names so the DLL's
  link-time export table actually contains them).
- **Decision:** GetCommandLine* return process-static empty
  strings (`""`, NUL only). v0 doesn't pass argv to PE
  binaries (`SpawnPeFile` takes no argument list); the Win32
  contract still mandates a non-null pointer to a
  caller-readable string for the program lifetime, so an
  empty terminator buffer is the smallest answer that lets
  CRT startup proceed without crashing on a null deref. The
  pointer is stable across the process's lifetime — same
  shape real Windows guarantees.
- **Why:** Fixes a follow-up bug from #120: I'd added
  LockFile / UnlockFile / *Ex bodies to `kernel32.c` but
  forgot to extend the explicit `/export:` list in the build
  script, so the DLL contained the code but not the entry-
  table. `objdump -p` now shows entries 230 (LockFile), 231
  (LockFileEx), 64 (GetCommandLineA), 65 (GetCommandLineW)
  in the canonical alphabetical order. File size stayed the
  same (512-byte alignment swallowed the growth).
- **Rules out / defers:** Real argv plumbing — when
  `SpawnPeFile` grows an argv parameter, this code reads
  from a per-process `Process::win32_cmdline_*` slot
  populated at spawn time (the `proc_env.h` layout already
  reserves the bytes; just no producer yet).
- **Revisit when:** First PE workload that wants real argv —
  most likely the `/APPS` PE-launch path (#115) when a
  manifest grows an `args=` field.
- **Related tracks:** Track 9 (Win32 — kernel32 surface),
  Track 7 (Userland — argv plumbing).

---

## 120 — kernel32 LockFile / UnlockFile / *Ex — stub-success exports

- **Scope:** `userland/libs/kernel32/kernel32.c` (new
  `LockFile`, `UnlockFile`, `LockFileEx`, `UnlockFileEx`
  exports).
- **Decision:** Add the four byte-range locking entry points
  with v0 stub-success bodies — they take no real lock but
  return TRUE so the caller proceeds. v0 has a single-process
  workload model and a single-writer FAT32 layer, so no two
  callers can race the same byte range; advisory locking has
  nothing to enforce yet. The Win32 surface wiki claimed
  these "return success without locking" but they were
  actually missing exports — a real PE that imported them
  would fail to load. This makes the wiki claim accurate and
  ensures future PE workloads that use LockFile see the
  contract the doc promises.
- **Why:** Bumps the kernel32 DLL from 46080 to 46592 bytes
  (~512 bytes of new export-table + body). Cost is negligible;
  unblocks a category of Win32 binaries that the loader
  previously rejected.
- **Rules out / defers:** Real per-file byte-range tracking
  (per-handle range table, contention-aware acquire). Real
  multi-user concurrency. SQLite-style mandatory locking.
  Returns success even on overlapping ranges from the same
  process — caller responsibility today.
- **Revisit when:** A second writer to the same FAT32 file
  becomes possible (multi-process write contention). A
  workload genuinely depends on advisory locking semantics.
- **Related tracks:** Track 9 (Win32 — kernel32 surface).

---

## 119 — Shell `lastdump` operator readout for the last minidump

- **Scope:** `kernel/shell/shell_storage.cpp` (`CmdLastdump`),
  `kernel/shell/shell_internal.h` (prototype),
  `kernel/shell/shell_dispatch.cpp` (dispatch + name).
- **Decision:** Add a `lastdump` shell command that reads the
  byte-buffer `AccessLastMinidump` exposes and prints
  size + the "MDMP" signature + version word. On QEMU the
  dump bytes egress via debugcon (port 0xE9) on every emit;
  on real hardware those writes go nowhere, so an in-system
  command that confirms a dump was emitted (and how big it
  was) is the only operator-facing surface that survives.
  Prints "no minidump emitted this boot" when
  `AccessLastMinidump` returns false.
- **Why:** Real-hardware crash diagnostics. Today the only
  way to see whether a minidump fired was to grep the serial
  log for `[minidump] emitting`; on a board without serial
  capture that log is invisible. `lastdump` reads the same
  static buffer the debugcon path emits so the operator
  always has a "did the dump happen" answer reachable from
  the shell.
- **Rules out / defers:** Writing the bytes to disk (the
  Roadmap's "Crash-dump persistence to disk" entry is still
  open — that's the FAT32 / reserved-LBA writer slice).
  Pretty-printing the ExceptionStream / ThreadList /
  ModuleList contents (each is a separate parser; deferred
  until an in-system debugger needs them).
- **Revisit when:** A reserved-LBA panic-time writer lands
  and `lastdump` grows a `--save` flag to copy the bytes
  to that LBA range from the post-boot operator session.
- **Related tracks:** Track 1 (Diagnostics), Track 11
  (Shell — operator commands).

---

## 118 — ReadFile dispatches by handle range (mirrors WriteFile)

- **Scope:** `userland/libs/kernel32/kernel32.c` (`ReadFile`).
- **Decision:** Mirror the WriteFile handle-range dispatch
  landed in #114:
  - Pipe sentinel (`DUETOS_PIPE_RD`) — drain the in-process
    pipe ring (existing path).
  - Std-handle range (0xFFFFFFF4..0xFFFFFFF6) — return
    `TRUE` + `*lpRead = 0` (Win32 EOF convention). STDIN has
    no kbd-read syscall yet; STDOUT / STDERR are write-only.
    The legacy fall-through called `SYS_FILE_READ` with the
    std-handle in `rdi`, which returned `-1` and surfaced as
    `FALSE` — semantically a read error. Returning EOF
    matches what real Win32 does on a closed STDIN pipe.
  - Anything else — `SYS_FILE_READ` (handles 0x100..0x10F
    work; the kernel rejects out-of-band handles with `-1`,
    surfaced as `FALSE`).
- **Why:** Symmetric with #114's WriteFile dispatch. Win32
  CRT startup commonly probes STDIN to size an input buffer;
  a `FALSE` return there used to confuse callers expecting
  the standard "no data" path. The 0-byte EOF return makes
  PE binaries' "read input until EOF" loops terminate
  instead of reporting an error and aborting.
- **Rules out / defers:** Real keyboard-backed STDIN reads
  (would need a SYS_STDIN_READ that drains the kernel's
  input-event queue). Async / overlapped reads. Read-side
  share-mode enforcement.
- **Revisit when:** A workload genuinely needs a STDIN that
  reads keystrokes (a userland REPL); add SYS_STDIN_READ +
  switch the std-handle branch over.
- **Related tracks:** Track 9 (Win32 — file syscall surface).

---

## 117 — Shell `mkfs` command on a writable block device

- **Scope:** `kernel/shell/shell_storage.cpp` (`CmdMkfs`),
  `kernel/shell/shell_internal.h` (prototype),
  `kernel/shell/shell_dispatch.cpp` (dispatch case + name in
  `kCommandSet[]`).
- **Decision:** Add a shell `mkfs` command with the
  signature `mkfs <handle-hex> ERASE`. Validates argv length,
  parses the block-device handle, asserts admin privilege,
  refuses unless the second arg is the literal `ERASE`
  confirmation token (the disk-installer plan's typed-
  confirmation contract for every DESTRUCTIVE primitive),
  checks `BlockDeviceIsWritable` + minimum 32 MiB sector
  count, calls `Fat32Format`, and confirms via a fresh
  `Fat32Probe` that the BPB came back. Failures log a one-line
  reason without further explanation — the operator typed
  ERASE; they can read a klog message.
- **Why:** Surfaces the existing `Fat32Format` primitive at
  the operator level. Before this slice the only way to
  exercise the FS format path was the boot self-test on a
  ramdisk; a real installer flow needs an interactive entry
  point. Admin-gated + `ERASE`-token-gated matches the
  pre-existing pattern for destructive operations (`READ`'s
  admin check, the in-flight installer plan).
- **Rules out / defers:** A full `mkfs.fat` flag set
  (`-F 32`, `-n LABEL`, `-c bad-block scan`, etc.) — single-
  flavour FAT32 today. GPT layout (`mkfs` writes a raw FAT32
  BPB to LBA 0 of the device, ignoring any partition table —
  matches what `Fat32Format` does). Per-partition formatting
  (operates on whole devices; carving partitions first goes
  through `GptInitDisk` + a future `mkpart` command).
- **Revisit when:** A real installer wizard lands and needs
  per-partition `mkfs`. Other FS flavours (ext4, NTFS) gain
  format support and the verb wants a `-t fstype` selector.
- **Related tracks:** Track 3 (Filesystem — installer
  primitives), Track 11 (Shell — admin commands).

---

## 116 — gpt::FormatGuid + corrected disk-installer Roadmap

- **Scope:** `kernel/fs/gpt.{h,cpp}` (new `kGuidStringLen`,
  `FormatGuid(guid, *out, cap)`), `kernel/shell/shell_storage.cpp`
  (`CmdLsgpt` switches to `FormatGuid`; also prints `DISK_GUID`,
  which it never did before), `wiki/reference/Roadmap.md`
  (corrected the "Disk installer" entry).
- **Decision:** Extract the canonical mixed-endian (8-4-4-4-12)
  GUID renderer the shell had open-coded into a public
  `gpt::FormatGuid` so other callers (a future installer wizard,
  GPT diagnostics, `gpt-info` shell command) don't recopy the
  byte-order table. The shell `lsgpt` output gains the disk's
  top-level GUID line — it's been in `Disk::disk_guid` since
  GptProbe parsed the header but no command surfaced it.
- **Why:** The Roadmap's "Disk installer" entry claimed GPT
  write and FAT32 mkfs were "blocks on" the installer; both
  primitives have actually been in tree since GptInitDisk and
  Fat32Format landed. The corrected entry makes the real gap
  ("orchestration layer + bootloader copy") legible to the next
  contributor instead of pointing them at code that already
  works. Extracting `FormatGuid` is the smallest sub-step that
  also eliminates a duplicated byte-order table.
- **Rules out / defers:** `ParseGuidString` (the inverse —
  installer wizard will need it once a user can type a GUID).
  Lowercase rendering (Microsoft + UEFI canon is uppercase; we
  match). Locale-aware separators (none needed).
- **Revisit when:** A user-typed GUID lands in a shell command
  (mkpart / installer); add `ParseGuid`. A non-canonical render
  (lower / no-hyphen) becomes load-bearing for diff readability
  in a future test fixture.
- **Related tracks:** Track 3 (Filesystem — disk installer
  building blocks).

---

## 115 — /APPS manifests can launch PE/ELF binaries from FAT32

- **Scope:** `kernel/drivers/video/start_menu_apps.{h,cpp}`
  (new `ShortcutKind` enum, `Slot::path`, `kPathCap`,
  `ParsedManifest`, `StartMenuAppsResolveLaunch`, extended
  parser + self-test), `kernel/core/main.cpp` (menu-action
  dispatch reads the file off FAT32 and calls `SpawnPeFile` /
  `SpawnElfFile`).
- **Decision:** Manifests can pick exactly one of two launch
  forms:
  - `target=<role>` — raise an existing app window (current
    behaviour, unchanged).
  - `kind=pe|elf` + `path=<fat32-path>` — read the binary
    bytes from FAT32 (8 MiB cap), KMalloc-stage them, and
    spawn via `SpawnPeFile` / `SpawnElfFile` with trusted caps
    + budget.
  Manifests that have neither directive are rejected (the
  legacy parser silently dropped them too; the new self-test
  asserts the rejection path). The action dispatcher in
  `main.cpp` resolves through `StartMenuAppsResolveLaunch`,
  which yields the kind + path; PE/ELF kinds skip the
  ThemeRole-raise block.
- **Why:** Closes the "PE/ELF launching from /APPS manifests"
  Roadmap item. Before this, manifests could only alias an
  already-built-into-the-kernel app — useless for users who
  drop a `.exe` onto disk. The kernel has had `SpawnPeFile`
  for embedded ramfs PEs since the loader landed; this slice
  just puts the FAT32-staging + dispatch glue in front of it.
  Trusted caps for v0 because the manifest writer is a local
  user; per-manifest cap fields are a follow-up.
- **Rules out / defers:** Per-manifest `caps=` /
  `frame-budget=` / `tick-budget=` fields (sandboxed
  manifests). Argv / env passthrough (manifests carry no
  `args=` field; would require `SpawnPeFile`'s argv shim from
  Roadmap entry #109's "First ring-3 program wants argv"
  trigger). Auto-detect ELF-Linux vs ELF-DuetOS-native
  (manifests pick explicitly via `kind=elf`; `kind=elf-linux`
  follow-up when needed). > 8 MiB binaries (KMalloc staging
  cap; mmap-backed staging is the next-bigger lift).
- **Revisit when:** A workload needs sandboxed launches from
  a manifest (drop the cap from Trusted to Sandbox + a
  per-manifest field). A real argv user shows up. ELF-Linux
  becomes a separate kind.
- **Related tracks:** Track 7 (Userland — launcher), Track 4
  (Process — spawn surface).

---

## 114 — WriteFile dispatches by handle range, not "always stdout"

- **Scope:** `userland/libs/kernel32/kernel32.c` (`WriteFile`).
- **Decision:** `WriteFile` now dispatches by the handle's
  numeric range:
  - Pipe sentinel (`DUETOS_PIPE_WR`, 0xA0010002) — push into
    the in-process anonymous-pipe ring (existing path).
  - Kernel file handle (0x100..0x10F, planted by `CreateFileW`
    via `SYS_FILE_OPEN` / `SYS_FILE_CREATE`) — `SYS_FILE_WRITE`
    (syscall 43). Cap-gated on `kCapFsWrite`; routes through
    the per-handle cursor + canary wall + FAT32 in-place-or-
    grow write landed in #111.
  - Std-handle range (0xFFFFFFF4..0xFFFFFFF6 — what
    `GetStdHandle(STD_OUTPUT/STD_INPUT/STD_ERROR_HANDLE)`
    zero-extends DWORD `(DWORD)-12..(DWORD)-10` into) —
    `SYS_WRITE(fd=1)` (existing console-write path).
  - Anything else — return `FALSE` with `*lpWritten = 0`. The
    legacy "all writes to stdout" fallback used to swallow
    bugs where a Win32 caller wrote to a stale handle.
- **Why:** Closes the only Roadmap item under "Arbitrary file
  writes through PE workloads." A Win32 PE that calls
  `CreateFileW("/disk/0/foo.txt") + WriteFile(...)` previously
  saw its bytes appear on the serial console rather than in
  the file. The kernel-side write path (canary wall, rate
  guard, in-place + grow write) was complete; this change
  routes the userland API to it.
- **Rules out / defers:** `OVERLAPPED` (async I/O completion
  ports — the current path is synchronous). Console-mode bit
  vs file-mode bit dispatch on handle attributes (we route by
  numeric range; Win32 normally tags handles internally but
  our pseudo-handles don't carry a flag word). Per-handle
  share-mode + access-mode enforcement (kernel layer doesn't
  read the `dwDesiredAccess` flag yet — `kCapFsWrite` is the
  whole story).
- **Revisit when:** A workload needs `OVERLAPPED` async writes;
  Winsock async surface lands and shares the completion-port
  scaffold. A second std-handle producer (e.g. forwarded child
  stdout) reuses the dispatch.
- **Related tracks:** Track 9 (Win32 — file syscall surface),
  Track 3 (Filesystem — write path).

---

## 113 — VFS mount registry routes Win32 file syscalls

- **Scope:** `kernel/fs/mount.{h,cpp}` (new
  `VfsMountResolve(path, *out_subpath)` longest-prefix resolver +
  4 self-test cases), `kernel/fs/file_route.cpp`
  (`ParseDiskPath` consults the resolver before falling back to
  the hard-coded `/disk/<idx>/...` prefix; new `fs/mount.h`
  include), `kernel/core/main.cpp` (auto-`VfsMount` every probed
  FAT32 volume at `/disk/<idx>` after the FAT32 self-test).
- **Decision:** The mount registry becomes the source of truth
  for the kernel's on-disk path namespace. `VfsMountResolve`
  walks the table for the longest-prefix match (component-aware
  — `/disk/0` won't match `/disk/01/foo`) and hands back the
  `MountEntry*` plus the in-mount sub-path. `ParseDiskPath` runs
  the resolver first; only a non-FAT32 hit OR a complete miss
  triggers the legacy prefix parse. FAT32 volumes are
  auto-mounted at boot so the registry is populated before the
  first `OpenForProcess` call. The hard-coded prefix path stays
  as a fallback for the (currently-unreachable) "boot before
  auto-mount" window — once Stage 6's third slice lands the
  ramfs-side `VfsLookup` rewrite, the fallback retires.
- **Why:** Closes the second of three sub-items under "Stage 6
  — VFS mount path" on the Roadmap. Without this, the mount
  registry was bookkeeping-only — every Win32 file syscall
  routed through a hard-coded `"/disk/"` prefix in
  `file_route.cpp`. Wiring the registry into `ParseDiskPath`
  means a future on-disk FS (NTFS read, ext4 read) only has to
  call `VfsMount` to be reachable from `OpenForProcess` /
  `WriteForProcess`; the routing layer doesn't grow per-FS
  branches. Component-aware longest-prefix match also unlocks
  nested mounts (e.g. binding a filesystem image at
  `/disk/0/IMAGES/foo.img` over the parent `/disk/0` FAT32).
- **Rules out / defers:** Returning a generic `VfsNode` from
  `VfsLookup` (still `const RamfsNode*`; that's the third
  Stage 6 slice). Stripping the legacy `"/disk/<idx>"` parse
  (kept as a safety net while only one FS type is mountable).
  Per-process mount namespaces (the registry is global; per-
  process roots remain `Process::root` ramfs handles).
- **Revisit when:** A second on-disk FS type ships and routes
  through the resolver. Per-process mount namespaces become a
  requirement (sandboxing). The ramfs-side VfsLookup grows a
  cross-FS handle so the legacy prefix parser can be deleted.
- **Related tracks:** Track 3 (Filesystem — VFS layer), Track 9
  (Win32 — file syscall routing).

---

## 112 — Extended-boot USB mouse: wheel + buttons 4/5

- **Scope:** `kernel/drivers/input/ps2mouse.h` (added `dz`,
  `kMouseButton4`, `kMouseButton5` to `MousePacket`),
  `kernel/drivers/usb/xhci_input.cpp` (`HidMouseInjectN(buf, len)`
  decoder; `HidMouseInject` now thunks through it),
  `kernel/drivers/usb/xhci_internal.h` (prototype),
  `kernel/drivers/usb/xhci_init.cpp` (residual-aware actual-length
  computation, replaced fixed 3-byte read), `kernel/core/main.cpp`
  (PS/2 reader path passes `p.dz` instead of hard-coded zero).
- **Decision:** Decode by report length rather than by fixed
  3-byte boot layout. The xHCI poller computes
  `actual = max_packet - residual` from the TRB completion and
  hands `[0..actual)` to `HidMouseInjectN`. Length-3 reports
  decode as boot protocol; length-4 adds the signed wheel byte;
  length-5+ adds buttons 4/5 from byte 0 bits 3/4. Reports
  shorter than 3 bytes are dropped; longer than 8 are clamped.
  The wheel field flows through the existing
  `MouseInputAccumulate` Win32 accumulator (which already
  accepted a `dz` argument).
- **Why:** Closes the "USB mouse beyond boot protocol" Roadmap
  item to the extent the existing parser supports. Most wheel
  mice without explicit `SetProtocol(boot)` ship 4-byte reports
  in the extended-boot layout (button + dx + dy + wheel) — the
  industry de-facto fallback for vendors that don't ship a
  full report descriptor. Decoding it gets us scroll + 5
  buttons without needing the parser to expose per-field
  offsets, which is a much bigger lift.
- **Rules out / defers:** 16-bit X / Y axes (high-DPI gaming
  mice), digitizer / absolute pointers, horizontal tilt as a
  first-class field. Those need `HidParseDescriptor` to track
  field offsets — today it sums Report Size × Report Count
  without recording position. The Roadmap entry now reads
  "high-DPI 16-bit XY" reflecting the smaller scope still
  open.
- **Revisit when:** A workload needs digitizer / absolute
  pointers, or a high-DPI mouse arrives in the test fleet
  whose 16-bit XY layout the extended-boot heuristic
  misreads.
- **Related tracks:** Track 6 (Drivers — USB HID), Track 9
  (Win32 — mouse-input accumulator).

---

## 111 — SYS_FILE_WRITE grows FAT32 files past EOF via Fat32WriteAtPath

- **Scope:** `kernel/proc/process.h` (new `fat32_path[64]` field
  on `Win32FileHandle`), `kernel/fs/file_route.cpp`
  (`CopyPathInto` helper, path stamping in `OpenForProcess` /
  `CreateForProcess`, `WriteForProcess` rewrite, updated
  self-test), `kernel/syscall/syscall.h` (doc comment).
- **Decision:** `WriteForProcess` now picks one of three paths
  based on the (cursor + len) range:
  1. `cursor + len <= file_size` → `Fat32WriteInPlace` (fast
     path, no parent-dir walk).
  2. Past-EOF AND the open-time path fit in the 64-byte cap →
     `Fat32WriteAtPath` grows the cluster chain and patches
     the dir-entry size.
  3. Past-EOF AND the path overflowed the cap → bounded
     in-place write up to current EOF, returns the short count
     (matches POSIX `ssize_t` semantics).
  After a growing write the cached `DirEntry` snapshot in the
  handle is refreshed from `Fat32LookupPath` so a follow-up
  `SeekForProcess(SEEK_END)` / `FstatForProcess` returns the
  new size. Self-test was inverted: the past-EOF case used to
  panic if the write succeeded; it now panics if the file
  doesn't grow.
- **Why:** Closes the only remaining sub-item under "Writable
  FAT32" on the Roadmap. Win32 `WriteFile` callers + shell
  redirect-append flows that wrote past EOF were silently short-
  written or rejected; with the cluster chain + dir-entry size
  patching reachable from the syscall surface, a real PE workload
  doing `fopen("a") + fwrite + fclose` actually appends. The path
  cap is set to 64 chars because the `Win32FileHandle` table is
  16 entries × per-process — 1 KiB total per process for the path
  cache, which fits cleanly in the existing process structure.
- **Rules out / defers:** Unbounded path length (paths over 63
  chars fall back to in-place + short-write — kernel-side
  `kSyscallPathMax` is 256, but most paths that hit this surface
  today are well under 64 chars). Storing the parent-cluster +
  basename instead of the path (would skip `ResolveParentDir` per
  call but bloats the handle and complicates rename semantics).
  Atomic overwrite-then-grow batching (every chunked write does
  a separate FAT-walk; batching lands when a profiler shows it).
- **Revisit when:** A workload regularly hits the >63-char path
  fallback; bump the cap or move to a per-process path arena.
  Rename-while-open lands and the cached path goes stale.
- **Related tracks:** Track 3 (Filesystem — write surface), Track
  9 (Win32 — `WriteFile` semantics).

---

## 110 — Driver fault-domain teardown for e1000 + fat32

- **Scope:** `kernel/drivers/net/net.cpp` (`E1000Quiesce` helper
  used by `NetShutdown`), `kernel/fs/fat32.{h,cpp}`
  (`Fat32Shutdown`), `kernel/core/main.cpp` (new `fs/fat32`
  fault-domain registration + lighter init lambda).
- **Decision:** `NetShutdown` now actually quiesces a brought-up
  e1000 — masks IRQs, clears IVAR routing, disables RX/TX,
  software-resets the chip, frees the descriptor rings + buffer
  pools, wakes any sleeper on the RX wait queue, then zeroes the
  context. `Fat32Shutdown` wipes the in-memory volume snapshot
  array under the driver-wide mutex. Both are wired into the
  fault-domain machinery via `RegisterDriverDomain`; the fat32
  init lambda re-walks `BlockDeviceCount()` calling `Fat32Probe`
  per handle (lighter than `Fat32SelfTest`, which has CRUD side
  effects). Brings the driver fault-domain count from 18 to 19.
- **Why:** Closes the only Roadmap item under "Driver
  fault-domain registration." Both subsystems were registered
  with no-op or registry-only teardowns; a real restart left
  hardware programmed with stale ring pointers (e1000) or the
  volume registry in a half-populated state (fat32). Without a
  proper quiesce, `RestartDriverDomain("drivers/net")` silently
  corrupted any subsequent `NetInit` because PCI re-walk found
  the same NIC but the e1000 context was already populated and
  `E1000BringUp` early-returned.
- **Rules out / defers:** MSI-X vector unbind + `IrqAllocVector`
  return — no `PciMsixUnbind` API exists yet, and leaving the
  handler installed is harmless because the device-side IMC
  mask + reset stops events. Per-NIC MMIO unmap (mapping arena
  is non-reclaiming today). Stopping the `e1000-rx-poll` task —
  task termination doesn't exist; the task observes
  `online == false` via `E1000DrainRx` and idles cheaply.
- **Revisit when:** First USB hot-swap path needs to restart
  xHCI + drag fat32 along (mount-point handling cascades from
  there). MSI-X unbind lands. Task termination lands and the
  RX-poll task can be torn down properly.
- **Related tracks:** Track 6 (Drivers — restart story), Track
  3 (Filesystem — mount lifecycle).

---

## 109 — SYS_SPAWN = 7 — ring-3 can spawn ring-3 from an ELF path

- **Scope:** `kernel/core/syscall.{h,cpp}` — new `SYS_SPAWN`
  enum value + dispatcher case. Gated on `kCapFsRead` (the
  same cap that lets a process name a file path in `SYS_STAT`
  / `SYS_READ`). `rdi` = user pointer to path, `rsi` = path
  length. Returns child pid on success, `(u64)-1` on failure.
- **Decision:**
  - Inherit the caller's caps + namespace root (POSIX
    fork+exec shape: "spawn from a path, same privileges
    down"). A child that needs lower privileges drops caps
    post-spawn via `SYS_DROPCAPS`, matching the existing
    deprivilege pattern.
  - Cap check is on `kCapFsRead` rather than a new
    `kCapSpawn` — the observable primitive is "the caller
    named a file path," which is exactly what `kCapFsRead`
    already gates in STAT/READ. Avoids cap-set inflation.
  - `VfsLookup` runs against `proc->root`, so a sandboxed
    caller can only spawn binaries reachable from its own
    namespace — matching the existing jail semantics.
  - Budgets (`kFrameBudgetTrusted`, `kTickBudgetTrusted`) are
    hard-coded for v0; differentiated budgets per child land
    when a use case demands.
- **Why:** Completes the ring-3 story started in entries #107
  (ELF validator) + #108 (ElfLoad). With this, a ring-3
  program written as a byte payload wrapped in an ELF can
  call `int 0x80` with `eax=7` to launch peers, closing the
  self-hosting loop.
- **Rules out / defers:** Separate `kCapSpawn` cap. Explicit
  budget args in the syscall. Exec-in-place semantics
  (replace calling process's AS — POSIX `execve`). Arguments
  / environment passed to the child. Parent-child process
  graph for exit-code waiting. Spawn-with-reduced-caps via a
  pre-spawn DROPCAPS variant.
- **Revisit when:** First ring-3 program wants argv / env.
  Parent / child lifecycle matters (`waitpid` analogue).
  Toolchain lands that compiles real programs.
- **Related tracks:** Track 4 (Process — spawn syscall ABI),
  Track 7 (Userland — in-ring-3 launcher shape).

---

## 108 — `ElfLoad` — populate an AddressSpace from a validated ELF

- **Scope:** `kernel/core/elf_loader.{h,cpp}` extended with
  `ElfLoadResult` struct + `ElfLoad(file, len, AddressSpace*)`.
  `kernel/fs/ramfs.cpp` — `/bin/sample.elf` replaced with
  runnable 129-byte `/bin/exit.elf` (header + PT_LOAD + 9 bytes
  of `mov eax,0; xor edi,edi; int 0x80`). `kernel/core/
  ring3_smoke.{h,cpp}` — `Ring3UserEntry` promoted out of the
  anon namespace; new `SpawnElfFile` wraps the full AS → ELF →
  Process → SchedCreateUser pipeline. `kernel/shell/shell.cpp`
  — `CmdExec`'s dry-run print is now followed by a real
  `SpawnElfFile` call.
- **Decision:**
  - Per-page frame allocation. Each 4 KiB page of
    `[vaddr & ~page_mask, (vaddr+memsz+mask) & ~mask)` gets
    its own frame from `AllocateFrame`. Frames are
    zero-on-alloc (frame allocator contract), so the
    `memsz - filesz` .bss tail is free — no explicit zeroing
    required.
  - Page-level flag derivation: `kPagePresent | kPageUser`
    always; `kPageWritable` iff `PF_W`; `kPageNoExecute` iff
    NOT `PF_X`. The U-bit is forced on by
    `AddressSpaceMapUserPage` regardless.
  - Fixed v0 stack VA `0x7FFFE000` (one page below top of
    canonical 32-bit low), mapped `R|W|U|NX`. Clear of any
    typical PT_LOAD at 0x400000.
  - On partial failure (AllocateFrame OOM mid-walk):
    `ElfLoadResult::ok = false`, partial mappings left to
    the caller's `AddressSpaceRelease` to tear down.
    Rationale: the v0 AS tracks its user-region table and
    its destructor already handles teardown; duplicating
    that unwind here would drift from the canonical
    release path.
  - `/bin/exit.elf` uses `p_align = 1` so the file stays
    compact (129 bytes) rather than padding to match
    `p_offset % p_align == p_vaddr % p_align` for
    p_align=4096. ElfValidate skips the alignment check
    when `p_align <= 1`.
- **Why:** Closes the gap between "ELF parser works" (entry
  #107) and "ring-3 tasks can actually run from files."
  `exec /bin/exit.elf` now produces a real process that
  takes the SYS_EXIT path — end-to-end proof the pipeline
  works, unblocking SYS_SPAWN (entry #109) and any future
  user-mode toolchain.
- **Rules out / defers:** Multi-MiB binaries (stack VA is
  fixed; a PT_LOAD reaching 0x7FFFE000 would collide). PIE /
  relocated e_entry. ET_DYN files with DT_NEEDED. PT_INTERP
  (dynamic linker handoff). Per-task stack guard pages.
- **Revisit when:** Toolchain lands (ELFs produced by a
  cross-compiler have bigger PT_LOADs + possibly dynamic
  relocation). First PIE executable arrives.
- **Related tracks:** Track 4 (Process model — loader is
  the mouth of every user-mode launch path), Track 3 (MM —
  ElfLoad is now one of the two callers of
  `AddressSpaceMapUserPage`, alongside the smoke tasks).

---

## 107 — Proper ELF64 loader module + `exec` dry-run command

- **Scope:** `kernel/core/elf_loader.{h,cpp}` — new module.
  `kernel/shell/shell.cpp` — `exec PATH` command.
- **Decision:** Two-stage landing for SYS_SPAWN:
    Stage 1 (this slice): validation + iteration API.
      ElfValidate, ElfEntry, ElfProgramHeaderInfo,
      ElfForEachPtLoad. Returns rich ElfStatus enum so
      callers distinguish "too small" vs "bad magic" vs
      "bad machine" vs "segment out of bounds."
    Stage 2 (next): ElfLoad into an AddressSpace, then
      the full `exec PATH` that spawns a ring-3 task.
  Shell `exec` already exists as a DRY RUN — validates
  the ELF and prints the load plan. Lets users see the
  validator reject / accept a file without committing
  kernel state.
- **Why:** Splitting validation from loading keeps each
  layer testable on its own. The dry-run command is
  useful standalone for inspecting any ELF file the shell
  can read, and it exercises every validator rejection
  path without risk.
- **Rules out / defers:** Actual segment loading /
  AddressSpace population / process spawn. Dynamic
  linking (DT_NEEDED). Interpreter support (PT_INTERP).
  Segment NX enforcement beyond honoring PF_X flag bit.
  PIE / position-independent executables (entry relocated
  per process).
- **Revisit when:** User-mode toolchain lands (compiles
  into loadable ELFs). SYS_SPAWN implementation begins.
- **Related tracks:** Track 4 (Process — loader input),
  Track 7 (Userland shell — `exec` becomes spawn).

---

## 106 — Cross-task `kill` by PID + KillResult taxonomy

- **Scope:** `kernel/sched/sched.{h,cpp}` — new
  `KillReason::UserKill`, `KillResult` enum, and
  `SchedKillByPid(pid)` that walks every task list under
  Cli() to find the target, applies a state-specific
  detach, and sets `kill_requested` + `kill_reason`.
  Reserved tasks (pid 0, reaper, idle-*) are rejected as
  Protected. `kernel/shell/shell.cpp` — `kill PID` command
  translates KillResult to user messages.
- **Decision:** State-specific behaviour:
    Running / Ready  — flag only; Schedule() handles.
    Sleeping         — lift off sleep queue, re-queue Ready
                       (and decrement g_tasks_sleeping).
    Blocked          — flag only; caller gets `Blocked`
                       result. v0 has no safe cross-queue
                       detach — doing one would race the
                       WaitQueue's producer mid-enqueue.
                       The task dies when its normal
                       producer next wakes it.
    Dead             — reports `AlreadyDead`.
  Protected list enforces three hard-coded safety rules
  (boot task id==0, name=="reaper", name starts with
  "idle-"). Killing any of those would break scheduler
  invariants (empty runqueue, leaked zombies, broken
  boot-stack alias).
- **Why:** The `spawn` command lets users start ring-3
  tasks interactively but they ran to their own
  tick-budget / denial-ceiling ends; users couldn't
  terminate them on demand. `kill` closes that loop and
  makes interactive process management possible.
- **Rules out / defers:** Safe cross-WaitQueue detach
  (requires a global queue-registry or per-queue spinlock
  — neither exists). Signals (SIGTERM / SIGKILL / SIGINT
  as a real ABI). Group kills by parent or name prefix.
  `kill -9` / `kill -15` semantics. Kill notification to
  parent process (no parent/child graph yet).
- **Revisit when:** SMP scheduler lands (need per-cpu
  locks instead of global Cli). SIGINT-style signals
  arrive. Parent/child process graph lands (zombie
  delivery to parent). WaitQueue registry lands (then
  Blocked kills work).
- **Related tracks:** Track 2 (Scheduler — kill path),
  Track 4 (Process — lifecycle), Track 7 (Userland shell
  — `kill` command).

---

## 105 — Shell utility batch (sleep / reset / tac / nl / rev / expr / color / rand / flushtlb / checksum / repeat)

- **Scope:** `kernel/shell/shell.cpp` — eleven commands in
  two sub-batches. All wrappers around existing APIs.
- **Decision:**
  - `sleep N` polls the interrupt flag every second so a
    long sleep can be aborted, rather than one big
    SchedSleepTicks(N*100) that would ignore Ctrl+C.
  - `expr` is 64-bit signed, divide-by-zero reports
    instead of trapping (no #DE from user-typed input).
  - `repeat N CMD` re-dispatches through Dispatch() so
    alias / env / redirect / pipes all apply to each
    iteration. Fresh buffer copy per iteration because
    Dispatch() mutates its input.
  - `rand` uses splitmix64 seeded from TSC. Not
    cryptographic — disclosed in the output.
  - `flushtlb` reloads CR3 with its current value — the
    classic "invalidate non-global TLB" primitive.
  - `checksum` is FNV1A-32: no allocation, one pass, good
    enough for "did content change" sanity.
  - `color` takes hex fg + optional bg; defaults bg to a
    sane navy rather than requiring both.
- **Why:** Filling out the shell's utility surface — the
  last round was file-inspection; this round is
  script-friendly ergonomics (sleep, repeat, expr, rand)
  + text-processing (tac, nl, rev) + runtime tuning
  (color, flushtlb).
- **Rules out / defers:** `sleep 0.5` fractional seconds
  (no sub-tick granularity yet). `expr` parentheses /
  precedence. `rand MIN MAX`. Cryptographic rand source.
  SHA / MD5 hashes. `repeat INF` (would need a clean
  interrupt story on pipelines).
- **Revisit when:** Fractional-second timing arrives via
  HPET scheduler integration. First user wants bigger
  rand ranges. SHA-2 hardware instructions become useful.
- **Related tracks:** Track 7 (Userland shell).

---

## 104 — Shell file-inspection commands (hexdump / stat / basename / dirname / cal)

- **Scope:** `kernel/shell/shell.cpp` — five commands, each a
  thin wrapper around existing ramfs/tmpfs paths + a bit of
  local parsing. `hexdump` renders 16-byte rows with the
  canonical HH/ASCII layout. `stat` prints ramfs vs tmpfs +
  size / child count. `basename` / `dirname` do path
  splitting. `cal` renders the current month using Zeller's
  congruence against the RTC date with today highlighted.
- **Decision:** All five are leaf commands — no new kernel
  API needed. `cal` uses Zeller for weekday-of-first rather
  than baking a lookup table; cheap and reuses the existing
  RTC reader.
- **Why:** File-inspection ergonomics. `stat` closes the
  "is this file there" question without a full ls; `hexdump`
  complements `readelf` for byte-level inspection;
  `basename`/`dirname` round out path manipulation; `cal`
  is just nice to have when a clock is visible.
- **Rules out / defers:** `stat -c '%s'` format strings. Full
  `hexdump -C` feature set (region / length flags). `cal`
  multi-month / yearly views.
- **Revisit when:** First user wants hexdump slice / length
  flags. Scripts need format-string output.
- **Related tracks:** Track 7 (Userland shell).

---

## 103 — `readelf` command + sample ELF64 in ramfs

- **Scope:** `kernel/fs/ramfs.cpp` — 120-byte minimal valid
  ELF64 binary at `/bin/sample.elf` (64-byte header + one
  PT_LOAD). `kernel/shell/shell.cpp` — `readelf PATH` parser
  + LeU16/LeU32/LeU64 unaligned readers + type-name lookup
  tables.
- **Decision:** Ship a synthetic header rather than wire up
  a real build target for user-mode binaries. The synthetic
  file is just enough to exercise every field of the parser;
  when a real user toolchain arrives, the parser works on
  its output unchanged. Validate magic + ELFCLASS64 +
  ELFDATA2LSB up front; reject anything else.
- **Why:** First concrete step toward SYS_SPAWN + ELF
  loading. The parser is the gate — once it accepts real
  ELFs, "copy each PT_LOAD segment into the right VA" is a
  direct extension. Also useful standalone for inspecting
  any future disk images.
- **Rules out / defers:** Section header parsing. Symbol
  tables. Relocation entries. DYNAMIC segment handling
  (needed for PIE). Note / .comment section display.
  Actual program loading.
- **Revisit when:** First user-mode toolchain produces an
  ELF to load. SYS_SPAWN implementation begins.
- **Related tracks:** Track 4 (Process — loader input),
  Track 7 (Userland shell — inspection tool).

---

## 102 — Shell `spawn` command — ring-3 tasks on demand

- **Scope:** `kernel/core/ring3_smoke.{h,cpp}` — new
  `SpawnOnDemand(kind)` dispatcher exposing the existing
  boot-time ring-3 spawners. `kernel/shell/shell.cpp` —
  new `spawn <kind>` command where kind ∈ {hello, sandbox,
  jail, nx, hog, hostile, dropcaps}.
- **Decision:** Keep SYS_SPAWN deferred until a user-mode
  toolchain lands (ELF loader, user-mode libc, user-mode
  linker script); in the meantime, expose the hand-crafted
  byte payloads the boot fleet already uses via an opt-in
  shell command. Each invocation creates a fresh Process +
  AddressSpace — the standard path — so every gadget the
  kernel reaches for (ASLR, reaper cleanup, per-AS VAs)
  runs just as it does at boot.
- **Why:** Lets a user at the prompt watch the ring-3
  machinery in action — `spawn hello` produces a visible
  ring-3 task; `spawn jail` proves the page-protection
  kill path; `spawn hog` proves the tick-budget kill path.
  Closes the gap between "ring 3 works once at boot" and
  "ring 3 can be driven interactively."
- **Rules out / defers:** Loading arbitrary ELFs from
  ramfs. Running user-written binaries. SYS_SPAWN syscall
  (ring-3 → ring-3 spawn). Toolchain for ring-3 binaries.
- **Revisit when:** ELF loader lands; user toolchain in
  tree; SYS_SPAWN slice begins.
- **Related tracks:** Track 4 (Process model — spawn
  dispatcher shape), Track 7 (Userland shell — user-
  facing surface).

---

## 101 — Scheduler task enumeration + `ps` command

- **Scope:** `kernel/sched/sched.{h,cpp}` — new
  `SchedTaskInfo` snapshot struct + `SchedEnumerate(cb,
  cookie)` that walks every known task (current +
  runqueues + sleep queue + zombie list). `kernel/core/
  shell.cpp` — `ps` command renders `PID STATE PRI NAME`
  rows with a `*` marker on the running task.
- **Decision:** Snapshot-by-value (no Task* leaves the
  API), CLI-bracketed walk to protect against timer-IRQ
  list mutations mid-visit. Callback runs under the CLI
  window — Console writes are byte-sized stores so that's
  fine; nothing blocking permitted inside the callback.
- **Why:** Before this the scheduler only published
  aggregate counters (SchedStatsRead). `ps` is what users
  reach for to understand what the OS is doing; without
  it `stats` is a partial answer.
- **Rules out / defers:** Per-task CPU time / runtime
  accumulation. Memory per task. Parent/child links.
  Kill-by-pid. Sort-by-cpu.
- **Revisit when:** Per-task time accounting lands (add
  a TIME column). SYS_SPAWN lands (parent PID matters).
  kill(pid) lands (interactive process management).
- **Related tracks:** Track 2 (Scheduler — enumeration
  API), Track 7 (Userland shell — consumer).

---

## 100 — Shell Ctrl+C interrupt + uncapped seq

- **Scope:** `kernel/core/shell.{h,cpp}` — latched
  `g_interrupt` flag, `ShellInterrupt` + `ShellInterruptRequested`
  API. `kernel/core/main.cpp` — kbd reader catches Ctrl+C
  (Ctrl held + 'c' / 'C', no Alt) and flips the flag
  without triggering any recompose. `seq` loses its 200-
  iteration cap and polls the flag per iteration.
- **Decision:** One-shot latched flag, single producer
  (kbd reader) + single consumer (command loop), no
  explicit barrier. Works because x86_64's byte-store
  memory model guarantees the reader sees the set on the
  next poll. Future commands (infinite `yes`, tail -f,
  long find) poll the same hook.
- **Why:** Uncapping `seq` was the immediate driver, but
  the pattern generalises — any long-running command now
  has a standard "user can abort" shape. The cap itself
  was always a workaround for the missing interrupt; now
  it's gone.
- **Rules out / defers:** SIGINT handler dispatch (no
  signals yet). Cross-task interrupt (only the running
  command sees the flag). Ctrl+Z / suspend. Blocking on
  interrupt (the flag is polled, not waited on).
- **Revisit when:** SIGINT-shaped API needed for user-
  mode handlers. Signals across ring boundaries land.
- **Related tracks:** Track 7 (Userland shell), Track 4
  (Process — signals / interrupts).

---

## 099 — Shell system-manipulation command suite (29 new commands)

- **Scope:** `kernel/shell/shell.cpp` — one batch of 20 kernel-
  introspection / control commands (cpuid, cr, rflags, tsc, msr,
  hpet, ticks, lapic, smp, lspci, heap, paging, fb, kbdstats,
  mousestats, loglevel, getenv, yield, reboot, halt) plus a
  second batch of 9 POSIX-compat stubs (uname, whoami, hostname,
  pwd, true, false, mount, lsmod, free). New `WriteU64Hex`
  helper shared by every register-dump command.
- **Decision:** All commands are thin wrappers around existing
  kernel accessors. The register-dump commands roll inline
  asm (cpuid, rdmsr, rdtsc, pushfq) rather than taking a
  dependency on a cpu.h extension — keeps the kernel core
  unchanged. Power commands (`reboot`, `halt`) don't prompt
  for confirmation; the user typed them intentionally.
  Freestanding-build gotcha: avoid in-function struct arrays
  like `const Bit bits[] = {...}` — they emit a memcpy from
  .rodata that the kernel doesn't link. Use parallel
  primitive-array locals instead.
- **Why:** The user explicitly asked for every possible
  getter / setter / manipulator command — this batch cashes
  in on every kernel API the tree already exposes. Also
  closes the gap between "system looks real" and "system
  answers diagnostic questions like a real OS."
- **Rules out / defers:** MSR writes (wrmsr can brick the
  CPU with bad values). `reboot` confirmation prompt.
  `mount` / `lsmod` as genuine reflection (they're static
  strings). True per-task `ps` (scheduler doesn't expose a
  task enumerator yet). Nested CPUID subleaf parsing.
- **Revisit when:** SYS_SPAWN lands (`reboot` could warn
  about active processes first; `ps` becomes real).
  Per-task accounting (`free` grows a per-task column).
  Writable MSR subset approved (some runtime tuning).
- **Related tracks:** Track 7 (Userland shell — all 29
  commands live here), Track 2 (Platform — register /
  device introspection).

---

## 098 — Shell pipes (`|`) via console capture + tmpfs transport

- **Scope:** `kernel/drivers/video/console.{h,cpp}` — new
  `ConsoleBeginCapture` / `ConsoleEndCapture` divert
  shell-slot writes to a caller buffer (klog slot
  unaffected). `kernel/shell/shell.cpp` — Dispatch parses
  `|` before tokenisation, runs the left half with
  capture active, stashes the output in `/tmp/__pipe__`,
  then re-dispatches the right half with the tmpfs path
  appended as the final argument. Unlinks the temp file
  on unwind.
- **Decision:** Pipe transport via tmpfs file + recursion
  into Dispatch, not via an in-process stream abstraction.
  Rationale: no command in the tree reads stdin (they
  read paths), so the cheapest mechanism that makes
  `A | B` work is "capture A's console output into a
  real file and feed that file's path to B." Multi-stage
  pipes fall out for free because the recursion handles
  the right side's own embedded `|`. Reserved name
  `/tmp/__pipe__` makes nested reuses overwrite-safe.
- **Why:** The one iconic missing shell feature. Every
  command already produces console text and most already
  accept a trailing path; the capture/transport trick
  reuses both without touching the individual commands.
  Real pipes (Linux-style fd 1 → fd 0 kernel buffer) come
  later with SYS_SPAWN; v0's tmpfs transport satisfies the
  ergonomics.
- **Rules out / defers:** Streaming (a stage can't produce
  output before the previous stage finishes). Stderr
  redirection (2>&1). Commands that read real stdin.
  Capture buffer cap == tmpfs content max; longer pipelines
  truncate. pipefail / SIGPIPE semantics.
- **Revisit when:** SYS_SPAWN lands (real process-to-process
  pipes). User pipelines exceed 512 bytes of intermediate
  output (bump the tmpfs slot size or move to heap).
  Streaming required (interactive filters like `tail -f`).
- **Related tracks:** Track 7 (Userland shell — iconic
  feature), Track 4 (Process — real pipes wait on this),
  Track 5 (VFS — pipe file-style abstraction).

---

## 097 — Shell `sort` + `uniq`

- **Scope:** `kernel/shell/shell.cpp` — `CmdSort` + `CmdUniq`
  and shared helpers `SliceLines` + `LineCompare`.
- **Decision:** `sort` uses insertion sort on a (offset, length)
  index pair array (stack-local, cap 128 lines) — line bodies
  stay in the scratch buffer and we only swap indices, so the
  algorithm is zero-copy. Classic `uniq` semantics — consecutive
  duplicates only. Both share `SliceLines` so future line-
  oriented commands (`tac`, `uniq -c`, `sort -r`) pick up the
  slicing for free.
- **Why:** Closes the "classic text pipeline" trio (grep / sort
  / uniq) — a user can now script read-only log triage
  workflows entirely in the shell.
- **Rules out / defers:** `-r` reverse sort. `-n` numeric sort.
  `-u` unique (merged into sort). `uniq -c` / `-d`. Large-file
  sort (backing store).
- **Revisit when:** Pipes land (`sort` and `uniq` are the
  canonical pipe consumers — `cmd | sort | uniq`). First user
  wants `-r` or `-n` flags.
- **Related tracks:** Track 7 (Userland shell).

---

## 096 — Move man pages into /etc/man/ ramfs files

- **Scope:** `kernel/fs/ramfs.cpp` — twelve new `/etc/man/*`
  files (ls, cat, echo, cp, mv, grep, find, history, alias,
  env, time, source) declared via a one-line `MAN_NODE()`
  macro. New `k_trusted_etc_man_dir` slots into `/etc`.
  `kernel/shell/shell.cpp` — `CmdMan` rewritten to build
  `/etc/man/<name>` and dispatch through `ReadFileToBuf`.
- **Decision:** Keep the man-page text in ramfs, not inline
  in shell.cpp. MAN_NODE() macro collapses each per-page
  `RamfsNode` definition to one line. CmdMan loses ~100
  lines of switch/case for a 30-line VfsLookup + cat.
- **Why:** `cat /etc/man/ls` now works, which is the POSIX
  promise; `ls /etc/man` enumerates what's available; and
  shell.cpp stops carrying help text that belongs on disk.
  Also sets up the pattern for future man-page additions —
  drop a constexpr byte array + a MAN_NODE() line.
- **Rules out / defers:** Sectioned pages (man 1, 2, ...).
  Formatting (bold / italic / underline — none of which our
  font supports anyway). User-writable man pages in
  /tmp/man/ (mount nesting).
- **Revisit when:** On-disk FS lands (man moves to a real
  disk path). Formatted output primitives arrive (ANSI SGR,
  per-cell colour).
- **Related tracks:** Track 5 (VFS — first nested directory
  with > 2 files), Track 7 (Userland shell — disk-backed
  documentation).

---

## 095 — Shell `time` / `which` / `seq` + factored kCommandSet

- **Scope:** `kernel/shell/shell.cpp` — three new commands, plus
  the canonical `kCommandSet[]` lifted from a function-local
  static into a file-scope `static const` so it has one source
  of truth for tab-complete and the new `which` lookup.
- **Decision:** All three are 10-30 LOC wrappers around stuff
  that already exists. `time` recurses through `Dispatch` so
  it inherits the full pipeline (alias / env / redirect).
  `seq` caps at 200 because there's no Ctrl+C handler — one-
  shot infinite output would lock a screen we can't interrupt.
  `which` checks builtins then aliases; reporting "NOT FOUND"
  matches `which`'s POSIX exit-code-1 case.
- **Why:** All three are muscle-memory commands. `time` in
  particular is what users reach for the moment they want to
  benchmark anything; no point asking them to read tick
  counts from `stats`.
- **Rules out / defers:** `time` user vs system breakdown
  (no per-task accounting). `seq START STOP STEP` POSIX form.
  `which -a` to list shadowing.
- **Revisit when:** SYS_SPAWN lands (`which` should also
  resolve `/bin/<cmd>` real binaries). Per-task time
  accounting available (separate user/sys/real).
- **Related tracks:** Track 7 (Userland shell).

---

## 094 — Shell `grep` + `find`

- **Scope:** `kernel/shell/shell.cpp` — `grep PATTERN PATH`
  walks line-by-line and prints matches; `find NAME`
  recursively walks the ramfs tree printing absolute paths
  whose leaf contains NAME, then enumerates tmpfs slots.
  Shared `SubstringPresent` helper.
- **Decision:** Substring match only (no regex), case-
  sensitive, no flags. `find` walks both backends because
  the user expects `/tmp/<name>` paths to surface alongside
  ramfs ones — keeping them visually unified. Path buffer
  is 128B and stack-local so the recursion doesn't pressure
  any global state.
- **Why:** `grep` + `find` are how you inspect any non-trivial
  filesystem — even at 6 ramfs files it's nicer than scrolling
  `ls`. The same shape extends to a real on-disk FS without
  refactoring.
- **Rules out / defers:** Regex (`grep -E`). Recursive grep.
  `find` predicates (-type, -name with glob, -size).
  Case-insensitive (-i). Multi-file `grep PATH PATH PATH`.
- **Revisit when:** First user wants regex (which usually
  means writing log filters). On-disk FS lands and the
  recursion depth needs bumping past 128B.
- **Related tracks:** Track 7 (Userland shell), Track 5
  (VFS — multi-backend walker reuse).

---

## 093 — /etc/motd + /etc/profile + source / man commands

- **Scope:** `kernel/fs/ramfs.cpp` — seeds `/etc/motd`
  (welcome banner + key bindings) and `/etc/profile`
  (default aliases + prompt). `kernel/shell/shell.cpp` —
  new `source` command (dispatches each line of a file as
  a shell command; `#` comments + blank lines skipped;
  `.` alias). New `man NAME` prints detailed per-command
  help from an inline switch. `ShellInit` auto-cats motd
  + auto-sources /etc/profile.
- **Decision:** motd + profile land in the ramfs as real
  files so users can point at them with `cat /etc/motd` and
  eventually edit via tmpfs copy. `source` lets the user
  run ad-hoc scripts from /tmp too (write a script to
  /tmp/foo, source it). `man` pages stay inline in shell.cpp
  for v0 — moving them to /etc/man/<cmd> files is a mostly-
  mechanical refactor that adds pressure on the ramfs
  seeding code, so defer until an on-disk FS lands.
- **Why:** The shell boots feeling like a real system now:
  a persistent system-identity file is on disk, defaults
  auto-apply, users can get detailed help on any command,
  and scripts are a thing. Incremental but high-impact
  polish.
- **Rules out / defers:** /etc/man/<cmd> as real files
  (easy follow-up once there's more disk content). Scripts
  with shebang, arguments, conditionals, loops. Per-user
  profile (no user concept yet). Motd generators (dynamic
  content via special markers).
- **Revisit when:** On-disk FS lands (motd/profile/man
  become real files; user-edited profile persists). First
  scripting construct needed (if/while/for). Multi-user
  appears.
- **Related tracks:** Track 5 (VFS — persistent system
  config files), Track 7 (Userland shell — scripts),
  Track 4 (Process model — per-user / per-process env).

---

## 092 — Severity-coloured KERNEL LOG window

- **Scope:** `kernel/core/main.cpp` — log-viewer content
  drawer inspects the first chunk per line (always the
  severity tag from `LevelTag()`) and sets the render
  foreground per line: white-ish = Info, grey = Debug,
  amber = Warn, soft red = Error. Newline resets.
- **Decision:** Line-level colouring, not per-cell. Detected
  from the LevelTag() shape "[X] " — the renderer matches
  `s[0]=='[' && s[2]==']'`, which no other chunk produces.
  Zero storage overhead; colour lives only in the render
  function's static.
- **Why:** Previously every severity looked identical on
  screen; klog output was visually flat. Amber warnings and
  red errors now jump out the moment the window paints —
  matches every modern log viewer (journalctl, dmesg -H,
  etc.).
- **Rules out / defers:** Per-token / per-column colours
  (no rich ANSI escape handling). Colour theme config. Per-
  severity background highlight. Copy-with-colour.
- **Revisit when:** ANSI escape codes land in the console
  generally. User wants a custom palette.
- **Related tracks:** Track 9 (Windowing — log surface),
  Track 7 (Userland — readable logs).

---

## 091 — Shell alias / unalias / sysinfo + $PS1 prompt

- **Scope:** `kernel/shell/shell.cpp` — 8-slot alias table
  (names 32B, expansions 96B); `alias` / `unalias` / `sysinfo`
  commands; Prompt() now consults $PS1 before defaulting to
  "$ ".
- **Decision:** Alias expansion runs BEFORE tokenisation in
  Dispatch — the expansion flows through the full shell
  pipeline (env substitution, redirects). One level of
  expansion; an alias referencing another is not recursively
  expanded (bash's default sans expand_aliases). sysinfo
  consolidates version + uptime + wall time + task counts +
  memory + window count + display mode into a single
  read-only dump.
- **Why:** Three small polish items that together make the
  shell feel like a real terminal:
    alias    — muscle memory ("alias ll ls")
    $PS1     — prompt customization (the canonical shell
               expression of individuality)
    sysinfo  — one-shot "what is this machine doing?"
- **Rules out / defers:** Recursive alias expansion.
  Alias arguments / parameters. $PS1 escape sequences
  (\u, \h, \w, \t — would need richer Prompt rendering).
  sysinfo -v flags.
- **Revisit when:** First alias consumer needs parameter
  substitution. $PS1 users ask for hostname / cwd
  expansion (implies a CWD concept).
- **Related tracks:** Track 7 (Userland shell).

---

## 090 — Shell env variables + $VAR whole-token substitution

- **Scope:** `kernel/shell/shell.cpp` — 8-slot env table
  (32-byte names, 128-byte values). New `set` / `unset` /
  `env` commands + pre-tokenize pass in Dispatch that
  replaces whole-token `$VAR` references with their value
  (undefined → empty string).
- **Decision:** Whole-token substitution only. Partial
  expansion (`prefix$VAR`, `${VAR}`, nested, command
  substitution) all deferred. Rationale: whole-token catches
  every boot-time use (`echo $HOME`, `cat $FILE`) and keeps
  the substituter a one-line `argv[i] = EnvFind(...)->value`
  swap. A real expander lands when someone writes a non-
  trivial shell script.
- **Why:** Env vars unlock a PATH-like story for when
  SYS_SPAWN arrives (shell picks binaries by `$PATH` lookup
  rather than hard-coded `/bin`). Before that, they're just
  a scratchpad, but the primitive is the same either way.
- **Rules out / defers:** `${VAR}` syntax. Partial-token
  expansion. Quoting. Export vs local. PATH semantics.
  Per-process env (all commands share the single table).
  Persistence across reboot.
- **Revisit when:** SYS_SPAWN lands. First env-dependent
  shell script attempt. Quoting needed for filenames with
  spaces (a tmpfs that allows them).
- **Related tracks:** Track 7 (Userland shell), Track 4
  (Process model — per-process env).

---

## 089 — cp / mv / wc / head / tail coreutils-ish commands

- **Scope:** `kernel/shell/shell.cpp` — five new commands
  built on a shared `ReadFileToBuf` helper that dispatches
  on the /tmp prefix to pick tmpfs vs ramfs.
- **Decision:** Keep the commands thin — each is a 20-50
  line wrapper around the shared read helper + the existing
  tmpfs write path. `cp` reads from either backend, writes to
  tmpfs; `mv` is tmpfs-only and unlinks the source only AFTER
  write succeeds. `head` / `tail` default to 5 lines with a
  `-N` short form; `wc` emits the POSIX trio (lines, words,
  bytes) with unterminated-last-line counting as a line.
- **Why:** `cp` + `mv` round out file manipulation so users
  can do more than "write once, read". `head` / `tail` / `wc`
  are the classic file-inspection trio — adding them makes
  the shell feel genuinely like a terminal, not a demo.
- **Rules out / defers:** -r recursive variants. `cp` into
  ramfs (impossible, read-only). Globbing. `wc -l` / `-w`
  selector flags. `head`/`tail` follow mode.
- **Revisit when:** Second writable backend (on-disk FS) lets
  us relax the tmpfs-only destination restriction. First
  shell script needs a specific single-column count.
- **Related tracks:** Track 7 (Userland shell), Track 5
  (VFS — multi-backend read dispatch is already factored).

---

## 088 — Shell `history` + `!N` / `!!` recall

- **Scope:** `kernel/core/shell.{h,cpp}` — `ShellHistoryCount`
  / `ShellHistoryGet` expose the existing history ring;
  new `history` command prints it oldest-first with 1-based
  numbering. `HistoryExpand` runs before argv tokenisation in
  Dispatch, resolving `!!` and `!N` into the recalled line
  (echoed first, then recursively dispatched).
- **Decision:** Display numbers count oldest-first so users
  intuit "!1 is what I ran first." Internal `HistoryAt(n)`
  still counts newest-first; the `history` command + the
  recall path both invert at the boundary. Recursion is
  depth-bounded at 1 — history entries can't themselves
  begin with `!` because the push path dedups, and a `!X`
  that resolves to another `!Y` is rejected up front.
- **Why:** Up/Down arrow cursor recall + `history` + `!N`
  together cover the full bash-flavoured history surface
  users expect. Zero new storage; just wrappers + a tiny
  pre-dispatch expansion step.
- **Rules out / defers:** `!prefix` (run the most recent
  command starting with `prefix`). `!$` (last arg of last
  command). `Ctrl+R` incremental search. Persistent history
  across reboot.
- **Revisit when:** Second shell session coexists (needs
  per-session vs global). Persistent history (needs writable
  FS).
- **Related tracks:** Track 7 (Userland shell).

---

## 087 — Live KERNEL LOG viewer window

- **Scope:** `kernel/core/main.cpp` — fourth registered window
  ("KERNEL LOG") with a content drawer that streams the klog
  ring into a wrapped character grid. Uses
  `DumpLogRingTo` with a chunk callback that writes char-by-
  char, stopping at the client-area row limit.
- **Decision:** Render from the ring directly — no scratch
  buffer, no per-window state. ui-ticker's 1 Hz recompose is
  the refresh cadence; that matches the klog update rate for
  boot-line cadence.
- **Why:** Second consumer of the content-drawer API proves
  the hook is general enough for streaming wrapped text, not
  just fixed-row numeric panels like Task Manager. Also
  surfaces klog in desktop mode where Ctrl+Alt+F2 isn't
  available as a flip.
- **Rules out / defers:** Scrollback pagination. Filter by
  severity. Click-to-copy. Sticky tail-follow.
- **Revisit when:** Log volume exceeds one screen often
  enough that scrolling matters. Severity highlighting
  becomes visually useful.
- **Related tracks:** Track 9 (Windowing — second content
  drawer), Track 7 (Userland — visible logs).

---

## 086 — `>>` append redirect for tmpfs

- **Scope:** `kernel/fs/tmpfs.{h,cpp}` — new `TmpFsAppend`
  that grows the target slot's content up to the hard cap.
  `kernel/shell/shell.cpp` — echo tokenizer recognises `>>`
  separately from `>` and routes accordingly.
- **Decision:** Append truncates the portion past
  kTmpFsContentMax rather than failing — matches ENOSPC on a
  real fs. `>>` is a distinct token from `>`; the shell's
  whitespace tokenizer already separates them cleanly.
- **Why:** `>` plus `cat` covered one-shot content, but any
  log-style use (`date >> /tmp/notes`, multi-line scratch)
  needs append. One-line add on the fs side; one-line branch
  on the shell side.
- **Rules out / defers:** 2>&1 / 2> stderr redirects (no
  separate stderr yet). Heredocs. Process-substitution.
- **Revisit when:** Second output stream exists (stderr
  split from stdout for commands).
- **Related tracks:** Track 7 (Userland shell).

---

## 085 — Dual consoles (shell + klog) with Ctrl+Alt+F1/F2

- **Scope:** `kernel/drivers/video/console.{h,cpp}` —
  ConsoleState struct + 2-slot array. Slot 0 = shell
  (interactive), slot 1 = klog (read-only, target of the
  klog tee). New `ConsoleSelectShell` / `ConsoleSelectKlog`
  swap the render target in place; both consoles share the
  same screen origin. `kernel/core/main.cpp` — klog tee now
  forwards to `ConsoleWriteKlog`; new Ctrl+Alt+F1 / F2
  shortcuts flip the render target.
- **Decision:** Single shell instance, dual output channels,
  user-selectable render target. Shell output always lands in
  slot 0; klog always in slot 1. Switching is a pure
  presentation-layer change — shell state never moves. Each
  slot has independent scrollback, so flipping back to F1
  after watching klog leaves the prompt undisturbed.
- **Why:** Linux VT feel without per-VT shell state (which
  would balloon into per-console history, process contexts,
  stdio redirection). The 80% win — see kernel log without
  interleaving it with your typing — is delivered for one
  extra 3 KB .bss console buffer.
- **Rules out / defers:** True multi-shell VTs (one shell per
  console). More than two channels (F3..F6). Per-channel font /
  theme. Copy-between-channels. Scrollback paging.
- **Revisit when:** SYS_SPAWN lands (multiple processes could
  each want a TTY). First user needs a dedicated "mouse event
  log" or similar third channel.
- **Related tracks:** Track 7 (Userland shell — where input
  lands), Track 9 (Windowing — presentation switch), Track 2
  (Platform — logging infrastructure).

---

## 084 — Per-window content drawers + Task Manager window

- **Scope:** `kernel/drivers/video/widget.{h,cpp}` — new
  `WindowContentFn` type, `WindowSetContentDraw`, and a
  content-invoke step at the end of each window's entry in
  `WindowDrawAllOrdered`. `kernel/core/main.cpp` — registers
  a "TASK MANAGER" window and installs a drawer that prints
  seven live rows (uptime, context switches, task counts,
  memory frames).
- **Decision:** Content drawers are optional per-window
  function pointers plus a void* cookie, invoked with the
  pre-computed client rect. The drawer runs inside the
  compositor lock (via the normal compose path) so it can
  safely read any GUI-adjacent state. No clipping yet — the
  drawer is trusted to stay inside the rect.
- **Why:** Closes the "windows are static images" observation.
  Every live-data panel (task manager, log viewer, network
  monitor, device list) fits this shape. Landing the hook
  now means the next dozen such windows cost one small
  function each.
- **Rules out / defers:** Per-window repaint cadence
  (ui-ticker recomposes at 1 Hz and that's fine for v0).
  Clip rects enforced by the compositor. Partial redraw.
  Content-drawer-only repaint without recomposing the whole
  window stack.
- **Revisit when:** First window needs to repaint at a
  different cadence (e.g. 60 Hz animation). Damage-rect
  compositor lands. Clipping matters.
- **Related tracks:** Track 9 (Windowing — widget + content
  hook), Track 7 (Userland — shell complement).

---

## 083 — Writable /tmp tier (tmpfs) + touch / rm / echo redirect

- **Scope:** `kernel/fs/tmpfs.{h,cpp}` — new 16-slot flat
  writable tier with 32-byte names and 512-byte content
  buffers in .bss. `kernel/shell/shell.cpp` — `ls` / `cat` /
  Tab completion route /tmp paths through tmpfs; new
  `touch` / `rm` commands; `echo ... > /tmp/name` redirect.
- **Decision:** The first writable tier is deliberately
  primitive — flat namespace, static-size slots, no heap —
  so it unblocks shell feel (`echo hi > /tmp/note; cat
  /tmp/note`) without prejudging the real VFS write-path
  API. Every later tier (on-disk FS, network mount) plugs
  into the VFS instead. Paths outside /tmp stay read-only,
  shell refuses writes with a clear "ONLY /tmp/<NAME>" msg.
- **Why:** Direct answer to "I want a terminal that feels
  like Linux/macOS" — without writable files the shell is
  a read-only REPL. tmpfs is the cheapest concrete storage
  that lets the classic "echo > file && cat file" pipeline
  actually work end-to-end.
- **Rules out / defers:** Subdirectories inside /tmp.
  Appending (>> redirect). Moving / renaming. Permissions.
  Mount abstraction. Heap allocation (all storage is .bss).
  Multi-process file sharing semantics. Proper VFS
  write-path trait.
- **Revisit when:** First consumer needs nested /tmp dirs.
  Append semantics required (log file). On-disk FS lands.
  First multi-process writer appears.
- **Related tracks:** Track 5 (VFS — writable tier teaser),
  Track 7 (Userland shell — redirect + file mgmt).

---

## 082 — Tab path completion for ls / cat

- **Scope:** `kernel/shell/shell.cpp` — `ShellTabComplete`
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
  compile-time `DUETOS_BOOT_TTY` flag; no cmdline leaves
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

## 076 — DuetOS shell: interactive command line

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
  — new `DUETOS_BOOT_TTY` option for text-first initial boot.
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
  new switch case; `kernel/proc/ring3_smoke.cpp` — payload
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
  comment in `kernel/proc/ring3_smoke.cpp` downgrading the manual
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
  Ring-3 payload update in `kernel/proc/ring3_smoke.cpp` (now
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
  `kernel/proc/ring3_smoke.cpp`.
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

- **Scope:** `kernel/diag/heartbeat.cpp` — replace
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

- **Scope:** `kernel/log/klog.cpp` — prefixes every log line
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

## 100 — Timed-wait primitives across sched + IPC layer

- **Scope:** `kernel/sched/sched.h` + `sched.cpp` (`MutexLockTimed`),
  `kernel/ipc/kmutex.{h,cpp}` (`KMutexAcquireTimed`),
  `kernel/ipc/kevent.{h,cpp}` (`KEventWaitTimed`),
  `kernel/ipc/ksemaphore.{h,cpp}` (`KSemaphoreAcquireTimed`).
  Self-tests in each KObject TU exercise the un-contended fast
  paths.
- **Decision:** Add a timed-wait variant to every IPC primitive
  that previously documented "no timeout in v0; lands when the
  SYS_*_WAIT migration needs it." `sched::MutexLockTimed` mirrors
  `MutexLock` but uses `WaitQueueBlockTimeout`; the hand-off
  contract from `MutexUnlock` is unchanged (owner stamped before
  wake), so a `true` return means the lock is held even if the
  task came in via the slow path. Lockdep: `BeforeAcquire`
  fires eagerly (matches `MutexLock`); the held-stack push
  (`AfterAcquire`) fires only on success. `KEvent` /
  `KSemaphore` build on `sched::CondvarWaitTimeout` with a
  deadline computed once at entry — spurious wakeups and
  "another waiter raced first" cases don't re-arm the budget.
- **Why:** This is the missing infrastructure piece on the
  critical path of the SYS_MUTEX / SYS_EVENT / SYS_SEM migration
  to `Process::kobj_handles`. The Win32 ABI returns
  `kWaitObject0` / `kWaitTimeout` from `WaitForSingleObject` —
  neither value is meaningful without a timed-wait primitive
  underneath each KObject. Landing the primitives first lets the
  migration commit be a flat substitution (replace per-type
  `Process::win32_*` with `HandleTableInsert / Lookup` calls)
  rather than co-evolving the primitive contract and the syscall
  surface.
- **Rules out / defers:** Real waiter-contention testing — the
  v0 self-tests cover the un-contended branches (timeout=0
  test-and-drop, fast-path success on signaled events / non-zero
  count / unowned mutex). Spawned-waiter tests that prove a
  timer beats an unlock-handoff (or vice versa) are gated on
  SMP AP bringup unblocking real concurrent acquires. The
  v0 implementation is correct under the existing
  `WaitQueueBlockTimeout` / `CondvarWaitTimeout` race-handling
  contract; the defer is testing-only.
- **Revisit when:** The `SYS_MUTEX_*` / `SYS_EVENT_*` /
  `SYS_SEM_*` syscall handlers migrate to `kobj_handles`. They
  call `KMutexAcquireTimed` / `KEventWaitTimed` /
  `KSemaphoreAcquireTimed` directly, returning
  `kWaitObject0` on `true` and `kWaitTimeout` on `false` —
  preserving the existing Win32 ABI without re-implementing
  the timed-wait machinery per-syscall.
- **Related tracks:** Track 1 (Kernel — sched + IPC primitives),
  Track 5 (Win32 subsystem — SYS_*_WAIT migration is the next
  consumer of this infrastructure).

---

## 101 — SYS_MUTEX_* migrated to KMutex + kobj_handles

- **Scope:** `kernel/subsystems/win32/mutex_syscall.cpp` (full
  rewrite), `kernel/subsystems/win32/file_syscall.cpp`
  (CloseHandle dispatch arm for the mutex range), `kernel/proc/
  process.{h,cpp}` (legacy `Win32MutexHandle` struct + array
  removed; `kWin32MutexCap` redefined to `kHandleTableCapacity`),
  `kernel/ipc/handle_table.{h,cpp}` (new `HandleTableLookupRef`
  for refcount-safe pin-during-use), `kernel/ipc/kmutex.cpp`
  (wait-time + holder refcounting), `kernel/ipc/kevent.cpp`,
  `kernel/ipc/ksemaphore.cpp` (wait-time refcounting on the
  paths that block).
- **Decision:** The Win32 mutex syscalls now allocate `KMutex`
  objects on the kheap and route handles through
  `Process::kobj_handles`. The Win32 handle is `kWin32MutexBase
  + ipc_handle` so the per-type handle range stays disjoint
  from event/file/thread/semaphore for `CloseHandle` to keep
  dispatching by range. The legacy fixed-size 8-slot array on
  every `Process` is gone — handle capacity is now whatever
  `kHandleTableCapacity` is (64 today). Wait-time refcounting
  guarantees that closing every handle to a contended or held
  mutex cannot free the storage out from under a current
  holder or a still-blocked waiter; `HandleTableLookupRef`
  pins the object across the syscall handler's blocking work
  to close the lookup→use race.
- **Why:** This is the slice the project pillar
  ("one source of truth per resource") demands for IPC
  objects. Win32 ABI is preserved at the syscall boundary —
  PEs that imported `CreateMutexW` / `WaitForSingleObject` /
  `ReleaseMutex` previously continue to work unchanged; the
  pe-winapi smoke profile validates the recursion-OK +
  multi-create cases under TCG. The wait-time refcounting
  pattern also closes a class of bugs the legacy fixed-array
  scheme was structurally immune to (because the array
  storage outlived the process), but that any future
  cross-process DuplicateHandle would have re-introduced
  without it.
- **Rules out / defers:** Per-handle contention metric beyond
  the first 8 ipc_handles — `kContentionSlotCap` stays at 8
  because the array sits per-process and the metric is
  best-effort observability. Real abandoned-mutex semantics
  (Win32's `WAIT_ABANDONED_0`) — v0 force-releases the closer's
  ownership and hands off to the next waiter cleanly; the
  abandoned-status signal-back to waking waiters is not
  delivered. Cross-process `DuplicateHandle` + per-process
  ref accounting interactions — single-process for now.
- **Revisit when:** A workload needs >8-handle contention
  tracking (bump `kContentionSlotCap` to `kHandleTableCapacity`
  — one-line change). A workload depends on `WAIT_ABANDONED_0`
  signaling (add a per-mutex abandoned flag set by force-release
  and propagated by `KMutexAcquire{,Timed}` to its returning
  waiter). SYS_EVENT_* / SYS_SEM_* migrate (same pattern —
  the infrastructure now in place).
- **Related tracks:** Track 1 (Kernel — IPC + handle table),
  Track 5 (Win32 subsystem — SYS_MUTEX_* end-to-end).

---

## 102 — SYS_EVENT_* / SYS_SEM_* migrated to KEvent / KSemaphore + kobj_handles

- **Scope:** `kernel/subsystems/win32/event_syscall.cpp` (full
  rewrite mirroring `mutex_syscall.cpp`), new
  `kernel/subsystems/win32/semaphore_syscall.{h,cpp}`,
  `kernel/syscall/syscall.cpp` (SYS_SEM_CREATE / SYS_SEM_WAIT /
  SYS_SEM_RELEASE inline blocks replaced with single dispatch
  calls; WaitForMultipleObjects probe + auto-reset-consume passes
  refactored onto `HandleTableLookup` + `KEventIsSignaled` /
  `KEventClearAutoReset` / `KSemaphoreCount`),
  `kernel/subsystems/win32/file_syscall.cpp` (CloseHandle event
  arm rewritten through the handle table; new semaphore arm —
  none existed pre-migration), `kernel/proc/process.{h,cpp}`
  (legacy `Win32EventHandle` / `Win32SemaphoreHandle` structs +
  arrays removed; `kWin32EventCap` / `kWin32SemaphoreCap`
  redefined to `kHandleTableCapacity`),
  `kernel/ipc/kevent.{h,cpp}` (new `KEventIsSignaled` +
  `KEventClearAutoReset` non-blocking primitives for WFMO),
  `kernel/ipc/ksemaphore.{h,cpp}` (new `KSemaphoreTryRelease` —
  non-panicking release that surfaces `ERROR_TOO_MANY_POSTS` to
  the ABI rather than panicking the kernel on overflow).
- **Decision:** Win32 events and semaphores allocate `KEvent` /
  `KSemaphore` on the kheap and route through
  `Process::kobj_handles`. Win32 handles stay
  `kWin32EventBase + ipc_handle` and `kWin32SemaphoreBase +
  ipc_handle` so CloseHandle's range-dispatch is unchanged.
  Two non-blocking primitives close the WFMO design gap from
  the legacy code: `KEventIsSignaled` for the probe phase,
  `KEventClearAutoReset` for the satisfied-consume phase.
  Semaphore probe reuses the existing `KSemaphoreCount`
  accessor (no consume — wait-all without consuming the count
  was the v0 design and remains so). `KSemaphoreTryRelease`
  was added because `KSemaphoreRelease` panics in debug on
  overflow, which is correct for kernel callers but wrong for
  an ABI surface that has to surface `ERROR_TOO_MANY_POSTS` to
  potentially malicious userland.
- **Why:** Completes the Win32 side of the
  "one source of truth per resource" handle-table migration
  started in entry #101. Same wait-time + holder refcounting
  guarantees as KMutex now apply to events and semaphores —
  closing every handle to a contended event or semaphore
  cannot free the storage out from under a waiter, and a
  CloseHandle race against WaitForMultipleObjects can no
  longer dereference a stale slot (the WFMO probe goes through
  `HandleTableLookup` with a type tag).
- **Incidental fixes:**
  - **CloseHandle had no semaphore arm pre-migration.** Closed
    semaphore slots leaked their `Win32SemaphoreHandle` slot
    forever. The legacy code only added arms for the handle
    families that had matching close paths; semaphores never
    got one. Routing through the unified handle table fixes
    this without an extra patch.
  - **WFMO event/sem branches now type-check.** The legacy
    code reached straight into `proc->win32_events[slot]` /
    `proc->win32_semaphores[slot]` without a tag check; an
    out-of-range handle that happened to fall in the same
    slot of a different table would have read the wrong
    storage. Post-migration, `HandleTableLookup` rejects
    type-mismatched handles by returning nullptr.
- **Capacity tradeoff:** Legacy was 64 mutex + 8 event + 8 sem
  = 80 total Win32 IPC handles per process. Post-migration,
  all three share the unified 64-slot `kobj_handles` table
  (a strict reduction). Same constant as the mutex migration's
  already-shipped tradeoff; one-line bump in
  `kernel/ipc/handle_table.h` if a workload demands it.
- **Rules out / defers:** Race-free WFMO across semaphores
  (consume-on-satisfaction without lost wakeups) — still a
  poll loop, count is read but not consumed, matching the v0
  design noted in the legacy code. KSemaphoreRelease's
  debug-build panic-on-overflow stays — it's the right
  behaviour for kernel-internal callers; the ABI surface uses
  `KSemaphoreTryRelease` to opt out.
- **Revisit when:** A workload exceeds 64 simultaneous IPC
  handles (bump `kHandleTableCapacity`). A workload needs
  race-free wait-multiple semantics over semaphores
  (consume-on-satisfaction across the whole set, not poll +
  read). The Linux fd-table → KFile track lands (the third
  ABI front-end converging on `kobj_handles`).
- **Commit:** `fe07e28`.
- **Related tracks:** Track 1 (Kernel — IPC + handle table),
  Track 5 (Win32 subsystem — SYS_EVENT_* / SYS_SEM_* end-to-end).

---

## 103 — Linux fd-table → KFile sidecar (pipe + eventfd migrated)

- **Scope:** `kernel/ipc/kfile.{h,cpp}` (KFile extended with
  `KFileKind` enum + `pool_index` slot + per-kind release
  callback fired from `KFileDestroy`),
  `kernel/proc/process.{h,cpp}` (new `LinuxFd::kf_handle`
  sidecar field reusing the previous `_pad2` slot — same struct
  size; new helper API: `LinuxFdAllocLowest`,
  `LinuxFdAttachKFile`, `LinuxFdClose`, `LinuxFdDup`,
  `LinuxFdSetCloexec` / `LinuxFdGetCloexec`,
  `LinuxFdInheritFromParent`, `LinuxFdCloseOnExec`,
  `LinuxFdSelfTest`; new `kLinuxFdFlagCloexec` bit),
  `kernel/subsystems/linux/syscall_fd.cpp` (full rewrite of
  dup / dup2 / dup3 / fcntl on the helpers — dup3 honours
  `O_CLOEXEC`, fcntl(F_GETFD/F_SETFD) reads/writes the per-fd
  bit, F_DUPFD_CLOEXEC stamps it on the new fd),
  `kernel/subsystems/linux/syscall_file.cpp` (DoOpen routes
  through `LinuxFdAllocLowest` for both regular files and
  directory snapshots, honours `O_CLOEXEC`; DoClose dual-
  tracks: drops the KFile ref via `LinuxFdClose` for migrated
  kinds, falls through to legacy `*Release` calls for un-
  migrated ones gated on `kf_handle == kHandleInvalid`),
  `kernel/subsystems/linux/syscall_pipe.cpp` (DoPipe2 +
  DoEventfd2 attach KFile sidecars carrying `&PipeReleaseRead`
  / `&PipeReleaseWrite` / `&EventfdRelease`; `O_CLOEXEC` /
  `EFD_CLOEXEC` honoured),
  `kernel/subsystems/linux/syscall_clone.cpp` (fork inherits
  through `LinuxFdInheritFromParent` which calls
  `HandleTableDuplicate` per occupied slot; the existing per-
  state `*Retain` block stays for un-migrated kinds, gated on
  the same `kf_handle == kHandleInvalid` predicate),
  `kernel/core/main.cpp` (boot-self-test list).
- **Decision:** Each Linux fd is a `LinuxFd` slot (legacy 16-
  entry array on `Process`) plus a `KFile` sidecar living in
  `Process::kobj_handles`. The legacy slot keeps the hot-path
  fields (state, first_cluster, size, offset, path, flags) so
  read / write / lseek / etc. don't pay an indirection cost.
  The `KFile` sidecar carries the per-state pool tag + the per-
  pool release callback; close / dup / fork all drive
  `HandleTableRemove` / `HandleTableDuplicate` so per-pool
  retain/release rides KObject refcounting. The dual-track —
  presence of a `kf_handle` selects KFile semantics, absence
  selects the legacy explicit `*Retain` / `*Release` path —
  lets each remaining kind migrate as its own slice without
  one big atomic landing.
- **Why:** Linux fds are a single per-process namespace with
  fifteen distinct backings; migrating any one in isolation
  forced a dual-track close path anyway. Storing the KFile
  alongside (sidecar) instead of replacing the slot wholesale
  preserves the hot-path zero-indirection access pattern that
  the syscall layer relies on (every read / write / lseek /
  poll handler reaches for `linux_fds[fd].first_cluster` or
  `.offset` directly), while still placing every fd's lifecycle
  on the unified handle table for `HandleTableDrain` at
  process-exit and `HandleTableDuplicate` at fork.
- **Incidental fixes:**
  - **dup() of a pipe / eventfd fd no longer leaks the pool
    ref.** Pre-migration, `CopyFdSlot` copied the pool index
    verbatim without bumping `pool.read_refs` / `write_refs` —
    closing one of the two fds dropped the count to zero and
    woke disconnect under the still-live other fd. Post-
    migration, `LinuxFdDup` calls `HandleTableDuplicate` so
    each fd holds an independent `KFile` reference; the per-
    pool release fires once at the last close.
  - **FD_CLOEXEC is a real per-fd bit now.** Pre-migration was
    a documented sub-GAP (every fd survived exec
    unconditionally). Post-migration, `LinuxFdCloseOnExec`
    walks the table and drops every cloexec-stamped slot;
    creators honour `O_CLOEXEC` / `EFD_CLOEXEC` flag bits.
    `LinuxFdCloseOnExec` is wired for the future execve
    handler and exists today for the boot-time self-test.
- **Capacity tradeoff:** Each Linux fd in the pool-backed
  kinds (3..15) consumes one slot in `Process::kobj_handles`
  on top of its `LinuxFd` slot. Linux fds cap at 16; the table
  has 64 slots; Linux processes don't share `kobj_handles`
  with Win32 mutex/event/sem (different abi_flavor), so the
  worst case is 16 fds + a handful of native KObjects, well
  within budget.
- **Rules out / defers:** Wholesale replacement of the
  `LinuxFd` struct with `KFile*` (the design considered first):
  rejected because read / write / lseek hot paths would pay
  an extra indirection per access. Per-fd open-file-description
  sharing à la real Linux dup() (single offset, single flag
  set across dup'd fds): still a v0 sub-GAP — KFile carries
  per-fd state, not per-open-file-description state. Per-fd
  cwd for `*at` syscalls: still keyed on AT_FDCWD only.
  Migrating the remaining ten state-kinds (socket, timerfd,
  signalfd, epoll, inotify, dirfd, pidfd, POSIX MQ, memfd,
  fanotify): each is a self-contained slice that only needs
  to flip its creator + remove its explicit `*Retain` /
  `*Release` calls; the dual-track logic handles the rest.
- **Revisit when:** A Linux workload demonstrates a corner the
  legacy `LinuxFd` slot data layout can't represent (real
  pidfd polling that needs target-process events, real
  io_uring rings that need `KFile` ↔ pool back-pointers,
  per-FD-CWD `*at` syscalls). At that point the slot fields
  collapse into a single `KFile*` and the hot-path indirection
  cost is justified by the new feature.
- **Related tracks:** Track 1 (Kernel — IPC + handle table),
  Track 4 (Linux subsystem — fd table + creators).
- **Commit:** `da31973`. QEMU smoke (debug profile, OVMF) ran
  every IPC self-test in order — `kobject` → `handle_table` →
  `kmutex` → `kevent` → `ksemaphore` → `kmailbox` → `kwaitable`
  → `kfile` — and the new `[proc] linux-fd-table self-test OK`
  fires immediately after, exercising AllocLowest / AttachKFile /
  Dup / SetCloexec / CloseOnExec / final-Close end-to-end
  including the per-pool release-callback dispatch through
  `KFileDestroy`.

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

---

## 104 — Firewall v0 (rule table + IPv4 in/out hooks + kCapNetAdmin)

- **Scope:** `kernel/net/firewall.{h,cpp}`,
  `kernel/net/stack.{h,cpp}` (per-iface counters +
  `IfaceTx` egress helper + ingress hook in
  `Ipv4HandleIncoming`), `kernel/proc/process.{h,cpp}`
  (`kCapNetAdmin`), `kernel/apps/firewall.cpp` (read-only
  rule list + per-rule hits), `kernel/apps/netstatus.cpp`
  (rx/tx packet + byte columns).
- **Decision:** Static fixed-capacity rule table (32
  entries) evaluated first-match-wins. Each rule carries
  direction, protocol (Any / ICMP / TCP / UDP), src + dst
  prefix, src + dst port range, action (Allow / Deny),
  active flag, hit counter. Default policies are per
  direction and configurable; default to Allow / Allow at
  boot so the existing DHCP / DNS / TCP smoke paths keep
  working. Read access is unprivileged; edit operations
  (FwAdd / FwRemove / FwToggle / FwSetDefaultPolicy) are
  gated on a brand-new `kCapNetAdmin` capability —
  distinct from `kCapNet` so a process can be allowed to
  USE the network without being allowed to RECONFIGURE
  it. Hooks live at IPv4 ingress (after header
  validation) and IPv4 egress (inside `IfaceTx`, the new
  helper every TX site routes through). Per-iface
  counters (`rx_packets`, `rx_bytes`, `tx_packets`,
  `tx_bytes`, `tx_dropped_firewall`, `tx_dropped_unbound`)
  share the same plumbing.
- **Why:** Adding a packet filter without a chokepoint
  invites bypasses — three of the existing TX call
  sites already had subtle differences. Funnelling them
  through `IfaceTx` makes the firewall + counter
  invariants uniform: there is no way to send a frame
  out a bound interface without consulting them. Keeping
  the rule capacity static avoids a kernel allocation
  on every rule edit and matches the v0 expectation
  that a workstation has a small handful of explicit
  rules; promoting to dynamic is reserved for a real
  workload that actually exhausts 32 slots.
- **What it rules out:** Connection tracking ("established
  + related" semantics) is not v0 — flipping the
  default-deny inbound policy on without it would break
  every TCP connect we initiated, since the peer's reply
  would arrive unsolicited. We default Allow inbound
  until conntrack lands. Logging hooks (a bounded ring of
  recent denials for the kernel shell to surface) and an
  editor surface in the desktop firewall app are also
  deferred — the kernel-shell command driver is the v0
  edit path.
- **Revisit when:** A workload demands per-process socket
  policy keyed on `Process::caps` (deny network egress
  for sandboxed PEs entirely) — that's the next major
  slice and unlocks "default-deny inbound + sandbox
  egress lockdown". Conntrack lands when an operator
  legitimately wants Windows-style default-deny inbound
  and a TCP active-open path no longer breaks.
- **Related tracks:** Track 6 (Networking — protocols
  + interfaces), Track 12 (Security — capability gating).

---

## 105 — Lock screen: same-user-only unlock policy

- **Scope:** `kernel/security/login.{h,cpp}`.
- **Decision:** `LoginLock` captures the active username
  (via `AuthCurrentUserName`) into a new `locked_user`
  field on the login state and sets a `locked` flag. Both
  the TTY and GUI submit paths short-circuit before
  `AuthLogin` if `locked` is true and the submitted
  username doesn't match `locked_user`, displaying a
  "LOCKED — USE THE SAME USER OR LOG OUT TO SWITCH" status
  and emitting a serial diagnostic. Successful unlock
  clears both fields; `LoginReopen` (the path the existing
  `logout` shell command takes) also clears them so a
  fresh login is unconstrained. If `LoginLock` fires with
  no active session (programmer error — locking an empty
  desktop), the lock policy is not engaged so the box
  doesn't become unreachable.
- **Why:** Win9x-style "any valid user can unlock" was a
  documented gap on the LOCK action — useful for v0 boot
  bring-up but a clear regression once multi-user accounts
  landed in the auth database. The fix is small (one
  policy field plus one short-circuit on the submit path)
  but couldn't be retrofitted without committing to
  capturing the active user at lock time, which means a
  defined behaviour for locking an empty desktop.
- **What it rules out:** Idle-timeout auto-lock (no kernel
  idle source today; needs a per-input-event timestamp +
  a scheduler-tick comparator) and an on-screen "switch
  user" affordance distinct from `logout` (a different
  user must currently log out the locker first to reach
  the gate, mirroring an early-Windows-NT discipline).
- **Revisit when:** A workload demands automatic lock
  after N minutes of input idle, or an on-screen
  affordance that does what `LoginReopen` does without
  the locker having to type the `logout` command first.
- **Related tracks:** Track 12 (Security — auth gate).

---

## 106 — Device Manager: USB section + Network Status FW-DROP column

- **Scope:** `kernel/apps/devicemgr.cpp`,
  `kernel/apps/netstatus.cpp`.
- **Decision:** Device Manager renders two sections — PCI
  devices (existing) and USB devices (new) — by walking
  `XhciControllerAt(i)->ports[]` per xHCI controller and
  printing `controller_idx port_num VID:PID speed
  class_label hid_hint` for every connected port. Network
  Status grows a `FW-DROP` column reading
  `InterfaceCountersRead(i).tx_dropped_firewall`. Both
  reads are unprivileged — these surfaces are diagnostic.
- **Why:** Decision 104 added per-iface counters and the
  firewall verdict path but stopped short of surfacing
  `tx_dropped_firewall` in the app — it stayed a
  diagnostic on the kernel side. Closing that loop costs
  one column. Device Manager's PCI-only view was a known
  gap; xHCI already populates `PortRecord` with
  vendor/product/class/HID-classifier on every successful
  enumeration, so adding the second section is a render
  change, not a discovery change.
- **What it rules out:** The new sections do not merge
  hot-unplug events (no driver path supports it) and do
  not yet render virtio child enumeration (no virtio bus
  walker today). `Eject` is also not gated yet — the
  whole surface is read-only by design until the
  unplug-capable path lands.
- **Revisit when:** A virtio bus walker lands and it makes
  sense to merge its devices into the same tree, or
  hot-unplug becomes possible and the surface needs an
  `Eject` button (gated on a new `kCapDeviceAdmin`).
- **Related tracks:** Track 9 (Drivers — buses), Track 13
  (UX — apps).

---

## 107 — Firewall shell command + Network Status routing/DNS surface

- **Scope:** `kernel/shell/shell_network.cpp`,
  `kernel/shell/shell_dispatch.cpp`,
  `kernel/shell/shell_internal.h`,
  `kernel/apps/netstatus.cpp`.
- **Decision:** A new `firewall` shell command exposes
  every `FwAdd` / `FwRemove` / `FwToggle` /
  `FwSetDefaultPolicy` / `FwSnapshot` / `FwStatsRead` /
  `FwInit` operation through a uniform argv parser. Names
  are deliberately distinct from the existing `fwpolicy`
  / `fwtrace` commands (which target firmware loading,
  not the packet filter). Network Status grows a routing
  / DNS section pulled from `DhcpLeaseRead()` showing
  GATEWAY, DNS resolver, DHCP server, and lease seconds.
  Both surfaces are unprivileged reads (configuration is
  not secret); edit operations through the shell run in
  the trusted profile so `kCapNetAdmin` is satisfied
  automatically.
- **Why:** The firewall API landed in #104 with no
  text-mode operator surface — only the read-only
  desktop app. A real audit ("did the rule I added
  actually take effect? what's been denied so far?")
  needs a kernel-shell equivalent. Network Status
  similarly had counters but no routing context — a
  user looking at "why doesn't ping reach the gateway"
  needed an external command to see what gateway the
  stack thought it had.
- **What it rules out:** Per-iface DHCP lease (only one
  global lease today — the stack tracks one transaction
  at a time) and a desktop firewall editor. The shell
  driver is the v0 edit path; promoting to a desktop
  widget waits for an interactive widget framework
  bound to caps.
- **Revisit when:** Multiple concurrent DHCP transactions
  ship and per-iface lease tracking lands, or a workload
  needs an interactive desktop firewall editor that
  doesn't reach through the kernel shell.
- **Related tracks:** Track 6 (Networking), Track 13
  (UX — apps).

---

## 108 — Lock-screen idle-timeout auto-lock

- **Scope:** `kernel/security/login.{h,cpp}`,
  `kernel/drivers/input/ps2kbd.cpp`,
  `kernel/drivers/input/ps2mouse.cpp`,
  `kernel/core/main.cpp`.
- **Decision:** Every kbd / mouse ingest path stamps a
  global `g_input_last_activity_ticks` via
  `core::InputActivityStamp`. A dedicated `idle-lock`
  task (`SchedSleepTicks(100)` per iteration — 1 Hz at
  the scheduler's 100 Hz tick) computes
  `now - last_activity` and calls `LoginLock()` once the
  gap exceeds the configured threshold AND a session is
  active AND the gate isn't already up. Threshold
  defaults to 600 seconds (10 minutes) and is
  configurable per-boot via the `idlelock=<seconds>`
  kernel cmdline token; 0 disables auto-lock entirely.
  The activity stamp is a single 64-bit aligned
  variable; reads use a single load, writes happen
  inside the existing Cli/Sti bracket of each input
  driver — no new lock. The watcher takes
  `CompositorLock` itself when it transitions to
  locked, matching the discipline the kbd-reader thread
  uses for `LoginFeedKey`.
- **Why:** The same-user-only unlock policy from #105
  closed the "any user can unlock a locked desktop"
  hole, but the gap that comes BEFORE that — "operator
  walks away, screen never locks" — was still open.
  The roadmap entry called out the dependency on a
  per-input-event timestamp and a tick comparator;
  both are cheap and well-defined. Sticking the watcher
  in its own task avoids inflating the keyboard-reader
  thread's responsibilities and keeps the periodic
  check off the IRQ path.
- **What it rules out:** An on-screen "switch user"
  affordance distinct from `logout` — that's still
  pending. The auto-lock fires only on full operator
  idleness; no per-feature exemptions (e.g. "don't
  lock during a long-running build" requires the
  application to call `InputActivityStamp` itself
  periodically, which we explicitly chose NOT to ship
  as a syscall in v0 — granting a process the ability
  to defer lock would require a cap and a UX
  affordance).
- **Revisit when:** A workload needs per-feature lock
  exemption (a media player suppressing screensaver
  during playback, etc.), or the on-screen switch-user
  affordance lands and needs to interact with the
  auto-lock timing.
- **Related tracks:** Track 12 (Security — auth gate),
  Track 4 (Input — kbd / mouse pipelines).

---

## 109 — Firewall conntrack-lite + denial-log ring + Ctrl+Alt+S switch-user

- **Scope:** `kernel/net/firewall.{h,cpp}`,
  `kernel/shell/shell_network.cpp`,
  `kernel/security/login.{h,cpp}`,
  `kernel/core/main.cpp`.
- **Decision:** Three layered additions to the firewall
  + auth gate:
  1. **Conntrack v0** — every egress packet whose proto
     is TCP / UDP and that no rule explicitly matched
     registers a `(proto, local_ip, local_port, peer_ip,
     peer_port)` entry. Capacity 64; LRU eviction; TTLs
     300 s (TCP) / 60 s (UDP); refresh on each match.
     On ingress, when no rule matches AND the default
     policy would be Deny, the firewall consults
     conntrack for the reverse-direction tuple before
     logging — a hit yields Allow. Models "established
     connections accepted" without doing real TCP-state
     tracking.
  2. **Denial log** — bounded ring (32 slots) capturing
     every Deny verdict with its 5-tuple, direction,
     timestamp, and matched rule index (or `kFwMaxRules`
     when the default policy fired). Surfaced via
     `FwLogSnapshot` / `FwLogTotalCount` and the new
     `firewall log` shell subcommand. `firewall stats`
     gains conntrack counters
     (`inserts`/`hits`/`evictions`).
  3. **Switch-user affordance** — `Ctrl+Alt+S` on a
     locked GUI (active session, gate up because
     `LoginLock` fired) clears the lock policy, calls
     `AuthLogout`, and re-opens the gate. The locked
     GUI grows a footer hint identifying the locker
     and the chord. On a non-locked gate (fresh boot,
     no active session) the chord routes to
     `LoginFeedKey` like every other keystroke.
- **Why:** With conntrack in place an operator can
  finally `firewall default in deny` without breaking
  outbound TCP / UDP replies. The denial log closes the
  observability hole the rule table created — without
  it, a "why is this connection failing" question
  needs an external sniffer. The switch-user chord
  fills the last gap from #105 / #108: the locker
  could trap a different user under their lock policy
  with no escape short of `logout` (which they
  couldn't reach without unlocking).
- **What it rules out:** Real TCP-state-aware conntrack
  (SYN / FIN / RST observation, half-open timeouts).
  Per-process socket policy keyed on `Process::caps`.
  An interactive desktop firewall editor. All three are
  follow-up slices.
- **Revisit when:** A real workload exercises the
  default-deny inbound policy long enough that the
  TTL-only conntrack lets stuck half-opens leak;
  per-process firewall comes when a sandboxed PE
  needs network egress restricted but not denied
  outright.
- **Related tracks:** Track 6 (Networking), Track 12
  (Security — auth gate).

---

## 110 — TCP-state-aware conntrack + firewall app log/conntrack panels

- **Scope:** `kernel/net/firewall.{h,cpp}`,
  `kernel/net/stack.cpp`, `kernel/apps/firewall.cpp`.
- **Decision:** `FwEvaluate` grew a `tcp_flags` u8
  argument that the IPv4 ingress / egress hooks fill
  from the TCP header (offset 13). Conntrack entries
  carry a `TcpState` enum (NEW / Established / FinWait
  / Closed); transitions are driven by SYN / SYN+ACK /
  FIN / RST observation per direction. Per-state TTLs
  replace fixed proto TTLs: NEW=30 s (catches
  abandoned half-opens), Established=300 s, FinWait=
  60 s, Closed=10 s (drains the slot quickly after
  clean teardown). UDP / Any keep a single fixed TTL
  in Established. The desktop firewall app now renders
  the active conntrack entries (proto + state + local
  + peer, top 4) and the recent-denials list (top 4)
  underneath the rule table.
- **Why:** Decision 109's conntrack-lite was a
  TTL-only timer; a stuck half-open kept its slot for
  the full Established TTL, and there was no signal to
  the operator that the connection had progressed past
  setup. Folding state observation into the same
  refresh path costs one byte of struct + a
  six-line state machine and makes the LRU eviction
  pressure proportional to how connections are
  actually used. The firewall-app panels close the
  observability loop the kernel-shell `firewall log`
  / `firewall conntrack` opened in #109 — an operator
  with a desktop session no longer has to drop to the
  kernel shell to see why a connection failed.
- **What it rules out:** Window scaling / sequence-
  number tracking, real conntrack helpers (FTP control
  channel triggering data channels, etc.), and SYN
  cookies. Those land if a workload demands them; the
  v0 state machine intentionally stays a
  short-and-correct subset.
- **Revisit when:** A workload exposes timing edges
  the four-state machine misses — e.g. simultaneous
  open, half-close-then-data, or RST-after-FIN
  pathologies. Standard recommendation is to grow
  the enum first, then revisit per-state TTLs.
- **Related tracks:** Track 6 (Networking), Track 13
  (UX — apps).

---

## 111 — Crash-dump persistence to NVMe reserved LBA region

- **Scope:** `kernel/drivers/storage/nvme.{h,cpp}`,
  `kernel/diag/minidump.{h,cpp}`,
  `kernel/shell/shell_storage.cpp`,
  `kernel/core/main.cpp`.
- **Decision:** Reserve the LAST
  `kNvmeDumpReservedSectors` (8192 sectors = 4 MiB at
  512B / 32 MiB at 4K) of NVMe namespace 1 for crash
  dumps. The minidump emit path
  (`EmitMinidump` / `EmitMinidumpFromTrapFrame`) calls a
  new `NvmePanicWriteDump` after the existing debugcon
  egress; the writer chunks the buffer through
  `NvmeDoIo` per command (bounded by the staging
  buffer + MDTS), busy-waits on the CQ phase tag (the
  regular polled path), and reports both
  fully-succeeded and partial-write outcomes via
  `NvmePanicWriteSucceededLast` /
  `NvmePanicLastWriteBytes`. A new
  `DiskPersistSelfTest` runs after `NvmeInit` so the
  full path is exercised at every boot — the synthetic
  dump it writes gets overwritten cleanly by the next
  real panic. The `lastdump` shell command surfaces the
  on-disk LBA + byte count + success status. NVMe
  staging buffer + CQ + DMA pages are all allocated at
  driver init, so the panic path adds zero allocations.
- **Why:** Decision-deferred in earlier roadmap text:
  the bytes-access foundation
  (`AccessLastMinidump`) was in place but no consumer
  shipped. The polled NVMe path that the regular
  block layer already used was already
  scheduler/slab-free; the only gap was wrapping it in
  a chunker that took an arbitrary byte buffer and
  routing it to a stable LBA range. AHCI gets the same
  treatment when a workload demands it; v0 picks NVMe
  because QEMU's `-device nvme` makes the verification
  path real.
- **What it rules out:** AHCI panic-write parity (same
  shape applies but the AHCI driver doesn't have the
  helper yet), and a partition-table reservation for
  the dump region (the last 4 MiB of namespace 1 is
  trusted to be unused — true for the shipped scratch
  image, not guaranteed on real hardware until the
  disk installer lands). Multi-controller dumps also
  out of scope: only namespace 1 of the FIRST NVMe
  controller is reserved.
- **Revisit when:** A real-hardware panic shows the
  dump region collided with workload data (partition
  table reservation needed), or AHCI/SATA becomes the
  primary storage path on a target machine and needs
  the same write.
- **Related tracks:** Track 7 (Storage / FS), Track 11
  (Diagnostics — minidump / panic surface).


## ModuleState enum is 3-valued, not 6 (2026-05-05)

- **Decision:** The operator-visible `core::ModuleState` enum
  has three values — `Stopped`, `Running`, `Crashed` — not the
  six (`Stopped`, `Starting`, `Running`, `Stopping`, `Crashed`,
  `Restarting`) a textbook lifecycle would suggest.
- **Why:** `init` and `teardown` are non-yielding under the
  single-writer fault-domain registry. Transient
  `Starting` / `Stopping` / `Restarting` would never be observable
  to a reader: the same call that flips `Stopped → Starting`
  flips `Starting → Running` synchronously. The intermediate
  values would surface only if a reader happened to interrupt
  a writer mid-call, which can't happen on the single-CPU
  heartbeat path that owns the registry. `Crashed` is the only
  new state worth distinguishing from `Stopped` because they
  answer different operational questions ("operator stopped me"
  vs "trap landed in my code, watchdog hasn't drained yet").
- **Why not (alternatives considered):**
  - **Six-valued**: dead complexity. Every state name a reader
    can see has to be documented + tested; making three of
    them unreachable is anti-bloat by definition.
  - **Two-valued (`Stopped` / `Running`)**: loses the "fault
    just tripped" signal an operator wants to see. `Crashed`
    is the difference between "I asked to stop this" and "this
    crashed and is about to come back."
- **Revisit when:** SMP runqueues land and the registry grows
  to support per-CPU restart paths. If two CPUs can drive a
  domain's lifecycle simultaneously, the transient states
  become observable and we'd need to expand the enum.
- **Related tracks:** [Kernel Modularization](../security/Kernel-Modularization.md),
  [Runtime Recovery](../security/Runtime-Recovery.md).

## Fault-domain registry capacity is 48 (2026-05-05)

- **Decision:** `core::kMaxFaultDomains` is 48 — not 16 (the
  initial v0 cap) and not unbounded.
- **Why:** Roughly 30 subsystems are restartable per the
  foundation-vs-restartable classification in
  [Kernel Modularization](../security/Kernel-Modularization.md).
  20 are already registered today; 48 gives 50% headroom for
  follow-up migrations without forcing a registry rebuild.
  Linear scans (`FaultDomainTick`, `FaultDomainFind`) stay
  trivial at this size — one cache line per few rows.
- **Why not (alternatives considered):**
  - **Unbounded (heap-allocated):** the registry is consulted
    from the trap handler's heartbeat tick where every alloc
    is a risk. Fixed-size keeps that path lock-free /
    alloc-free.
  - **128 or 256:** YAGNI — even with full migration of every
    restartable subsystem we don't reach 48. The bigger array
    is dead memory the kernel image carries forever.
- **Revisit when:** Migration of the wave-1 + wave-2 modules
  pushes the actual count past 36 (75% of capacity); raise to
  64 then.
- **Related tracks:** [Kernel Modularization](../security/Kernel-Modularization.md).

## Per-domain crash dump is non-fatal and lives in its own TU (2026-05-05)

- **Decision:** `BeginDomainDump` / `EndDomainDump` are
  separate APIs from `core::BeginCrashDump` / `EndCrashDump`,
  emitted from `kernel/security/domain_dump.cpp`, never call
  `SerialEnterPanicMode`, never broadcast NMI, never halt.
  The dump goes to serial **and** an in-kernel ring of the
  last 8 records per domain (replayable via `module dumps`).
- **Why:** Re-using the panic crash-dump path for non-fatal
  domain crashes would dilute the panic semantics — that
  path's reader assumes the kernel is dead. A separate emitter
  keeps panic.cpp focused on its one job and lets the heartbeat-
  side fault-react drain emit dumps without touching panic
  state.
- **Why not (alternatives considered):**
  - **Halt-on-dump:** defeats the entire modularization point.
  - **Disk persistence:** depends on a writable FS that is
    itself a managed module — bootstrap problem. Serial +
    in-kernel ring is enough for v0; QEMU serial capture
    plays the role of "disk."
- **Revisit when:** A non-foundational FS module (ramfs is the
  obvious candidate) is willing to host `/var/crash/` and
  accept the bootstrap-ordering complexity of being writable
  before the dump path needs it.
- **Related tracks:** [Kernel Modularization](../security/Kernel-Modularization.md).

## SMP scheduler join: per-CPU runqueues, lock-passing, work-stealing, reschedule-IPI (2026-05-06)

- **Decision:** Land the full SMP scheduler arc in six small
  commits — lock-passing across `ContextSwitch`, per-CPU
  runqueue data layout with `Task::last_cpu` cache affinity,
  per-AP GDT/TSS/IST stacks, reschedule-IPI on vector 0xF8,
  AP scheduler join via `SchedEnterOnAp`, and work-stealing
  in `RunqueuePopRunnable`. All under a single global
  `g_sched_lock` for now — data structures are per-CPU; lock
  granularity is not.
- **Why:** APs were halting at `cli; hlt` after LAPIC enable;
  every kernel task ran on the BSP. Six small commits keep the
  bisect window tight (each commit is UP-equivalent until
  commit 5 lights up multi-core). The lock-passing slot lives
  in `cpu::PerCpu` (not `Task`) because the slot identifies the
  lock THIS CPU just acquired; the resumed task is irrelevant.
  Cache-affinity routing via `last_cpu` keeps hot tasks on the
  CPU running them; work-stealing balances when a CPU is idle.
- **Why not (alternatives considered):**
  - **Per-CPU lock split now:** the lock-order graph for
    Schedule's kill-path (zombies + reaper wake) versus
    OnTimerTick (sleep queue + wake-from-WQ) versus
    WaitQueueWakeOne is non-trivial. Single global lock is
    correct and meets v0 contention budget; per-CPU split is a
    tractable follow-up when profiles justify it.
  - **Lock-pass slot on Task:** wrong — Tasks migrate between
    CPUs, but the slot tracks "the lock THIS CPU just
    acquired." Per-CPU is correct.
  - **Steal half / proportional steal:** steal-one keeps the
    lock-held window short and is sufficient for v0 balance.
  - **CPU affinity masks / priorities / RT class:** out of
    scope; deferred to Roadmap B3.
  - **Per-CPU sleep queue:** the sleep queue is touched once
    per OnTimerTick + each Sleep call, much less contended
    than the runqueue. Stays global.
- **Revisit when:** Profiles show `g_sched_lock` contention
  (split per-CPU), or a workload exposes IST exhaustion on an
  AP (extend per-AP IST stacks beyond 4 KiB), or
  heterogeneous-package hardware exposes per-CPU LAPIC
  frequency variance (per-CPU LAPIC calibration).
- **Related tracks:** [Scheduler](../kernel/Scheduler.md),
  [SMP-AP-Bringup-Scope](../advanced/SMP-AP-Bringup-Scope.md),
  Roadmap B2-followup.

## CPU topology + locality-aware work-stealing — cluster collapse rule (2026-05-06)

- **Decision:** the scheduler treats each CPU as belonging to one
  cluster, identified by `cpu::PerCpu.cluster_id` (a `u16`
  appended to `PerCpu` past the syscall-stub-relevant offsets).
  Cluster IDs are assigned once at boot using the **innermost
  meaningful grouping** rule:
  1. ≥2 distinct NUMA nodes (from ACPI SRAT) → cluster = numa_node.
  2. Else ≥2 distinct packages (from CPUID 0x1F / 0x0B / leaf-4
     fallback) → cluster = package_id.
  3. Else single cluster — every CPU gets `cluster_id = 0`.
  `StealNormalFromPeer` does a two-pass round-robin scan: pass 0
  visits same-cluster peers only, pass 1 visits cross-cluster.
  On a single-cluster machine pass 0 covers every peer (no
  regression vs. the pre-clustering scheduler).
- **Why:** matches the cache topology a steal would actually
  benefit from. NUMA nodes are the natural cluster on multi-
  socket workstations; package IDs are the natural cluster on
  single-socket multi-die desktops (Threadripper, Sapphire
  Rapids); UMA single-package boxes collapse to one cluster
  with zero scheduler-side overhead. The collapse keeps the
  cluster vocabulary the same across SKUs.
- **Why not (alternatives considered):**
  - **Always cluster by package:** wrong on multi-socket NUMA
    boxes — two packages can live on the same node, and you
    want the stealer to prefer in-node first.
  - **Always cluster by NUMA node:** wrong on multi-die single-
    socket boxes — without an SRAT entry the kernel would
    treat them as one cluster and lose the L3 locality signal.
  - **Always expose hierarchy (node ⊇ package ⊇ core):** the
    extra level helps placement and migration cost models, but
    the steal path only needs one bit of "near vs far". Defer
    until placement affinity / migration cost lands.
- **Trampoline rendezvous:** `cpu::TopologyInitAp(cpu_id)` runs
  inside `ApEntryFromTrampoline` immediately **before** the
  `online_flag = 1` write. The BSP's existing `WaitForApOnline`
  poll therefore doubles as the rendezvous on AP topology
  decode, so `TopologyAssignClusters()` after `SmpStartAps()`
  returns is race-free without a separate done flag. Putting
  the call inside `SchedEnterOnAp` instead would race the BSP,
  which already considers the AP "online" by then.
- **Failure handling:** any decode or SRAT failure is non-fatal.
  `kTopologyParseFailed` probe fires, the affected CPU stays at
  `cluster_id = 0`, and locality stealing degrades to round-
  robin for that CPU. No panic.
- **Revisit when:** the NUMA-aware page allocator lands (will
  consume the same `numa_node` field), or per-cluster runqueue
  splits go in (Roadmap B2-followup), or x2APIC IDs above 255
  appear on hardware we care about (current SRAT parser caps at
  `kMaxApicId = 256`).
- **Related tracks:** [CPU Topology](../kernel/CPU-Topology.md),
  [Scheduler](../kernel/Scheduler.md), Roadmap entry
  "Topology-driven follow-ons".

## Microbenchmark harness as a sibling of loadtest, not a fork of perf (2026-05-06)

- **Decision:** the kernel ships a `bench` shell command in
  `kernel/shell/shell_bench.cpp` (sibling of `shell_loadtest.cpp`)
  that produces fixed-workload cycles/op + ns/op + ops/sec
  numbers for four hot paths (KMalloc round-trip, uncontended
  `sched::Mutex`, `SyscallDispatch(SYS_GETPID)`, `KEvent`
  wakeup). The harness reuses the boot-time HPET-derived TSC
  calibration via two new public helpers in `kernel/time/`:
  `time::ReadTsc()` (hoisted out of an anonymous namespace) and
  `time::TscToNanos(u64 cycles)` for cycle→ns conversion. Wakeup
  bench routes the worker's first wake to a peer CPU using a new
  `sched::SchedSetAffinity(Task*, u32 cpu_id)` hint that writes
  `Task::last_cpu` under the existing scheduler spinlock.
- **Why:** `loadtest` (stress) and `perf` (statistical sample
  ring) cover orthogonal axes — fairness/OOM behaviour and
  "where did we spend cycles?" — but neither answers "how fast
  is hot path X under a fixed workload?" The recent SMP
  scheduler work (per-CPU runqueues, work-stealing, reschedule-
  IPI) makes scheduler-wakeup-latency benchmarks meaningful for
  the first time, and a regression sentinel for the dispatcher
  path is cheap to maintain once the harness exists.
- **Why not (alternatives considered):**
  - **Extend `perf` with a microbench mode:** wrong shape —
    `perf`'s sample ring measures emergent cost across whatever
    workload happens to be running; bench measures specific
    paths under deliberate workloads. Mixing the two would
    blur both.
  - **Extend `loadtest` with a `measure` subcommand:**
    loadtest's contract is "stress until something breaks";
    bench's contract is "complete in well under one second
    and report a number." Two contracts, two TUs.
  - **Bench from a userland helper (PE or native) instead of
    a kernel shell command:** would require the userland to
    issue every primitive it wants to measure (no way to bench
    the dispatcher itself from outside it), and would conflate
    the bench timer with userland scheduling jitter.
  - **Hard CPU pin via affinity mask:** the wakeup bench only
    needs the FIRST wake routed to the peer; the existing
    `last_cpu = CurrentCpu()` write at the context-switch site
    keeps subsequent wakes pinned. A full per-task affinity
    mask is deferred to Roadmap B3.
- **What it rules out / defers:** no PMU / IA32_PERFEVTSEL
  programming (perf's NMI sampling owns hardware-event
  sampling); no persistent results storage (output to console
  + boot log only — `/sys/bench/` is a follow-up once `/sys`
  exists); no comparison-vs-baseline or statistical-confidence
  reporting in v0 (mean over ITERS is the only summary).
- **Revisit when:** a regression detector is needed (then add
  baseline storage + delta reporting); a real userland needs
  to measure the same paths (then port the harness primitives
  to a userland tool that issues int 0x80 directly to
  measure the full ring-3 round-trip); hardware-event sampling
  becomes useful enough to integrate (then a `bench --pmu`
  surface delegates to `perf`'s ring rather than reimplementing).
- **Related tracks:** [Shell Commands](Shell-Commands.md),
  [Scheduler](../kernel/Scheduler.md), Roadmap entry "Bench
  follow-ups".

## Single-bbox damage tracking, not a rect list, for the v0 framebuffer present pipeline (2026-05-06) — SUPERSEDED

> **Superseded by the disjoint-rect banded path in `FramebufferPresent`** (see `kernel/drivers/video/framebuffer.cpp` around `g_damage_rect_count` / `g_damage_rects[]`). The accumulator is still single-bbox per the original decision, but `FramebufferEndCompose`'s content diff promotes spatially-separated changes into a list that the present hook fires once per rect, removing the "D1 flicker" caused by a caret-blink + clock-tick fusing into one fullscreen union. The original decision below stands as a v0 record of WHY single-bbox accumulation was chosen; the disjoint-rect promotion at present time was the right escape hatch and lands without changing the accumulator's cost or shape.


- **Decision:** the framebuffer driver
  (`kernel/drivers/video/framebuffer.{h,cpp}`) accumulates one
  axis-aligned bounding box of dirty pixels per compose pass.
  Every primitive that writes pixels (`PutPixel`, `FillRect`,
  `Blit`, `BlendFill`, `FillRectGradient`) routes its post-
  clip rect through an internal `MarkDamage` helper that unions
  with the running bbox. `FramebufferEndCompose` copies only that
  bbox from the shadow buffer to the live framebuffer;
  `FramebufferPresent` hands the same rect to the registered
  present hook, which on virtio-gpu becomes
  `VirtioGpuFlushScanout(x, y, w, h)`. A clean compose pass
  (`damage.valid == false`) skips the flush entirely.
- **Why:** the chrome-only frames the compositor produces
  thousands of times per session (cursor blink, taskbar clock
  tick, focus pulse) only touch a handful of small rects. Before
  this slice every present uploaded the full surface
  (`width * height * 4` bytes) over the virtio-gpu transfer ring
  AND ran a full-surface shadow→live blit; both were dominated
  by chrome that had already been drawn. The bbox tracker turns
  a 1024×768 cursor-blink frame from 786 432 pixels of work
  into ~256, with no per-pixel cost in the inner loops (only
  one update per primitive call, hoisted out of the tight
  store loop). The present hook also picks up a "skip the
  whole thing" fast path for frames where the compositor wrote
  nothing.
- **Why not (alternatives considered):**
  - **No tracker (status quo):** burns full-surface bandwidth
    every present even when nothing changed. virtio-gpu's
    transfer cost is the bottleneck; making it proportional to
    work done is the obvious win.
  - **Per-window damage list (`DirtyRegion[]`):** the right
    answer for a desktop with many small disjoint changes
    (cursor blink in one corner + clock tick in another), but
    overkill for v0. The compositor today still walks every
    window and re-draws chrome the same way it always has, so
    the disjoint-rect case is rare relative to "this whole
    window repainted." Adding a list now would require either a
    fixed cap (artificial limit) or an allocator on the present
    path (kheap pressure on a hot path) to handle pathological
    counts. Single-bbox keeps the per-frame cost constant.
  - **Hardware scissor / region clip:** GPUs can do this cheaply
    on the host side, but we don't yet have a real hardware
    GPU driver — virtio-gpu's API takes a flush rect, full
    stop. Hardware scissors land when we have a real GPU
    command queue, not before.
  - **Per-tile dirty bitmap:** very efficient for sparse damage
    on large surfaces (think 4K) but memory and bookkeeping cost
    is fixed per-tile and dwarfs the v0 surface sizes. Revisit
    when the active framebuffer crosses ~8 megapixels.
- **What it rules out / defers:** disjoint damage rects (a
  cursor in one corner + a clock in another currently flushes
  the bbox spanning both); per-window damage tracking the
  compositor could use to skip whole windows; hardware-side
  scissor / region. None of those are required for the
  bandwidth win the v0 chrome-only frames produce.
- **Revisit when:** the compositor grows a "this window is
  unchanged, skip its draw call entirely" pass (then per-
  window rects feed naturally into a list-of-rects damage
  surface); a real GPU driver lands with a scissor primitive;
  the active framebuffer routinely crosses ~8 megapixels (4K
  desktop, multi-monitor) and the chrome-only frame's bbox
  starts pulling in too many pixels.
- **Related tracks:** [Graphics Drivers](../drivers/Graphics-Drivers.md),
  [Compositor and Window Manager](../subsystems/Compositor.md),
  Roadmap entry "Multi-monitor / runtime resolution change".

## Task Manager v1 — per-task list with sort + kill (2026-05-07)

- **Decision:** the Task Manager window flips from a 7-row
  aggregate-stats panel (uptime / ctx-switches / TASKS LIVE /
  MEM FREE counters) to a Windows Task Manager / `htop` style
  per-task list. The implementation lives in
  `kernel/apps/taskman.{h,cpp}`, registered via `TaskmanInit`
  on the existing window handle. Each row shows PID, name,
  state, since-boot CPU%, on-CPU tick count. Header line
  carries CPU% / IDLE% / MEM MiB / live task count. Keyboard:
  `↑`/`↓` move selection, PgUp/PgDn page-step, Home/End jump,
  `S` cycles sort (CPU% → PID → NAME → STATE), `K` / Del opens
  a kill-confirm `MessageBoxOpen` for the selected PID.
- **Why:** an OS that exists for users needs an answer to "what
  is running and why is it slow?" The old panel showed seven
  global counters and could not name a single task — useless
  for triage. `SchedEnumerate` already exposed every field a
  proper list needs (id, name, ticks_run, owner_pid, state,
  is_running) and `SchedKillByPid` already wired the
  termination path; no new kernel primitive was needed.
- **What was considered + rejected:**
  - **Per-task instantaneous CPU%:** would require keeping a
    shadow table of `prev_ticks_run` per task id between
    redraws. Since-boot CPU% (`ticks_run / total_ticks`) is a
    cheaper denominator that matches what `top --cumulative`
    shows, and `is_running` already highlights the on-CPU
    task in green so an operator can see "who's running right
    now" at a glance. Re-derive instantaneous on demand once
    a workload exposes a real user-visible miss.
  - **A kheap-allocated row buffer:** `kMaxRows = 128` snapshot
    on `.bss` keeps the snapshot rebuild allocator-free and
    avoids any "task manager itself triggers OOM" tail risk.
    Tasks past 128 are silently dropped from the listing
    (header's TASKS count still reflects the live total).
  - **Direct callback drawing under SchedEnumerate's CLI:**
    rejected because the framebuffer path is heavy; build the
    snapshot first, then sort + draw with interrupts back on.
- **What it rules out / defers:** no per-process memory column
  (would need to walk Process->as->regions table — defer until
  Process exposes a `MemUsage()` accessor; today it tracks
  `heap_pages` only and that's a partial number). No
  multi-column click-to-sort by mouse — `S` cycles via
  keyboard and that's enough for v1. No process-tree grouping
  by parent PID. No "End Process Tree" recursive kill.
- **Revisit when:** Process gains a `MemUsage()` (then add a
  MEM column); a workload routinely produces > 128 tasks
  (then bump `kMaxRows` or grow to a kheap-backed scrollable
  table); the compositor grows mouse-routed column-header
  clicks (then bind sort cycling to a header click).
- **Related tracks:** [`Start Menu`](../kernel/Start-Menu.md),
  scheduler enumeration (`SchedEnumerate`, `SchedKillByPid`),
  end-user features (the Task Manager bullet on the Roadmap
  used to read "deeper teal panel"; this slice cashes that
  in).

## End-user app feature slate (2026-05-07)

- **Decision:** ship a batch of everyday-OS feature parity items
  on top of the desktop apps that already exist, pulled from
  Windows / macOS / common-Linux conventions:

  1. **Task Manager PERFORMANCE tab** — Tab key cycles
     PROCESSES <-> PERFORMANCE. PERFORMANCE renders two
     stacked 60-sample sparklines for CPU% busy + MEM%
     used, sampled at 1 Hz via the existing UI ticker.
     Bottom row shows 1/5/15-min load averages from
     `LoadavgSnapshot`. (`kernel/apps/taskman.cpp`.)

  2. **Notes find / find-next / find-and-replace** —
     Ctrl+F opens an InputBox seeded with the last query;
     F3 steps to the next match; Ctrl+H runs a two-stage
     "Find:" + "Replace with:" dialog flow. Match
     highlighting reuses the existing selection band.
     (`kernel/apps/notes.cpp` + main.cpp keybinding.)

  3. **Calculator scientific + bitwise + multi-radix preview** —
     keyboard adds `q` sqrt, `x` square, `y` abs, `!`
     factorial, `r` reciprocal, `~` bitwise NOT, plus
     binary `& | ^ < >`. The display strip grew a second
     band that renders the live decimal value as `0xFF` /
     `0b1011...` / `0o377` simultaneously; the calculator
     window grew 220 → 260 px to host the band. Input
     remains decimal — multi-radix is purely visual.
     (`kernel/apps/calculator.cpp`, main.cpp window dim.)

  4. **Files sort modes** — `s` cycles NAME (case-insensitive
     ascending) → SIZE → TYPE (dirs first, alphabetical
     within). Insertion sort over the cached entries arrays
     (kFatMax = 64); selection re-anchors to the prior
     selection's name across re-sort so the cursor doesn't
     snap. (`kernel/apps/files.cpp`.)

  5. **Help reference + main.cpp PrintShortcutHelp synced** to
     advertise every new chord. The two surfaces explicitly
     stay lock-stepped per the kRows comment.

- **Why:** the wiki Roadmap's "End-user features" track listed
  these as known gaps in the everyday-usability story; the
  underlying infrastructure (`SchedEnumerate`,
  `LoadavgSnapshot`, `MessageBoxOpen` / `InputBoxOpen`,
  `FramebufferDrawLine`, the existing per-app draw / feed
  hooks) was already in tree, so each item was a
  straightforward delta on top of what existed. Holistically
  the slate moves DuetOS from "demo desktop" closer to
  "actually usable for everyday text-editing, arithmetic,
  process-monitoring, file-browsing without a mouse."

- **What was considered + rejected per slice:**
  - Per-task instantaneous CPU% (vs. since-last-sample) —
    deferred until a workload exposes the user-visible miss.
  - HLSL bytecode-driven Calculator — way out of scope.
  - Hex / bin / oct INPUT in Calculator — input radix toggle
    is a substantial UX rework (digit-set conflicts with
    memory keys); the multi-radix preview gets the user
    most of the value with no input ambiguity.
  - Files sort by date — DirEntry doesn't expose mtime in
    the v0 FAT32 walker; revisit when it does.

- **What it rules out / defers:** none of these slices changes
  the Win32 / Linux subsystem isolation contract; they all
  live in `kernel/apps/*` content drawers and `core::Cap*` is
  not relaxed. The PROCESSES tab's kill action goes through
  the existing `SchedKillByPid` cap-checked path.

- **Revisit when:** Process gains a per-process MemUsage()
  accessor (Task Manager grows a MEM column); the dialog
  system grows multi-line input (Notes Replace can become a
  single dialog); FAT32 DirEntry exposes mtime (Files sort
  gains DATE).

- **Related tracks:** End-user features (Roadmap),
  [`Compositor`](../subsystems/Compositor.md),
  [`Win32-Surface-Status`](Win32-Surface-Status.md) is
  unaffected.

## End-user app slate, batch 2 (2026-05-07)

- **Decision:** ship a follow-up batch of usability features on
  top of the apps that landed in the first slate:

  1. **Calendar Shift+arrow day navigation** — plain arrows
     keep their month / year semantics; Shift+arrows now step
     the date selection ±1 day (left/right) or ±7 days (up/down).
     `CalendarFeedArrow` grew a `modifiers` parameter (default
     0). View follows the selection so the cell is always
     visible. (`kernel/apps/calendar.cpp`.)

  2. **Calendar event persistence** — `CalendarSave` /
     `CalendarLoad` round-trip the event table to
     `CALENDAR.TXT` on the FAT32 root. One line per event in
     `YYYY-MM-DD\tEVENT\n` form; atomic save mirrors
     `NotesSave`'s tmp + rename. Auto-loads at boot once
     FAT32 is online. Bound to Ctrl+S / Ctrl+O when Calendar
     is the active window. Persist self-test snapshots /
     restores around a round-trip.

  3. **Notes Ctrl+A + Ctrl+G** — select-all + goto-line.
     `NotesSelectAll` anchors the selection at byte 0 with
     the caret at end; `NotesGotoLine(N)` walks the buffer
     counting newlines and parks the caret at line N's first
     column (clamps for out-of-range targets). Ctrl+G opens
     an InputBox; the callback parses + jumps.

  4. **Help live filter** — Help-active-window consumes
     printable ASCII into a 31-char case-insensitive
     substring filter. Section headers survive when at
     least one of their following rows matches, so the
     filtered output stays grouped. Backspace pops; the
     title line shows "TYPE TO FILTER" in dim until the
     first key, then "FIND: <q>" in fg. No-match state
     prints an explicit fallback line.

  5. **ImageView '+' / '-' zoom** — keyboard equivalents of
     the existing Ctrl+wheel zoom. Both grow / shrink the
     window via `WindowResizeFromEdge`; FitThumbnail re-fits
     on the next draw. '+' and '=' both bound (US layout
     unshifted is '='); '-' and '_' both bound, matching the
     same convention every browser uses for its zoom keys.

- **Why:** all five close concrete usability gaps a user
  doing real everyday work hits within minutes — the calendar
  was useless without persistence, Notes had find-and-replace
  but no select-all, the Help table was too long to scan at
  ~70 rows, and ImageView's zoom required the mouse.

- **What was rejected per slice:**
  - Calendar event recurrence (weekly / monthly) — would
    require a richer schema than `YYYY-MM-DD\tTEXT`. Defer
    until a workload exposes the gap.
  - Notes "save selection only" — selection model is single-
    range; multi-cursor is the bigger lift if users need it.
  - Help: section-header click to toggle collapse — needs a
    per-section open/closed state. Defer.
  - ImageView pan when zoomed past the window — current
    FitThumbnail caps at source size; a real zoomed-pan model
    is its own slice.

- **Revisit when:** Process gains MemUsage(); FAT32 grows
  mtime in DirEntry; multi-line InputBox lands; recurring
  events become a real workload.

---

### DD-RUST-001 — Rust toolchain bootstrap via DuetFS v0

- **Scope & commit:** `kernel/fs/duetfs/` (Rust crate) +
  `kernel/fs/duetfs.{h,cpp}` + `kernel/fs/duetfs_block_dev.cpp` +
  `kernel/fs/duetfs_rust_panic.cpp` + `rust-toolchain.toml`. First
  Rust subsystem in the kernel.

- **Decision:**
  1. **Trigger #1 (on-disk filesystem) of the Rust bring-up
     plan is hereby fired.** The toolchain is wired in at
     nightly-2026-01-15 with `rust-src` + `x86_64-unknown-none`
     pinned in `/rust-toolchain.toml`.
  2. **DuetFS is clean-room from RedoxFS** — file lineage is
     called out in source comments and `wiki/filesystem/DuetFS.md`,
     but the on-disk format, build system, and source code are
     written from scratch. RedoxFS's MIT license and B-tree /
     AES-XTS / Argon2 / LZ4 stack are studied as prior art only;
     none of their crates are vendored in v0.
  3. **v0 ships a deliberately tiny on-disk format** — fixed 256 B
     nodes, one contiguous extent per file, flat node table, no
     CoW, no journal, no encryption, no compression. The first
     slice's job is to prove the FFI / build / link / boot self-
     test path works, not to ship a feature-complete FS.
  4. **The image is in-memory only in v0** — synthesized at boot
     into a 16 KiB `.bss` buffer by `BuildSelfTestImage`. Block-
     device backing is a separate slice.
  5. **CMake side is a leaf custom_command** — `kernel/fs/duetfs/
     CMakeLists.txt` runs `cargo build --release --target
     x86_64-unknown-none -Z build-std=core,alloc -Z
     build-std-features=compiler-builtins-mem` and exposes the
     produced `libduetfs.a` to both kernel stages via
     `target_link_libraries`. No new build system; cargo is a
     leaf, not a peer.
  6. **C ↔ Rust contract is hand-mirrored** — `include/duetfs.h`
     (C++) and `src/ffi.rs` (Rust) define the same four-call
     surface (probe / lookup / read_file / panic shim). Bindgen /
     cbindgen are forbidden — short enough that code review
     catches drift.

- **Why:**
  - Trigger #1 fired naturally: the slice parses on-disk metadata
    (a superblock + node table) from a buffer the kernel will
    eventually receive from a block device. That's the exact
    "attacker-controllable byte stream" the bring-up plan named.
  - Clean-room rather than vendor-and-rename keeps the on-disk
    format ours, so future divergence from RedoxFS doesn't fight
    upstream conventions. The cost (writing format.rs / image.rs /
    lookup.rs from scratch) is about 250 lines for v0 — much
    smaller than untangling the RedoxFS adapter layer.
  - Tiny v0 format means the slice ships a working end-to-end
    FFI in one PR without dragging in `aes-xts` / `argon2` /
    `lz4_flex`. Each of those is its own future PR with its own
    blast-radius review.
  - In-memory image keeps the read-path entirely deterministic
    for the boot self-test — no disk dependency, no FAT32-style
    "skip if no volume" branch.

- **What it rules out / defers:**
  - **Vendoring upstream redoxfs.** Re-adopting upstream sources
    would now require rewriting every file we authored.
  - **B-tree / hash-tree directory index.** Flat node table caps
    directories at ~16 entries until that lands.
  - **Multiple extents per file.** Single contiguous extent only.
  - **A second Rust subsystem before the toolchain has been
    proven on this one.** The CMake leaf-target pattern is in
    place; the next crate's CMakeLists is a copy-paste with the
    crate name swapped.
  - **Vendoring redoxfs's encryption/compression stack.** Each
    of `aes-xts`, `argon2`, `lz4_flex`, `seahash` is its own slice
    when the workload that wants it appears.
  - **VFS routing integration.** No `FsType::DuetFs` enum value
    yet — the self-test exercises the FFI directly. Routing lands
    after the block-device backing.

- **Revisit when:**
  - A second Rust crate lands → factor any duplicate CMake bits
    into a `duetos_rust_subsystem(name)` helper function.
  - Block-device backing is wired → DuetFS becomes mountable;
    `FsType::DuetFs` lands; the synthesized self-test image
    moves out of `.bss` and onto a ramdisk image baked into the
    kernel via `embed-blob.py`.
  - First directory grows past ~1000 entries → swap the flat
    child-id list for a B-tree.
  - First file needs to span > one extent → swap to multi-extent.
  - First panic from the Rust side fires in production → tighten
    the `duetos_rust_panic` shim to capture the file:line site
    via `core::panic::Location` (today only the message is
    forwarded).

- **Related roadmap track(s):**
  - Rust bring-up — section in [`Roadmap.md`](Roadmap.md) updated
    from "first crate lands when" → "bootstrapped; remaining
    triggers apply for future crates".
  - Filesystem track — DuetFS becomes the project's native FS
    once the block-device backing slice ships.

---

### DD-FS-DUETFS-V1 — DuetFS v1: write path + free-block bitmap + VFS routing

- **Scope & commit:** `kernel/fs/duetfs/` (Rust crate, near-total
  rewrite of v0) + `kernel/fs/duetfs.{h,cpp}` (kernel adapter) +
  `kernel/fs/duetfs_block_dev.cpp` (Device builders) +
  `kernel/fs/mount.{h,cpp}` (FsType::DuetFs, DuetFsLookup) +
  `kernel/fs/vfs.{h,cpp}` (VfsBackend::DuetFs + VfsNode fields) +
  `kernel/core/main.cpp` (DuetFsBoot + DuetFsSelfTest at boot).

- **Decision:**
  1. **DuetFS jumps from v0 (read-only synthesized image) to v1
     (write path, mounted at boot)** in a single slice. The v0
     surface was a stepping-stone to prove FFI plumbing; production
     workloads need a real read+write FS.
  2. **On-disk format v1 layout** = superblock(1) + free-bitmap(1) +
     node-table(4) + data(rest). 64 nodes max, 128 MiB max image,
     1024 children per directory. Single contiguous extent per
     file with `ext_blocks` headroom (auto-grow via realloc-and-
     copy, double-and-grow strategy).
  3. **Magic bumped from "DuetFS00" to "DuetFS01"; version 1 → 2.**
     v0 images are NOT compatible with v1 readers — there is no
     migration path because v0 was never persistent.
  4. **One Device descriptor for both backends.** `kernel/fs/duetfs/
     include/duetfs.h` declares a single `Device` struct with
     read/write callbacks; the C++ adapter
     (`duetfs_block_dev.cpp`) provides two builders —
     `MakeMemoryDevice` (cookie = a small struct holding buf+len)
     and `MakeBlockHandleDevice` (cookie = the block handle, cast
     through `uptr`). The Rust crate doesn't know which is which.
     This avoids a polymorphic Rust trait at the FFI boundary and
     keeps the crate truly stateless across calls.
  5. **Stateless FFI.** Each `duetfs_*` call constructs a fresh
     `Fs` from the descriptor, performs the op, drops the `Fs`.
     The bitmap auto-flushes on every mutation, so a successful
     return leaves the device consistent. No retained state, no
     handle table.
  6. **VfsNode extended with five duetfs fields**
     (`block_handle / node_id / kind / size / child_count`). Same
     by-value snapshot pattern as the FAT32 backend so callers
     don't have to track FS-internal lifetimes.
  7. **Boot mount lives in `.bss`, not a kernel block-device.**
     `RamBlockDeviceCreate` allocates its own buffer at runtime;
     for the boot mount we want a known address before init runs,
     so the boot image is a static array and the kernel-block-
     handle adapter is exercised by self-test code on a separately-
     created RAM disk in a later slice. The block-handle backend
     IS implemented — it just doesn't drive the boot mount today.

- **Why:**
  - Becoming the project's primary FS requires write capability.
    v0 was a scaffold, not a usable filesystem.
  - Free-bitmap allocator is a real allocator (not bump-only) so
    unlink + truncate-shrink can actually reclaim blocks, not
    leak them. Required for any long-lived workload.
  - Auto-grow on write keeps the per-call API simple — callers
    don't have to call truncate-then-write — at the cost of some
    realloc churn. v0 had no growth semantics at all.
  - VFS routing integration means every kernel caller that already
    speaks the VFS (sandbox enforcement, syscall path resolution)
    transparently sees DuetFS the same way it sees FAT32 and
    ramfs. No special-case code.
  - One descriptor / two backends keeps the build matrix flat —
    a future kernel-block-handle-backed boot mount adds zero new
    FFI surface.

- **What it rules out / defers:**
  - **v0 disk-image compatibility.** No upgrade path; the magic
    bump is a hard wall.
  - **Multi-extent files.** Single contiguous extent forces
    realloc-and-copy on every grow past ext_blocks. Acceptable
    for v1 workloads (small config files, kernel logs); painful
    for large files. Multi-extent is the next FS slice.
  - **Multi-block dirs.** 1024 children/dir is plenty for typical
    `/etc`, `/bin`, `/home/$user` — but not for a sprawling
    `/usr/share`. Bumping the cap requires multi-block dir
    children + a B-tree, both later slices.
  - **Persistent backing.** The boot image lives in `.bss` and is
    lost on reboot. A real on-disk DuetFS partition (probe the
    boot disk, mkfs if blank) is its own slice.
  - **Crash safety.** No journal, no CoW. A crash mid-mutation
    leaves a node and a bitmap entry that disagree. `fsck` lands
    when there's a real workload that crashes.
  - **Free-on-shrink truncate.** Shrinking a file via truncate
    keeps the extent allocated — the wasted blocks become
    unreachable until the file is unlinked or grown again.

- **Revisit when:**
  - First file needs to be > ~256 KiB (the boot image size, and
    where realloc cost first hurts) → multi-extent.
  - First directory grows past 1024 children → multi-block dirs +
    B-tree.
  - First crash-resilience requirement appears → CoW or journal.
  - First reboot test that needs the FS to survive → persistent
    on-disk backing.
  - First time the 64-node cap matters → bump `NODE_TABLE_BLOCKS`
    or move to dynamically-sized node tables.
  - First time a kernel block-device handle gets used to back a
    DuetFS volume → the block-handle adapter (already in the
    tree) becomes the primary path.

- **Related roadmap track(s):**
  - Filesystem track — DuetFS surface flips from "read-only
    proof of concept" to "primary FS with write path".

---

### DD-FS-DUETFS-V2 — DuetFS v2: multi-extent + CRC + fsck + on-disk auto-mount

- **Scope & commit:** `kernel/fs/duetfs/src/format.rs` + new
  `crc32.rs` + new `fsck.rs` + extent-aware `ops.rs` + extent-aware
  `ops_dir.rs::grow_file` + `mkfs.rs` (writes CRC) + `ffi.rs`
  (`duetfs_fsck` + new status codes) + `kernel/fs/duetfs.cpp`
  (boot-time disk probe).

- **Decision:**
  1. **Multi-extent files**: Node carries up to 8 inline extents
     instead of a single contiguous extent. `grow_file` first tries
     to extend the last extent in place (cheap), then allocates a
     new extent if a slot is free, then returns
     `kStatusNoSpaceExtents` (no realloc-and-copy). This drops the
     v1 single-extent constraint without dragging in indirect
     blocks.
  2. **Superblock CRC32 (zlib polynomial 0xEDB88320)** —
     foundation for corruption detection. mkfs writes it; mutation
     paths (today: only fsck-with-repair) rewrite it. `Fs::open`
     verifies on every mount and returns `kStatusCorrupt` on
     mismatch.
  3. **fsck walks the reachable tree, recomputes the should-be
     bitmap, diffs against on-disk.** Optional repair rewrites
     the bitmap and the superblock with a fresh CRC + `free_blocks`.
     Later DuetFS slices added per-block CRCs, orphan detection,
     and parent-chain cycle detection.
  4. **Boot probe + on-disk auto-mount.** Every kernel block-device
     handle that's not a partition view and holds a v2 superblock
     gets mounted at `/disks/duetfs<N>`. Blank devices are NEVER
     auto-mkfs'd — that's a destructive operation that requires an
     explicit user command (in a future userland-shell slice).
  5. **Format-version bump from 2 to 3.** Magic stays
     `"DuetFS01"` to keep the dump tool's grep stable; the version
     field signals the layout difference. v1 images are rejected
     with `kStatusInvalid` (version mismatch) by v2 readers — there
     was no persistent v1 storage in the wild, so the break is
     real but harmless.
  6. **Per-block CRCs deliberately deferred to a follow-up.**
     Storing CRCs alongside data blocks needs either a separate CRC
     region (file-system-wide table) or per-block trailers (cuts
     usable block size). Both are real design decisions — neither
     fits in this slice.

- **Why:**
  - Multi-extent: v1's "realloc-and-copy on grow past extent"
    was correct but quadratic for streaming writes. With 8 inline
    extents, a streaming write that starts at 0 and ends at 32 KiB
    finishes with ≤ 8 allocations and zero copies. The next
    cliff (file > 8 extents worth of capacity) lands when first
    workload hits it.
  - SB CRC: cheap (one CRC per mount + on every mutation today,
    none of those are hot-path), catches torn writes from a power
    loss during the SB write. Per-block CRCs would catch the
    much wider class of "block X is corrupt" — but they're a
    bigger design decision.
  - fsck: necessary the moment there's any persistence story. v2's
    `.bss`-backed boot image doesn't survive a reboot, but the
    on-disk auto-mount path means real disks DO survive — and a
    crash mid-mutation needs a recovery story.
  - Auto-mount on probe (not on mkfs): we never want the boot path
    to silently format a stranger's disk. A blank disk gets ignored
    until a user explicitly says "format this".

- **What it rules out / defers:**
  - **Per-block CRCs.** Only the SB has a CRC in v2; a corrupted
    data block reads stale bytes silently.
  - **CoW / journal.** A crash mid-write to a file's data extent
    can leave the file with garbage at the unflushed offset; v2
    has no protection against torn writes outside the SB.
  - **Indirect extents.** Files needing > 8 extents are out of
    luck. Each extent can be many blocks (single 4-byte u32 length
    field), so the file size cap depends on free-list contiguity,
    not extent count alone.
  - **Multi-block dirs.** Still 1024-child cap.
  - **Auto-mkfs of a blank disk.** Boot probe never formats; that's
    a user shell command.
  - **fsck orphan repair.** Detection lands in a later slice;
    automatic node recycling waits for journaled node-table repair.

- **Revisit when:**
  - First file needs > 8 extents → indirect blocks, new Node field.
  - First crash mid-mutation corrupts user data → CoW or journal.
  - First disk fail surfaces a single bad sector → per-block CRCs.
  - First directory grows past 1024 children → multi-block dirs.
  - First boot of a real disk needs to be auto-formatted → user shell `mkfs.duetfs /dev/...`.

- **Related roadmap track(s):**
  - Filesystem track — DuetFS reaches "primary FS with crash-
    resistant SB". Persistent on-disk volumes mount at boot;
    the next persistence cliff is the journal.

---

### DD-FS-DUETFS-FSCK-DEEP-CHECKS — DuetFS fsck orphan and parent-cycle detection

- **Scope & commit:** `kernel/fs/duetfs/src/fsck.rs` adds a
  bounded root reachability walk plus a per-node `parent_id` chain
  walk. `kernel/fs/duetfs.cpp` extends the self-test by corrupting
  `/hello.txt`'s `parent_id` into a self-cycle and requiring
  `orphan_nodes` to become non-zero before restoring the field.

- **Decision:** fsck now reports live nodes that are unreachable
  from the root directory, have invalid / non-directory parents, or
  whose `parent_id` chain cycles before reaching root. Directory
  child-list walks are bounded by `DIR_MAX_CHILDREN` and invalid
  child IDs / directory storage extents are counted as bad extents
  rather than indexing past the one-block directory format.

- **Why:** link-count drift alone does not catch a reachable node
  with a broken parent chain, nor does it catch an unreferenced node
  whose extents still pin allocator space. The extra fsck pass makes
  those structural failures visible without changing the on-disk
  format.

- **What it rules out / defers:** repair does not recycle orphan
  nodes yet. Until node-table clearing and extent release are
  journaled as one operation, fsck keeps orphan extents pinned in
  the rebuilt bitmap and reports the problem for a future repair
  policy.

- **Revisit when:** node-table mutation repair is journaled; then
  `repair=1` can clear unreachable nodes, free their extents, and
  rewrite the CRC table in the same recovery pass.


---

### DD-FS-DUETFS-TRUNCATE-SHRINK-FREE — DuetFS truncate frees tail extents

- **Scope & commit:** `kernel/fs/duetfs/src/ops.rs` teaches
  `Fs::truncate` to zero bytes that could be exposed by a future
  grow and to free whole tail blocks / extents when shrinking.
  `kernel/fs/duetfs.cpp` extends the self-test to assert that a
  shrink from 8 KiB to 4 bytes keeps exactly one block, then
  re-grows and verifies the exposed range is zero-filled.

- **Decision:** shrinking a file now returns full tail blocks to the
  allocator immediately. The retained partial block is zeroed from
  the new logical EOF to the block boundary covered by the old size,
  and growth zeroes the newly exposed logical byte range.

- **Why:** keeping tail blocks allocated after shrink makes the
  allocator pessimistic and leaves stale bytes available after a
  later grow. Freeing whole-block tails matches normal filesystem
  expectations, and zeroing retained/grown ranges preserves the
  caller-visible truncate contract.

- **What it rules out / defers:** shrinking still works at block
  granularity. DuetFS does not punch sub-block holes or compact
  middle extents; sparse files remain a future format feature.

- **Revisit when:** indirect extents or sparse-file support lands;
  those features should share this zero-before-expose policy while
  avoiding unnecessary full-block rewrites for holes.


---

### DD-FS-DUETFS-READ-CRC — DuetFS read-time data-block CRC verification

- **Scope & commit:** `kernel/fs/duetfs/src/fs.rs` adds
  `Fs::read_data_block`; `ops.rs` routes file and symlink-target
  reads plus partial-block write preserve reads through it;
  `ops_dir.rs` routes directory child-list reads through it;
  `xattr.rs` routes xattr get / list / set / remove block reads
  through it; `kernel/fs/duetfs.cpp` extends the boot self-test to require
  `kStatusCorrupt` on a deliberately flipped data block before
  fsck repair.

- **Decision:** verify per-block CRCs on the DuetFS data-region
  read path. The helper reads the block, recomputes CRC32, compares
  against the cached CRC-table entry, and returns `FsError::Corrupt`
  before any file bytes, symlink target bytes, directory child IDs,
  or xattr records are consumed.

- **Why:** the CRC table already existed and every data write updates
  it in lockstep. Checking it at read time turns the integrity tier
  from an operator-invoked fsck signal into a normal caller-visible
  failure, preventing corrupted directory entries, xattr records, or file
  contents from being used silently.

- **What it rules out / defers:** node-table and bitmap reads remain
  raw in the normal `Fs::open` / `read_node` paths for now. fsck must
  be able to open and inspect a damaged volume to produce a report and
  repair bookkeeping, so metadata hard-fail-on-read is a separate
  policy decision.

- **Revisit when:** the VFS/userland syscall surface needs a richer
  error distinction than `kStatusCorrupt`, or when mount-time policy
  grows a read-only degraded mode for metadata CRC mismatches.


---

### DD-FS-DUETFS-V3 — DuetFS v3: per-block CRCs + symlinks + hard links

- **Scope & commit:** `kernel/fs/duetfs/src/format.rs` (CRC table
  fields, NODE_KIND_SYMLINK, link_count) + new `crc_table.rs` +
  `fs.rs` (caches CRC table, `write_data_block` helper) +
  `mkfs.rs` (initializes CRC table) + `ops.rs` (symlinks +
  hardlinks + write_data_block routing) + `ops_dir.rs` (link_count
  on create) + `fsck.rs` (per-block CRC + link_count verification)
  + `ffi.rs` (3 new fns + 2 new status codes + extended FsckReport)
  + `kernel/fs/duetfs/include/duetfs.h` (mirrored).

- **Decision:**
  1. **Per-block CRC table at LBA 2.** One block, 1024 × u32
     entries, indexed by FS block LBA. Updated in lockstep with
     every data-block write via `Fs::write_data_block`.
     **Verified by fsck only**, not on the read hot path — keeps
     reads cheap until a workload demands stronger guarantees.
  2. **Image cap drops from 128 MiB to 4 MiB.** Single CRC block
     covers 1024 FS blocks. Multi-block CRC tables (lifting the
     cap to 32 MiB / 128 MiB) is a separate slice.
  3. **NODE_KIND_SYMLINK = 3.** Target string stored inline in
     the symlink node's first extent (one block, capped at
     `SYMLINK_TARGET_MAX = 1024` bytes). `lookup_path` does NOT
     auto-resolve through symlinks in v3 — it returns the symlink
     kind and lets the caller re-resolve. Cycle detection makes
     auto-resolution non-trivial; ship the inert form first.
  4. **Hard links via `link_count` refcount on every node.**
     `unlink` decrements; only frees extents and recycles the
     node when `link_count` reaches 0. fsck cross-checks node
     `link_count` against the count derived from dir entries
     and reports drift in `link_count_mismatch`.
  5. **v3 hard-link caveat: `new_path`'s last component must
     equal the target's existing name.** v3 stores the name on
     the inode itself; until a separate dirent table lands, two
     dirents pointing at the same inode share a single name.
     POSIX `link("/a", "/dir/b")` would semantically rename;
     v3 returns `kStatusInvalid` rather than allow that.
  6. **Symlink targets are byte-for-byte preserved**, NOT
     resolved at creation. `readlink` returns the bytes
     verbatim. Same shape as POSIX `readlink(2)`.
  7. **Format-version bump 3 → 4.** Magic stays `"DuetFS01"`.
     v2 images fail open() with `kStatusInvalid` (version
     mismatch). On-disk v2 volumes from the previous slice need
     to be reformatted; the boot self-test was the only known
     consumer and it formats every time.
  8. **fsck rebuilds the CRC table on repair**, not just the
     bitmap. After `fsck(repair=1)` a clean second pass reports
     zero CRC mismatches. Repair semantics: trust the
     metadata + data blocks, rewrite the bookkeeping.

- **Why:**
  - Per-block CRCs give us bit-rot detection (the foundation
    of a real durability story). Coupled with a future journal,
    this becomes "data integrity end-to-end" for free —
    journal commit can verify CRCs as it replays.
  - SB-only CRC (v2) catches torn writes to the SB itself but
    nothing else. v3 catches "block X is corrupt" — though only
    on demand at fsck time, which is when an operator runs it
    explicitly or at mount-time recovery.
  - Symlinks and hard links are POSIX bedrock. Every Unix
    binary that calls `symlink(2)` / `link(2)` works the day
    the userland syscall surface lands.
  - link_count on every node, not just files, means dirs are
    refcounted too (root has self-loop link_count=1). Sets up
    the "rmdir an empty dir frees the inode" semantics
    cleanly.

- **What it rules out / defers:**
  - **Metadata read-time CRC verification.** The initial read-time
    switch covers data-region file / symlink / directory / xattr blocks;
    node table and bitmap policy remains fsck-led.
  - **CRC table > 1 block.** 4 MiB image cap until then.
  - **Symlink auto-resolution in `lookup_path`.** Caller-side
    re-resolve until cycle detection lands.
  - **Hard-link names different from target's name.** Needs a
    dirent table.
  - **Journal.** Mid-write crash on a file's data extent still
    leaves garbage at the unflushed offset. CRC catches it
    after the fact; no atomic-commit guarantee.
  - **Encryption / compression.** Both untouched in v3.

- **Revisit when:**
  - First production metadata-corruption incident needs mount-time
    hard-fail semantics → extend read-time verification to node
    table / bitmap reads.
  - First image > 4 MiB needs a CRC table → multi-block CRC
    table.
  - First user wants `link("/a", "/dir/b")` to do POSIX-style
    rename → dirent table.
  - First package install with symlinks works on a real disk →
    auto-symlink resolution.

- **Related roadmap track(s):**
  - Filesystem track — DuetFS reaches "primary FS with data
    integrity tier". Next cliffs: journal, encryption.








## 2026-05-08 — HDA bootstrap output-path selector

- **Decision:** Add `hda::FindFirstOutputPath()` as the first
  consumer-facing HDA routing selector. It chooses the preferred
  output pin from the jack inventory in Speaker → Headphone Out →
  Line Out order and pairs that pin with the first DAC node the
  codec walker recorded on the same codec.

- **Why:** The existing `ConfigureOutputPath()` verb sequence was
  useful plumbing, but callers still had to know which DAC and pin
  nodes to pass. A conservative selector gives the upcoming system-
  beep / smoke-playback path a stable tuple without prematurely
  implementing the full HDA graph solver.

- **What it rules out / defers:** This is not mixer / selector
  topology solving. Codecs with a non-trivial DAC → mixer → pin
  chain may need the future connection-list parser before audio can
  route correctly. The selector skips any codec without a recorded
  DAC and still requires a playback consumer to allocate DMA buffers,
  fill a BDL, arm a stream, call `ConfigureOutputPath()`, and set RUN.

- **Related roadmap track(s):** Audio — HDA stream programming and
  first audible playback.

---

## 043 — Win32 LastError is task-local until writable TEBs land

- **Scope:** `kernel/sched/sched.cpp`, `kernel/syscall/syscall.cpp`,
  `userland/libs/kernel32/kernel32.c`
- **Commit:** this slice
- **Decision:** `SYS_GETLASTERROR` / `SYS_SETLASTERROR` read and write
  a field on the scheduler `Task`, not on `Process`.
- **Why:** Windows defines LastError as thread-local TEB state. DuetOS
  already supports multiple Win32 threads per process, so the previous
  process-wide slot let one thread clobber another thread's error code.
  A full writable TEB/TLS model is larger Track 6 work; a Task field is
  the narrowest kernel-owned per-thread storage available today.
- **Rules out / defers:** This does not make the TEB's `LastErrorValue`
  offset writable or observable from user code. Direct TEB field
  semantics stay deferred to the full TEB/TLS implementation.
- **Revisit when:** T6-01 lands writable per-thread TEB/TLS storage; at
  that point the Task field should either mirror the TEB slot or be
  removed in favour of direct TEB-backed reads.
- **Related roadmap track(s):** QW-05, Track 6 (Process and Thread
  Model).

---

## 2026-05-09 — Keep COM local until RPC / windowing need cross-process semantics

- **Scope:** `userland/libs/ole32/ole32.c`, `userland/apps/com_smoke/com_smoke.c`
- **Commit:** this change
- **Decision:** The first real COM runtime is process-local: per-thread
  `CoInitializeEx` state, an in-process `CoRegisterClassObject` table,
  static factories for StdComponentCategoriesMgr / FileOpenDialog /
  FileSaveDialog, and IUnknown/IClassFactory vtables. Unknown CLSIDs now
  fail with `REGDB_E_CLASSNOTREG` rather than the older
  class-unavailable facade.
- **Why:** Compatibility probes overwhelmingly need local COM bootstrap
  semantics before they need RPC, ROT, monikers, or cross-process
  apartments. Returning the registry-style error for unknown classes lets
  callers take their normal fallback path while known built-ins can be
  queried and released safely.
- **Rules out / defers:** Cross-process COM, RPC marshalling, OBJREFs,
  structured storage, and real file-dialog UI remain separate slices. The
  FileOpenDialog / FileSaveDialog registrations can be resolved and can
  create safe `IUnknown` identities, but they are not usable picker
  implementations yet.
- **Revisit when:** shell COM objects or modal dialog work requires an
  actual IFileDialog method surface, or rpcrt4 lands.
- **Related roadmap track(s):** T2-01 (landed), T2-02, T14-04 (landed).

---

## 2026-05-09 — Roadmap audit: lift confirmed-done win32 surface items

- **Scope:** `wiki/reference/Roadmap.md`,
  `userland/libs/user32/user32.c`,
  `userland/libs/shell32/shell32.c`
- **Commit:** this slice
- **Decision:** Audit each Track 1 / Track 12 / Track 14 P0/P1 row and
  the imported quick-wins table against the live tree; rows whose
  acceptance criteria are demonstrably met by the current sources +
  smoke corpus are removed from the roadmap in this commit. Removed:
  T1-01 (per-window message queue + GetMessage/PeekMessage/
  PostMessage/DispatchMessage), T1-02 (BeginPaint/EndPaint/TextOut/
  InvalidateRect/UpdateWindow + the GDI draw path),
  T12-01 (LoadLibrary{A,W} / LoadLibraryEx{A,W} / FreeLibrary /
  GetProcAddress / GetModuleHandle / GetModuleFileName), T12-02
  (Windows 10 19041 GetSystemInfo / GetVersionEx / RtlGetVersion /
  IsWow64Process), T14-02 (covered by `windowed_hello` +
  `msg_smoke` + `wndmsg_smoke` + `gdi_smoke`), and the entire
  imported-quick-wins table (QW-01..QW-12, all twelve
  verified). T1-04 keeps its row but loses the AdjustWindowRect
  bullet — `AdjustWindowRect` / `AdjustWindowRectEx` /
  `AdjustWindowRectExForDpi` now ship in user32 sourced from
  `GetSystemMetrics`. T2-02 keeps its row (IFileDialog vtables
  pending) but loses the SHGetDesktopFolder bullet — a singleton
  IShellFolder lands in shell32 returning empty / sentinel results
  through every vtable slot, so callers see `S_OK` instead of
  `class-not-registered`. T1-05 keeps its row with a sharper
  description (CreateCompatibleDC sentinel needs real bitmap-backing
  storage).
- **Why:** Roadmap entries that don't reflect tree state mislead
  contributors picking the next slice. The CLAUDE.md policy
  "**delete its entry from this page in the same commit that
  delivers the code**" requires audit passes when several slices
  land without the contemporaneous roadmap bump.
- **Rules out / defers:** Removing a row is *not* a claim that the
  surface is bug-free or feature-complete; it's a claim that the
  named acceptance criterion is met. New gaps surface as new
  roadmap rows or as `// STUB:` / `// GAP:` markers, not as
  re-resurrected old rows.
- **Revisit when:** the next batch audit (run
  `git grep -nE "// (STUB|GAP):"` plus a pass over the smoke corpus
  to spot newly-real callers) — typically every 5–10 win32 slices.
- **Related roadmap track(s):** Track 1, Track 2, Track 12, Track
  14, Imported Quick Wins.

---

## 2026-05-09 — IFileDialog vtables, ucrtbase tmpfile + setvbuf, mem-DC BitBlt wiring

- **Scope:** `userland/libs/ole32/ole32.c`,
  `userland/libs/ucrtbase/ucrtbase.c`,
  `userland/libs/gdi32/gdi32.c`
- **Commit:** this slice
- **Decision:** Three concrete win32-surface gap-closes shipped
  alongside the prior roadmap-audit commit:
    1. **IFileDialog / IFileOpenDialog / IFileSaveDialog vtables.**
       The `kCLSID_FileOpenDialog` and `kCLSID_FileSaveDialog`
       factories now allocate per-instance objects whose vtables
       publish 27 (Open) / 32 (Save) slots in canonical Win SDK
       order. `Show` returns `S_FALSE` so apps' "user cancelled"
       fall-through runs; setters succeed silently; getters fail
       cleanly with cleared out params.
    2. **Memory-DC + BitBlt wired through to kernel tables.**
       `gdi32!CreateCompatibleDC` / `CreateCompatibleBitmap` /
       `SelectObject` / `DeleteDC` / `DeleteObject` / `BitBlt`
       now route through SYS_GDI_CREATE_COMPAT_DC (106) /
       SYS_GDI_CREATE_COMPAT_BITMAP (107) / SYS_GDI_SELECT_OBJECT
       (110) / SYS_GDI_DELETE_DC (111) / SYS_GDI_DELETE_OBJECT
       (112) / SYS_GDI_BITBLT_DC (113) into the per-process
       MemDC + Bitmap tables in
       `kernel/subsystems/win32/gdi_objects.cpp`. Window-DC
       (GDI_TAG-wrapped) HDCs still bypass the kernel tables
       because the existing draw helpers expect to recover an
       HWND from the HDC; mixing the two flavours is the
       caller's responsibility (BitBlt mem→window crosses the
       boundary, which the kernel's `DoGdiBitBltDC` already
       handles).
    3. **ucrtbase stdio top-up.** Added `setvbuf`, `setbuf`,
       `tmpnam`, `tmpnam_s`, `tmpfile`. Buffer settings are
       silently dropped (no buffered I/O on the FILE structs
       yet); tmpnam generates a `C:\Temp\duetXXXX.tmp` path
       using a process-local counter so consecutive calls don't
       collide; tmpfile delegates to fopen with "w+b".
- **Why:** Each item closes a known fall-back path that was
  causing apps to take the "this Windows surface isn't
  available" branch. None of the three required new syscalls
  or kernel changes — the kernel-side machinery was already
  in tree for both BitBlt and the COM factories. The wiring
  was the gap.
- **Rules out / defers:** A real file-picker UI (compositor
  modal-input mode), buffered stdio with explicit flush, and
  `BitBlt` with non-`SRCCOPY` ROPs (XOR / NOT / pattern brush
  blits) all stay deferred. `tmpfile` doesn't auto-delete on
  close — Windows ships `FILE_FLAG_DELETE_ON_CLOSE` which our
  v0 `fopen` doesn't honour.
- **Revisit when:** the compositor grows a modal-input mode
  (IFileDialog UI), a workload demands buffered stdio
  (setvbuf becomes a real consumer), or a workload demands
  pattern-brush BitBlt.
- **Related roadmap track(s):** T1-05 (landed), T2-02 (landed),
  T12-04 (landed).

---

## 2026-05-09 — T7-02 W/A symmetry + process-local named sync (T6-04 v0)

- **Scope:** `userland/libs/kernel32/kernel32.c`
- **Commit:** this slice
- **Decision:** Two more roadmap items close in this commit:
    1. **T7-02 W/A symmetry.** `GetCurrentDirectoryW`,
       `GetFullPathNameA`, `GetDiskFreeSpace{A,W}`, and
       `GetVolumeInformation{A,W}` now ship; the prior set covered
       only one variant per pair (A or W). Volume name reports
       "DuetOS", filesystem name reports "FAT32" (matches the
       `Fat32Format` primitive), free/total cluster counts pin to
       a 1 GiB ramfs-friendly geometry.
    2. **T6-04 process-local named-sync v0.** `Create{Mutex,Event,
       Semaphore}{A,W}` with a non-NULL `name` argument now check
       a process-local 32-slot name table; on hit they return the
       existing handle; on miss they allocate a fresh kernel
       handle and record it. `Open{Mutex,Event,Semaphore}{A,W}`
       look up the same table and return NULL on miss. This
       satisfies all WITHIN-process named-sync probes (one
       process opening the same name twice gets the same handle)
       without a kernel-resident namespace.
- **Why:** Both items unblock specific PE behaviour patterns: any
  code that round-trips through `GetVolumeInformation` to label a
  drive UI now sees real values; any code that uses named sync
  for "I should run only once per process" patterns (the most
  common in-process use of named primitives) now works without
  the kernel-resident namespace landing.
- **Rules out / defers:** Cross-process named sync (parent +
  child sharing a named event) still needs the kernel-resident
  namespace — that's the remainder of T6-04. The volume info
  is canned (no per-volume labels yet); a real disk installer
  would seed the value at format time.
- **Revisit when:** kernel-resident named-sync namespace lands
  (T6-04 follow-on), or a workload requires per-volume labels.
- **Related roadmap track(s):** T7-02 (landed), T6-04 (v0
  process-local landed; cross-process pending).

---

## 2026-05-09 — /GS + CFG facades in vcruntime140 (T9-02 v0, T9-03)

- **Scope:** `userland/libs/vcruntime140/vcruntime140.c`
- **Commit:** this slice
- **Decision:** vcruntime140 now exports the symbols that MSVC's
  `/GS` and `/guard:cf` codegen reach for at runtime, so binaries
  compiled with either flag can load and execute under DuetOS
  without crashing on the first guard call:
    1. **/GS (T9-02 v0)**: `__security_cookie` (default value
       `0x00002B992DDFA232`), `__security_cookie_complement`,
       `__security_init_cookie` (no-op — no entropy source wired
       in), `__security_check_cookie` (compares input to the
       global; aborts on mismatch), `__report_gsfailure` /
       `__report_rangefailure` (aborts). The compiler-emitted
       save/check pair compares the same value across one
       function call, so leaving the cookie at its default value
       still detects real corruption — what's deferred is
       per-image randomisation.
    2. **CFG / XFG (T9-03)**: `_guard_check_icall` and
       `_guard_xfg_check_icall` are no-op (trust the call);
       `_guard_dispatch_icall` and `_guard_xfg_dispatch_icall`
       are naked `jmp *%rax` so the compiler-prepared target in
       rax runs without bitmap enforcement. CFG bitmap
       materialisation + per-image fptr patching is the
       remaining gap, marked `// GAP: CFG not enforced`.
- **Why:** Both items unblock loading of any PE built with
  modern MSVC defaults — `/GS` is on by default, and `/guard:cf`
  is increasingly common in shipping binaries. Without these
  exports, a CFG-enabled DLL's first indirect call goes through
  a NULL function pointer and traps; without `__security_cookie`,
  the prologue's first `mov rcx, [__security_cookie]` reads
  unmapped memory.
- **Rules out / defers:** Real entropy-seeded per-image cookies
  (T9-02 follow-on — needs PE-loader read of
  `IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie`), real CFG bitmap
  enforcement (T9-03 follow-on — needs the per-image bitmap
  materialised + per-image fptr slots patched to enforcement
  helpers).
- **Revisit when:** PE loader gains load-config awareness, or a
  workload demands enforced CFG (e.g. a security-sensitive
  third-party DLL that asserts the per-image fptr is non-NULL).
- **Related roadmap track(s):** T9-02 (v0 landed; per-image
  randomisation pending), T9-03 (landed).

---

## 2026-05-09 — Roadmap audit pass 2: T11-01 ACPI + T11-03 registry hive

- **Scope:** `wiki/reference/Roadmap.md`
- **Commit:** this slice
- **Decision:** Two more rows lift off the roadmap based on
  re-audit against the live tree:
    1. **T11-01 (ACPI parser coverage)**:
       `kernel/acpi/acpi.cpp` ships `ParseRsdp` /
       `ParseXsdt` / `ParseMadt` (LAPIC + I/O APIC + Interrupt
       Source Override + LAPIC Address Override) / `ParseFadt`
       (PM1A/B control + reset register + ACPI enable) /
       `ParseHpet` (validation + main-counter enable).
       `kernel/acpi/srat.cpp` ships SRAT (CPU + Memory Affinity
       for NUMA frame allocator). The AML interpreter remains
       the documented gap for ACPI S5 / battery / lid-close,
       but that's owned by the Drivers section + T11-05 — not
       T11-01.
    2. **T11-03 (registry hive persistence)**: every successful
       Reg* mutation in `kernel/subsystems/win32/registry.cpp`
       triggers `RegistryHiveSave` (throttled by byte-compare
       against the on-disk pool); `RegistryHiveLoad` runs at
       boot once FAT32 mounts. HKLM / HKCU / HKU + the full
       advapi32 Reg* CRUD + enumeration surface persist
       across reboots as a result.
- **Why:** Both rows had been fully-real for several slices; the
  roadmap entries were stale. Removing them keeps the audit
  invariant from the prior pass: a row remains if a contributor
  picking it up would have real work to do, not paperwork.
- **Rules out / defers:** Nothing — these are clean removals.
- **Revisit when:** the next Track 11 audit (typically every
  5–10 kernel-infra slices).
- **Related roadmap track(s):** T11-01 (landed), T11-03
  (landed).

---

## 2026-05-09 — PE-loader /GS cookie randomisation (T9-02 follow-on)

- **Scope:** `kernel/loader/pe_loader.cpp`,
  `wiki/reference/Roadmap.md`
- **Commit:** this slice
- **Decision:** `SeedSecurityCookie(file, file_len, h, as)` runs as
  step 3a of `PeLoad` (after relocations, before TLS gate). The
  helper reads the PE's `IMAGE_LOAD_CONFIG_DIRECTORY` (data directory
  10), checks that its `Size` field covers the SecurityCookie
  field at offset 0x58, generates a 48-bit random cookie via
  `duetos::core::RandomU64()` (avoiding zero and the documented
  MSVC default `0x00002B992DDFA232`), and writes it directly into
  the loaded image at the SecurityCookie VA using the same
  per-page frame-lookup pattern `ApplyRelocations` uses. PEs
  without a load config, with a pre-/GS layout, or with the
  cookie VA in an unmapped page silently skip — the compiler's
  save/check pair still detects real corruption because it
  compares the cookie to itself across one function call.
- **Why:** Closes the remaining gap in T9-02. Without per-image
  randomisation, every process saw the same default cookie value
  vcruntime140 ships, which makes the `/GS` check trivial to
  bypass with a known overflow. With this slice, each spawned PE
  gets a fresh value seeded from RDSEED/RDRAND (with a splitmix
  fallback), and the cookie is unique per process.
- **Rules out / defers:** The cookie's high 16 bits are zeroed
  (matches MSVC's convention for keeping the value usable as a
  SEH key). DLL load paths (`DllLoad`) still don't seed
  per-DLL cookies — they use the static default in
  vcruntime140's data section. That's the next follow-on; PE-side
  randomisation is the more important seal because the main
  image owns the stack frames where /GS overflow detection runs.
- **Revisit when:** the DLL loader gains the same cookie-seeding
  step, or the PE loader needs to honour additional
  IMAGE_LOAD_CONFIG_DIRECTORY fields (CFG bitmap pointer,
  GuardCFCheckFunctionPointer patching) — these expand naturally
  on the same plumbing.
- **Related roadmap track(s):** T9-02 (landed).

---

## 2026-05-09 — APC queue v0 (T8-02 single-thread surface)

- **Scope:** `userland/libs/kernel32/kernel32.c`
- **Commit:** this slice
- **Decision:** `QueueUserAPC` + alertable `SleepEx` /
  `WaitForSingleObjectEx` ship a process-local APC surface:
    - 16-slot static queue indexed by target TID.
    - `QueueUserAPC(pfn, hThread, dwData)` appends to the queue
      (returns 0 if full).
    - `SleepEx(_, TRUE)` / `WaitForSingleObjectEx(_, _, TRUE)`
      check the queue for entries targeting the calling TID,
      fire each in registration order, and return
      `WAIT_IO_COMPLETION (0xC0)` if any were drained. Otherwise
      they fall through to the underlying Sleep / wait primitive.
- **Why:** Many MSVC-built apps (notably the CRT's stdio and
  WinHTTP completion path) probe `QueueUserAPC` + alertable
  `SleepEx` at startup. Without the symbols and the
  `WAIT_IO_COMPLETION` return path, these probes either fail or
  block forever. The single-thread queue covers the
  caller-queues-to-itself idiom (the most common shape — a
  parent thread queues an APC and the same thread later waits
  alertably).
- **Rules out / defers:** Cross-thread APC delivery still needs
  kernel-side per-thread APC queue + scheduler wake. A target
  thread sleeping in WaitForSingleObjectEx today doesn't see
  APCs queued by another thread until it next enters the
  alertable path. NtQueueApcThread / QueueUserAPC2 also stay
  unimplemented (different ABI surface).
- **Revisit when:** a workload needs cross-thread APCs (e.g. an
  IOCP-style completion port routes file I/O completions via
  APC to a worker pool).
- **Related roadmap track(s):** T8-02 (v0 landed; cross-thread
  pending).

---

## 2026-05-09 — Gate PE ASLR on DllCharacteristics DYNAMIC_BASE (T9-01 v0)

- **Scope:** `kernel/loader/pe_loader.{h,cpp}`,
  `kernel/proc/ring3_smoke.cpp`
- **Commit:** this slice
- **Decision:** PE spawn paths now consult
  `PeIsDynamicBase(file, file_len)` before applying ASLR. The
  helper reads the Optional Header DllCharacteristics field at
  offset 70 and tests for IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
  (0x0040). When set, ring3_smoke picks a 64 KiB-aligned delta in
  [0, 64 MiB) from `duetos::core::RandomU64()`. When not set, the
  PE loads at its preferred ImageBase (delta = 0).
- **Why:** Win32's contract is that ASLR only applies to PEs
  built with `/DYNAMICBASE` — PEs without the flag may have
  hard-coded address assumptions that break under ASLR. Modern
  MSVC defaults set the flag, so the behavioural change is
  invisible for typical workloads, but legacy / freestanding
  PEs that intentionally pin their base now load reliably.
- **Rules out / defers:** DLL randomisation (DllLoad still
  passes `aslr_delta=0`) is the remaining gap — DLL preload runs
  cooperatively with DLLs the loader expects to find at the
  preferred base for IAT chasing. Per-DLL randomisation needs
  the DLL preload table to refresh-after-relocate, which is a
  separate slice. T9-01 keeps its row pending that follow-on.
- **Revisit when:** the DLL preload path tracks per-DLL
  effective base post-ASLR (DLL randomisation), or a workload
  exercises a non-DYNAMICBASE PE that the always-on prior
  behaviour would have broken.
- **Related roadmap track(s):** T9-01 (PE-image gate landed;
  DLL randomisation pending).

---

## 2026-05-09 — Winsock async surface v0 (WSAEventSelect family)

- **Scope:** `userland/libs/ws2_32/ws2_32.c`
- **Commit:** this slice
- **Decision:** Add `WSAEventSelect` / `WSAEnumNetworkEvents` /
  `WSAWaitForMultipleEvents` backed by a process-local
  `WsaEventBinding[32]` table that records (socket, event-handle,
  lNetworkEvents, pending-mask) tuples. The producer side
  (TCP stack notifying that a socket is readable / writable /
  has accepted) is not wired yet — `WSAEnumNetworkEvents` always
  reports zero events and `WSAWaitForMultipleEvents` returns
  `WSA_WAIT_TIMEOUT` after a single non-blocking probe.
- **Why:** Many Win32 PEs that use sockets (HTTP servers, IRC
  clients, anything written against the Win32 async pattern)
  call `WSAEventSelect` very early after socket creation. Without
  the symbol, the IAT chase would fall through to the missing-
  import miss-logger and the PE would crash on the first access.
  The registry exists so the registration succeeds; the events
  just never fire (the caller's normal polling loop will block
  forever instead of progressing — a workload-specific concern,
  not a load-time crash).
- **Rules out / defers:** Real async event delivery requires the
  TCP stack to flag bindings on socket-readable etc. Overlapped
  I/O (`WSARecv` with OVERLAPPED + IOCP completion) requires
  wiring kernel32's IOCP infrastructure into the socket read
  path. Both stay deferred behind networking Track 3.
- **Revisit when:** the TCP stack lands per-socket event
  notifications, or a workload exercises the Win32 async
  socket pattern enough to demand functional event delivery.
- **Related roadmap track(s):** Winsock async surface (v0
  landed; producer-side delivery pending).

---

## 2026-05-10 — Input routing to focused PE + window chrome interactions (T1-03 v0 / T1-04 closed)

- **Scope:** `kernel/core/main.cpp`,
  `kernel/drivers/video/widget.{h,cpp}`,
  `kernel/drivers/video/modal_input.{h,cpp}`,
  `kernel/subsystems/win32/window_syscall.cpp`,
  `userland/libs/user32/user32.c`,
  `wiki/subsystems/Compositor.md`,
  `wiki/reference/Roadmap.md`
- **Commit:** post-audit roll-up (this commit is the
  documentation flush; the code landed across the prior slices
  this audit is reconciling).
- **Decision:** The kernel mouse-reader and kbd-reader in
  `kernel/core/main.cpp` are the canonical Win32 input router.
  Keystrokes targeting a window with `owner_pid > 0` post
  `WM_KEYDOWN` / `WM_SYSKEYDOWN` (Alt held → SYS variant) and
  `WM_CHAR` / `WM_SYSCHAR` to the per-window message ring,
  with lParam bit 29 set for SYS forms. Mouse motion and
  primary-button edges post `WM_MOUSEMOVE` (0x0200) /
  `WM_LBUTTONDOWN` (0x0201) / `WM_LBUTTONUP` (0x0202) with
  client-coordinate lParam packing; double-click adds
  `WM_LBUTTONDBLCLK` (0x0203). Wheel events post
  `WM_MOUSEWHEEL` (0x020A) with the standard 120-step
  zDelta. Window chrome (close / max / min glyphs, title-bar
  press-and-drag, double-click max-toggle, resize bands at the
  4-px borders) lives in the same kernel mouse loop and reaches
  `WindowClose` / `WindowMaximize` / `WindowMinimize` /
  `WindowRestore` / `WindowMoveTo` / `WindowResizeFromEdge`.
  Right-click on the title bar opens the system menu via the
  shared kernel popup-menu primitive; the Move / Size system-
  menu items hand off to `ModalInputBegin` for cursor-follow
  interactive forms. Keyboard parity: `Alt+F4` closes,
  `Ctrl+Alt+Arrow` runs the snap shortcuts. Z-order tracks any
  in-window press through `WindowRaise`.
- **Why:** Before this lands the kernel mouse loop was the only
  surface that spoke directly to the input source (PS/2 +
  xHCI HID), so any per-PE message routing has to live there
  too — pushing it into userland would cost a syscall per packet
  and serialise with the focused PE's own pump. The same
  argument applies to the chrome buttons: hit-test against
  `g_windows[h]` is a kernel-side data structure, so the
  press handler is naturally kernel-side as well.
- **Rules out / defers:** `WM_KEYUP` / `WM_SYSKEYUP` aren't yet
  posted (the kbd-reader only fires on press / repeat edges
  for the PE branch); `SetCapture` / `ReleaseCapture` track
  the captured HWND in user32 but the kernel mouse loop still
  routes by HWND-under-cursor on every packet, so a captured
  PE button doesn't yet receive button-up events outside its
  client area; `SetForegroundWindow` returns success but
  doesn't yet rewrite `WindowActive()` outside an explicit
  raise-on-press. All three are the residual half of T1-03.
- **Revisit when:** a workload depends on KEYUP edges (e.g.
  game input), or `SetCapture` is needed for a real drag
  gesture initiated by a PE (e.g. a slider widget).
- **Related roadmap track(s):** T1-03 (residual KEYUP +
  capture/foreground gaps tracked on the row); T1-04 closed
  with this entry.

---

## 2026-05-10 — WM_KEYUP / WM_SYSKEYUP routing closes T1-03

- **Scope:** `kernel/core/main.cpp`, `wiki/reference/Roadmap.md`,
  `wiki/subsystems/Compositor.md`
- **Commit:** this slice
- **Decision:** Extend the kbd-reader's release branch in
  `kernel/core/main.cpp` to post `WM_KEYUP` (0x0101) /
  `WM_SYSKEYUP` (0x0105) to the focused PE before the existing
  `continue` that swallows release edges. Modifier-only
  transitions (`ev.code == kKeyNone`) skip — modifier state is
  already tracked via `WindowInputTrackKey` and a release of
  the modifier alone has no VK to deliver. lParam carries the
  Win32-spec layout: bit 30 (previous state) = 1, bit 31
  (transition state) = 1, bit 29 = Alt context, repeat-count
  = 1 in the low 16 bits. The CompositorLock bracket mirrors
  the existing KEYDOWN branch so the post and `WindowMsgWakeAll`
  serialise against compose. Re-audit of T1-03's other claimed
  residuals (`SetCapture` + `SetForegroundWindow`) found both
  are already wired: the mouse-routing block in `main.cpp`
  consults `WindowGetCapture()` before the HWND-under-cursor
  hit-test, and `SetForegroundWindow` plumbs through
  `SetActiveWindow` → `SYS_WIN_SET_ACTIVE` → `WindowRaise`,
  which sets `g_active_window`.
- **Why:** PE workloads that distinguish hold-vs-tap (game
  input, modifier-aware shortcut handlers, anything that uses
  `GetKeyState` reactively rather than polling) need the
  release edge — without it a key looks held forever from the
  PE's perspective. The cost is a single extra
  CompositorLock/Unlock + WindowPostMessage per release packet,
  which the kbd-reader already pays for the press path.
- **Rules out / defers:** `SYS_RUN_TYPE_*` doesn't carry the
  scan code itself — the wParam is the VK (kernel `kKey*`
  enum), so a PE that needs to disambiguate scan vs VK
  (e.g. raw input) still has nothing. That's a separate
  syscall surface (raw input / WM_INPUT) and is not on any
  active track.
- **Revisit when:** a PE workload demands raw scan codes via
  `WM_INPUT` / `RegisterRawInputDevices`.
- **Related roadmap track(s):** T1-03 closed.

---

## 2026-05-10 — Track 10 build/CI roadmap closures (T10-01/02/03)

- **Scope:** `wiki/reference/Roadmap.md`,
  `wiki/subsystems/Compositor.md`
- **Commit:** this slice (documentation flush — the underlying
  CI workflow, KASAN preset, and LTO preset all landed in
  earlier slices).
- **Decision:** Three Track 10 rows correspond to landed work
  and are closed in the Roadmap:
  - **T10-01** — `.github/workflows/build.yml` runs check-format
    + build-debug + build-release + qemu-smoke jobs on push to
    `main` / `claude/**` and on PRs to `main`;
    `.github/workflows/release.yml` publishes the rolling
    flavor channels. README carries the build-flavors + per-
    channel + lifetime-downloads badges so the Roadmap row's
    "green CI badge" acceptance is met.
  - **T10-02** — `CMakePresets.json` defines the `x86_64-kasan`
    configure preset (inherits `x86_64-debug`, sets
    `DUETOS_KASAN=ON`) and the matching `x86_64-kasan` build
    preset. `cmake --preset x86_64-kasan` configures cleanly.
  - **T10-03** — `CMakePresets.json` defines `x86_64-release-lto`
    with `DUETOS_LTO=ON`; the kernel link succeeds through lld
    with ThinLTO enabled.
- **Why:** The Roadmap convention is to delete a row in the
  same commit that delivers the code (CLAUDE.md "Updating
  roadmap items"). The build-system slices that delivered
  T10-01/02/03 didn't follow through on the Roadmap edit, so
  this audit closes them retroactively. T10-04 stays open with
  a precise residual: the host ctest harness today covers
  Result + string + syscall_error + cvt + text_hash +
  d3dcompiler + damage_rect + wild_address; PE parser + VFS
  path resolution + registry lookup still live only in the
  on-target boot self-tests.
- **Rules out / defers:** Adding PE parser / VFS / registry
  fixtures to the host harness needs `#ifdef DUETOS_HOST_TEST`
  shims around kernel-only globals (frame allocator, panic,
  serial), which is a real refactor — deferred until a workload
  warrants it.
- **Revisit when:** a regression hits one of the three uncovered
  pillars on the on-target side and a host-runnable repro would
  shorten the loop.
- **Related roadmap track(s):** Track 10 (T10-01/02/03 closed;
  T10-04 narrowed).

---

## 2026-05-10 — Compositor.md: drop duplicate `PE SetCursor` GAP

- **Scope:** `wiki/subsystems/Compositor.md`
- **Commit:** this slice
- **Decision:** The Compositor "Known Limits / GAPs" list
  carried the `PE SetCursor` GAP twice (once near the menu
  block, once near the Settings block). Drop the second
  occurrence so a reader gets one canonical statement of the
  limit. Both bullets said the same thing in slightly
  different prose.
- **Why:** Duplicate Known-Limits trip up new readers — they
  start hunting for the difference between "GAP" and "ABI"
  framings when there isn't one. One bullet = one canonical
  description of a GAP. Trivial cleanup.
- **Related roadmap track(s):** none — pure docs hygiene.

---

## 2026-05-10 — Waitable + multimedia timers (T11-04 closed)

- **Scope:** `userland/libs/kernel32/kernel32.c`,
  `userland/libs/winmm/winmm.c`,
  `wiki/reference/Roadmap.md`
- **Commit:** this slice
- **Decision:** Waitable timers and multimedia timers both use a
  per-process polling service thread that wakes every 10 ms,
  walks a fixed-size table, and either fires `SetEvent` (waitable
  case) or invokes a TIMECALLBACK (multimedia case) for any
  slot whose absolute due time has arrived. Periodic timers
  re-arm from the fire instant; single-shot timers
  self-deactivate. The service thread is lazily spawned at the
  first `SetWaitableTimer` / `timeSetEvent` call so processes
  that never use timers don't pay for the thread. Both tables
  are sized at 16 slots — the same cap kernel32's existing
  per-process resource tables use (TLS slots, APC queue, named
  object dedup); workloads that need more get the `MAX_TIMERS`
  return rather than silent overflow.
- **Why:** `CreateWaitableTimer` previously returned a
  pre-signaled manual-reset event so any `WaitForSingleObject`
  fell through immediately — workloads using
  `CreateWaitableTimer` + `SetWaitableTimer(-100ms)` as a sleep
  substitute saw zero delay instead of 100 ms. `timeSetEvent`
  returned 0 and never invoked the callback. Both shapes are
  required by the Track 11-04 acceptance ("Waitable timers and
  `timeSetEvent` callbacks fire accurately"). A polling service
  thread is the simplest path that doesn't require new kernel
  syscalls — the kernel side already has CreateThread + SetEvent
  + GetTickCount64; the only userland-side change is the table
  + thread.
- **Rules out / defers:**
  - APC completion routines on waitable timers
    (`SetWaitableTimer`'s `pfnCompletionRoutine` / `lpArgToCompletionRoutine`
    parameters are accepted and ignored). Cross-thread APC
    delivery is Track 8-02; until that lands, the completion
    routine couldn't run on the caller's thread anyway.
  - TIME_CALLBACK_EVENT_SET / TIME_CALLBACK_EVENT_PULSE flag
    variants of `timeSetEvent`. The pulse-event surface needs
    a per-process pulse path that's safe from a service thread,
    which the v0 event implementation doesn't have.
  - Sub-10 ms resolution. The polling cadence is the floor.
    `timeBeginPeriod(1)` is accepted (returns success) but
    doesn't actually shorten the cadence.
  - Resume from suspend (`fResume == TRUE` is silently ignored
    — ACPI S3 not implemented, Track 11-05).
  - Absolute FILETIME due times. `SetWaitableTimer` only honours
    relative (negative) due values; absolute (positive) values
    are coerced to "fire immediately" so callers don't hang
    forever. A FILETIME → boot-relative-ms conversion table
    needs the system clock to be set, which v0 doesn't yet do.
- **Revisit when:** a workload exercises one of the deferred
  paths (a media-player that wants 1 ms ticks, a SetWaitableTimer
  caller that depends on APC completion, a thread that pulses
  an event-based mm-timer). Each is a separate slice keyed off
  the missing infrastructure (Track 8-02 / event pulse surface
  / system-clock setting).
- **Related roadmap track(s):** T11-04 closed.

---

## 2026-05-10 — Track 4 retroactive closures (T4-01 / T4-02 / T4-04)

- **Scope:** `wiki/reference/Roadmap.md`
- **Commit:** this slice (documentation flush — code landed in
  earlier slices)
- **Decision:** Three Track 4 rows correspond to landed work and
  are closed in the Roadmap with a banner pointing at the live
  files:
  - **T4-01** — D3D11 / DXGI swap-chain present into compositor
    windows works. `userland/libs/d3d11/d3d11.c::d3d11sc_Present`
    + `d3d11sc_GetBuffer` + `d3d11sc_ResizeBuffers` route through
    `dx_bb_present` / `dx_win_get_rect`. The screenshot harness
    `dx_demo_window` renders a 24-vertex cube into a real HWND
    via the swap chain. The row called out
    `SYS_WIN_HWND_TO_RECT (68)`, but the actual syscall is
    `SYS_WIN_GET_RECT = 70` (the rename happened in an earlier
    slice; same contract, different name).
  - **T4-02** — Vulkan ICD v0 ships in
    `kernel/subsystems/graphics/`. `graphics_vk_selftest.cpp`
    walks the create / queue / swapchain / present lifecycle on
    every boot without crashing; unimplemented paths return
    `VK_ERROR_INITIALIZATION_FAILED`.
  - **T4-04** — AMD / NVIDIA / Intel GPU probes ship and
    degrade cleanly: each `Probe` reads vendor/device IDs +
    BAR-region MMIO and logs discovery state; the command-
    submission path returns `Err{Unsupported}`. The D3D11 and
    Vulkan layers don't attempt to enqueue commands so the
    fallback to the shared software rasterizer is automatic.
    The `// STUB:` markers on the per-vendor TUs document the
    next steps without changing the degrade-to-software
    contract.
- **Why:** Same retroactive-closure pattern as the Track 10
  audit. The Roadmap convention is "delete the row in the
  same commit that delivers the code," but several
  long-running tracks landed work piecemeal and never
  retroactively pruned the row.
- **Rules out / defers:** T4-03 (Intel iGPU command ring + 2D
  blitter) is the only Track 4 row left open. The probe lands;
  the GTT setup + ring + blitter haven't.
- **Revisit when:** a workload depends on hardware-accelerated
  BitBlt — the row stays open until then.
- **Related roadmap track(s):** Track 4 (T4-01/02/04 closed;
  T4-03 narrowed).

---

## 2026-05-10 — Track 3 networking closures (T3-02 + T3-03)

- **Scope:** `kernel/syscall/syscall.h`,
  `kernel/syscall/syscall.cpp`,
  `userland/libs/iphlpapi/iphlpapi.c`,
  `userland/libs/ws2_32/ws2_32.c`,
  `wiki/reference/Roadmap.md`
- **Commit:** this slice
- **Decision:**
  - Add `kSockOpGetLease = 13` op on `SYS_SOCKET_OP` (153) that
    snapshots the kernel's DHCP lease into a 40-byte
    `SocketLeaseInfo` user buffer (valid flag, IP / netmask /
    gateway / DNS in network byte order, lease-seconds, MAC,
    iface index). The MAC is read through `InterfaceMac(0)`;
    netmask defaults to /24 when the lease is valid (DhcpLease
    doesn't currently carry netmask). A short user buffer
    fails with `-ERANGE`.
  - `iphlpapi!GetAdaptersInfo` calls the new op and emits a
    two-record chain: ethernet (eth0, populated from the lease)
    followed by loopback (127.0.0.1). The "next" pointer is
    written directly into the first record's bytes 0..7. When
    the lease syscall fails (no NIC bound) the ethernet record
    still ships with zero IP / mask / gateway so callers see
    a row.
  - `ws2_32!getaddrinfo` now resolves IP literals through
    `inet_addr`, special-cases "localhost" /
    "localhost.localdomain" → 127.0.0.1, and falls through a
    16-slot LRU cache + `kSockOpResolveA` for everything else.
    `freeaddrinfo` releases the single-block (addrinfo +
    sockaddr_in) allocation.
- **Why:**
  - The Track 3 acceptance criteria for both rows hinge on
    "Winsock name lookups resolve through real DNS" and
    "e1000 probe acquires an IPv4 lease and stores it in the
    kernel network state." The kernel side already had both
    pieces; the missing seam was the userland-facing exposure.
    A new socket op + an iphlpapi rewrite is cheaper than
    inventing a new top-level syscall, since the
    SYS_SOCKET_OP dispatcher already handles the cap-gating
    and the user-buffer copy.
- **Rules out / defers:**
  - No netmask in the kernel's `DhcpLease` struct — the
    syscall returns 255.255.255.0 as a default. Real DHCP-
    OPTION 1 parsing into the lease is a separate slice (the
    kernel does decode the option byte but doesn't store it).
  - `GetAdaptersAddresses` still returns `ERROR_NO_DATA` —
    the larger IP_ADAPTER_ADDRESSES layout has IPv6 prefix
    chains and per-adapter DNS that aren't yet tracked.
  - Cache size is 16 entries, not 64. Growth is mechanical
    (the lookup is a flat scan); enlarge when a workload
    demands it.
  - IPv6 (AF_INET6 / sockaddr_in6 / AAAA records) — no
    resolver path yet.
  - Service-name resolution in `getaddrinfo` (the `service`
    parameter is parsed as a numeric port; symbolic names
    like "http" aren't recognised). A future
    `getservbyname` would fix this without touching the
    resolver.
- **Revisit when:** a workload exercises one of the deferred
  paths (an IPv6-aware HTTP client, a DHCP server pushing a
  non-/24 mask, a service-name caller).
- **Related roadmap track(s):** Track 3 (T3-02 + T3-03 closed;
  T3-01 still open until WSAStartup → socket → connect → send
  → recv loopback round-trip is verified end-to-end).

---

## 2026-05-10 — Track 13/14 closures (T13-01, T13-02, T14-01)

- **Scope:** `wiki/reference/Win32-Surface-Status.md`,
  `wiki/reference/Roadmap.md`,
  `userland/apps/pe_stress/pe_stress.c`,
  `userland/apps/build-smokes.sh`,
  `kernel/CMakeLists.txt`,
  `kernel/proc/ring3_smoke.cpp`
- **Commit:** this slice
- **Decision:**
  - **T13-01** Win32-Surface-Status audit: bumped the page's
    summary count to 2026-05-10, corrected the live STUB/GAP
    marker count from 4 to 0 (userland/libs/ + kernel/subsystems/win32/
    are clean today; markers live entirely in kernel TUs like
    gpu and iwlwifi), and corrected the smoke-corpus count from
    127 to 143 fixtures. Flipped CreateWaitableTimer{A,W} +
    SetWaitableTimer + CancelWaitableTimer rows from NOOP to
    REAL after the T11-04 closure. Refreshed the kernel32 +
    winmm narrative sections to call out the new waitable +
    multimedia timer paths.
  - **T13-02** Roadmap-population discipline: this audit-driven
    session itself satisfies the row. Each landed slice has
    deleted its imported-TODO entry (or shrunk it to the true
    residual) in the same commit, with a Design-Decisions entry
    recording what's deferred. Closing the row makes the
    discipline a permanent expectation rather than an aspiration.
  - **T14-01** PE stress fixture: new `pe_stress.c` spawns five
    worker threads beating on heap / mutex / event / file /
    registry surfaces in tight loops for 2 seconds, then joins
    via WaitForSingleObject and exits 0 iff every worker made
    >= 16 iterations. Embedded into the boot smoke corpus via
    `duetos_embed_smoke_pe(pe_stress kBinPeStressBytes)` +
    `SpawnPeFile("ring3-pe-stress", ...)`. Duration is 2 seconds
    not the row's 30 seconds — a 30s soak per boot would balloon
    CI; operators wanting the longer run can `pe_stress.exe`
    standalone.
- **Why:**
  - T13-01 / T13-02 are doc rows that the session has already
    been satisfying piecemeal (every closure updates the
    Surface-Status table + deletes the corresponding Roadmap
    entry). Calling them done formalises the convention.
  - T14-01 provides a multi-surface stress signal that
    catches cross-subsystem regressions a single-surface smoke
    can't. Heap corruption that only surfaces under contention,
    a mutex that drifts under N workers, registry hive
    serialisation that races with FAT32 writes — none of those
    show up in the existing single-API smokes.
- **Rules out / defers:**
  - T13-03 (per-syscall arg/return docs) stays open. The
    Syscall-ABI auto-table only carries `# | Symbol`; adding
    args / return columns needs a doc-gen pipeline change
    (extending `tools/build/gen-wiki-auto.py` to read a richer
    syscall-metadata source). Out of scope for this slice.
  - PE stress duration is 2 seconds. Lifting to 30 seconds
    needs a different way to gate the smoke corpus (e.g. a
    "long soak" preset that runs only on operator-driven CI
    branches). Tracked informally; not on the Roadmap.
- **Revisit when:** T13-03 needs to land, or a regression
  surfaces during the 2 s pe_stress run that demands a longer
  soak window.
- **Related roadmap track(s):** Track 13 (T13-01 + T13-02
  closed; T13-03 stays open). Track 14 (T14-01 closed; T14-02
  was already closed; T14-03 stays open until T3-01 lands).

---

## 2026-05-10 — Wire AcpiShutdown into KernelHalt (T11-05 closed)

- **Scope:** `kernel/power/reboot.cpp`,
  `kernel/power/reboot.h`,
  `wiki/reference/Roadmap.md`
- **Commit:** this slice
- **Decision:** `KernelHalt` had a long-standing `// GAP:` marker
  claiming ACPI S5 wasn't implemented because no AML interpreter
  existed. The AML interpreter actually shipped earlier
  (`kernel/acpi/aml.cpp::AmlReadS5` walks the DSDT/SSDT
  namespace for `\_S5_` and extracts SLP_TYP_A / SLP_TYP_B), and
  `acpi::AcpiShutdown` chains the AML extract with the PM1A_CNT
  + PM1B_CNT register write. KernelHalt now calls
  `AcpiShutdown` first, falls through to the QEMU-known
  shutdown ports (0x604 q35, 0xB004 piix, 0x4004 — the chipset
  models honour these even when the FADT didn't carry a usable
  PM1A address), and parks the CPU as the documented last
  resort. The companion `KernelReboot` already chained
  `AcpiReset` (FADT RESET_REG) → 0xCF9 → 8042 → triple-fault;
  the row's reset-fallback acceptance was met, only the S5
  acceptance was outstanding.
- **Why:** The Track 11-05 acceptance ("ExitWindowsEx
  (EWX_POWEROFF) powers off through ACPI S5 where supported")
  hinges on the kernel's halt path actually issuing the S5
  write. The AML interpreter to extract `\_S5_` and the
  PM1-register writer were both already in tree; the only
  missing piece was the `AcpiShutdown` call from `KernelHalt`
  itself. A two-line change.
- **Rules out / defers:** Real `_PTS` / `_GTS` method execution.
  The AML interpreter parses `Name`, not `Method` — firmware
  that requires `_PTS` to drive an EC or set a chipset bit
  before the PM1A write may stay powered. The QEMU shutdown
  ports cover the test fleet; bare-metal that needs `_PTS`
  is a future slice. S3 (suspend-to-RAM) stays deferred.
- **Revisit when:** a target machine in the test fleet stays
  powered after a `KernelHalt` call, indicating it needs the
  AML method-execution path.
- **Related roadmap track(s):** T11-05 closed.

---

## 2026-05-10 — Cross-process named-object namespace (T6-04)

- **Scope:** new `kernel/ipc/named_kobjects.{h,cpp}`,
  new `kernel/subsystems/win32/named_kobj_syscall.{h,cpp}`,
  `kernel/syscall/syscall.{h,cpp}`,
  `kernel/syscall/syscall_names.def`,
  `kernel/core/main.cpp` (boot self-test wiring),
  `userland/libs/kernel32/kernel32.c`,
  `wiki/reference/Roadmap.md`
- **Commit:** this slice
- **Decision:** Cross-process named mutex/event/semaphore
  ships via a new kernel-resident table.
  - Storage: 32-slot table guarded by a single spinlock, LRU
    eviction, max name length 64. Fits the typical Win32
    Global\/Local\ namespace footprint without growing the
    kernel data section.
  - Lifetime: the table holds a refcount on every registered
    KObject. The entry's refcount drops only when the slot is
    LRU-evicted by another Register call. Callers of
    `NamedKObjectFind` receive a fresh refcount they're
    responsible for releasing (typically by handing the
    kobject off to a HandleTable, which takes its own ref).
  - ABI: a single new syscall
    `SYS_NAMED_KOBJ_OPEN_OR_CREATE = 185` covers all three
    types via a 1-byte type field. `open_only=1` distinguishes
    `OpenMutex` from `CreateMutex` semantics. The syscall
    consumes (type, name, name_len_cap, init_state_or_owner,
    open_only) and returns a type-biased handle so the caller's
    existing CloseHandle / WaitForSingleObject paths route
    correctly.
  - Userland: `kernel32!Create{Mutex,Event,Semaphore}{A,W}`
    with a non-NULL name route through the new syscall; on
    success the result is also cached in the existing
    process-local table for hot-path lookup. `Open*` consults
    the local cache first, then falls through to the syscall
    with `open_only=1`. Unnamed paths stay on the existing
    SYS_MUTEX_CREATE / SYS_EVENT_CREATE / SYS_SEM_CREATE
    syscalls.
- **Why:** Win32 contract: `CreateMutexW(NULL, FALSE,
  L"Global\\Foo")` in process A and `OpenMutexW(0, FALSE,
  L"Global\\Foo")` in process B must return handles to the
  SAME kernel object. The previous userland-only name table
  was process-local — process B's lookup never saw process
  A's registration. A new syscall is the cleanest way to add
  the cross-process seam without ABI-breaking changes to the
  existing per-type Create syscalls.
- **Rules out / defers:**
  - Hierarchical namespaces (`Global\` vs `Local\` prefix
    handling — both flatten into the same table today).
    Workloads that depend on session-isolated naming will hit
    accidental aliases; not a concern for v0.
  - Permission gating. The caller's caps aren't checked; any
    process can open any name. Tracked under the broader
    cap-enforcement work, not Track 6.
  - Owner-pid tracking + process-exit cleanup. The table
    holds entries until LRU eviction; long-running boxes with
    many distinct names will see hot entries fight for slots.
    Bumping `kNamedKObjectSlots` is the v0 fix.
  - Refcount-on-last-handle-close → unregister. The table
    holds the entry until LRU; opens hit the cached object
    even after the original creator's last handle closes.
    Acceptable for v0 because Wait/Release on a kobj with
    only the table's ref is a no-op (the kobj is alive but
    has no active waiters).
- **Revisit when:** a workload exercises one of the
  deferred edges (a server that creates 100+ named events,
  hierarchical namespace use, or a need for process-exit
  cleanup). Each is mechanical to add without changing the
  syscall ABI.
- **Related roadmap track(s):** T6-04 closed.

---

## 2026-05-10 — Cross-process Win32 pipes (T11-02 closed)

- **Scope:** `kernel/proc/process.h`,
  `kernel/fs/file_route.cpp`,
  `kernel/subsystems/linux/syscall_pipe.{h,cpp}`,
  new `kernel/subsystems/win32/pipe_syscall.{h,cpp}`,
  `kernel/syscall/syscall.{h,cpp}`,
  `kernel/syscall/syscall_names.def`,
  `userland/libs/kernel32/kernel32.c`,
  `wiki/reference/Roadmap.md`
- **Commit:** this slice
- **Decision:** The Linux subsystem's pipe pool (16 slots × 4 KiB
  ring with proper waitqueue semantics, EPIPE on write-side
  close, EOF on read-side close, splice / tee fast-paths) is
  now the cross-subsystem canonical pipe primitive. Win32
  CreatePipe routes through it via:
  - A new `FsBackingKind::Pipe` variant on `Win32FileHandle`
    with `pipe_pool_idx` + `pipe_is_write_end` fields. Both
    ends of a single CreatePipe call share the same pool
    index; the bool distinguishes which end the slot owns.
  - `ReadForProcess` / `WriteForProcess` / `CloseForProcess`
    dispatch the new kind to `PipeRead` / `PipeWrite` /
    `PipeReleaseRead` / `PipeReleaseWrite`. Wrong-end calls
    (read on the write end / vice versa) return -1.
  - New `SYS_WIN32_CREATE_PIPE = 186` allocates a pool slot,
    reserves two Win32 handle table slots, stamps both, and
    `CopyToUser`s the read + write handles. Roll-back on any
    failure step drops both per-end refcounts so the pool
    entry tears down cleanly.
  - `PipeAlloc()` was hoisted out of the anonymous namespace
    in `syscall_pipe.cpp` and added to the public header so
    a single definition serves both subsystems.
  - Userland `kernel32!CreatePipe` issues the new syscall;
    the legacy in-process ring (`DUETOS_PIPE_RD/_WR` sentinels)
    stays as the kernel-OOM fallback so a 17th pipe still
    succeeds in a single process even though the kernel pool
    is full.
- **Why:** The previous CreatePipe was a userland-only ring
  buffer — single-process only. Track 11-02's acceptance
  ("Pipe-backed stdin/stdout/stderr redirection works across
  parent/child processes") needs the kernel pool. The Linux
  pool already had everything: refcounts, waitqueues, the
  ring buffer, and Linux pipe(2) was already feeding through
  it. Routing Win32 through the same pool is one new syscall
  + one new FsBackingKind variant.
- **Rules out / defers:**
  - Named pipes (`CreateNamedPipeW`, `ConnectNamedPipe`,
    `WaitNamedPipe`) — no kernel-side namespace registered for
    pipe names today; T6-04's `NamedKObjectFind` could be
    adapted but the I/O side needs more work.
  - Mailslots — analog of named pipes for one-shot messages.
  - CreateProcess stdio redirection — gated on T6-03
    (CreateProcess itself).
  - `SetNamedPipeHandleState` and the rest of the named-pipe
    surface — out of scope for v0.
- **Revisit when:** a workload exercises one of the deferred
  surfaces. Named pipes are the next logical add (extend
  `FsBackingKind::Pipe` with a name-table back-pointer +
  surface a SYS_WIN32_NAMED_PIPE_*).
- **Related roadmap track(s):** T11-02 closed.

---

## 2026-05-10 — Socket loopback via pipe-pool routing (T3-01 + T14-03)

- **Scope:** `kernel/net/socket.h`, `kernel/net/socket.cpp`,
  `kernel/syscall/syscall.cpp`,
  new `userland/apps/net_loopback_smoke/net_loopback_smoke.c`,
  `userland/apps/build-smokes.sh`, `kernel/CMakeLists.txt`,
  `kernel/proc/ring3_smoke.cpp`,
  `wiki/reference/Roadmap.md`
- **Commit:** this slice
- **Decision:** TCP loopback (`connect(127.0.0.1:port)` →
  listener bound to that port → matched accepted socket pair)
  is implemented entirely on top of the kernel's existing pipe
  pool (the same one Linux pipe(2) and Win32 CreatePipe consume).
  Two pipe pool slots make up a pair: a connector→server ring
  and a server→connector ring. The on-wire TCP slot
  (NetTcpActive + canned-reply) is bypassed when the destination
  is loopback, so loopback works regardless of e1000 binding.
  - New Socket fields: `loopback_paired`, `loopback_pipe_recv_idx`,
    `loopback_pipe_send_idx`, `loopback_pending_accept_idx`,
    `accept_wq`. The pending-accept slot is single-deep on the
    listener (v0 backlog = 1).
  - `SocketConnect` short-circuits when `peer_ip[0] == 127`:
    finds a listener bound to `peer_port`, allocates the
    accepted socket and the two pipe slots, wires both ends,
    parks the accepted-socket idx on the listener's pending
    slot, and wakes its accept_wq.
  - `SocketAcceptLoopback` is a non-blocking probe — pops the
    pending slot if present. The accept syscall handler in
    `syscall.cpp` runs a unified poll loop that checks both the
    loopback queue and the on-wire snapshot on every pass, so a
    single accept() services either path.
  - `SocketSendStream` / `SocketRecvStream` detect
    `loopback_paired` and route through `PipeWrite` / `PipeRead`
    on the per-end pipe slot; the pipe pool's existing
    waitqueue + EPIPE/EOF semantics carry full TCP-shaped
    blocking semantics for free.
  - `SocketRelease` drops the per-end pipe refcounts (read on
    one slot, write on the other). When both ends close, both
    pipe slots tear down via the pipe pool's existing
    refcount-on-zero free path.
- **Why:** T3-01's acceptance ("A PE can socket / connect
  127.0.0.1 / send / recv data in loopback") had been gated on
  the on-wire TCP slot being usable, which it is in QEMU SLIRP
  but not deterministically across boot. The pipe pool provides
  exactly the bytes-in / bytes-out contract loopback needs and
  we already rely on it (Linux pipe2, Win32 CreatePipe), so
  routing socket loopback through the same primitive is one
  small Socket extension + one new syscall-handler arm.
- **Rules out / defers:**
  - Multi-pending accept queue. The listener's pending slot is
    single-deep — a second connector that races a not-yet-
    accepted prior connector returns ECONNREFUSED. Bumping to
    a small ring is mechanical when a workload demands it.
  - Listener fairness across cross-port connectors. A connector
    matches the FIRST listener whose `local_port == peer_port`
    in pool-order; if a process binds two listeners on the same
    port through SO_REUSEPORT (which v0 doesn't support anyway),
    only the first one ever pairs.
  - On-wire ←→ loopback dual mode. A listening socket can be
    paired through loopback OR receive on-wire connections, but
    not both simultaneously: the accept syscall handler is
    unified but the listener's bookkeeping isn't. Real Win32
    listen() services both; v0 favours loopback when present
    and falls back to on-wire only if loopback isn't pending.
- **Revisit when:** a workload exercises one of the deferred
  paths (multi-connector burst, dual-mode listener).
- **Related roadmap track(s):** T3-01 + T14-03 closed (Track 3
  + Track 14 fully closed).

## 2026-05-10 — Kernel APC queue + NtQueueApcThread (T8-02)

- **What changed:**
  - New `Process::apc_slots[16]` ring carrying (target_tid, pfn,
    data) triples — the kernel-resident half of the APC delivery
    contract. Lives next to the existing user-space queue in
    `kernel32`, which now serves as the overflow buffer.
  - New syscalls `SYS_QUEUE_USER_APC = 187` +
    `SYS_DRAIN_USER_APC = 188`. Enqueue is cap-gated on
    `kCapSpawnThread` (same bar that lets a caller create a
    thread it could otherwise queue an APC against) and refuses
    cross-process targets — `SchedFindTaskByTid` resolves the
    target's owning Process and the handler returns -1 if it
    doesn't match the caller's. Drain pops the first slot whose
    `target_tid` matches `CurrentTaskId()`.
  - `kernel32!QueueUserAPC` tries the kernel queue first, falls
    back to the legacy user-space ring on overflow / cap denial.
    `kernel32!win32_drain_apc_queue` drains both queues.
    `ntdll!NtQueueApcThread` / `NtQueueApcThreadEx` route through
    `SYS_QUEUE_USER_APC`; `SystemArgument1` / `SystemArgument2`
    are dropped (NormalContext is packed as `ulData`).
  - Boot self-test (`ApcSelfTest`) drives queue / drain /
    cross-tid isolation / capacity overflow on a stand-in
    Process so any regression surfaces in the boot log.
- **Why:** The roadmap row called out two follow-ons:
  `NtQueueApcThread` and a kernel-resident per-thread APC list.
  The user-space queue worked for same-process polling but was
  invisible to the kernel — `NtQueueApcThread` and any future
  cross-thread "wake target out of a kernel-blocked alertable
  wait" path needed a queue the kernel can see. The 16-slot
  per-process kernel ring sized to match the existing user-space
  queue keeps the contract symmetric.
- **Rules out / defers:**
  - Cross-process APC delivery. Same-process is the v0 contract
    — cross-process needs target-side wake (a reschedule IPI to
    the target CPU after the enqueue) and a kernel-blocked
    alertable wait that the kernel can wake on the target's
    behalf. The roadmap row notes the deferral.
  - True three-arg `NtQueueApcThread` fidelity. The kernel queue
    carries one `ulData` payload; SystemArgument1/2 are ignored.
    Real apps relying on the three-arg form get the first arg
    only — which matches the SDK's `QueueUserAPC` shape; the
    extended shape is rare in practice.
  - Per-thread APC lists (vs. per-process). With at most 16
    pending APCs across all threads in a process, the
    target-tid scan inside the slot table is O(16) — not worth a
    per-thread split until a workload demands it.
- **Revisit when:** a real workload's profile shows kernel APC
  delivery latency dominating (would motivate per-thread
  splitting) or a PE depends on cross-process APC (would
  motivate the IPI-wake path).
- **Related roadmap track(s):** T8-02 closed.

## 2026-05-10 — CreateProcess stdio inheritance (T6-03 stdio)

- **What changed:**
  - New syscall `SYS_PROCESS_SPAWN_EX = 190` carrying a 24-byte
    `ProcessSpawnStdio` bundle (`stdin_handle / stdout_handle /
    stderr_handle`, each a Win32-shaped handle in the parent's
    `win32_handles` table). The kernel-side spawner walks the
    bundle pre-spawn (rejecting unsupported handle kinds
    cleanly), spawns via the existing `SpawnPeFile / SpawnElfFile`,
    then duplicates each non-zero handle into the child's table.
    Pipe handles bump the per-end pool refcount via
    `PipeRetainRead/Write` so the parent's CloseHandle doesn't
    tear the child's view down.
  - New syscall `SYS_GET_INHERITED_STD = 191` reads
    `Process::std_handles[idx]` (idx 0/1/2 = stdin/stdout/stderr)
    so `kernel32!GetStdHandle` can return the inherited Win32
    handle when it exists, falling back to the legacy
    pseudo-handle (-10/-11/-12) otherwise.
  - `kernel32!CreateProcessA/W` decodes
    `STARTUPINFO.dwFlags & STARTF_USESTDHANDLES` from the
    104-byte STARTUPINFO layout and routes to the new syscall
    when set; falls back to `SYS_PROCESS_SPAWN` otherwise so
    non-inheriting callers see no behaviour change.
- **Why:** A parent that wants to read its child's stdout —
  the canonical CreateProcess use case — needed the child's
  WriteFile(STD_OUTPUT_HANDLE, ...) to land on the parent's
  CreatePipe-allocated read end instead of the global serial
  console. Without per-process stdio handles, every child
  shared one stdout fd and the parent had no read path.
- **Rules out / defers:**
  - Process-attribute lists (PROC_THREAD_ATTRIBUTE_*). The
    Win32 STARTUPINFOEX layout extends STARTUPINFO with an
    attribute list pointer; v0 ignores it. Same precedent as
    `lpDesktop / lpReserved` — recorded in user space, not
    consulted by the kernel.
  - Cursor-share inheritance. Child gets a fresh `cursor = 0`
    on each duplicated handle. Real Windows shares the open
    file description's cursor — that's a separate slice
    once a workload exercises shared offsets across processes.
  - Job-object propagation, environment-block parsing,
    duplicate-handle ACL gating. All ride later.
- **Revisit when:** a workload depends on shared cursors,
  STARTUPINFOEX attribute lists, or full Job-object
  inheritance.
- **Related roadmap track(s):** T6-03 stdio half closed; the
  CreateProcess + wait + exit-code half was already covered by
  the pre-existing PROCESS_OPEN / Wait / Exit path.

## 2026-05-10 — Win32 priority class on Process (T8-01 partial)

- **What changed:**
  - `Process::win32_priority_class` (u32) records the Windows
    priority-class constant (NORMAL_PRIORITY_CLASS = 0x20,
    HIGH_PRIORITY_CLASS = 0x80, etc.).
  - New syscall `SYS_PRIORITY_CLASS = 189` (op=get/set) round-trips
    the value. `kernel32!SetPriorityClass / GetPriorityClass`
    route through it; the previous kernel-side
    `kOffReturnPrioNormal` thunk fallback stays as the
    catch-all for old PEs that don't bind the real export.
- **Why:** Two of the three T8-01 acceptance prongs (priority
  class storage + Win32 priority class mapping) are scheduler-
  independent — the value just needs to round-trip through
  Process state. The third prong (priority aging / decay /
  preemption) requires per-CPU runqueue lock-splitting (the
  B2-followup row) before adding bands makes sense.
- **Rules out / defers:**
  - Scheduler bias on the priority class value. The runqueue
    is single-band; the value is recorded but not consulted on
    enqueue. A future MLFQ rebuild reads it.
  - Per-thread priority (`SetThreadPriority`). The Win32 thread
    priority is a delta off the process's class; v0 ignores
    the delta entirely.
  - Cross-process SetPriorityClass on a non-self handle.
    `kernel32!SetPriorityClass` ignores `hProcess` and modifies
    only the calling process — fits v0's "no cross-process
    process-wide knobs" stance.
- **Revisit when:** the scheduler split (B2-followup) lands
  and a workload exercises priority-class-driven scheduling.
- **Related roadmap track(s):** T8-01 partial — full closure
  rides on the per-CPU lock split.

## 2026-05-10 — Multi-heap process allocator (T5-02)

- **What changed:**
  - `Process::extra_heaps[4]` carries up-to-16-page secondary
    heaps (1 MiB stride from 0x55000000). The first-fit walker
    in `kernel/subsystems/win32/heap.cpp` was refactored to take
    a `Win32HeapBinding` (base, pages, free-head pointer); the
    legacy `Win32HeapAlloc / Free / Size / Realloc` are now
    thin wrappers that build a binding for the default heap.
  - New syscalls:
    `SYS_HEAPEX_CREATE = 192` (allocate frames + map RW+NX +
    seed free list), `SYS_HEAPEX_DESTROY = 193` (unmap pages +
    free slot), `SYS_HEAPEX_ALLOC / FREE / SIZE / REALLOC =
    194 / 195 / 196 / 197` (handle in rdi, payload args in
    rsi/rdx). `Win32HeapResolveHandle` resolves both 0 and
    `kWin32HeapVa` to the default heap so userland can pass
    either as a handle without crossing the secondary-heap path.
  - `kernel32!HeapAlloc / HeapFree / HeapSize / HeapReAlloc /
    HeapCreate / HeapDestroy` route through the new syscalls;
    `dwFlags & HEAP_ZERO_MEMORY = 0x8` is honoured in user
    space (the kernel doesn't know which payload the caller
    cares about, so userland zeros after a successful alloc).
  - CRT `malloc / free / realloc` continue routing through the
    legacy `SYS_HEAP_ALLOC` (11) / `SYS_HEAP_FREE` (12) /
    `SYS_HEAP_REALLOC` (15) on the default heap. No userland
    rebuild required for those paths.
- **Why:** A PE that calls `HeapCreate` followed by
  `HeapAlloc(hHeap, ...)` previously got the same heap as
  `GetProcessHeap` — corrupting the default heap's free list
  if the secondary heap had different lifetime semantics. The
  acceptance ("a PE can allocate from and destroy a secondary
  heap without corrupting the default heap") needs each heap
  to keep its own free list; the binding refactor lets one
  walker serve both.
- **Rules out / defers:**
  - Heap coalescing on free. Adjacent freed blocks stay
    separate; fragmentation is accepted (same v0 contract as
    the default heap).
  - Heap growth past 16 pages. `HeapCreate` clamps the page
    request silently. A workload that hits the cap can grow
    `kWin32ExtraHeapPagesMax`.
  - More than 4 simultaneous secondary heaps. Cap matches
    typical Win32 apps (CRT keeps one private heap; most apps
    never call HeapCreate).
  - HEAP_GENERATE_EXCEPTIONS / HEAP_NO_SERIALIZE /
    HEAP_REALLOC_IN_PLACE_ONLY flag handling. Ignored at the
    user-space wrapper.
  - HeapWalk / HeapValidate / HeapCompact behaviour on
    secondary heaps. Existing kernel32 stubs return success
    for the default heap; secondary-heap-aware versions ride
    once a workload exercises them.
- **Revisit when:** a workload exercises one of the deferred
  capabilities (in-place realloc, walk/validate on a
  secondary heap, > 4 heaps, > 64 KiB heap).
- **Related roadmap track(s):** T5-02 closed.

## 2026-05-10 — Overlapped I/O via IOCP (T7-03)

- **What changed:**
  - `kernel32!CreateIoCompletionPort(hFile, hExisting, key, ...)`
    now registers a (file_handle → iocp_handle, key) binding in
    a 16-slot user-space table when `hFile` is a kernel file
    handle (range 0x100..0x10F). The existing port creation
    path is unchanged; binding is purely additive.
  - `kernel32!ReadFile` / `WriteFile` honour `lpOverlapped` for
    kernel file handles: read `OVERLAPPED.Offset` /
    `.OffsetHigh`, seek to that position via SYS_FILE_SEEK,
    perform the synchronous read/write, then stamp
    `OVERLAPPED.Internal` (status code) + `.InternalHigh`
    (bytes transferred). If the handle is bound to an IOCP,
    a completion packet (key, OVERLAPPED*, bytes) is posted
    to the bound port via the existing in-process IOCP ring
    so a subsequent `GetQueuedCompletionStatus` surfaces the
    result.
  - End-to-end smoke (`userland/apps/iocp_overlapped_smoke/`)
    exercises CreateFileA + WriteFile + reopen + bind + ReadFile
    with OVERLAPPED + GetQueuedCompletionStatus + payload check.
- **Why:** The acceptance row called out a PE using overlapped
  reads receiving completion through GQCS. The existing IOCP
  ring worked for `PostQueuedCompletionStatus`-driven posts but
  the kernel never connected file I/O to the ring — every
  overlapped read silently dropped the completion. The 16-slot
  binding table + ReadFile/WriteFile patch closes the loop in
  user space without a kernel-side I/O queue rewrite.
- **Rules out / defers:**
  - True `ERROR_IO_PENDING` async completion. The I/O is
    synchronous; the completion packet is posted before
    `ReadFile` returns. Real Windows allows the I/O to be
    pending while the caller waits on GQCS — that needs a
    kernel-side I/O scheduler (DPCs, deferred completion).
  - Share-mode enforcement (`FILE_SHARE_READ` /
    `FILE_SHARE_WRITE` etc.) on CreateFileA/W. v0 doesn't
    track share modes; concurrent opens on the same file
    succeed regardless. Acceptable until a workload races.
  - `OVERLAPPED.hEvent` signaling. Apps using a manual-reset
    event for sync still see the event un-signalled even
    though the I/O completes. Easy to layer on top of the
    existing user-side event API once a workload demands it.
  - Cross-thread completion delivery. The user-side IOCP
    ring is in-process; a cross-process IOCP would need a
    kernel-side port pool (which we already have via SYS_IOCP_*
    but don't wire to ReadFile/WriteFile yet).
- **Revisit when:** a workload depends on real async semantics
  (ERROR_IO_PENDING + in-flight I/O), share-mode enforcement,
  or hEvent signaling.
- **Related roadmap track(s):** T7-03 closed.

## 2026-05-10 — IRQ-safe KMalloc / KFree (T5-04 partial)

- **What changed:**
  - `kernel/mm/kheap.cpp` gets a `KheapIrqOff` RAII that
    disables interrupts on entry and restores `IF` only if it
    was set on entry. Same shape as
    `FramePoolIrqOff` (frame allocator) and `IrqOff` (slab).
    Both `KMalloc` and `KFree` now bracket their state-mutating
    body with a `KheapIrqOff irq_guard;`.
  - `wiki/kernel/Memory-Management.md` gains an
    "Allocator family — context contract" table summarising
    IRQ-safety + SMP-safety + sleep status across frame
    allocator / kheap / slab / kstack.
- **Why:** The kheap was previously single-CPU + IRQ-unsafe.
  Any IRQ handler that itself called `KMalloc` (event-trace
  growth, log ring resize, frame-allocator audit-trail buffer)
  could re-enter the heap mid-mutation and observe a half-
  updated freelist — a class of bug that would surface only
  under load. Bracketing with IRQ-disable matches the rest of
  the allocator family and closes the immediate window without
  waiting for the SMP lock-split.
- **Rules out / defers:**
  - SMP-safe heap. The `KheapIrqOff` brace handles re-entrance
    on a single CPU; cross-CPU contention still races. Adding
    `spin_lock_irqsave` rides on the per-CPU scheduler-lock
    split (B2-followup) so the lockdep ordering can absorb
    the new dependency.
  - Buddy coalescing on the kheap. Adjacent free chunks stay
    separate; fragmentation is accepted (same v0 contract).
  - Per-CPU slab magazines. Profile evidence triggers it.
- **Revisit when:** SMP brings actual cross-CPU heap contention,
  or a profile shows fragmentation hurting workloads.
- **Related roadmap track(s):** T5-04 partial — IRQ-safety + docs
  closed; coalescing + magazines deferred.

## 2026-05-10 — Per-thread Win32 TLS slot values (T6-01 partial)

- **What changed:**
  - `sched::Task` gets a 64-slot `win32_tls_slot_value[64]`
    array (512 bytes per task, ~15 KiB at peak across ~30 live
    tasks). Reachable via two new accessors
    `sched::CurrentTaskTlsSlotValue(idx)` /
    `SetCurrentTaskTlsSlotValue(idx, value)` that mirror the
    existing `CurrentTaskWin32LastError` shape.
  - `kernel/subsystems/win32/tls_syscall.cpp` (DoTlsGet /
    DoTlsSet) now reads/writes the per-thread storage
    instead of `Process::tls_slot_value`. DoTlsAlloc still
    uses `Process::tls_slot_in_use` for the allocation
    bitmap — TlsAlloc returns one shared slot index across
    every thread in the process, by Win32 contract.
- **Why:** Pre-fix, every thread in the same Process shared
  one `Process::tls_slot_value[]` array. Two threads calling
  `TlsSetValue(5, x)` would clobber each other — a correctness
  bug, since dynamic TLS is supposed to give each thread an
  independent value per slot. Single-threaded Win32 PEs didn't
  trip it, but `pe_stress` and any future multithreaded smoke
  would. Per-thread storage closes that gap.
- **Rules out / defers:**
  - Static TLS via `__declspec(thread)`. The compiler-emitted
    code reads through `gs:[0x58]`
    (`TEB.ThreadLocalStoragePointer`) into a per-module TLS
    block. The PE loader still rejects PEs with a non-empty
    TLS callback array (`pe_loader.cpp` step 3b), and even
    PEs with an empty callback array don't get a per-thread
    template allocation today. Full closure needs the
    template-walk + per-thread block alloc + TEB.TLSPtr
    population + TLS-callback ring-3 thunk.
  - Larger slot caps (the 64-slot v0 limit fits every CRT we
    ship; lifting it costs 8 bytes per slot per Task).
- **Revisit when:** a real PE depends on `__declspec(thread)`,
  or the PE-loader follow-up that wires the static-TLS
  template lands.
- **Related roadmap track(s):** T6-01 partial — dynamic TLS
  closed; static TLS + callbacks defer.

## 2026-05-10 — winmm waveOut API surface (T12-03 partial)

- **What changed:**
  - New syscall `SYS_AUDIO_DEVICE_INFO = 198` queries the audio
    backend for HDA-class controller presence + the canonical
    48 kHz / stereo / 16-bit format. Counts only HDA controllers
    (not AC'97 / legacy) since winmm's playback path has no
    backend wired for those today.
  - `winmm!waveOutGetNumDevs` returns 1 when an HDA codec is
    brought up, 0 otherwise — replacing the always-zero stub.
  - `winmm!waveOutOpen` returns a real sentinel handle
    (`MM_AUDIO_HDA_HANDLE_SENTINEL = 0xA1A0001`) when a device
    is present so PEs no longer get `MMSYSERR_NODRIVER` at
    probe time.
  - `waveOutPrepareHeader` stamps `WHDR_PREPARED`,
    `waveOutWrite` stamps `WHDR_DONE` synchronously,
    `waveOutUnprepareHeader` clears the prepared flag. A poll-
    for-completion loop terminates because the buffer is
    immediately marked done.
- **Why:** Two audiences depend on this surface:
  1. PEs that probe waveOut at startup and gate functionality
     on success — they now get past the probe and continue
     normally. Even though no audio plays, the rest of the
     program runs.
  2. PEs that wait for `WHDR_DONE` before proceeding — they
     no longer hang.
  Real playback rides on the DMA-coherent buffer pool +
  BDL programming work under the "Audio — HDA codec / stream
  programming" Roadmap row, which is its own slice.
- **Rules out / defers:**
  - Real samples reaching the codec. Buffers are accepted but
    dropped. Closing this needs DMA buffer alloc + BDL
    program + RUN bit + completion notification — kernel-side
    work that crosses the audio backend.
  - waveIn (recording). Same scaffolding gap as waveOut.
  - Mixer / waveOutSetVolume hardware backend. The volume
    setter still no-ops; the stored value isn't propagated to
    the codec amp gain.
  - waveOutGetDevCaps (per-device capability query). Currently
    NOOP; could plumb through SYS_AUDIO_DEVICE_INFO with
    additional ops.
- **Revisit when:** the DMA-coherent buffer pool + BDL+RUN
  path lands, or a workload depends on real playback.
- **Related roadmap track(s):** T12-03 partial — API surface
  closed; backend playback defer.

## 2026-05-10 — VirtualAlloc reserve/commit + protection (T5-01 partial)

- **What changed:**
  - `Process::vmap_regions[16]` records `{base_va, pages,
    committed_bits (u32 bitmap), protection}` per Win32-style
    VirtualAlloc region. Carved out of the existing vmap arena
    (kWin32VmapBase = 0x40000000), region cap at 32 pages
    matches the bitmap width.
  - Three new syscalls: `SYS_VIRTUAL_ALLOC = 199`,
    `SYS_VIRTUAL_FREE = 200`, `SYS_VIRTUAL_PROTECT = 201`. The
    alloc handler dispatches on the `MEM_RESERVE` /
    `MEM_COMMIT` flag combo:
    * `MEM_RESERVE` alone — claim a region slot, no frame alloc.
    * `MEM_RESERVE | MEM_COMMIT` — claim + map all pages.
    * `MEM_COMMIT` alone with non-zero `hint_va` — commit the
      touched pages of an existing reservation.
  - `SYS_VIRTUAL_FREE` honours `MEM_DECOMMIT` (unmap pages,
    keep slot) and `MEM_RELEASE` (unmap + clear slot).
  - `SYS_VIRTUAL_PROTECT` translates `PAGE_*` to the AS layer's
    page flags and calls `AddressSpaceProtectUserPage` for each
    committed page in the touched range. `PAGE_EXECUTE*` is
    rejected (W^X enforcement).
  - `kernel32!VirtualAlloc / VirtualFree / VirtualProtect`
    route through the new ABI; the legacy `SYS_VMAP` (28) /
    `SYS_VUNMAP` (29) entry points stay as the bump-arena
    fallback for in-tree callers that haven't been migrated
    yet (no caller currently uses them, but the entry points
    remain to keep the ABI surface forward-compatible).
- **Why:** MSVC CRT startup probes the stack with
  reserve-then-commit; AppVerifier and a few telemetry libraries
  call `VirtualProtect` to flip a page from RW to RO before
  re-checking. Pre-fix: every call returned the same RW+NX
  page regardless of caller intent, so a real PAGE_READONLY
  request silently received writable memory. Real region
  tracking + AS-level protect closes that gap.
- **Rules out / defers:**
  - PAGE_GUARD / one-shot trap-then-reset semantics. Real
    Windows fires STATUS_GUARD_PAGE_VIOLATION on first touch
    and auto-clears the flag. v0 rejects PAGE_GUARD at the
    protection translator and returns 0 from VirtualAlloc /
    VirtualProtect.
  - PAGE_NOACCESS that actually traps on read. v0 maps as
    "Present + User + NX, no Writable" — read still works.
    Closing the gap needs the AS layer to support the "not
    present but reserved" PTE state without confusing the
    region tracker.
  - Cross-region merging / splitting on partial commit. v0
    refuses MEM_RESERVE | MEM_COMMIT on a hint_va that lands
    inside an existing reservation; only the explicit "commit
    into existing" path handles partial commit.
  - NtAllocateVirtualMemory ABI mirror. The Win32 syscall
    forwards to the same SYS_VIRTUAL_ALLOC path; ntdll's
    Native API stub is still a thin wrapper.
- **Revisit when:** an MSVC PE depends on PAGE_GUARD (typically
  thread-stack-overflow probes), or PE startup fails because of
  a real PAGE_NOACCESS gap.
- **Related roadmap track(s):** T5-01 partial — reserve/commit
  + protection closed; guard pages + true NOACCESS defer.

## 2026-05-10 — Disk-installer orchestration + Method-form `_S5_` decode

- **What:** two Tier-0 daily-driver gaps closed in one pass.
  - **`install <handle> INSTALL` shell command** (`kernel/fs/installer.{h,cpp}`,
    `kernel/shell/shell_storage.cpp::CmdInstall`). Drives the destructive
    sequence that turns a blank block device into a DuetOS-bootable
    layout: `GptInitDisk` (3-partition GPT — ESP, system, crash-dump),
    `Fat32Format` on ESP + system, ESP `boot/grub/grub.cfg` + system
    `boot/.duetos-installed` sentinel writes, `VfsMount(/esp)` +
    `VfsMount(/system)`. Admin-gated; literal `INSTALL` confirmation
    token; refuses disks under 100 MiB. Disk + per-partition unique
    GUIDs are RFC-4122 v4 (`FillRandomGuid` stamps version + variant
    bits over `RandomU64()`). Crash-dump partition uses
    `kDuetCrashDumpTypeGuid` so the existing `GptFindCrashDumpRegion`
    path discovers it on next boot.
  - **AML method-form `_S5_` decode** (`kernel/acpi/aml.cpp::AmlReadS5`).
    The namespace walker already records `Method(_S5_)` entries
    (kind = AmlObjectKind::Method); `AmlReadS5` now also accepts
    those. It reads the method's PkgLength to bound the body, skips
    NameString + MethodFlags, and scans for the canonical
    `Return(Package(...))` byte sequence (`0xA4 0x12`). Bounded
    16-byte scan span keeps malformed AML from becoming a foothold.
- **Why:** the installer was the highest-impact Tier-0 gap — without
  it DuetOS was ISO-only, no on-disk life. The primitives (GPT-init,
  FAT32-format, partition block devices, mount registry) all shipped
  earlier; the orchestration was the missing piece. The Method-form
  `_S5_` decode is the smallest possible step toward "actually
  shutting down on real consumer firmware" — most modern UEFI uses
  the Name form, but a meaningful slice of OEM-modified firmware
  (especially older / locked machines) defines `_S5_` as a method.
- **Rules out / defers:**
  - **Bootloader-bytes copy.** v0 of the installer lays down the
    partition skeleton and the chainload stub, not the actual
    `BOOTX64.EFI` + `duetos-kernel.elf` bytes on disk. Embedding the
    running kernel into ramfs is the bootstrap problem (kernel.elf
    bytes change after the embed, requiring a two-stage build).
    Out-of-band staging (USB / network / ISO chainload) is the
    likely first cut. The installer prints a follow-up note pointing
    at this.
  - **Full AML method interpreter.** Method bodies more complex than
    `Return(Package{...})` — sub-method calls, conditionals, integer
    expressions, `_PTS` / `_GTS` evaluation — are still beyond the
    walker. Closing this is its own slice.
  - **Self-test for Install at boot.** A KMalloc-backed RAM block
    device caps at the 2 MiB kheap; an installer self-test would
    need a ≥ 100 MiB synthetic disk. The constituent primitives
    (`GptSelfTest`, `Fat32SelfTest`, mount-table + partition-block
    self-tests) cover the components; the orchestration is exercised
    by the operator running `install <handle> INSTALL` on a real
    target.
- **Revisit when:** the bootloader-bytes path lands (graduates this
  entry to a "fully shipped" line) or a real chipset surfaces an
  `_S5_` Method body the v0 scanner can't decode (extends the
  scanner toward a real interpreter).
- **Related roadmap track(s):** End-user features → Disk installer
  (orchestration closed; bootloader-bytes residual remains);
  End-user features → ACPI S5 (method-form `_S5_` closed; full
  AML interpreter still open).

## 2026-05-10 — Installer UEFI-loader copy + layout self-test

- **What:** the disk installer now ships the easy half of the
  bootloader-bytes residual.
  - **`BOOTX64.EFI` embedded into the kernel image.** New
    `generated_bootx64_efi.h` produced by a custom command in
    `kernel/CMakeLists.txt` that runs `embed-blob.py` on the
    `${DUETOS_UEFI_EFI}` artifact (set by `boot/uefi/CMakeLists.txt`).
    Top-level `CMakeLists.txt` reorders so `boot/uefi` is processed
    before `kernel`, exposing the cache var to the kernel
    `add_custom_command`. New accessors
    `RamfsBootX64EfiBytes()` / `RamfsBootX64EfiSize()` in
    `fs/ramfs.{h,cpp}`.
  - **`installer.cpp::WriteEspGrubStub`** now also writes
    `/EFI/BOOT/BOOTX64.EFI` to the freshly-formatted ESP from the
    embedded blob — the canonical UEFI fall-back removable-media
    path. Real-hardware UEFI firmware finds the loader by the
    spec-mandated path with no explicit boot-variable setup.
  - **`PlanLayout` factored out** of `Install` and exposed in
    `installer.h`. Pure math (no I/O); takes `disk_sectors`,
    fills the six LBA fields of a `Report`. `Install` calls it
    first thing.
  - **`InstallerSelfTest`** wired into the boot path next to
    `Fat32SelfTest`. Exercises `PlanLayout` against four canonical
    sizes (just-too-small, just-large-enough at
    `kMinInstallSectors`, 1 GiB, 1 TiB) and the null-out case.
    Panics on layout regression. Surfaced a real off-by-some bug
    in the original `kMinInstallSectors = 196608` constant — the
    actual minimum is `ESP + min-system + crash-dump + GPT
    overhead = 204867`. Replaced the hard-coded number with a
    computed expression so future bumps to `kEspSectors` /
    `kCrashDumpSectors` stay self-consistent.
- **Why:** the bootloader-bytes residual was the headline
  remaining gap on the installer. Splitting it into "UEFI loader
  bytes" (a separate build artifact, no bootstrap problem) and
  "kernel-ELF bytes" (the real two-stage problem) lets us close
  half cleanly. The ESP now has a complete loader skeleton —
  grub.cfg + BOOTX64.EFI both present at the right paths — so
  the only piece still pending is the kernel ELF itself.
  Layout-math self-test is cheap and pays for itself the first
  time a constant drifts.
- **Rules out / defers:**
  - **Two-stage kernel-ELF embed.** Real path forward — build
    once to produce kernel-stage-1.elf, build again to embed
    those bytes as a blob in kernel-stage-2.elf. Doubles build
    time; the alternative is out-of-band staging (USB / network /
    ISO chainload) which keeps build cheap. Defer until the cost
    of doubling build time becomes a nuisance.
  - **Self-test against a real RAM disk.** A 100+ MiB synthetic
    disk would exceed the 2 MiB kheap; testing the full
    `Install` pipeline at boot needs a different allocation
    strategy. The `GptSelfTest` + `Fat32SelfTest` cover the
    constituent primitives; `InstallerSelfTest` covers the
    layout math. End-to-end verification is shell-driven on
    real targets.
- **Revisit when:** the kernel-ELF embed lands (full
  `installer.cpp` ships, deletes the residual row from
  `Daily-Driver-Readiness.md` Tier 0).
- **Related roadmap track(s):** End-user features → Disk
  installer (residual now is kernel-ELF copy only; UEFI loader
  closed).

## 2026-05-10 — Installer `--duetfs` + DuetFS audit

- **What:** correction pass + an installer extension.
  - **Audit-driven correction.** The Daily-Driver-Readiness Tier-0
    row claimed DuetFS was "read-only". In fact DuetFS ships with
    the full write surface (`duetfs_write_at` /
    `duetfs_create_path` / `duetfs_unlink_path` /
    `duetfs_truncate` / `duetfs_link` / `duetfs_create_symlink`),
    a journal, AES-XTS sector encryption, Argon2id KDF, LZ4
    compression, snapshots, and CRC-checked blocks — all
    exercised by per-feature self-tests at every boot. Auto-
    mounted at `/duetfs` (RAM-backed, 256 KiB) and at
    `/disks/duetfsN` for on-disk volumes. Wired through
    `kernel/fs/file_route.cpp` so `SYS_FILE_OPEN` /
    `SYS_FILE_READ` / `SYS_FILE_WRITE` reach `duetfs_*` for
    DuetFS-backed handles. Refreshed the row to describe what's
    actually shipped.
  - **`kDuetFsTypeGuid` GPT type GUID** landed in
    `kernel/fs/gpt.h`, paralleling `kDuetCrashDumpTypeGuid`.
    Picked so the printable bytes spell "DUETOSDUETOSDUET" — a
    DuetFS volume self-identifies in `lsgpt` output and external
    tooling (`fdisk -l`) classifies it as "unknown DuetOS"
    rather than misidentifying as Microsoft Basic Data.
  - **Installer `--duetfs` flag** in
    `kernel/fs/installer.{h,cpp}` and
    `kernel/shell/shell_storage.cpp::CmdInstall`. `Install` now
    takes `bool use_duetfs_system`; when true the system
    partition is formatted with `duetfs::duetfs_mkfs` (cookied
    through `duetfs::MakeBlockHandleDevice`), typed
    `kDuetFsTypeGuid`, and mounted via `FsType::DuetFs`. Default
    behaviour unchanged: FAT32, `kSystemTypeGuid` (Microsoft
    Basic Data), interoperable. `WriteSystemSentinel` is skipped
    on `--duetfs` for now — DuetFS path-create needs a NUL-
    terminated path through the Rust ABI which the installer
    doesn't currently wrap. The post-mkfs `duetfs_probe` success
    is the proof the partition is initialised; the sentinel was
    cosmetic.
- **Why:** the installer was the most-requested "make this OS
  installable" item. DuetFS as the system FS gives operators a
  journalled / encryption-capable native filesystem for the
  partition that holds the kernel + user data, while keeping the
  ESP FAT32 (which UEFI mandates). The audit correction matters
  because a wiki claim that's wrong about a fully-shipped feature
  hides the work from the next reader and lets stale "missing"
  rows accumulate.
- **Rules out / defers:**
  - **DuetFS sentinel write at install time.** Path-create
    through the Rust ABI requires NUL-terminated path bytes
    + size; not yet wrapped. Cosmetic; defer until a workload
    exercises the path-create surface from C++.
  - **DuetFS-as-`/`-root direct boot.** Currently the kernel
    chain goes UEFI → FAT32 ESP → multiboot2 → DuetOS kernel →
    DuetFS at `/system`. Booting a DuetFS partition directly
    would need a DuetFS reader in GRUB / UEFI, OR a tiny FAT
    partition holding just the kernel ELF that pivots to DuetFS
    immediately. The pivot path is mechanical once the
    kernel-ELF embed lands; the GRUB-DuetFS-reader path is
    upstream-GRUB scope.
- **Revisit when:** the kernel-ELF embed lands on the installer
  (graduates the disk-installer track entirely) or a workload
  exercises the DuetFS path-create surface from C++.
- **Related roadmap track(s):** End-user features → Disk
  installer (residual is now kernel-ELF copy only); Filesystem →
  DuetFS follow-ups (the row's "writable native FS" gap was
  always closed; visibility was the issue).

## 2026-05-10 — Installer kernel-ELF embed via `.incbin` (opt-in)

- **What:** new CMake option `DUETOS_INSTALLER_KERNEL_EMBED`
  (default OFF) drives a `.incbin` directive in
  `kernel_elf_blob.S`, generated by
  `tools/build/gen-kernel-blob.sh`, that pulls the stage-1
  `duetos-kernel.elf` bytes into stage 2's `.rodata`. Stage 1
  carries a separate always-empty stub blob (so its references
  link cleanly). New ramfs accessors `RamfsKernelElfBytes()` /
  `RamfsKernelElfSize()` expose the bytes; the installer's
  `WriteSystemSentinel` writes `/system/boot/duetos-kernel.elf`
  whenever the size is non-zero. The shell `install` command's
  final summary now reports which of the three bytes states
  (BOOTX64.EFI written; kernel.elf-with-DuetFS-skipped;
  kernel.elf-not-embedded; kernel.elf-written-N-bytes) actually
  ran.
- **Why `.incbin`:** the existing `embed-blob.py` emits constexpr
  byte-array literals which compile in time linear with file
  size; a 10 MiB blob would balloon kernel compile time by
  minutes. `.incbin` is processed by the assembler in constant
  time — no matter how big the file. Cost is binary size only.
- **Why opt-in:** ON path doubles kernel binary (~10 MiB →
  ~21 MiB) and ISO size (~18 MiB → ~28 MiB), AND surfaces a
  runtime issue: the larger image consumes the entire 0..16 MiB
  DMA zone and trips the `mm/zone` boot self-test. Default OFF
  keeps build cost off the iteration loop and lets us land the
  pipeline (embed-blob → ramfs accessor → installer write)
  without forcing the linker-script slice that fixes the DMA
  zone. Operators wanting a self-installable ISO build with
  `-DDUETOS_INSTALLER_KERNEL_EMBED=ON` and currently get an
  image-correct but non-self-bootable kernel — useful for
  "build on machine A, install onto machine B" workflows.
- **Rules out / defers:**
  - **Self-booting embed path.** Linker-script slice that
    places the blob at a higher physical region (32 MiB+) so
    the DMA zone stays usable. Mechanical once we decide the
    layout; deferred because the ON path's "build once, install
    elsewhere" use case is sufficient for now.
  - **Runtime self-image extraction.** Reading the kernel
    image from physical memory at install time would dodge the
    bootstrap problem entirely (no embed needed) and also
    bypass the binary-doubling cost. More invasive — needs to
    emit a valid ELF from the live segments — but a real path
    forward.
  - **Two-stage symbol table on the embedded kernel.** The
    embedded bytes are stage-1 (stub symbols, no addr2line
    table). An installed kernel would have stub-symbol
    backtraces. Acceptable; future-stage embed could chain
    further.
- **Revisit when:** the linker-script slice lands (opens
  self-bootable embed) or a workload demands runtime self-image
  extraction.
- **Related roadmap track(s):** End-user features → Disk
  installer (kernel-ELF embed shipped as opt-in; DMA-zone fix
  is the closing residual).

## 2026-05-11 — Spectre v1 nospec at audited dispatch sites (Class N follow-up)

- **Context:** `util::MaskedIndex` had been in the tree since the
  Linux CVE audit (Class N) but only two callsites — Linux fd
  dispatch in `syscall_io.cpp::DoRead` / `DoWrite` — actually used
  it. The roadmap row called for the helper to be walked across
  every syscall-dispatch table where a user-supplied integer
  indexes an array (Linux fd, Win32 NT handle table, Win32 thread
  / process / GDI handle tables) and inserted at the dispatch
  site. Without the masks, a misprediction of the `if (idx >= N)`
  branch could still speculate the array load past the table even
  though the architectural path was correctly bounded — the same
  class as Spectre v1 / bounds-check bypass in Linux.
- **Decision:** Apply `util::MaskedIndex(idx, bound)` between the
  runtime bounds check and the array load at every audited
  user-controlled dispatch site. The check stays unchanged (it
  protects correctness); the mask is the speculative-window
  bound.
- **Sites hardened in this slice:**
  - **Win32 NT object handle table** — `HandleTableLookup`,
    `HandleTableLookupRef`, `HandleTableRemove` in
    `kernel/ipc/handle_table.cpp` (drives every
    `HandleTableLookup(KObjectType::*)` consumer — events,
    mutexes, semaphores, files, mailboxes, waitables — so each
    NT-object subsystem inherits the mitigation from one
    chokepoint).
  - **Win32 thread / process handle dispatch** —
    `LookupThreadHandle`, `LookupProcessHandle`,
    `SYS_THREAD_EXIT_CODE`, `SYS_THREAD_WAIT`, the
    wait-multiple poll loop's thread branch, and
    `SYS_GET_INHERITED_STD` in `kernel/syscall/syscall.cpp`.
  - **Win32 GDI handle tables** — `GdiLookupMemDC`,
    `GdiLookupBitmap`, `GdiLookupBrush`, `GdiLookupPen`,
    `GdiWindowDcState`, `GdiSysColor`, `GdiSysColorBrush` in
    `kernel/subsystems/win32/gdi_objects.cpp`.
  - **Win32 file handle resolver** — `HandleToSlot` in
    `kernel/fs/file_route.cpp` (chokepoint for every consumer
    of `proc->win32_handles[slot]`).
  - **Linux fd dispatch** — `DoClose`, `DoFstat` in
    `syscall_file.cpp`; `DoFchdir` in `syscall_path.cpp`;
    `ResolveFdToPath` in `syscall_xattr.cpp`;
    `DoPidfdSendSignal`, `DoPidfdGetfd`, `DoSplice`, `DoTee`,
    `DoVmsplice` in `pidfd_splice.cpp`.
- **Alternatives considered (and why not):**
  - Compiler-emitted `__builtin_constant_p`-style speculation
    fence at every branch — drags Spectre v1 cost into the
    architectural critical path and the kernel already
    correctly bounds-checks. The mask cost is one AND on the
    register-already-loaded index.
  - One global "all kernel arrays are sliced through a masked
    helper" wrapper type — too invasive for v0; mechanical
    site-by-site application keeps the diff inspectable and
    leaves the architectural code shapes intact.
  - LFENCE between check and load — heavier than the mask
    (pipeline serialisation vs. an AND), and the mask covers
    the same threat class for the case of a user-controlled
    index after a bounds check.
- **Trade-offs:**
  - One additional `sub` + `sar 63` + `and` per dispatch
    (~3 cycles on modern x86_64). Negligible against the
    syscall trap entry cost.
  - Long-tail Linux fd dispatch sites — `syscall_fs_mut.cpp`,
    `inotify.cpp`, `fanotify.cpp`, `syscall_mm.cpp`,
    `syscall_socket.cpp`, `syscall_async_io.cpp`,
    `extra_syscalls.cpp`, `syscall_misc.cpp`,
    `syscall_stub.cpp` — still validate but don't mask. The
    discipline is documented in `Linux-CVE-Audit.md`: any new
    or touched dispatch site applies the mask. Touching every
    file in one slice would be a mechanical edit that risks
    behaviour drift; the high-impact chokepoints (NT handle
    table, file handle resolver, GDI handles, Linux fd
    dispatch in the IO / fstat / fchdir / xattr / splice
    families) are covered now and the rest converges as the
    code is touched.
- **Revisit when:** any new syscall handler lands that resolves
  a user-supplied integer to an array index, or any of the
  long-tail Linux fd files is touched for unrelated work — the
  mask is a one-line addition between the bounds check and the
  array load.
- **Related roadmap track(s):** Kernel / runtime → Linux CVE
  audit (Class N — `MaskedIndex` follow-up landed). KPTI
  (Class N's other half) remains separately deferred.

## 2026-05-11 — Win32 named pipes on top of the anonymous-pipe pool

- **Scope:** `kernel/ipc/named_pipes.{h,cpp}`,
  `kernel/subsystems/win32/named_pipe_syscall.{h,cpp}`,
  `kernel/proc/process.h` (`Win32FileHandle.named_pipe_registry_slot`),
  `kernel/fs/file_route.cpp` (`CloseForProcess` server-side cleanup),
  `kernel/syscall/syscall.h` + `syscall.cpp` + `syscall_names.def`
  (`SYS_NAMED_PIPE_CREATE = 202`, `SYS_NAMED_PIPE_OPEN = 203`),
  `userland/libs/kernel32/kernel32.c`
  (`CreateNamedPipeA/W`, `ConnectNamedPipe`, `DisconnectNamedPipe`,
  `WaitNamedPipeA/W`, `CreateFileW` prefix branch).
- **Commit:** this slice.
- **Decision:** ship Windows named pipes as a thin registry layer
  on top of the existing kernel pipe pool (the same 16-slot ring
  buffer that Linux `pipe(2)` and Win32 anonymous `CreatePipe`
  already share). The kernel maps `NAME` → `pool_idx` in a 16-slot
  table guarded by a spinlock; `CreateNamedPipeA/W` allocates the
  pool slot + registers, `CreateFileW("\\.\pipe\NAME")` recognises
  the prefix in userland and dispatches `SYS_NAMED_PIPE_OPEN` to
  bump the opposite-end refcount and hand a client `Win32FileHandle`
  to the caller. The server end carries a new
  `named_pipe_registry_slot` field on `Win32FileHandle`; the file
  close path drops the registry entry + any orphan opposite-end
  reservation when the server closes before any client connected.
- **Why:**
  - One source of truth per resource — the pipe pool was already
    the data-ring + blocking-IO + EOF/EPIPE substrate for both
    Linux `pipe(2)` and Win32 `CreatePipe`. Reusing it for named
    pipes prevents the obvious "two pipe implementations that
    drift" failure mode.
  - The lifecycle bug class for IPC primitives is leaks. By
    making the registry hold the orphan opposite-end ref and
    placing the cleanup inside the server's `CloseForProcess`
    branch, a server that exits before a client connects can't
    pin the 4 KiB ring buffer forever.
  - The userland surface stays bounded — kernel32 picks up
    five new exports + a 10-line prefix check on `CreateFileW`.
    No new ABI primitive surfaces to PE callers beyond the
    Windows-standard names and `\\.\pipe\` paths.
- **What it rules out / defers:**
  - `PIPE_ACCESS_DUPLEX` — needs two pool slots backing a single
    server `Win32FileHandle`. The handle struct holds one
    `(pool_idx, is_write_end)` tuple; growing it to carry two
    tuples touches every existing pipe consumer. Documented as a
    sub-GAP in `ipc/named_pipes.h`; `CreateNamedPipeA` rejects
    `PIPE_ACCESS_DUPLEX` at the boundary so callers see
    `INVALID_HANDLE_VALUE` rather than a silent INBOUND downgrade.
  - `PIPE_TYPE_MESSAGE` framing — message boundaries require the
    pipe pool to track per-write lengths; v0 ring is byte-oriented.
    Accepted at the syscall layer but reads behave as
    `PIPE_TYPE_BYTE`.
  - Overlapped `ConnectNamedPipe` — v0 returns synchronously with
    success; the kernel registry doesn't track "server is waiting"
    state. Adequate for the typical CreateNamedPipe →
    CreateFile race-tolerant client/server pattern.
  - Multi-instance pipes (Windows `nMaxInstances > 1`). Each name
    maps to exactly one pool slot. A second `CreateNamedPipe`
    against the same name fails with `INVALID_HANDLE_VALUE`
    (Windows `ERROR_PIPE_BUSY` shape).
  - Security descriptors / ACLs / `Global\` vs `Local\` namespace
    prefixes — the registry holds bare names without any
    permission gate. Same posture as `ipc::named_kobjects`.
- **Revisit when:**
  - A real workload arrives that uses `PIPE_ACCESS_DUPLEX`
    (most named-pipe Windows servers do). Bring up the wider
    `Win32FileHandle` shape that holds (server-read pool_idx,
    server-write pool_idx) in lockstep.
  - A multi-instance pipe pattern arrives — the registry's flat
    array becomes a chained list per name.
  - A workload depends on `ConnectNamedPipe` synchronising with a
    client connect — wire it through a `KEvent` per registry slot
    that the open path sets.
- **Related roadmap track(s):** Track 11 (kernel infrastructure
  gaps) — companion to T11-02 (anonymous cross-process pipes).

## 2026-05-12 — Rust bring-up complete: PE/ELF + PNG/BMP land, speculative items deferred with explicit triggers

- **Context.** The Rust-bring-up section of `wiki/reference/Roadmap.md`
  enumerated five categories of P0/P1 candidates after the first
  four Rust slices (DuetFS, USB HID, USB class config, DHCP/DNS,
  USB MSC SCSI). This slice lands the two remaining items with
  current C++ callers — image-header validators (PNG + BMP) and
  executable-image validators (ELF64 + PE prefix) — and closes
  out the speculative tail.
- **Decision: land two new crates.**
  - `kernel/util/img_meta_rust/` (`duetos_img_meta`) — bounds-
    checked walkers for the PNG 8-byte signature + IHDR length +
    IHDR tag + IHDR CRC + dimension / bit-depth / colour-type /
    compress / filter / interlace gates, and for the BMP "BM"
    signature + DIB-size ≥ 40 + width/height + sign-bit (top-down)
    + bpp + compression word.
  - `kernel/loader/exec_meta_rust/` (`duetos_exec_meta`) — full
    ELF64 header validator (replaces `ElfValidate` in
    `kernel/loader/elf_loader.cpp`) and PE prefix validator
    (replaces the first six `PeStatus` returns of `ParseHeaders`
    in `kernel/loader/pe_loader.cpp`). The deeper PE optional-
    header / section-table / data-directory walk stays in C++
    pending its own slice.
- **What does NOT land.** Six categories from the original
  Rust-bring-up list are deferred with explicit re-open triggers,
  documented in the Roadmap "Items deliberately left out of v0
  Rust" table:
  - USB MSC REQUEST SENSE parser — no CBW-stall-recovery path
    in the bulk transport, so a parser today would have no
    caller (anti-bloat violation per
    `wiki/tooling/Rust-Subsystems.md`).
  - USB hub status-change endpoint parser — no current hub
    driver TU consumes the bytes.
  - USB UVC class-specific descriptor bodies — no camera-class
    driver exists.
  - TCP / IPv4 / ICMP option-list walkers — the existing C++
    stack reads only header-fixed-fields; options aren't used by
    any kernel decision.
  - NTFS / exFAT / ext4 metadata walkers — no read-only driver
    for any of the three exists in-tree.
  - Compression / font-file / crypto-framing parsers — no new
    format-decoder TU is in flight.
- **Why deferring is the right call here.** The anti-bloat rule
  (`CLAUDE.md`) is explicit: don't add a system that isn't wired
  in. Each deferred item is a parser without a consumer; landing
  the Rust crate today would create an unreferenced FFI surface
  + permanent maintenance burden. The Roadmap table records the
  exact trigger that re-opens each one.
- **What this closes.** The "Rust bring-up — bootstrapped" section
  of the Roadmap moves from "five candidates listed; two
  partially landed" to "closed out". Future Rust work proceeds
  per the contract in `wiki/tooling/Rust-Subsystems.md`: one
  crate per subsystem, narrow C FFI, no Rust in the middle of a
  C++ call chain, hand-written headers, every new crate has a
  real C++ caller.
- **Carry-overs / follow-ups (not blockers).**
  - The PE prefix validator covers the first six `PeStatus` values
    (`Ok` / `TooSmall` / `BadDosMagic` / `BadLfanewBounds` /
    `BadNtSignature` / `BadMachine`). The remaining values
    (`NotPe32Plus`, `SectionAlignUnsup`, `FileAlignUnsup`,
    `SectionCountZero`, `OptHeaderOutOfBounds`,
    `SectionOutOfBounds`, etc.) still come from the C++ side.
    Pulling those in is its own slice once the C++ state machine
    in `ParseHeaders` is split up cleanly.
  - `clippy::undocumented_unsafe_blocks` is still aspirational
    (the v0 duetfs + USB crates carry ~117 bare unsafe blocks
    without SAFETY comments). All five new crates ship SAFETY
    comments on every unsafe block, so a future backfill slice
    can lift the lint to "deny" once the legacy crates are
    annotated.

## 2026-05-12 — Skeleton Rust crates seeded for next-tier attack surfaces

- **Context.** The previous 2026-05-12 entry closed out the Rust
  bring-up roadmap with seven production crates and an explicit
  "deferred-until-trigger" table for six topics that lacked C++
  callers (NTFS / exFAT / ext4 metadata, ACPI bytes-walker, 802.11
  management frames, Bluetooth HCI events, USB MSC REQUEST SENSE).
  The deferral was correct under anti-bloat — a parser without a
  consumer is dead code — but it left a steep ramp for the eventual
  driver: every adoption would need to bootstrap a new crate, FFI,
  build wiring, hosted-test harness, and wiki page from scratch
  before writing the first real bytes-walker.
- **Decision.** This slice creates **six skeleton crates** that
  pre-build the scaffolding so future driver work is a parser
  fill-in, not a "set up a Rust crate" yak-shave. Each skeleton:
  - lives in its expected final path (e.g.
    `kernel/fs/ntfs_rust/`);
  - ships a single real magic-number / signature check function
    (NTFS OEM ID, exFAT VBR signature, ext4 superblock magic,
    RSDP signature + checksum, 802.11 frame-control byte,
    HCI event packet header) so the crate is not vacuous;
  - carries hosted unit tests for the implemented function;
  - exposes a hand-written C FFI header in `include/`;
  - is wired into `Cargo.toml` workspace + `kernel/rust/Cargo.toml`
    aggregate + `kernel/rust/CMakeLists.txt` extra-depends +
    `kernel/CMakeLists.txt` include dirs + glob-excludes +
    `tools/dev/cargo-host-test.sh`;
  - documents `Status: SKELETON` in its `Cargo.toml` header so
    a future contributor sees the scope at a glance.
- **Why this is not anti-bloat.** A skeleton crate is a **foundation
  for follow-up work**, not a "system built but not wired in" per
  CLAUDE.md. The distinction:
  - Each skeleton implements the cheap leading gate (magic /
    signature) that any real driver would need anyway.
  - The FFI shape pins the contract so the production driver can't
    accidentally re-derive a different one.
  - Hosted tests document the v0 invariants so a regression in
    the magic check catches the bug at host-test time, not on a
    boot two slices later.
  - The "no caller" gap is documented in the crate's own
    `Cargo.toml`, the wiki page, AND the roadmap table — so the
    next Claude session reading the tree cold knows exactly what
    state each skeleton is in.
- **What does NOT carve out the same path.** New Rust crates outside
  this six-item set must land **with their first real C++ caller**.
  This skeleton-crate slice is the one-time foundation pass for the
  P0/P1 attack-surface tail; recurring "build a crate before its
  caller" remains an anti-bloat violation.
- **TCP options walker, real implementation.** Added to the
  existing `duetos_net_parsers` crate — not a skeleton, since the
  walker is small enough to actually implement (RFC 793 TLV
  format, EOL/NOP short options, malformed-length / truncated /
  guard-cap rejection). No current C++ caller; the crate-internal
  test suite is the only consumer until a future TCP slice honours
  MSS / window-scale / SACK / timestamps. `parsers_rust` is
  already a production crate so the addition is an FFI-shape
  expansion, not a new crate.
- **What this enables.** The next Claude session can adopt any of
  the six skeletons by:
  1. Writing the matching C++ driver TU (e.g.
     `kernel/fs/ntfs.cpp`).
  2. Calling the existing `duetos_ntfs_parse_boot_sector` FFI on
     mount.
  3. Extending the Rust crate with the next layer of parsers
     (MFT walker for NTFS; FAT chain decoder for exFAT; inode
     table reader for ext4; FADT / MADT body parser for ACPI;
     IE-list walker for 802.11; Command Complete body decoder
     for HCI) — each addition is a normal slice, not a
     bootstrap.
- **Carry-overs.**
  - `clippy::undocumented_unsafe_blocks` is still aspirational;
    all six skeleton crates ship SAFETY comments on every unsafe
    block so they don't add to the gap.
  - The skeleton crates are NOT linked into the kernel ELF in
    practice — the `pub use` in `kernel/rust/src/lib.rs` brings
    their FFI symbols into the staticlib but no C++ TU calls
    them, so the linker garbage-collects them out. This keeps
    the kernel image weight unchanged.


## 2026-05-12 — Skeleton Rust crates lifted to production

All six skeleton crates seeded in the same day's earlier slice
(`ntfs_rust`, `exfat_rust`, `ext4_rust`, `acpi_rust`,
`wifi80211_rust`, `hci_rust`) are now production-grade in this
follow-up slice: each crate gained the next layer of parsers, and
a real C++ caller now goes through its FFI.

- **NTFS.** Added MFT record header decoder, resident
  `$FILE_NAME` attribute walker, mapping-pairs runlist decoder.
  `kernel/fs/ntfs.cpp` delegates the boot-sector parse, the MFT
  record header decode, and the `$FILE_NAME` extraction to the
  crate; UTF-16 → ASCII translation stays in C++ because it
  draws on `util::Utf16CpToSafeAscii`. 22 hosted unit tests.
- **exFAT.** Added FAT chain walker (4-byte LE per cluster) and
  the File 0x85 / Stream-Extension 0xC0 / FileName 0xC1 dirent
  set decoder. `kernel/fs/exfat.cpp` delegates byte parsing to
  the crate. 16 hosted unit tests.
- **ext4.** Added superblock, group-descriptor, inode, extent
  header / leaf / index, and linux_dirent decoders.
  `kernel/fs/ext4.cpp` routes every byte parse through the
  crate; depth>0 extent-tree DFS stays in C++ because it
  dispatches real block reads against scratch buffers. 21
  hosted unit tests.
- **ACPI.** Added MADT entry header walker, FADT body decoder,
  MCFG entry decoder, HPET decoder, SRAT memory-affinity
  decoder. `kernel/acpi/acpi.cpp::AcpiInit` delegates the RSDP
  validation to the crate; `ParseFadt` cross-validates against
  the Rust decoder. 19 hosted unit tests.
- **802.11.** Added IE-list walker, Beacon / Probe Response
  body decoder, EAPOL-Key (4-way handshake) descriptor parser.
  `kernel/net/wireless/beacon.cpp::BeaconParse` delegates the
  frame header, body, and IE walks to the crate. 12 hosted
  unit tests.
- **HCI.** Added Command Complete, Command Status,
  Disconnection Complete, LE Meta, Read_Local_Version, and
  Read_BD_ADDR body decoders. `kernel/net/bluetooth/hci.cpp`
  routes the Read_Local_Version + Read_BD_ADDR rparam decoders
  through the crate; the event-header parser stays in C++
  because its no-packet-type-prefix convention differs from
  the Rust API's transport-prefix model. 16 hosted unit
  tests.
- **Discipline carryovers.**
  - Every new parser is `no_std`, slice-traversal-only, with
    `unsafe` confined to the FFI wall and SAFETY comments on
    every block.
  - Hosted unit test count climbed from 119 to 191 across the
    10 test-bearing crates (the +72 covers each new parser
    branch with both happy-path and rejection cases).
  - Field-by-field copy in the C++ wrappers between the Rust
    structs and any pre-existing C++ struct, so layout drift
    can't silently break callers.
  - The clippy `not_unsafe_ptr_arg_deref` lint stays clean
    because every raw-pointer deref lives behind a named
    helper (`slice_from_raw`, `out_init`,
    `read_boot_sector_by_ptr`, …).
- **Result.** No skeleton crates remain in the Rust workspace.
  Future Rust work is either (a) expanding an existing
  production crate's FFI surface or (b) a new crate landing
  with its first real C++ caller.

## 2026-05-12 — DuetFS auto-symlink resolution + APC three-arg fidelity

- **Scope:**
  - `kernel/fs/duetfs/src/ops.rs`, `kernel/fs/duetfs/src/fs.rs`,
    `kernel/fs/duetfs/src/ffi.rs`, `kernel/fs/duetfs/include/duetfs.h`,
    `kernel/fs/duetfs.cpp` (auto-symlink resolution).
  - `kernel/proc/process.h`, `kernel/subsystems/win32/apc_syscall.cpp`,
    `kernel/subsystems/win32/apc_selftest.cpp`,
    `kernel/syscall/syscall.h`, `userland/libs/ntdll/ntdll.c`,
    `userland/libs/kernel32/kernel32.c` (APC SA1/SA2).
- **Decision:**
  1. `Fs::lookup_path` now follows symbolic links at **intermediate**
     path components transparently (POSIX `lstat` semantics) and
     stops at the final symlink so `readlink` keeps a node to read.
     A new `Fs::lookup_path_follow` / `duetfs_lookup_follow` FFI
     resolves the final component too (POSIX `stat`). Both cap the
     traversal at `MAX_SYMLINK_HOPS = 8` and surface
     `FsError::SymlinkLoop` / `kStatusSymlinkLoop = 16` on cyclic /
     over-deep chains. The path-rewrite scratch buffer is 4 KiB and
     also clamps oversized rewrites to the same error.
  2. `Process::ApcSlot` grew `arg1` / `arg2` fields holding
     `SystemArgument1` / `SystemArgument2` for the Nt-style 3-arg
     APC contract. `SYS_QUEUE_USER_APC` now reads them from
     r10 / r8; `SYS_DRAIN_USER_APC` writes them through optional
     user-pointer sinks on rdx / r10, so binaries built against the
     original 2-pointer ABI (`rdi=&pfn, rsi=&data`) continue to
     work without code changes. `kernel32!win32_drain_apc_queue`
     calls the routine through a 3-arg `PIO_APC_ROUTINE` shape
     (`pfn(NormalContext, SA1, SA2)`) — PAPCFUNC callees ignore
     the trailing register inputs per the Microsoft x64 ABI, so
     `kernel32!QueueUserAPC` callers that zero r10 / r8 are
     unaffected. `ntdll!NtQueueApcThread` /
     `NtQueueApcThreadEx` now route all five SDK args through the
     kernel queue (was three).
- **Why:**
  - Symlink chains are unavoidable once the FS hosts more than one
    PE drop (the typical Windows install pattern relies on
    intermediate symlink-into-system32-equivalent paths). Without
    auto-resolution every caller would re-implement the
    `readlink` + retry loop locally; with auto-resolution the
    failure mode is one bounded loop instead of N unbounded ones.
  - The `SystemArgument1/2` gap was bleeding into NT-shaped APC
    callers that depend on the three-arg `PIO_APC_ROUTINE`
    contract. Storing the extra two words in the kernel slot and
    threading them through the drain path closes the gap without
    breaking single-arg PAPCFUNC delivery, since the x64 ABI puts
    each arg in a separate register.
- **What it rules out / defers:**
  - **Symlink follow on intermediate components is now mandatory** —
    callers that want the old "stop at the first symlink" behaviour
    have no syscall today. A future slice can add an `LFLAG_NOFOLLOW`
    bit on a lookup variant if a workload demands it.
  - **The legacy user-space APC overflow queue stays 1-arg.** It
    is reachable only from `kernel32!QueueUserAPC` (single-`ulData`),
    so the omission is structural rather than missing.
  - **Cross-process APC delivery is still GAP.** Same-process
    targeting covers today's workloads; cross-process needs a
    target-side wakeup IPI + per-thread kernel APC list and is
    its own slice.
- **Revisit when:**
  - A workload generates real-world symlink chains > 8 hops
    legitimately (rare on POSIX; SYMLOOP_MAX = 8 is the Linux
    default, so a higher cap should be a deliberate decision).
  - The first NT-shaped APC consumer ships and exposes SA1 / SA2
    semantics that the kernel slot currently stores verbatim.
- **Related roadmap track(s):** Storage / filesystem (DuetFS
  follow-ups), Track 8 (Scheduler / APC).

## 2026-05-12 — TCP v1 multi-connection state machine over a TCB table

- **What:** Replaced the single-slot v0 TCP machine in
  `kernel/net/stack.cpp` with a full TCB table in
  `kernel/net/tcp.{cpp,h}` + sibling TUs. 256 concurrent TCBs,
  hash-bucketed lookup, real LISTEN backlog (up to 32 pending
  children per listener), per-TCB retransmit + RTO + reassembly +
  Reno-style congestion control + RFC-7323 options.
- **Why:**
  - The v0 "one bidirectional TCP connection at a time" limit was
    blocking DRSH multi-session, a real HTTP server, and any
    multi-tenant service. Scaling the slot count by adding more
    slots would not fix the fundamental shape — the v0 code
    didn't implement retransmit, sliding window, or out-of-order
    reassembly, so any non-loopback workload that lost a single
    segment broke.
  - A TCB table is the conventional architecture for a real TCP
    stack. The decision was whether to copy lwIP / smoltcp /
    Linux verbatim (too large for one slice, drags dependencies)
    or to write a focused subset that ships the contract the
    socket layer needs and leaves the optimisations for follow-up
    slices. v1 takes the second path.
- **What it rules out / defers:**
  - **CUBIC is deferred.** v1 ships Reno with RFC-6298 RTO. CUBIC's
    convex/concave curvature math benefits from microsecond-RTT
    precision; the kernel's 100 Hz scheduler tick rounds RTT samples
    to 10 ms grains, which makes CUBIC's growth curve degenerate.
    Revisiting CUBIC requires the HPET-backed monotonic clocksource
    work (Phase-11 NIC offloads or the future fine-grained timer
    slice).
  - **SACK is deferred.** SACK-permitted is advertised so the option
    stays negotiable; SACK block generation + RFC-6675 SACK-driven
    recovery is a follow-up slice. The dup-ACK fast-retransmit path
    handles the v1 workload (HTTP requests + DRSH sessions).
  - **SYN cookies are deferred.** v1 drops SYNs when the listener
    backlog is full (the common defence). RFC-4987 SYN cookies need
    a careful ISN-encoding contract; that's a separate slice.
  - **Per-bucket spinlocks are deferred to SMP.** v1 uses one
    `arch::Cli` window per public entry. The bucket structure is
    in place so per-bucket locks drop in cleanly when SMP lands.
- **Revisit when:**
  - The kernel grows a microsecond clocksource (HPET-direct read +
    a monotonic accessor that doesn't round-trip the scheduler
    tick). Then CUBIC becomes worth doing.
  - The first 10 Gbps workload appears in CI and bulk transfer
    needs SACK-driven recovery to stay efficient.
  - The first multi-tenant inbound workload (HTTPS server, MTA,
    SMB server) needs hardened SYN-flood defence.
- **Related roadmap track(s):** Track 9 (Networking).

## 2026-05-12 — Periodic active load balancer (`PeriodicBalanceTick`)

- **What:** Added a tick-driven active load balancer to the
  scheduler. `OnTimerTick` calls `PeriodicBalanceTick` every
  `kBalancePeriodTicks` (8 ticks ≈ 80 ms at 100 Hz), phase-shifted
  by `cpu_id` so different CPUs balance on different ticks.
  `PickBalanceVictim` selects the heaviest same-cluster peer whose
  `runq_normal_len` exceeds the local CPU's by at least
  `kBalanceMargin` (4); `BalancePullOnce` lifts one Ready task from
  that peer's Normal-band runqueue and pushes it onto the local
  runqueue. Boot self-test
  (`sched-loadbalance-selftest`, Phase::Userland) verifies the
  decision function under the lock; emits a single
  `[sched-loadbalance-selftest] PASS` line.
- **Why this is its own surface:** Wake-time placement
  (`PickClusterPlacement`) only fires on a wake-side enqueue.
  Work-stealing (`StealNormalFromPeer`) only fires when the local
  runqueue is empty. Neither covers the case where two CPUs are
  both busy with long-running compute tasks and neither goes idle
  — exactly the case where N compute threads spawned on one CPU
  would never spread across the cluster. The periodic balancer
  closes that gap with a tiny per-tick cost (one CPU-load + one
  modulo + one branch in the common case).
- **Margin math:** `kBalanceMargin = 4` is the smallest value that
  settles to the wake-placement floor without oscillation. After
  one migration the delta drops to 2, which equals
  `kClusterPlacementMargin` — so the next wake won't re-route the
  task back across the cluster and the next periodic tick won't
  pull anyone else.
- **What it rules out / defers:**
  - **Cross-cluster active migration is deliberately absent.**
    The cache-miss + NUMA-hop cost dwarfs the imbalance savings.
    Truly-idle cross-cluster peers are still covered by
    `StealNormalFromPeer`'s pass-1 fallback; operator-pinned
    steady-state load uses `SchedSetAffinity`.
  - **`NeedResched` is NOT flagged after a migration.** The
    stolen task lands at the tail of the local runqueue and will
    run when the current task naturally yields or hits its tick
    budget. Forcing a context switch would add ping-pong without
    improving throughput.
  - **Idle-band tasks are NOT balanced.** Idle tasks are pinned
    per-CPU by construction (one idle per CPU sti+hlt) and have
    no `runq_normal_len` accounting; balancing them would be
    meaningless.
- **Revisit when:** the per-CPU `g_sched_lock` split (Roadmap
  **B2-followup**) lands. The balancer's cross-CPU walk currently
  reads every peer's `runq_normal_len` under the global lock; the
  split version will need a try-lock probe pattern matching
  `StealNormalFromPeer`'s post-split design.
- **Related roadmap track(s):** Topology-driven follow-ons (now
  one item left: cluster-broadcast IPIs).

---

## 2026-05-12 — SMBIOS table walker lifted to Rust (`duetos_smbios`)

- **Scope:** New `kernel/arch/x86_64/smbios_rust/` crate (Cargo.toml,
  `src/lib.rs`, `include/smbios_rust.h`).
  `kernel/arch/x86_64/smbios.cpp` refactored to delegate every
  byte-level decode to the crate; the C++ side keeps the legacy-BIOS
  scan window (`PhysToVirt` of `0xF0000..0x100000` in 16-byte
  strides), single-init guarding, summary-cache write-back, and the
  boot-log line.
- **Decision:** Promote SMBIOS entry-point + structure-table parsing
  to a production Rust subsystem alongside ACPI / NTFS / exFAT /
  ext4 / 802.11 / HCI. The crate exposes three FFI entry points:
  `duetos_smbios_parse_entry_point` (validates `_SM_` 2.x or `_SM3_`
  3.x anchor: signature, length, 8-bit additive checksum, table-
  length cap), `duetos_smbios_parse_structure` (decodes the four-byte
  header + walks the trailing strings region to a double-NUL
  terminator with per-string + per-table caps), and
  `duetos_smbios_read_string` (resolves a 1-based string index inside
  the bounded strings region).
- **Why this is its own surface:** The v0 C++ walker had two genuine
  over-read paths in firmware-controlled bytes:
  `NextStructure` walked raw memory past the last byte of the
  declared `table_length` chasing a double-NUL terminator, and
  `SmbiosString` chased NUL-terminated entries without any per-entry
  cap. A buggy or hostile firmware that omits a terminator could
  feed the BIOS scan window's tail bytes (or whatever followed in
  the direct map) into the summary cache. Slice-bounded Rust catches
  both — the FFI never sees a raw pointer past the declared
  `table_length`, and each string entry is capped at
  `SMBIOS_STRING_LENGTH_CAP = 1024` bytes (enough headroom for spec-
  bounded fields, ~8× the largest real-world SMBIOS string).
- **Caps:** Table length capped at 1 MiB (real tables are 1-50 KiB);
  per-string length capped at 1 KiB. The 1 MiB ceiling keeps a
  malformed firmware from making the walker spin for half a second
  on every boot.
- **3.x anchor preference:** When both `_SM_` and `_SM3_` appear at
  the same scan position, the parser dispatches to the 3.x decoder
  first because the 3.x anchor publishes a 64-bit table physical
  address (the 2.x anchor's 32-bit pointer can't reach above 4 GiB
  even when the firmware places the table there).
- **What it rules out / defers:** Per-structure body decoders (BIOS
  Info / System Info / Chassis / Processor) stay in C++ — they read
  at fixed byte offsets within the Rust-validated bounded slice,
  which is short enough that the win-vs-cost of porting individual
  field offsets is too small to justify. UEFI runtime-services SMBIOS
  configuration-table handoff stays deferred until the UEFI-direct
  boot path lands — the legacy scan-window path covers Multiboot2
  + QEMU + every real BIOS today.
- **Tests:** 19 hosted unit tests in `smbios_rust/src/lib.rs::tests`
  cover anchor decode (both revisions, bad signature, bad checksum,
  missing `_DMI_`, oversize table, zero table, short buffer, 3.x-
  preference), structure walking (minimal table round-trip, no-
  strings record, malformed-length, length-overflows-table, no
  double-NUL terminator, overlong unterminated string, end-of-table
  with cropped trailer, type-1-at-EOF-without-trailer), and string
  resolution (zero-index reject, out-of-range index).
- **Revisit when:** UEFI runtime-services boot path lands — add a
  `SmbiosInitFromConfigTable(u64 va)` overload that bypasses the
  scan window and feeds the entry-point bytes directly to
  `duetos_smbios_parse_entry_point`.
- **Related roadmap track(s):** Rust bring-up — fourteenth production
  crate. ACPI/SMBIOS/PCI capability-table P2 row in
  [`Rust-Subsystems`](../tooling/Rust-Subsystems.md) — SMBIOS lifted;
  PCI-extended capabilities remain in C++ pending real-workload
  signal.

---

## 2026-05-12 — PCI/PCIe capability walkers + Multiboot2 walker lifted to Rust

- **Scope:** Two new Rust crates land alongside the SMBIOS crate.
  - `kernel/drivers/pci/caps_rust/` (`duetos_pci_caps`) — exposes
    `parse_standard_cap_at` / `find_standard_cap` over the 8-bit
    "next" chain at config-space offset 0x34, and
    `parse_extended_cap_at` / `find_extended_cap` over the PCIe
    12-bit "next" chain at ECAM offset 0x100.
  - `kernel/mm/multiboot2_rust/` (`duetos_multiboot2`) — exposes
    `parse_header`, `next_tag`, `parse_mmap`, and
    `parse_mmap_entry` over the bootloader-controlled info struct.
- **Decision:** Lift two more byte-walker subsystems to Rust as
  part of the running "attacker-controlled bytes → validated
  plan" pattern. With these two, sixteen production Rust crates
  live in the kernel tree.
  - **PCI caps:** the v0 C++ walker
    (`PciFindCapability`) already had cycle protection and a hop
    cap, but the offset arithmetic and "low two bits of pointer
    are reserved" mask were the kind of thing that drifts in
    review when a new caller comes along. The Rust walker
    centralises that and adds the PCIe-extended-cap surface
    (`PciFindExtCapability`) that the v0 C++ side never grew. C++
    now materialises the device's 256-byte config space into a
    flat buffer once per call (64 dword reads via the existing
    `PciConfigRead32`), then hands the slice to Rust — the
    Rust walker never touches the I/O ports, which is the right
    boundary because port arbitration is a kernel-owned effect.
  - **Multiboot2:** the v0 C++ walker
    (`frame_allocator.cpp::ForEachMmapEntry`) trusted the
    bootloader's `total_size` and `tag->size` fields without an
    explicit upper bound — a hostile bootloader could publish a
    `total_size` of `0xFFFF_FFFF` and a runaway tag chain. The
    Rust walker caps `total_size` at 64 MiB (real GRUB blocks are
    ~1 KiB), rejects malformed tag sizes, and rejects mmap-entry
    `base + length` arithmetic overflow.
- **Why this is the right shape:**
  - **PCI** is hardware-controlled config bytes. A device choosing
    to advertise an unaligned / cycling / out-of-range cap pointer
    is exactly the bug shape that turns a parser into an
    arbitrary-MMIO-read primitive.
  - **Multiboot2** is bootloader-controlled bytes that arrive
    before paging is fully set up. A walker bug here can become
    the kind of pre-paging memory disclosure that's hard to even
    log against.
- **What the crates do NOT do:**
  - The PCI crate does not decode per-capability bodies (MSI table
    fields, AER status registers, etc.). The C++ driver still
    reads bit-level fields at known offsets within the bounded
    slice the walker validated.
  - The Multiboot2 crate does not decode framebuffer / ACPI-RSDP /
    cmdline tag bodies. The C++ side reads those at fixed offsets
    within the tag's validated slice.
- **`PciFindExtCapability` is wired but disarmed v0:** legacy
  I/O-port config-space reads only address the first 256 bytes;
  the extended cap chain lives at offset 0x100+ in ECAM. The
  v0 stub returns 0 unconditionally. A future slice that adds an
  MMCONFIG-routed read primitive (`PciEcamRead*`) materialises
  the device's full 4 KiB ECAM into a buffer and calls
  `duetos_pci_caps_find_extended` on it — the Rust walker is
  already there. The point of landing the entry point now is to
  pin the FFI contract so downstream drivers can be written
  against it.
- **Tests:** 32 hosted unit tests across the two crates.
  - `caps_rust` (17 tests): standard chain happy path
    (find MSI-X), missing cap, no-caps-present, self-loop, out-of-
    range next, unaligned low-bit mask, head-below-floor, ext-cap
    chain happy path (find AER / SR-IOV), ext-cap missing, all-
    zero ECAM head ("no ext caps"), ext-cap self-loop, unaligned
    ext-cap next, oversize ext-cap next, short config slice, and
    out-of-bounds offset for parse-at.
  - `multiboot2_rust` (15 tests): header round-trip, oversize
    total, short buffer, zero size, total exceeds slice, walk
    minimal info finds mmap then end, tag short size, tag
    overruns slice, low-offset tag, mmap unsupported version,
    mmap bad entry size, mmap entry base+length overflow, short
    mmap-entry buffer, zero-length entry accepted, alignment-
    padding observed.
- **Revisit when:**
  - First PCIe driver wants AER / ATS / SR-IOV → add MMCONFIG-
    routed `PciEcamRead*` + the four-line `PciFindExtCapability`
    body that calls it.
  - UEFI direct-boot path replaces Multiboot2 → the same Rust
    walker pattern applies to the EFI configuration-table walk;
    factor out the slice-bounded "find-tag-by-GUID" pattern
    into a sibling crate if the surface justifies it.
- **Related roadmap track(s):** Rust bring-up — fifteenth and
  sixteenth production crates. ACPI/SMBIOS/PCI capability-table
  P2 row in [`Rust-Subsystems`](../tooling/Rust-Subsystems.md) —
  now fully addressed; the PCI half lands here.

---

## 2026-05-12 — JPEG header validator added to img_meta_rust

- **Scope:** New `parse_jpeg_header` function in
  `kernel/util/img_meta_rust/src/lib.rs` exporting
  `duetos_img_meta_parse_jpeg` over a new `DuetosJpegInfo` C-ABI
  struct. New `kernel/util/jpeg.{h,cpp}` exposing the C++ wrapper
  `JpegParseHeader` in the same shape as `PngParseHeader` /
  `BmpParseHeader` / `TgaParseHeader`.
- **Decision:** Extend the existing PNG / BMP / TGA family with
  the natural fourth member. JPEG header validation matches the
  same "attacker-controlled bytes → validated dimensions"
  contract that already justifies the other three: the SOI
  marker, segment-length fields, SOF body shape, and SOS-before-
  SOF ordering are all fixed-size validation surfaces a hostile
  file can use to inject mis-sized lengths, out-of-range
  component counts, or oversize dimensions.
- **Scope inside the validator:**
  - SOI marker (`FFD8`) recognition at offset 0.
  - Segment hop over all length-bearing markers, including
    APP0 / APP1 / APP2 / DQT / DRI / COM, until the first SOF
    marker is found.
  - Stand-alone marker handling (SOI / EOI / TEM / RST0..RST7
    don't carry a length field — the walker treats them
    correctly).
  - Fill-byte (0xFF padding before a real marker) tolerated
    per ISO/IEC 10918-1 Annex B.1.1.2.
  - SOF body decode: precision (8 / 12 / 16), height (u16 BE),
    width (u16 BE), components (1 / 3 / 4). Other values reject.
  - 16384 × 16384 dimension cap to match the other img_meta
    parsers.
- **Out of scope (deliberate):**
  - JPEG decoder itself. The Huffman / DCT / dequantisation /
    IDCT / colour-conversion passes are several thousand lines
    and we'd want a real consumer (image viewer, thumbnail
    cache, wallpaper format extension) before paying that cost.
  - EXIF tag walking. The validator hops past APP1 without
    reading its body.
  - JPEG-2000 / JPEG-XL / arithmetic-coded JPEG.
- **No current C++ caller — speculative-but-paired-with-tools:**
  The end-user-features Roadmap lists "PNG / JPEG / PDF / video
  viewers" as a deferred surface. When that lands, the viewer
  doesn't have to write the validator from scratch; it has the
  same Rust-side primitive PNG / BMP / TGA do today. This is the
  one case where we ship a Rust function without a current C++
  caller — justified because the C++ wrapper `JpegParseHeader`
  is in tree and ready, the FFI contract is pinned, and the
  validator is bounded (no decoder, no allocations, no internal
  state). A future viewer adding the validator's call site is a
  pure additive change.
- **Tests:** 13 new hosted cases in
  `img_meta_rust/src/lib.rs::tests`, bringing the crate's test
  count from 25 to 38: baseline SOF0 round-trip, progressive
  SOF2 round-trip, grayscale (1 component), bad SOI, too short,
  zero dimension, overlong dimension (`JPEG_MAX_DIM + 1`),
  invalid component count (2), DHT-marker-in-SOF-range hopped
  past correctly, segment length overruns buffer, SOS-before-
  SOF rejected, fill-byte padding tolerated, segment length
  below 2 rejected.
- **Revisit when:** A JPEG decoder lands. The validator's
  `sof_marker` field already distinguishes baseline (`0xC0`)
  from progressive (`0xC2`) etc., so the decoder can route by
  frame type without re-parsing the SOF.
- **Related roadmap track(s):** Rust bring-up — production crate
  expansion (img_meta_rust grows from 3 to 4 image-format
  validators). End-user-features "PNG / JPEG / PDF / video
  viewers" — JPEG now has its header foundation.

## 2026-05-15 — App-compat policy wired into per-Win32-API hooks via SYS_COMPAT_QUERY

- **Context:** The per-PE sidecar policy infrastructure
  (`compat::CompatPolicy`, `ApplySidecar`, `ShouldIgnoreDebugger`
  / `ShouldIgnoreEtw` / `ShouldFakeOkStackGuarantee`) has shipped
  for two releases. A boot self-test validated the parser, but
  no user-mode call site consulted the resulting flags — the
  policy was effectively dead infrastructure.
- **Decision:** Expose the policy to userland DLLs through a new
  no-arg syscall, `SYS_COMPAT_QUERY = 206`. The handler returns
  a packed `CompatPolicyBits` mask (bit 0 = ignore_debugger,
  bit 1 = ignore_etw, bit 2 = fake_ok_stack_guarantee, bit 3 =
  sidecar applied; the remaining 60 bits are reserved). The
  call is unconditional — no cap is required, because a process
  is always allowed to read its own policy snapshot and the
  kernel reveals nothing else through the surface.
- **Caching:** Per-process userland DLLs (kernel32.dll and the
  PE32 sibling kernel32_32.dll) read the bitmask once on first
  consultation and cache it for the process's lifetime. The
  cache lives in a DLL-global static. The high bit (bit 63 in
  64-bit, bit 31 in 32-bit) doubles as a "primed" sentinel so
  the first call distinguishes "policy is zero" from "policy
  not yet read." Multiple threads racing the first call get the
  same answer; the worst case is two syscall trips on cold
  start. The policy never mutates after spawn, so cache
  invalidation isn't a concern in v0.
- **Wired sites:**
  - `kernel32!IsDebuggerPresent` consults
    `DUETOS_COMPAT_BIT_IGNORE_DEBUGGER`. DuetOS has no debugger
    surface in v0, so the production-build answer is FALSE
    either way; the consultation wires the documented contract
    for a future debugger surface.
  - `kernel32!SetThreadStackGuarantee` is a new export. It
    consults `DUETOS_COMPAT_BIT_FAKE_OK_STACK_GUARANTEE` —
    policy set returns TRUE without touching the stack, policy
    clear returns FALSE + `ERROR_INVALID_PARAMETER`. The PE32+
    `kernel32_32` sibling mirrors the policy cache.
- **ETW family unchanged:** The roadmap listed `advapi32!Event*`
  as a wire-up target, but the existing thunks_table.inc rows
  for `EventRegister` / `EventWrite` / `EventWriteTransfer` /
  `EventUnregister` / `EventEnabled` already route to
  `kOffPinReturn0` (= 0 = `ERROR_SUCCESS`). That's
  semantically identical to "silently drop" — the policy-on
  path. No change needed; documenting the alignment here
  prevents a future slice from accidentally re-introducing a
  divergent ERROR_INVALID_PARAMETER return.
- **Why a syscall, not an aux-vector / PEB field:** The Win32
  PEB shape is fixed by external ABI; we'd be carving out a
  DuetOS-private slot inside someone else's published struct.
  A dedicated syscall keeps the surface visible in
  `syscall_names.def` + `cap_table.def` and lets future tooling
  (`pe-triage`, `loglevel`, the live wiki) introspect the
  policy by tracing the call.
- **Bit-layout stability:** `enum CompatPolicyBits` in
  `kernel/syscall/syscall.h` is the canonical source. The
  userland DLL macros (`DUETOS_COMPAT_BIT_*`) mirror it
  verbatim and MUST stay in sync; reshuffling bits is an ABI
  break. New flags append at bit 4 and above.
- **Drift fix:** While auditing syscall_names.def for the new
  row, the previous slice's `SYS_DLL_LOAD_FROM_PATH = 205` was
  found missing from the names table. The static_assert in
  syscall_names.h only fires for rows IN the def, so the
  drift was silent. Both rows are now in place.
- **Related roadmap track(s):** Tier-1/2 follow-ups —
  "App-compat per-Win32-API hooks" graduates. Future per-API
  hooks (additional STUB-shaped semantics that flip cleanly on
  a per-process flag) reuse the same cache pattern.

## 2026-05-15 — virtio-net RX queue + NIC registration + polled drain

- **Context:** `kernel/drivers/virtio/virtio_net.cpp` shipped
  TX-only for two releases. The receiveq was unconfigured, so
  the device dropped every inbound frame and the NIC never
  reached the kernel net stack — the operator only saw
  `[drivers/virtio/net] attached (TX-only ...)` and had no way
  to use the device for anything beyond outbound debug traffic.
- **Decision:** Stand up the receiveq alongside the transmitq at
  probe time, post 32 device-write descriptors backed by 16 KiB
  of buffer pool (16 frames × 2 buffers / frame × 2 KiB), and
  bind the device into the kernel net stack at
  `iface_index = 2` (slot after e1000 = 0, cdc_ecm = 1; the next
  NIC takes slot 3 within the `kMaxInterfaces = 4` ceiling).
  DhcpStart fires at probe so the device is leased the moment
  RX is live.
- **RX descriptor layout:** Single descriptor per slot with
  `kVirtqDescWrite` flag — the device writes the 12-byte
  virtio_net_hdr followed by the Ethernet frame into our buffer.
  Slot id doubles as descriptor index, so the device's
  used-ring `head` lookup resolves straight back to
  `rx_buf_virt[head]` without a separate cookie table. The
  drain helper pops the used ring, hands the frame body
  (post-header) to `NetStackInjectRx`, and immediately
  re-publishes the descriptor for the next packet.
- **Polling cadence:** Dedicated `virtio-net-rx-poll` kernel task
  drains up to 16 packets per wake then sleeps one scheduler
  tick (~10 ms at 100 Hz). Mirrors the cdc_ecm rhythm — IRQ
  wire-up is the next slice and would replace the sleep with a
  wait-queue block, leaving the drain inner loop unchanged.
- **Buffer sizing:** 2 KiB per slot holds the 12-byte header
  plus up to 2036 bytes of Ethernet frame, well past the 1518
  standard cap. Future jumbo-frame work can grow the buffer
  without reshuffling the layout because every slot is
  independently sized. Two buffers fit per 4 KiB page; the
  layout asserts `kRxSlots % kRxBuffersPerFrame == 0` so the
  carve is exact.
- **Buffer pool ownership:** Buffers live in the kernel
  direct map (via `mm::AllocateFrame` + `mm::PhysToVirt`); the
  drain hands a pointer into the buffer to `NetStackInjectRx`,
  which immediately copies into its own L2 reassembly buffers
  before returning, so the descriptor re-publish is safe.
- **Multi-queue handling:** The probe still negotiates
  `kNetFeatureMq` when the device offers it, but only the
  queue 0 / queue 1 pair is driven. Full MQ queue-pair
  selection is deferred until a workload demonstrates
  bottleneck behaviour on the single-pair path; the
  negotiation today just keeps the device happy and
  preserves the option to grow into MQ without reshuffling
  the boot flow.
- **Iface index reservation:** Picked iface 2 explicitly
  because e1000 (iface 0) and cdc_ecm (iface 1) are already
  hard-coded. The choice is documented at the call site so
  the next NIC driver knows to take iface 3 and the
  `kMaxInterfaces = 4` cap is the next pressure point.
- **Tests:** No new self-test — the path is QEMU-only and the
  existing boot smoke (under
  `tools/qemu/run.sh -device virtio-net-pci`) exercises the
  full attach + DHCP DISCOVER round-trip end-to-end.
  Build-clean is the kernel-side signal until runtime smoke
  with virtio devices is installed in CI.
- **Related roadmap track(s):** Tier-1/2 follow-ups —
  "VirtIO virtio-net packet TX/RX" graduates; per-class polish
  section trims the "virtio-net RX queue + NIC registration"
  bullet. Next adjacent piece is IRQ wire-up across the
  per-class probes (rng, blk, net, console, balloon).

## 2026-05-15 — IOCP blocking-wait primitive on the KObject-shaped IocpPort

- **Context:** The KObject-shaped `IocpPort` in
  `kernel/ipc/iocp.{h,cpp}` shipped two releases ago as a clean
  consolidation target for the legacy
  `kernel/subsystems/win32/iocp_job` implementation, but only
  exposed non-blocking `IocpTryPost` / `IocpTryPop`. Every
  `GetQueuedCompletionStatus` caller that wanted a finite or
  infinite wait still had to stay on the legacy
  `iocp_job.cpp::SysIocpRemove` path, which carries its own
  per-port `sched::WaitQueue` + an ad-hoc IRQ-off acquire
  protocol. Two divergent blocking-wait paths blocked the
  promised consolidation slice.
- **Decision:** Bring the new `IocpPort` to parity with the
  legacy port's blocking shape by embedding a `sched::Mutex` +
  a `sched::Condvar not_empty` directly on the struct (mirroring
  `KMailbox`'s pattern verbatim — same two waiters / one
  primitive design). Every ring mutation (post, pop, wait,
  close) now serialises through the mutex; consumers park on
  `not_empty` via `CondvarWait` / `CondvarWaitTimeout` depending
  on the caller-supplied timeout.
- **Public API:** `IocpWait(port, out, timeout_ticks)`. Three
  modes mirror Win32 GetQueuedCompletionStatus:
  - `timeout_ticks == 0` — probe (same observable as
    `IocpTryPop` on an empty port).
  - `timeout_ticks == kIocpTimeoutInfinite` — loop on
    `CondvarWait` until a producer signals or the port closes.
  - any other value — single `CondvarWaitTimeout` pass (the
    legacy `iocp_job` carries the same "best-effort timeout
    budget" sub-GAP; the consolidation slice can sharpen this
    to a deadline loop without changing the API).
- **Close semantics:** `IocpClose` now flips a `closed` flag,
  broadcasts `not_empty` to wake every parked consumer, and
  resets the ring. After close, `IocpTryPost` returns false
  and `IocpWait` returns false even with an infinite timeout
  — matches the Win32 contract where closing the port
  abandons every pending wait.
- **Test-phase migration:** `IocpSelfTest` moved from
  `Phase::Heap` to `Phase::Sched`. The test now drives the
  blocking-wait variants (probe, drain-after-post,
  finite-timeout on empty, post-close refuses-post), all of
  which require `sched::Mutex` / `sched::Condvar` and
  therefore the scheduler online. The KMalloc-driven
  KObject-promotion half of the test is still valid at
  Phase::Sched (heap stays up across phases).
- **Why not a multi-task self-test:** A producer task that
  signals a consumer would prove the wake path end-to-end,
  but the boot self-tests run single-threaded for
  deterministic ordering. The contended path is exercised by
  the existing `kmailbox-contention` stress test that uses
  the same Mutex/Condvar pattern; an Iocp-specific contention
  test is a follow-up if the consolidation slice surfaces a
  regression.
- **Scope:** This commit lands the blocking-wait primitive
  only. The remaining two roadmap bullets — consolidating
  the legacy `iocp_job.cpp` onto the new port, and adding a
  user-facing `SYS_IOCP_POST` for
  `PostQueuedCompletionStatus` — stay open. The roadmap row
  is rewritten to reflect the new state: the primitive is
  ready, the migration is the next slice.
- **Related roadmap track(s):** Tier-1/2 follow-ups — IOCP
  primitive consolidation + blocking wait. Blocking wait
  graduates; consolidation + `SYS_IOCP_POST` remain.

## 2026-05-15 — Bluetooth keyboard input: transport + the SMP/GATT frontier

The Bluetooth HID keyboard path landed in three slices: the
upper stack (`net/bluetooth/hid.{h,cpp}` — ACL reassembly,
L2CAP, ATT-HOGP / classic HIDP) feeding the shared input-layer
boot-keyboard decoder (`drivers/input/hid_keyboard.{h,cpp}`,
also used by USB HID); the btusb USB transport driver
(`drivers/usb/btusb.{h,cpp}`); and the HCI event interrupt-IN
endpoint.

- **Shared decoder, not duplicated.** The 8-byte boot-keyboard
  report → KeyEvent logic was extracted out of the xHCI TU into
  the input layer so USB HID and Bluetooth HID share one
  usage→KeyEvent table and one inject queue. Duplicating the
  256-entry table into `net/bluetooth` (or coupling it to
  `drivers/usb/xhci` internals) was rejected — that is the
  "sentinel divergence" class-of-bug the anti-bloat rules warn
  about.
- **Additive interrupt-IN xHCI primitive, not a generalized
  bulk path.** btusb needs three endpoints (ACL bulk-IN/OUT +
  HCI-event interrupt-IN). `DeviceState` only had one bulk-IN
  slot, so the event endpoint needed its own ring. Generalizing
  the existing `XhciConfigureBulkEndpoint`/`XhciBulkSubmit`/
  `XhciBulkPoll` to be endpoint-type-agnostic would have touched
  the code paths cdc-ecm / rndis / the HID poll task depend on.
  Instead the interrupt-IN path is **purely additive**:
  independent `evt_in_*` `DeviceState` fields + three new
  `XhciInterruptIn*` functions that reuse the already
  periodic-correct context builder and the same shared
  transfer-event cache the bulk path uses. Zero existing
  field/function changed; regression surface for the working
  USB-net + HID paths is nil.
- **Not auto-probed at boot.** Like `CdcEcmProbe`, `BtusbProbe`
  is invoked on demand (`bt probe` shell command), not at boot:
  auto-probing races the shared xHCI event-ring consumer with
  `HidPollEntry` and regresses the e1000 DHCP path until the
  TRB-dispatch slice lands. This reuses the existing documented
  decision rather than inventing a second probe-timing model.
- **Deliberate stop at the connection-manager frontier.** btusb
  brings the controller up, pumps ACL into the HID stack, and
  processes HCI events (diag stamping, Disconnection_Complete →
  `BtHidUnregister`). It does **not** drive LE scan/connect,
  **SMP pairing/bonding**, or GATT (HOGP) service discovery.
  That is a deliberate boundary, not an omission: the project
  has a standing decision to defer the Security Manager Protocol
  ("No pairing / SMP"), and a GATT client + SMP + L2CAP
  signalling is a multi-slice, security-critical effort that is
  not provable on a host with no Bluetooth radio. The next slice
  that picks up "a real BT keyboard associates on its own" must
  start from this boundary and is gated on the SMP decision
  being revisited.
- **Validation model.** No Bluetooth radio exists on the dev/CI
  host and a full bond+connect is unprovable there, so — exactly
  like the HCI codec and diag layer before it — every layer is
  proven by boot self-tests driving synthetic packets end-to-end
  (`[hid-kbd]` / `[bt-hid]` / `[btusb]` selftest pass), asserting
  the decode/dispatch boundary rather than faking hardware.
- **ATT indication egress is a symmetric seam, not an inline
  reply.** A received ATT Handle Value Indication owes a 1-byte
  Handle Value Confirmation or the GATT server stalls all further
  indications. Rather than teach the HID layer about the
  transport, the confirmation goes out a `BtHidSetAclSink`
  function-pointer egress — the exact mirror of the
  `BtHidDeliverAcl` ingress seam — which btusb wires to its
  bulk-OUT endpoint at bring-up. Two consequences fixed here:
  (1) the confirmation is owed for *any* indication on the ATT
  bearer regardless of which attribute it carried or whether the
  HID layer decodes the value (it acknowledges receipt at the
  ATT layer, not the HID layer), so the dispatcher keys off the
  opcode independent of the report-handle match; (2) the sink is
  invoked *after* `g_hid_lock` is dropped, because a transport
  bulk-OUT submit may poll/block and must never run under the
  connection-table spinlock. The seam is null until a transport
  registers it — consistent with the ingress, which is likewise
  inert until btusb pumps it.
- **Related roadmap track(s):** Bluetooth. Keyboard transport +
  upper stack + event endpoint graduate; connection manager
  (LE scan/connect), SMP pairing, GATT-HOGP discovery, and the
  general L2CAP-signalling / RFCOMM / SDP layers for non-keyboard
  profiles remain open and SMP-gated.

## 2026-05-16 — virtio-input keyboard: reuse the PS/2 keymap, don't add an evdev table

The `kInput` virtio class was detected-but-unprobed (a `// STUB:`
in the fabric dispatch). virtio-input is the highest-leverage
unclaimed class: every QEMU/cloud guest can attach
`virtio-keyboard-pci`, and it has a clear in-kernel consumer (the
shared input queue) and a clear test path.

- **Decode reuses the active PS/2 keymap; no new evdev table.**
  Linux evdev keycodes for the AT 101/104 block (1..0x58) are
  numerically identical to PS/2 set-1 scancodes by historical
  design. So `EvdevToKeyCode` indexes the *same*
  `Ps2KeyboardActiveLowerMap()` / `UpperMap()` the PS/2 and
  USB-HID decoders already use, with a small switch for the
  specials that diverge (Esc, F1–F12, the extended nav block at
  102–111). This is the deliberate alternative to shipping a
  parallel ~110-entry evdev→char table: a second table would be
  a second source of truth for keyboard layout and would silently
  drift on a runtime layout switch. The next slice must extend the
  switch / shared keymap, NOT add an evdev table. (CLAUDE.md rule
  6 — one source of truth per resource.)
- **eventq mirrors the proven virtio-net RX shape.** N device-
  write descriptors, one `virtio_input_event` per buffer, drained
  by a dedicated 10 ms-cadence `virtio-input-evt-poll` task,
  re-posted per slot. No new queue primitive; the wire plumbing
  is the verbatim virtio-net/console pattern. IRQ-driven eventq
  is the next layer, exactly as it is for net/console.
- **Keyboard only, single device.** The statusq (LED/FF) is not
  installed (no consumer) and EV_REL/EV_ABS pointer events decode
  to nothing — virtio-mouse/tablet is a separate slice into the
  mouse injection path, GAP-marked. A second virtio-input
  function is rejected, matching virtio-console's v0 single-device
  stance. These are deliberate boundaries, not omissions.
- **Validation model.** A pure capture-seam self-test
  (`VirtioInputSelfTest`, `DUETOS_BOOT_SELFTEST`) drives synthetic
  evdev records and asserts the decoded KeyEvents
  (`[virtio-input] selftest pass`); a headless boot with
  `-device virtio-keyboard-pci` confirms the real device-probe /
  config-name / queue-setup / poll-task path attaches cleanly.
- **Related roadmap track(s):** VirtIO per-class polish.
  virtio-input keyboard graduates; pointer (EV_REL/EV_ABS) +
  statusq + IRQ delivery remain open. The fabric `// STUB:` now
  covers scsi/socket only.

## 2026-05-17 — DuetOS debug surface rides GDB `qRcmd`, not a parallel protocol

The in-kernel GDB server was already feature-complete for generic
debugging, but stock GDB cannot express DuetOS-specific state
(capability bitsets, IPC handle tables, the Win32 window manager,
probes, kdbg channels). The requirement was "a server a client/
specialized tool can connect to as a debugger" with full
introspection + control.

- **Extend the existing server via `qRcmd`; do NOT build a second
  debug server.** A `duet <verb>` command surface is delivered
  over the standard GDB `monitor` (`qRcmd,<hex>`) packet, so both
  a specialized client and stock `gdb` (`monitor duet …`) work
  against one transport / stop-loop / breakpoint implementation.
  A parallel debug protocol would have been a new forever-ABI and
  a second source of truth for "stop the box and inspect it"
  (CLAUDE.md rule 6). The reviewable signal — "could a malicious
  PE use this?" — is unchanged: every verb routes through the
  same physical-serial stop loop the `M`/`G` packets already trust.
- **Two new TUs, not inline.** `gdb_server.cpp` is already 1.9k
  lines (over the ~500 threshold). The surface lives in
  `kernel/diag/gdb_monitor.cpp` (dispatch + MonitorWriter +
  control verbs + self-test) and `gdb_monitor_read.cpp` (read
  verbs). The read-only subsystem-API consumers are isolated in
  one TU for the isolation audit; each TU stays under threshold.
- **Trust model is the honest one: no `kCapDebug` facade.** There
  is no authenticated principal on a raw serial transport. The
  monitor surface inherits the exact boundary the shipped `M`/`G`
  write packets already have; adding a cap check that gates
  nothing would be a probe-satisfying facade (CLAUDE.md-forbidden).
  Documented in `gdb_monitor.h`.
- **Single reply, hard-truncated; O-packet streaming deferred.**
  Over-long reports are truncated by `MonitorWriter` with a
  visible `[truncated]` sentinel — never a malformed/oversized
  packet. `O<hex>` console-output streaming is a v2 item; the
  Python client (`tools/debug/duetos-gdb-monitor.py`) already
  tolerates `O` packets so v2 is client-compatible.
- **Registry got the only new subsystem API.** Every other verb
  reused an existing kernel-callable accessor. The Win32 registry
  had no read-only kernel API, so a narrow `RegistryQuery` (renders
  text out, no `kRegKeys` pointer escapes) was added to the
  registry's own header — the same one-source-of-truth pattern
  `widget.h`'s window accessors already follow. No
  `Subsystem-Isolation.md` change needed: all reads go through
  public subsystem APIs.
- **DLL image names are not tracked.** `core::DllImage` carries no
  name field, so `duet mods` lists base/size/entry_rva/file_len by
  index. Naming is a follow-up if a real workload needs it.
- **Verified:** clean `x86_64-debug` build; boot self-test emits
  `[gdb-monitor-selftest] PASS`; `boot-log-analyze.sh` verdict OK
  (0 non-deliberate failures); end-to-end `qRcmd` exercised via
  the Python client against a `DUETOS_GDB_DEMO=ON` boot.
- **Related roadmap track(s):** GDB stub completion (peer-thread
  `vCont;s` remains the only deferred generic item; `qRcmd`
  `O`-packet streaming is the deferred monitor item).

## 2026-05-18 — Unified environment view is a read-only aggregator, not a new detector

The kernel already detected every environmental fact it needed
(hypervisor kind, CPU census, RAM, NUMA, AC/battery/lid, thermal)
but the detection was scattered and read ad-hoc — every consumer
re-derived state from a different subsystem and re-checked
`IsEmulator()` itself. The requirement was "allow the OS to be
aware and reactive of its environment," delivered over three
slices; this entry records slice 1 (aggregation + banner + query
API).

- **`kernel/env/` is a read-only aggregator; it never re-detects.**
  `EnvironmentInit()` copies fields from the owning subsystems
  (`arch::HypervisorInfoGet`, `acpi::CpuCount`,
  `arch::SmpCpusOnline`, `cpu::TopologyForCpu`, `mm::TotalFrames`,
  `acpi::srat::*`, `drivers::power::PowerSnapshotRead`). The
  rejected alternative — moving detection *into* `env/` — would
  have created a second source of truth per resource (CLAUDE.md
  rule 6) and an isolation-audit hazard. The reviewable signal is
  unchanged: `env` issues no new probes, takes no locks, and a
  guest workload cannot reach anything through it that it couldn't
  reach through the underlying subsystems.
- **One canonical banner via raw `SerialWrite`, not klog.** The
  `[env] …` line is a structural sentinel (like `[smoke] …`) so it
  survives log-level demotion and `boot-log-analyze.sh` can grep
  it. This is the consolidated hypervisor/SMP banner CLAUDE.md /
  the analyzer expected; the scattered `[hv]`/`[smp]`/`[thermal]`
  lines stay as their owners' detail.
- **Power policy is a pure function.** `EnvironmentDerivePolicy()`
  has no side effects so slice 2's monitor recomputes it
  identically on every poll; the self-test pins the
  cached-equals-derived invariant slice 2 depends on.
- **No CMake edit.** `kernel/CMakeLists.txt` globs sources
  `CONFIGURE_DEPENDS`, so `kernel/env/environment.cpp` is picked
  up automatically — the plan's "add to CMake" step was a
  non-issue once the glob was confirmed.
- **Verified:** clean `x86_64-release` build (zero warnings);
  `x86_64-release` full boot prints the `[env]` banner and
  `boot-log-analyze.sh` verdict OK (0 non-deliberate failures);
  `x86_64-debug` `bringup-only` smoke additionally emits
  `[env-selftest] PASS` (analyzer OK, 119 self-tests).
- **Related roadmap track(s):** environment awareness slices 2–3
  (monitor task + ACPI SCI/GPE power events) — see Roadmap
  "Environment awareness — runtime monitor + power events".

## 2026-05-18 — env-monitor: idle-path reaction deferred, not faked

Slice 2 of the environment work adds the `env-monitor` poller.
The approved plan also called for "bias the MWAIT/HLT idle path on
`PowerSave`." Implementing that faithfully surfaced that there is
**no safe real lever today**, so the decision is to deliver the
monitor now and land the idle reaction with slice 3.

- **No idle facade.** `sched::IdleMain` already issues MWAIT-C1
  (`EAX=0`) whenever the CPU advertises it — the code documents
  that as "at least as deep as a bare HLT and lower-power on most
  parts" with identical IRQ-wake semantics. The only deeper lever
  (the MWAIT EAX C-state hint / deep C-states + a cpuidle
  governor) is explicitly deferred elsewhere with "no profile
  evidence and no consumer yet." Wiring `EnvironmentPowerPolicy()`
  into the hot idle loop where it would change nothing is a
  probe-satisfying facade (CLAUDE.md rule). Rejected. The idle
  C-state reaction lands in slice 3, where the real lever and a
  consumer arrive together. User chose this over (a) a bounded
  pre-halt spin-poll (perf tuning with no profile evidence —
  anti-bloat) and (b) pulling deep-C-states forward. DD-009
  (tickless) stays untouched.
- **The reactive payoff is the live cache, not a knob.** Slice 1
  froze the snapshot at boot; slice 2's monitor re-composes and
  republishes every ~2 s, so every later reader sees current
  state. That is the substantive "reactive" delta — a consumer
  (shell, slice 3) acting on stale boot state was the actual gap.
- **Policy transition is INFO, not WARN.** A power-source change
  is a legitimate, expected event. Logging it at WARN would flood
  on every unplug (CLAUDE.md "log-level abuse" class-of-bug). The
  summary is `KLOG_INFO`, detail is `KLOG_DEBUG_V`, and the
  GDB-breakable sentinel is the `env.policy_change` probe
  (`ProbeId::kEnvPolicyChange`, ArmedLog: a clean steady boot
  never transitions so the log stays quiet).
- **Reads are snapshot-by-value under a spinlock.**
  `EnvironmentGet()` changed from returning `const&` (slice 1,
  write-once) to returning `SystemEnvironment` by value under
  `g_env_lock`, because the monitor now mutates `g_env`
  concurrently and a reference would tear. `EnvironmentDerivePolicy`
  stays pure so monitor and self-test recompute identically.
- **Verified:** clean `x86_64-release` build (zero warnings);
  release full boot prints `[env]` + `boot-log-analyze.sh`
  verdict OK; `x86_64-debug` `bringup-only` smoke emits
  `[env-selftest] PASS` and `[I] env : environment monitor
  online`, no spurious `env.policy_change` (policy stays
  `balanced` on QEMU — clean boot stays quiet), analyzer OK
  (119 self-tests, 0 non-deliberate failures).
- **Related roadmap track(s):** environment awareness slice 3
  (ACPI SCI/GPE power events + the now-meaningful idle reaction).

## 2026-05-18 — env slice 3: ACPI SCI power events; idle reaction stays deferred (honest correction)

Slice 3 wires the ACPI System Control Interrupt so the OS reacts
to a real power-management interrupt instead of only a 2 s poll.
It also corrects an over-promise made in the slices 1–2 docs.

- **IRQ-context handler, process-context worker, WaitQueue seam.**
  The SCI handler must not touch AML / allocate / block, but the
  reaction (`AcpiShutdown` evaluates `\_S5` AML) is process-context
  only. Split: `kernel/acpi/acpi_sci.cpp`'s handler read-/write-1-
  clears PM1+GPE status, latches a `SciPending`, and
  `WaitQueueWakeOne(&g_env_wq)` (the documented IRQ-safe wake);
  the `env-monitor` task blocks on that queue
  (`WaitQueueBlockTimeout`, 2 s fallback) and does the AML work.
  ACPI owns the hardware (registers, enable handshake, handler);
  env owns the policy (button ⇒ shutdown). No subsystem-boundary
  violation.
- **GPE `_Qxx` is a documented GAP, not built.** The handler acks
  + masks GPE status (so a level-triggered SCI can't stay
  asserted) but does not evaluate the firmware's per-GPE `_Qxx`
  method. A full `_Qxx`/EC-query path is untestable on the only
  available target (QEMU has no EC, no power AML) — building it
  now would be speculative + unverifiable (anti-bloat). Power
  button (the event QEMU *can* raise) is fully handled. The
  "Battery + ACPI suspend" roadmap entry tracks the `_Qxx`
  residual.
- **Idle-path C-state reaction: still deferred — honest
  correction.** Slices 1–2 said it would land "with slice 3,
  where a real lever and a consumer arrive together." That was
  optimistic: slice 3 added the SCI *event* path, not deep
  C-states. There is still no safe non-speculative idle lever
  (`IdleMain` already uses MWAIT-C1; the deeper hint / cpuidle
  governor remains deferred with no profile evidence and no
  consumer). Wiring a no-op policy read into the hot idle loop
  remains a facade and is still rejected. The substantive
  slice-3 reactivity is event-driven (instant power-button
  shutdown + SCI-driven monitor wake), which fulfils the
  requirement without the facade. The C-state lever lands only
  if deep C-states are implemented for their own reasons.
- **Pre-existing ~17 s CI auto-poweroff — bisected, NOT a slice-3
  regression.** While testing, the release headless boot was
  observed to ACPI-poweroff (~17 s) on its own. Building the
  slice-2 commit and re-running the identical QMP-status probe
  showed the **same ~17 s shutdown** — it predates this feature
  (it is the CI/smoke boot's normal end; that is why
  `boot-log-analyze` reports "completed"). Slice 3 introduced no
  regression; the env/SCI sentinels never fired during it.
- **Live power-button e2e is un-observable here — say so, don't
  fake it.** The `env-monitor` (Normal priority) only gets CPU
  after the boot task winds down, ~coincident with that
  pre-existing auto-poweroff, so the SCI arms just as the box
  powers itself off — no window to land a QMP button press
  first. `tools/test/env-powerbtn-smoke.sh` (committed; `qmp.sh`
  gained a `powerdown` verb) therefore reports **SKIP** (exit 0)
  on that race, **PASS** only on the raw `[env/sci] PWRBTN_STS
  latched` sentinel, **FAIL** only on panic or an armed-but-
  ignored button. Correctness up to the hardware boundary is
  proven by `[acpi/sci-selftest] PASS` (synthetic PM1 decode +
  latch round-trip), the raw `[acpi/sci] armed` milestone
  (verified in release), `[env-selftest] PASS`, and a clean
  analyzer verdict.
- **Sentinels are raw serial, by design.** `[acpi/sci] armed`
  (one-time milestone, like the sibling `[acpi] sci_int=` line)
  and `[env/sci] PWRBTN_STS latched` / `power button -> ACPI
  shutdown` (rare, terminal) are raw `SerialWrite` so they
  survive klog level demotion in release and the analyzer / smoke
  can gate on them — same rationale as the `[env]` banner.
  Redundant KLOG lines next to them were removed (anti-bloat).
- **DD-012 revisited.** FADT GPE0/GPE1 + PM1 event blocks +
  SMI_CMD/ACPI_ENABLE are now parsed and consumed (status + ack +
  enable handshake). `_Qxx` AML evaluation and the PM timer
  remain unconsumed.
- **Verified:** clean `x86_64-release` build (zero warnings);
  release boot prints `[env]` + `[acpi/sci] armed`,
  `boot-log-analyze.sh` verdict OK; `x86_64-debug` `bringup-only`
  emits `[acpi/sci-selftest] PASS`, `[env-selftest] PASS`,
  `[acpi/sci] armed`, `environment monitor online`, analyzer OK
  (120 self-tests, 0 non-deliberate failures, no spurious
  PWRBTN); power-button smoke SKIPs cleanly per the race above.
- **Related roadmap track(s):** "Battery + ACPI suspend" (`_Qxx`
  AML query residual; S3/S0ix). Environment-awareness slices
  1–3 are complete and removed from the Roadmap.

## 2026-05-18 — Autonomic engine acts CPU-side; scheduler knob is balancer-cadence, not a faked tick-rate

- **Context.** The neural-engine arc's step 2 (sense → decide →
  **act**) needed a real actuator. An inventory of the kernel
  (`tools/` agent sweep) confirmed there is **no** runtime
  scheduler tick-rate or quantum knob — `time::kTickHz` and the
  round-robin quantum are compile constants. The earlier
  "idle reaction deferred" entries already established there is
  no safe idle-C-state lever either.
- **Decision.** Do **not** fake a power knob. The autonomic
  engine (`kernel/env/autonomic.{h,cpp}`) drives only real,
  task-context-safe levers: `mm` reclaim/trim, `security`
  guard/policy escalation, `RuntimeCheckerScan`, and one new
  *genuine* scheduler lever — `SchedSetPowerBias`, which scales
  the **active load-balancer cadence** (`PowerSave`: 8→32 ticks).
  Balancer cadence is real, observable, reversible, and
  hot-path-cheap (one byte read + branch); it is explicitly
  *not* a tick-rate/quantum facade. Rules are rising-edge
  latched; the decision (`AutonomicEvaluate`) is pure so the
  future NPU-learned policy swaps it without touching actuators.
- **Rules out.** A cpuidle governor / MWAIT C-state hint as the
  power lever (no profile evidence, no consumer — same reasoning
  as the slice-3 idle entry); a per-vendor whitelisted actuator
  set (rule predicates are property tests, not allow-lists).
- **Security posture.** Rule 3 deliberately auto-applies
  `Production`/`Enforce` on a kernel-integrity finding from the
  monitor poll — the user chose the full escalation (not the
  alert-only variant). This closes the runtime-checker's
  long-standing "no automatic escalation" gap.
- **NPU independence.** The engine has zero NPU dependency and
  runs entirely CPU-side — the honest "works without the NPU /
  no firmware yet" baseline. The NPU later only replaces the
  pure decision function.
- **Verified:** zero-warning `x86_64-debug` **and**
  `x86_64-release` builds; debug boot emits `[npu] selftest
  pass`, `sched : power bias changed to="balanced"`,
  `[autonomic] engine primed`, `[autonomic] selftest pass`;
  `boot-log-analyze.sh` verdict OK (120 self-tests, 0
  non-deliberate failures); `clang-format` clean; `ctest`
  boot-smoke SKIPs cleanly under TCG (no `/dev/kvm`).
- **Related roadmap track(s):** the neural-engine arc step 3
  (NPU firmware + submit gate, then learned policy behind
  `AutonomicEvaluate`).

## 2026-05-18 — Oversized core TUs are cohesive by design; do not size-split syscall.cpp / sched.cpp / widget.cpp

- **Context.** The CLAUDE.md bloat-check flags the five largest
  TUs (`syscall.cpp` ~4.1k, `sched.cpp` ~4.9k,
  `drivers/video/widget.cpp` ~3.4k, `userland/libs/user32/user32.c`
  ~3.4k, `core/boot_tasks.cpp` ~3.1k) as over the ~500-line
  guideline. A refactor pass investigated whether each should be
  split into sibling TUs by responsibility.
- **Decision.** Do **not** mechanically size-split the three that
  are cohesive units. The anti-bloat rule is explicit that the
  threshold is "pause and think," not a hard limit — "split if
  doing multiple jobs; leave if one coherent unit," and "never
  sacrifice readability to hit a line count." Evidence per file:
  - `syscall.cpp` — a single deliberate `switch (num)` over 223
    cases where (per the file's own banner) every handler shares
    inline scratch state and the common early-exit / capability /
    fault-domain paths *specifically to avoid per-handler
    boilerplate*. A switch is one function; "splitting" it means
    extracting 223 handlers and threading the shared scratch
    through parameters — undoing a documented design choice and
    adding ABI-critical risk for zero readability gain.
  - `sched.cpp` — scheduler core: 16 file-static structures and
    ~153 internal cross-references across ~128 functions. Maximal
    cohesion; splitting exports scheduler internals across a TU
    boundary (dangerous, low value).
  - `widget.cpp` — desktop toolkit with bidirectional
    window↔button↔tooltip state coupling interleaved across the
    whole file (button code reads `g_windows`; window code reads
    button/tooltip state). A window *contains* buttons; this is
    one coherent subsystem.
- **Rules out.** A future slice mechanically splitting these by
  line count "because the bloat-check flagged them." It should
  not: the flag warrants the investigation (done here), and the
  investigation's answer is "cohesive — leave." Re-opening
  requires a *genuine* multi-responsibility seam, not size alone.
- **Open (not ruled out).** `boot_tasks.cpp` (28 file-statics,
  few very large phase functions) and `user32.c` (42 file-statics,
  flat Win32-API surface) *may* have real seams (boot-phase /
  API-group), but each needs a dedicated careful per-file
  partition analysis — explicitly NOT a rushed mechanical split.
- **Verified:** analysis only; no code changed by this decision.
  Conclusion backed by per-file file-static/cross-reference counts
  and each file's own header banner.
- **Related roadmap track(s):** refactor backlog "split oversized
  TUs" — partially resolved (3 closed as cohesive; 2 deferred to
  dedicated sessions with the seam analysis above as the brief).

## 2026-05-19 — AP per-CPU register state is established AFTER segment/IDT load, and `CurrentCpu()` never assumes BSP

The intermittent SMP "task double-run" (`MUTEX-NONOWNER` /
`sync/spinlock release-out-of-order` under `gui-fuzz.sh 18` on
4 CPUs) and the silent AP-bring-up triple fault were one root cause
in two parts, both on the AP bring-up path:

1. **GSBASE was programmed before the GDT load, not after.**
   `LoadGdtForCurrent`'s `mov %ax, %gs` reloads GS's hidden base
   from the kernel-data descriptor (base 0) — it ZEROES
   `IA32_GS_BASE` as a side effect. `ApEntryFromTrampoline` wrote
   the AP's per-CPU pointer *before* that, so it was dead on
   arrival and every `cpu::CurrentCpu()` on the AP saw GSBASE=0.
2. **`cpu::CurrentCpu()` "fell back to the BSP slot" for a
   non-kernel GSBASE.** Correct single-CPU; on SMP it silently
   mis-attributed an AP to the BSP, so the AP read/wrote the BSP's
   `current_task`, `ctxsw_lock_to_release` lock-pass slot, per-CPU
   runqueue, and the `g_per_cpu[0]` lockdep held-stack alias — the
   cross-CPU corruption behind every observed symptom.
3. **APs never executed `lidt`.** IDTR is per-CPU; the trampoline
   only loads a transition GDT and `IdtInit` lidt'd only the BSP.
   The first timer tick on an AP #GP'd reading a bogus gate ->
   #DF -> triple fault, silent on serial (looked like a hang).

**Decisions (rule out the alternatives):**

- The kernel per-CPU MSR pair (`IA32_GS_BASE` /
  `IA32_KERNEL_GS_BASE`) is established **after** `LoadGdtForCurrent`
  on every CPU that loads a GDT, mirroring the BSP (`PerCpuInitBsp`
  writes GSBASE after `GdtInit`). Writing it before a segment
  reload is rejected: the reload clobbers it.
- `cpu::CurrentCpu()`, when GSBASE is non-kernel, resolves the
  **real** CPU via the hardware-authoritative LAPIC ID, never by
  assuming BSP. The "assume BSP" shortcut is rejected for SMP: a
  wrong-but-kernel-looking PerCpu is worse than a fault because it
  corrupts silently. A gated `kCurrentCpuGsbaseFallback` probe +
  `OnTimerTick` count sentinel turns any future swapgs/AP-GS
  regression into a single WARN + probe instead of silent
  corruption (clean boot stays at zero).
- IDTR is per-CPU: every CPU that runs kernel code must `lidt`
  the shared global IDT during its own bring-up
  (`IdtLoadForCurrent()`), after its GDT load and before it
  unmasks interrupts. Sharing the *table* does not share the
  *register*.

**Verified:** 6/6 clean `tools/qemu/gui-fuzz.sh 18` SMP runs
(complete, ~11k–13k iters, no crash signature) + a 6-boot
determinism sweep (all 3 APs join every boot, byte-stable,
zero panic / triple-fault / GSBASE fallback). Plain SMP boot now
runs steady-state past AP bring-up (previously triple-faulted
~t=500 ms). qemu.log `-d int,cpu_reset` shows no exception
escalation.

**Related roadmap track(s):** deleted "SMP task double-run under
heavy scheduler churn"; updated "Lockdep held-set must be
per-task" (the SMP `release out-of-order` symptom was this root,
now resolved; the spinlock-vs-mutex held-stack split remains as
architectural cleanup with no live failure).

## Mouse input is coalesced; compose-rate is decoupled from packet-rate

The `mouse-reader` task may force a full-screen `DesktopCompose()`
in response to a packet (menu hover, drag, resize). A full compose
cannot complete within the ~100 Hz PS/2 packet interval, so a
one-compose-per-packet design makes the consumer fall behind the
IRQ producer; the 32-slot decoded-packet ring overflows
(drop-oldest), motion deltas are lost, and the cursor visibly
crawls — most noticeably navigating the Start menu.

**Decision:** the reader coalesces consecutive **same-button-mask**
motion packets into one before acting (`AcquireCoalescedPacket`),
and the menu-open recompose is gated on an actual highlighted-row
change (`MenuTrackHoverAt` → whole-stack `HoverSignature`), not raw
motion.

**Rejected alternatives, and why they stay rejected:**

- *One compose per packet (the original).* Structurally cannot keep
  up with the PS/2 rate; the ring overflow is not a tuning problem.
- *Just enlarge the ring.* Treats the symptom: a bigger ring delays
  overflow under sustained motion, it doesn't prevent it, and it
  adds latency (stale deltas) when it finally drains.
- *Coalesce across button transitions / "only when no button is
  held".* Either loses a fast press+release that lands within one
  drain, or refuses to coalesce during a held-button drag (so drag
  lag survives). Coalescing spans a held-button drag specifically
  because the mask is constant there — no edge is hidden — while
  any mask change ends the batch and is replayed discretely.

**Verified:** clean build on both x86_64-release and
x86_64-debug-ubsan (UBSan live). Runtime, x86_64-debug-ubsan:
`tools/test/mouse-motion-soak.sh` injected **1411** HMP mouse
moves over 30 s; the coalesced reader processed them end-to-end
(post-bringup `[ui] netpanel hover preview` recomposes fired —
the *same* expensive-recompose-per-motion mechanism as the menu
bug), and the ps2mouse ring once-warn ("consumer too slow")
fired **0** times, with 0 non-deliberate soft-lockups / UBSan /
panics. This is the load-bearing positive evidence. The
menu-specific repro `tools/test/mouse-menu-lag-repro.sh` is
committed but currently **inconclusive headlessly**: opening the
Start menu needs a pixel-precise HMP click on a theme-dependent
START rect, which this QEMU rig can't place reliably (it exits
75/INCONCLUSIVE, not FAIL — a tooling limit, not a regression).
The netpanel-hover path above is the proven stand-in.

**Related roadmap track(s):** none (defect fix; no roadmap item).

## virtio-tablet absolute coordinates: convert to deltas at driver, don't fork MousePacket

QEMU's `-device virtio-tablet` advertises `EV_ABS` axes carrying
absolute device coordinates rather than `EV_REL` deltas. The
existing pointer ABI (`MousePacket` in
`kernel/drivers/input/ps2mouse.h`) is relative-only and shared by
every pointer driver (PS/2, xHCI HID boot, virtio-input), per the
CLAUDE.md "one source of truth" rule for input.

**Decision:** the virtio-input decoder converts `EV_ABS` axes into
relative deltas at the driver boundary, by remembering
`last_abs_{x,y}` per axis and emitting `dx = curr - last` on the
next `EV_SYN` frame. The first `EV_ABS` sighting per axis records
the baseline silently — no packet — so a freshly attached tablet
doesn't fling the cursor toward (0, 0).

**Rejected alternatives:**

- *Extend `MousePacket` with `abs_x` / `abs_y` + a flag and teach
  the cursor consumer to honour it.* Architecturally cleaner but
  forks the unified pointer ABI: the compositor mouse loop, the
  xHCI HID decoder, and the PS/2 path all consume `MousePacket`
  uniformly today; an absolute-vs-relative branch leaks into every
  consumer. The end-user behaviour for the QEMU-tablet flow is
  identical either way (host motion drives guest cursor 1:1) —
  QEMU releases its pointer grab as soon as the guest reads
  `EV_ABS`, independent of whether the guest internally treats
  the axes as absolute or relative.
- *Translate to screen coordinates using `ID_ABS_INFO` resolution
  and `kFramebufferWidth/Height`.* Adds a config-space query +
  screen-size knowledge to the driver, neither of which is needed
  for the delta path; pure surface for a future regression when
  the framebuffer resizes.
- *Drop EV_ABS silently (keep the old GAP marker).* The status quo;
  the tablet's host-cursor-to-guest-cursor flow stays broken.

**Why this rules out the alternative going forward:** any future
pointer driver that ships absolute coordinates (USB-HID digitiser,
multi-touch) follows the same "convert at driver boundary"
convention rather than re-introducing an `abs` branch in
`MousePacket`. Multi-touch (which truly needs per-contact state)
will land its own contact-list ABI alongside `MousePacket`, not
inside it.

**Revisit when:** a workload appears that needs the *exact* host
cursor position with sub-frame precision (e.g. a drawing tablet
that pre-emptively locates the cursor before a stroke begins),
which the delta path approximates but doesn't anchor. At that
point the convert-at-driver invariant gets a per-driver "current
absolute position" out-of-band query, not an in-band MousePacket
field.

**Related roadmap track(s):** VirtIO per-class polish
(`virtio-input EV_ABS + statusq` — the EV_ABS half is closed by
this slice; statusq LED / force-feedback remains).

## Audio mixer v0 is in-place saturating-add, not a per-producer staging mixer

The audio backend's `WritePcmS16Stereo` had been a single-producer
overwrite — whoever wrote the ring last owned the buffer until
they were done, so two concurrent PEs calling `SYS_AUDIO_WRITE`
would stomp each other. The roadmap "Audio — mixer" item called
for fixing this. Two end-shapes were considered:

**Decision:** `WritePcmS16Stereo` is now a *saturating-add* into
the existing single ring — two contributors writing into the same
slot compose by sum, with INT16 saturation preventing
wrap-around-to-noise on overflow. A new
`WritePcmS16StereoOverwrite` entry preserves the legacy
"replace" semantic for fill-the-whole-ring producers (`WriteSine`,
which would compound across calls otherwise).

**Rejected alternatives, and why they stay rejected:**

- *Per-producer staging buffers + a mixer task that sums N rings
  into the DMA ring before each playout window.* The correct
  long-term shape, but the staging memory + the periodic mixer
  task + the producer-cursor table is substantially more code
  than the in-place add. With one ring and same-offset producers,
  the in-place add is already a real mixer for the dominant case
  (music + notification beep at the same instant). Per-producer
  staging earns its keep only when staggered-offset producers
  need cursor management — that's the *next* slice, not v0.
- *Keep `WritePcmS16Stereo` overwrite, add a parallel
  `WritePcmS16StereoAdd`.* Producer code (`SYS_AUDIO_WRITE`,
  `winmm!waveOutWrite`) would have had to opt in. Defaulting the
  existing entry to additive means every existing producer
  automatically composes; the `Overwrite` variant is the explicit
  one, used only by `WriteSine` and friends that intend to fill
  the entire ring with one signal.
- *Per-producer write-cursor table now.* A clean v0 needs a
  per-process cursor entry, ring-allocation policy when a
  producer first writes, and a cleanup path on producer exit.
  All three are doable but expand the slice past what the
  roadmap item required.

**Why the in-place mixer is correct for v0:**

- Same-offset concurrent writes (the dominant collision pattern)
  now compose instead of stomping.
- Saturation prevents the "two loud streams = noise" pathology.
- `WriteSine` and other fill-the-buffer producers retain
  overwrite semantics through the explicit
  `WritePcmS16StereoOverwrite` entry — they don't accidentally
  compound by calling the additive path.
- Self-test extension verifies both the sum and saturation
  invariants on the same code path the user-mode producers
  exercise.

**Revisit when:** staggered-offset multi-stream producers appear
(two PEs each emitting their own continuous audio without any
shared offset coordination). At that point each producer needs
its own `frame_offset` anchored relative to LPIB + a small
lookahead, and the ring-clearing policy moves from "WriteSilence
between sessions" to "kernel zeroes the fresh region ahead of
LPIB on each tick." Until that workload exists the in-place
saturating mixer is the right size.

**Related roadmap track(s):** Audio — real-hardware audible +
per-producer cursors (the v0 mixer half closed by this slice;
per-producer write cursors remain).

## SMP AP IA32_APIC_BASE must set EXTD when g_x2apic is true, not just EN

Across QEMU runs we observed an intermittent `#GP` (`trap.kernel_gpf`
with `rip` resolving to `arch::WriteMsr` at `kernel/arch/x86_64/cpu.h:187`,
i.e. the `wrmsr` inside the generic `WriteMsr`) during SMP bring-up.
Frequency on `tools/qemu/run.sh` (debug preset, 4 vCPUs, x2APIC
host CPU model): roughly **40% of clean origin/main boots** hit
it; some delivered a full panic dump, others surfaced as a
`recursive-fault` short-circuit. The fault is in the LapicWrite
→ `WriteMsr(0x800+offset, ...)` path — an `wrmsr` to the x2APIC
MSR range from a CPU that the BSP-side scheduler believes is in
x2APIC mode (`g_x2apic = true`).

Root: `kernel/arch/x86_64/smp.cpp::ApEntryFromTrampoline` (the AP
kernel entry) only set IA32_APIC_BASE bit 11 (EN — global APIC
enable) on the AP. The BSP's `LapicInit` sets `EN | EXTD` (bit 10
= x2APIC mode select) and flips `g_x2apic = true`. The AP's
trampoline-side state for IA32_APIC_BASE was QEMU-dependent: in
some runs bit 10 was preserved from the BSP-side configuration of
the AP, in others it was not. When it was not, the AP transitioned
through `ApEntryFromTrampoline` in plain xAPIC mode while
`g_x2apic` said x2APIC mode — and `LapicWrite(TPR, 0)` at the end
of AP startup `#GP`'d on `wrmsr 0x808`.

**Decision:** the AP now reads `LapicIsX2apic()` (the same
`g_x2apic` flag) and ORs in `(EN | EXTD)` when true,
or just `EN` when false. The check guards a single rdmsr +
conditional wrmsr; idempotent if firmware already set the bits,
corrective if not.

**Rejected alternatives:**

- *Always wrmsr EN | EXTD unconditionally.* Equivalent on x2APIC
  systems, but flips EXTD on plain-xAPIC systems where
  `g_x2apic` is false — that's a one-way mode transition with
  no rollback, and we don't want it on hardware that doesn't
  support x2APIC (`CpuHas(kCpuFeatX2Apic)` is false, so
  `g_x2apic` stays false, so the conditional is correct).
- *Re-check `apic_base` after the wrmsr.* Pointless — wrmsr
  either takes or `#GP`s; a follow-up rdmsr only confirms
  what the architecture already does.
- *Bail out and panic if EXTD wasn't preserved.* Worse than
  silent recovery — every release of QEMU could regress us, and
  setting the bit costs nothing.

**Residual (not yet fixed in this slice):** a separate
intermittent `#GP` in `WriteMsr` still fires on roughly 20% of
runs *after* this fix, this time during the BSP-side AP startup
loop (right after `arch/smp : starting AP apic_id val=0x1`,
before AP1's `ApEntryFromTrampoline` has run). The fault site is
`LapicSendIcr` → `WriteMsr(kX2ApicIcrMsr=0x830, ...)` from the
BSP, but the BSP has been in x2APIC mode since `LapicInit` and
the ICR value violates no documented Intel SDM constraint
(INIT-assert = `0x500 | 0x4000 = 0x4500`, SIPI = `0x600 |
vector`; no reserved bits set). The kernel recovers via the
`recursive-fault` short-circuit (no panic dump emitted), so
boot continues, but the underlying race deserves its own
investigation slice. The fix above is still load-bearing —
without it the failure mode was a *full panic dump* with the
kernel halted, not a recoverable probe.

**Verified:** 10-run QEMU smoke gate (`DUETOS_TIMEOUT=45`,
debug preset): 0/10 panic dumps, 2/10 `recursive-fault`
recoveries (vs. 2/5 hard panic dumps on clean origin/main),
30/30 selftests passed (terminal / virtio-input / audio).

**Revisit when:** the residual ICR `#GP` is investigated, or a
real-hardware fleet shows a different LAPIC mode mismatch
shape. The cleanest follow-on is a per-CPU "ensure my LAPIC is
the same mode the BSP committed to" assert at AP entry, with
an explicit panic if it can't be brought into agreement —
fail loud rather than rely on `wrmsr` reserved-bit silence.

**Related roadmap track(s):** none directly (SMP bring-up is
considered shipped); the residual ICR race is a candidate for
a new "SMP-AP scheduler residual flakes" roadmap entry.

## 2026-05-22 — Panic dump stack scans must stop at the kstack-arena guard page

**Decision:** `kernel/core/panic.cpp::PlausibleStackPointer`
(and its mirror in `kernel/diag/bsod.cpp`) reject any address
that falls inside a kernel-stack-arena guard page (via
`mm::IsKernelStackGuardFault`). Every dump-side stack scan
(`DumpStack`, `DumpReturnAddressPointers`, `DumpBacktrace`,
`DrawStackTop`, `DrawBacktrace`) is gated by this predicate, so
the bound is enforced once per process rather than per loop.

**Why:** when the panicking task's `rsp` sat near the top of
its 64 KiB stack slot, `DumpReturnAddressPointers`'s 0x80-quad
forward scan would walk past the slot top and read into the
**next** slot's deliberately-unmapped guard page on iteration
`N = (slot_top - rsp) / 8`. That read #PF'd; the trap
dispatcher recognised the address via `IsKernelStackGuardFault`
and called `Panic("sched/kstack", "guard-page hit — kernel
stack overflow")` — which hit the recursive-panic short-circuit
in `Panic()` because the original panic had already set
`PanicInProgress`. Net effect: the original panic banner
truncated mid-dump (`[panic] --- diagnostics ---` started but
the BSOD, minidump, and peer-CPU snapshots never streamed) and
the post-mortem only had the one-line recursive-panic marker.

Observed shape pre-fix in 2026-05-22 SMP=8 release loop (15
boots): 2/15 ended with
`[recursive-panic] sched/kstack: guard-page hit — kernel stack
overflow value=0xffffffffe018N000` truncating an underlying
`#UD` on a fresh AP idle task. Same root for the user-reported
`[recursive-panic] security/stack: stack canary corrupted —
short-circuiting` shape (compiler-emitted `__stack_chk_fail`
firing because the dump path's deep frames blew their own
prologue stash before reaching the guard page).

**Rejected alternatives:**

- *Bound each scan loop manually (per-call-site).*
  `DumpStack` + `DumpReturnAddressPointers` + the two BSOD
  mirrors all walk forward; bound-them-each meant four diffs +
  four chances to forget. Gating at the predicate fans out for
  free and catches future scan helpers that route through the
  same check.
- *Pre-compute `slot_top` from `Current()->stack_base +
  stack_size` and clamp the loop.* Wrong for the boot task
  (stack from `boot.S`, not in the arena) and for AP bootstrap
  stacks (`KMalloc`-allocated). The `IsKernelStackGuardFault`
  check naturally excludes both (returns `false` outside the
  arena VA range).
- *Page-bound the scan (`hexdump.cpp` shape — "stay in the
  starting page").* Already shipped for `hexdump.cpp` earlier
  this session, but tighter than necessary — `DumpStack`
  legitimately wants to scan a few pages of stack when the
  task's locals span multiple frames. Slot-bounding (one full
  64 KiB) is the right granularity for dump readers without
  cutting into legitimate scans.

**Verified:** post-fix 15-boot SMP=8 release loop showed 0/15
recursive-panic short-circuits (down from 2/15 baseline) AND
1/15 emitted the full original `#UD` panic banner (with
`probe trap.kernel_ud` armed, peer-CPU snapshots, held-lock
table, log-ring tail, dump end marker) instead of being
truncated. The underlying `#UD` on `rip=0x101e` is unchanged —
it's a separate latent issue now visible enough to triage in a
follow-up slice (Roadmap: "Boot-tail #UD at RIP=0x101e on a
fresh AP idle task").

**Revisit when:** the kernel-stack arena layout changes
(stride, guard-page count, or arena base move), since
`IsKernelStackGuardFault`'s implementation closes that contract
in `mm/kstack.h`. The dump-side predicate just routes through it.

**Related roadmap track(s):** "Boot-tail #UD at RIP=0x101e on
a fresh AP idle task — intermittent" carries the residual
investigation now that the panic banner streams cleanly.

## 2026-05-23 — SchedTaskTrampoline reserves 16 bytes so RSP never sits at slot_top

**Decision:** `kernel/sched/context_switch.S::SchedTaskTrampoline`
emits `sub $0x10, %rsp` as its first instruction after `endbr64`
and keeps RSP at `slot_top - 16` (or deeper) for the rest of the
trampoline's lifetime. The planted `&SchedTaskTrampoline` at
`slot_top - 8` is therefore preserved across every IRQ that
fires while the trampoline is running. The validator in
`Schedule()` (kernel/sched/sched.cpp:2386) is tightened to
accept ONLY `&SchedTaskTrampoline` at that slot — the
`+0x17` / `+0x1c` (return-from-`call rbx` / `call SchedExitC`)
acceptances are removed because those return addresses now land
at `slot_top - 24`, not `slot_top - 8`.

**Why:** x86_64 hardware unconditionally pushes a 40-byte iretq
frame on every interrupt taken from kernel mode — SS, RSP,
RFLAGS, CS, RIP, in that order, top-to-bottom. The TOP quad
(SS = `kKernelDataSelector` = `0x10`) lands at `<RSP at time of
IRQ> - 8`. If an IRQ fires while RSP = slot_top inside the
trampoline (the window between ContextSwitch's `ret` and the
trampoline's first `call`, and again between every internal
`ret` and the next `call`), the SS push overwrites the planted
RA with `0x10`. After iretq, RSP returns to slot_top but the
bytes at slot_top-8 keep the `0x10` value. The next push at
slot_top-8 (inside the next `call`) overwrites it back to a
valid return-address shape; but if the task is preempted in
the meantime, its saved-state slot_top-8 retains `0x10`, and
the next switch-back-in either (a) trips the proactive
validator (observed shape, ~60% on SMP=8 release boots) or
(b) eventually pops `0x10` via some `ret` and faults wild
(observed shape pre-2026-05-22, before the validator landed —
`rip=0xffffffffe014Nfe7` NX_VIOLATION inside the kstack arena).

The `sub $0x10, %rsp` shifts the trampoline's RSP one full
16-byte ABI alignment frame below slot_top for the entire
trampoline lifetime. IRQ frames now land at `slot_top - 24`
and below, never at `slot_top - 8`. The planted RA is intact
across every preemption-and-resume cycle, the validator
goes silent, and the wild-RIP shape stops reproducing.

`16` (not `8`) keeps RSP 16-aligned per SysV — calls expect
`(RSP+8) mod 16 == 0` on entry. With slot_top 16-aligned,
slot_top - 16 is also 16-aligned. The 8 dead bytes between
RSP and the planted RA are never read or written by trampoline
code.

**Rejected alternatives:**

- *Move `sti` to immediately before `call rbx` and rely on the
  one-instruction sti-shadow to protect that single push.*
  Covers only one of three vulnerable windows (between the
  Validator's `ret` and `call rbx`). The other two — between
  ContextSwitch's `ret` and the first trampoline `call`, and
  between the entry function's `ret` (if it returns) and
  `call SchedExitC` — still hit the SS-scribble. Two-phase
  cli/sti gymnastics would patch them individually, but at the
  cost of a fragile audit surface every time the trampoline
  gains an instruction.
- *Plant the trampoline RA at slot_top - 16 instead of
  slot_top - 8.* Would require an extra padding push in
  `SchedCreate`'s primer and a 7-quad pop in ContextSwitch
  (currently 6); doesn't generalise to other situations where
  RSP must not equal slot_top (e.g. a future ring-0-only
  trampoline variant); and the validator would still have to
  watch wherever the new "topmost legitimate quad" lives.
- *Memset the stack to zero in `AllocateKernelStack` (defensive
  hygiene against stale frame content).* Ruled out by
  experiment 2026-05-23: a 30-boot sweep with the full-stack
  memset still showed ~60% scribble rate, identical to the
  pre-fix baseline. The 0x10 was being WRITTEN to slot_top-8
  by an active hardware push, not leaked from a previous
  use of the physical frame.
- *Broadcast an IPI to clear slot_top-8 after the trampoline's
  first call.* Catches the bug AFTER it has already happened
  (the proactive validator already does so without the IPI
  cost); doesn't prevent the wild-RIP shape from manifesting
  in the window between the SS push and the next push.
- *Add a kernel-side hardware watchpoint on the planted RA
  slot.* `kernel/debug/watch.h` exists but per-task DR state
  doesn't broadcast across CPUs (and the SS push originates
  from the IRQ hardware path, before any C code that would
  consult DR0..DR3 runs). Only useful as a regression
  detector, not a fix.

**Verified:** post-fix 30-boot SMP=8 release sweep (via
`tools/test/trampoline-scribble-sweep.sh`) shows 0/30 scribble
fires (down from 3/5 = 60% pre-fix baseline on the same
sweep harness, same kernel modulo the trampoline patch and
the validator tightening). Boot-tail #UD shape last observed
pre-fix is now structurally impossible — the SS push that fed
it has nowhere damaging to land.

**Revisit when:** the trampoline gains a new `call` site that
moves RSP back to slot_top transiently (any `add rsp, 16` /
`pop r…` that walks the reservation back up); when the
kernel-data selector value moves out of GDT slot 2 (= 0x10)
and into a value that happens to be a valid kernel text RIP
shape; or when DuetOS adopts a CPU architecture whose IRQ frame
ordering differs from x86_64's "top quad = saved SS."

**Related roadmap track(s):** "Boot-tail #UD at RIP=0x101e on
a fresh AP idle task — intermittent" — closes the underlying
shape that the 6 indirect-control-flow validators kept silent
on. Validator suite stays in place as regression armour for
unrelated wild-target dispatch shapes.

**2026-06-04 addendum — a NEW manifestation under VirtualBox, +
a sixth dispatcher-site validator.** A user VBox boot (single
CPU — note the SMP-focused trampoline fix above was verified on
SMP=8) crashed at boot-tail (~13 s, just after `x509-verify-
selftest`) with a *different* wild shape than the documented
`0x10`-in-RA: `TrapDispatch` was entered with a wild trap-frame
*pointer* (`frame = 0xffff'ffff'ffff'ffff`, canonical-but-
unmapped) and the kstack region was filled with a non-canonical
`0x001d2025…`. The fatal fault was a SECOND #PF: `RipIntegrity
Guard`'s ctor dereferences `frame->rip/cs` immediately, so the
diagnostic guard *itself* faulted on the wild pointer — burying
the original context (cr2=-1, fault-site mislabeled as the guard
ctor). **Fix (this slice, `traps.cpp`): a sixth dispatcher-site
validator `TrapFramePointerIsSane(frame)` runs BEFORE the guard
ctor** — a pure-arithmetic canonical test (a non-canonical deref
would #GP, so never deref) then a fault-surviving
`mm::SafeReadKernel` probe for present; on a wild pointer it
names the offender (`[arch/traps] WILD trap-frame pointer …`) and
halts cleanly. This does **not** fix the wild-frame *root* (still
the tracked boot-tail bug — this single-CPU/VBox shape needs a
VBox + gdb-stub repro to localise); it stops that bug from
masking itself so the next occurrence is diagnosable instead of a
nested #PF. `TrapsSelfTest` exercises the validator's fault-free
legs (non-canonical refused, live frame accepted); the unmapped-
present-reject leg rides on `SafeReadKernel`'s own contract
(`TrapsSelfTest` precedes `TrapsRegisterExtable` in boot, so it
cannot safely probe an unmapped address itself).

## 2026-05-26 — MADT Local x2APIC (type 9) entries are parsed and registered

**Decision:** `kernel/acpi/acpi.cpp::ParseMadt` accepts MADT
sub-entries of type 9 (Local x2APIC) and type 10 (Local x2APIC
NMI). The type-9 body — `{ u16 reserved, u32 apic_id, u32 flags,
u32 processor_uid }` per ACPI 6.5 §5.2.12.12 — is registered into
the same `g_lapics[]` table the legacy type-0 entries land in.
`LapicRecord::apic_id` is widened from `u8` to `u32` to hold the
wider ID. A new `LapicRecord::is_x2apic` boolean records the
source for diagnostic rendering (the AP-bringup boot-log line in
`kernel/arch/x86_64/smp.cpp` renders 8 hex digits for x2APIC IDs,
2 for legacy xAPIC). The Intel-reserved sentinel `0xFFFFFFFF` is
dropped without registering a phantom CPU. Type 10 (Local x2APIC
NMI) is accepted by the parser so the malformed-table guard
doesn't trip, but the entry is not yet cached — IOAPIC GSI is the
only NMI source DuetOS currently routes.

**Why:** firmware on any logical-CPU box that exceeds 254 cores
enumerates **all** CPUs as MADT type 9 — the type-0 entries are
absent above the 8-bit ID boundary. Without the type-9 case, a
real dual-socket Xeon SP / EPYC box would boot with only the
first 254 cores visible and the rest silently invisible to AP
bring-up. Modern Linux (`arch/x86/kernel/acpi/boot.c::
acpi_parse_x2apic`) and FreeBSD (`sys/x86/acpica/madt.c::
madt_setup_cpus_handler`) both gate on the same shape; we
mirror their accept-shape.

**Verified:** new boot self-test `AcpiMadtX2ApicSelfTest`
(`[acpi/madt-x2apic-selftest] PASS` sentinel) builds a synthetic
MADT containing one valid x2APIC entry (id=0x12345678), one
sentinel entry (id=0xFFFFFFFF, must drop), and one type-10 NMI
entry (must parse). Snapshots and restores `g_lapics` around the
call so the test is idempotent. Wired under `DUETOS_BOOT_SELFTEST`
in `kernel/core/boot_bringup.cpp` alongside the existing ACPI
selftests.

**Alternatives considered and rejected:**
- *Leave type 9 in the `default:` arm and ignore.* Today's
  behaviour. Silently loses cores on big servers; the firmware
  ID is present in the table but the kernel pretends it isn't.
  Anti-pattern: "system that exists but is never called."
- *Bump `kMaxCpus` past 32 to accept all CPUs an enterprise
  server might list.* Would cascade through `mm/slab.cpp`,
  `mm/frame_allocator.cpp` (per-CPU magazines / frame pools
  sized by `kMaxCpus`), and the 32-bit `affinity_mask` in
  `sched::Task`. Deferred as its own slice — landing MADT-9
  parsing first means a future cap-bump only has to widen the
  mask, not also teach the parser to find the entries.
- *De-duplicate type-9 entries against existing type-0 entries
  by APIC ID before inserting.* Linux does this. For DuetOS v0
  the SMP bring-up code (`SmpStartAps`) already skips its own
  LAPIC ID via `bsp_apic_id` and would naturally dedupe its
  iteration. Accept the duplication in the table; the cap
  (`kMaxCpus`) is the practical limiter and we log + drop
  rather than panic when it's hit.

**Revisit when:** an actual >32-thread target appears in the
hardware matrix (requires the `kMaxCpus` cascade above), or a
workload needs LAPIC-routed NMI delivery (would consume the
type-10 entries we currently accept-and-drop).

**Sources:** ACPI 6.5 §5.2.12.12 / §5.2.12.13; Linux
`arch/x86/kernel/acpi/boot.c`; FreeBSD `sys/x86/acpica/madt.c`.

**Related roadmap track(s):** Topology — cluster-scoped IPI
fan-out (Roadmap line 323) references x2APIC; the cluster fan-out
work itself remains gated on workload-justified profile evidence,
but the *enumeration* of x2APIC-only CPUs is now correct.

## 2026-05-26 — API-set v1 is a static curated table, not a parsed schema

**Decision:** the api-set contract → host DLL mapping lives in
`kernel/loader/apiset_static.cpp` as a sorted in-kernel table of
~70 entries (the contracts DuetOS PEs actually import). Lookup
is binary search by case-folded contract head (the trailing
`-<major>-<minor>.dll` is stripped before compare). The PE
loader's api-set fallback (`pe_loader.cpp::ResolveImports`)
consults the static table first; on miss it falls through to the
existing "first preloaded export by name" heuristic so behaviour
is monotonically better than the heuristic-only path. The boot
log distinguishes `via-apiset-table` from `via-apiset-heuristic`,
making any contract that needs to be promoted into the table
grep-able from a boot transcript.

**Why not load Microsoft's `apisetschema.dll`:** we do not load
Microsoft binaries at runtime. A v2 path that builds a v6
schema blob from a vendored JSON manifest is documented as a
follow-on (see the research report), but v1 doesn't need it —
the surface DuetOS PEs touch is small enough that a static table
is both adequate and reviewable.

**Why not parse a vendored v6 schema blob now:** YAGNI. The
in-tree PE corpus has not shown a case where one base DLL
exports the same name as another with different semantics — the
only "API-set in practice" risk the heuristic GAP names. A
parsed schema gains us (a) per-parent-module aliasing and (b)
per-SKU host swaps — neither are workloads DuetOS has today. The
v2 path is documented + the file layout is sketched in the
research notes so a future slice can pick it up cheaply.

**Verified:** new boot self-test `ApiSetSelfTest`
(`[apiset-selftest] PASS` sentinel) validates: table sort order;
known contract lookup returns the expected host; uppercase input
resolves case-insensitively; head-only contract (no version
suffix) matches; trailing `.dll` without version digits matches;
unknown contract returns `false` without scribbling `out_host`;
NULL inputs return false. Wired under `DUETOS_BOOT_SELFTEST` in
`boot_bringup.cpp:509`.

**Alternatives considered and rejected:**
- *Keep the heuristic only.* Today's behaviour. The
  `pe_loader.cpp:1609 // GAP` was the marker; the heuristic
  works in practice but bakes in a silent collision risk and
  makes the boot log carry no record of which base DLL ended
  up hosting each import.
- *Parse the v6 schema from a vendored blob.* The right v2
  answer, deferred per YAGNI above.

**Sources:** Microsoft Learn — "API set loader operation";
Geoff Chappell — Windows API Sets reference; Wine
`dlls/ntdll/loader.c::get_apiset_target`; ReactOS
`sdk/lib/apisets/apisets.c`.

**Related roadmap track(s):** Closes the `kernel/loader/pe_loader.cpp:1609 // GAP` marker. Future v2 (real schema blob)
would replace the static table with a parser; the loader-side
call site stays unchanged.

## 2026-05-26 — Page-poison v1 records SRAR PFNs but does not (yet) rmap-walk

**Decision:** the machine-check architecture (`MachineCheckReport`)
detects the SRAR class (Software Recoverable Action Required —
Intel SDM Vol 3 §16.4.2.1: S=1, AR=1, UC=1, PCC=0, ADDRV=1) on
the first matching bank and calls `mm::PoisonFrame(addr)` with
the failing physical address. `mm::PoisonFrame` records the
page-aligned PFN in a 32-entry spinlock-guarded blacklist
(`kernel/mm/poison_list.cpp`). `FreeFrame` then consults
`mm::IsFramePoisoned` before recycling — a poisoned PFN is
dropped (bitmap stays USED, frame leaked for this boot)
instead of being returned to the free pool. The 0xDE poison
stamp is skipped on known-bad frames so the 4 KiB write doesn't
fault on the failing DRAM cell.

**Why not full v1 (rmap walk + signal):** v0 has no rmap. Linux's
`memory_failure()` walks every PTE that references the poisoned
folio, converts each to a hwpoison swap entry, and SIGBUSes
every task that mapped it. DuetOS would need (a) a reverse-map
per frame and (b) a Win32+Linux signal-delivery primitive for
SRAR-class events. Both are real follow-ons. v1 minimal is "do
the structural minimum so a future reboot-persistence layer has
the failing PFN to permanently exclude" — Linux's
`take_page_off_buddy` analogue, without the in-flight kill
half.

**Why not hook AllocateFrame:** the FreeFrame drop is sufficient
to keep a poisoned PFN out of new allocations once it's been
freed once. A poisoned PFN currently free in the pool might
still be handed out until that pool slot recycles through
FreeFrame; the windows are bounded and not all boots see SRAR
at all. The allocator-side skip-loop is a follow-on, small but
not currently load-bearing.

**Critical lock-discipline note:** the IsFramePoisoned check in
FreeFrame MUST run BEFORE `PoisonFreedPage`'s 4 KiB 0xDE stamp.
Writing 4 KiB into a frame whose ECC cell already failed could
fault on the next access or — worse — corrupt adjacent memory
sharing the same ECC line. Order is documented in the FreeFrame
code; class-of-bug pattern for any future refactor moving the
check.

**Verified:** new boot self-test `PoisonFrameSelfTest`
(`[mm/poison-selftest] PASS`) round-trips insert, query,
idempotent re-insert, page-mask normalisation (byte offset
within frame matches), second distinct PFN, negative lookup,
restore-original-state. Wired under `DUETOS_BOOT_SELFTEST` in
`boot_bringup.cpp:962`.

**Alternatives considered and rejected:**
- *Halt on every SRAR (today's behaviour, no recording).* The
  GAP at machine_check.cpp:213. Failing frame is forgotten on
  reboot — the operator can't even tell which DIMM cell is
  failing. v1 minimal records, halt remains.
- *Implement the full PTE-walk recovery first.* Needs rmap +
  signal delivery + per-Win32/Linux signal routing. Multiple
  slices; gated on infrastructure DuetOS doesn't have. v1
  minimal lands the structural cap so the rest can layer on.

**Sources:** Intel SDM Vol 3 §16.4 (MCA architecture); Linux
`mm/memory-failure.c`; WHEA `PFA Performed by a PSHED Plug-In`
(Microsoft Learn); FreeBSD `sys/x86/x86/mca.c` (comparison).

**Related roadmap track(s):** Closes
`kernel/arch/x86_64/machine_check.cpp:213 // GAP` in part
(restartable-info arm now does useful work). Persistence
(`/system/badmem-list`) is the next slice once writable
system FS for secrets/config lands.

## 2026-05-27 — Block layer issues FLUSH and DISCARD on every storage backend

**What changed:** `BlockOps` grew a `discard(cookie, lba, count)`
hook alongside the existing `flush`. NVMe, AHCI, and virtio-blk
all wire both:
- **NVMe Flush (0x00)** and **NVMe DSM Deallocate (0x09, AD=1)**
  in `kernel/drivers/storage/nvme.cpp`.
- **AHCI FLUSH CACHE EXT (0xEA)** and **DSM TRIM (0x06 +
  FEATURES=0x01)** in `kernel/drivers/storage/ahci.cpp`. The
  DSM TRIM payload reuses the per-port DMA scratch's IDENTIFY
  slot (consumed once at bring-up, free thereafter); up to 64
  8-byte LBA range descriptors per command.
- **virtio-blk DISCARD (`VIRTIO_BLK_T_DISCARD`, virtio 1.2
  §5.2.5)** in `kernel/drivers/virtio/virtio_blk.cpp`. Negotiated
  via the `VIRTIO_BLK_F_DISCARD` feature bit.

FAT32 routes through both:
- `Fat32Sync(volume)` exposes `BlockDeviceFlush` through the
  FS API; `Fat32Delete*` and `Fat32Truncate*` auto-flush on
  success so destructive metadata operations cannot lose their
  commit to a power cut.
- `Fat32Trim(volume)` walks the FAT for free clusters and
  coalesces contiguous runs into `BlockDeviceDiscard` calls.
  `FreeClusterChain` discards freed cluster chains inline.

**Shell surface:** `lsblk` now reports per-device TRIM support
and the running total of discard hints issued + sectors hinted
since boot. `fstrim <volume-index>` drives the FAT32 batch trim
path manually.

**Why this matters:** the previous block-layer contract that
"absent flush op == nothing to flush == return 0" was a silent
data-loss bug on any backend with a volatile write cache — every
NVMe SSD, every AHCI SATA SSD, every QEMU virtio-blk backed by
qcow2/raw. `BlockDeviceFlush` would return success without any
data actually durable on media. Now real flushes are issued at
FAT32 commit points, so `Fat32DeleteAtPath` returning true means
the directory entry and the freed FAT entries are on
non-volatile media, not just in the controller's DRAM cache.

The discard tier is the SSD-longevity half: without it, every
file unlink leaks the previously-written LBAs into the SSD's
FTL forever. Real-world write amplification on a never-trimmed
consumer SSD hits 4–8× under sustained mixed workloads; this
collapses to 1.2–1.5× when TRIM is issued at unlink time.

**Verified:** the block-layer self-test exercises every new op
on every debug boot: discard zeros the RAM-backed test sector,
counters advance, OOB / zero-count rejects, flush succeeds on
a backend that has no flush op (deliberate no-op path) and
rejects on an invalid handle. `[block] self-test OK (RAM device
write + read + OOB reject + discard + flush)` appears on every
boot under `boot-log-analyze.sh` verdict OK.

**Alternatives considered and rejected:**
- *Build a buffer cache first, defer flush/discard.* The cache
  helps performance, not durability. Power-loss-safety is the
  bar for "actual files can be stored"; the cache is throughput
  scaffolding. Flush + discard ship first.
- *Continuous discard (Linux `-o discard`).* Issue a DSM on
  every `unlink`. We do this for now in `FreeClusterChain`
  because the cluster-chain free path is the natural point —
  it's not on a latency-critical workload. A future workload
  showing per-unlink discard cost will move us to batch-only.
- *NVMe DSM coalescing across calls.* The spec allows up to 256
  ranges per DSM command; we issue one range per call. Caller
  patterns from FAT32 are mostly run-of-clusters anyway, and the
  `FreeClusterChain` coalescer already concatenates physically
  contiguous freed clusters into one BlockDeviceDiscard call.

**Sources:** NVMe Base Spec 2.0 §5.2 (Flush), §5.5 (Dataset
Management); ACS-4 §7.10 (FLUSH CACHE EXT), §7.11 (DATA SET
MANAGEMENT); virtio 1.2 §5.2.5 / §5.2.6; Linux
`drivers/nvme/host/core.c::nvme_setup_flush/discard`,
`block/blk-lib.c::blkdev_issue_discard`; Microsoft Learn
"Storage Driver Architecture" (the storport / class / port /
miniport split that informs the future block-layer refactor —
not adopted in this slice).

**Related roadmap track(s):** Closes the "Storage and
filesystem" item that listed NVMe/AHCI flush as "wired alongside
FUA writes" — flush+discard now lead, FUA-write is a follow-on.
Unblocks any FS-write slice that needs durable commit (ext4
write, NTFS write, DuetFS Rust-side flush hook).

## 2026-05-28 — `[[nodiscard]]` Pattern-5 sweep annotates only ref/ptr-returning `Result` functions, not by-value ones

**Decision:** the idiom-audit Phase-1 Pattern-5 sweep adds
`[[nodiscard]]` only to functions whose return type is a
*glvalue* `Result` — `Result<T>&`, `const Result<T>&`,
`Result<T>*`. Functions returning `Result<T>` **by value** are
NOT annotated, because `Result` is already declared
`class [[nodiscard]]` (`kernel/util/result.h:180`) and the
type-level attribute already diagnoses every discarded prvalue.
Wave 1 (`kernel/util`) found **zero** ref/ptr-returning `Result`
functions, so the Pattern-5 sweep is a no-op for this PR.

This narrows the spec's §2 goal ("Add `[[nodiscard]]` to every
function declaration returning `Result<T, E>`") and its §6.5
mechanical rule ("Every function declaration ... gets
`[[nodiscard]]`"). The spec's §6.5 skip-rule already noted the
type is `[[nodiscard]]` but asserted function-level "matters for
many call patterns" — that is true *only* for glvalue returns,
which is the set this decision keeps.

**Verified:** GCC 16.1 / `-std=c++23 -Wall -Wextra` on a minimal
`class [[nodiscard]] Result<T>` reproduction: discarding a
by-value `Result<int> f()` call already emits
`-Wunused-result` ("ignoring returned value of type 'Result<int>',
declared with attribute 'nodiscard'", citing both the type and the
function). Adding `[[nodiscard]]` to the function changed only the
diagnostic wording, not whether it fired. Tree grep
(`Result<...>[&*]` returns under `kernel/util`) returned 0 matches.

**Alternatives considered and rejected:**
- *Annotate all 122 by-value returners anyway (spec literal).*
  Adds zero diagnostic coverage on GCC/Clang for prvalue returns
  and violates the CLAUDE.md anti-bloat rule ("write only what is
  needed today"). Rejected as redundant noise.
- *Annotate none, ever (drop Pattern 5 entirely).* Wrong for
  later waves: a function returning `const Result<T>&` (e.g. an
  accessor that hands back a cached result) is NOT caught by the
  type-level attribute, so the function-level annotation is the
  only signal there. Keeping the precise rule preserves that.

**Sources:** [dcl.attr.nodiscard] (the attribute applies to a
*type* for discarded prvalues of that type; to a *function* for
that function's discarded result regardless of value category);
GCC 16.1 `-Wunused-result` behaviour as reproduced above;
`kernel/util/result.h:180` (`class [[nodiscard]] Result`).

**Related roadmap track(s):** Refines idiom-audit Phase-1 spec
§2/§6.5 for Waves 2+ (`log`, `sync`, `mm`, `core`, then
`userland`): the Pattern-5 worklist for each wave is
"ref/ptr-returning `Result` functions", not "all `Result`
returners". No separate roadmap item; tracked in the phase-1
spec under `docs/superpowers/specs/`.

## 2026-06-05 — Zombie publish is deferred to `SchedFinishTaskSwitch` for *every* termination path

**Scope & commit:** `kernel/sched/sched.cpp` `Schedule()` budget-/policy-kill
branch — boot-tail wild-jump reaper UAF.

**Decision:** A dying task is published to the global zombie list at
**exactly one** site — `SchedFinishTaskSwitch`, which runs on the *next*
task's stack after `ContextSwitch` has committed the rsp swap — fed by the
per-CPU `ctxsw_dying_task_to_zombie` slot. The `kill_requested` branch in
`Schedule()` (budget/sandbox/fs-rate/fault-react/canary kills) no longer
pushes onto `g_zombies` inline; it marks the task `Dead`, fires
`OnTaskExited`, and stashes it into the slot, exactly as `SchedExit` does.

**Why:** Publishing a zombie while the CPU is still executing on that
task's kernel stack lets a peer-CPU reaper `FreeKernelStack` those pages
before the in-flight `ContextSwitch` finishes saving/restoring `rsp`/`rip`;
the resume then reads freed, reused memory and jumps wild (corrupt `rsp`
into kernel `.text`, null/garbage `rip`, TSC-shaped register garbage —
the SMP=4 post-x509 "boot-tail wild-jump" cascade). The 2026-05-22 SMP=8
fix closed this for `SchedExit` via the deferred slot but left the
parallel `kill_requested` branch — contractually "treat identically to
SchedExit" — on the old inline-push path. This was a
*whitelist/sentinel-divergence* class bug: two paths that must behave
identically, only one updated.

**What it rules out / defers:** No termination path may push to
`g_zombies` directly again — the inline `g_zombies = prev` form is deleted
and the single-publish-site invariant is documented in
[`Scheduler.md`](../kernel/Scheduler.md). The three resume/reaper guards
(resume-context validator, reaper reachability scan, `RunqueuePop` sanity)
stay as permanent assertions; they are the regression net, not the fix.
A future per-CPU `g_sched_lock` split must preserve "task is off every
runqueue and off every CPU's `current_task` before its stack is freed".

**Revisit when:** real KASAN lands (would have caught this UAF at the
freed-page read directly), or the per-CPU runqueue-lock split changes the
zombie-handoff locking. Re-verify on `accel=kvm`/real HW for an
untruncated dump (QEMU 8.2 TCG+SMP aborts on a true guest panic via its
own BQL re-entrancy, masking dumps — host bug, not guest).

**Related roadmap track(s):** Scheduler / SMP. This closes a genuine
latent reaper UAF on the kill path, but is **orthogonal** to — and does
**not** resolve — the Roadmap entry "SMP=4 boot-tail wild-jump cascade
(post-x509 self-test)", which reproduces a corrupt resume of a
`stack_base==nullptr` boot/idle task and remains open.

## 2026-06-05 — Boot-tail wild-jump was a boot-stack overflow, not a reaper/scheduler UAF

**Scope & commit:** `kernel/arch/x86_64/boot.S` (boot stack 128→512 KiB);
investigation also touched `kernel/sched/sched.cpp`.

**Decision:** The long-standing "SMP=4 boot-tail wild-jump cascade
(post-x509)" is attributed to and fixed as a **boot-stack overflow** — the
BSP boot task ran the deep post-x509 network self-test chain
(TLS→x509→ASN.1→RSA/EC) on the 128 KiB boot stack, demanding ~268 KiB.
Growing the boot stack to 512 KiB is the verified fix.

**Why (and what it rules out):** Multiple sessions chased this as a
reaper/scheduler use-after-free (resume of a freed `Task` with corrupt
`rsp`). That hypothesis is **retired** for this symptom: an instrumented
capture showed the wild transfer to `RIP=0` fired **none** of the four
kernel control-transfer gates (`ContextSwitch` ret-check, kernel `iretq`
RIP-check, retpoline, trampoline), each of which range-checks
`[_text_start,_text_end)` and would catch a saved `RIP=0` on a scheduler/
iretq path. No gate firing ⇒ an **ungated plain `ret` off a scribbled
stack frame**, and the corrupt `rsp=0xffffffff800dfc40` sits ~140 KiB
below `stack_bottom` — an overflow signature, not a freed-struct
signature. The overflow was invisible because the higher-half 2 MiB map
is RW (so growth past the boot sections into low RAM does not fault).

**Forward guidance for the next slice (so the wrong tree isn't re-climbed):**
a wild kernel jump whose `rsp` lands just below a known stack base, with
NO control-transfer-gate banner, is a **stack overflow**, not a UAF —
check stack depth / guard pages before instrumenting the reaper. The
kill-path reaper UAF and the resume-validator hardening landed in the same
investigation are genuine but were **orthogonal** (they did not change the
cascade).

**Revisit when:** the boot-stack guard page lands (then an overflow faults
at the boundary and this becomes self-diagnosing), or the deep self-tests
are moved off the boot task (then 512 KiB can shrink again). Re-confirm on
`accel=kvm`/real HW (the TCG host `abort()`s on its BQL assertion mid-fault,
so the `-d int` log + unbuffered serial were the capture path).

**Related roadmap track(s):** Scheduler / SMP / boot. Closes the Roadmap
entry "SMP=4 boot-tail wild-jump cascade (post-x509 self-test)".

## 2026-06-06 — exFAT adopts only DuetOS-owned volumes (serial marker), mirroring the FAT32 gate

Following the hardware-safety audit generalizing commit 7bb94062, the
exFAT probe was inverted from default-to-act to default-to-inert.

**Decision.** `ExfatProbe` registers a parsed exFAT volume **only** when
its VBR VolumeSerialNumber (offset 0x64) equals
`exfat::kDuetOsVolumeSerial` (0xCAFEBABE) — checked via the new
`ExfatVolumeIsDuetOsOwned` predicate, the exFAT analogue of
`Fat32VolumeIsDuetOsOwned`. A foreign exFAT volume (a Windows / macOS SD
card, a USB stick) is parsed and logged but **not** added to the
registry, so its root-dir write paths can never reach a partition DuetOS
does not own once exFAT is wired into the VFS.

**Alternatives ruled out (so the next slice doesn't re-pick them):**

- *Adopt any parseable exFAT volume* (the pre-fix behaviour) — this is
  exactly Vector B of the incident; a foreign exFAT volume would become
  writable the moment exFAT is exposed through the VFS.
- *Gate on the volume label instead of the serial* — exFAT carries its
  label in a root-directory entry (type 0x83), not the boot sector, so
  it isn't available at probe time without a second walk. FAT32 requires
  BOTH serial + label because the BPB gives it both cheaply; for exFAT
  the boot-sector serial alone is the pragmatic marker. A 1-in-2³²
  accidental collision is acceptable under this threat model (accidental
  corruption of the user's own data, not a hostile disk) — the same
  "not a security boundary" framing as the FAT32 marker.

**Required of every exFAT producer.** The synthetic selftest VBR
(`exfat_selftest.cpp`) now stamps the marker, and a new foreign-reject
leg asserts a non-marked volume is refused (`Fail("foreign-not-rejected")`
/ `Fail("foreign-registered")`). A future on-target exFAT formatter must
stamp `kDuetOsVolumeSerial` in the VolumeSerialNumber field.

**Related.** The full hardware-safety contract and the pre-landing
precondition table for every still-unimplemented risky controller live
in [`security/Hardware-Safety`](../security/Hardware-Safety.md).

## 2026-06-06 — RAPL is read-only telemetry, vendor + hypervisor gated

First slice of the hardware build-out following the Hardware-Safety
audit. `kernel/arch/x86_64/rapl.{h,cpp}` reads the RAPL energy/power MSRs
and decodes joules / watts / the TDP envelope.

**Decision — read-only, no limit writes.** RAPL exposes
`MSR_PKG_POWER_LIMIT`, but DuetOS deliberately does NOT write it. Raising
PL1/PL2 without adequate cooling overheats the package, so per the
hardware-safety contract RAPL is telemetry only; a future limit-*setting*
surface must sit behind a kernel capability + a cooling-aware tune mode.
This rules out "expose a powerlimit knob now" for the next slice.

**Decision — mirror thermal's gating, not a fault-safe rdmsr.** Reads are
issued only when `CpuHas(kCpuFeatMsr)` AND the vendor is Intel/AMD AND
`!IsEmulator()`. An unimplemented-MSR `rdmsr` raises a `#GP` the trap
dispatcher does not recover from; KVM/TCG do not reliably expose RAPL.
The proven thermal.cpp envelope (vendor whitelist + emulator bail) is
reused rather than introducing a `ReadMsrSafe` extable primitive this
slice. Consequence: RAPL reports "unavailable" under QEMU, so the
runtime-verifiable part is the pure-math `RaplSelfTest()` (unit decode +
µJ/ms→mW), which gates CI identically on QEMU and bare metal — the same
verification model thermal uses.

**Decision — Rust not used.** Per the project's Rust rule (standalone
greenfield subsystems only, no Rust-in-a-C++-call-chain), RAPL is
MSR/register reads tightly coupled to existing C++ arch code
(`cpu_info`, `hypervisor`, `timekeeper`), so it stays C++. Rust is
reserved for the later device-blob *parsers* in this program (EDID,
SPI SFDP, NIC EEPROM image) — the standalone-parser shape the
`exfat_rust` / `ntfs_rust` crates already use.

## 2026-06-06 — Heavy crypto boot self-tests are opt-in (`selftests=full`), default off everywhere

The asymmetric-crypto boot self-tests (`RsaSelfTest`, `X509SelfTest`,
`X509VerifySelfTest` incl. the ECDSA `EcSelfTest`, `TlsSelfTest`,
`TlsSocketSelfTest`, Argon2id `PasswordHashSelfTest`) cost ~200 s under
QEMU TCG — a single contiguous block that dominated boot time.

**Decision.** Gate them behind an explicit `selftests=full` kernel-cmdline
token (`g_expensive_selftests` + `DUETOS_BOOT_SELFTEST_CI` in
`boot_bringup.cpp`), OFF by default. They run neither on a normal
interactive boot nor under the CI `bringup` smoke gate.

**Why not tie them to the `smoke=` profile.** The first cut keyed "expensive
enabled" off any `smoke=` token, reasoning that CI wants full coverage. That
was wrong: the CI smoke job *is* the time-constrained path — running the
200 s crypto block there ate its entire timeout. The whole point is to keep
the smoke gate fast, so the trigger is a dedicated `selftests=full` that CI's
main job does not pass. A full-verification run (developer chasing a crypto
regression, or a dedicated/nightly job) opts in explicitly and budgets the
longer timeout.

**Safety of skipping.** These are pure self-tests (validate + panic on fail,
no init side effects — the `DUETOS_BOOT_SELFTEST` contract), so skipping
changes no runtime state. The smoke harness (`ctest-boot-smoke.sh`) asserts
no crypto sentinels, so nothing downstream breaks.

**Measured effect.** The `bringup` smoke (`profile-boot-smoke.sh bringup`,
the exact CI path) drops from ~520 s of guest time (timing out) to ~45 s
guest / ~59 s wall, `boot-report result=pass`.

**Ruled out for the next slice.** Do not re-enable these on the default boot
path "for coverage" — coverage belongs in the explicit `selftests=full`
lane. Further gating of other heavy tests (SMP saturation / stress) can reuse
the same `DUETOS_BOOT_SELFTEST_CI` macro if they later dominate.
