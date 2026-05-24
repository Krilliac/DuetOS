# Localizing SMP AP-bringup + cross-CPU issues in DuetOS

For APs that never come online; for "AP joined the scheduler but its
runqueue is silent"; for IPI-routing failures (TLB shootdowns lost,
reschedule IPIs dropped); for per-CPU corruption ("CurrentCpu() returns
garbage from one CPU only"); for "boot passes on 1 vCPU, fails on 4".

---

## PROMPT (paste verbatim)

```text
DuetOS has an SMP issue — an AP didn't join the scheduler, an IPI
disappeared, or a per-CPU structure is corrupted on one CPU only.
Localize using the SMP methodology in tools/debug/SMP-BRINGUP-LOCALIZATION.md.

SYMPTOM:
  <paste any of: SmpStartAps banner + per-AP join lines,
   "[smp] AP N online" / "[smp] AP N joined runqueue" or missing,
   `inspect cpu` output if available,
   the per-CPU peer snapshots from a panic banner.>

==========================================================================
STEP 1 — Confirm the AP count.

  CMD: dmesg-equivalent for SmpStartAps. Expected:
    [smp] discovered N application processors from MADT
    [smp] AP 1 online
    [smp] AP 2 online
    ...
    [smp] all APs online (N+1 CPUs total)

  Each MISSING `AP X online` line is one stuck AP.

==========================================================================
STEP 2 — Classify the bringup failure.

  AP NEVER FIRES INIT-SIPI:
    BSP couldn't deliver INIT/SIPI to that AP. Causes: APIC ID outside
    the routable range, AP holding INIT signal asserted (rare on
    hypervisors), MADT mis-enumerated.
    Signature: SmpStartAps loop exits early OR with timeout-waiting-
    for-AP banner. No serial from the AP.

  AP RUNS TRAMPOLINE BUT NEVER REACHES LONG MODE:
    INIT/SIPI delivered, AP started executing trampoline.S at the
    real-mode vector, then hung in protected-mode handoff. Usually a
    GDT/IDT load or paging-enable issue.
    Signature: a partial `[smp] AP X early ...` line if the trampoline
    emits one; otherwise total silence from that AP.

  AP REACHES LONG MODE BUT DOESN'T JOIN RUNQUEUE:
    Trampoline finished its handoff, jumped to ap_main(), then never
    showed up on the scheduler. Per-CPU init order is fragile here.
    Signature: `[smp] AP X early` fires but `[smp] AP X online` doesn't.

  AP JOINS RUNQUEUE BUT NEVER RUNS TASKS:
    Online, but its runqueue is silent — no task ever scheduled.
    Cross-CPU wake (WaitQueueWakeOne firing on BSP, routing to AP)
    isn't reaching the AP. Reschedule IPI handler missing or its
    vector misrouted.
    Signature: tasks_live on the AP stays at 0 forever; BSP scheduler
    stats show task_count growing but never migrating.

==========================================================================
STEP 3 — Bisect by lowering AP count.

  Boot with `nosmp` cmdline (or `maxcpus=1`) — if the bug disappears,
  it's SMP-specific. Then try maxcpus=2 → maxcpus=4. The threshold at
  which it first fires often pinpoints the broken AP index.

==========================================================================
STEP 4 — Read the panic-time peer-CPU snapshots.

  CLAUDE.md core/panic emits `DumpPeerCpuSnapshots()` — every peer
  CPU's per-CPU snapshot buffer dumps after the panicking CPU's
  banner. If the panicking CPU is the BSP and an AP is stuck, the
  AP's snapshot tells you where it last was:

    PER-CPU SNAPSHOT (cpu=2 lapic_id=2):
      current_task=<addr> ('<name>')
      saved_rip=<addr>
      saved_rsp=<addr>

  llvm-addr2line on the saved_rip tells you which kernel function
  the AP was executing when the BSP panicked.

==========================================================================
STEP 5 — Per-CPU corruption checks.

  If only ONE CPU is misbehaving and the rest are fine:
    - The per-CPU GS-base register (IA32_KERNEL_GS_BASE) is wrong on
      that CPU only. CurrentCpu() reads %gs:offset. If GS isn't loaded
      with the per-CPU area pointer, every CurrentCpu() returns garbage.
      Check kernel/cpu/percpu.cpp: PerCpuInstall on the AP path.
    - Memory `vbox-bringup-pr266.md` notes the CurrentCpu() non-kernel
      GS-base guard (PR #284, #285) — that's the canonical fix shape.

==========================================================================
STEP 6 — IPI route checks.

  Lost reschedule IPI / TLB-shootdown IPI signature:
    - sched: tasks queued on BSP runqueue stay queued, never migrate
      to APs even though APs are idle.
    - mm: a process unmaps a page on BSP, accesses on AP read stale
      data — but this manifests later, as data corruption, not boot
      hang.

  Verify via `inspect ipi` shell command (if available) — shows the
  per-vector counter for sent + acknowledged IPIs. Sent without ack
  = lost route.

==========================================================================
STEP 7 — Fix.

  Trampoline issue: read kernel/arch/x86_64/smp_trampoline.S carefully.
    The real-mode → 32-bit → 64-bit handoff is fragile. Add serial
    output via direct port 0x3f8 writes between phases (klog not yet
    online).

  Per-CPU GS: ensure PerCpuInstall runs BEFORE any code on that AP
    calls CurrentCpu(). Most AP-init bugs are ordering issues.

  IPI routing: SmpInstallReschedIpiHandler and SmpInstallTlbShootdownIpiHandler
    must run BEFORE the first AP wakes (per main.cpp line 703-708).

==========================================================================
STEP 8 — Validate.

  Boot under multiple maxcpus settings:
    maxcpus=1: should still pass (single-CPU is the smallest config).
    maxcpus=2,4,8: should each pass.

  For an SMP-specific bug, run 20 consecutive boots on the
  highest-stress count.

==========================================================================
STEP 9 — Save memory:
  Capture: AP count threshold, the failure phase, the fix shape.
```

## Known signatures → known fixes

| Symptom | Likely class | First check |
|---|---|---|
| AP X online but tasks_live stays 0 | reschedule IPI not routed | check SmpInstallReschedIpiHandler ordering |
| CurrentCpu() returns 0 from CPU 2 | per-CPU GS not installed | percpu.cpp PerCpuInstall on AP path |
| AP hangs at trampoline → long-mode | GDT/IDT load order | smp_trampoline.S handoff sequence |
| 1 vCPU passes, 4 vCPU fails | spinlock not actually serialising | grep volatile / atomic on the contested var |
| nosmp passes, default fails | classic SMP race | bisect with maxcpus=2 |
| Random TLB-related #PF after process exit | TLB shootdown IPI lost | SmpInstallTlbShootdownIpiHandler timing |
