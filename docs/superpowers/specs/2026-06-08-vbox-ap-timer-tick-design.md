# VBox AP timer-tick delivery (PIT-fallback path) — design

**Date:** 2026-06-08
**Status:** approved, pending implementation
**Branch:** `claude/vbox-ap-timer-tick`

## Problem

On VirtualBox the LAPIC timer counts down but never raises its underflow
IRQ (a known VBox quirk). `TimerVerifyDeliveryOrFallback` detects this and
calls `StartPitPeriodicTickFallback`, which routes PIT IRQ0 through the
IOAPIC to **the BSP's APIC ID only** (`kernel/arch/x86_64/timer.cpp:347-348`).
Consequently, when each AP runs `LapicTimerStartOnCurrent`, it sees
`g_pit_fallback_active == true` and returns early **without arming its LAPIC
timer** (`timer.cpp:468-474`). The APs therefore receive **zero timer ticks**.

Two observable consequences on VBox:

1. **The system monitor shows only one core utilized.** Each AP's
   `PerCpu::sched_total_ticks` (read by `kernel/apps/sysmon.cpp` via
   `sched::SchedStatsReadCpu`) never increments, so every AP bar renders
   as a frozen `0%` / dim grey regardless of real work.
2. **APs are not preemptible.** No scheduler tick fires on an AP, so a
   task placed there runs cooperatively until it blocks.

This is the documented GAP at `timer.cpp:454-474`. It is unreachable on
QEMU / real hardware (where LAPIC-timer delivery works) and reachable on
VBox specifically.

The "only one core utilized at idle" report is, strictly, *expected* for an
idle single-threaded desktop — but on VBox it also masks this real gap,
which would suppress AP utilization (and preemption) even under load.

## Approach

IPI-broadcast a periodic tick from the BSP to every online AP, on the
PIT-fallback path only. IPIs are proven to deliver on VBox (TLB-shootdown
and resched IPIs already function there) — only the LAPIC *timer's*
self-IRQ is broken. This is option (a) named in the existing GAP comment.

Rejected alternatives:

- **Reuse the resched IPI** (`ReschedIpiHandler`): it also fires on wake
  events, so folding per-CPU tick accounting into it would over-count and
  corrupt the per-core %.
- **Per-AP TSC-deadline timer** (GAP option (b)): TSC-deadline delivers
  through the same LAPIC-timer LVT vector VBox fails to raise — almost
  certainly dead on the exact platform being fixed.

## Components

1. **`sched::OnApTimerTick()`** (`kernel/sched/sched.{h,cpp}`) — the
   per-CPU slice of `OnTimerTick`:
   - charge the current task's `ticks_run`;
   - bump the global `g_total_ticks` / `g_idle_ticks` sums (keeps the
     system-wide aggregate matching a healthy SMP boot, where every CPU's
     `OnTimerTick` already increments these);
   - bump this CPU's `PerCpu::sched_total_ticks` / `sched_idle_ticks`
     (what sysmon reads);
   - enforce the per-process tick budget (kill a runaway task);
   - `SetNeedResched()` (preemption).

   It deliberately does **not** touch `g_ticks` (wall-clock, stays
   BSP-owned at 100 Hz), the global sleep list, cyclic timers, RCU, the
   heartbeat, or the NMI watchdog — those remain BSP-only. The BSP's full
   `OnTimerTick` still runs every tick.

2. **AP-timer IPI vector + handler** (`kernel/arch/x86_64/smp.{h,cpp}`) —
   `kApTimerIpiVector` (an unused fixed vector adjacent to
   `kReschedIpiVector = 0xF8`, verified free at implementation time);
   `ApTimerIpiHandler() → sched::OnApTimerTick()`; installed via
   `SmpInstallApTimerIpiHandler()` alongside `SmpInstallReschedIpiHandler`,
   before `SmpStartAps`.

3. **`SmpBroadcastApTimerTick()`** (`kernel/arch/x86_64/smp.cpp`) — loops
   `cpu_id` over `[0, SmpCpuIdLimit())`, skips self and any
   `!PerCpu::online`, sends the fixed IPI to each. Targeted loop (not
   all-excluding-self) so a not-yet-online AP or a non-DuetOS CPU is never
   poked.

4. **Wire-in** (`TimerHandler`, `kernel/arch/x86_64/timer.cpp`) — after
   `sched::OnTimerTick(g_ticks)`:
   `if (g_pit_fallback_active && SmpCpusOnline() > 1) SmpBroadcastApTimerTick();`.
   Gated on the fallback flag so healthy hardware (APs already get their
   own LAPIC ticks) never double-ticks.

5. **GAP update** (`timer.cpp:454-474`) — the early-return still correctly
   skips arming the dead LVT, but the rationale flips from "APs get no tick
   from either source" to "APs get ticks via `SmpBroadcastApTimerTick`";
   retire the `FIX_NOTE_GAP`.

## Data flow

Healthy HW/QEMU: each AP LAPIC timer → `TimerHandler` → `OnTimerTick`
(unchanged; broadcast gate is false).

VBox fallback: BSP PIT IRQ0 → `TimerHandler` → `OnTimerTick` (BSP per-CPU
work + global timekeeping) → `SmpBroadcastApTimerTick` → fixed IPI to each
online AP → `ApTimerIpiHandler` → `OnApTimerTick` (that AP's per-CPU
accounting + resched). Net: every CPU's `sched_total_ticks` advances at
~100 Hz, `g_ticks` stays 100 Hz on the BSP.

## Testing

- **Hosted/self-test (runs everywhere, incl. CI/QEMU):** a sched self-test
  that calls `OnApTimerTick()` directly and asserts (a) the current CPU's
  `sched_total_ticks` advanced, (b) `g_total_ticks` advanced, (c)
  `need_resched` is set. Pins the per-CPU accounting logic regardless of
  platform. Emits a `[sched-aptick-selftest] PASS` sentinel.
- **Build:** clean under `x86_64-release` (WSL); existing sched/smp
  self-tests stay green.
- **Live VBox (decisive, user-run):** boot under VBox with SMP ≥ 2, open
  the system monitor, drive a multi-threaded CPU load; AP bars should now
  show non-zero utilization. Before the fix they are frozen grey. This is
  the only environment the end-to-end IPI path reproduces; it cannot be
  driven headlessly from the dev host.

## Risk / consistency notes

- Gated strictly on `g_pit_fallback_active` → zero behavior change on
  QEMU / real hardware.
- `OnApTimerTick` calls only functions already invoked concurrently from
  every CPU's `OnTimerTick` on a healthy SMP boot, so it introduces no new
  concurrency assumptions.
- Broadcast cost: `(online-1)` fixed IPIs per tick; at 100 Hz on a typical
  VBox SMP=2..4 guest this is negligible.

## Docs to update (Definition of Done)

- `timer.cpp` GAP comment (above).
- `wiki/advanced/SMP-AP-Bringup-Scope.md` or `wiki/kernel/Scheduler.md` —
  record that the PIT-fallback path now delivers AP ticks via IPI.
- `wiki/reference/Design-Decisions.md` — rules out the TSC-deadline
  alternative.
- `wiki/reference/Roadmap.md` — remove/adjust the SMP-tick-GAP item if one
  exists.
