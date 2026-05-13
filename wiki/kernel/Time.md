# Kernel Timekeeping

> **Audience:** Kernel hackers, driver authors
>
> **Execution context:** Kernel — IRQ-safe reads, task-context writes
>
> **Maturity:** v0 — HPET monotonic + CMOS wall-clock; TSC opportunistic;
> timezone editor active

## Overview

Time on DuetOS is layered exactly once. Every caller — scheduler tick, log
timestamper, file mtime, `KEvent` timed wait — funnels through one of three
APIs ([`kernel/time/`](../../kernel/time/)):

```
Wall clock + monotonic + tick count
                |
        kernel/time/timekeeper.{h,cpp}   <-- high-level read APIs
                |
        kernel/time/clocksource.{h,cpp}  <-- pluggable monotonic backend
                |
        HPET (primary) | TSC (calibrated) | PIT (fallback)
```

The clocksource layer abstracts the underlying hardware so the rest of the
kernel never sees an HPET MMIO register or a `rdtsc`. The tick subsystem
([`tick.h`](../../kernel/time/tick.h)) is a separate counter advanced by
the timer IRQ — it is the scheduler's heartbeat, not a precise time.

## Why three layers

| Layer | What it answers | Granularity | Source |
|-------|-----------------|-------------|--------|
| `tick.h` — `TickCount()` | "how many scheduler ticks since boot" | scheduler tick (default 1 ms) | timer IRQ tail |
| `clocksource.h` — `Clocksource::Read()` | "monotonic counter, fixed cadence" | ~10 ns (HPET) / ~0.3 ns (TSC) | HPET MMIO / `rdtsc` |
| `timekeeper.h` — `MonotonicNs()` etc. | "nanoseconds since boot / since epoch" | derived from clocksource | snapshot of above |

The clocksource API is what lets us swap HPET for TSC opportunistically once
the calibration phase decides TSC is invariant on this CPU.

## Clocksource Selection

[`clocksource.h`](../../kernel/time/clocksource.h) ranks available sources at
boot and picks the best:

1. **HPET** — primary. Required for SMP determinism; one global counter that
   every CPU sees identically.
2. **TSC** — calibrated against HPET at boot. Promoted to primary only when
   CPUID reports invariant TSC (`CPUID.80000007:EDX[8]`) and the calibration
   delta is within tolerance. See
   [`timekeeper::TscCalibrated()`](../../kernel/time/timekeeper.h).
3. **PIT** — failure-mode fallback. If neither HPET nor TSC is usable the
   boot panics rather than running on PIT silently (a 1 ms tick is too
   coarse for everything).

`ClocksourceRefreshCurrent()` re-reads the source and is what the timekeeper
samples on every call. `ClocksourceSelfTest()` is wired into the boot
self-test and asserts: source registered, read monotonic across N samples,
no overflow on calibration period.

## Timekeeper API

The [`timekeeper.h`](../../kernel/time/timekeeper.h) header is the surface
every caller should touch:

```cpp
u64 ns = timekeeper::MonotonicNs();        // nanoseconds since boot
u64 ns = timekeeper::BoottimeNs();         // counts CLOCK_BOOTTIME-style
u64 ft = timekeeper::RealtimeFiletime();   // Windows FILETIME (1601 epoch)
BrokenDown t = timekeeper::RealtimeBrokenDown();
u64 tsc = timekeeper::ReadTsc();           // raw rdtsc (use TscToNanos to convert)
u64 ns = timekeeper::TscToNanos(tsc);
bool ok = timekeeper::TscCalibrated();     // was TSC promoted?
```

- `MonotonicNs` never goes backward. It is what the scheduler bills off,
  what `KEvent` deadlines are computed against, and what every "duration"
  log line measures.
- `RealtimeFiletime` is the format the Win32 ABI expects; the timekeeper
  derives it from `MonotonicNs() + boot_realtime_filetime`, where the boot
  realtime baseline is read once from CMOS RTC.
- `RealtimeBrokenDown` is the same realtime in Y/M/D/H/M/S form for the UI
  (clock app, file modtime display).

## Wall Clock Baseline

The CMOS RTC ([`arch::Rtc*`](../../kernel/arch/x86_64/rtc.cpp)) is read **once**
at boot. From then on:

- Monotonic is the truth; wall-clock = monotonic + baseline.
- A user changing the system time via the settings app writes a new baseline,
  not a new monotonic.
- Timezone is a presentation-layer adjustment ([`timezone.h`](../../kernel/time/timezone.h)),
  not a stored-time adjustment. Internally everything is UTC.

This is the same model as Linux's `CLOCK_REALTIME` vs `CLOCK_MONOTONIC` —
deliberate, so PE binaries that probe `GetSystemTimeAsFileTime` get sane
values across suspend/resume even before suspend/resume actually lands.

## Timezone

[`timezone.h`](../../kernel/time/timezone.h) keeps a signed UTC offset in
minutes plus a DST step toggle. It is editable via the settings app
([`kernel/apps/settings_datetime.cpp`](../../kernel/apps/settings_datetime.cpp))
and via the shell command `time set tz <offset>`. The kernel logs and
RTC writes always use UTC; only the user-facing clock app applies the
offset.

`TimezoneSelfTest()` is wired into the boot self-test and validates a few
known cities round-trip (UTC ↔ EST ↔ JST). A failure here usually means a
broken DST step calculation.

## Tick Subsystem

[`tick.h`](../../kernel/time/tick.h) is a single `u64` counter advanced by
the timer IRQ. It is intentionally separate from the clocksource layer —
the scheduler decides what cadence it wants (default 1 ms on QEMU, can
move to 100 Hz on slow hardware), and the tick counter is whatever the
scheduler chose.

Use `TickCount()` for:
- Scheduler internals (slice expiry, runqueue rotation)
- Soft-lockup detector (100 ticks ≈ 1 s on default cadence — see
  [Diagnostics](Diagnostics.md))
- Coarse-grained `sleep(ms)` where the caller already knows the cadence

Do **not** use `TickCount()` for:
- Wall-clock display
- Anything that needs sub-millisecond precision
- Anything where the cadence might change between boots

`TickSelfTest()` validates monotonicity and IRQ-rate sanity (tick rate
within 10% of programmed HPET cadence).

## Threading and Locking

- All read APIs are IRQ-safe. They read a seqlock-protected snapshot and
  retry if a writer (rare — boot baseline write, timezone change) was in
  flight.
- The clocksource backend's read is hardware-defined: HPET is an aligned
  MMIO load; `rdtsc` is one instruction. No locks on the fast path.
- `Tick` is a single `u64` advanced by the timer IRQ on the boot CPU. SMP
  AP CPUs read it too; the IRQ owner is always the BSP in v0.

## Known Limits / GAPs

- **No CLOCK_REALTIME drift correction.** The CMOS baseline is read once
  at boot and not adjusted for clock skew. Acceptable for v0 (no NTP yet);
  revisit when networking gets a time client.
- **No suspend/resume time arithmetic.** When suspend/resume lands the
  timekeeper will need to re-baseline monotonic against the wall clock
  on resume so monotonic doesn't appear to leap forward.
- **Per-CPU TSC offsets** are not yet read from MSR_TSC_ADJUST. SMP TSC
  reads are HPET-routed until that calibration slice lands.
- **TSC promotion is opportunistic.** The default boot uses HPET; TSC
  takes over only when the CPUID + calibration gate passes. The HPET
  path stays as a long-term safety net.

## Related Pages

- [Boot Path](Boot.md) — when timekeeping comes online
- [Scheduler](Scheduler.md) — consumer of `TickCount()`
- [Diagnostics](Diagnostics.md) — soft-lockup and heartbeat both
  consume `MonotonicNs()`
- [Logging and Tracing](Logging-And-Tracing.md) — log timestamps
- [Syscalls](Syscalls.md) — `SYS_TIME_*` family wraps `timekeeper::*`
