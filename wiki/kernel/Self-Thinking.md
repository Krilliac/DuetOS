# Self-Thinking and Cross-Subsystem Introspection

> **Audience:** Kernel hackers, SREs, anyone correlating live kernel state
>
> **Execution context:** Kernel — snapshot + ring reads are safe from any
> context; the `kselfthink` thread runs in task context only
>
> **Maturity:** v0 (Slices A + B landed) — snapshot + causal ring + shell,
> plus closed-loop autonomic feedback and rolling per-metric baselines.
> The operator narrative + cross-boot persistence ship in Slice C.

## Overview

DuetOS exposes a wealth of per-subsystem counters and dedicated diagnostic
primitives — [resmon](../../kernel/diag/resmon.h),
[runtime_checker](../../kernel/diag/runtime_checker.h), the
[probe ring](../../kernel/debug/probes.h),
the [autonomic engine](../../kernel/env/autonomic.h), the
[fix journal](../../kernel/diag/fix_journal.h), and the cross-boot
[introspect](../../kernel/diag/introspect.h) digest. Each one answers a
single question well. None of them assembles **"what is the whole kernel
doing right now, and what recent events led to that state"** in one place.

`selfthink` is that assembly. It owns two artefacts:

1. A **`SelfPortrait`** value-type snapshot of every subsystem surface
   the kernel can read cheaply.
2. A **`CausalChain`** lock-free ring of recent kernel events
   (probe fires, autonomic actions, anomalies, fault reactions, heals).

A `kselfthink` kernel thread wakes once per second to keep the snapshot
fresh; shell queries read it without paying the assembly cost.

## Why `selfthink` and not `introspect`?

The verb `introspect` is already taken by `duetos::diag::introspect`
([Diagnostics](Diagnostics.md)) — the cross-boot fix-journal diff that
classifies each journal record as **NEW**, **PERSISTENT**, or
**RESOLVED** relative to the prior boot. That subsystem is about
*temporal* introspection: comparing what changed between two boots.

`selfthink` is about *spatial* introspection: assembling a coherent
picture of the running system's state across every subsystem **right now**.
The two are complementary; `SelfPortrait` actually copies the
`introspect` digest counts (`new` / `persistent` / `resolved`) into its
Health section so an operator looking at the portrait sees both at once.

## SelfPortrait

`duetos::diag::selfthink::SelfPortrait` is a single value-type struct
(see [`selfthink.h`](../../kernel/diag/selfthink.h)). Every field is
sourced through an existing public stats accessor — there is **no new
kernel-internal state** owned by `selfthink`.

| Section | Fields | Source |
|---------|--------|--------|
| `resmon` (embedded) | CPU busy %, uptime, load averages, physical / heap usage, live / sleeping / blocked task counts | [`ResmonSample()`](../../kernel/diag/resmon.h) |
| Scheduler | `sched_total_ticks`, `sched_idle_ticks`, `sched_tasks_reaped` | [`SchedStatsRead()`](../../kernel/sched/sched.h) |
| Memory | `mm_frames_total`, `mm_frames_free`, `mm_frames_peak_used`, `mm_heap_alloc_count`, `mm_heap_free_count`, `mm_heap_free_chunks` | [frame_allocator.h](../../kernel/mm/frame_allocator.h), [kheap.h](../../kernel/mm/kheap.h) |
| Health | `health_scans_run`, `health_issues_total`, `health_last_scan_issues`, `health_last_issue`, `health_baseline_ok` | [`RuntimeCheckerStatusRead()`](../../kernel/diag/runtime_checker.h) |
| Fix journal | `fix_records_total`, `fix_records_unique`, `fix_records_dropped` | [`FixJournalGetStats()`](../../kernel/diag/fix_journal.h) |
| Cross-boot introspect | `introspect_new`, `introspect_persistent`, `introspect_resolved` | [`introspect::GetStats()`](../../kernel/diag/introspect.h) |
| Probes | `probe_total_fires` | [`ProbeRingTotalFires()`](../../kernel/debug/probes.h) |
| Autonomic | `auto_ticks`, `auto_actions_fired`, `auto_last_action`, `auto_last_rule` | [`AutonomicStatus()`](../../kernel/env/autonomic.h) |
| Fault domains | `fault_domains_count` | [fault_domain.h](../../kernel/security/fault_domain.h) |

`SelfPortraitSnapshot()` returns the struct by value, lock-free, in
microseconds. Safe from any context.

## CausalChain

A 1024-entry lock-free ring of 48-byte `CausalEntry` rows (48 KiB of
`.bss`). Each row holds:

```cpp
struct CausalEntry
{
    u64 tick;          // TickCount() at append time
    u32 cpu_id;        // current CPU at append time
    u16 kind;          // CausalKind enum
    u16 source_id;     // probe id / autonomic action / metric
    u64 value;         // probe value / packed delta / anomaly score
    u64 caller_rip;    // origin RIP (probe path) or 0
    char tag[16];      // null-terminated subsystem tag
};
```

`CausalKind` values:

| Kind | Meaning |
|------|---------|
| `ProbeFire` | A `debug::ProbeId` fired (armed-log path) |
| `AutoAction` | `env::AutonomicApply` ran a real effect |
| `Anomaly` | Layer 2 — metric outside its baseline window |
| `FaultReact` | `diag::FaultReactDispatch` handled a fault |
| `Heal` | `runtime_checker` Heal-class issue resolved |
| `Annotation` | Operator-injected note from the shell |

Append is single-CPU-race-tolerant (the worst case under SMP contention
is one row overwritten by another — identical contract to the
[probe ring](../../kernel/debug/probes.h)). The `total` counter is the
source of truth for "how many events"; the ring is a best-effort tail.

`CausalRingWalk` walks newest-to-oldest, invoking a callback per row.
Used by the shell command and (in later slices) the narrative writer.

## Kernel thread: `kselfthink`

Spawned once from `kernel_main` after `StartHeartbeatThread()`. The
thread wakes every 100 scheduler ticks (1 s at 100 Hz, drift-free via
`SchedSleepUntil`) and refreshes the cached portrait so shell queries
land on a pre-assembled snapshot.

Pattern matches `kheartbeat` exactly — no global tick hook list, no new
init phase.

## Closed-loop autonomic feedback (Slice B)

The autonomic engine [decides + acts](Environment.md), but until this
slice it had no way to *verify* whether each action achieved its goal.
`kernel/env/autonomic_feedback.{h,cpp}` adds the missing leg:

- `AutonomicApply` calls `CapturePreMetrics()` once per action set
  (heap %, physical %, runtime-checker issue total).
- For every action in the set it enqueues a `FeedbackEntry` with the
  pre-snapshot + `check_at_tick = now + 10` (100 ms at 100 Hz).
- `kselfthink` calls `feedback::Tick()` on every wake. Entries whose
  deadline has passed get classified:
  - **Improved** — targeted metric moved expected direction by >2 %.
  - **NoChange** — within ±2 % noise floor.
  - **Worsened** — moved against expected direction; fires
    `kAutonomicOutcomeMissed` so an attached GDB can break right at
    the regression.
  - **Diagnostic** — action class has no quantifiable single-metric
    move (`SecurityEscalate`, `SchedPerformance` / `Balanced` /
    `PowerSave`). Recorded for visibility only.
- Every classified outcome appends a `CausalKind::AutoAction` entry
  to the causal chain encoding `(outcome_code << 32) | rule_id`.

The classification table per `AutoAction`:

| Action | Watch | Direction |
|--------|-------|-----------|
| `MemReclaim` | `heap_used_pct` | should decrease |
| `FootprintTrim` | `phys_used_pct` | should decrease |
| `ForceHealthScan` | `health_issues_total` | any change visible |
| `SecurityEscalate` | — | diagnostic only |
| `SchedPerformance` / `SchedBalanced` / `SchedPowerSave` | — | diagnostic only |

## Rolling per-metric baselines (Slice B)

`kernel/diag/selfthink_baselines.{h,cpp}` adds a second leg of anomaly
detection that complements the runtime_checker's hard-coded invariants.
For each tracked metric:

- 256-sample ring of values (recent history).
- `Read(metric)` returns `count`, `last`, `mean`, `variance`, `stddev`
  computed on demand via a two-pass integer walk (no FP, no Welford
  precision drift).
- `IsAnomaly(metric, value, k = 3)` returns true when
  `|value - mean| > k * stddev`. Returns false until at least 8
  samples are populated (insufficient history to call anomaly).
- Anomalies append `CausalKind::Anomaly` entries to the causal chain
  with the metric id and offending value, so the same chain dump
  shows them alongside probe fires and autonomic actions.

The v0 metric set is intentionally small:

| MetricId | Source | Notes |
|----------|--------|-------|
| `FreeFrames` | `mm::FreeFramesCount()` | Sudden drops → leak or pressure spike |
| `HeapUsedPct` | `ResmonSnapshot::heap_used_pct` | Sudden rises → allocator churn or leak |
| `RunnableTasks` | `SchedStats::tasks_live` | Sudden rises → spawn storm |

Adding a new metric is enum + sampler-callsite-only — the ring,
classifier, and stats accessor are metric-agnostic.

## Shell command: `selfthink`

```text
selfthink                  — print the current SelfPortrait
selfthink causality [N]    — print the last N causal entries (default 32)
selfthink baselines        — per-metric rolling mean / stddev / anomalies
selfthink feedback         — autonomic action outcomes (recent + lifetime stats)
```

The portrait dump is one section per `SelfPortrait` surface, each line
short enough for `grep` to extract a single field cleanly.

Read-only; no cap gate (symmetric with `resmon`, `ps`, `free`, `dintro`,
`probe list`).

## Boot self-tests

Three tests run inside the boot self-test battery
(`DUETOS_BOOT_SELFTEST`, see [build_config.h](../../kernel/util/build_config.h)):

- **`SelfthinkSelfTest()`** — snapshot completes + arithmetic
  coherent; causal-ring round-trip; tag NUL-termination.
- **`env::feedback::SelfTest()`** — synthetic Enqueue +
  EvaluateAction classification across Improved / Worsened /
  NoChange / Diagnostic.
- **`baselines::SelfTest()`** — push 16 inliers + assert mean is
  not flagged + outlier flag holds on a clean ring + IntSqrt
  sanity.

Each emits one explicit pass-line so CI greps have positive
evidence; on FAIL fires
[`kBootSelftestFail`](../../kernel/debug/probes.h) with a sub-check id
so an attached GDB can break at the exact frame.

## Cooperation with related modules

- [Diagnostics](Diagnostics.md) — `selfthink` is a higher-level
  consumer of every primitive on that page. The portrait does not
  duplicate counter storage; it samples and copies on demand.
- The cross-boot [introspect](Diagnostics.md) digest is surfaced
  inside `SelfPortrait.introspect_*`. Both subsystems answer
  "introspection" questions but along orthogonal axes (spatial vs
  temporal); the wiki names reflect that distinction.
- [Environment / Autonomic](Environment.md) — `selfthink` reads the
  autonomic report. A future slice closes the loop: `AutonomicApply`
  will append `CausalKind::AutoAction` entries with pre/post telemetry
  so the engine can re-evaluate whether each action achieved its goal.

## Roadmap

Layered slices, each independently shippable:

- **Slice A (landed)** — Snapshot + causal ring + shell + self-test.
- **Slice B (landed)** — Closed-loop autonomic feedback (pre/post
  telemetry around each `AutoAction`, missed-outcome probe fire) +
  rolling per-metric baselines for learned anomaly detection.
- **Slice C** — Operator-facing narrative (`selfthink why` walks the
  recent chain + portrait and produces English) + cross-boot
  persistence of the causal ring (FAT32 / NVMe) so post-mortems
  survive reboots.
