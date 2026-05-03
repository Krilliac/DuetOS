# Purple team — coverage scorecard v0

**Type:** Decision + Pattern
**Status:** Active
**Last updated:** 2026-05-03

## What it is

A measurement layer that wraps `AttackSimRun` and answers three
questions for every red-team attack:

1. **Was it detected?**  (yes/no — did at least one detector fire?)
2. **How fast?**  (ns from attack start to detector trip)
3. **Was the right detector the one that fired?**  (or did some
   unrelated wall trip first because the test perturbed unrelated state?)

Today, `attack_sim.cpp` runs an attack and prints a one-line
"Caught by: <detector>" string if HealthIssue counters changed.
That's a binary signal with no timing and no false-positive
filter. Purple team adds:

- Pre/post snapshot of `EventRingStats.published_total` and per-
  EventKind counters via `EventRingForEachKind`.
- Wall-clock timing brackets around each attack via the existing
  `time::UptimeNs()`.
- Expected-EventKind table: each `AttackKind` declares "if I work
  correctly and detection is intact, EventKind X must fire".
- Score = (kind_match × detected) — a 2-axis classifier:
  - **detected & correct kind** → ✅ "in coverage"
  - **detected & wrong kind**   → ⚠️ "noisy detection"
  - **not detected**            → ❌ "blind spot"

## API shape

```cpp
namespace duetos::security {

struct AttackExpectation
{
    AttackKind  attack;          // existing enum from attack_sim.h
    EventKind   expected_event;  // what should fire if detection works
};

struct AttackOutcome
{
    AttackKind   attack;
    EventKind    expected;
    EventKind    actual_first;     // first event published in window;
                                   //   = None if nothing fired
    u64          detected_at_ns;   // 0 if not detected
    u64          attack_start_ns;
    u64          attack_end_ns;
    u32          events_in_window; // total events published during the run
    bool         detected;
    bool         correct_kind;
};

struct ScorecardSummary
{
    u32 attacks_run;
    u32 detected;
    u32 detected_correct_kind;
    u32 detected_wrong_kind;
    u32 not_detected;
    u64 total_attack_window_ns;
    u64 total_detection_latency_ns;  // sum across detected attacks
    u32 max_detection_latency_ns;    // ←- 32-bit ns is plenty (~4 s ceiling)
};

ScorecardSummary PurpleTeamRunAll();   // runs every registered attack
                                       //   under the v0 expectation table
core::Result<AttackOutcome, core::ErrorCode>
        PurpleTeamRunOne(AttackKind kind);

// Pretty-print to serial: one row per attack + summary footer.
void PurpleTeamReport(const ScorecardSummary& s);

void PurpleTeamSelfTest();   // boot-time: walks expectation table,
                             //   asserts every AttackKind has a row OR
                             //   is explicitly opted-out

} // namespace duetos::security
```

## Expectation table (initial)

| AttackKind | Expected EventKind |
|---|---|
| BootkitBootSector       | BootSectorModified       |
| KernelTextPatch         | KernelTextModified       |
| IdtHookEntry            | IdtModified              |
| GdtCorruption           | GdtModified              |
| LstarHijack             | SyscallMsrHijacked       |
| SysenterCsHijack        | SyscallMsrHijacked       |
| SysenterEipHijack       | SyscallMsrHijacked       |
| Cr0WpClear              | Cr0WpCleared             |
| Cr4SmepClear            | Cr4SmepCleared           |
| Cr4SmapClear            | Cr4SmapCleared           |
| EferNxeClear            | EferNxeCleared           |
| FsRateBurst             | FsWriteRateBurst         |
| FsRateLowSlow           | FsWriteRateSustained     |
| CanaryFileTouch         | CanaryTouch              |
| PersistenceDropAdvisory | PersistenceDrop          |
| StackCanaryDefang       | StackCanaryZero          |

## Sampling the event ring

For each attack:

```
snapshot = EventRingStatsRead();
attack_start = time::UptimeNs();
RunOneAttack(kind);                 // existing attack_sim entrypoint
attack_end = time::UptimeNs();

// Walk events with seq > snapshot.published_total. The first one
// whose uptime_ns >= attack_start is the detection event;
// its EventKind is `actual_first`.
```

The lookup uses `EventRingForEach` and short-circuits on the first
match. A 256-entry ring is plenty: a single attack publishes at
most 1-2 events, and we run them serially.

## Why this is its own subsystem (not just a flag in attack_sim)

- attack_sim is **red-team code** — a known-permitted operator
  privilege escalation tool. It's allowed to mutate kernel state
  to test detectors. Mixing measurement into it would make
  attack_sim's job (perturb state) and purple's job (measure
  detector response) interfere.
- The expectation table is a **contract**: "if you add a new
  detector, you must add a row" — same shape as the IR runbook
  self-test. Centralizing it means a fresh detector cannot ship
  without an expected-event registration.

## Future extensions

- **CI gate**: PurpleTeamRunAll exit code → 0 if every attack is
  detected with correct kind, non-zero otherwise. Gate PRs on it
  once `qemu-smoke` can capture serial output reliably.
- **Latency histograms**: instead of just max-latency, bucket into
  <1µs / <10µs / <100µs / <1ms / <10ms / >10ms.
- **Negative tests**: run a benign workload, assert ZERO detector
  trips → false-positive coverage.
