# Runtime invariant checker v0

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — live, runs every heartbeat + on shell
`health` command. Covers heap, frames, scheduler, control
registers, both stack-canary kinds.

## Why this exists

Normal panic / trap handling catches problems the CPU or the
code itself actively trips on. Plenty of kernel corruption is
silent — it breaks an invariant that a LATER piece of code
will eventually notice, often on the wrong thread, far from
the buggy writer. By the time the downstream consumer panics,
the crash site has zero signal about what caused it.

This checker runs a fixed O(1) battery of invariant tests on
every heartbeat (~5 s) and on shell `health` request. Each
failing test logs a Warn-level klog line with a specific
issue tag — so the boot log pinpoints the class of
corruption immediately, instead of showing a downstream
panic.

## Invariants covered

| Test                         | What it detects                                     |
| ---------------------------- | --------------------------------------------------- |
| `HeapPoolMismatch`            | used + free > pool (bookkeeping drift)             |
| `HeapUnderflow`               | free_count > alloc_count (double-free / overflow)  |
| `HeapFreelistEmpty`           | free list empty but pool not fully used            |
| `HeapFragmentationHigh`       | > 256 free chunks (splinter bug)                   |
| `FramesOverflow`              | free > total in bitmap                             |
| `FramesAllAllocated`          | all frames used (leak or real pressure)            |
| `SchedExitedMoreThanCreated`  | scheduler counter drift                            |
| `SchedReapedMoreThanExited`   | reaper counter drift                               |
| `SchedLiveUnreasonable`       | tasks_live > 256 (leak / fork bomb)                |
| `SchedNoContextSwitches`      | timer not firing after grace period                 |
| `Cr0WpCleared`                | write-protect bit dropped silently                 |
| `Cr4SmepCleared`              | SMEP bit dropped silently                          |
| `Cr4SmapCleared`              | SMAP bit dropped silently                          |
| `EferNxeCleared`              | NXE bit dropped silently                           |
| `StackCanaryZero`             | `__stack_chk_guard` flipped to 0                   |
| `TaskStackOverflow`           | any task's bottom-of-stack sentinel scribbled      |

## Kernel-stack overflow detection

Every task's kernel stack has two sentinels:

1. The classic `__stack_chk_guard`-based per-function prologue/
   epilogue cookie (compiler-emitted `-fstack-protector-strong`).
   Detects overflow that reaches past locals into saved regs.

2. An 8-byte `0xC0DEB0B0CAFED00D` canary planted at stack_base[0..7]
   at `SchedCreate` time. Detects deep overflow that scribbles
   anywhere in the bottom page of a 16 KiB kernel stack.

Sentinel #1 tripping produces an IMMEDIATE panic. Sentinel #2
was previously only checked by the reaper at task-exit — so
any task that overflowed but didn't yet die would corrupt the
heap (the task struct + stack live in the kernel heap)
silently. This checker now walks the runqueue + sleep queue +
zombie list every heartbeat and verifies every task's
sentinel #2. Overflow detected within 5 s instead of
"eventually maybe never".

## Control-register drift detection

Baseline captured in `RuntimeCheckerInit` right after
`ProtectKernelImage` runs — when W^X + SMEP + SMAP + NXE are
all online. Every scan re-reads CR0 / CR4 / EFER and flags any
baseline-set bit that's now cleared.

This is the ONLY way to detect silent security-feature
drops — the CPU doesn't panic when these clear, it just stops
enforcing. A bug that executes `mov cr4, r8` with the wrong
value (e.g. zero-extending a smaller register) would silently
disable protection. The checker catches it on the next scan.

## Wiring

```
main.cpp:
  ProtectKernelImage()
  RuntimeCheckerInit()        ← captures control-register baseline

heartbeat.cpp:
  RuntimeCheckerTick()        ← every ~5 s
  LogWithValue health_last_scan_issues
  LogWithValue health_issues_total

shell.cpp:
  "health" / "checkup" cmd    ← on-demand scan + per-issue breakdown
```

## Public API

```cpp
namespace customos::core {

enum class HealthIssue : u32 { None, HeapPoolMismatch, ... };
const char* HealthIssueName(HealthIssue);

struct HealthReport {
    u64 scans_run;
    u64 issues_found_total;
    u64 last_scan_issues;
    u64 per_issue_count[16];
    HealthIssue last_issue;
    u64 baseline_captured;
};

void RuntimeCheckerInit();
u64  RuntimeCheckerScan();           // returns # of NEW issues this scan
void RuntimeCheckerTick();           // fire-and-forget variant
const HealthReport& RuntimeCheckerStatusRead();  // by reference (no memcpy)

} // namespace
```

## Design notes

- The 128-byte `per_issue_count` array makes return-by-value
  require `memcpy`. The kernel doesn't have it. Accessor
  returns `const HealthReport&`.
- Each check is branch-independent: one scan tests every
  invariant, so a single report covers everything.
- Scan is microseconds — the heap stats accessor is O(freelist),
  the sched canary walk is O(runqueue + sleep + zombies).
  Tolerable every 5 s.
- Reports LOG at Warn level but do NOT panic. A follow-on slice
  can add escalation (e.g. panic on 2nd consecutive CR-drift
  since those are catastrophic).

## Follow-ups

1. **Guard subsystem escalation** — the security guard currently
   only gates image loads. Tie it to the runtime checker so
   any `HealthIssue::Cr*Cleared` finding flips the guard into
   safe mode + denies every subsequent image load until
   operator intervention.

2. **Per-CPU invariant check** — when SMP is online, each CPU
   has its own GDT/TSS/per-CPU struct; the BSP scan should
   IPI-fan-out a per-CPU scan.

3. **IDT integrity check** — hash the IDT at `RuntimeCheckerInit`
   and compare against the baseline each scan. A rootkit-style
   handler swap would otherwise be invisible.

4. **Kernel-image text hash** — same idea for `.text`. Full
   SHA-256 is too slow; a per-page CRC32 at boot + periodic
   spot-check of N random pages would catch text corruption
   with bounded latency.
