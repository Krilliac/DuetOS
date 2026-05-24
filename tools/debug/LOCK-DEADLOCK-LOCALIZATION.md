# Localizing lock-order inversions + deadlocks in DuetOS

For multiple tasks all alive but none progressing (no soft-lockup because
each task IS yielding, just on a wait queue that nobody wakes); for RCU
stalls; for "scheduler stats show 9 tasks live but serial is silent for
seconds at a time"; for the lockdep WARN class.

This is DIFFERENT from a soft-lockup hang (HANG-LOCALIZATION.md). A hang
has one task busy-spinning. A deadlock has N tasks all blocked, each
holding a lock the other needs.

---

## PROMPT (paste verbatim)

```text
DuetOS is deadlocked — multiple tasks alive per sched stats, but boot
isn't making progress and no soft-lockup line fires. Localize using the
deadlock-bisect methodology in tools/debug/LOCK-DEADLOCK-LOCALIZATION.md.

SYMPTOM:
  <paste the smoke log around the wedge point, AND if available the
   `inspect tasks` shell-command output or sched stats snapshot.
   The key piece: a list of LIVE tasks AND what each is blocked on.>

==========================================================================
STEP 1 — Confirm it's a deadlock vs a hang vs a wedge.

  Tell-tale signs of a DEADLOCK (not a hang):
  - No `[soft-lockup]` line — every task IS yielding.
  - sched_stats live count > 1, blocked count > 0.
  - The expected sentinel never fires AND no panic banner.
  - Timer ticks still emit (the timer task isn't blocked).

  Tell-tale signs of a HANG (use HANG-LOCALIZATION.md instead):
  - `[soft-lockup] task stuck` line present.
  - ticks_in_run is some number >= the threshold.

  If unsure, the diagnostic is the same — proceed.

==========================================================================
STEP 2 — Enumerate the lock-class graph.

  cd ~/source/DuetOS
  grep -rn "kLockClass\w\+\|class_id\s*=.*kLockClass" kernel/ | sort -u

  Every Mutex constructed with .class_id is tagged. Lockdep records every
  edge `held -> requested` across all classes and asserts no cycle.

  If `inspect lockdep` is available in the shell, dump the recorded graph.
  Otherwise, walk the source: list every (class_a -> class_b) pair where
  code holds class_a and acquires class_b. A cycle in that graph is
  the inversion.

==========================================================================
STEP 3 — Identify the cycle.

  Pattern to watch for:

    Task A: acquires fat32_mutex, then calls into klog → log_sink_mutex.
    Task B: acquires log_sink_mutex (e.g. in klog flush), then calls
            into fat32 → fat32_mutex.

  Both tasks block forever, neither is in a busy-spin, no soft-lockup.

  Common DuetOS cycles to watch for (from memory + general kernel
  experience):
  - fs/fat32_mutex × log/klog-persist (klog writing to FAT32 while a
    task is reading FAT32 with klog enabled).
  - sched/runqueue_lock × any caller that holds a higher-class lock
    across SchedYield / SchedSleep.
  - compositor/window_mutex × kbd-reader / mouse-reader (input feeds
    the compositor; compositor can't request input).

==========================================================================
STEP 4 — Bisect by reducing one lock's scope.

  Pick the cycle's TIGHTER lock (the one held for less time) and move
  the cycle-breaking operation OUTSIDE its scope. Example: if the
  cycle is (fat32 -> log_sink), and the log_sink call is buried inside
  fat32 code, hoist the log emission to AFTER fat32 returns.

==========================================================================
STEP 5 — Add lockdep-style guard if missing.

  If a Mutex is constructed without a class_id, lockdep can't see its
  edges. Find the constructor:

  grep -n "sched::Mutex\b.*=.*{}\|sched::Mutex\s\w\+\s*;" kernel/

  Add a class_id from kernel/sync/lockdep.h's enum. Edit lockdep.h to
  add a new class if no existing one fits. Lockdep then catches the
  inversion AT THE FIRST acquire-second-lock-while-holding-first event,
  not at the eventual hang.

==========================================================================
STEP 6 — Validate.

  - Lockdep INFO/WARN lines disappear from the boot log.
  - Smoke runs through the formerly-hung phase.
  - 20 consecutive runs all pass.

==========================================================================
STEP 7 — Document the canonical order in wiki/kernel/Lock-Order.md if
not already there. The rule (kernel convention): subsystem locks above
filesystem locks above scheduler locks above arch locks. Inversions go
across the wiki page header.

==========================================================================
STEP 8 — Save memory:
  Capture: the two classes in the cycle, which subsystem each lock
  belongs to, the fix shape (hoist out / class-id-add / order-swap).
```

## Known signatures → known fixes

| Symptom | Likely class | First check |
|---|---|---|
| All tasks blocked, no progress, klog still ticks | fat32 × klog-persist cycle | check klog-persist for FAT32 calls under its own lock |
| RCU stall warn after compositor lock change | compositor × input lock cycle | move compositor compose outside input ring drain |
| lockdep WARN `class X held when class Y acquired` | the WARN IS the answer | follow the location, swap order |
| Boot wedge during initcall, no panic | initcall holds a lock its own callback re-enters | refactor to drop-then-callback |
