# Localizing boot-time / runtime performance regressions in DuetOS

For "boot got 2× slower"; for smoke profiles timing out at the wall
budget (480s) when they previously completed in 8s; for `[t=Xms]`
timestamps drifting upward across commits; for `ctx_switches=` count
ballooning; for "release builds suddenly take longer than debug".

NOT for hangs (use HANG-LOCALIZATION.md) — perf regressions complete,
they just take too long.

---

## PROMPT (paste verbatim)

```text
DuetOS boot or scenario is slower than it used to be. Localize using
the perf-bisect methodology in tools/debug/PERF-REGRESSION-LOCALIZATION.md.

SYMPTOM:
  CURRENT TIME: <e.g. bringup-complete at t=18000ms, was t=8000ms a week ago>
  WAS-PASSING SHA: <e.g. fbce9e3 from main, last green CI smoke>
  CURRENT SHA: <e.g. 0e017192 from PR #336>

==========================================================================
STEP 1 — Capture timings from both SHAs.

  # Old:
  git worktree add /tmp/duetos-old <was-passing-sha>
  cd /tmp/duetos-old
  cmake --preset x86_64-debug && bash tools/test/wsl-bringup-smoke.sh bringup
  # Note the timestamp on the [bringup-tail] post-metrics line.

  # New:
  cd ~/source/DuetOS
  bash tools/test/wsl-bringup-smoke.sh bringup
  # Note the same timestamp.

  Compute the delta. Find which PHASES of boot consumed the extra time:

  awk '/\[bringup-tail\]/ || /\[t=/{ts=$1; sub(/\[t=/,"",ts); sub(/ms\].*/,"",ts); print ts, $0}' \
    /mnt/c/Users/natew/AppData/Local/Temp/bringup-pass.log

  Diff the two outputs side-by-side. The phases where the OLD and NEW
  timestamps diverge are where the regression landed.

==========================================================================
STEP 2 — Identify the slow phase.

  CLASS-OF-BUG shortcuts:

  SELF-TEST EXPLOSION:
    A new initcall self-test takes several seconds. Self-tests run in
    serial — see kernel/core/boot_bringup.cpp's
    DUETOS_BOOT_SELFTEST(...) chain. A 5-second self-test in 13 phases
    adds up.
    Recently added self-tests (post-fbce9e3):
      diag/selfthink::SelfthinkSelfTest
      env/feedback::SelfTest
      diag/selfthink::baselines::SelfTest
      diag/selfthink::persist::SelfTest
      diag/selfthink::narrative::SelfTest

  FAT32 STORM:
    klog-persist's per-area rotation does many lookups (TEST.0..3,
    KERNEL.F0..3, etc.). Each FAT32 lookup is ~5ms on KVM. 50 lookups
    = 250ms. If a new subsystem adds another <BASE>.LOG, that's
    +50ms minimum.

  BUSY-SPIN TIMEOUT:
    A new poll loop ran the full kPollSpinLimit before giving up. Each
    bounded spin is ~1s (matches HANG-LOCALIZATION.md ticks_in_run=101
    shape, except this time the spin RETURNED — so it shows up as
    "this phase took 1s" instead of an outright hang).

  KASLR RE-ROLL:
    KASLR base randomization can land on a slow cache-miss layout for
    a hot table. Try kaslr=off boot cmdline — if the regression
    disappears, it's KASLR layout sensitivity, not real perf.

  LTO TUNING:
    DUETOS_LTO=ON for release builds. A new LTO pass cost can make
    one TU's link-time explode. Look at `[<build/x86_64-release/...]
    Linking CXX executable` wall-time.

==========================================================================
STEP 3 — Bisect.

  If the bad-window is many commits wide, use git bisect with smoke
  as the test:

  git bisect start <bad-sha> <good-sha>
  git bisect run sh -c '
    bash tools/build/wsl-kernel-build-debug.sh && \
    out=$(bash tools/test/wsl-bringup-smoke.sh bringup 2>&1) && \
    ts=$(echo "$out" | grep -oP "t=\K[\d.]+(?=ms.*post-metrics)" | head -1) && \
    [ -n "$ts" ] && python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 12000 else 1)" "$ts"
  '

  Adjust the 12000ms threshold to your bad/good split.

==========================================================================
STEP 4 — Instrument the slow phase with phase timestamps.

  Add KLOG_METRICS at the bracket points to make the delta visible:

    KLOG_METRICS("perf", "phase-X start");
    ... slow code ...
    KLOG_METRICS("perf", "phase-X end");

  KLOG_METRICS emits unconditionally + includes timestamp. The delta
  between adjacent METRICS lines is the phase's wall budget.

==========================================================================
STEP 5 — Fix patterns.

  - Move self-test off the boot path (defer to first shell command,
    or gate behind DUETOS_BOOT_SELFTESTS_LATE flag).
  - Coalesce per-area FAT32 lookups into one directory scan.
  - Shorten kPollSpinLimit for non-essential devices, or add a
    HasFastFail() fast-bail when the hypervisor reports "device not
    present" in CPUID.
  - For LTO regressions: split the TU that LTO is struggling with.

==========================================================================
STEP 6 — Validate.

  Time 5 boots of each preset. Mean should be within 5% of pre-
  regression timing. Variance should be similar (LTO regressions
  often inflate variance even when mean stays close).

==========================================================================
STEP 7 — Save memory:
  Capture: the phase that regressed, the commit that introduced it,
  the fix shape, the delta before-and-after. Future perf bisects
  shortcut to the same shape.
```

## Known signatures → known fixes

| Symptom | Likely class | First check |
|---|---|---|
| Boot 2× longer than a week ago | self-test explosion | grep "DUETOS_BOOT_SELFTEST" diff against was-passing |
| Sudden 1s gap in [t=Xms] timestamps mid-boot | busy-spin returned-false | grep for new kPollSpinLimit-shape loops in recent commits |
| Variance up but mean unchanged | KASLR layout-sensitive | try kaslr=off cmdline |
| Release build slower than debug | LTO pass exploded on a TU | check link-time of build/x86_64-release/CMakeFiles/duetos-kernel.dir/<your-recent-tu>.cpp.obj |
| FAT32 phase doubled | new <BASE>.LOG channel | see klog_persist.cpp area enum, check rotation overhead |
