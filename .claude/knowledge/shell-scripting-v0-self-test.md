# Shell scripting v0 — `exit N` + boot-time self-test

**Type:** Decision + Pattern + Observation
**Status:** Active — `exit N` shipped; `/etc/selftest.sh` baked into ramfs
**Last updated:** 2026-05-03

## Context

Phase 3 (commit `2988a22`) shipped scripting v0 (if/while/for/comments
/ `$?`). The scripting roadmap had `exit N` listed as item #6. Phase
3 also left scripting v0 with **zero in-tree exerciser** — the
features can rot silently between commits because nothing on the
default boot path runs a non-trivial script.

This entry covers two changes that close that gap:

1. **`exit N`** — short-circuits the enclosing script. Implemented
   as a sticky executor flag (`g_script_exit_requested` in
   `shell_script.cpp`), polled by `ExecuteRange` /
   `ExecuteWhileBlock` / `ExecuteForBlock` between statements. Reset
   on `ScriptExecute()` entry so a stale request from a prior
   `source` doesn't leak forward. Outside a script (typed at the
   prompt) `exit N` is a no-op apart from setting `$?` — the kernel
   shell IS the user surface, there is no parent to terminate.
2. **`/etc/selftest.sh`** baked into ramfs (`kEtcSelftestBytes` in
   `kernel/fs/ramfs.cpp`). Always present (doubles as reference /
   demo material — the wiki points at it for "known-good shape"),
   auto-sourced under the `DUETOS_SHELL_SELFTEST=ON` build flag.

## Why both at once

The self-test isn't useful without `exit N`. Without it, a single
`assert` failure in line 5 of a 30-line test would still run lines
6..30, producing garbled diagnostics on regression. With it, the
first failure terminates with a non-zero `$?` and the operator (or
serial-log grepper) sees `SELFTEST FAIL: <reason>` followed by
nothing more from the test.

## The mirror-to-COM1 quirk

`ConsoleEnableSerialMirror(true)` is normally first armed by
`SerialInputStart()` at `kernel/core/main.cpp:2998`, **after**
`ShellInit()` runs at line 1453. So output produced by the
`/etc/profile` chain at boot — including the SELFTEST markers —
would only land on the framebuffer, not on serial.

Headless QEMU runs see only serial. Under
`DUETOS_SHELL_SELFTEST` we therefore briefly arm the mirror around
the auto-source dispatch in `ShellInit` and disarm it after, leaving
the post-boot mirror state to `SerialInputStart` to manage. This
keeps the selftest visible to `tools/qemu/run.sh | grep SELFTEST`
without changing default-build serial behaviour.

## Procedures NOT converted

The user asked whether existing procedures could be moved to the
new scripting language. Audit result: **none.** Concrete checks:

| Procedure | Verdict | Reason |
|-----------|---------|--------|
| `/etc/profile` (`kEtcProfileBytes`) | Keep as-is | Already minimal `set` / `alias` lines; no control flow needed. |
| `CmdRepeat` | Keep as-is | Tighter than `for i in 1 2 3 ; do` — no need to enumerate values. |
| C++ kernel self-tests (`BpSelfTest`, `GuardSelfTest`, FAT32 round-trips, ...) | Keep as-is | Run during pre-shell init; cannot use shell scripting. |
| `tools/test/*.sh`, `tools/qemu/run.sh`, `tools/build/*.sh` | Keep as-is | Run on the host, not in the kernel shell. |

Conversion would have been bloat in every case.

## Verification recipe

```bash
# Default build → no SELFTEST output, no behavioural change.
cmake --preset x86_64-release
cmake --build build/x86_64-release --target duetos-iso
DUETOS_TIMEOUT=15 tools/qemu/run.sh | grep -c SELFTEST    # expects 0

# Selftest build → all 9 markers, ending with EXIT-OK.
cmake --preset x86_64-release -DDUETOS_SHELL_SELFTEST=ON
cmake --build build/x86_64-release --target duetos-iso
DUETOS_TIMEOUT=20 tools/qemu/run.sh | grep SELFTEST
# SELFTEST BEGIN
# SELFTEST IF-TRUE OK
# SELFTEST ELIF OK
# SELFTEST ELSE OK
# SELFTEST FOR alpha
# SELFTEST FOR beta
# SELFTEST FOR gamma
# SELFTEST WHILE TICK
# SELFTEST EXIT-OK
```

A `SELFTEST FAIL:` line OR absence of `SELFTEST EXIT-OK` is the
regression signal.

## Pointers

- `kernel/shell/shell_script.cpp` — `g_script_exit_requested`
  flag + `ScriptRequestExit` / `ScriptExitRequested` accessors,
  poll sites in the block walkers.
- `kernel/shell/shell_extra.cpp` — `CmdExit` handler.
- `kernel/shell/shell_dispatch.cpp` — `"exit"` registration in
  `kCommandSet[]` + the Dispatch if/else chain + the SCRIPTING
  help section.
- `kernel/fs/ramfs.cpp` — `kEtcSelftestBytes` script body +
  `k_trusted_etc_selftest` ramfs node + the
  `DUETOS_SHELL_SELFTEST` chain-source into `/etc/profile`.
- `kernel/shell/shell.cpp` — mirror-to-COM1 arm/disarm around
  the auto-source dispatch.
- `CMakeLists.txt` — `DUETOS_SHELL_SELFTEST` option (default OFF).
- `wiki/reference/Shell-Scripting.md` — "Built-in self-test"
  section + roadmap update.
