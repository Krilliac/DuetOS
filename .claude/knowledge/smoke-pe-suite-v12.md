# Surface-coverage PE smoke suite v12 — 97 apps, 357 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v11

## Description

The smoke PE suite expanded from 91 apps to **97 apps**. Total
guarded surface: **357 PASS** across the 97 apps (+32 from v11).

## New in v12

| App                | DLL surface       | PASS | FAIL |
|--------------------|-------------------|------|------|
| `key_smoke`        | user32            | 4/0  | 0/4  |
| `reg2_smoke`       | advapi32          | 0/3  | 3/3  |
| `paths2_smoke`     | shlwapi           | 4/1  | 1/5  |
| `advapi_smoke`     | advapi32          | 2/1  | 1/3  |
| `heap3_smoke`      | msvcrt            | 3/1  | 1/4  |
| `thread3_smoke`    | kernel32          | 2/3  | 3/5  |

## Iteration fixes — big PASS lift

Added 13 new exports + impls in `userland/libs/kernel32/kernel32.c`:

- **CreateIoCompletionPort + Post + Get** — 32-slot ring per
  port (4 ports max). Lifts iocp2_smoke 0→3 PASS, stream_smoke 0→3.
- **CreateTimerQueue / DeleteTimerQueue** — sentinel handles.
  Lifts timer_smoke 0→2 PASS.
- **CreateWaitableTimerW + SetWaitableTimer + CancelWaitableTimer**
  — backed by SYS_HANDLE_CREATE_EVENT (initially signaled).
  Lifts asyn_smoke 0→4 PASS.
- **WTSGetActiveConsoleSessionId + ProcessIdToSessionId** — return
  session 1. Lifts wts_smoke 1→2 PASS.
- **GetSystemPowerStatus + SetThreadExecutionState +
  IsSystemResumeAutomatic** — return canned "AC plugged".
  Lifts power_smoke 1→3 PASS.

## Cumulative tally

97 apps, 357 PASS, 93 FAIL — pass rate ≈ 79.3%.
