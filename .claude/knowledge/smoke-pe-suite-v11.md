# Surface-coverage PE smoke suite v11 — 91 apps, 325 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v10

## Description

The smoke PE suite expanded from 84 apps to **91 apps**. Total
guarded surface: **325 PASS** across the 91 apps (+12 from v10).

## New in v11

| App                | DLL surface       | PASS | FAIL |
|--------------------|-------------------|------|------|
| `select_smoke`     | ws2_32            | 2/1  | 1/3  |
| `proc2_smoke`      | kernel32          | 3/1  | 1/4  |
| `find_smoke`       | kernel32          | 3/0  | 0/3  |
| `iocp2_smoke`      | kernel32          | 0/1  | 1/3  |
| `signal_smoke`     | msvcrt            | 2/1  | 1/3  |
| `timer_smoke`      | user32 + kernel32 | 0/2  | 2/4  |
| `winsock_ext_smoke`| ws2_32            | 2/1  | 1/4  |

## Highlights

- `find_smoke` 3/0 PASS — `FindFirstFileW` / `FindNextFileW`
  iteration, `FindFirstFileExW`, missing-pattern probe all clean.
- `proc2_smoke` validates `GetExitCodeProcess` returns
  `STILL_ACTIVE` (259) on self.

## Cumulative tally

91 apps, 325 PASS, 91 FAIL. Pass rate: 325/(325+91) ≈ 78.1%.
