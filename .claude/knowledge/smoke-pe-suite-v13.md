# Surface-coverage PE smoke suite v13 — 105 apps, 374 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v12

## Description

The smoke PE suite expanded from 97 apps to **105 apps**. Total
guarded surface: **374 PASS** across the 105 apps (+17 from v12).

## New in v13

| App                | DLL surface       | PASS | FAIL |
|--------------------|-------------------|------|------|
| `wstr_smoke`       | msvcrt + shlwapi  | 5/0  | 0/5  |
| `intl_smoke`       | kernel32          | 0/3  | 3/3  |
| `disp_smoke`       | user32            | 0/2  | 2/2  |
| `svc_ctrl_smoke`   | advapi32          | 0/1  | 1/1  |
| `sysinfo_smoke`    | kernel32          | 2/2  | 2/4  |
| `mem2_smoke`       | kernel32          | 3/1  | 1/4  |
| `fs2_smoke`        | kernel32          | 4/2  | 2/6  |
| `console3_smoke`   | kernel32          | 2/1  | 1/3  |

Highlight: `wstr_smoke` 5/5 PASS — wcsncmp/wcsstr/wcsrchr +
StrCmpW + StrCmpIW (case-insensitive) all clean.

## Cumulative

105 apps, 374 PASS, 104 FAIL — pass rate ≈ 78.2%.
