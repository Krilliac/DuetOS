# Surface-coverage PE smoke suite v14 — 112 apps, 394 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v13

## New in v14

| App                | DLL surface       | PASS | FAIL |
|--------------------|-------------------|------|------|
| `xml_smoke`        | ole32             | 2/0  | 0/2  |
| `reg3_smoke`       | advapi32          | 3/1  | 1/4  |
| `proc3_smoke`      | kernel32          | 2/1  | 1/3  |
| `com2_smoke`       | ole32             | 1/1  | 1/2  |
| `advmem_smoke`     | kernel32          | 6/0  | 0/6  |
| `wstr2_smoke`      | msvcrt            | 0/2  | 2/4  |
| `fs3_smoke`        | shlwapi           | 1/1  | 1/2  |

## Iteration fixes

Six new exports in `userland/libs/kernel32/kernel32.c`:
- `GetUserGeoID` / `GetSystemGeoID` — return 244 (USA).
- `GetGeoInfoW` — canned ISO2 "US" / ISO3 "USA" / friendly "United States".
- `GetCalendarInfoEx` / `GetCalendarInfoA` — return "Gregorian"
  for `CAL_SCALNAME`.
- `GetDpiForSystem` — return 96 (default 100% scale).

Lifts: **intl_smoke 0→3 PASS**, locale2_smoke +1, disp_smoke +1.

## Cumulative

112 apps, 394 PASS, 106 FAIL — pass rate ≈ 78.8%.
