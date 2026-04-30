# Surface-coverage PE smoke suite v10 — 84 apps, 313 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v9

## Description

The smoke PE suite expanded from 76 apps to **84 apps**. Total
guarded surface: **313 PASS** across the 84 apps (+19 from v9).

## New in v10

| App                | DLL surface          | PASS | FAIL |
|--------------------|----------------------|------|------|
| `stream_smoke`     | kernel32             | 0/1  | 1/3  |
| `setupapi_smoke`   | setupapi             | 2/1  | 1/3  |
| `asyn_smoke`       | kernel32             | 0/1  | 1/4  |
| `wndmsg_smoke`     | user32               | 6/0  | 0/6  |
| `scrap_smoke`      | user32               | 5/0  | 0/5  |
| `trace_smoke`      | advapi32             | 3/0  | 0/3  |
| `wmi_smoke`        | ole32                | 2/0  | 0/2  |
| `enviro_smoke`     | kernel32             | 1/1  | 1/2  |

Highlights: **wndmsg + scrap + trace + wmi all clean PASS** —
the NULL-window probes, caret blink, AnyPopup, ETW Register/
Write/Unregister, COM init security all work out of the box.

## Cumulative tally

84 apps, 313 PASS, 84 FAIL — `PASS rate` is 313/(313+84) ≈ 78.8%.

## v10 backlog

1. CreateIoCompletionPort + GetQueuedCompletionStatus —
   stream_smoke 0→3.
2. CreateWaitableTimerW + SetWaitableTimer — asyn_smoke 0→4.
3. SetupDiGetClassDevsW — setupapi 2→5.
4. Real fopen / msvcrt FILE — stdio_smoke 0→7.
5. registry HKLM — registry_smoke 0→6, profile_smoke 0→3.
6. Real HTTP transport for wininet/winhttp.
7. psapi DLL preload diagnosis.
