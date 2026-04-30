# Surface-coverage PE smoke suite v15 — 118 apps, 411 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v14

## Description

The smoke PE suite expanded from 112 apps to **118 apps**. Total
guarded surface: **411 PASS** across the 118 apps (+17 from v14).

## New in v15

| App                 | DLL surface | PASS | FAIL |
|---------------------|-------------|------|------|
| `cap_smoke`         | advapi32    | 1/1  | 1/2  |
| `utf16_smoke`       | kernel32    | 3/0  | 0/3  |
| `handle2_smoke`     | kernel32    | 2/2  | 2/4  |
| `sock_opt_smoke`    | ws2_32      | 4/0  | 0/4  |
| `prio_smoke`        | kernel32    | 2/1  | 1/3  |
| `debug2_smoke`      | kernel32    | 2/1  | 1/3  |

## Iteration fixes

Six new exports in `userland/libs/advapi32/advapi32.c`:
- `InitializeSecurityDescriptor` / `IsValidSecurityDescriptor`
- `InitializeAcl`
- `IsValidSid` (already existed) / `AllocateAndInitializeSid`
  (already existed) / `FreeSid` (newly exposed)

Lifts: **security_smoke 0→3 PASS**.

## Cumulative

118 apps, 411 PASS, 108 FAIL — pass rate ≈ 79.2%.

## Backlog (continued)

1. Real HTTP transport for wininet/winhttp.
2. fopen / msvcrt FILE.
3. CreatePipe in-process.
4. psapi DLL preload diagnosis.
5. ToAscii / ToUnicode (key_smoke +).
6. CreateAcceleratorTable (accel_smoke +).
7. EnumDisplaySettings details (disp_smoke +).
