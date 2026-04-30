# Surface-coverage PE smoke suite v9 — 76 apps, 294 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v8

## Description

The smoke PE suite expanded from 68 apps to **76 apps**. Total
guarded surface: **294 PASS** across the 76 apps (+10 from v8).

## New in v9

| App                | DLL surface          | PASS | FAIL |
|--------------------|----------------------|------|------|
| `vol_smoke`        | kernel32             | 2/3  | 3/5  |
| `drive_smoke`      | kernel32             | 2/1  | 1/3  |
| `conio_smoke`      | msvcrt               | 2/1  | 1/3  |
| `mbcs_smoke`       | msvcrt               | 1/2  | 2/3  |
| `fpcontrol_smoke`  | msvcrt               | 2/0  | 0/2  |
| `locale2_smoke`    | kernel32             | 0/4  | 4/4  |
| `gdiplus_smoke`    | gdiplus              | 1/0  | 0/2  |
| `dde_smoke`        | user32               | 1/2  | 2/3  |

## v9 backlog (ongoing — keep going until exhausted)

1. **psapi DLL preload diagnosis** — fix the kernel-side
   thunk override so the userland psapi.c impls (already
   real) actually serve the calls.
2. **Real fopen / FILE — stdio_smoke 0→7**.
3. **registry HKLM RegOpenKeyExW** — wire prefix-tree.
4. **Real HTTP transport** through wininet/winhttp.
5. **CreatePipe in-process** — pipe_smoke 1→4.
6. **InitializeSecurityDescriptor real** — security_smoke 0→4.
7. **AllocateAndInitializeSid real** — security_smoke 0→4.
8. **EnumDisplayDevices / GetMonitorInfo** — multimon 2→5.
9. **GetSystemPowerStatus** — power_smoke 1→3.
10. **CreateAcceleratorTable** — accel_smoke 0→3.
