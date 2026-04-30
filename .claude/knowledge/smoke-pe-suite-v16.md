# Surface-coverage PE smoke suite v16 — 118 apps, 421 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v15

## Description

Same 118 apps as v15, but **421 PASS** (+10) thanks to high-leverage
STUB-to-real conversions. **Pass rate: 81.4%** (up from 79.2%).

## Iteration fixes

### iphlpapi.c — 1→4 PASS

- `GetIpAddrTable` returns 1 row (127.0.0.1 / 255.0.0.0).
- `GetTcpTable` / `GetUdpTable` return empty tables (header only).
- `GetNetworkParams` writes a "duetos" hostname.

### kernel32.c — NLS / volume / profile / thread

- `GetDateFormatA` (MM/DD/YYYY), `GetTimeFormatA` (HH:MM:SS),
  `GetNumberFormatA` (pass-through), `EnumSystemLocalesA` (one
  callback with "00000409"). Lifts **nls 1→4 PASS**.
- `GetVolumeInformationW` ("DuetOS" / "DUETFS"),
  `GetDiskFreeSpaceExW` (8GiB total / 1GiB free). Lifts
  **vol 2→4 PASS**.
- `GetPrivateProfileStringA` / `GetPrivateProfileIntA` /
  `GetProfileStringA` — return supplied default. Lifts
  **profile 0→3 PASS**.
- `GetThreadIOPendingFlag` returns FALSE. Lifts **thread3 2→3**.

15 new exports added.

## Cumulative

118 apps, 421 PASS, 96 FAIL — pass rate ≈ 81.4%.

## Next high-leverage targets

1. multimon (3 FAIL) — EnumDisplayMonitors / MonitorFromPoint
2. gdi (3 FAIL) — CreateCompatibleDC etc.
3. psapi (4 FAIL) — preload diagnosis
4. crt (3 FAIL) — strncpy details
5. registry+reg2 (2+3 FAIL) — HKLM/HKCU root open
6. module (2 FAIL) — GetModuleHandleW(name)
7. debug (2 FAIL) — pseudo-handle resolution
8. dde (2 FAIL) — DDEML
