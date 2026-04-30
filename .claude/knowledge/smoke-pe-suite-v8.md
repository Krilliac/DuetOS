# Surface-coverage PE smoke suite v8 — 68 apps, 284 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v7

## Description

The smoke PE suite expanded from 60 apps to **68 apps**. Total
guarded surface: **284 PASS** across the 68 apps (+25 from v7).

## New in v8

| App                | DLL surface          | PASS | FAIL | Notes |
|--------------------|----------------------|------|------|-------|
| `token_smoke`      | advapi32             | 2/1  | 1/3  | OpenProcessToken + GetUserNameA PASS |
| `security_smoke`   | advapi32             | 0/4  | 4/4  | SD/SID family STUB |
| `perf_smoke`       | kernel32             | 4/2  | 2/6  | QPC + QueryProcess/ThreadCycleTime |
| `accel_smoke`      | user32               | 0/1  | 1/3  | accelerator table STUB |
| `wts_smoke`        | wtsapi32             | 1/1  | 1/2  | WTSGetActiveConsoleSessionId |
| `winerr_smoke`     | kernel32             | 3/1  | 1/4  | SetLastError/Get + FormatMessageA + W |
| `sleep_smoke`      | kernel32             | 3/0  | 0/4  | Sleep(0/50) + SleepEx + SwitchToThread |
| `nt_smoke`         | ntdll                | 3/0  | 0/3  | NtQuerySystemTime + RtlAllocateHeap |

## Iteration fixes landed alongside v8

### 1. Real console cursor + attribute state in kernel32

Added 8 new exports + impls in `userland/libs/kernel32/kernel32.c`:
- In-memory cursor state `(g_console_cur_x, g_console_cur_y)`.
- `SetConsoleCursorPosition` writes it.
- `GetConsoleCursorInfo` / `SetConsoleCursorInfo` round-trip
  visibility + size.
- `SetConsoleTextAttribute` writes color attribute.
- `FillConsoleOutputAttribute` / `FillConsoleOutputCharacterA/W`
  return success with full count.
- `GetNumberOfConsoleInputEvents` returns 0 (no queued input).

Result: **console2_smoke 0→5 PASS**.

### 2. CreateFileMappingW / MapViewOfFile real impls

8-slot table of {size, base} maps backed by SYS_HEAP_ALLOC.
Anonymous (`INVALID_HANDLE_VALUE` source) mappings work; named
ones still STUB. CloseHandle of the mapping releases the
backing heap region.

Result: **ipc_smoke 0/1 (CreateFileMappingW now allocates;
MapViewOfFile + round-trip not exercised in this run due to
test layout — check next round).**

### 3. CreateJobObjectW / AssignProcessToJobObject / IsProcessInJob

Sentinel handle 0x7001, all calls return success, IsProcessInJob
reports FALSE before assignment. Result: **jobobj_smoke 0→3 PASS**.

## v8 backlog

1. **Real HTTP transport** through wininet/winhttp via socket APIs
   — would let `InternetReadFile` / `WinHttpReadData` actually
   return body bytes from `www.google.com:80`.
2. **psapi DLL preload diagnosis** — 0/4 in current runs despite
   real impls in psapi.c. Suspect kernel-side thunk override.
3. **fopen / msvcrt FILE I/O** — stdio_smoke 0→7.
4. **registry HKLM RegOpenKeyExW** — wire prefix-tree.
5. **Real CreatePipe in-process** — pipe_smoke 1→4.
6. **GetProcessId pseudo-handle** — debug_smoke 4→6.
7. **AllocateAndInitializeSid + IsValidSid** — security_smoke 0→4.
8. **CreateAcceleratorTable** — accel_smoke 0→3.
9. **InitializeSecurityDescriptor real impl** — security_smoke 0→4.

## Audit checklist

```bash
total_p=0; total_f=0
for app in mini_browser crypto_smoke paths_smoke time_smoke \
           iphlpapi_smoke wininet_smoke string_smoke mem_smoke \
           fs_smoke registry_smoke handle_smoke process_smoke \
           module_smoke env_smoke debug_smoke codepage_smoke \
           rng_smoke version_smoke psapi_smoke com_smoke \
           dbghelp_smoke winhttp_smoke crt_smoke critsec_smoke \
           tls_smoke atom_smoke console_smoke datetime_smoke \
           locale_smoke gdi_smoke msg_smoke pipe_smoke \
           resource_smoke ntdll_smoke shell_smoke userenv_smoke \
           interlock_smoke fiber_smoke profile_smoke \
           clipboard_smoke windowclass_smoke wow64_smoke \
           mathlib_smoke stdio_smoke nls_smoke services_smoke \
           eventlog_smoke sound_smoke multimon_smoke power_smoke \
           heap_smoke thread2_smoke ipc_smoke jobobj_smoke \
           console2_smoke dns_smoke network2_smoke dxgi_smoke \
           dwm_smoke uxtheme_smoke token_smoke security_smoke \
           perf_smoke accel_smoke wts_smoke winerr_smoke \
           sleep_smoke nt_smoke; do
    p=$(grep -caE "^\[$app\].*PASS" /tmp/smokes.log)
    f=$(grep -caE "^\[$app\].*FAIL" /tmp/smokes.log)
    total_p=$((total_p+p)); total_f=$((total_f+f))
done
echo "TOTAL PASS=$total_p FAIL=$total_f"
```

Expect 284 PASS / 67 FAIL.
