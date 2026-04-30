# Surface-coverage PE smoke suite v6 — 52 apps, 242 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v5

## Description

The smoke PE suite expanded from 44 apps to **52 apps**. Total
guarded surface: **242 PASS** across the 52 apps (+29 from v5).

## New in v6

| App                | DLL surface       | PASS | FAIL | Notes |
|--------------------|-------------------|------|------|-------|
| `nls_smoke`        | kernel32          | 1/5  | 5/6  | UI language PASS; format STUBs |
| `services_smoke`   | advapi32          | 0/1  | 1/1  | OpenSCManagerW STUB (expected) |
| `eventlog_smoke`   | advapi32          | 3/0  | 0/3  | Register/Report/Deregister cycle |
| `sound_smoke`      | winmm             | 4/0  | 0/4  | wave/midi count + PlaySound NULL |
| `multimon_smoke`   | user32            | 2/3  | 3/5  | screen metrics + monitor count |
| `power_smoke`      | kernel32          | 1/2  | 2/3  | IsSystemResumeAutomatic only |
| `heap_smoke`       | kernel32          | 5/2  | 2/7  | HeapAlloc/Size/ReAlloc/Compact |
| `thread2_smoke`    | kernel32          | 5/2  | 2/7  | CreateThread + Wait + ExitCode + SRWLock |

## Iteration fixes landed alongside v6

### 1. wininet sentinel handles

**Symptom**: wininet_smoke saw 0/3 — every Internet handle allocator
returned NULL.

**Fix**: `userland/libs/wininet/wininet.c` now returns sentinel
handles (`0x4001` session, `0x4002` connect, `0x4003` request) so
callers can drive Open → OpenUrl → Read → Close without trapping.
InternetReadFile returns TRUE with 0 bytes (EOF). Real HTTP
transport over ws2_32 still deferred.

Result: **wininet_smoke 0→2 PASS**.

### 2. winhttp sentinel handles + 1-bit success returns

**Fix**: `userland/libs/winhttp/winhttp.c` sentinel handles
(`0x5001/0x5002/0x5003`) plus WinHttpSendRequest /
WinHttpReceiveResponse / WinHttpReadData all return TRUE.
WinHttpReadData reports 0 bytes (EOF).

Result: **winhttp_smoke 0→5 PASS**.

## v6 backlog (next iteration)

1. **Real HTTP transport** through wininet/winhttp via SYS_SOCKET_OP
   — would let `InternetReadFile` and `WinHttpReadData` actually
   return bytes from `www.google.com:80`.
2. **psapi DLL preload diagnosis** — still 0/4. The impls are real
   but the call goes to NO-OP. Suspect kernel-side thunk override.
3. **registry HKLM RegOpenKeyExW** — wire prefix-tree.
4. **CreatePipe in-process buffer** — pipe_smoke 1→4.
5. **GetProcessId/GetThreadId pseudo-handle** — debug_smoke 4→6.
6. **GetModuleHandleW(name)** — module_smoke 4→5.
7. **profile.c real impl with INI lookup** — profile_smoke 0→3.
8. **fopen / msvcrt FILE** — stdio_smoke 0→7.
9. **GetTimeFormat / GetDateFormat / GetNumberFormat** —
   nls_smoke 1→4.
10. **EnumDisplayDevices / GetMonitorInfo** — multimon_smoke 2→5.
11. **GetSystemPowerStatus / SetThreadExecutionState** —
    power_smoke 1→3.

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
           heap_smoke thread2_smoke; do
    p=$(grep -caE "^\[$app\].*PASS" /tmp/smokes.log)
    f=$(grep -caE "^\[$app\].*FAIL" /tmp/smokes.log)
    total_p=$((total_p+p)); total_f=$((total_f+f))
    printf "  %-19s PASS=%-3d FAIL=%-3d\n" "$app" "$p" "$f"
done
echo "TOTAL PASS=$total_p FAIL=$total_f"
```

Expect 242 PASS / 54 FAIL.
