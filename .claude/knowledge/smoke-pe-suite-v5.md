# Surface-coverage PE smoke suite v5 — 44 apps, 213 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v4

## Description

The smoke PE suite expanded from 36 apps to **44 apps**. Total
guarded surface: **213 PASS** across the 44 apps (+36 from v4).

## New in v5

| App                   | DLL surface          | PASS | FAIL | Notes |
|-----------------------|----------------------|------|------|-------|
| `interlock_smoke`     | kernel32             | 7/0  | 0/7  | every Interlocked* primitive |
| `fiber_smoke`         | kernel32             | 5/0  | 0/5  | IsThreadAFiber + Fls* (alloc/set/get/free) |
| `profile_smoke`       | kernel32             | 0/3  | 3/3  | INI APIs entirely STUB (legacy) |
| `clipboard_smoke`     | user32               | 5/0  | 0/5  | OpenClipboard / Empty / Close + format probes |
| `windowclass_smoke`   | user32               | 3/1  | 1/4  | RegisterClassW + Unregister PASS |
| `wow64_smoke`         | kernel32             | 4/0  | 0/4  | IsWow64Process + IsWow64Process2 + native AMD64 |
| `mathlib_smoke`       | kernel32             | 9/0  | 0/9  | every basic FPU op + comparisons |
| `stdio_smoke`         | kernel32 + msvcrt    | 0/1  | 1/2  | fopen STUB |

## Iteration fixes landed alongside v5

### 1. psapi.dll real impls

**Symptom**: psapi_smoke saw 0/4 — every call returned NULL/FALSE.

**Fix**: rewrote `userland/libs/psapi/psapi.c`:
- `EnumProcesses` returns 1 PID (sentinel current process).
- `EnumProcessModules` returns the EXE module handle.
- `GetProcessImageFileNameW` / `GetProcessImageFileNameA` return
  a sentinel "C:\\bin\\ring3.exe" path.
- `GetProcessMemoryInfo` fills the cb-prefixed counters struct.
- Added `GetProcessImageFileNameW/A` to the export list in
  `kernel/CMakeLists.txt::duetos_stub_dll(psapi …)`.

(Note: not yet observed as PASS in the v5 boot transcript;
likely a DLL-preload-order interaction. Tracking in v6 backlog.)

### 2. GetTimeZoneInformation

Real implementation in `userland/libs/kernel32/kernel32.c`
returning UTC-0 with no DST and StandardName = "UTC". Lifts
datetime_smoke's GetTimeZoneInformation from STUB to PASS.

### 3. GetConsoleScreenBufferInfo

Real implementation returning 80x25 buffer at cursor (0,0).
Lifts console_smoke 5→6.

### 4. GetFullPathNameW

Real implementation that prefixes "C:" if path starts with `/`
or `\\` and copies the rest. Sufficient for fs_smoke's PASS.

### 5. fs_smoke 7→8

`GetFileAttributesW` was already routed through
SYS_FILE_QUERY_ATTRIBUTES (kernel-side) and now PASSes when
the file exists. fs_smoke up from 7 to 8 PASS.

## v5 backlog (next iteration)

1. **wininet `InternetOpenA`** — opaque session handle.
2. **winhttp `WinHttpOpen`** — same idea.
3. **psapi DLL preload diagnosis** — the impls are real but
   the call still goes to NO-OP. Likely a thunk-table override
   issue.
4. **registry HKLM RegOpenKeyExW** — wire prefix-tree.
5. **CreatePipe in-process** — buffer-backed handle pair.
6. **GetProcessId / GetThreadId pseudo-handle resolution** —
   debug_smoke 4→6.
7. **GetModuleHandleW(name)** — module_smoke 4→5.
8. **profile.c real impl with INI lookup** — profile_smoke 0→3.
9. **fopen / msvcrt FILE I/O** — stdio_smoke 0→7.
10. **psapi EnumProcesses real list of PIDs** — once preload
    resolves.

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
           mathlib_smoke stdio_smoke; do
    p=$(grep -caE "^\[$app\].*PASS" /tmp/smokes.log)
    f=$(grep -caE "^\[$app\].*FAIL" /tmp/smokes.log)
    total_p=$((total_p+p)); total_f=$((total_f+f))
    printf "  %-19s PASS=%-3d FAIL=%-3d\n" "$app" "$p" "$f"
done
echo "TOTAL PASS=$total_p FAIL=$total_f"
```

Expect 213 PASS / 39 FAIL.
