# Surface-coverage PE smoke suite v7 — 60 apps, 259 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0..v6

## Description

The smoke PE suite expanded from 52 apps to **60 apps**. Total
guarded surface: **259 PASS** across the 60 apps (+17 from v6).

## New in v7

| App                | DLL surface       | PASS | FAIL | Notes |
|--------------------|-------------------|------|------|-------|
| `ipc_smoke`        | kernel32          | 0/1  | 1/1  | CreateFileMappingW STUB |
| `jobobj_smoke`     | kernel32          | 0/1  | 1/1  | CreateJobObjectW STUB |
| `console2_smoke`   | kernel32          | 0/5  | 5/5  | Cursor/Attribute/Fill all STUB |
| `dns_smoke`        | ws2_32            | 3/0  | 0/3  | WSAStartup + gethostname + getaddrinfo |
| `network2_smoke`   | ws2_32            | 8/1  | 1/9  | byte-order + socket + setsockopt |
| `dxgi_smoke`       | dxgi              | 2/0  | 0/2  | CreateDXGIFactory + V1 returned |
| `dwm_smoke`        | dwmapi            | 3/0  | 0/3  | DwmIs/Get/Flush returned |
| `uxtheme_smoke`    | uxtheme           | 3/1  | 1/4  | IsAppThemed + IsThemeActive + AppProps |

## Iteration fixes landed alongside v7

- dxgi.dll, dwmapi.dll, uxtheme.dll all flipped to
  `essential=true` so their imports resolve to real exports
  rather than the catch-all NO-OP. Same recurring lesson.

## v7 backlog (next iteration)

1. **CreateFileMappingW** — anonymous mapping should at least
   allocate a heap region.
2. **CreateJobObjectW** — opaque handle is enough for v0.
3. **SetConsoleCursorPosition / GetConsoleCursorInfo** —
   in-memory cursor state.
4. **FillConsoleOutputCharacter / FillConsoleOutputAttribute**
   — no-op success returns.
5. **psapi DLL preload diagnosis** — still 0/4. Need to look
   at the kernel-side thunk-table-vs-DLL-export resolution
   order.
6. **Real HTTP transport** through wininet / winhttp via
   SYS_SOCKET_OP — would let `InternetReadFile` /
   `WinHttpReadData` actually return bytes.
7. **fopen / msvcrt FILE** — stdio_smoke 0→7.
8. **registry HKLM RegOpenKeyExW** — wire prefix-tree.
9. **CreatePipe in-process** — pipe_smoke 1→4.
10. **GetProcessId pseudo-handle** — debug_smoke 4→6.

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
           dwm_smoke uxtheme_smoke; do
    p=$(grep -caE "^\[$app\].*PASS" /tmp/smokes.log)
    f=$(grep -caE "^\[$app\].*FAIL" /tmp/smokes.log)
    total_p=$((total_p+p)); total_f=$((total_f+f))
done
echo "TOTAL PASS=$total_p FAIL=$total_f"
```

Expect 259 PASS / 63 FAIL across 60 apps.
