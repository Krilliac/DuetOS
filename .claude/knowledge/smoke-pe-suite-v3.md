# Surface-coverage PE smoke suite v3 — 30 apps, 143 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0 / v1 / v2

## Description

The smoke PE suite expanded from 22 apps to **30 apps**. Total
guarded surface: **143 PASS** across 30 apps.

```bash
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=240 tools/qemu/run.sh 2>&1 \
  | grep -E '^\[(crypto|paths|time|iphlpapi|wininet|string|mem|fs|registry|handle|process|module|env|debug|codepage|rng|version|psapi|com|dbghelp|winhttp|crt|critsec|tls|atom|console|datetime|locale|gdi)_smoke?\]|^\[mini_browser\]'
```

## New in v3

| App                | DLL surface           | PASS | FAIL | Notes |
|--------------------|-----------------------|------|------|-------|
| `crt_smoke`        | kernel32 + msvcrt     | 7/13 | 6/13 | mem*/strcmp/strlen PASS; strcpy/strcat/strchr/qsort/atoi STUB |
| `critsec_smoke`    | kernel32              | 6/6  | 0/6  | Init/Enter/Leave/Try/SpinCount/Delete all work |
| `tls_smoke`        | kernel32              | 6/6  | 0/6  | TlsAlloc/Set/Get/Free + multi-slot all work |
| `atom_smoke`       | kernel32 + user32     | 2/7  | 5/7  | only FindAtom-not-found PASS; rest STUB |
| `console_smoke`    | kernel32              | 5/7  | 2/7  | StdHandle/CP/Title PASS; Mode/SBI STUB |
| `datetime_smoke`   | kernel32              | 4/5  | 1/5  | Get/Compare PASS; GetTimeZoneInfo STUB |
| `locale_smoke`     | kernel32              | 1/7  | 6/7  | only IsValidLocale PASS; LCID family STUB |
| `gdi_smoke`        | gdi32 + user32        | 2/5  | 3/5  | GetDC + DeleteObject PASS; rest STUB |

## Iteration fixes landed alongside v3

### 1. CreateFileW path-separator normalisation

**Symptom**: existing PE programs that hard-code Windows-style
`C:\path\to\file` couldn't find anything in the ramfs.

**Fix**: in `userland/libs/kernel32/kernel32.c::CreateFileW`,
strip a leading drive prefix (`C:`, `c:`, etc.) and translate
`\` → `/` byte-by-byte before issuing `SYS_FILE_OPEN`. The
ramfs lookup is POSIX-style; this lets Windows-style paths
work through the standard ABI.

### 2. Real `GetCPInfo` + `LCMapStringW`

**Symptom**: codepage_smoke saw 6/8; GetCPInfo returned 1 but
left output struct zero (kernel-hosted `kOffReturnOne` stub),
and LCMapStringW was `kOffReturnZero`.

**Fix**: real implementations in kernel32.c:
- `GetCPInfo`: fills MaxCharSize (4 for UTF-8, 1 elsewhere),
  DefaultChar = `?`, no lead bytes.
- `LCMapStringW`: implements LCMAP_LOWERCASE / LCMAP_UPPERCASE
  with proper sizing-call vs. transform-call dispatch.

Result: **codepage_smoke now 8/8 (was 6/8)**.

### 3. Real `FormatMessageW` with canned messages

**Symptom**: module_smoke saw FormatMessageW empty.

**Fix**: kernel32.c FormatMessageW returns one of three canned
UTF-16 strings:
- `dwMessageId == 0`: "The operation completed successfully."
- `dwMessageId == 3` (ERROR_PATH_NOT_FOUND): "The system cannot find the path."
- otherwise: "Generic failure."

Real localised tables / argument substitution deferred. Result:
**module_smoke now 4/2 (was 3/3 FAIL)**.

### 4. Six new exports in kernel32

`GetEnvironmentVariableW`, `GetEnvironmentVariableA`,
`SetEnvironmentVariableW`, `SetEnvironmentVariableA`,
`ExpandEnvironmentStringsW`, `ExpandEnvironmentStringsA`,
`GetCPInfo`, `LCMapStringW`, `FormatMessageW` —
nine additional Win32 functions exported from the userland
DLL. All from this round + v2.

### 5. gdi32.dll flipped to essential=true

Same recurring lesson — gdi_smoke imports needed real
exports rather than NO-OP catch-all.

## v3 backlog (next iteration)

Sorted highest-leverage to fix:

1. **msvcrt strcpy/strcat/strchr/strrchr/strstr** — implement
   in `userland/libs/msvcrt/msvcrt.c`; would lift crt_smoke
   from 7/13 to ~12/13.
2. **GetLocaleInfoW / GetLocaleInfoA** — return canned strings
   for LOCALE_USER_DEFAULT (LOCALE_SISO639LANGNAME = "en",
   LOCALE_SCOUNTRY = "United States", etc.). Each is ~10 lines.
3. **GlobalAddAtom / GlobalFindAtom / GlobalGetAtomName** —
   implement a 32-slot atom table in user32.c.
4. **GetConsoleMode / GetConsoleScreenBufferInfo** — return
   reasonable defaults (ENABLE_PROCESSED_OUTPUT, 80x25 buffer).
5. **GetUserDefaultLCID / GetSystemDefaultLCID / GetThreadLocale**
   — return 0x0409 (en-US). Already-fixed-style work.
6. **CreateCompatibleDC / Bitmap / SelectObject** — opaque
   handle bookkeeping in gdi32.c; no actual rendering.
7. **GetTimeZoneInformation** — return STANDARD timezone
   with bias = 0 (UTC); easy.
8. **psapi entire surface** — multi-session.
9. **InternetOpenA / WinHttpOpen** — multi-session network
   client wiring.
10. **RegOpenKeyExW** — wire HKLM via prefix-tree registry.

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
           locale_smoke gdi_smoke; do
    p=$(grep -caE "^\[$app\].*PASS" /tmp/smokes.log)
    f=$(grep -caE "^\[$app\].*FAIL" /tmp/smokes.log)
    total_p=$((total_p+p)); total_f=$((total_f+f))
    printf "  %-18s PASS=%-3d FAIL=%-3d\n" "$app" "$p" "$f"
done
echo "TOTAL PASS=$total_p FAIL=$total_f"
```

Expect 143 PASS / 44 FAIL. PASS-to-FAIL flips are regressions.
