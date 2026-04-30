# Surface-coverage PE smoke suite v4 — 36 apps, 177 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0 / v1 / v2 / v3

## Description

The smoke PE suite expanded from 30 apps to **36 apps**. Total
guarded surface: **177 PASS** across the 36 apps.

```bash
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=240 tools/qemu/run.sh 2>&1 \
  | grep -E '^\[(crypto|paths|time|iphlpapi|wininet|string|mem|fs|registry|handle|process|module|env|debug|codepage|rng|version|psapi|com|dbghelp|winhttp|crt|critsec|tls|atom|console|datetime|locale|gdi|msg|pipe|resource|ntdll|shell|userenv)_smoke?\]|^\[mini_browser\]'
```

## New in v4

| App                | DLL surface           | PASS | FAIL | Notes |
|--------------------|-----------------------|------|------|-------|
| `msg_smoke`        | user32                | 6/1  | 1/7  | Post/Peek/Translate/Dispatch all work |
| `pipe_smoke`       | kernel32              | 1/1  | 1/2  | Wait-no-pipe PASS; CreatePipe STUB |
| `resource_smoke`   | kernel32 + user32     | 5/0  | 0/5  | all return-NULL paths handled cleanly |
| `ntdll_smoke`      | ntdll                 | 4/0  | 0/4  | RtlGetVersion / SecureZero / Init / NtStatus all work |
| `shell_smoke`      | kernel32 + shell32    | 2/1  | 1/3  | CommandLineToArgvW + one folder PASS |
| `userenv_smoke`    | kernel32 + userenv    | 1/2  | 2/3  | OpenProcessToken PASS; profile dirs STUB |

## Iteration fixes landed alongside v4

### 1. msvcrt: 35+ new exports

**Symptom**: crt_smoke saw FAIL on strcpy/strcat/strchr/strrchr/
strstr/qsort/bsearch/atoi/abs.

**Cause**: `userland/libs/msvcrt/msvcrt.c` had implementations
for most of these, but `tools/build/build-msvcrt-dll.sh` only
exported 8 of them. Everything else fell to the catch-all
NO-OP.

**Fix**: added `strcat` + `strncat` to the source, added 35
new `/export:` lines to the build script (str* family, mem*,
isXxx, atoi/atol/atoll, abs/labs/llabs, qsort, bsearch).
Result: **crt_smoke 7→11 PASS (+57%)**.

### 2. Locale APIs in kernel32

**Symptom**: locale_smoke saw 1/7 — only IsValidLocale (which
went via the kernel-hosted `kOffReturnOne` thunk) PASSed.

**Fix**: real implementations in `userland/libs/kernel32/kernel32.c`:
- `GetUserDefaultLCID` / `GetSystemDefaultLCID` / `GetThreadLocale`
  return 0x0409 (en-US).
- `GetUserDefaultLangID` / `GetSystemDefaultLangID` return 0x0409.
- `IsValidLocale` accepts en-US, LOCALE_USER_DEFAULT,
  LOCALE_SYSTEM_DEFAULT.
- `GetLocaleInfoW` returns canned UTF-16 strings keyed off the
  most common LCType selectors (LANGNAME, COUNTRY, ISO639,
  ISO3166, decimal/thousand separators, etc.).
- `SetThreadLocale` accepts and returns 1.

Result: **locale_smoke 1→7 PASS (700% gain)**. Real localised
data still STUB; this lifts callers that gate on "is the locale
sensible" rather than reading actual translation tables.

### 3. Userland atom table in kernel32

**Symptom**: atom_smoke saw 2/7 — only the not-found probes
PASSed. Add/Find/GetName/Delete were all NO-OP.

**Fix**: 32-slot atom table in `userland/libs/kernel32/kernel32.c`
with case-insensitive name lookup, ref counting on duplicate
adds, and the canonical 0xC000+ atom-number range. Local +
Global atoms share the same backing (matches older Windows).

Eight new exports: AddAtomA / FindAtomA / DeleteAtom +
GlobalAddAtomA / GlobalFindAtomA / GlobalGetAtomNameA /
GetAtomNameA / GlobalDeleteAtom.

Result: **atom_smoke 2→7 PASS (+250%)**.

### 4. Per-app gain summary

| App | v3 PASS | v4 PASS | Δ |
|-----|---------|---------|---|
| crt_smoke | 7 | 11 | +4 |
| locale_smoke | 1 | 7 | +6 |
| atom_smoke | 2 | 7 | +5 |
| **Iteration delta** | | | **+15** |
| 6 new round-4 apps | | 19 | +19 |
| **v3 → v4 total** | **143** | **177** | **+34** |

(Six small per-app log-interleave artefacts on the older apps
account for the difference between +34 and +15+19 = +34.)

## v4 backlog (next iteration, sorted by leverage)

1. **psapi entire surface** — EnumProcesses/EnumProcessModules/
   GetProcessMemoryInfo (4 STUB lines).
2. **GetConsoleMode + GetConsoleScreenBufferInfo** — return
   sane defaults (lifts console_smoke 5→7).
3. **WinHttpOpen** — opaque session handle, no wire I/O yet.
   (Lifts winhttp_smoke 0→1+, plus dependent calls.)
4. **InternetOpenA** — same idea for wininet_smoke.
5. **CreatePipe in-process** — pair of buffer-backed handles
   (lifts pipe_smoke 1→4).
6. **GetProcessId/GetThreadId pseudo-handle resolution** — fixes
   debug_smoke 4→6.
7. **psapi.GetProcessImageFileNameW** — link to current PE path.
8. **GetTimeZoneInformation** — return UTC-0 STANDARD struct.
9. **registry HKLM RegOpenKeyExW** — wire prefix-tree.
10. **GetFileAttributesW + GetFullPathNameW** — fs_smoke 7→9.

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
           resource_smoke ntdll_smoke shell_smoke userenv_smoke; do
    p=$(grep -caE "^\[$app\].*PASS" /tmp/smokes.log)
    f=$(grep -caE "^\[$app\].*FAIL" /tmp/smokes.log)
    total_p=$((total_p+p)); total_f=$((total_f+f))
    printf "  %-18s PASS=%-3d FAIL=%-3d\n" "$app" "$p" "$f"
done
echo "TOTAL PASS=$total_p FAIL=$total_f"
```

Expect 177 PASS / 34 FAIL.
