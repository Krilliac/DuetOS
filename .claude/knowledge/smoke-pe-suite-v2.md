# Surface-coverage PE smoke suite v2 — 22 apps, 112 passing Win32 APIs

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes v0 / v1

## Description

The smoke PE suite expanded from 13 apps to **22 apps**. Each is a
self-contained ~10 KB Windows PE32+ that boots, exercises one
Win32 surface, prints PASS/FAIL/STUB per call, and exits. Total
guarded surface: **112 PASS** across the 22 apps.

```bash
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=180 tools/qemu/run.sh 2>&1 \
  | grep -E '^\[(crypto|paths|time|iphlpapi|wininet|string|mem|fs|registry|handle|process|module|env|debug|codepage|rng|version|psapi|com|dbghelp|winhttp)_smoke?\]|^\[mini_browser\]'
```

## Suite (v2)

### Carryover from v1 (re-verified)

| App                  | DLL surface       | PASS | Notes |
|----------------------|-------------------|------|-------|
| `mini_browser`       | kernel32 + ws2_32 | 5/5  | reaches google.com |
| `crypto_smoke`       | bcrypt + advapi32 | 6/7  | SHA-256 vector ✅ |
| `paths_smoke`        | shlwapi           | 9/9  | every path API |
| `time_smoke`         | kernel32 + winmm  | 7/7  | every time API |
| `iphlpapi_smoke`     | iphlpapi          | 1/4  | only GetAdaptersInfo PASS |
| `wininet_smoke`      | wininet           | 0/3  | InternetOpenA NULL stub |
| `string_smoke`       | kernel32 + user32 | 15/15 | every string API |
| `mem_smoke`          | kernel32          | 10/10 | VirtualAlloc/Heap*/Global*/Local* |
| `fs_smoke`           | kernel32          | 7/9  | CreateFile/Read/Find work |
| `registry_smoke`     | advapi32          | 0/2  | RegOpenKeyExW STUB |
| `handle_smoke`       | kernel32          | 12/12 | every sync primitive |
| `process_smoke`      | kernel32          | 11/12 | only PATH lookup empty |
| `module_smoke`       | kernel32          | 3/6  | named lookup STUB |

### New in v2

| App                  | DLL surface           | PASS | Notes |
|----------------------|-----------------------|------|-------|
| `env_smoke`          | kernel32              | 7/7  | all env APIs (Set/Get/Expand) |
| `debug_smoke`        | kernel32              | 4/6  | IsDebugger + Output PASS; pid/tid mismatch |
| `codepage_smoke`     | kernel32              | 6/8  | GetACP/OEMCP, IsValid, MB↔WC sizing |
| `rng_smoke`          | bcrypt + advapi32     | 3/3  | every RNG produces varying output |
| `version_smoke`      | kernel32 + version    | 2/3  | VerifyVersionInfo + GetVersion PASS |
| `psapi_smoke`        | kernel32 + psapi      | 0/4  | entirely STUB today |
| `com_smoke`          | kernel32 + ole32      | 5/5  | CoInit / TaskMem / StringFromCLSID PASS |
| `dbghelp_smoke`      | kernel32 + dbghelp    | 5/5  | SymInit/Get/SetOpts/UnDecorate/Cleanup |
| `winhttp_smoke`      | kernel32 + winhttp    | 0/1  | WinHttpOpen NULL stub |

## Iteration fixes landed alongside v2

### 1. Real env-var Get/Set/Expand in kernel32

**Symptom**: env_smoke saw GetEnvironmentVariableW return 0 even
after a successful Set.

**Cause**: kernel32.dll relied on the kernel-hosted `kOffReturnZero`
catch-all for env-var Get; Set was a no-op stub. Only
GetEnvironmentStringsW (kernel-managed env block) worked.

**Fix**: implemented a per-process **userland** env table in
`userland/libs/kernel32/kernel32.c` (16 slots × 32-char name ×
96-char value). Set, Get, ExpandEnvironmentStringsW (literal
copy), and the A-suffix variants all route through it.
Added the six new exports to `tools/build/build-kernel32-dll.sh`.

### 2. Real `StringFromCLSID` in ole32

**Symptom**: com_smoke saw `StringFromCLSID` return E_NOTIMPL.

**Cause**: stub returned E_NOTIMPL.

**Fix**: implemented full GUID formatting in
`userland/libs/ole32/ole32.c`:
`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`. Allocates via
`CoTaskMemAlloc`, returns S_OK. Exercises the GUID layout
(little-endian data1/2/3, raw data4) so a CLSID round-trip via
StringFromCLSID + CLSIDFromString (still STUB) is testable.

### 3. Three DLLs flipped to `essential=true`

**Symptom**: `psapi`, `ole32`, `winhttp`, `version` imports were
hitting the catch-all NO-OP under emulator.

**Fix**: marked all four `essential=true` in the preload list in
`kernel/proc/ring3_smoke.cpp`. Same recurring lesson as v0/v1.

### 4. kernel32 env-table size tuning

**Symptom**: with `g_env_table[64][644 bytes]`, kernel32.dll
.bss bloated to ~40KB and the loader panic'd with
"AddressSpaceMapUserPage: virt already mapped" when a later
preloaded DLL's image landed inside kernel32's range.

**Fix**: shrank the env table to 16 × 32 × 96 = ~2KB. The
loader's preload-base spacing leaves comfortable room for that.
A proper fix is making the loader account for .bss when sizing
the next DLL's base — added to v3 backlog.

## Confirmed-stub gaps (v3 backlog, sorted by leverage)

1. **`CreateFileW` separator normalisation** — translate `\` → `/`
   so existing Windows path strings work.
2. **`GetFileAttributesW`** — bind to ramfs node attrs.
3. **`RegOpenKeyExW`** — wire HKLM through the prefix-tree
   registry. ~5 smoke tests blocked on this.
4. **`GetModuleHandleW(name)`** — expose loaded-DLL table
   to user.
5. **`InternetOpenA`** + **`WinHttpOpen`** — route through ws2_32.
6. **`GetIpAddrTable` / `GetTcpTable` / `GetNetworkParams`** —
   wire to `kernel/net/stack.cpp`.
7. **`GetEnvironmentVariable("PATH")`** — seed process_smoke's
   env block with PATH at boot.
8. **`FormatMessageW`** — canned messages would unlock dozens of
   error-handling code paths.
9. **`GetCPInfo`** + **`LCMapStringW`** — codepage info table.
10. **`EnumProcesses`** + **`EnumProcessModules`** + the rest of
    psapi — multi-session, but high value for any debugger / task
    manager port.
11. **`CheckRemoteDebuggerPresent`** + **`GetProcessId(handle)`** /
    **`GetThreadId(handle)`** — pseudo-handle resolution.
12. **`GetFileVersionInfoSizeW`** — needs version resources baked
    into PE images.

## Audit checklist

```bash
for app in mini_browser crypto_smoke paths_smoke time_smoke \
           iphlpapi_smoke wininet_smoke string_smoke mem_smoke \
           fs_smoke registry_smoke handle_smoke process_smoke \
           module_smoke env_smoke debug_smoke codepage_smoke \
           rng_smoke version_smoke psapi_smoke com_smoke \
           dbghelp_smoke winhttp_smoke; do
    p=$(grep -caE "^\[$app\].*PASS" /tmp/smokes.log)
    f=$(grep -caE "^\[$app\].*FAIL" /tmp/smokes.log)
    printf "  %-18s PASS=%-3d FAIL=%-3d\n" "$app" "$p" "$f"
done
```

Expect 112 PASS / 26 FAIL. PASS-to-FAIL flips are regressions.
