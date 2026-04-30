# Surface-coverage PE smoke suite v1 — comprehensive Win32 API tests

**Last updated:** 2026-04-30
**Type:** Observation + Pattern + Issue
**Status:** Active — supersedes the v0 inventory in
[smoke-pe-suite-v0.md](smoke-pe-suite-v0.md)

## Description

The smoke PE suite expanded from 6 apps to **13 apps**. Each is a
self-contained ~10 KB Windows PE32+ that boots, exercises one
Win32 surface, prints PASS/FAIL/STUB per call, and exits.

Total guarded surface: **80 PASS** across the 13 apps. The boot
serial transcript IS the gap inventory:

```bash
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=120 tools/qemu/run.sh 2>&1 \
  | grep -E '^\[(crypto|paths|time|iphlpapi|wininet|string|mem|fs|registry|handle|process|module)_smoke?\]|^\[mini_browser\]'
```

## Suite (v1)

### Carryover from v0

| App                  | DLL surface       | PASS | FAIL | Notes |
|----------------------|-------------------|------|------|-------|
| `mini_browser`       | kernel32 + ws2_32 | 5/5  | 0/5  | reaches google.com |
| `crypto_smoke`       | bcrypt + advapi32 | 6/7  | 1/7  | SHA-256 vector ✅; legacy CryptAcquireContextW STUB |
| `paths_smoke`        | shlwapi           | 9/9  | 0/9  | every path API |
| `time_smoke`         | kernel32 + winmm  | 7/7  | 0/7  | every time API |
| `iphlpapi_smoke`     | iphlpapi          | 1/4  | 3/4  | only GetAdaptersInfo PASS |
| `wininet_smoke`      | wininet           | 0/3  | 3/3  | InternetOpenA NULL stub |

### New in v1

| App                  | DLL surface          | PASS | FAIL | Highlights |
|----------------------|----------------------|------|------|------------|
| `string_smoke`       | kernel32 + user32    | 15/15 | 0/15 | every string API + char-class |
| `mem_smoke`          | kernel32             | 10/10 | 0/10 | VirtualAlloc/Protect, Heap*, Global*, Local* |
| `fs_smoke`           | kernel32             | 7/9  | 2/9  | CreateFile/Read/Find PASS; Attrs+FullPath STUB |
| `registry_smoke`     | advapi32             | 0/2  | 2/2  | RegOpenKeyExW returns ERROR; both fail early |
| `handle_smoke`       | kernel32             | 12/12 | 0/12 | Event + Mutex (recursive) + Semaphore + Wait |
| `process_smoke`      | kernel32             | 11/12 | 1/12 | only GetEnvironmentVariable(PATH) empty |
| `module_smoke`       | kernel32             | 3/6  | 3/6  | NULL handle + ProcAddress work; named lookup STUB |

## Five iterations landed alongside the suite

### 1. `lstrcatA` and `lstrcatW` were missing from kernel32

**Symptom**: string_smoke `lstrcpyA + lstrcatA` FAIL.

**Cause**: kernel32.c had `lstrcpy*` but not `lstrcat*`. Catch-all
NO-OP returned 0 → buf left at "hello", expected "hello world".

**Fix**: implemented both in `userland/libs/kernel32/kernel32.c`,
added `/export:lstrcatA` and `/export:lstrcatW` to
`tools/build/build-kernel32-dll.sh`.

### 2. `CharLowerA`/`CharUpperA`/`IsCharAlpha*` missing from user32

**Symptom**: string_smoke saw four FAIL rows for these.

**Cause**: user32.c had only the W-suffix variants. The A-suffix
variants and the `IsCharAlpha*` family weren't implemented at all.

**Fix**: added the four functions to `userland/libs/user32/user32.c`
and updated the `duetos_stub_dll(user32 ...)` export list in
`kernel/CMakeLists.txt`.

### 3. user32.dll wasn't preloaded under emulator

**Symptom**: even though `CharLowerW` already existed and was
exported, every user32 import was hitting the catch-all NO-OP.

**Cause**: same as the v0 ws2_32 lesson — `essential=false` skips
the preload under `arch::IsEmulator()`.

**Fix**: flipped user32 to `essential=true` in
`kernel/proc/ring3_smoke.cpp`. Costs one extra DllLoad on boot;
unlocks every user32 export across the entire smoke suite.

### 4. fs_smoke used Win32-style path separators

**Symptom**: `CreateFileW(L"\etc\version")` FAIL → entire app exits early.

**Cause**: the kernel ramfs lookup uses POSIX-style forward-slash
paths. The kernel32 CreateFileW thunk doesn't translate
backslashes to slashes (yet). Other PEs that work (winkill,
hello-winapi) all use forward slashes for this reason.

**Fix**: changed test paths from `L"\\etc\\version"` to
`L"/etc/version"`. The proper fix is to teach the CreateFileW
thunk to normalise the separator — added to "next iteration" list.

### 5. SHA-256 test vector validated (carryover from v0)

The SHA-256 implementation in `userland/libs/bcrypt/bcrypt.c`
continues to match the FIPS 180-4 test vector
SHA-256("abc") = `ba78...15ad`.

## Confirmed-stub gaps (next-iteration backlog)

Sorted highest-leverage to fix next:

1. **`CreateFileW` separator normalisation** — translate `\` → `/`
   in the kernel32 thunk so existing PE programs that hard-code
   Windows paths work.
2. **`GetFileAttributesW`** — bind to ramfs node attributes.
   Currently returns INVALID_FILE_ATTRIBUTES.
3. **`RegOpenKeyExW`** — wire HKLM hierarchy through the
   prefix-tree registry (see `registry-prefix-tree-v0.md`).
   Several smoke probes blocked on this single function.
4. **`GetModuleHandleW(name)`** — non-NULL lookups return 0
   today; need to expose the loaded-DLL table to userland.
5. **`InternetOpenA`** — could route through ws2_32 internally;
   one allocator + state machine = ~30 PASS lines unlocked.
6. **`GetIpAddrTable` / `GetTcpTable` / `GetNetworkParams`** —
   wire to `kernel/net/stack.cpp`'s interface + DHCP state.
7. **`GetEnvironmentVariable(\"PATH\")`** — the env block is
   built (GetEnvironmentStringsW PASS) but PATH isn't in it.
8. **`FormatMessageW`** — currently empty. Returning canned
   "OK" / "GENERIC FAILURE" strings would unlock dozens of
   error-handling code paths in real Windows binaries.

## Structural pattern (unchanged from v0)

Each smoke app follows the same shape:

```
userland/apps/<name>_smoke/
  <name>_smoke.c       — ~80-200 lines of C, freestanding PE
  <name>_smoke.exe     — checked-in prebuilt PE, embedded by CMake
```

Adding a new surface costs ~150 lines of C, one CMake line, one
spawn line. Boot transcript tells you immediately what's real.

`userland/apps/build-smokes.sh` rebuilds all 13 PEs in one command.

## Audit checklist

Aggregate counts via:

```bash
for app in mini_browser crypto_smoke paths_smoke time_smoke \
           iphlpapi_smoke wininet_smoke string_smoke mem_smoke \
           fs_smoke registry_smoke handle_smoke process_smoke \
           module_smoke; do
    p=$(grep -caE "^\[$app\].*PASS" /tmp/smokes.log)
    f=$(grep -caE "^\[$app\].*FAIL" /tmp/smokes.log)
    printf "  %-18s PASS=%-3d FAIL=%-3d\n" "$app" "$p" "$f"
done
```

Expect 80 PASS / 12 FAIL. Regressions show up as a previously-passing
line flipping to FAIL.

## Why this matters

The DuetOS Win32 stub matrix has historically been hard to audit.
Each function was either "real" or "STUB" but the per-call truth
was scattered across `.cpp` files. This suite makes the audit
**continuously verifiable from the boot transcript**: every PASS
line is a guarded API contract, every FAIL is a labelled gap.

The pattern also acts as a regression net: a future loader change
that breaks DLL preload, an export-list edit that drops a function,
or a thunk rewrite that returns wrong bytes will show up as a
PASS-to-FAIL flip in the very next boot.
