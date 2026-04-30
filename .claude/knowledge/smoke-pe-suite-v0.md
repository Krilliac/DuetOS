# Surface-coverage PE smoke suite — Win32 API gap inventory

**Last updated:** 2026-04-30
**Type:** Observation + Pattern
**Status:** Active

## Description

A growing suite of small (~10 KB) Windows PE32+ executables, one
per Win32 DLL surface, that boot-spawn and print PASS/FAIL/STUB
per API call. The boot serial transcript IS the gap inventory —
no external test harness, no pivot table to maintain.

This is the "rinse and repeat" iteration target: each new app
maps a previously-untested surface, and the kernel-side fixes
cascade through the existing apps for free. Every passing line
in the transcript is a guarded API surface.

## Suite (as of v0)

| App                  | DLL surface               | APIs probed                                                                          | Result      |
|----------------------|---------------------------|--------------------------------------------------------------------------------------|-------------|
| `mini_browser`       | kernel32 + ws2_32         | WSAStartup, gethostbyname, socket, connect, send, recv, closesocket, WSACleanup      | 5/5 ✅      |
| `crypto_smoke`       | kernel32 + bcrypt + advapi32 | BCryptGenRandom, OpenAlgorithm/CreateHash/HashData/FinishHash/Destroy, CryptAcquireContextW | 6/7 (1 STUB) |
| `paths_smoke`        | kernel32 + shlwapi        | PathFindExtension{A,W}, PathFindFileNameA, PathRemoveFileSpecW, PathAddBackslashW, PathAppendW, PathCombineW, PathFileExistsA, PathStripPathW | 9/9 ✅       |
| `time_smoke`         | kernel32 + winmm          | GetTickCount{,64}, QPF, QPC, GetSystemTimeAsFileTime, timeGetTime, timeBeginPeriod/EndPeriod | 7/7 ✅       |
| `iphlpapi_smoke`     | kernel32 + iphlpapi       | GetAdaptersInfo, GetIpAddrTable, GetTcpTable, GetNetworkParams                       | 1/4 (3 STUB) |
| `wininet_smoke`      | kernel32 + wininet        | InternetOpenA, InternetOpenUrlA, InternetReadFile, InternetCloseHandle               | 0/3 (STUB)   |

**28 passing API surfaces** under the v0 suite. Every PASS
line is grep-able from the boot serial transcript:

```bash
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=90 tools/qemu/run.sh 2>&1 \
  | grep -E '^\[(crypto|paths|time|iphlpapi|wininet|mini_browser)_smoke?\]'
```

## Two iterations landed alongside the suite

### 1. Real SHA-256 in `userland/libs/bcrypt/bcrypt.c`

**Symptom**: `BCryptFinishHash` returned all-zero digest — fake.

**Fix**: ~80-line FIPS 180-4 reference SHA-256 implementation
threaded through `BCryptCreateHash` (`Sha256Init`),
`BCryptHashData` (`Sha256Update`), `BCryptFinishHash`
(`Sha256Final`). Verified against the canonical test vector
SHA-256("abc") = `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
Single-static-slot, single-threaded scope — same v0 ceiling
as the rest of bcrypt. Other algorithms still zero-fill the
output until they're individually wired up.

### 2. `PathRemoveFileSpecW` returned wrong type

**Symptom**: `paths_smoke` saw `BOOL ok = PathRemoveFileSpecW(buf)`
return garbage — function modified `buf` correctly but caller
saw whatever was in `eax` at return.

**Fix**: changed signature in `userland/libs/shlwapi/shlwapi.c`
from `void` to `BOOL` matching MSDN, returning `1` if a path
component was removed and `0` otherwise. The header file
already declared `BOOL` — the .c was the lone offender.

## Three iterations landed in the previous slice (mini_browser)

The mini_browser slice already taught us:

- Mark a DLL `essential=true` in `kernel/proc/ring3_smoke.cpp`'s
  preload list when an app needs it under emulator.
- `gethostbyname` now routes through new `kSockOpResolveA = 12`
  in `SYS_SOCKET_OP` to `NetDnsQueryA`.
- `SocketConnect` blocks until the TCP three-way handshake
  completes, with retry on slot-busy (parallel app contention).
- Inline-asm operand indices are zero-based with `%0` =
  first OUTPUT — `ws2_op` had been off-by-one for months.

## Structural pattern

Every smoke app follows the same shape:

```
userland/apps/<name>/
  <name>.c             — ~80-150 lines of C, mingw-w64 freestanding-PE
  <name>.exe           — checked-in prebuilt PE, embedded by kernel CMake
```

Build via `userland/apps/build-smokes.sh` (one driver script).
Embed via the `duetos_embed_smoke_pe(<name> <symbol>)` function
in `kernel/CMakeLists.txt`. Spawn via one line in
`kernel/proc/ring3_smoke.cpp::StartRing3SmokeTask`.

Every PE:
- entry = `mainCRTStartup` (no CRT runtime, no RTL_USER_PROCESS_PARAMETERS)
- imports kernel32 unconditionally + one targeted DLL
- prints PASS/FAIL/STUB per API
- exits via `ExitProcess(0)` on success, with non-zero rc per failure step

This means each new surface costs ~150 lines of C, one CMake
line, one spawn line, and you immediately see the boot
transcript tell you what's real vs. what's a NO-OP.

## Confirmed-stub gaps (highest-leverage to fix next)

Sorted by how easy they'd be relative to how much surface they unlock:

1. **`PathFindFileNameW`** — paths_smoke doesn't probe this yet but every Windows
   app uses it. ~10 lines.
2. **`InternetOpenA`** — single function, currently returns NULL.
   Hooking it up to allocate an opaque session handle (no wire I/O
   yet) opens the door to ~5 more `[wininet_smoke]` PASS lines.
3. **`GetIpAddrTable`** — wire to `g_interfaces[]` in
   `kernel/net/stack.cpp`. One row per bound interface.
4. **`GetTcpTable`** — wire to `kernel/net/socket.cpp` socket pool.
5. **`GetNetworkParams`** — DHCP-supplied DNS servers + a fixed
   "duetos" hostname. ~20 lines.
6. **`CryptAcquireContextW`** — legacy advapi32 crypto. Most modern
   apps use BCrypt; can stay STUB longer.

## Audit checklist

```bash
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=90 tools/qemu/run.sh 2>&1 \
  | grep -E '^\[(crypto|paths|time|iphlpapi|wininet|mini_browser)_smoke?\]'
```

Expect the PASS counts above. Regressions show up as a previously-passing
line flipping to FAIL.
