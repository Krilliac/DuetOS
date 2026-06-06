# Smoke Test Suite

> **Audience:** QA, contributors adding ABI coverage, anyone investigating
> a regression in a specific Win32 surface
>
> **Execution context:** Userland — PEs running on the target kernel
>
> **Maturity:** v0 active — 130+ smoke binaries; profile dispatcher live

## Overview

[`userland/apps/`](../../userland/apps/) hosts ~130 small Windows PE
smoke tests. Each one exercises one slice of the Win32 ABI surface —
file I/O, threading, GDI, DirectX, network sockets, registry, locale,
crypto, etc. The smokes share three properties:

- **One topic per binary.** A smoke test exercises a single subsystem,
  prints `PASS` or `FAIL` per check, and exits with code 0 on
  full success.
- **Output is grep-able.** Each test prints `[<topic>-smoke] PASS …` or
  `[<topic>-smoke] FAIL: …`. The boot smoke harness greps for FAIL.
- **No internal deps.** Smokes don't link against each other; each
  binary stands alone.

These binaries are how DuetOS proves that a Win32 ABI surface actually
works end-to-end against a live PE rather than against a unit test of
the kernel side.

The boot dispatcher
([`kernel/test/smoke_profile.cpp`](../../kernel/test/smoke_profile.cpp))
picks which smoke (or set of smokes) to run for a given profile. The
profiles are documented at [QEMU Smoke](../tooling/QEMU-Smoke.md); this
page is the per-test inventory.

## How to Run

From a live boot, smokes are PE files at `/APPS/<name>.EXE`. From the
shell:

```
exec /APPS/console_smoke.exe
```

From CI, the boot dispatcher launches the smoke that matches the
profile selected by the `smoke=` cmdline:

```
qemu -kernel … -append "smoke=PeHello"           # spawns hello_pe.exe
qemu -kernel … -append "smoke=PeWinapi"          # spawns hello_winapi.exe
qemu -kernel … -append "smoke=PeWinkill"         # spawns windows_kill.exe
qemu -kernel … -append "smoke=Linux"             # spawns the Linux smoke
qemu -kernel … -append "smoke=browser"           # spawns browser_pe.exe + mini_browser.exe
qemu -kernel … -append "smoke=Bringup"           # boots to desktop, runs nothing
```

`smoke=browser` is the emulator-friendly path for the two browser
PEs (they otherwise only run on bare metal via the `!emulator`
zoo). The qemu SLIRP NIC has a DHCP lease by bringup, so the
WinInet (`browser_pe.exe`) and raw-WinSock (`mini_browser.exe`)
fetches are live: real `200` / `404` from google.com + example.com.
Invoke locally with `DUETOS_SMOKE_PROFILE=browser tools/qemu/run.sh`.

The CI greps the boot log for `[smoke] profile=… complete` (success)
or `[E]` / `FAIL` (failure).

## Smoke Catalogue by Surface

The table groups smokes by the surface they exercise so you can find
the closest existing smoke before adding a new one.

### Core Win32 — Console, CRT, Paths, Environment

| Smoke | What it checks |
|-------|----------------|
| `console_smoke`, `console2_smoke`, `console3_smoke` | `GetStdHandle`, `WriteConsole`, console code page, console-mode flags |
| `conio_smoke` | `_getch` / `_putch` / `_kbhit` |
| `crt_smoke` | CRT init, atexit, exit codes, `_set_app_type` |
| `env_smoke`, `enviro_smoke` | `GetEnvironmentVariable`, `_environ`, `SetEnvironmentVariable` |
| `paths_smoke`, `paths2_smoke` | path canonicalisation, `GetFullPathName` |
| `drive_smoke`, `vol_smoke` | `GetLogicalDrives`, `GetVolumeInformation` |
| `stdio_smoke`, `stream_smoke` | `fopen/fread/fwrite`, FILE* lifecycle |
| `string_smoke`, `wstr_smoke`, `wstr2_smoke`, `utf16_smoke`, `mbcs_smoke` | string + wstring ops + UTF-16 ↔ MBCS |
| `codepage_smoke`, `intl_smoke`, `nls_smoke`, `locale_smoke`, `locale2_smoke` | code page selection, NLS lookups, locale info |
| `datetime_smoke` | `GetSystemTime`, `GetLocalTime`, `FileTimeToSystemTime` |
| `mathlib_smoke`, `fpcontrol_smoke` | float math, FPU control word |
| `signal_smoke` | `signal()` handler install + raise |
| `sleep_smoke`, `time_smoke`, `timer_smoke` | `Sleep`, `GetTickCount`, multimedia timers |
| `perf_smoke` | `QueryPerformanceCounter`, `QueryPerformanceFrequency` |
| `sysinfo_smoke` | `GetSystemInfo`, OS version, processor count |

### Memory, Heaps, Handles

| Smoke | What it checks |
|-------|----------------|
| `mem_smoke`, `mem2_smoke`, `advmem_smoke` | `VirtualAlloc`, `VirtualProtect`, `VirtualFree` |
| `heap_smoke`, `heap3_smoke` | `HeapCreate`, `HeapAlloc`, `HeapFree`, `HeapValidate` |
| `handle_smoke`, `handle2_smoke` | `DuplicateHandle`, `CloseHandle`, handle lifetime |
| `module_smoke` | `LoadLibrary`, `GetProcAddress`, `FreeLibrary` |
| `accel_smoke` | `LoadAccelerators`, accelerator-table translation |

### Threads, Sync, IPC

| Smoke | What it checks |
|-------|----------------|
| `thread2_smoke`, `thread3_smoke`, `thread_stress` | `CreateThread`, `WaitForSingleObject`, thread-exit, stress |
| `tls_smoke` | TLS slot allocation + thread-local fetch |
| `fiber_smoke` | `CreateFiber`, `SwitchToFiber` |
| `critsec_smoke` | `EnterCriticalSection`, `LeaveCriticalSection` |
| `interlock_smoke` | `InterlockedIncrement`, `InterlockedExchange`, `InterlockedCompareExchange` |
| `iocp_overlapped_smoke`, `iocp2_smoke` | `CreateIoCompletionPort`, `GetQueuedCompletionStatus`, overlapped I/O |
| `ipc_smoke`, `pipe_smoke` | anonymous + named pipes |
| `msg_smoke`, `wndmsg_smoke` | `PostMessage`, `GetMessage`, `DispatchMessage` |
| `nt_smoke`, `ntdll_smoke` | `Nt*` direct-syscall paths |
| `jobobj_smoke` | `CreateJobObject`, job assignment |

### Processes

| Smoke | What it checks |
|-------|----------------|
| `process_smoke`, `proc2_smoke`, `proc3_smoke` | `CreateProcess`, `OpenProcess`, `GetExitCodeProcess` |
| `debug_smoke`, `debug2_smoke` | `DebugActiveProcess`, `WaitForDebugEvent`, debug event loop |
| `psapi_smoke` | `EnumProcessModules`, `GetModuleFileNameEx` |
| `dbghelp_smoke` | `MiniDumpWriteDump`, `SymGetLineFromAddr` |
| `profile_smoke` | sample-based profiler hooks |
| `trace_smoke` | ETW-style trace surface |
| `power_smoke` | `SetThreadExecutionState` |
| `prio_smoke` | thread / process priority + affinity |
| `wow64_smoke` | WoW64 redirection stubs (NOPs on a 64-bit target) |
| `services_smoke`, `svc_ctrl_smoke` | service control manager surface |

### Filesystem

| Smoke | What it checks |
|-------|----------------|
| `fs_smoke`, `fs2_smoke`, `fs3_smoke` | `CreateFile`, `ReadFile`, `WriteFile`, `SetFilePointer` |
| `find_smoke` | `FindFirstFile`, `FindNextFile`, `FindClose` |

### GDI, User, Windows

| Smoke | What it checks |
|-------|----------------|
| `gdi_smoke`, `gdiplus_smoke` | `BitBlt`, `Rectangle`, `TextOutW`, GDI+ flat APIs |
| `windowclass_smoke`, `wndmsg_smoke` | `RegisterClassEx`, WndProc dispatch |
| `disp_smoke`, `multimon_smoke` | `EnumDisplayDevices`, monitor enumeration |
| `key_smoke` | keyboard event injection |
| `atom_smoke` | global atom table |
| `clipboard_smoke`, `scrap_smoke` | `OpenClipboard`, format conversion |
| `dde_smoke` | DDE messaging (legacy) |
| `shell_smoke` | `ShellExecute`, `SHGetSpecialFolderPath` |
| `dwm_smoke` | `DwmGetWindowAttribute`, composition stubs |
| `uxtheme_smoke` | theme API |

### DirectX / Multimedia

| Smoke | What it checks |
|-------|----------------|
| `d2d1_smoke` | Direct2D factory + render target |
| `d3d9_smoke` | D3D9 device + clear + present |
| `d3d11_smoke` | D3D11 device + immediate context + clear + present |
| `d3d12_smoke` | D3D12 device + command queue + present |
| `ddraw_smoke` | DirectDraw surface enumeration |
| `dinput8_smoke` | DirectInput8 device enumeration |
| `dsound_smoke` | DirectSound enumeration + buffer create |
| `dwrite_smoke` | DirectWrite factory + text format |
| `dxgi_smoke` | DXGI factory + adapter enum + swap chain |
| `xaudio2_smoke` | XAudio2 device + voice |
| `xinput_smoke` | XInput controller poll |

### Network

| Smoke | What it checks |
|-------|----------------|
| `net_loopback_smoke`, `network2_smoke` | local TCP loopback round-trip |
| `dns_smoke` | `getaddrinfo`, hostname resolution |
| `iphlpapi_smoke` | `GetAdaptersAddresses`, interface enum |
| `sock_opt_smoke` | `setsockopt`, `getsockopt` |
| `select_smoke` | `select` multiplexing |
| `asyn_smoke` | async/overlapped sockets |
| `winsock_ext_smoke` | Winsock extensions (`AcceptEx`, `ConnectEx`) |
| `winhttp_smoke` | `WinHttpOpen`, `WinHttpConnect`, `WinHttpSendRequest` |
| `wininet_smoke` | `InternetOpen`, `InternetReadFile` |

### Registry, Security, Identity

| Smoke | What it checks |
|-------|----------------|
| `registry_smoke`, `reg2_smoke`, `reg3_smoke`, `reg_fopen_test` | `RegOpenKeyEx`, `RegQueryValueEx`, `RegSetValueEx` |
| `token_smoke` | `OpenProcessToken`, `GetTokenInformation` |
| `security_smoke` | SID / ACL surface |
| `crypto_smoke` | `CryptAcquireContext`, `CryptGenRandom` |
| `rng_smoke` | `BCryptGenRandom` |
| `userenv_smoke`, `wts_smoke` | user profile / WTS surface |
| `eventlog_smoke` | `ReportEvent` |
| `wmi_smoke` | WMI query surface |
| `setupapi_smoke` | device installation surface |
| `version_smoke` | `GetFileVersionInfo` |
| `xml_smoke` | XML lite |
| `winerr_smoke` | `GetLastError`, `FormatMessage` |

### COM and Custom DLLs

| Smoke | What it checks |
|-------|----------------|
| `com_smoke`, `com2_smoke` | `CoInitializeEx`, `CoCreateInstance` |
| `customdll_test` | a hand-written sample DLL exercising the DLL loader |
| `resource_smoke` | `LoadResource`, `LockResource` |

### Synthetic Stress / Composite

| Smoke | What it checks |
|-------|----------------|
| `synet` | composite networking workload |
| `synfs` | composite FS workload |
| `synfull` | composite "everything at once" workload |
| `synxtest` | DirectX-heavy composite |
| `syscall_stress` | high-rate syscall loop |
| `pe_stress` | rapid PE load / unload |

### Hello / Demo

| Smoke | What it checks |
|-------|----------------|
| `hello_pe` | smallest non-trivial PE: WriteConsole + ExitProcess |
| `hello_winapi` | WinMain + minimal window + message pump |
| `windowed_hello` | `WM_PAINT` with GDI primitives, `WM_TIMER`, registered WndProc |
| `dx_demo`, `dx_demo_window` | DirectX device + window cycle |
| `mini_browser` | composite HTTP + UI demo (uses winhttp + windowing) |
| `windows_kill` | real-world MSVC PE (~80 KB, 52 imports across 6 DLLs, SEH + TLS + resources) |

## Adding a New Smoke

The boilerplate is small. Per smoke:

1. Create `userland/apps/<name>/<name>.cpp` with a `main` or
   `WinMain`. Link against the minimal CRT and the DLL surface you
   need to exercise.
2. Print `[<topic>-smoke] PASS` on success or `[<topic>-smoke] FAIL:
   <reason>` on each check.
3. Add the smoke to `userland/apps/CMakeLists.txt` to get a build
   target.
4. If the smoke should run from a CI profile, add it to the dispatcher
   ([`kernel/test/smoke_profile.cpp`](../../kernel/test/smoke_profile.cpp)).

Keep the smoke focused — one binary, one topic. If you find yourself
adding "while we're at it, let's also exercise X," split into a
second binary.

## Boot-Smoke Profiles

The boot dispatcher's profiles are an orthogonal axis to the per-binary
catalogue:

- `None` — boot to desktop, run nothing extra
- `Bringup` — run the bring-up suite (no app spawn)
- `Ring3` — spawn the ring-3 verification harness
- `PeHello` / `PeWinapi` / `PeWinkill` — single named PE smoke
- `Linux` — Linux ABI verification harness

See [QEMU Smoke](../tooling/QEMU-Smoke.md) for the profile contract
and what each profile asserts at boot exit.

### Expensive self-tests are opt-in (`selftests=full`)

The heavy asymmetric-crypto boot self-tests — `RsaSelfTest`,
`X509SelfTest`, `X509VerifySelfTest` (RSA-4096 + ECDSA P-256/P-384, and
the ECDSA `EcSelfTest` it calls), `TlsSelfTest`, `TlsSocketSelfTest`, and
`PasswordHashSelfTest` (Argon2id) — cost **~200 s under QEMU TCG**. That
blew the budget in both directions: it made an interactive boot crawl
*and* ate the entire CI smoke timeout.

They are therefore **OFF by default everywhere** — the normal interactive
boot AND the CI `bringup` smoke gate — and run only behind an explicit
kernel-cmdline opt-in:

```
multiboot2 /boot/duetos-kernel.elf ... selftests=full
```

Wired via `g_expensive_selftests` + the `DUETOS_BOOT_SELFTEST_CI` macro in
`kernel/core/boot_bringup.cpp`. Deliberately **not** triggered by the
`smoke=` profile token, so the smoke gate stays fast. The smoke harness
(`tools/test/ctest-boot-smoke.sh`) asserts no crypto sentinels, so
skipping them under smoke breaks no CI check. Result: the `bringup` smoke
reaches `boot : metrics bringup-complete` in ~45 s of guest time instead
of ~520 s. A full on-target verification run passes `selftests=full` —
e.g. `DUETOS_EXTRA_CMDLINE="selftests=full" tools/qemu/run.sh`, or with
the bringup profile via `DUETOS_EXTRA_CMDLINE="selftests=full"
tools/test/profile-boot-smoke.sh bringup`.

**Where the per-PR crypto coverage actually lives: hosted ctest.** The
heavy crypto verification is pure computation over embedded byte
fixtures, so booting a whole kernel under TCG to run it is the wrong
tool. The same production crypto TUs are compiled and run **natively**
as `tests/host/test_ec.cpp` (ECDSA P-256/P-384) and
`tests/host/test_x509_verify.cpp` (RSA-4096 + ECDSA + 8-root chain
verify), driving the kernel's own `EcSelfTest()` / `X509VerifySelfTest()`
with host shims (`tests/host/crypto_host_shims.h`). They run in ~13 s
total in the existing `host-tests` CI job on **every** PR — no QEMU, no
TCG penalty. The `selftests=full` boot path is the on-target counterpart
for when you want to exercise the same code in the real kernel.

## Known Limits / GAPs

- **PE smokes alone.** No ELF smoke harness yet — ELF segment load is
  still on the way (see [Loader](../kernel/Loader.md)).
- **No randomised inputs.** Every smoke is deterministic. Fuzzing
  surfaces are tracked separately under
  [Attack Simulation](../security/Attack-Simulation.md).
- **No flaky-test detection.** A smoke that occasionally fails is
  treated as fully failing. Adding flake-rate accounting belongs in
  the CI layer.
- **Smoke count grows fast.** The line between "useful coverage" and
  "redundant ABI tour" gets blurry past ~150 binaries. Audit + prune
  is a Roadmap item.

## Related Pages

- [QEMU Smoke](../tooling/QEMU-Smoke.md) — boot dispatcher + profiles
- [Testing](../advanced/Testing.md) — full test pyramid (unit, kernel
  self-test, smoke)
- [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md)
- [Win32 Surface Status](Win32-Surface-Status.md) — per-export
  REAL/STUB/MISSING; smokes mostly exercise REAL surface
- [Win32 DLLs](../subsystems/Win32-DLLs.md) — what each smoke links against
