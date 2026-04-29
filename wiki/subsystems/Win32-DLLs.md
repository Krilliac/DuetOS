# Win32 Translator DLLs

> **Audience:** PE/Win32 devs, DLL authors
>
> **Execution context:** Userland — DLLs run in the target process's user-mode context
>
> **Maturity:** 29 DLLs preloaded into every Win32 PE process

## Overview

The Win32 user-mode DLLs in `userland/libs/` are **translators** that
adapt the Win32 ABI shape to DuetOS's native `int 0x80` syscall ABI.
They are *not* parallel subsystems — there is one TCP stack in the
kernel, one VFS, one registry, one window manager. The DLLs marshal
Win32 calls into syscalls and trust the kernel's return.

## DLL Inventory (canonical 29)

| DLL | Notes |
|-----|-------|
| `kernel32` | 155 exports — base API |
| `ntdll`    | 114 exports — NT API |
| `user32`   | 73 exports — windowing + messages |
| `gdi32`    | 44 exports — drawing |
| `kernelbase` | 44 forwarders to kernel32 |
| `ucrtbase` | 72 exports — modern UCRT (`fopen`, `printf`, …) |
| `msvcrt`, `msvcp140`, `vcruntime140` | Legacy CRT + C++ runtime |
| `dbghelp`, `psapi`, `advapi32` | Debug helpers, registry, security |
| `shell32`, `shlwapi` | Shell helpers, path utilities |
| `ole32`, `oleaut32` | COM (returns `CLASS_E_CLASSNOTAVAILABLE` today) |
| `winmm`, `bcrypt`, `crypt32` | Multimedia, crypto |
| `comctl32`, `comdlg32`, `version`, `setupapi` | Common controls, dialogs, version, setup |
| `iphlpapi`, `userenv`, `wtsapi32`, `dwmapi`, `uxtheme`, `secur32` | Net helpers, env, WTS, DWM/UX/secur32 |
| `ws2_32`, `wininet`, `winhttp` | Network sockets, HTTP |
| `d3d9`, `d3d11`, `d3d12`, `dxgi` | DirectX v0 (Clear + Present) |

Total: ~760 exports across 29 DLLs.

## Load Time

Every Win32-imports PE process preloads the full set at spawn. The PE
loader maps each DLL into the new process's `AddressSpace`, applies
relocations, and registers the DLL with the per-process DLL table.
Per-process cost: ~96 frames.

This is a deliberate v0 simplification. Lazy loading
(`LoadLibrary`-on-demand) would save frames for small PEs but
complicates the spawn path. Today every PE pays the same flat cost.

## Real Implementations Behind the Surface

The DLLs are not flat stubs. Real implementations land per slice:

- **Registry** (`advapi32`): hand-curated static tree with
  `HKLM\Software\Microsoft\Windows NT\CurrentVersion`, `HKCU\Volatile
  Environment`, etc. Real case-insensitive `RegOpenKeyEx` /
  `RegQueryValueEx` with `REG_SZ` / `REG_DWORD` and `ERROR_MORE_DATA`.
- **File I/O** (`ucrtbase`): `fopen` / `fread` / `fseek` / `ftell` /
  `fgets` / `fgetc` / `fclose` wrap a `FILE*` around a real kernel
  handle and route through `SYS_FILE_*`.
- **`printf` family** (`ucrtbase`): real `vsnprintf` + variants with
  `%d/%i/%u/%x/%X/%p/%s/%c/%%` + width + 0-pad + `l/ll/z` modifiers.
- **Environment variables** (`kernel32`): 17-entry static block
  (`PATH`, `TEMP`, `USERNAME`, `COMPUTERNAME`, `SYSTEMROOT`,
  `WINDIR`, …).
- **Time** (`kernel32`): `GetSystemTimeAsFileTime`,
  `QueryPerformanceCounter`, `GetTickCount{64}` — HPET-backed,
  100 Hz LAPIC timer.
- **Heap** (`kernel32`, `ucrtbase`): `malloc` / `free` / `HeapAlloc` /
  `HeapFree` route to `SYS_HEAP_*`, a real first-fit allocator with
  O(1) free-prepend on a 64 KiB per-process arena.
- **Atomics** (`kernel32`): full `Interlocked*` (32-bit and 64-bit)
  via `__atomic_*` intrinsics that compile to single `lock xadd` /
  `lock cmpxchg` / `xchg`.
- **Critical sections + SRW + InitOnce**: real spin-CAS on the
  caller's lock word with `SYS_YIELD` on contention.

## DLL Authoring Conventions

- Every userland DLL is **freestanding**. It does not include kernel
  headers and does not assume kernel internals. It issues syscalls
  and trusts the return.
- A function whose v0 implementation is not real is marked with
  `// STUB:` (see [Logging and Tracing > STUB / GAP markers](../kernel/Logging-And-Tracing.md)).
- A function that's correct on its happy path but missing a documented
  edge case is marked with `// GAP: <missing> -- <revisit>`.
- See [Subsystem Isolation](../kernel/Subsystem-Isolation.md) for the
  six rules every DLL must respect.

## Adding a New DLL

1. Create `userland/libs/<name>/` with `CMakeLists.txt` and the
   sources.
2. Build target produces `<name>.dll` (PE32+, x86_64).
3. Register the DLL in the preload set wired through
   `kernel/loader/dll_loader.cpp` so every spawning PE picks it up.
4. Add to the DLL inventory in [Win32 PE Subsystem](Win32-PE-Subsystem.md)
   and refresh `docs/sync-wiki.sh` output.

<!-- AUTO:dll_list -->
*38 DLLs preloaded into every Win32 PE process.*

| DLL | Exports (approx) | Path |
|-----|------------------|------|
| `advapi32` | 0 | `userland/libs/advapi32/` |
| `bcrypt` | 0 | `userland/libs/bcrypt/` |
| `comctl32` | 0 | `userland/libs/comctl32/` |
| `comdlg32` | 0 | `userland/libs/comdlg32/` |
| `crypt32` | 0 | `userland/libs/crypt32/` |
| `customdll2` | 0 | `userland/libs/customdll2/` |
| `customdll` | 0 | `userland/libs/customdll/` |
| `d3d11` | 0 | `userland/libs/d3d11/` |
| `d3d12` | 0 | `userland/libs/d3d12/` |
| `d3d9` | 0 | `userland/libs/d3d9/` |
| `dbghelp` | 0 | `userland/libs/dbghelp/` |
| `dwmapi` | 0 | `userland/libs/dwmapi/` |
| `dxgi` | 0 | `userland/libs/dxgi/` |
| `gdi32` | 0 | `userland/libs/gdi32/` |
| `iphlpapi` | 0 | `userland/libs/iphlpapi/` |
| `kernel32` | 0 | `userland/libs/kernel32/` |
| `kernelbase` | 0 | `userland/libs/kernelbase/` |
| `msvcp140` | 0 | `userland/libs/msvcp140/` |
| `msvcrt` | 0 | `userland/libs/msvcrt/` |
| `ntdll` | 0 | `userland/libs/ntdll/` |
| `ole32` | 0 | `userland/libs/ole32/` |
| `oleaut32` | 0 | `userland/libs/oleaut32/` |
| `psapi` | 0 | `userland/libs/psapi/` |
| `secur32` | 0 | `userland/libs/secur32/` |
| `setupapi` | 0 | `userland/libs/setupapi/` |
| `shell32` | 0 | `userland/libs/shell32/` |
| `shlwapi` | 0 | `userland/libs/shlwapi/` |
| `ucrtbase` | 0 | `userland/libs/ucrtbase/` |
| `user32` | 0 | `userland/libs/user32/` |
| `userenv` | 0 | `userland/libs/userenv/` |
| `uxtheme` | 0 | `userland/libs/uxtheme/` |
| `vcruntime140` | 0 | `userland/libs/vcruntime140/` |
| `version` | 0 | `userland/libs/version/` |
| `winhttp` | 0 | `userland/libs/winhttp/` |
| `wininet` | 0 | `userland/libs/wininet/` |
| `winmm` | 0 | `userland/libs/winmm/` |
| `ws2_32` | 0 | `userland/libs/ws2_32/` |
| `wtsapi32` | 0 | `userland/libs/wtsapi32/` |
<!-- /AUTO:dll_list -->

_Inventory above is auto-synced from `userland/libs/<dll>/` by
`docs/sync-wiki.sh sync`._

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md)
- [PE Loader](PE-Loader.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Win32 Thunks Compat Note](../advanced/Win32-Thunks-Compat-Note.md)
