# CustomOS — history

This document is the narrative of how CustomOS got to where it is today.
It's written for someone who's just landed in the repo and wants to know
**why** each subsystem looks the way it does before reading the code.

For day-to-day architectural reference, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Phase 0 — a kernel that could tell you what a CPU was doing

CustomOS began as an experiment in live CPU instrumentation. The earliest
commits brought up a minimal x86_64 kernel — Multiboot2 handoff, GDT/IDT,
serial console on COM1, a PIT-calibrated LAPIC timer — with one specific
purpose: to boot on commodity hardware and **dump everything the CPU was
doing** so we could reason about it.

The `inspect` subsystem (`kernel/debug/inspect.h`) is the direct descendant
of that original goal. Its subcommands still read like an RE toolkit:

- `inspect syscalls <path>` — scan an executable, find every
  `syscall` / `int 0x80` / `int 0x2E` / `sysenter` site, recover the
  preceding `mov eax, imm32`, and cross-reference the numbers against the
  NT / Linux / native syscall tables.
- `inspect opcodes <path>` — first-byte opcode histogram + instruction-
  class counters over a file's executable sections.
- `inspect arm` — latch the next spawn so we scan whatever gets loaded
  next.

That tooling was how we first understood what Windows binaries actually
call at the instruction level.

---

## Phase 1 — ring 3, native ABI, first PE load

With a kernel that could observe itself, the next step was to run
userland. A round-robin preemptive scheduler, per-CPU data, per-process
address spaces, W^X + SMEP/SMAP, `int 0x80` as the syscall gate. The
native ABI: `SYS_EXIT`, `SYS_WRITE`, `SYS_YIELD`, `SYS_GETPID`.

Then PE executables. The first PE loader took a freestanding `.exe`
produced by `clang --target=x86_64-pc-windows-msvc` + `lld-link` (no CRT,
no imports), parsed the DOS stub + NT headers + section table, mapped
each section into a fresh `AddressSpace` with the flags encoded in the
PE characteristics, and entered ring 3 at `ImageBase +
AddressOfEntryPoint`. A hand-written `hello.exe` printed via `SYS_WRITE`
and exited with `SYS_EXIT(42)`.

That slice proved the concept. The loader did not yet handle imports,
relocations, TLS, or anything a real Windows program needs.

---

## Phase 2 — PeReport: measuring the gap before closing it

Instead of charging at the next obstacle, we built a diagnostic. `PeReport`
is the function that runs before the loader even tries to map sections:
it walks every data directory in the PE, prints the section table, lists
every imported DLL and every imported function, counts base-relocation
blocks, counts TLS callbacks. It is called for every PE spawn —
including ones the loader will reject.

We then pointed it at `windows-kill.exe`: a real 80 KiB MSVC console
utility with 8 sections, 52 imports across 6 DLLs, SEH, TLS, and a
resource directory. The report told us exactly what "run Windows
binaries natively" would require:

- 12 user-mode DLLs (`kernel32`, `ntdll`, `advapi32`, `msvcp140`,
  `vcruntime140`, `ucrtbase`, 7 `api-ms-win-crt-*` apisets, `dbghelp`).
- ~80 distinct functions imported.
- Base relocations.
- TLS callback dispatch.
- SEH + unwind tables (`.pdata` + `.xdata`, `__C_specific_handler`).

That single log line — `[ring3] pe reject name="ring3-winkill"
reason=ImportsPresent` — with a 40-line preceding diagnostic, was the
project's forcing function for the next two stages.

---

## Phase 3 — hand-assembled Win32: the stubs page

Rather than ship 12 userland DLLs up front, the first Win32 subsystem
was a single page of hand-assembled trampolines mapped into every
Win32-imports process. Each imported `{dll, func}` pair resolved to a
6–30 byte stub that translated the Win32 x64 calling convention
(rcx/rdx/r8/r9) into our native `int 0x80` ABI (rdi/rsi/rdx/r10).

Examples from that period:

- `ExitProcess(code=rcx)` → `mov rdi, rcx; xor eax, eax; int 0x80; ud2`
  (9 bytes).
- `GetCurrentProcessId()` → `mov eax, 8; int 0x80; ret` (8 bytes).
- `memcpy`, `strlen`, `strcmp` — hand-written pure-assembly loops.

Over the course of many rounds this grew to ~122 `{dll, func}` entries
across 14 DLL names. Along the way the kernel grew the syscalls those
stubs needed: `SYS_HEAP_ALLOC` / `SYS_HEAP_FREE`, `SYS_MUTEX_*`,
`SYS_EVENT_*`, `SYS_TLS_*`, `SYS_FILE_*`, `SYS_THREAD_CREATE`.

The milestone for this phase: **`windows-kill.exe` ran end-to-end**.
A real MSVC-built Windows PE — imported, relocations applied, IAT
patched against the stubs page, entered at its CRT entry, parsed its
(missing) arguments, called `WriteFile` to print `Windows Kill 1.1.4 |
Windows Kill Library 3.1.3 Not enough argument. Use -h for help.`, and
exited cleanly. No VM, no emulation shell. Bits as shipped, running on
our scheduler, calling our syscalls, writing to our serial console.

---

## Phase 4 — real DLLs, real EATs

The stubs page worked, but was architecturally a shim. Real Windows
programs call `GetProcAddress(hmod, "RegQueryValueW")`. They expect a
DLL to be a **real PE** in the process's address space, with an
exportable EAT that `GetProcAddress` walks. Without that, anything
beyond statically-linked imports stopped at the stubs table.

The current phase rebuilt the Win32 subsystem around real DLLs:

1. **EAT parser** (`kernel/core/pe_exports.{h,cpp}`). Given a PE file
   buffer, validates `IMAGE_EXPORT_DIRECTORY` and exposes a tight
   iteration + lookup API. Forwarder exports detected and reported.
2. **DLL loader** (`kernel/core/dll_loader.{h,cpp}`). Maps a DLL PE
   into a process's `AddressSpace`, applies base relocations, parses
   the EAT.
3. **Per-process DLL table** (`Process::dll_images[]`). Registered by
   `ProcessRegisterDllImage` on load; walked by
   `ProcessResolveDllExport` at resolution time.
4. **`SYS_DLL_PROC_ADDRESS` syscall**. `GetProcAddress` in the shipped
   `kernel32.dll` trampolines into it; the kernel looks up the export
   by (HMODULE, name) against the per-process table.
5. **Forwarder chasing**. `CustomAddFwd = customdll.CustomAdd`-style
   forwarders get resolved recursively across the preloaded set at
   IAT-patch time.
6. **The retirement wave**. Every row in the flat stubs table that
   could be replaced with userland C code got replaced. Today the
   preload set ships 29 userland DLLs — `kernel32` (155 exports),
   `ntdll` (114), `ucrtbase` (72), `user32` (73), `gdi32` (44),
   `kernelbase` (44 forwarders), plus `msvcrt`, `msvcp140`,
   `vcruntime140`, `dbghelp`, `advapi32`, `shell32`, `shlwapi`,
   `ole32`, `oleaut32`, `winmm`, `bcrypt`, `psapi`, `crypt32`,
   `comctl32`, `comdlg32`, `version`, `setupapi`, `iphlpapi`,
   `userenv`, `wtsapi32`, `dwmapi`, `uxtheme`, `secur32`,
   `ws2_32`, `wininet`, `winhttp`, `d3d9`/`11`/`12`, `dxgi` —
   totalling ~760 exports.

Every Win32-imports process preloads the full set. Per-process cost:
~96 frames.

---

## Phase 5 — real implementations behind the surface

Having the surface is the prerequisite for making the surface do
something useful. The current focus is replacing "return NULL /
E_NOTIMPL / ERROR_NOT_SUPPORTED" stubs with real implementations wired
to kernel backends:

- **Registry** — `advapi32.dll` holds a hand-curated static tree with
  `HKLM\Software\Microsoft\Windows NT\CurrentVersion` (ProductName,
  CurrentVersion, CurrentBuild, EditionID, …), `HKCU\Volatile
  Environment`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet
  Settings`. `RegOpenKeyEx` / `RegQueryValueEx` walk it with real
  case-insensitive matching, REG_SZ / REG_DWORD support, size-only
  queries, ERROR_MORE_DATA on short buffer.
- **File I/O** — `ucrtbase.dll`'s `fopen` / `fread` / `fseek` / `ftell`
  / `fgets` / `fgetc` / `fclose` wrap a `FILE*` struct around a real
  kernel handle (0x100..0x10F) and route through `SYS_FILE_OPEN /
  READ / SEEK / CLOSE`. `stdin` / `stdout` / `stderr` are preallocated
  with synthetic handles that `fwrite` / `fputs` route to `SYS_WRITE(fd=1)`.
- **`printf` family** — `vsnprintf` + `sprintf` + `snprintf` + `printf`
  + `fprintf` with `%d/%i/%u/%x/%X/%p/%s/%c/%%` + width + 0-pad +
  `l/ll/z` modifiers. Real formatting, 1 KiB stack buffer, truncates
  silently at that ceiling.
- **Environment variables** — 17-entry static block (`PATH`, `TEMP`,
  `USERNAME`, `COMPUTERNAME`, `SYSTEMROOT`, `WINDIR`, …). `getenv` is
  case-insensitive per Win32 convention.
- **`GetSystemTimeAsFileTime` / `QueryPerformanceCounter` /
  `GetTickCount{64}`** — HPET-backed, 100 Hz LAPIC timer, real
  monotonic clock.
- **Heap** — `malloc` / `free` / `HeapAlloc` / `HeapFree` / `HeapSize`
  / `HeapReAlloc` all back to `SYS_HEAP_*`, which is a real first-fit
  allocator with O(1) free-prepend on a 64 KiB per-process arena.
- **Atomics** — full `Interlocked*` surface (32-bit and 64-bit) via
  `__atomic_*` intrinsics that compile to single `lock xadd` / `lock
  cmpxchg` / `xchg` instructions.
- **Critical sections + SRW locks + InitOnce** — real spin-CAS on the
  caller's lock word with `SYS_YIELD` on contention.

Verification is live. An end-to-end fixture (`userland/apps/reg_fopen_test/`)
opens `HKLM\Software\Microsoft\Windows NT\CurrentVersion`, queries
`ProductName`, gets back `"CustomOS"`, opens `/bin/hello.exe` via
`fopen`, reads two bytes via `fread`, confirms `"MZ"`, and prints every
step via `printf` with `%s`/`%u`/`%02x` formatting. Boot log:

```
[reg-fopen-test] ProductName="CustomOS" (type=1, size=9)
[reg-fopen-test] /bin/hello.exe first two bytes: 0x4d 0x5a
[reg-fopen-test] all checks passed
```

---

## The current gap to "runs arbitrary Windows apps"

For context on how far we actually are: Wine has been working for ~30
years and runs around 70-80% of Windows games. ReactOS has been working
for ~25 years and runs perhaps 50% of Win32 programs. CustomOS is at
approximately 1-2% of either. The surface is broadly covered, but
most of the interesting subsystems (compositor-backed windows, real
sockets, COM runtime, DirectX-to-Vulkan translation) still return
documented-error sentinels rather than running.

What does work today:
- Freestanding Win32 PEs (no CRT, direct int 0x80) — since Phase 1.
- MSVC-built console PEs with CRT, threads, mutexes, events, atomics,
  printf, file I/O, registry queries — since Phase 4 / 5.
- `windows-kill.exe` (a real shipped third-party Windows binary) —
  since the end of Phase 3.

What doesn't work:
- Windowed programs (user32 / gdi32 return NULL at CreateWindow).
- Networking (ws2_32 returns WSAENETDOWN).
- Any program whose happy path requires a COM instance, a loaded DLL
  by path, actual file writes, or DirectX.

Each of those is its own multi-slice implementation track. The DLL
surface is a scaffolding for making them possible, not a substitute
for doing the work.

---

## How to read the rest of the tree

- `CLAUDE.md` — the authoritative project context, coding standards,
  and anti-bloat guidelines.
- `docs/ARCHITECTURE.md` — the layering model, how a Win32 call
  travels from the PE's `call qword [iat]` to a kernel syscall.
- `kernel/core/pe_loader.cpp` — PE spawn path with diagnostic
  PeReport.
- `kernel/core/pe_exports.cpp` — EAT parser.
- `kernel/core/dll_loader.cpp` — DLL loader and via-DLL resolver.
- `userland/libs/*/` — the 29 userland DLL sources.
- `.claude/knowledge/` — working notes accumulated during development.
  Many of these reference internal slice/batch numbering that does not
  appear in public-facing code comments; they are kept as a historical
  log, not as current specification.
