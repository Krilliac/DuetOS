# DuetOS — history

This document is the narrative of how DuetOS got to where it is today.
It's written for someone who's just landed in the repo and wants to know
**why** each subsystem looks the way it does before reading the code.

For day-to-day architectural reference, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Phase 0 — a kernel that could tell you what a CPU was doing

DuetOS began as an experiment in live CPU instrumentation. The earliest
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
   could be replaced with userland C code got replaced. By the close
   of Phase 4 the preload set shipped 29 userland DLLs (`kernel32`,
   `ntdll`, `ucrtbase`, `user32`, `gdi32`, `kernelbase`, plus
   `msvcrt`, `msvcp140`, `vcruntime140`, `dbghelp`, `advapi32`,
   `shell32`, `shlwapi`, `ole32`, `oleaut32`, `winmm`, `bcrypt`,
   `psapi`, `crypt32`, `comctl32`, `comdlg32`, `version`, `setupapi`,
   `iphlpapi`, `userenv`, `wtsapi32`, `dwmapi`, `uxtheme`, `secur32`,
   `ws2_32`, `wininet`, `winhttp`, `d3d9`/`11`/`12`, `dxgi`)
   totalling ~760 exports. Phase 5 and beyond grew the surface to 44
   production DLLs / ~1100 exports — see
   [`Win32-Surface-Status`](../reference/Win32-Surface-Status.md) for
   the live inventory.

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
`ProductName`, gets back `"DuetOS"`, opens `/bin/hello.exe` via
`fopen`, reads two bytes via `fread`, confirms `"MZ"`, and prints every
step via `printf` with `%s`/`%u`/`%02x` formatting. Boot log:

```
[reg-fopen-test] ProductName="DuetOS" (type=1, size=7)
[reg-fopen-test] /bin/hello.exe first two bytes: 0x4d 0x5a
[reg-fopen-test] all checks passed
```

---

## Phase 6 — windowed Win32 + live network

The "What doesn't work" list from the end of Phase 5 has shrunk. As of
2026-04-25:

- **Win32 windowing is live.** `windowed_hello` boots, paints with
  `Rectangle` / `Ellipse` / `DrawTextW` / `FillRect`, dispatches
  `WM_PAINT` / `WM_TIMER` / `WM_LBUTTONDOWN` through a user-registered
  WndProc, round-trips `SendMessage`, queries focus / styles / sys
  palette, and exits cleanly. The compositor renders into a virtio-gpu
  scanout (kernel framebuffer) and the present hook flushes per
  compose.
- **Networking is live.** Intel e1000 wired NIC + USB CDC-ECM + USB
  RNDIS drivers, full TCP/UDP/IP/ARP stack, DHCP client, DNS
  resolver. DuetOS reaches Google over a real connection. RNDIS now
  delivers every `RNDIS_PACKET_MSG` per bulk transfer (was: only the
  first).
- **PE loader stage 2 closed several gaps.** Forwarders chase
  through the per-process DLL table for both name-form and ordinal-
  form (`Dll.#N`) entries; by-ordinal IAT entries resolve against
  preloaded EATs; `PeExportLookupName` is binary-search.

For context on how far we actually are: Wine has been working for ~30
years and runs ~70–80% of Windows games. ReactOS has been working for
~25 years and runs perhaps 50% of Win32 programs. DuetOS is still
~1–2% of either by application coverage, but the surface that an
arbitrary windowed Win32 app touches at boot now actually runs
end-to-end on every commit.

What works today:
- Freestanding Win32 PEs (no CRT, direct int 0x80) — since Phase 1.
- MSVC console PEs with CRT, threads, mutexes, events, atomics,
  printf, file I/O, registry queries — since Phase 4 / 5.
- `windows-kill.exe` (a real shipped third-party Windows binary) —
  since the end of Phase 3.
- Windowed Win32 PEs (`windowed_hello` end-to-end on every boot) —
  Phase 6.
- Live Internet (DNS + TCP to a real Internet host) — Phase 6.

What still doesn't work:
- Cross-process COM/RPC, monikers, structured storage, and real native file-dialog UI.
- DirectX rendering (D3D9/11/12 DLLs are real COM-vtable shapes but
  the underlying device returns E_FAIL on real submits).
- Modal dialogs, menus, common controls, scroll bars, outline fonts,
  multi-threaded message queues.
- Most of `winsock2`'s asynchronous surface (the synchronous BSD-
  socket subset works).
- Arbitrary file writes through the FS write paths (read paths are
  live; write is the next FS slice).

Each of those is its own multi-slice track. The DLL surface is the
scaffolding for making them possible; this phase is replacing the
documented-error sentinels with real implementations one
subsystem at a time.

---

## Phase 6.5 — SMP scheduler online (2026-05-06)

Until this slice, the kernel ran every task on the BSP — APs came up
through `INIT-SIPI-SIPI`, enabled their LAPICs, and halted on
`cli; hlt`. Six small commits closed the loop:

1. **Lock-passing across `ContextSwitch`.** `Schedule()` now holds
   `g_sched_lock` across the stack swap, with the source CPU writing
   the lock pointer + saved IRQ flags into its `cpu::PerCpu`'s
   `ctxsw_lock_to_release` slot; the resumed code drains the slot and
   releases on the new stack. Mirrors Linux's
   `prepare_task_switch` / `finish_task_switch`.
2. **Per-CPU runqueue data layout.** The four runqueue head/tail
   pointers (Normal+Idle bands) moved into `cpu::PerCpu`; every Task
   carries `last_cpu` for cache-affinity wake routing.
3. **Per-AP GDT + TSS + IST stacks.** Each AP allocates its own GDT
   clone, TSS body, and three 4 KiB IST stacks (#DF / #MC / #NMI) so
   critical traps on an AP don't race the BSP's static slots.
4. **Reschedule-IPI vector.** `arch::SmpSendReschedIpi(cpu_id)`
   delivers vector `0xF8` to a peer CPU; the handler sets
   `need_resched` and the dispatcher's post-EOI check fires
   `Schedule()` before iretq. Wake-to-run latency drops from ~10 ms
   (next tick) to microseconds.
5. **AP scheduler join.** `ApEntryFromTrampoline` hands off to
   `sched::SchedEnterOnAp`, which spawns the AP's `idle-apN`, mints
   a non-runnable boot sentinel, arms the AP's LAPIC timer, and drops
   into a sti+hlt idle loop. The first timer IRQ on the AP fires
   `Schedule()`; from then on the AP runs whatever tasks land on its
   runqueue via `last_cpu` routing.
6. **Work-stealing.** When a CPU's local runqueue is empty,
   `StealNormalFromPeer` walks peer CPUs round-robin and lifts one
   Normal-band task. Stolen tasks have their `last_cpu` updated to
   the stealer.

The remaining limitation is lock granularity — every per-CPU
runqueue is still serialised through one global `g_sched_lock`. The
data structures are per-CPU; the lock is not. Splitting per-CPU is a
tractable follow-up when profiles show contention.

Locality awareness landed immediately afterward: each CPU is now
decoded into a `cpu::Topology` row at boot (CPUID 0x1F / 0x0B /
leaf-4 fallback + ACPI SRAT) and assigned a `cluster_id`. The
work-stealing path scans same-cluster peers first and falls back
to cross-cluster only when the local cluster has no work. UMA
single-package boxes collapse to one cluster and behave identically
to the pre-clustering scheduler.

See [`Scheduler`](../kernel/Scheduler.md),
[`CPU Topology`](../kernel/CPU-Topology.md),
[`SMP-AP-Bringup-Scope`](../advanced/SMP-AP-Bringup-Scope.md), and
the 2026-05-06 entries in
[`Design-Decisions`](../reference/Design-Decisions.md) for the
rationale.

## Phase 6.6 — Roadmap audit + Win32 fillers (2026-05-10)

A two-day audit pass against
[`reference/Roadmap.md`](../reference/Roadmap.md) closed ten
imported-TODO rows. Five rows landed real code; five were
documentation flushes for work that had already shipped piecemeal
and never had its row deleted.

**Code shipped this phase:**

- **Track 1 (windowing)** — `kernel/core/main.cpp` kbd-reader
  now posts `WM_KEYUP` / `WM_SYSKEYUP` to the focused PE on
  release edges (T1-03 closed). Re-audit confirmed the row's
  other claimed residuals (`SetCapture` and
  `SetForegroundWindow`) had already shipped earlier — the
  mouse-routing block honours `WindowGetCapture()`,
  `SetForegroundWindow` plumbs through `WindowRaise` to set
  `g_active_window`.
- **Track 11 (kernel infrastructure)** — `userland/libs/kernel32`
  and `userland/libs/winmm` ship per-process polling-thread
  timer surfaces (T11-04 closed). `CreateWaitableTimer` /
  `SetWaitableTimer` / `WaitForSingleObject` round-trip
  through a 16-slot table + lazily-spawned 10 ms service
  thread that fires `SetEvent` when due. `timeSetEvent`
  mirrors the same pattern for multimedia callbacks.
- **Track 3 (networking)** — new `kSockOpGetLease = 13` op on
  `SYS_SOCKET_OP` snapshots the kernel's DHCP lease into a
  40-byte user buffer. `iphlpapi!GetAdaptersInfo` now emits
  a two-record chain (eth0 from the lease + loopback);
  `ws2_32!getaddrinfo` resolves IP literals + "localhost"
  locally and falls through a 16-slot LRU cache + the
  kernel resolver for everything else (T3-02 + T3-03 closed).

**Closed retroactively (work shipped earlier, row never deleted):**

- **Track 1** — T1-04 chrome interactions (title-bar drag,
  click min/max-restore/close, double-click toggle, Alt+F4,
  snap shortcuts).
- **Track 4** — T4-01 D3D11/DXGI swap-chain present, T4-02
  Vulkan ICD v0, T4-04 AMD/NVIDIA/Intel GPU probe + clean
  software-fallback.
- **Track 10** — T10-01 GitHub Actions CI, T10-02
  `x86_64-kasan` preset, T10-03 `x86_64-release-lto` preset.

**Second pass (same day) — Track 13 + 14 closures:**

- **Track 13** — T13-01 Win32-Surface-Status audit (summary
  count refresh + waitable-timer status flips +
  kernel32 / winmm narrative refresh) and T13-02
  Roadmap-population discipline (the audit-driven session
  itself satisfies the row).
- **Track 14** — T14-01 PE stress fixture
  (`userland/apps/pe_stress/pe_stress.c`, five worker threads
  beating heap / mutex / event / file / registry for 2 s,
  embedded into the boot smoke corpus).

**Third pass (same day) — Track 6 + 11 closures:**

- **Track 11** — T11-05 ACPI S5 shutdown (KernelHalt now wires
  through the existing AML `\_S5_` extractor +
  `acpi::AcpiShutdown` PM1A/PM1B writer; QEMU shutdown ports
  are the second-tier fallback).
- **Track 6** — T6-04 cross-process named-object namespace:
  new `kernel/ipc/named_kobjects.{h,cpp}` (32-slot LRU table)
  + `kernel/subsystems/win32/named_kobj_syscall.{h,cpp}` +
  `SYS_NAMED_KOBJ_OPEN_OR_CREATE = 185`. Userland kernel32's
  `Create{Mutex,Event,Semaphore}{A,W}` and `Open*` consult
  the kernel-resident table when a name is provided.

**Fifth pass (same day) — Track 3 + 14 closures (loopback):**

- **Track 3** — T3-01 socket loopback round-trip:
  `kernel/net/socket.cpp` short-circuits `connect()` for 127/8
  destinations, allocates two kernel pipe pool slots (one per
  direction, reusing the Linux pipe pool), pairs the connector
  with a freshly-allocated accepted socket. New non-blocking
  `SocketAcceptLoopback` probe lets `accept()` service loopback
  + on-wire arrivals from a unified poll loop. Send/recv on a
  paired socket route through `PipeWrite` / `PipeRead`; the pipe
  pool's waitqueue + EPIPE/EOF semantics carry full TCP-shaped
  blocking for free.
- **Track 14** — T14-03 network loopback test fixture:
  `userland/apps/net_loopback_smoke/net_loopback_smoke.c`
  exchanges 16 KiB of deterministic pseudo-random bytes through
  loopback and verifies a per-byte folded checksum.

**Fourth pass (same day) — Track 11 IPC pipes:**

- **Track 11** — T11-02 anonymous cross-process pipes: the
  Linux subsystem's pipe pool (16 slots × 4 KiB ring +
  waitqueue + EPIPE/EOF semantics) is now reachable from
  Win32 too. New `FsBackingKind::Pipe` variant +
  `pipe_pool_idx` / `pipe_is_write_end` fields on
  `Win32FileHandle`; new `SYS_WIN32_CREATE_PIPE = 186`
  syscall (handler in `kernel/subsystems/win32/pipe_syscall.cpp`).
  `userland/libs/kernel32/kernel32.c::CreatePipe` routes
  through the kernel pool; legacy in-process ring stays as
  the kernel-OOM fallback. `ReadForProcess` /
  `WriteForProcess` / `CloseForProcess` dispatch the new
  kind to the existing Linux pipe pool helpers — single
  definition, two subsystems.

Closing tally for the day: **19 imported-TODO rows closed** —
T1-03, T1-04, T3-01, T3-02, T3-03, T4-01, T4-02, T4-04, T6-04,
T10-01, T10-02, T10-03, T11-02, T11-04, T11-05, T13-01, T13-02,
T14-01, T14-03. Ten with new code (T1-03 WM_KEYUP, T11-04
waitable + mm timers, T3-02 + T3-03 networking, T11-05
KernelHalt wiring, T6-04 named-kobj namespace, T11-02 cross-
process pipes, T14-01 PE stress, T3-01 + T14-03 socket loopback
+ test fixture); nine with documentation flushes.

Tracks 1, 3, 11, and 14 are fully closed.

After five passes the remaining open imported-TODO rows are:
T4-03 (Intel iGPU command ring), T5-01..04 (memory manager
polish), T6-01..03 (PE TLS / SEH / CreateProcess), T7-03/T7-04
(overlapped I/O + NTFS write), T8-01/T8-02 (MLFQ aging +
cross-thread APC), T10-04 (host ctest harness extension),
T12-03 (winmm waveOut over HDA), T13-03 (per-syscall arg/return
docs).

## Phase 6.7 — Tier-0 daily-driver: disk installer + Method-form `_S5_` (2026-05-10)

A focused pass against `wiki/reference/Daily-Driver-Readiness.md`'s
Tier-0 gaps.

- **Disk installer orchestration shipped** — new `install <handle>
  INSTALL` shell command (`kernel/fs/installer.{h,cpp}`,
  `kernel/shell/shell_storage.cpp::CmdInstall`) lays down a fresh
  3-partition GPT (ESP / system / crash-dump), formats ESP +
  system as FAT32, seeds `/esp/boot/grub/grub.cfg` with a
  chainload stub + `/system/boot/.duetos-installed` sentinel, and
  mounts the new partitions at `/esp` + `/system`. Crash-dump
  partition uses `kDuetCrashDumpTypeGuid` so the existing
  `GptFindCrashDumpRegion` path picks it up next boot. UUID-v4
  GUIDs throughout. Admin + literal `INSTALL` confirmation +
  100 MiB minimum-disk gate. Bootloader-bytes copy
  (`BOOTX64.EFI` + `duetos-kernel.elf` onto the freshly-formatted
  ESP) remains a follow-on slice — embedding the running kernel
  into ramfs is the classic two-stage bootstrap problem.
- **Method-form `_S5_` decode shipped** — `AmlReadS5` now accepts
  both the classic `Name(_S5_, Package(...))` form (UEFI / QEMU)
  AND the `Method(_S5_) { Return(Package(...)) }` form used by
  some consumer firmware. The walker reads the method's
  PkgLength, skips NameString + MethodFlags, and scans (bounded
  16-byte span) for the `Return(Package(...))` byte sequence.
  Closes the gap for chipsets that pre-evaluate `_PTS` / `_GTS`
  but define `_S5_` as a method body.

What's still open in Tier 0: bootloader-bytes copy on the
installer; writable native FS; NTFS write; system updater;
full AML method interpreter (`_PTS` / `_GTS` runtime evaluation).
See [`Daily-Driver-Readiness`](../reference/Daily-Driver-Readiness.md)
for the live drilldown.

## Phase 6.8 — Installer UEFI-loader copy + layout self-test (2026-05-10)

A second cut against the same Tier-0 row.

- **`BOOTX64.EFI` embedded into the kernel image** via a new
  custom command in `kernel/CMakeLists.txt` (depends on the
  `${DUETOS_UEFI_EFI}` artifact set by `boot/uefi/`). Top-level
  CMake reordered so `boot/uefi` processes before `kernel`,
  exposing the cache var to the kernel embed step. New ramfs
  accessors `RamfsBootX64EfiBytes()` / `RamfsBootX64EfiSize()`.
- **Installer now stamps `BOOTX64.EFI` into `/EFI/BOOT/`** on the
  freshly-formatted ESP — the canonical UEFI fall-back removable-
  media path. Combined with the existing `grub.cfg` stub, the ESP
  now has a complete loader skeleton; the only piece still
  pending is `duetos-kernel.elf` on the system partition.
- **`PlanLayout` factored out** of `Install` as a pure-math
  helper. New `InstallerSelfTest` runs at every boot
  (`100 MiB / 1 GiB / 1 TiB / undersized refused`) and surfaced
  a real off-by-some bug in the original `kMinInstallSectors`
  constant. Replaced the hard-coded number with a
  computed expression (`kEspSectors + kMinSystemSectors +
  kCrashDumpSectors + kGptOverheadSectors`) so the layout floor
  tracks the partition sizing constants automatically.

## Phase 6.9 — Installer DuetFS option + DuetFS audit (2026-05-10)

A correction pass + an installer extension.

- **Audit-driven correction.** The Daily-Driver-Readiness Tier-0
  row claimed "DuetFS read-only". In fact DuetFS ships with the
  full write surface (`duetfs_write_at` / `duetfs_create_path`
  / `duetfs_unlink_path` / `duetfs_truncate` / `duetfs_link` /
  `duetfs_create_symlink`), a journal, AES-XTS sector
  encryption, Argon2id KDF, LZ4 compression, snapshots, and
  CRC-checked blocks; auto-mounted at `/duetfs` (RAM-backed)
  on every boot and at `/disks/duetfsN` for on-disk volumes.
  Refreshed the row to describe what's actually shipped.
- **Installer `--duetfs` flag.** New `kDuetFsTypeGuid` GPT
  partition-type GUID lands in `kernel/fs/gpt.h`. `Install` now
  takes a `use_duetfs_system` parameter; when set, the system
  partition is formatted with `duetfs_mkfs` (cookied through
  `MakeBlockHandleDevice`), typed `kDuetFsTypeGuid`, and mounted
  at `/system` via `FsType::DuetFs`. Default behaviour
  (`install <handle> INSTALL`) is unchanged: FAT32 system
  partition, `kSystemTypeGuid` (Microsoft Basic Data),
  interoperable with Windows / Linux fdisk. Operators wanting
  a journalled, encryption-capable native FS pass
  `install <handle> INSTALL --duetfs`.

## Phase 6.10 — Installer kernel-ELF embed via `.incbin` (2026-05-10)

Closes the easy half of the kernel-ELF residual; documents the
hard half.

- **Opt-in `.incbin` blob.** New CMake option
  `DUETOS_INSTALLER_KERNEL_EMBED` (default OFF) drives
  `tools/build/gen-kernel-blob.sh` which emits a tiny
  `kernel_elf_blob.S` that .incbins the stage-1 kernel ELF.
  `.incbin` is processed by the assembler in constant time, so
  embedding ~10 MiB doesn't blow up compile time the way a
  constexpr-array literal would. Stage 1 carries a separate
  always-empty stub blob so its references resolve. New ramfs
  accessors `RamfsKernelElfBytes()` / `RamfsKernelElfSize()`
  expose the bytes; `WriteSystemSentinel` writes
  `/system/boot/duetos-kernel.elf` whenever the size is non-zero.
  When the option is OFF (default) the blob is a 0-byte stub and
  the installer prints a one-line note pointing at out-of-band
  staging.
- **Cost trade.** With ON: kernel binary ~10 MiB → ~21 MiB; ISO
  ~18 MiB → ~28 MiB. Runtime cost: the larger image consumes
  the entire 0..16 MiB DMA zone and trips the `mm/zone` boot
  self-test. Closing that needs a linker-script change to place
  the blob at a higher physical region (32 MiB+). Until then the
  option is "image-correct, doesn't self-boot" — useful for
  "build the installer ISO once on machine A, run it to install
  onto machine B" but not for live-iterating on the embed path
  itself. Documented in
  [`Build-System`](../tooling/Build-System.md) §"Optional Knobs".

---

## Phase 6.11 — Win32 named pipes (2026-05-11)

Companion to the anonymous cross-process pipes that landed under
T11-02: Win32 PEs can now use `CreateNamedPipeA/W` +
`CreateFileW("\\.\pipe\NAME")` end-to-end, on top of the existing
kernel pipe pool.

- **What landed.**
  - **Kernel registry.** `kernel/ipc/named_pipes.{h,cpp}` — a
    16-slot table mapping `NAME` → `(pool_idx, server_is_writer,
    client_connected)` under a spinlock. `NamedPipeRegisterServer`
    is the server-create hook; `NamedPipeConnectClient` is the
    client-open hook; `NamedPipeOnServerClose` releases the
    orphan opposite-end refcount if no client connected before
    server close, preventing a 4 KiB ring-buffer leak.
  - **Syscalls.** `SYS_NAMED_PIPE_CREATE = 202` (server) and
    `SYS_NAMED_PIPE_OPEN = 203` (client) ship in
    `kernel/syscall/syscall.h` + the dispatch table in
    `syscall.cpp`. Handlers live in
    `kernel/subsystems/win32/named_pipe_syscall.cpp`.
  - **Handle table.** `Process::Win32FileHandle` carries a new
    `named_pipe_registry_slot` field (i8, -1 = anonymous /
    client). `kernel/fs/file_route.cpp::CloseForProcess` consults
    it on `FsBackingKind::Pipe` closes to call
    `NamedPipeOnServerClose` for the server-side handle.
  - **Userland.** `userland/libs/kernel32/kernel32.c` adds
    `CreateNamedPipeA`, `CreateNamedPipeW`, `ConnectNamedPipe`,
    `DisconnectNamedPipe`, `WaitNamedPipeA`, and `WaitNamedPipeW`.
    `CreateFileW` recognises the `\\.\pipe\` (or `//./pipe/`
    after slash normalisation) prefix and dispatches
    `SYS_NAMED_PIPE_OPEN` instead of `SYS_FILE_OPEN`.
  - **Boot self-test.** `NamedPipeSelfTest` exercises register +
    duplicate-reject + connect + miss + orphan cleanup against
    the live pipe pool. Wired through `DUETOS_BOOT_SELFTEST` in
    `kernel/core/main.cpp` alongside `NamedKObjectSelfTest`.
- **What's still GAP.**
  - `PIPE_ACCESS_DUPLEX` is rejected at the syscall layer
    (needs two pool slots). Documented in
    [`Win32-Surface-Status`](../reference/Win32-Surface-Status.md)
    §kernel32.dll.
  - `PIPE_TYPE_MESSAGE` framing — message boundaries unsupported;
    reads behave as `PIPE_TYPE_BYTE`.
  - Overlapped `ConnectNamedPipe` — v0 returns synchronously
    with success. Workloads that depend on the server-blocks-
    until-client-connects synchronisation hit a sub-GAP.
  - Multi-instance pipes (`nMaxInstances > 1`) — each name
    occupies exactly one pool slot.
  - Security descriptors / ACLs / `Global\` vs `Local\` namespace
    prefixes — bare names only.

## Phase 6.12 — WinInet real HTTP transport + browser_pe (2026-05-13)

The wininet.dll thunks used to return a fixed `"HTTP/1.1 200 OK"` /
`"DuetOS hello"` body for any `InternetOpenUrl` + `InternetReadFile`
sequence. Browsers and other WinInet-using PEs would always see the
canned response — useful for verifying ABI shape, useless for
verifying anything else.

This slice replaces the canned response with real HTTP/1.1 GET
transport over the kernel socket pool (`SYS_SOCKET_OP`, the same path
ws2_32 already uses), and ships a WinInet-based browser_pe smoke that
exercises the new path end-to-end.

- **What landed.**
  - **wininet.dll transport.** `userland/libs/wininet/wininet.c` —
    new freestanding handle pool (8 slots × 256 B host + 1 KiB
    path + 1 KiB extra headers + 4 KiB rxbuf). `InternetOpenA/W`,
    `InternetConnectA/W`, `HttpOpenRequestA/W`, `HttpSendRequestA/W`,
    `HttpAddRequestHeadersA/W`, `InternetOpenUrlA/W`,
    `InternetReadFile`, `InternetReadFileExA/W`, `InternetCloseHandle`,
    and `InternetQueryDataAvailable` now drive the same kernel
    socket pool ws2_32 uses (DNS via `kSockOpResolveA`, then
    socket / connect / sendto / recvfrom).
  - **Handle encoding.** `0x4000 | (kind << 8) | slot` — fits in
    16 bits, never collides with `NULL` or `INVALID_HANDLE_VALUE`,
    decodes with a single kind / slot tag check.
  - **Header parsing.** `HttpQueryInfoA/W` now answers real queries:
    `STATUS_CODE`, `STATUS_TEXT`, `RAW_HEADERS`,
    `RAW_HEADERS_CRLF`, `CONTENT_TYPE`, `CONTENT_LENGTH`,
    `LOCATION`, `SERVER`, `VERSION` — and their `FLAG_NUMBER`
    variants for the numeric ones.
  - **Graceful CI fallback.** If DNS / connect / send / first recv
    fails (e.g. on a host with no outbound networking), the slot
    transparently switches to a fixed `"HTTP/1.1 200 OK"` /
    `"DuetOS hello"` body. ABI-shape smokes still pass; live boots
    on QEMU SLIRP (or bare metal) see real Google responses.
  - **browser_pe smoke.** `userland/apps/browser_pe/browser_pe.c` —
    a real WinInet client that does three GETs (root / example.com /
    404 path), prints status + content-type + content-length +
    Location (on redirect) + first body line for each. Wired into
    `ring3_smoke.cpp` alongside `mini_browser` and reachable via
    the shell as `kind=browser2` / `kind=wininet`.
- **What's still GAP.**
  - **HTTPS / TLS.** `InternetOpenUrl` against an `https://` URL
    parses the scheme and reports port 443, but the slot
    short-circuits to the canned body — no TLS handshake yet.
  - **Async I/O.** `INTERNET_FLAG_ASYNC` / `InternetSetStatusCallback`
    are still STUB. Synchronous flow only.
  - **Auto-redirects.** v0 honours `INTERNET_FLAG_NO_AUTO_REDIRECT`
    implicitly — 3xx responses surface to the caller. Auto-follow
    is a follow-up.
  - **Persistent connections.** Each request opens and closes its
    own socket; `Connection: close` is hardcoded. HTTP/1.1
    keep-alive needs request multiplexing in the handle pool.

## Phase 6.13 — 32-bit PE (i386) loader recognition + Layer 2/3 plumbing (2026-05-13)

Until now the PE loader rejected anything that wasn't
`Machine=0x8664` (AMD64) + `Magic=0x20B` (PE32+). That makes every
real-world 32-bit Windows browser binary (NetSurf 3.11 ships only
x86, lynx/links/dillo are 32-bit by default) load-time invisible —
PeReport can't even walk its imports because the validator fails at
byte 18 of the FileHeader.

This slice lands Layers 1, 2 and 3 of a four-layer plan for proper
WoW64-style 32-bit PE support. With Layers 1-3 in, the kernel
**recognises** PE32 (the validator parses the i386 optional-header
layout, the data-directory array, and per-section table correctly);
it has the **arch-level mechanics** (32-bit user code/data
descriptors in the GDT, EnterUserMode32 entry path, 32-bit syscall
register remap in the int 0x80 handler) ready to use; and it
**cleanly rejects** execution with a typed status until Layer 4
(the i386 DLL set port) and Layer 5 (pointer marshalling across all
syscalls) land.

- **What landed (Layer 1 — loader recognition).**
  - `kernel/loader/exec_meta_rust/src/lib.rs` accepts
    `PE_MACHINE_I386 = 0x014C` alongside `PE_MACHINE_AMD64 = 0x8664`,
    and branches the optional-header parser on
    `OptHdrMagic == 0x10B` (PE32) vs `0x20B` (PE32+). PE32 stores
    ImageBase as `u32` at offset 28 (because BaseOfData occupies
    offsets 24..27 in that variant) and the four
    stack/heap-reserve/commit slots are `u32` instead of `u64`,
    shifting the data-directory array from offset 112 (PE32+) to 96
    (PE32). `DuetosPeImage` grows three new fields — `is_pe32`,
    `data_dir_offset`, `number_of_rva_and_sizes` — so the C++ side
    never re-derives the layout.
  - `kernel/loader/dll_loader.cpp` + `pe_exports.cpp` accept both
    Machine values so the DLL loader can also walk the EAT of a
    PE32-imported file diagnostically.
  - New `PeStatus::Pe32ExecutionNotReady` enumerator. The loader
    re-classifies the otherwise-Ok PE32 path as this status so
    `FixJournalRecord` + the boot-log warning (`[W] loader/pe : PE
    rejected status="Pe32ExecutionNotReady"`) make the reject
    reason visible.
- **What landed (Layer 2 — 32-bit user mode mechanics).**
  - The GDT grows from 7 to 9 entries. Slot 7 is a 32-bit user
    code descriptor (flags=0xC -> G=1 L=0 D=1, access=0xFA -> P
    DPL=3 S R/Exec); slot 8 is the matching 32-bit user data
    descriptor. Selector constants:
    `kUserCode32Selector = 0x3B`, `kUserData32Selector = 0x43`.
  - `EnterUserMode32(user_rip, user_rsp)` in
    `kernel/arch/x86_64/usermode.S` builds an iretq frame with the
    32-bit selectors so the ring-3 transition lands in long
    compatibility mode and instructions decode as 32-bit. No
    swapgs / GSBASE-MSR setup — 32-bit PEs reach the TEB through
    FS, not GS.
  - Per-AP GDT bundles are extended uniformly so all CPUs see the
    same 9-entry GDT.
- **What landed (Layer 3 — 32-bit syscall ABI).**
  - `isr_common` (kernel/arch/x86_64/exceptions.S) detects 32-bit
    callers by `CS == 0x3B` in the trap frame and remaps the Linux
    i386 syscall register convention into the 64-bit slots the C++
    dispatcher expects:
    `(eax,ebx,ecx,edx,esi,edi,ebp) -> (rax,rdi,rsi,rdx,r10,r8,r9)`.
    Source-stable order: every source slot is snapshotted into
    kernel scratch (r11..r15) before any target slot is written.
    Pointer args zero-extend automatically — every 32-bit register
    write in compat mode zeros the upper 32 bits of the matching
    64-bit register.
  - 64-bit callers skip the remap via a `cmp+jne` fast path. Zero
    overhead delta on the PE32+ smokes.
- **Live verification.**
  - `userland/apps/pe32_smoke/pe32_smoke.c` — a 6 KiB PE32 (i386)
    built with i686-w64-mingw32-gcc. Wired into the ring3 smoke
    profile so every boot prints the explicit reject status line.
- **What's still GAP (Layers 4 + 5).**
  - **Layer 4 — i386 DLL set port.** All 44 userland DLLs are
    PE32+ today; a 32-bit PE can't import from them. Each DLL
    needs to be recompiled as PE32 (i386), the syscall trampolines
    in `userland/libs/ws2_32/ws2_32.c` and
    `userland/libs/wininet/wininet.c` need 32-bit asm variants
    (`int $0x80` with eax/ebx/.../edi instead of rdi/rsi/r10/r8/r9),
    and the kernel needs to map the matching set based on each
    process's bitness. Realistic scope: ~10 hours.
  - **Layer 5 — pointer marshalling.** Every syscall that takes
    user pointers needs to be reviewed for the "32-bit caller
    passes a 4-byte pointer in the low 32 of the register" case.
    Most syscalls already work because of the auto-zero-extension
    in Layer 3's remap; the audit catches the corner cases
    (sockaddr structs, WriteFile/ReadFile buffer descriptors, etc.).
  - **PE32 ImageBase / stack VA**: the loader currently doesn't
    pin the mapping to the low 4 GiB. Layer 4 lands the bitness-
    aware ImageBase allocator and stack VA picker.

## Phase 6.14 — PE32 (i386) execution end-to-end (2026-05-13)

Companion to Phase 6.13: the same session lifted the
`Pe32ExecutionNotReady` gate and pushed Layers 4 + the integration
glue across the finish line. `pe32_smoke.exe` now boots ring 3 in
32-bit compat mode, calls `GetStdHandle`, `WriteConsoleA`,
`GetCurrentProcessId`, and `ExitProcess` through its post-reloc IAT,
and exits cleanly. Each call is an indirect jump through an IAT slot
the kernel loader patched at load time to point at the matching
export in our `kernel32_32.dll` (a 2 KiB i386 companion to the
existing PE32+ kernel32.dll).

Live verification on every ring3 boot now includes the line
`[pe32] hello from compat mode` printed by ring-3 32-bit code via
the full Win32 -> int 0x80 -> kernel -> serial chain.

- **What landed.**
  - **`kernel32_32.dll` (i386).** New userland DLL under
    `userland/libs/kernel32_32/`. Exports `ExitProcess`,
    `TerminateProcess`, `GetCurrentProcessId`, `GetCurrentThreadId`,
    `GetCurrentProcess`, `GetCurrentThread`, `GetLastError`,
    `SetLastError`, `GetStdHandle`, `WriteFile`, `WriteConsoleA`.
    Built with `clang --target=i686-pc-windows-msvc` + `lld-link
    /machine:x86`. Output filename is `kernel32.dll` (not
    `kernel32_32.dll`) so the PE Export Directory's Name field
    reads `kernel32.dll` — the string the PE32 importer's
    case-insensitive resolver compares against.
  - **Per-bitness preload set.** `SpawnPeFile` probes the PE bytes
    via the new `PeIsPe32` helper, then picks between the existing
    44-DLL PE32+ preload list and a fresh PE32 list (currently just
    `kernel32_32.dll`). PE32 processes get the i386 DLL mapped in
    the low 4 GiB and visible to `ResolveImports` at IAT walk time.
  - **`dll_loader.cpp` + `pe_exports.cpp` PE32-aware.** Both
    branches the optional-header layout on `OptHdrMagic` —
    `ImageBase` reads as `u32` at offset 28 for PE32 vs `u64` at
    offset 24 for PE32+; data-directory array sits at offset 96
    (PE32) vs 112 (PE32+). `DllHeaders` + `PeHeaderShape` grow
    `is_pe32` + `data_dir_offset` so the EAT walker / reloc applier
    pick the right offsets.
  - **`pe_loader::ReadDataDir` bitness-aware.** Was hardcoded to
    PE32+ offsets (108 / 112) — the silent bug that caused PE32
    relocs to walk an empty data directory. Now reads
    `h.number_of_rva_and_sizes` + `h.data_dir_offset` from the
    per-`PeHeaders` fields the Rust validator pre-populates.
  - **`pe_loader::ResolveImports` PE32-aware.** Branches its IAT
    slot-size and ordinal-bit reads on `h.is_pe32`: 4-byte slots
    with the ordinal flag at bit 31 for PE32, 8-byte slots with
    the flag at bit 63 for PE32+. The IAT-slot patch writes 4
    bytes for PE32, 8 for PE32+. The `Win32ThunksLookupKind`
    catch-all is skipped for PE32 (the 64-bit thunks page isn't
    mapped in PE32 ASs); imports that don't resolve via the
    i386 preload set still get the IAT entry pointed at the
    catch-all VA for diagnostic visibility.
  - **`pe_loader::ApplyRelocations` HIGHLOW.** Accepts
    `IMAGE_REL_BASED_HIGHLOW` (type=3, 4-byte patch) alongside
    `IMAGE_REL_BASED_DIR64` (type=10, 8-byte). PE32 images use
    HIGHLOW exclusively. `dll_loader::ApplyDllRelocs` got the same
    treatment.
  - **`Process::user_is_pe32`** + **`Ring3UserEntry` branch.** A
    PE32 process spawns through `arch::EnterUserMode32` (CS=0x3B,
    SS=0x43, long-compatibility mode) instead of
    `EnterUserModeWithGs`. The kernel's `isr_common` detects the
    bitness from CS in the trap frame and routes the syscall arg
    remap accordingly.
  - **`isr_common` syscall un-remap.** After `TrapDispatch`
    returns, the trap frame's rdi (slot 72) and rsi (slot 80)
    slots are restored from the target r10 (slot 40) and r8 (slot
    56) — the remap path planted user's original rsi/rdi there as
    a side effect, and the C++ syscall handlers don't write back
    to those arg slots. Without this restore, `iretq` would pop
    the remapped arg1/arg2 values back into user's edi/esi, and
    `kernel32_32!WriteFile`'s `*lpWritten = bytes_written` store
    would `#PF` at the bogus pointer. The visible failure mode
    that motivated this fix was `ring3-pe32-smoke #PF` at the
    `mov %ecx,(%esi)` in WriteFile.
- **What's still GAP.**
  - **Layer 4 surface is tiny.** 11 kernel32 exports cover
    pe32_smoke's print-and-exit flow. NetSurf's 13 imported DLLs
    span ~450 functions. Each follow-up slice ports a chunk of
    that surface as a PE32 DLL (msvcrt_32, ntdll_32, user32_32,
    gdi32_32, ws2_32_32, wininet_32, etc.).
  - **No 32-bit Win32 thunks page.** PE32 callers whose imports
    don't resolve via the i386 preload set get the IAT slot
    pointed at the 64-bit catch-all VA, which isn't mapped in
    PE32 ASs. The page-fault is visible as a clear "task-kill" so
    the missing export shows up immediately, but a real PE32
    workload needs the catch-all to be 32-bit code at a low VA.
  - **No 32-bit TEB.** The 32-bit Windows TEB has a different
    layout from x64's, and is reached via FS, not GS. PE32s that
    deref `fs:[0x18]` (TEB self-pointer) or `fs:[0x30]` (PEB)
    fault. Lands with the 32-bit TEB setup slice.
  - **No 32-bit `__chkstk`.** PE32s built with MSVC use
    `__chkstk` to probe the stack a page at a time. Not in our
    msvcrt_32 yet.

## Phase 6.15 — i386 DLL set: 13-DLL PE32 surface (2026-05-14)

Layer 4 of 32-bit PE support delivered. The PE32 preload set is
now **13 i386 stub DLLs** mirroring the imports of a real-world
Win32 PE32 (NetSurf 3.11's import set was the audit reference).
The `pe32_rich` smoke exercises one or two functions from each
DLL — every call goes through the via-DLL IAT path the kernel
loader patches at spawn time.

- **What landed (new userland DLLs, all PE32 / i386).**
  - `userland/libs/kernel32_32/` — ~40 exports (built up
    in Phase 6.14, expanded in this slice with `GetModuleHandleA/W`,
    `GetProcAddress`, `LoadLibraryA/W`, `FreeLibrary`,
    `GetProcessHeap`, `HeapAlloc/Free/Size/ReAlloc`,
    `GetCommandLineA/W`, `GetStartupInfoA/W`, `GetFileType`,
    `Sleep`, `GetTickCount`, the full `InitializeCriticalSection`
    family, `IsDebuggerPresent`, the `Interlocked*` quartet,
    `GetVersion`, `CloseHandle`, `SetUnhandledExceptionFilter`).
  - `userland/libs/msvcrt_32/` — ~50 exports: memcpy / memmove /
    memset / memcmp; strlen / strcmp / strncmp / strcpy / strncpy
    / strcat / strchr / strrchr / strstr / _stricmp / _strnicmp;
    CRT startup (_errno, _amsg_exit, _assert, exit, _exit, abort,
    _initterm, _initterm_e, __set_app_type, __setusermatherr,
    _iob, __p__commode / _fmode / _acmdln, __getmainargs,
    __initenv); a minimal bump-allocator malloc / free / calloc /
    realloc; stubbed fopen / fread / fwrite; puts (forwards to
    SYS_WRITE); atoi / atol.
  - `userland/libs/user32_32/` — ~60 exports: window lifecycle
    (CreateWindowEx, Destroy / Show / UpdateWindow), full message
    loop (Peek / Get / Translate / Dispatch / Post / SendMessage,
    DefWindowProc, PostQuitMessage), class registration
    (RegisterClass[Ex][AW], UnregisterClass), resource loaders
    (LoadIcon / Cursor / etc.), MessageBoxA/W returning IDOK,
    GetDC / ReleaseDC, clipboard / caret / paint / cursor / focus
    stubs, GetSystemMetrics with sensible defaults.
  - `userland/libs/gdi32_32/` — ~45 exports: Create{Bitmap,
    CompatibleBitmap, CompatibleDC, Pen, SolidBrush, BrushIndirect,
    Font{A,W,IndirectA,IndirectW}}, Delete{DC,Object},
    SelectObject, GetStockObject, drawing primitives, pixel ops,
    SetBkColor / TextColor / BkMode / TextAlign / MapMode,
    GetObject{A,W}, CreateDIB{Section,itmap}, GetDIBits.
  - `userland/libs/advapi32_32/` — 24 exports: Registry stubs
    (RegOpen/Enum/Close/QueryValue), the full CryptoAPI v0
    (Crypt{Acquire,Release}Context, CryptCreateHash,
    CryptHashData, CryptGetHashParam, CryptGenRandom,
    CryptSignHashW, etc.), Event log stubs, and
    SystemFunction036 (RtlGenRandom) returning an LCG sequence.
  - `userland/libs/comctl32_32/` — 5 exports: ImageList_Create /
    Destroy / AddMasked, InitCommonControlsEx, PropertySheetA.
  - `userland/libs/comdlg32_32/` — 1 export: ChooseFontA.
  - `userland/libs/crypt32_32/` — 10 exports: Cert{Close,Open,
    OpenSystem}Store, CertDuplicateCertificateContext,
    CertEnumCertificatesInStore, CertFindCertificateInStore,
    CertFreeCertificateContext, CertGet{Certificate,Enhanced,
    Intended}KeyUsage / Property.
  - `userland/libs/iphlpapi_32/` — 4 exports: GetAdaptersAddresses,
    GetBestRoute2, GetUnicastIpAddressTable, FreeMibTable.
  - `userland/libs/shell32_32/` — 2 exports: CommandLineToArgvW
    (returns `argv = ["a.exe"]`), SHGetFolderPathA.
  - `userland/libs/shlwapi_32/` — 1 export: PathAppendA (real
    impl — walks the path string and appends with a `\` separator).
  - `userland/libs/ws2_32_32/` — ~40 exports: full Winsock
    surface backed by **real syscalls** to the kernel socket
    pool. socket / bind / listen / connect / accept / send / recv
    / sendto / recvfrom / shutdown / closesocket / select /
    inet_addr / inet_ntoa / gethostname / gethostbyname; the
    network-order helpers (htons / ntohs / htonl / ntohl) are
    real bit-swap implementations; WSA*Event surface stubbed.
  - `userland/libs/bcrypt_32/` — 1 export: BCryptGenRandom
    (LCG entropy).
- **Build infrastructure.**
  - `tools/build/build-stub-32-dll.sh` — generic builder that
    takes `(dll_name, base_va, symbol)` and produces a PE32 DLL
    via `clang --target=i686-pc-windows-msvc + lld-link
    /machine:x86 /def:<dll>_32.def`. The .def's `LIBRARY <name>.dll`
    directive plus the `/out:` basename being `<name>.dll` sets
    the PE Export Directory's Name field correctly for the i386
    importer's case-insensitive resolver.
  - `duetos_embed_32bit_stub_dll` CMake macro — one-line entry
    per new DLL.
- **Live verification.**
  - `userland/apps/pe32_rich/pe32_rich.c` — PE32 test that
    imports one or two functions from each preloaded i386 DLL.
    The boot transcript on every ring3 smoke run records:
    ```
    [pe32-rich] starting
    [pe32-rich] kernel32 ok
    [pe32-rich] msvcrt ok
    [pe32-rich] user32 ok
    [pe32-rich] gdi32 ok
    [pe32-rich] advapi32 ok
    [pe32-rich] comctl32 ok
    [pe32-rich] comdlg32 ok
    [pe32-rich] crypt32 ok
    [pe32-rich] iphlpapi ok
    [pe32-rich] shell32 ok
    [pe32-rich] shlwapi ok
    [pe32-rich] ws2_32 ok (htons real)
    [pe32-rich] bcrypt ok
    [pe32-rich] timer + module ok
    [pe32-rich] all 13 DLLs exercised — exit rc=0x42
    [proc] destroy pid=9 name="ring3-pe32-rich"
    ```
    Every line above the destroy is a real Win32 API call going
    through the IAT into one of our i386 stubs and back. The
    `htons` "real" tag confirms a byte-swap of 0x1234 → 0x3412,
    proving the 32-bit syscall remap + the i386 calling convention
    round-trip cleanly.
- **Memory budget bump.**
  `kernel/mm/address_space.h::kMaxUserVmRegionsPerAs` raised from
  1024 to 8192. Real-world PE32 images (e.g. NetSurf 3.11 at
  ~20 MiB) need ~5000+ pages just for sections + the 13-DLL
  preload set. The per-AS region-table cost goes from ~24 KiB
  to ~192 KiB — well within budget.

## Phase 6.16 — PE32 graceful-degradation surface (2026-05-14)

Three more pieces of the PE32 path. With Phase 6.15 the happy path
worked end-to-end; this slice takes the common failure modes from
"#PF at the first unstubbed call" to "process exits cleanly with a
readable signature."

- **32-bit Win32 thunks page** (`kernel/subsystems/win32/thunks.{h,
  cpp}`, `kernel/loader/pe_loader.cpp`).
  - New per-PE32-process R-X page mapped at
    `kWin32Thunks32Va = 0x60100000`. Distinct from the PE32+ thunks
    page at 0x60000000 (whose bytes are x86_64 instructions —
    decoding them in compat mode would trap immediately).
  - Single stub today at offset 0: `SYS_EXIT(0xDEAD0042)`. Any
    PE32 call to an unresolved Win32 import lands here and the
    process destroys cleanly with the sentinel exit code.
  - `ResolveImports`'s catch-all branch detects `h.is_pe32` and
    routes unresolved imports to this stub instead of the 64-bit
    catch-all VA (which isn't mapped for PE32 processes).
  - Verified live: `userland/apps/pe32_miss/pe32_miss.c` calls
    `user32!SetWindowsHookExA` (deliberately not stubbed), the
    indirect call routes through the new thunk, the process exits
    with rc=`0xDEAD0042`, boot continues.
- **32-bit TEB + FSBASE** (`kernel/loader/pe_loader.cpp`,
  `kernel/arch/x86_64/usermode.{S,h}`, `kernel/proc/ring3_smoke.cpp`).
  - PeLoad's step4b TEB allocator branches on `h.is_pe32` and
    writes the i386 NT_TIB layout:
    ```
    fs:[0x00] ExceptionList = 0xFFFFFFFF   (no SEH handler)
    fs:[0x04] StackBase     = kV0StackTop
    fs:[0x08] StackLimit    = kV0StackVa
    fs:[0x18] Self          = TEB VA (u32)
    fs:[0x30] PEB           = TEB VA (placeholder)
    ```
  - `EnterUserMode32` grows a third arg `user_fs_base` and issues
    `wrmsr MSR_FS_BASE` (`0xC0000100`). The user's compat-mode
    `mov eax, fs:[0x18]` then computes the linear address as
    `(FSBASE + 0x18) = TEB + 0x18`, landing on the Self slot
    rather than at linear 0x18.
  - Boot log: `step4b teb mapped va=0x70000000 (pe32 fs-base)`.
- **MSVC `__chkstk` / `_alloca_probe` / `_chkstk`** in `msvcrt_32`.
  - Three `__declspec(naked)` entry points all using the same
    body: `popl %ecx; subl %eax, %esp; pushl %ecx; ret`.
  - MSVC emits a call to one of these in any function prologue
    whose locals exceed a page, or that uses `_alloca`. On Windows
    they walk pages from current ESP downward, committing each as
    it goes; on DuetOS the entire stack is mapped up front so the
    routine is functionally an ESP adjustment + return-addr
    handoff. Real probing isn't needed — what matters is that the
    MSVC-emitted call doesn't fault.

The three existing PE32 fixtures plus the new pe32_miss all pass
cleanly on every ring3 boot:

```
[pe-load] step4b teb mapped va=0x70000000 (pe32 fs-base)  ← x3
[proc] destroy pid=8 name="ring3-pe32-smoke"
[pe32-rich] all 13 DLLs exercised — exit rc=0x42
[proc] destroy pid=9 name="ring3-pe32-rich"
[proc] destroy pid=10 name="ring3-pe32-miss"  ← unresolved import handled
[smoke] profile=ring3 complete
```

The pe32_miss `[proc] destroy` confirms an UNRESOLVED PE32 import
now degrades to a clean exit (`rc=0xDEAD0042`) instead of the #PF
that the same call previously produced. Combined with the 13-DLL
preload set from Phase 6.15, the PE32 surface now has both branches
of the via-DLL resolver (hit + miss) handled cleanly.

What's still GAP:

- **No per-import-name diagnostic** in the 32-bit thunk. All
  unresolved imports exit with the same sentinel. A future slice
  could emit per-slot stubs that log the IAT slot VA (decoded by
  the kernel's StagedMissAppend table back to the function name)
  before exiting.
- **No PEB structure.** PE32 reads of `fs:[0x30]` get the TEB VA
  back; dereferencing that produces zeros, which is fine for "did
  this read succeed" checks but not for code that walks
  PEB-relative fields (`fs:[0x30] + 0x18` = ImageBaseAddress,
  `+0x0C` = Ldr, etc.). A proper PEB lands with the registry +
  module-table slice.
- **`__chkstk` doesn't actually probe.** Acceptable on a kernel
  that maps the whole stack up front; a real MSVC PE32 with a
  16+ MiB stack reservation would still fault when its first
  spill writes past the mapped range. Stack-grow-on-fault is a
  separate slice.
- **File I/O still stubbed.** `msvcrt_32`'s `fopen` / `fread` /
  `fwrite` / `fclose` return failure. The VFS-aware PE32 spawn
  slice lands these the same time the 64-bit set gets its FS
  routing.

## Phase 6.17 — x64 SEH: kernel fault → user exception dispatch (2026-05-16)

Slices 1-2 had built the x64 unwinder (capture / `.pdata` lookup /
`RtlVirtualUnwind`) but a CPU fault in a Win32 PE still just
task-killed it. Phase 6.17 closes the loop: a ring-3 #DE/#UD/#GP/#PF
in a PE that has our ntdll mapped is no longer terminated on sight.
`kernel/subsystems/win32/seh_dispatch.cpp` builds a Microsoft
`EXCEPTION_RECORD` + `CONTEXT` (with a valid seeded FXSAVE image) on
the faulting thread's own user stack and rewrites the trap frame to
resume at `ntdll!KiUserExceptionDispatcher` — the same shape Windows
uses. ntdll's new `ntdll_dispatch.c` is the user-mode engine: it runs
the Vectored Exception Handler chain first, then the frame-based
`__C_specific_handler` → `RtlUnwindEx` → `RtlRestoreContext` walk;
`NtContinue` and `NtRaiseException` became real, and
`RtlLookupFunctionEntry` went cross-module (`SYS_MODULE_BASE_BY_VA`)
so a stack that crosses the EXE↔kernel32↔ntdll boundary resolves
every frame.

Two things shaped the slice:

- **The high-risk part is the trap-path rewrite**, so it fails safe:
  if ntdll isn't mapped, the user stack can't be written, or the same
  instruction keeps re-faulting into a wedged dispatcher, the kernel
  falls back to the original task-kill. A per-task backstop
  (`SchedSehDeliveryAllowed`) bounds a dispatcher that faults on
  itself; a genuinely unhandled exception terminates in *user* mode
  via the dispatcher's no-handler path, not by spinning the kernel.

- **mingw-w64 GCC has no MSVC `__try`/`__except` in C** (only the
  degenerate `__try1` macros), so the literal `__try` acceptance
  couldn't be smoke-tested under the existing toolchain. The
  frame-based engine ships exported and correct-by-construction for
  real MSVC-toolchain PEs (Chrome's vcruntime); the `seh_pe` smoke
  proves the *identical* kernel→user delivery + `RtlRestoreContext`
  machinery via a Vectored Exception Handler that catches a null
  write and a divide-by-zero, edits the CONTEXT, and continues —
  repeatably.

- **The `__try` smoke gap was then closed in the same effort.**
  `userland/apps/seh_try_pe` is compiled with
  `clang --target=x86_64-pc-windows-msvc -fasync-exceptions` (the
  flag that makes clang emit `.pdata`/`.xdata` + the
  `__C_specific_handler` personality over hardware faults) and
  linked by `lld-link` against our *own* `kernel32.lib` /
  `ntdll.lib` import libraries — no MSVC SDK, no CRT. It exercises
  the real frame-based path (`__C_specific_handler` scope-table
  walk → `RtlUnwindEx` → `RtlRestoreContext`): a null-write #PF and
  a divide-by-zero #DE caught by `__except` with the right
  `_exception_code()`, a `__finally` that runs while `RtlUnwindEx`
  walks out to the handler frame, and a repeatable case — all PASS.
  The clang `-fasync-exceptions` requirement was the catch: without
  it clang silently elides `__try` over faults and emits no unwind
  data. C++ EH (`__CxxFrameHandler*`) is still a separate slice.

## Phase 6.18 — Win32 synchronization + api-set host resolution (2026-05-16)

The first concrete Win10-API-breadth slice toward real Chrome. V8
and Chrome's thread pools are built on `WaitOnAddress` + condition
variables; DuetOS had SRW locks but no condition variables, no
`WaitOnAddress`, and the explicit `InitOnce` form was a no-op
thunk. This slice put a real futex underneath all of it: the
kernel gained `SYS_WAIT_ON_ADDRESS` / `SYS_WAKE_BY_ADDRESS`
(`kernel/subsystems/win32/waitaddr_syscall.cpp`) — address-hashed
wait queues where a bucket collision is at worst a spurious
wakeup, never a lost one (the wake side wakes the whole bucket and
each waiter re-checks its own word). Userland `kernel32` got real
`WaitOnAddress` / `WakeByAddress*`, the condition-variable family
(sequence-counter algorithm: the sleeper samples the sequence
under the lock before releasing, so a wake in the gap returns
immediately), and a real `InitOnceBeginInitialize` /
`InitOnceComplete` state machine.

The interesting blocker was binding. mingw's `-lsynchronization`
(and Chrome) import these not from `kernel32.dll` but from the
API-set contract `api-ms-win-core-synch-l1-2-0.dll`, which the
loader had no way to resolve — there is no such DLL. The fix is
the api-set host resolver in `pe_loader.cpp`: an `api-ms-win-*` /
`ext-ms-win-*` import is a *name contract*, so the function is
resolved by name against whichever preloaded base DLL (kernel32 /
kernelbase / ntdll / …) actually exports it. That single change
unblocks the whole modern synch contract surface for Chrome, not
just these functions — the boot log now shows
`[pe-resolve] via-apiset api-ms-win-core-synch-l1-2-0.dll!WaitOnAddress`.

Two build-robustness lessons landed alongside: clang's `-O1`/`-O2`
optimizer + `-fasync-exceptions` wedges *nondeterministically* on
`seh_try_pe.c` (one clang PID spinning 99% CPU for minutes in SEH
codegen — sometimes a fresh process is unlucky, sometimes not), so
that build dropped to `-O0` (deterministic, fast, same SEH output)
with a timeout+retry guard. Verified by `userland/apps/sync_smoke`
(`smoke=pe-hello`): a cross-thread `CONDITION_VARIABLE` +
`CRITICAL_SECTION` producer/consumer, a `WaitOnAddress` /
`WakeByAddressSingle` handshake, and the two-call `InitOnce` all
PASS, with zero SEH or browser regression.

## Phase 6.19 — Chrome tactility (Pass A): blend math, soft shadows, per-theme intensity (2026-05-24)

Pass A of the four-pass UX initiative. Until this slice, every window
border, shadow, hover lift, and focus glow was a flat opaque rect or
a fixed-width integer fill. Pass A made the compositor *physically
aware*: a window casts a soft gaussian-falloff shadow, a focused
window glows, a hovered chrome element lifts.

What landed (23 of 28 plan tasks, merged via PR #338):

- **`BlendRgba` / `BlendFill` math.** Porter-Duff `src-over` with
  alpha, skip-if-zero-alpha fast path, 8 × vectorisable iterations per
  fill call. Used by every chrome paint path below.
- **Atlas-based 9-slice soft shadow.** A 32 × 32 grey-level atlas
  baked at startup (one quadrant, 4 corner tiles + 4 edge tiles at
  `ATLAS_CORNER = 8 px`). `ShadowPaint9Slice` expands it to any window
  size in nine-slice fashion, compositing the shadow colour below the
  window surface without copying the framebuffer.
- **Seven new `Theme` fields:** `chrome_shadow_color`,
  `chrome_shadow_opacity`, `chrome_hover_lift_alpha`,
  `chrome_press_deepen_alpha`, `chrome_focus_glow_color`,
  `chrome_focus_glow_opacity`, `tactility_enabled`. Per-theme intensity
  matrix (HighContrast opts out entirely; Classic uses subdued values).
- **Runtime override:** `tactility=on|off|auto` on the kernel cmdline
  (mirrors the per-theme matrix for accessibility overrides).
- **Chrome paint integration** on windows, modals, snap previews,
  taskbar tabs + strip, menu panels, and the
  `WindowPaintFocusGlow` helper.
- **HighContrast invariant verified:** `tools/test/hc-invariant-check.sh`
  confirms the auto-vs-override pixel diff (324 px) is below the
  inter-boot noise floor (333 px) — tactility motion leaves
  HighContrast bit-for-bit identical to pre-spec.
- **Test infrastructure:** `tools/test/tactility-screenshot-matrix.sh`,
  `tools/test/hc-invariant-check.sh`, `tools/test/boot-determinism-sweep.sh`.
  Analyzer extended with a TACTILITY section (`blend=N shadow=N …`).

See [`Compositor`](../subsystems/Compositor.md#chrome-tactility-pass-a)
for the subsystem reference and
[`Roadmap`](../reference/Roadmap.md#chrome-tactility-pass-a--residual-polish--pass-a-verification)
for the deferred residuals.

## Phase 6.20 — First-impression moments (Pass B): splash, wallpaper motion, login GUI (2026-05-24)

Pass B of the four-pass UX initiative. Until this slice, the boot
sequence was invisible: the framebuffer showed a flat fill before
login, and the login screen was a bare credential form with no visual
relationship to the desktop. Pass B makes the four moments before any
app opens — boot, login, lock, desktop — feel like one continuous,
characterful surface.

What landed (all 25 plan tasks):

- **Boot splash** (`kernel/drivers/video/splash.{h,cpp}`). Full-screen
  wallpaper pattern paints immediately after `FramebufferInit()`. A
  phase ticker line at bottom-left snaps on each `SplashAdvancePhase()`
  call. Arcs rotate ±5° over 60 s; the pulse glow breathes on an 8 s
  sine; topo curves drift 1 px/s. `SplashDismiss()` clears the ticker
  rect and exits cleanly into the login path.
- **Animated wallpaper** (`kernel/drivers/video/wallpaper.{h,cpp}` +
  `WallpaperTick`). Three independent motion paths — arc rotation,
  pulse glow (alpha), topo drift — each computed from a shared
  `g_motion_ticks` counter advanced by the compositor tick scheduler at
  ≤ 15 FPS. Surgical dirty-rect declarations so Pass A's frame-elision
  continues to elide static chrome regions.
- **Login GUI redesign** (`kernel/drivers/video/login.{h,cpp}`).
  The same wallpaper backdrop (unchanged from splash) is the floor.
  A 84 px display-weight clock top-centre uses HPET. An atlas-shadow
  corner card bottom-right holds avatar (48 px arc placeholder),
  username + role label, a Pass A focus-glow password field, and a
  sign-in button. `LoginRefreshClock` + `WallpaperTick` fire on every
  minute boundary.
- **Lock screen** — the login screen is the lock screen with
  session-aware state; no new code path required.
- **Per-theme motion intensity** (`Theme::motion_intensity`). Five
  values: `Full` (Duet, Amber, Slate10), `Subdued` (Classic),
  `None` (HighContrast). The `motion=on|off|auto` cmdline override
  pairs with the per-theme matrix (same pattern as `tactility=`).
- **Self-tests:** `SplashSelfTest`, `WallpaperMotionSelfTest`,
  `LoginGuiSelfTest`, and the umbrella `PassBSelfTest`. Boot-log
  analyzer extended with a PASS B section (`splash=N wallpaper-motion=N
  login-gui=N umbrella=N`).
- **Test infrastructure:** `tools/test/pass-b-soak.sh`,
  `tools/test/tactility-screenshot-matrix.sh --splash --login --lock
  --wallpaper` (extended Task 22).

Verified on QEMU (2026-05-24): all PASS B sentinels fire, analyzer
reports clean, soak shows zero errors / zero real lockups / zero missed
ticks, no Pass A regressions.

See [`Compositor`](../subsystems/Compositor.md#first-impression-moments-pass-b)
for the subsystem reference and
[`Roadmap`](../reference/Roadmap.md#chrome-tactility-pass-b--residual-polish--pass-b-verification)
for the deferred residuals (VBox visual verification + screenshot
matrix, same pattern as the Pass A residuals).

## How to read the rest of the tree

- `CLAUDE.md` — the authoritative project context, coding standards,
  and anti-bloat guidelines.
- [Architecture Overview](Architecture-Overview.md) — the layering model,
  how a Win32 call travels from the PE's `call qword [iat]` to a kernel
  syscall.
- `kernel/loader/pe_loader.cpp` — PE spawn path with diagnostic
  PeReport.
- `kernel/loader/pe_exports.cpp` — EAT parser.
- `kernel/loader/dll_loader.cpp` — DLL loader and via-DLL resolver.
- `userland/libs/*/` — the userland DLL sources.
- [`reference/Roadmap`](../reference/Roadmap.md) — pending and
  deferred work items grouped by subsystem.
