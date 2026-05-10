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
