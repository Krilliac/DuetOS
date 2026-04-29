# DuetOS subsystems status — Win32 / NT + Linux ABI

**Type:** Decision + Observation (consolidated)
**Status:** Active — single source of truth
**Last updated:** 2026-04-29

This doc consolidates 17 prior knowledge files into one tracker for
the Win32/NT + Linux ABI subsystems. The originals (per-slice
observation logs) are preserved in git history; their landings are
captured below in §10 Landed.

---

## 1. What's left until "fully implemented"

Realistic estimate: from the current state, full feature-parity
with mature host OSes is ~2-3 years of focused work. The branch
peels off the highest-leverage 200-500 LOC slices each session.
Headline gaps:

### Linux ABI (~190 of 374 syscalls still stubbed)

- **BPF + perf_event_open** — huge surface, likely never realistic
- **Real signal completion**: user-handler trampoline + sigreturn — DONE 2026-04-29 for sa_restorer-supplying callers (glibc / musl, which means almost everyone). Old-style "no SA_RESTORER" callers still see the pending bit cleared without invocation (logged as a warning)
- **Containers**: setns, unshare, pivot_root, mount/umount2 (currently -EPERM)
- **Real ptrace state machine** (currently only kCapDebug-gated stub)
- ~~**clock_settime / settimeofday**~~ — landed: signed `g_realtime_offset_ns` in syscall_time.cpp, set by clock_settime(CLOCK_REALTIME) / settimeofday; CLOCK_MONOTONIC / boot-relative reject with -EINVAL (matches Linux). CLOCK_REALTIME readers (clock_gettime / gettimeofday / time) compose `RealtimeNs() = NowNs() + offset`; saturate-at-zero on negative-offset underflow so userspace never sees a negative tv_sec. Cap-gated by kCapDebug (CAP_SYS_TIME analog in v0); untrusted callers keep pre-slice -EPERM. **clock_adjtime / adjtimex** stay -EOPNOTSUPP for cap-holders (was -EPERM uniformly) — struct timex / NTP discipline not yet wired (separate slice)
- ~~**Real rlimit enforcement**~~ — landed for NOFILE + NPROC: per-Process soft caps (`linux_rlimit_nofile_cur`, `linux_rlimit_nproc_cur`) initialised to 0xFF... sentinel ("no cap below kernel ceiling"); setrlimit/prlimit64 lower them; getrlimit reports them. NOFILE enforced uniformly across all 15 fd-allocator sites (open / dup / F_DUPFD / pipe / pipe2 / socket / msgq_open / pidfd_open / pidfd_getfd / inotify_init / fanotify_init / signalfd / timerfd / eventfd / memfd_create) via `LinuxFdEffectiveMax(p)`; NPROC enforced in DoFork via `SchedCountChildrenOfPid` (live-child count vs. cap, returns -EAGAIN like Linux). Sub-GAPs remaining: STACK / AS / DATA still served from constants. CLONE_THREAD doesn't burn NPROC (same Process)
- ~~**mremap for real**, full madvise advice handling~~ — landed: madvise honors DONTNEED / FREE / REMOVE (zeros mapped pages, skips unmapped); mremap shrinks via real per-page unmap, MAYMOVE growth allocates a new range and direct-map-copies old contents page-by-page (sub-GAPs: file-backed VMAs not tracked, MREMAP_FIXED unimplemented)
- ~~**pidfd poll-on-exit**~~ — landed: `LinuxFdEpollReady` reports EPOLLIN on a state-12 slot when `SchedIsPidZombie(target_pid)` (task on `g_zombies`) or `SchedFindProcessByPid` returns nullptr (already reaped). `DoPoll` rerouted through the same predicate so POLLIN is consistent across epoll / poll / select. Wake-on-exit landed too: global `g_pidfd_exit_wq` woken by `LinuxPidfdExitWake()` at the top of `DoExitGroup`; `DoEpollWait` uses `WaitQueueBlockTimeout` against it when at least one watched fd is a pidfd, so wake latency is bounded by exit ordering instead of the 100 ms timer cadence. Sub-GAP: only pidfd has a real wake source — pipes / sockets / timerfds / signalfds still rely on the timer cadence within `DoEpollWait`.
- **Real splice / tee zero-copy for file↔pipe** (pipe→pipe landed 2026-04-29; vmsplice→pipe was already real)
- **userfaultfd, io_uring** (-ENOSYS facades only)
- **landlock / seccomp filter execution** (-ENOSYS facades only)

### Win32 / NT subsystem (~470 NT facades remaining of 506 total)

- ~~**NtCreateUserProcess**~~ — DONE (2026-04-29): ntdll's
  NtCreateUserProcess now parses RTL_USER_PROCESS_PARAMETERS,
  translates the Windows ImagePathName UNICODE_STRING into the
  kernel's `/disk/N/...` form (drive letter + extended-length
  prefix stripping inline; matches the kernel32 NormalizePathW
  translator), and issues SYS_PROCESS_SPAWN. ThreadHandle = -1
  (caller does NtOpenThread(pid) for a real handle). Sub-GAPs:
  CommandLine ignored; ProcessFlags / ThreadFlags ignored;
  CreateInfo / AttributeList ignored. Old NtCreateProcess /
  NtCreateProcessEx remain NotImpl (section-from-file based —
  separate slice).
- **LPC / ALPC family** — IPC backbone (NtCreatePort / NtConnectPort / NtRequestPort / NtReplyPort)
- **ETW / NtTrace*** — tracing infrastructure
- **KTM transactions** — NtCreateTransaction / NtCommitTransaction
- **WNF state data**
- **NtCreateMailslot, named pipes proper**
- **NtAdjustPrivilegesToken** — currently honors no real privileges
- **Section file-backed mappings** + partial-view offset/length (currently anonymous + whole-section only)
- **NtSetInformationFile** beyond FilePositionInformation

### Filesystems

- **ext4 write** (~2000 LOC, explicitly called out as remaining)
- **NTFS write** (~2000 LOC, explicitly called out) + read parsing completion
- **Page cache + real fsync**
- **Real journaling** for crash safety
- **Mount table + mount/umount syscalls**
- **Symlinks via NTFS reparse points, hardlinks, sparse files**

### Drivers

- **Intel HDA codec/stream** (audio playback) — probe only
- **AC'97 / USB audio class**
- **GPU acceleration**: Intel iGPU, AMD Radeon, NVIDIA — all probe-only
- **Vulkan ICD** + D3D9/11/12 translation
- **WiFi**: iwlwifi, RTL88xx, BCM43xx — chip ID only
- **AHCI/SATA driver** (NVMe done; AHCI not)
- **xHCI bulk-transfer API** for non-keyboard devices
- **PS/2 mouse, SD/MMC, eMMC**
- **ACPI suspend/resume**

### Architecture

- **SMP bring-up** (currently BSP-only)
- **ARM64 port** (planned, not started)
- **NUMA awareness, RT priority enforcement**

### Userland

- No native libc (only Win32 DLLs)
- No native init / shell / coreutils
- No real display server protocol

---

## 2. Subsystem isolation rule (DO NOT VIOLATE)

DuetOS hosts two guest ABIs — Win32/NT (PE binaries) and Linux
(ELF binaries). **Both are facades for executing those binaries.**
They are NOT auxiliary kernels, not co-equals to DuetOS-native
logic, and not free to drive the system on their own authority.

The DuetOS kernel — its capability set, scheduler, address-space
ledger, FS mediation, IPC, and timer infrastructure — is the
**single authority** on every effect a guest binary can have.

**Reviewable signal**: "could a malicious PE / ELF use this path
to do something a native DuetOS process couldn't?" If yes, the
gate is wrong, not the workload.

### Concrete rules

1. **Every subsystem-driven mutation of DuetOS state goes through
   a kernel-mediated, cap-gated SYS_\* syscall.** A Win32 PE that
   wants to write a file calls `SYS_FILE_WRITE` (cap-gated on
   `kCapFsWrite`). A Linux binary that wants to spawn a thread
   calls `SYS_THREAD_CREATE` (cap-gated on `kCapSpawnThread`). The
   NT or Linux thunk in `kernel/subsystems/{win32,linux}/` cannot
   skip the gate by reaching into kernel internals directly.

2. **Auth, privilege, and capability are kernel-owned.**
   `Process::caps` (the `kCap*` bitset in `kernel/proc/process.h`)
   is the source of truth. Any Win32-shaped privilege surface —
   NtAdjustPrivilegesToken, SeDebugPrivilege, integrity levels,
   ACLs, NtOpenProcessToken handles — is a probe-satisfying
   facade. Linux uid/gid: `getuid()` returns 0, but that means
   nothing — actual access control is the cap set.

3. **Userland DLLs (`userland/libs/*`) are freestanding.** They
   do NOT include kernel headers. They do NOT assume kernel
   internals. They issue syscalls and trust the kernel's return.
   The build contract is that ntdll.c, kernel32.c, advapi32.c,
   etc. compile against a freestanding C target with no
   DuetOS-kernel includes visible.

4. **In-kernel subsystem code routes through public kernel APIs**
   (`mm::*`, `sched::*`, `fs::routing::*`, `core::Cap*`). It does
   NOT mutate kernel-internal data structures (regions tables,
   runqueues, capability bitsets) directly.

5. **No subsystem-to-subsystem coupling.** Win32 doesn't call
   into Linux; Linux doesn't call into Win32. Both call the
   kernel.

6. **One source of truth per resource.** One TCP stack, one VFS,
   one registry, one window manager — each reachable from
   multiple ABI front-ends, but with one kernel-owned
   implementation.

### Audit checklist (before merging any subsystem-touching slice)

For each new or modified syscall handler:
- Does this mutation require a capability check? (cross-process
  / cross-resource: yes; self-AS: no)
- Does the handler mutate kernel-internal state directly?
  (regions[], runqueue links, caps, private struct fields → fix
  the API surface, don't reach in)
- Does the userland thunk depend on kernel internals?
  (kernel header in `userland/libs/*` → violation)
- Could a malicious guest bypass the gate? Walk the path: PE
  issues NT call → ntdll thunk → SYS_\* → kernel handler. The
  stop must live in the kernel, not the thunk.

For each new userland DLL thunk:
- Does it issue a syscall, or return a constant?
- If a constant returner, document it as a facade (see §3 below).

---

## 3. Known facade surfaces (intentional, documented)

These thunks DELIBERATELY return canned data instead of doing real
work, because the underlying kernel facility doesn't exist in v0.
Documented so an audit doesn't flag them:

| Thunk | Returns | Why not a violation |
|---|---|---|
| `NtOpenProcessToken` / `Ex` | constant handle 0xA00 | No auth model; kernel's `kCap*` is the real gate |
| `NtQueryInformationToken` (TokenUser, TokenIntegrityLevel) | static SIDs | Same. PE callers probe; nothing in DuetOS gates on the answer |
| ~~`NtAdjustPrivilegesToken`~~ | ~~success no-op~~ | FIXED 2026-04-29: real LUID→cap mapping via SYS_TOKEN_ADJUST. Disable / SE_PRIVILEGE_REMOVED / DisableAllPrivileges drop the mapped cap; enable refuses if the cap isn't held (returns STATUS_NOT_ALL_ASSIGNED) |
| `NtOpenMutant` / `NtOpenEvent` | STATUS_OBJECT_NAME_NOT_FOUND | No named-object table yet. Create* thunks DO work; only Open-by-name is a facade |
| `NtFsControlFile` / `NtDeviceIoControlFile` | STATUS_NOT_IMPLEMENTED | No IOCTL framework. Explicit NotImpl is the right answer |
| `NtFlushBuffersFile` | success no-op | No write cache; flush has nothing to do |
| `signalfd` reads (when no pending) | -EAGAIN | Honest "no signal pending" surface |

If you add a new facade thunk, document it here. If you find an
**undocumented** thunk that returns a constant, audit it — it
might be a violation pretending to be a facade.

## 4. Known gate sites (kernel-side cap enforcement)

| Syscall | Gate |
|---|---|
| `SYS_FILE_OPEN`, `SYS_STAT`, `SYS_FILE_QUERY_ATTRIBUTES`, `SYS_DIR_OPEN` | `kCapFsRead` |
| `SYS_FILE_WRITE`, `SYS_FILE_CREATE`, `SYS_FILE_UNLINK`, `SYS_FILE_RENAME` | `kCapFsWrite` |
| `SYS_REGISTRY` (kOpSetValue, kOpDeleteValue) | `kCapFsWrite` |
| `SYS_THREAD_CREATE`, Linux `clone()` / `fork()` | `kCapSpawnThread` |
| `SYS_THREAD_OPEN`, `SYS_PROCESS_OPEN`, `SYS_PROCESS_VM_READ/WRITE/QUERY`, `SYS_THREAD_GET/SET_CONTEXT`, `SYS_THREAD_SUSPEND/RESUME`, `SYS_VM_ALLOCATE/FREE/PROTECT` (foreign target), cross-process `SYS_PROCESS_TERMINATE` / `SYS_THREAD_TERMINATE` | `kCapDebug` |
| Linux BSD-socket family (`socket`, `bind`, `connect`, `accept`, `listen`, `send*`, `recv*`, `shutdown`, `getsockname`, `getpeername`, `getsockopt`, `setsockopt`, `socketpair`) | `kCapNet` |
| `SYS_WIN_GET_KEYSTATE`, `SYS_WIN_GET_CURSOR` | `kCapInput` |

Defined caps (`kernel/proc/process.h`, do not renumber):

| Cap | Value |
|---|---|
| `kCapNone` | 0 |
| `kCapSerialConsole` | 1 |
| `kCapFsRead` | 2 |
| `kCapDebug` | 3 |
| `kCapFsWrite` | 4 |
| `kCapSpawnThread` | 5 |
| `kCapNet` | 6 |
| `kCapInput` | 7 |

Reserved-but-not-yet-implemented (need their backing syscall to
exist before landing the cap, otherwise dead code): `kCapFramebuffer`,
`kCapAudio`, `kCapSignal`, `kCapFork`, `kCapExec`.

---

## 5. Win32 / NT subsystem state

### Architecture (from win32-subsystem-design)

- **The Win32 subsystem is a peer, not a shim.** NT syscall
  interface implemented directly in the kernel alongside the
  native DuetOS syscall interface. Both dispatch tables live in
  `kernel/syscall/` and both are first-class.
- **User-mode Windows DLLs are reimplementations.** `ntdll.dll`,
  `kernel32.dll`, `user32.dll`, `gdi32.dll`, `dxgi.dll`,
  `d3d11.dll`, `d3d12.dll`, `winmm.dll` are reimplemented under
  `userland/libs/<dll>/`. We want **executable compatibility**
  (run the `.exe`), not DLL compatibility.
- **PE loader lives in the kernel** (`kernel/loader/pe_loader.cpp`).
- **Wine and ReactOS are reference**, not dependencies.

### PE loader pipeline

PE bytes → `PeValidate` → `MapHeaders` → `MapSection×N` →
`ApplyRelocations` (real walk of `.reloc`; zero-delta in v0
because we always load at preferred ImageBase) → `stack×16` →
stubs page → `ResolveImports` → TEB → spawn ring-3 task.

Real-world reach (as of `074df0e`): MSVC `windows-kill.exe`
(80 KB, 8 sections, 52 imports across `dbghelp` / `kernel32` /
`advapi32` / `msvcp140` / `vcruntime140` / `api-ms-win-crt-*`,
SEH, TLS, resource dir) loads, enters CRT startup at
`0x140004070`, prints "Windows Kill " via MSVCP140::sputn →
SYS_WRITE, exits cleanly.

### Stage-2 DLL loader (`074df0e` etc.)

`kernel/loader/dll_loader.{h,cpp}` + `kernel/loader/pe_exports.{h,cpp}`:
- `DllLoad(file, len, as, aslr_delta)` — validates DLL bit, maps
  every section, applies base relocations, parses EAT.
- `PeExportsReport` dumps EATs at boot.
- `Process::dll_images[48]` table per process; lookup by name
  (case-insensitive) or by base VA. Forwarders are chased
  (name + ordinal forms). By-ordinal IAT entries resolve
  against preloaded EATs. `PeExportLookupName` is binary-search.

29 userland DLLs shipped, ~750+ exports — essentially full
Win32 surface coverage.

### Win32 thunks (`kernel/subsystems/win32/thunks.cpp`)

Renamed from `stubs.cpp` because most entries do real work —
they translate Windows x64 calling convention into the DuetOS
native syscall ABI and issue `int 0x80`. Only a small subset
(`kOffReturnZero`, `kOffReturnOne`, `kOffCritSecNop`,
`kOffMissLogger`) are genuine no-op stubs.

Historical ABI bug: every hand-assembled Win32 thunk that
translates the MS x64 calling convention to the int-0x80 ABI
must save/restore `rdi` and `rsi` (callee-saved on Windows,
caller-saved on Linux). Critical-path thunks fixed; latent in
ExitProcess / TerminateProcess / miss-logger (noreturn or
unknown-import paths only).

### Win32 windowing (through v1.4)

`windowed_hello` exercises the full surface end-to-end on every
headless QEMU boot: lifecycle, message queue, GDI primitives,
input, focus, parent/child, styles, caret, MessageBox returns,
SendMessage. Layout:

```
PE (user32 IAT) → user32 stub bytecode → int 0x80
                                          ↓
                                     SYS_WIN_*
                                          ↓
            kernel/subsystems/win32/window_syscall.cpp
```

Filled-ellipse compositor prim parity between window-HDC and
memDC paths; `text_color_set` flag honors explicit-black
SetTextColor.

### Win32 custom diagnostics + safety extensions (`win32-custom-extensions`)

Eleven opt-in features in `kernel/subsystems/win32/custom.{h,cpp}`,
syscall `SYS_WIN32_CUSTOM = 129`. New Process member
`win32_custom_state` (opaque void*; lazy-allocated). All gated
behind `kSetPolicy`; default policy 0 = standard Win32.

Tier 1 (auto-on for every Win32 PE — no observable behaviour
change): flight recorder, handle provenance, error provenance,
async-paint policy, pixel isolation snapshot.

Tier 2 (opt-in only — heap quarantine, deadlock detect,
contention profile, input replay, strict-RWX, strict-handle-inherit).

DumpOnAbnormalExit fires for every Win32 PE exit, gives a
post-mortem record without callers needing to know syscall details.

### DirectX v0 (`directx-v0`)

`d3d9` / `d3d11` / `d3d12` / `dxgi` user-mode DLLs ship real
COM-vtable interfaces. `D3D11CreateDeviceAndSwapChain →
ClearRenderTargetView → Present` (and equivalent D3D9/D3D12
paths) return real interfaces, fill BGRA8 back buffers, BitBlt
to the owning HWND via `SYS_GDI_BITBLT (102)`. Vulkan ICD does
not exist; D3D→Vulkan translation deferred.

### Win32 directory enumeration (`074df0e` + `364814d`)

`SYS_DIR_OPEN = 154` / `SYS_DIR_NEXT = 155` / `SYS_DIR_REWIND = 156`.
Process gained 8-slot `Win32DirHandle[]` at base 0xA00. Each
open KMallocs a 256-entry snapshot (Fat32ListDirByCluster for
"/disk/<idx>" paths; hand-rolled walker against per-process
Ramfs root otherwise).

`FindFirstFileA/W` + `FindNextFileA/W` + `FindClose` flipped
from "always INVALID_HANDLE / no more files" stubs to real
syscall thunks. Path normalisation strips trailing `\*` /
`\*.*` wildcards, translates backslash → forward slash.

`NtCreateFile` detects `FILE_DIRECTORY_FILE` (CreateOptions 0x1)
and routes to SYS_DIR_OPEN. `NtQueryDirectoryFile` real thunk
supports four `FILE_INFORMATION_CLASS` values: FileDirectory (1),
FileFullDirectory (2), FileBothDirectory (3, most common),
FileNamesInformation (12). NextEntryOffset = 0 (single entry per
call); callers loop until STATUS_NO_MORE_FILES.

### NT-table coverage

100% mapping coverage (`a7c459e` / `074df0e` etc.): all 506
Bedrock + Win11-25H2 NT calls have at least a NotImpl facade so
import resolution doesn't crash. ~36 are real implementations;
the rest return `STATUS_NOT_IMPLEMENTED` (0xC0000002) with their
NT-call signatures honoured.

---

## 6. Linux ABI subsystem state

### Routing

Each `core::Process` carries `abi_flavor`:
- `kAbiNative` (0): `int 0x80` → `core::SyscallDispatch` (DuetOS
  native + Win32 PE subsystem both use this — Win32 is a
  user-mode shim that trampolines through native ints)
- `kAbiLinux` (1): `syscall` instruction → `LinuxSyscallDispatch`
  via MSR_LSTAR, RAX = nr, RDI/RSI/RDX/R10/R8/R9 args, sysret expected

Loaders (`PeLoad`, `SpawnElfFile`, `SpawnElfLinux`) set the flag
at spawn time. ELF OS-ABI sniffing intentionally deferred —
callers decide explicitly.

### Coverage (current)

143 + ~30 implemented (≈46% of 374); ~190 unimplemented.

### Layout

`kernel/subsystems/linux/`:
- `syscall.{cpp,h}` — dispatcher
- `syscall_internal.h` — cross-TU surface for handlers
- `syscall_entry.S` — MSR_LSTAR entry trampoline
- `syscall_io.cpp` — read / write / lseek / ioctl / readv / writev / pread64 / pwrite64
- `syscall_file.cpp` — open / close / stat / fstat / lstat / access / openat / newfstatat
- `syscall_path.cpp` — chdir / fchdir / getcwd
- `syscall_fd.cpp` — dup / dup2 / dup3 / fcntl
- `syscall_fs_mut.cpp` — chmod / chown / unlink / mkdir / rmdir / rename / truncate / ftruncate / utime / mknod / *at-family
- `syscall_mm.cpp` — brk / mmap / munmap / mprotect / madvise / mremap / msync / mincore / mlock / munlock
- `syscall_proc.cpp` — exit / exit_group / getpid / gettid / kill / tgkill / getppid / getpgid
- `syscall_clone.cpp` — clone / clone3 / fork (real CLONE_THREAD + full fork with deep AS copy)
- `syscall_pipe.{cpp,h}` — pipe / pipe2 / eventfd / eventfd2 (real ring + WaitQueue)
- `syscall_socket.{cpp,h}` — BSD socket family (real UDP + single-slot TCP)
- `syscall_async_io.{cpp,h}` — timerfd / signalfd / epoll (real engines)
- `syscall_sig.cpp` — rt_sigaction / rt_sigprocmask / sigaltstack / rt_sigreturn / rt_sigpending / rt_sigsuspend / rt_sigtimedwait + LinuxSignalDeliver
- `syscall_cred.cpp` — uid/gid/groups (all uid-0 no-ops)
- `syscall_misc.cpp` — arch_prctl / uname / set_tid_address / sysinfo / getrandom / futex / personality / pause / flock / get/setpriority / getcpu / prctl (PR_SET_NAME real) / getrusage / poll / ppoll / select / pselect6 / getdents64 / set/get_robust_list / readlink
- `syscall_time.cpp` — clock_gettime / gettimeofday / time / nanosleep / times / clock_getres / clock_nanosleep
- `syscall_sched.cpp` — sched_setaffinity / sched_getaffinity / sched_getscheduler / sched_setscheduler / sched_get/setparam / sched_get_priority_{max,min} / sched_rr_get_interval
- `syscall_rlimit.cpp` — getrlimit / setrlimit / prlimit64
- `syscall_stub.cpp` — wait4 / waitid (real exit-queue drain), inotify (-ENOSYS — moved to inotify.cpp), fadvise64 / readahead, ptrace (kCapDebug-gated), syslog (canned banner), vhangup / acct / mount / umount2 / sync / syncfs / link / symlink / set_thread_area / get_thread_area / ioprio_get / ioprio_set
- `inotify.{cpp,h}` — real inotify(7) engine + FS-mutation publish-subscribe
- `pidfd_splice.cpp` — pidfd_open / pidfd_send_signal + splice / tee / vmsplice
- `sysv_ipc.cpp` — SysV shared memory + semaphores
- `msg_queues.cpp` — SysV msg queues + POSIX msg queues
- `ring3_smoke.{cpp,h}` — Linux ELF smoke harness

### LinuxFd states (in `Process::linux_fds[16]`)

| state | meaning | first_cluster |
|---|---|---|
| 0 | unused | — |
| 1 | reserved-tty (fd 0/1/2) | — |
| 2 | regular file (FAT32-backed) | first_cluster |
| 3 | pipe-read end | pipe pool idx |
| 4 | pipe-write end | pipe pool idx |
| 5 | eventfd | eventfd pool idx |
| 6 | socket | socket pool idx |
| 7 | timerfd | timerfd pool idx |
| 8 | signalfd | signalfd pool idx |
| 9 | epoll instance | epoll pool idx |
| 10 | inotify instance | inotify pool idx |
| 11 | dirfd (directory snapshot) | win32_dirs pool idx |
| 12 | pidfd | target pid |
| 13 | POSIX mq descriptor | posix_mq pool idx |

### ABI translation unit (`abi-translation-unit`)

`kernel/subsystems/translation/translate.cpp` — gap-fill TU
that catches dispatch-misses on both Linux + native sides
before they surface as -ENOSYS. Bidirectional: 18 Linux
translations, 4 native translations, hit-counter telemetry,
shell `translate` diagnostic. NT→Linux translator path
(`SYS_NT_INVOKE`) lets a Win32 PE issue NT calls that route
through the Linux engine when no kernel-side NT handler
exists.

### BSD socket family (`bsd-socket-family-v0`)

`kernel/net/socket.{h,cpp}` + `kernel/subsystems/linux/syscall_socket.{h,cpp}`:
- 8-slot kernel socket pool
- AF_INET + SOCK_DGRAM (full multi-socket UDP)
- AF_INET + SOCK_STREAM (single-slot active-connect TCP machine
  in `kernel/net/stack.cpp`)
- LinuxFd state 6, fork() inheritance via `SocketFdRetain`
- `kCapNet` gates every entry — withheld → -EACCES
- Win32 `ws2_32` thunks routed through `SYS_SOCKET_OP = 153`,
  WSAxxx errno translation in `wsa_translate_errno`

Sub-GAPs: `SOCK_NONBLOCK` / `SOCK_CLOEXEC` accepted but ignored;
single-slot TCP; setsockopt / getsockopt no-op; sendmmsg /
recvmmsg -ENOSYS; AF_UNIX socketpair -EOPNOTSUPP; accept() polls
instead of WaitQueueBlock; getpeername on accepted fd returns
0.0.0.0; server-side TCP send-after-establish needs its own
TcpServerSend slice.

### Process / signal model

- `Process::linux_parent_pid` — set on fork
- `Process::linux_exit_code` / `linux_was_signaled` /
  `linux_exit_signal` — set on exit / kill
- `Process::linux_child_exits[8]` queue + `linux_wait_wq` —
  per-process exit queue + wait waiters (drained by wait4 / waitid)
- `Process::linux_pending_signals` u64 bitmap + `linux_signal_wq`
- `Process::linux_sigactions[64]` — handler / flags / restorer / mask
- `Process::linux_signal_mask` — rt_sigprocmask state

`LinuxSignalDeliver(target, signum)` is the central delivery
helper. Default actions (SIGHUP/INT/QUIT/ABRT/BUS/FPE/KILL/
USR1/SEGV/USR2/PIPE/TERM = fatal) call `SchedKillByProcess`;
SIG_IGN drops; user handlers (with SA_RESTORER + restorer_va)
are invoked via the trampoline+sigreturn path landed 2026-04-29
(`subsystems/linux/signal_deliver.{cpp,h}`).

---

## 7. Stub & gap inventory — by family

Top-line numbers (re-derive periodically via the structural scan
described in §9):

| Surface | Total | Implemented | Stubbed |
|---|---|---|---|
| NT syscall table (Bedrock) | 292 | ~36 | ~256 |
| NT syscall table (Win11 superset) | 506 | ~36 | ~470 |
| Linux syscall table | 374 | ~173 | ~201 |
| Kernel-side stub handlers | — | — | shrinking |
| Win32 user-mode thunks (no-op / constant returners) | — | — | ~15 |
| Userland-DLL stub functions | — | — | ~20 |
| Filesystems with full write support | 6 | 3 (FAT32 partial, tmpfs, ramfs r/o) | 3 (ext4 r/o, NTFS r/o, exFAT partial) |
| Driver subsystems with packet I/O | 4 | 1 (e1000 + RNDIS partial) | 3 (audio / GPU accel / USB-bulk-non-HID) |

### NT subsystem — biggest stubbed families

| Family | Stubbed | Notable |
|---|---|---|
| Process control | NtCreateProcess / NtCreateProcessEx / NtCreateUserProcess | Subprocess spawn — explicitly waiting on section-from-file |
| Token / security | most NtSetInformationToken / NtAccessCheck / NtImpersonate / NtFilterToken | Real ACL eval |
| LPC / ALPC | NtCreatePort / NtListenPort / NtConnectPort / NtRequestPort / NtReplyPort / NtAlpcCreatePort | IPC backbone |
| Job / quota | NtCreateJobObject / NtAssignProcessToJobObject / NtQueryInformationJobObject | Resource limits |
| Debug | NtDebugActiveProcess / NtDebugContinue / NtQueryDebugFilterState | Debugger attach |
| Transactions (KTM) | NtCreateTransaction / NtCommitTransaction / NtRollbackTransaction | Cross-resource transactions |
| IOCP | NtSetIoCompletion / NtRemoveIoCompletion / NtRemoveIoCompletionEx | Async I/O |
| ETW / tracing | NtTraceEvent / NtTraceControl | Performance tracing |
| Power | NtPowerInformation / NtRequestWakeupLatency / NtInitiatePowerAction | Power management |
| WNF | NtSubscribeWnfStateChange / NtUpdateWnfStateData | Windows Notification Facility |
| Plug & Play | NtPlugPlayControl / NtAddDriverEntry | Device events |

### Linux subsystem — biggest stubbed families

| Family | Stubbed | Notable |
|---|---|---|
| libaio | io_setup / io_destroy / io_getevents / io_submit / io_cancel | |
| BPF / perf | bpf / perf_event_open / trace_* | Huge surface |
| Audit | audit_* (8+) | Kernel auditd |
| Containers | mount / umount2 / pivot_root / chroot / quotactl / unshare / setns | Returns -EPERM |
| Real ptrace | full ptrace state machine | -ENOSYS with cap clear; -EPERM without |
| KEYRINGS | add_key / request_key / keyctl | |
| seccomp / landlock / fanotify | full filter execution | |

### Userland-side gaps

`userland/libs/`:
- **ucrtbase**: `fwrite(fd > 2)` now routes to SYS_FILE_WRITE
  (was: silent 0 — fixed in `ad32498`); `fseek` non-console,
  `setvbuf` / `setbuf` still no-op-success
- **msvcrt**: `_setmode` returns -1 for non-standard FDs; `isatty`
  returns 1 for all FDs
- **user32**: MessageBox / DialogBox stub success (no UI)
- **gdi32**: GetDeviceCaps hardcoded device values
- **advapi32**: real Reg* read path; mutation now lands too
- **ws2_32**: real socket family routed through SYS_SOCKET_OP
- **comdlg32**: GetOpenFileName / GetSaveFileName return IDCANCEL

### Drivers (current)

| Family | State |
|---|---|
| Storage: NVMe + GPT + FAT32 + ext4 read | Real |
| Storage: AHCI / SATA | Probe only |
| Net: Intel e1000 wired | Real (TX/RX/IRQ wired, internet reachable) |
| Net: USB CDC-ECM | Real (probe not auto-called) |
| Net: USB RNDIS | Real (control plane; bulk concurrency gap) |
| Net: iwlwifi / RTL88xx / BCM43xx | Chip ID only |
| Audio: PC speaker | Real |
| Audio: Intel HDA / AC'97 / USB audio | Probe only |
| GPU: Bochs VBE / virtio-gpu (framebuffer) | Real |
| GPU: Intel iGPU / AMD / NVIDIA | Probe only (no acceleration) |
| Input: PS/2 keyboard + xHCI HID keyboard | Real |
| Input: PS/2 mouse | Stub |

---

## 8. Mismaps in the NT shim (semantically wrong targets)

| NT call | Current state |
|---|---|
| ~~`NtWriteVirtualMemory`~~ | FIXED: now routes to `SYS_PROCESS_VM_WRITE` |
| ~~`NtReadVirtualMemory`~~ | FIXED: now routes to `SYS_PROCESS_VM_READ` |
| ~~`NtCreateSemaphore`~~ | FIXED: routed to `kSysNtNotImpl` |
| ~~`NtReleaseSemaphore`~~ | FIXED: routed to `kSysNtNotImpl` |
| `NtSetInformationFile` | Mapped to `SYS_FILE_SEEK`; ntdll thunk handles FilePositionInformation (real seek) + FileBasicInformation (accept-as-success — v0 doesn't track on-disk file times); FileEndOfFileInformation / FileRenameInformation / FileDispositionInformation return STATUS_NOT_IMPLEMENTED |
| `NtCreateMutant` | Suspect — verify mapping |

**Action**: any new mismap discovered should either get a correct
dedicated SYS_\*, or be remapped to `kSysNtNotImpl` so callers get
a clean error rather than silent wrong-semantics.

---

## 9. Recommended fill-in order

Cheapest → most-expensive, by impact-per-LOC. Items struck through
have landed (see §10).

1. ~~Fix mismapped NT syscalls~~ — DONE (`ad32498`)
2. ~~`// STUB:` / `// GAP:` convention~~ — DONE (CLAUDE.md)
3. ~~Wire ucrtbase `fwrite` to `SYS_FILE_WRITE`~~ — DONE (`ad32498`)
4. **Add the 3 missing test-relevant capabilities** — PARTIAL:
   `kCapNet` + `kCapInput` landed (`3948bcd`). `kCapFramebuffer` /
   `kCapAudio` / `kCapSignal` / `kCapFork` / `kCapExec` deferred
   until their backing syscalls exist
5. ~~Implement registry read syscalls~~ — DONE for read path
   (`e60ce80` + `40a4230`), EXTENDED: registry value-write subset
   (`0caf60f`) — sidecar pool of mutable values; ENUMERATION
   landed (2026-04-29): static-tree gained 8 prefix entries so
   nested `RegOpenKey` walks one component at a time, kernel
   `DoEnumerateKey` op=9 lists direct children, `NtEnumerateKey`
   + advapi32 `RegEnumKey*` are real (no longer NotImpl stubs),
   `DoQueryKey` reports real subkey_count via `CountSubkeys`
6. ~~Cross-process VM access~~ — DONE (`23b2585` + `a2bb164`):
   NtOpenProcess + NtRead/Write/QueryVirtualMemory all live
7. ~~Thread manipulation~~ — DONE (`de3f155` + `c8f1bef` +
   `fa24d69`): NtSuspendThread / NtResumeThread / NtAlertResumeThread
   / NtGetContextThread / NtSetContextThread / NtOpenThread.
   Cross-process thread-hijack pipeline works end-to-end
8. ~~Section / view APIs~~ — DONE (`4891243`): NtCreateSection /
   NtMapViewOfSection / NtUnmapViewOfSection (anonymous /
   pagefile-backed only — file-backed is its own slice)
9. ~~FS mutation — rename / unlink~~ — DONE (`b50c26e`); symlinks
   deferred (FAT32 has no native; NTFS reparse points are a
   separate slice)
10. **Linux fork / clone / execve** — DONE: clone(CLONE_THREAD)
    `ae237a2`, fork() `c278041`, execve() `dc84b99` for static ELFs
11. ~~Implement socket family~~ — DONE (`f013268` + `97ac4b5`)
12. ~~NIC TX/RX paths for at least one driver~~ — DONE (e1000)
13. **NTFS / ext4 write paths** — STILL DEFERRED. Each ~2000 LOC.
    Lowest priority — read-only is acceptable for v0
14. ~~Linux pipe / pipe2 / eventfd / eventfd2~~ — DONE (`75bc4fa`)
15. ~~Linux timerfd / signalfd / epoll~~ — DONE (`3c9ec3a`):
    real engines built on WaitQueue + scheduler timer
16. ~~Linux wait4 / waitid + child-exit reaping~~ — DONE (`3c9ec3a`)
17. ~~Win32 FindFirstFile / FindNextFile / FindClose~~ — DONE
    (`074df0e`)
18. ~~Real NtQueryDirectoryFile + NtCreateFile FILE_DIRECTORY_FILE~~
    — DONE (`364814d`)
19. ~~Real inotify(7) + FS-mutation publish-subscribe~~ — DONE
    (`1d11b3b`)
20. ~~Real Linux signal delivery (default action)~~ — DONE
    (`6556b17`)
21. ~~Linux getdents64 + dirfd via shared snapshot pool~~ — DONE
    (`4b41615`)
22. ~~pidfd_open / pidfd_send_signal + splice / tee / vmsplice +
    PR_SET_NAME~~ — DONE (`3b7b753`)
23. ~~SysV shared memory + semaphores~~ — DONE (`8c2d619`)
24. **NT 100% coverage** — DONE (`a7c459e`): every NT call has at
    least a NotImpl facade; ~36 are real implementations
25. ~~SysV msg queues + POSIX msg queues~~ — DONE (`efe483e`):
    real ring + WaitQueue blocking; mtype filter (SysV) and
    priority delivery (POSIX); `Process::linux_fds` state 13
26. ~~Registry enumeration + nested OpenKey~~ — DONE (2026-04-29):
    8 prefix entries in the static tree make nested
    `RegOpenKey(parent, sub, &h)` walk one component at a time.
    `NtEnumerateKey` (op=9) + `RegEnumKey*` walk direct children.
    `DoQueryKey` reports `subkey_count` + `MaxNameLen` +
    `MaxValueNameLen` + `MaxValueDataLen`. `RegQueryInfoKeyA/W`
    + `RegEnumValueA` round out the userland API surface
27. ~~Win32 path translation (drive-letter + extended-prefix)~~ —
    DONE (2026-04-29): `kernel32::Win32PathPrefixA` + the
    `NormalizePathA/W` rewrite map `"C:\\..."` /
    `"\\?\C:\\..."` paths into the kernel's `/disk/N` form.
    Wired into `FindFirstFile*`, `DeleteFile*`, `MoveFile*`,
    `GetFileAttributes*`. `shlwapi::PathFileExists*` inlines a
    minimal mirror of the same translator and routes through
    `SYS_FILE_QUERY_ATTRIBUTES`
28. ~~`FindFirstFile*` glob filter~~ — DONE (2026-04-29):
    leaf glob (`*`/`?`) is parsed off the path, stored per
    handle in `g_find_slots[8]`, and `FindNextFile*` skips
    non-matching kernel-returned entries via `FindGlobMatch`
    (case-insensitive, recursive, bounded by the 63-byte
    pattern cap)

### Next slices (high-leverage, achievable)

- ~~**NtCreateUserProcess**~~ — DONE 2026-04-29 (RTL_USER_PROCESS_PARAMETERS
  parsing in ntdll, routes to existing SYS_PROCESS_SPAWN path-taking
  fast path)
- **NtCreateProcess / NtCreateProcessEx** (~400 LOC): legacy
  section-from-file spawn. Section-from-file path doesn't exist
  yet; PE-from-section is the bigger lift
- ~~**NtNotifyChangeDirectoryFile**: wire to inotify~~ — DONE (`4996457`)
- ~~**Real signal-handler trampoline + sigreturn**~~ — DONE
  (2026-04-29): `subsystems/linux/signal_deliver.{cpp,h}` plus
  hook in LinuxSyscallDispatch tail. Builds a saved frame on
  the user stack (LinuxSignalFrame, magic-guarded), mutates the
  trap frame so iretq lands in the handler with rdi=signum and
  rsp pointing at sa_restorer. rt_sigreturn (no longer the
  "kill on entry" stub) restores every register + signal mask
  from the saved frame. **Sub-GAPs**: SA_SIGINFO siginfo_t /
  ucontext_t pointers stub-zeroed; alt-stack delivery not
  honored; old-style no-SA_RESTORER callers see pending bit
  cleared with a serial warning
- ~~**POSIX message queues**~~ — DONE (`efe483e` + 2026-04-29 timeout honoring)
- ~~**SysV msg queues**~~ — DONE (`efe483e`)
- ~~**Real splice / tee zero-copy**~~ — DONE (2026-04-29):
  pipe→pipe fast path lands kernel-bypass via
  `PipeSpliceFromPipe` / `PipeTeeFromPipe` in
  `subsystems/linux/syscall_pipe.cpp`. No CopyToUser/FromUser
  bounce; rings are touched directly. `tee(pipe→pipe)` peeks
  without consuming. **Sub-GAPs**: file↔pipe paths still
  -EINVAL (need FAT32 integration); SPLICE_F_GIFT page-grant
  (vmsplice)
- ~~**NtAdjustPrivilegesToken honoring caps**~~ — DONE
  (2026-04-29): SYS_TOKEN_ADJUST = 169 with LUID→cap mapping for
  SeDebugPrivilege / SeBackupPrivilege / SeRestorePrivilege /
  SeIncreaseBasePriorityPrivilege; CapSetRemove helper;
  STATUS_NOT_ALL_ASSIGNED on enable-without-cap

### Audit cadence

Re-derive the inventory's structural numbers (§7 top-line
table) whenever:
- The NT or Linux syscall tables get regenerated
- A new big batch lands
- Otherwise quarterly

Cheap re-scan: `git grep -nE "// (STUB|GAP):"` for the marker
convention; counting `kSysNtNotImpl` occurrences for the NT
table; counting `case kSys.*:.*= kENOSYS;` for the Linux table.

---

## 10. Landed slice ledger

Each row = one slice that closed a gap. Append at the bottom when
a new slice lands. Hash is the merge / commit hash; impact field
captures what was unblocked. **Do not delete rows** — git history
already has the diffs, but this table is the human-readable
sequence of what got built when.

| Date | Commit | Slice |
|---|---|---|
| 2026-04-26 | `ad32498` | NT shim §1.2 mismaps: `NtWriteVirtualMemory` / `NtReadVirtualMemory` / `NtCreateSemaphore` / `NtReleaseSemaphore` route to `kSysNtNotImpl` (was: silent wrong-semantics). `NtSetInformationFile` kept at SYS_FILE_SEEK because position-info class is genuinely correct |
| 2026-04-26 | `ad32498` | ucrtbase §4.1: `fwrite(fd > 2)` routes to `SYS_FILE_WRITE` (was: silent 0). Stdio file writes from PEs actually land in FS now |
| 2026-04-26 | `3948bcd` | `kCapNet` + `kCapInput` caps added; STUB/GAP marker convention codified in CLAUDE.md |
| 2026-04-26 | `e60ce80` + `40a4230` | Registry read path: `SYS_REGISTRY = 130` op-multiplexed syscall + kernel-side static tree mirroring advapi32 well-known keys. ntdll thunks `NtOpenKey` / `NtOpenKeyEx` / `NtQueryValueKey` parse OBJECT_ATTRIBUTES + UNICODE_STRING |
| 2026-04-26 | `0caf60f` | Registry value-write subset: `kOpSetValue` / `kOpDeleteValue` / `kOpFlushKey` ops; 32-slot global sidecar pool of mutable values; ntdll grew `NtSetValueKey` / `NtDeleteValueKey` / `NtFlushKey` |
| 2026-04-26 | `23b2585` | NtOpenProcess (foundational): `SchedFindProcessByPid`, `Win32ProcessHandle` table at base 0x700, `SYS_PROCESS_OPEN = 131` cap-gated on kCapDebug |
| 2026-04-27 | `a2bb164` | Cross-process VM access: `SYS_PROCESS_VM_READ = 132`, `SYS_PROCESS_VM_WRITE = 133`, `SYS_PROCESS_VM_QUERY = 134`. Per-call cap 16 KiB; `kSyscallProcessVmMax` |
| 2026-04-27 | `de3f155` | Thread suspend / resume: `Task::suspend_count`, `g_suspended_head/tail`, `SchedSuspendTask` / `SchedResumeTask`, `SYS_THREAD_SUSPEND = 135` / `SYS_THREAD_RESUME = 136`, `NtSuspendThread` / `NtResumeThread` / `NtAlertResumeThread` |
| 2026-04-27 | `c8f1bef` | NtGetContextThread / NtSetContextThread: `Win32Context` mirrors first 0x100 of MS x64 CONTEXT, `SYS_THREAD_GET_CONTEXT = 137` / `SYS_THREAD_SET_CONTEXT = 138`. SET sanitises rflags + forces user CS/SS |
| 2026-04-27 | `fa24d69` | NtOpenThread: `SchedFindTaskByTid`, `Win32ForeignThreadHandle` at base 0x800, `SYS_THREAD_OPEN = 139` cap-gated on kCapDebug. Cross-process thread-hijack pipeline complete |
| 2026-04-26 | `4891243` | NtCreateSection / NtMapViewOfSection / NtUnmapViewOfSection: anonymous / pagefile-backed only. 8-slot global section pool, borrowed-page primitives |
| 2026-04-27 | `b50c26e` | FS unlink + rename: FAT32 `Fat32RenameAtPath`, tmpfs `TmpFsRename`. `SYS_FILE_UNLINK = 143` + `SYS_FILE_RENAME = 144`. kernel32 `DeleteFileA/W` + `MoveFileA/W` + ntdll `NtDeleteFile` |
| 2026-04-27 | `ae237a2` + `c278041` + `dc84b99` | Linux clone(CLONE_THREAD) for pthread_create + full fork() with deep AS copy + execve() for static ELFs (in-place AS replacement) |
| 2026-04-27 | `75bc4fa` | Linux pipe / pipe2 / eventfd / eventfd2: 16-slot kernel ring buffers with WaitQueue blocking |
| 2026-04-27 | `f013268` + `97ac4b5` | BSD socket family — Linux socket pool + Win32 ws2_32 routed through SYS_SOCKET_OP |
| 2026-04-27 | `a7c459e` | NT 100% coverage — bulk-generated NotImpl facades for all 506 Bedrock + Win11-25H2 calls |
| 2026-04-27 | `3c9ec3a` | timerfd / signalfd / epoll engines + wait4 / waitid + SIGCHLD reaping. `syscall_async_io.{cpp,h}` with state 7/8/9 LinuxFds. Process gained `linux_parent_pid` / `linux_exit_code` / `linux_was_signaled` / `linux_exit_signal` / `linux_child_exits[8]` queue / `linux_wait_wq` |
| 2026-04-27 | `074df0e` | Win32 directory enumeration: `SYS_DIR_OPEN = 154` / `SYS_DIR_NEXT = 155`, 8-slot `Win32DirHandle[]` at base 0xA00. `FindFirstFileA/W` / `FindNextFileA/W` / `FindClose` real thunks marshaling 96-byte `Win32DirEntryReport` into `WIN32_FIND_DATAA/W` |
| 2026-04-27 | `364814d` | Real `NtQueryDirectoryFile` + `RestartScan`: `SYS_DIR_REWIND = 156`, `NtCreateFile` detects `FILE_DIRECTORY_FILE`, real thunk supports four `FILE_INFORMATION_CLASS` values. Single-entry-per-call (sub-GAP) |
| 2026-04-27 | `1d11b3b` | Real `inotify(7)` engine: 8 instances × 16 watches × 32-event ring. `InotifyPublish(path, mask)` is the publish-subscribe entry point; FS-mutation hooks fire from `file_route.cpp` + `syscall_fs_mut.cpp`. State 10 LinuxFd |
| 2026-04-27 | `6556b17` | Real Linux signal delivery (default action + signalfd events): kill / tgkill cross-process; Process gained `linux_pending_signals` + `linux_signal_wq`; `LinuxSignalDeliver` dispatches SIG_DFL fatals via `SchedKillByProcess`, drops SIG_IGN, queues user handlers (no trampoline yet — sub-GAP). signalfd_read drains pendings with real 128-byte signalfd_siginfo |
| 2026-04-27 | `4b41615` | Real Linux `getdents64` + dirfd via shared snapshot pool. State 11 LinuxFd. `subsystems/win32/dir_syscall.{cpp,h}` exposed `SysDirOpenKernel` for cross-subsystem use. `linux_dirent64` marshaling |
| 2026-04-27 | `3b7b753` | Linux pidfd family (state 12) + splice/tee/vmsplice + PR_SET_NAME. pidfd_open ProcessRetains target; pidfd_send_signal forwards to `LinuxSignalDeliver`. splice/tee return -EINVAL (lib fallback); vmsplice honours iovec→pipe direction. `Process::linux_task_name[16]` matches TASK_COMM_LEN |
| 2026-04-27 | `8c2d619` | SysV shared memory + semaphores. shm: 8-segment global pool, frames mapped via `AddressSpaceMapBorrowedPage` at per-process arena (`kLinuxShmArenaBase = 0x70000000`); `Process::linux_shm_attaches[8]` table. sem: 8-set / 16-sem-per-set pool, `SemTryApplyLocked` atomic-batch with WaitQueue blocking |
| 2026-04-27 | `efe483e` | SysV msg queues + POSIX msg queues. SysV: 8-queue keyed pool, 16-msg ring of 1024-byte messages, mtype filter (== / 0 = any / < 0 = any ≤ filter), IPC_NOWAIT honoured. POSIX: 8-queue named pool, LinuxFd state 13, refcounted (mq_unlink + close-of-last frees), highest-priority delivery, mq_notify -ENOSYS. **Sub-GAPs**: ~~mq_timedsend / mq_timedreceive ignore timeout argument~~ FIXED 2026-04-29 — abs_timeout (struct timespec, treated as ns-since-boot) now honored via WaitQueueBlockTimeout; deadline-in-past returns -ETIMEDOUT immediately; null pointer = block forever; mq_getsetattr SET no-op; 1024-byte msg cap; 16-msg ring cap |
| 2026-04-27 | `108064b` | name_to_handle_at + open_by_handle_at flipped from -ENOSYS to real (FAT32 first_cluster + size encoded as 8-byte file_handle; root-only resolution sub-GAP). Modern mount API (fsopen / fsconfig / fsmount / fspick / open_tree / move_mount / mount_setattr) → -EPERM (was -ENOSYS) for honest CAP_SYS_ADMIN-style fallback. Net: 2 real + 7 EPERM |
| 2026-04-27 | `60bda43` | bpf / perf_event_open / init_module / finit_module / delete_module / kexec_load / kexec_file_load → -EPERM (matches Linux CAP_SYS_ADMIN gating); flock fd-validity gate (was: silent success on bad fd) |
| 2026-04-27 | `879f2e5` | Real pidfd_getfd cross-process fd dup. Cap-gated on kCapDebug. Pool-backed states (pipe / eventfd / socket / timerfd / signalfd / epoll / inotify / pidfd / mq) supported via slot-copy + refcount bump. Regular file / dirfd / memfd refused (-EINVAL) — real Linux uses shared file-descriptions; v0 sub-GAP |
| 2026-04-27 | `be744fc` | Real IOCP + JobObject engines (10 NT calls). **IOCP**: 8-port pool, 16-packet ring per port, SYS_IOCP_CREATE/SET/REMOVE/CLOSE (159-162), kCapSpawnThread-gated, WaitQueue blocking, handles 0xB00..0xB07. NtCreateIoCompletion / NtSetIoCompletion / NtRemoveIoCompletion / NtRemoveIoCompletionEx flipped from NotImpl to real. **JobObject**: 8-job pool, refcounted, 32 procs/job, SYS_JOB_CREATE/ASSIGN/IS_IN/TERMINATE/QUERY/CLOSE (163-168), handles 0xC00..0xC07. NtCreateJobObject / NtAssignProcessToJobObject / NtIsProcessInJob / NtTerminateJobObject / NtQueryInformationJobObject flipped to real. QueryInformationJobObject info classes 2 / 3 / 8 implemented. TerminateJobObject calls SchedKillByProcess on every member. **Sub-GAPs**: IOCP timeout / file-handle-association deferred; Job per-resource limits accepted but not enforced; Job info classes outside {2, 3, 8} -EINVAL |
| 2026-04-27 | `1ed6a6d` | Real CreateProcessA / CreateProcessW + new SYS_PROCESS_SPAWN. kernel-side handler in `subsystems/win32/spawn_syscall.{cpp,h}` reads named PE / ELF off FAT32 (`/disk/<idx>/<rest>`), autodetects format by magic (MZ / `0x7F ELF`), dispatches to existing SpawnPeFile / SpawnElfFile. Cap-gated on kCapSpawnThread. CreateProcessA/W kernel32 thunks fill PROCESS_INFORMATION with new pid. Caller inherits caps + root + tick_budget. **Sub-GAPs**: lpStartupInfo / lpEnvironment / lpCurrentDirectory / dwCreationFlags / bInheritHandles all ignored; hThread = 0 (callers can NtOpenThread the tid); 16 MiB file cap; "/disk/<idx>" paths only (no Win→Unix path translator yet); first-token cmdline parsing is literal-pointer (no quoted-multiword); NtCreateUserProcess still NotImpl pending RTL_USER_PROCESS_PARAMETERS parsing |
| 2026-04-27 | `4996457` | Real NtNotifyChangeDirectoryFile + new SYS_DIR_NOTIFY engine. Win32DirHandle gained `path[64]` (cached at SysDirOpenKernel time). New 8-slot subscriber pool in dir_syscall.cpp; each sub has {path, filter, subtree, last_action, last_name, wq}. SysDirNotify allocates sub, blocks on wq, writes single FILE_NOTIFY_INFORMATION record (12 + UTF-16 name) on wake. **Publish-side**: `Win32DirNotifyPublish(path, in_mask)` invoked from `InotifyPublish` (same fan-out point fanotify uses). IN_*→FILE_ACTION_* translation: IN_CREATE→ADDED, IN_DELETE→REMOVED, IN_MOVED_FROM/TO→RENAMED_OLD/NEW_NAME, IN_MODIFY→MODIFIED. FILE_NOTIFY_CHANGE_* filter bits honoured (FILE_NAME / DIR_NAME / ATTRIBUTES / SIZE / LAST_WRITE). ntdll thunk issues SYS_DIR_NOTIFY directly. Sub-GAPs: single-record-per-call (callers loop); Event / ApcRoutine / ApcContext accepted but not honoured |
| 2026-04-27 | `63a1c15` | fanotify(7) + keyrings + clock_settime/adjtime/adjtimex/settimeofday. **fanotify**: 4-instance / 16-mark / 32-event ring, LinuxFd state 15. Subscribes to the FS-mutation publish path that powers inotify; same exact-path-or-parent matcher, fanotify wire mask translated from inotify bits. 24-byte struct fanotify_event_metadata. fd field = FAN_NOFD; pid = 0. **keyrings**: per-process 16-key store keyed by pid (up to 32 processes). add_key (type "user" / "logon" only), request_key (lookup by type+desc), keyctl (GET_KEYRING_ID / READ / DESCRIBE / UPDATE / SETPERM / SEARCH / INVALIDATE / REVOKE / UNLINK / CLEAR + accept-as-noop for chown/link/timeout/etc.). 256-byte payload cap. **clock writeback**: clock_settime / clock_adjtime / settimeofday / adjtimex all -EPERM (no RTC writeback). Net: 9 syscalls flipped from -ENOSYS / facade to real-or-honest |
| 2026-04-29 | (this slice) | NtAdjustPrivilegesToken cap-honoring — SYS_TOKEN_ADJUST = 169 in `subsystems/win32/token_syscall.{cpp,h}`. LUID→cap map: SeDebugPrivilege (20)→kCapDebug, SeBackupPrivilege (17)→kCapFsRead, SeRestorePrivilege (18)→kCapFsWrite, SeIncreaseBasePriorityPrivilege (14)→kCapSpawnThread. SE_PRIVILEGE_REMOVED / DisableAllPrivileges drop the mapped cap (CapSetRemove helper, also new). Enable-without-cap returns STATUS_NOT_ALL_ASSIGNED (0x00000106) — no path adds caps from user space. PreviousState writeback honored when caller buffer fits |
| 2026-04-27 | `f8998d8` | 33 modern Linux syscalls in one TU (`extra_syscalls.cpp`). Real (5): **statx** (256-byte struct, STATX_BASIC_STATS); **copy_file_range** (4 KiB-stage bounce; cap-gated on kCapFsWrite); **memfd_create** (8-slot pool, LinuxFd state 14, 1-page initial alloc); **close_range** (skip stdin/out/err); **statfs / fstatfs** (FAT-shaped defaults). No-op success (8): NUMA family (set/get_mempolicy / mbind / migrate_pages / move_pages), mseal, process_madvise, process_mrelease. Honest -ENOSYS / -EINVAL (20): userfaultfd, io_uring_*, name_to_handle_at / open_by_handle_at, fsopen / fsconfig / fsmount / fspick / open_tree / move_mount / mount_setattr, landlock_*, pkey_alloc / pkey_free / pkey_mprotect (forwards to mprotect, key ignored). DoClose / DoFork arms wired for state 14. **Sub-GAPs**: statx timestamps + dio_align stamped 0; copy_file_range FAT32 only; memfd ftruncate-grow not wired; statfs defaults regardless of path/fd; mseal advisory not enforced; landlock returns -ENOSYS to avoid false-sandbox advertisement |

---

## 11. Violation history

| Date | Commit | Violation | Fix |
|---|---|---|---|
| 2026-04-27 | `0caf60f` (introduced) → fix in `bb6f872` | `SYS_REGISTRY` op `kOpSetValue` / `kOpDeleteValue` not cap-gated. Any sandboxed PE could mutate kernel-side registry sidecar | Add `core::CapSetHas(proc->caps, core::kCapFsWrite)` check at the top of `DoSetValue` + `DoDeleteValue` before any sidecar mutation. Record sandbox denial on miss |

---

## 12. Cross-references

- **CLAUDE.md** → "Subsystem isolation (DO NOT VIOLATE)" — repeats
  the §2 rules for every session start
- **README.md** → "Subsystem isolation rule" callout
- **`.claude/knowledge/redteam-coverage-matrix-v0.md`** —
  malware-technique map vs probes / attacks / detectors. When a
  slice from the recommended order lands, both this file's §10
  Landed table AND the matrix's relevant rows need updates
- **`.claude/knowledge/sandbox-overview-v0.md`** — consolidated
  5-wall sandbox story (AS / caps / VFS / W^X / budget)
- **`.claude/knowledge/process-capabilities-v0.md`** — Process +
  CapSet model with cap-gated syscalls

When a kernel surface becomes "real" rather than facade /
NotImpl, update §3 (remove from facades), §4 (add to gates if
new gate), §5 or §6 (note in subsystem state), §7 (top-line
numbers move), §9 (strike through landed item), §10 (append row).
