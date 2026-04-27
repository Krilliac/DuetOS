# Stub & gap inventory — v0

**Type:** Observation + Decision
**Status:** Active
**Last updated:** 2026-04-26

## What it is

Comprehensive catalogue of every interface in DuetOS that returns
"not implemented", returns a stub value, is mismapped, or doesn't
exist where you'd expect it. Built from a tree-wide audit of the NT
+ Linux syscall tables, Win32 user-mode DLL thunks, userland
libraries, kernel core handlers, capability framework, drivers, and
filesystems.

This doc is a **work queue** — each row is a gap that the team can
work through. When a gap is closed, mark it with the commit hash and
move it to the "Landed" table at the bottom.

## Top-line numbers

| Surface | Total | Implemented | Stubbed / unimpl |
|---|---|---|---|
| NT syscall table (Bedrock set) | 292 | 28 (9.6 %) | **264** |
| NT syscall table (Win11 superset) | 489 | ~28 | ~461 |
| Linux syscall table | 374 | 143 (38.2 %) | **233** |
| Kernel-side stub handlers | — | — | 18 |
| Win32 user-mode thunks (no-op / constant returners) | — | — | ~15 |
| Userland-DLL stub functions | — | — | ~30+ |
| Capabilities defined vs. needed | 7 | 7 | 5 missing (Framebuffer / Audio / Signal / Fork / Exec) |
| Filesystems with full write support | 6 | 2 (FAT32 partial, tmpfs) | 4 |
| Driver subsystems with packet I/O | 4 | 0 | 4 (net / audio / GPU / USB-bulk) |

**~1 050+ discrete gaps catalogued.** The headline is that the NT
syscall surface is the single biggest blocker for "real Windows
malware can run and be tested" — 90 % of Bedrock NT calls return
`NotImpl`. Below that, Linux syscall coverage is the next most
impactful at 62 % unimplemented.

## 1. Win32 NT syscall table

**File:** `kernel/subsystems/win32/nt_syscall_table_generated.h`

### 1.1 By family — how many of each are stubbed

| Family | Stubbed | Notable examples | Blocks |
|---|---|---|---|
| Registry | 17 | NtOpenKey, NtQueryValueKey, NtCreateKey, NtSetValueKey, NtDeleteKey, NtEnumerateKey, NtFlushKey | All registry-using apps; HKLM/HKCU reads |
| Process control | 12 | NtCreateProcess, NtCreateProcessEx, NtCreateThread, NtOpenProcess, NtQueryInformationProcess, NtSetInformationProcess, NtTerminateProcess | Multi-process apps; subprocess spawn; cross-process malware techniques |
| Memory query / map | 8 | NtQueryVirtualMemory, NtProtectVirtualMemory, NtMapViewOfSection, NtUnmapViewOfSection, NtAllocateVirtualMemoryEx | App runtime memory inspection; SEH unwind; process hollowing |
| Token / security | 15 | NtOpenProcessToken, NtQueryInformationToken, NtAdjustPrivilegesToken, NtDuplicateToken, NtAccessCheck | Privilege checks; ACL evaluation; impersonation; UAC |
| File / directory | 9 | NtQueryDirectoryFile, NtNotifyChangeDirectoryFile, NtQueryAttributesFile, NtSetEaFile | Directory enumeration; file change watching; extended attributes |
| Object management | 11 | NtDuplicateObject, NtQueryObject, NtOpenThreadToken, NtOpenThreadTokenEx | Handle duplication; object introspection |
| Debug / trace | 6 | NtDebugActiveProcess, NtDebugContinue, NtQueryDebugFilterState | Debugger attach; exception filtering |
| Port / RPC (LPC/ALPC) | 10 | NtCreatePort, NtListenPort, NtConnectPort, NtRequestPort, NtReplyPort, NtAlpcCreatePort | LPC / ALPC inter-process communication |
| Job / quota | 5 | NtCreateJobObject, NtAssignProcessToJobObject, NtQueryInformationJobObject | Job objects; resource limits |
| Thread manipulation | 6 | NtSuspendThread, NtResumeThread, NtSetContextThread, NtGetContextThread, NtAlertResumeThread | Thread hijack malware techniques; debugger thread control |
| Other (transactions, waits, set-info variants, etc.) | 175+ | NtTransactionCommit, NtWaitForMultipleObjects, NtSetInformation* | Complex subsystems not implemented yet |

### 1.2 Mismapped syscalls (semantically wrong target)

These compile to valid syscall numbers but the target SYS_* doesn't
do what the NT name implies — silent semantic bugs that would surface
the moment a real PE called them.

| NT call | Wrong mapping | What it should do | What it actually does |
|---|---|---|---|
| ~~`NtWriteVirtualMemory` (0x003a)~~ | ~~→ `SYS_WRITE`~~ | ~~Write bytes into another process's address space~~ | ~~Treats arg as fd + buffer + count → file write~~ — **FIXED** (commit `ad32498` → NotImpl; pending commit → real `SYS_PROCESS_VM_WRITE`) |
| ~~`NtReadVirtualMemory` (0x003f)~~ | ~~→ `SYS_READ`~~ | ~~Read bytes from another process's AS~~ | ~~Treats arg as fd + buffer + count → file read~~ — **FIXED** (commit `ad32498` → NotImpl; pending commit → real `SYS_PROCESS_VM_READ`) |
| `NtSetInformationFile` (0x0027) | → `SYS_FILE_SEEK` | Set arbitrary file attributes (rename, delete-on-close, position, etc.) | Only handles position |
| ~~`NtReleaseSemaphore` (0x000a)~~ | ~~→ `SYS_EVENT_SET`~~ | ~~Increment semaphore count~~ | ~~Sets a binary event (wrong semantics — semaphores have a count)~~ — **FIXED** (commit `ad32498` → NotImpl) |
| ~~`NtCreateSemaphore` (0x00c7)~~ | ~~→ `SYS_EVENT_CREATE`~~ | ~~Create counted semaphore~~ | ~~Creates a binary event~~ — **FIXED** (commit `ad32498` → NotImpl) |
| `NtCreateMutant` (— check) | (suspect) | Create a mutex (Mutant in NT lingo) | Likely also collapsed onto another primitive |

**Action:** these need either correct dedicated SYS_* implementations or to be remapped to `kSysNtNotImpl` so callers get a clean error rather than silent wrong-semantics.

## 2. Linux syscall table

**File:** `kernel/subsystems/linux/linux_syscall_table_generated.h`
**Coverage:** 143 / 374 implemented (38.2 %); **233 unimplemented**.

### 2.1 By family

| Family | Examples | Blocks |
|---|---|---|
| Process / fork | clone, clone3, fork, vfork, execve, execveat, wait4, waitid | Multi-process work; shell scripts; job control |
| Event loop | epoll_create, epoll_ctl, epoll_wait, select, pselect6, poll, ppoll | Async I/O; server multiplexing |
| Timers / event FDs | eventfd, eventfd2, timerfd_create, timerfd_settime, timerfd_gettime, signalfd, signalfd4 | Async timers; signal-driven I/O |
| IPC / messaging | mq_open, mq_send, mq_receive, semctl, semget, semop, msgctl, msgget, msgrcv, shmctl, shmget, shmat | POSIX IPC primitives |
| Sockets | socket, accept, listen, bind, connect, send, recv, sendto, recvfrom, sendmsg, recvmsg | All network communication |
| Filesystem mutation | mkdir, mkdirat, rmdir, unlink, unlinkat, rename, renameat, link, linkat, symlink, symlinkat, chmod, fchmod, chown, fchown, chdir | Directory ops; file deletion; attribute changes |
| Mount / admin | mount, umount2, pivot_root, chroot, quotactl, sysinfo, sysctl, _sysctl | Filesystem mounting; namespaces |
| Signals (partial) | rt_sigaction (some variants), rt_sigprocmask, rt_sigaltstack, sigpending | Signal-handling gaps |
| Advanced memory | mlock, mlockall, madvise, get_mempolicy, set_mempolicy, mbind | Memory locking; NUMA |
| Namespace / container | unshare, setns, prctl (many opts), personality, ioprio_get/set | Container features |
| Ptrace / debug | ptrace, process_vm_readv, process_vm_writev | Debugger ops; cross-process VM access |
| BPF / trace | bpf, perf_event_open, trace_* | eBPF; tracing infrastructure |
| Audit | audit_* (8+ syscalls) | Kernel auditd logging |

### 2.2 Stub handlers in `kernel/subsystems/linux/syscall_stub.cpp`

These return canonical errors so library fallbacks engage cleanly:

| Handler | Returns | Lines | Effect |
|---|---|---|---|
| `DoPipe` / `DoPipe2` | `-ENFILE` | 39–49 | Pipe pair creation; libc falls back to socketpair (also stubbed) |
| `DoWait4` / `DoWaitid` | `-ECHILD` | 54–70 | Wait for child; no fork → no children to wait on |
| `DoEventfd` / `DoEventfd2` | `-ENOSYS` | 75–80 | Event FD creation |
| `DoTimerfdCreate` / `DoTimerfdSettime` / `DoTimerfdGettime` | `-ENOSYS` | 81–100 | Timer FD ops |
| `DoSignalfd` / `DoSignalfd4` | `-ENOSYS` | 101–108 | Signal → FD conversion |
| `DoEpollCreate` / `DoEpollCreate1` | `-ENOSYS` | 140–149 | Epoll instance |
| `DoEpollCtl` / `DoEpollWait` / `DoEpollPwait` | `-ENOSYS` | 150–171 | Epoll add/wait |
| `DoInotifyInit` / `DoInotifyInit1` | `-ENOSYS` | 172–180 | File-watch notifications |
| `DoPtrace` | `-EPERM` | 189–196 | Process debugging |
| `DoSyslog` | `0` (success, no-op) | 201–207 | Kernel-log read returns nothing |
| `DoVhangup` | `0` | 210–213 | Terminal revoke: no-op |
| `DoAcct` | `0` | 216–220 | Process accounting: no-op |
| `DoMount` / `DoUmount2` | `-EPERM` | 225–239 | Filesystem mounting denied |
| `DoSync` / `DoSyncfs` | `0` (no-op) | 244–252 | Sync returns success but nothing syncs |
| `DoRename` / `DoLink` / `DoSymlink` | `-ENOSYS` | 258–275 | Path mutations |
| `DoSetThreadArea` / `DoGetThreadArea` | `-EINVAL` | 279–288 | x86-32 LDT TLS (64-bit uses arch_prctl) |
| `DoIoprioGet` / `DoIoprioSet` | `0` | 292–304 | I/O priority flat |
| `DoFadvise64` / `DoReadahead` | `0` | 114–136 | Readahead hints accepted, ignored |

## 3. Win32 user-mode DLL thunks

**File:** `kernel/subsystems/win32/thunks.cpp` (~900 lines, ~2 KB+ of bytecode)

| Stub kind | Count | Examples | Blocks |
|---|---|---|---|
| Constant returners | 8+ | `kOffReturnZero`, `kOffReturnOne`, `kOffReturnTwo`, `kOffReturnMinus1`, `kOffReturnPrioNormal` (0x20) | Apps checking return values; priority detection |
| No-op `ret`-only thunks | 5+ | `kOffCritSecNop`, `GetConsoleMode` (1), `GetConsoleCP` (65001), `SetConsoleMode` | CritSec ops; console mode |
| Logging stubs | 1 | `kOffMissLogger` (41-byte SerialWrite stub) | Diagnostic info only — apps fail silently |
| Stub landing pads | 15+ | D3D11CreateDevice, D3D11CreateRenderTarget, similar in user32/gdi32 | 3D graphics init |

### 3.1 Per-DLL severity

| DLL | Stubbed surface | Severity |
|---|---|---|
| kernel32 | CreateProcessW/A, GetModuleHandle (4-byte stub), GetTickCount, GetTickCount64 | HIGH — process spawn, module loading |
| user32 | GetMessageW, DispatchMessageW (real thunks but limited) | MEDIUM — message loop |
| gdi32 | CreatePen, CreateBrush, SelectObject (real but partial) | MEDIUM — drawing objects |
| d3d9/11/12 | D3DCreate*, D3DGetVersion (landing pads only) | HIGH — graphics |
| advapi32 | OpenProcessToken (real 13-byte thunk), LookupPrivilegeValue (13-byte thunk) | MEDIUM — security |
| ucrtbase | malloc, free, realloc (real thunks) | LOW — heap working |

## 4. Userland library stubs

**Location:** `userland/libs/*/`

### 4.1 ucrtbase (the biggest landmine)

| Function | Behaviour | Line | Effect |
|---|---|---|---|
| `fwrite(fd > 2)` | Returns 0 | ucrtbase.c:780-786 | **Real file writes silently drop** — apps think they wrote 0 bytes |
| `fprintf` to non-console | 0 | (via fwrite) | File logging fails silently |
| `fputs` to non-console | 0 | (via fwrite) | Same |
| `fseek` to non-console | 0 | — | Seek fails |
| `setvbuf` / `setbuf` | 0 (success stub) | — | Buffering ops succeed but do nothing |

**This `fwrite` gap was the immediate blocker for the redteam FS-flood payload — any "ransomware" PE that uses standard CRT file APIs writes nothing. Workaround: inline `int 0x80` to SYS_FILE_WRITE directly, or use Win32 `WriteFile` (which does work).**

### 4.2 Other DLLs

| DLL | Function | Returns | Blocks |
|---|---|---|---|
| msvcrt | `_setmode` | -1 for non-standard FDs | Mode changes fail |
| msvcrt | `isatty` | Constant 1 for all FDs | All FDs appear to be TTY |
| user32 | MessageBox, DialogBox | Stub success; no actual UI | No UI dialogs |
| gdi32 | GetDeviceCaps | Hardcoded device values | Renders may fail on real device queries |
| advapi32 | RegOpenKeyEx, RegQueryValueEx | Stub 0 / empty strings | Registry reads fail or return empty |
| ws2_32 | socket, WSASocket | Stub 0 or invalid handles | Network sockets cannot be created |
| comdlg32 | GetOpenFileName, GetSaveFileName | Returns IDCANCEL | File dialogs always cancel |

## 5. Kernel core syscall handlers

**File:** `kernel/syscall/syscall.cpp`

The native DuetOS syscall surface (SYS_* numbers 0–58+) is mostly
implemented; gaps are concentrated in the Linux + NT subsystem
adapters. The kernel-side stubs documented in §2.2 are the
canonical "this Linux call has no implementation" set.

Notable native-ABI gaps:

| Syscall | State | Notes |
|---|---|---|
| `SYS_FILE_WRITE` (43) | Implemented | Routes to `subsystems::win32::DoFileWrite` |
| `SYS_FILE_CREATE` (44) | Implemented but limited | Creates files only in writable mounts (tmpfs); ramfs is read-only |
| `SYS_FORK` / `SYS_CLONE` | **Missing** | No multi-process primitive on the native ABI |
| `SYS_EXEC` | **Missing** | No native exec — only PE/ELF spawn at task creation |
| Cross-process VM access | **Missing** | No native syscall for inspecting/modifying another process's AS |
| Signals | **Missing** | No native signal delivery primitive |

## 6. Capability framework

**File:** `kernel/proc/process.h:56-114`

### Defined caps

| Cap | Value | Gates |
|---|---|---|
| `kCapNone` | 0 | (reserved) |
| `kCapSerialConsole` | 1 | `SYS_WRITE(fd=1)` to COM1 |
| `kCapFsRead` | 2 | `SYS_STAT`, file metadata reads |
| `kCapDebug` | 3 | `SYS_BP_INSTALL` / `SYS_BP_REMOVE` |
| `kCapFsWrite` | 4 | `SYS_FILE_WRITE`, `SYS_FILE_CREATE` |
| `kCapSpawnThread` | 5 | `SYS_THREAD_CREATE` |
| `kCapNet` | 6 | Linux BSD-socket family (`socket` / `socketpair` / `accept` / `connect` / `bind` / `listen` / `shutdown` / `getsockname` / `getpeername` / `getsockopt` / `setsockopt` / `send*` / `recv*`). Withheld → -EACCES |
| `kCapInput` | 7 | `SYS_WIN_GET_KEYSTATE` (key polling) + `SYS_WIN_GET_CURSOR` (cursor polling). Withheld → "no key pressed" / "cursor at (0,0)" deception (the call still returns success so the caller's polling loop doesn't trip an error path) |

### Missing caps (would gate currently-ungated operations)

| Missing cap | Would gate | Blocks (testing-side) |
|---|---|---|
| `kCapFramebuffer` | Framebuffer / DRM reads / writes | Screen-scraper prevention. Deferred until a user-mode FB-readback or direct-FB-write syscall actually exists — adding the cap before the gate site would be dead code |
| `kCapAudio` | Audio capture / playback | Microphone-snoop prevention |
| `kCapSignal` | Sending signals to other processes | Cross-process signal-based attack prevention |
| `kCapFork` | Process duplication | Currently no fork — moot until impl'd |
| `kCapExec` | Exec a different image | Currently no exec — moot until impl'd |

These five caps are the remaining infrastructure that blocks the
screen-grab / audio-snoop / cross-proc-signal / fork-exec slices of
the redteam coverage matrix. Each one only earns its existence once
its target syscall does — see the §12 Landed entry for the policy.

## 7. Drivers

### 7.1 Network — discovery only, no I/O

**Scope today:** PCIe enumeration + classification + MMIO BAR map. **Zero packet I/O.**

| NIC | Probe | MAC read | Link state | TX path | RX path | IRQ |
|---|---|---|---|---|---|---|
| Intel e1000 | ✅ | partial | NO | NO | NO | NO |
| Realtek RTL88xx | ✅ | partial | NO | NO | NO | NO |
| Broadcom bcm43xx | ✅ | NO | NO | NO | NO | NO |
| Intel iwlwifi | ✅ | NO | NO | NO | NO | NO |
| Virtio-net | ✅ | partial | NO | NO | NO | NO |
| USB CDC-ECM | ✅ | partial | partial | partial | partial | NO (probe not auto-called) |
| USB RNDIS | ✅ | partial | partial | partial (control plane) | partial | bulk concurrency gap |

**Per `NicInfo` (kernel/drivers/net/net.h:78):** every entry reports `link_up = false`.

### 7.2 Audio — PC speaker only

| Driver | State |
|---|---|
| PC speaker (pcspk) | ✅ Implemented |
| Intel HDA | ❌ probe only, no codec/stream setup |
| AC'97 | ❌ |
| USB audio class | ❌ |

### 7.3 GPU — discovery + framebuffer-blit only

| Driver | State |
|---|---|
| Bochs VBE | ✅ framebuffer init |
| Virtio-GPU | ✅ framebuffer init |
| Intel iGPU | ❌ probe only |
| AMD Radeon | ❌ probe only |
| NVIDIA | ❌ probe only |

D3D9 / D3D11 / D3D12 user-mode DLLs are landing pads; no actual
rendering. Vulkan ICD does not exist.

### 7.4 USB

xHCI host controller works (HID keyboard end-to-end). Bulk-transfer
API has known concurrency gap (RNDIS bulk-poll serialisation —
see `.claude/knowledge/usb-rndis-driver-v0.md`).

## 8. Filesystem backends

| FS | Read | Write | Create | Rename | Unlink | Symlink | Notes |
|---|---|---|---|---|---|---|---|
| ramfs (built-in) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | Compile-time tree; `/tmp` punches a tmpfs hole |
| tmpfs | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | Mutable in-memory; no rename/unlink yet |
| FAT32 | ✅ | ✅ | ✅ | ❌ | ❌ | n/a | Create/write work; mutation incomplete |
| exFAT | ✅ | ✅ | ✅ | ❌ | ❌ | n/a | Same shape as FAT32 |
| ext4 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | **Read-only** — no Linux data partition writes |
| NTFS | partial | ❌ | ❌ | ❌ | ❌ | ❌ | **Read-only** + NTFS parsing incomplete |

**Critical gap for adversarial tests:** no FS supports `rename` /
`unlink` / `symlink` from any code path. So the symlink-race
(TOCTOU) attack class can't be tested even synthetically.

There is no `mount` / `umount` syscall — the filesystem topology is
static at boot. Per-process root is set once via `Process::root` at
`ProcessCreate`.

## 8.5 Build-tooling gaps discovered during this audit

| Gap | File | Impact |
|---|---|---|
| `tools/linux-compat/gen-linux-syscall-table.py` only scans `kernel/subsystems/linux/syscall.cpp` for `Do*` handlers, but the dispatcher was refactored into 16 separate files (`syscall_file.cpp`, `syscall_cred.cpp`, `syscall_path.cpp`, …). Regenerating the Linux syscall artifact resets coverage to 0% and clobbers the Implemented annotations. | `tools/linux-compat/gen-linux-syscall-table.py:212-216` | Anyone running `tools/build/regenerate-syscall-artifacts.sh` silently corrupts the Linux table. Need to either pass a glob (`syscall*.cpp`) or scan the whole `kernel/subsystems/linux/` directory. ~10-line fix. |

## 9. TODO / FIXME / XXX markers in source

The codebase doesn't lean on TODO markers — gaps are encoded
structurally (`kSysNtNotImpl`, `DoXxx_Stub`, `kOffReturnZero`, etc.)
rather than via comment annotations. The few text markers found:

| File:line | Marker | Notes |
|---|---|---|
| `kernel/subsystems/win32/thunks.cpp:386` | "unhandled-filter offset no longer matches `SetUnhandledExceptionFilter` stub bytes" | Bytecode offset validation — needs re-derivation when the stub region changes |
| `kernel/subsystems/win32/proc_env.cpp:28` | "stub; no syscall on the hot path" | Process env loading |
| `kernel/subsystems/win32/window_syscall.cpp:77` | Note about `kOffReturnOne` legacy convention | Message-handling artefact |
| `kernel/subsystems/linux/translate.cpp:367` | "doesn't implement the machinery; return -ENOSYS" | Linux → NT translation |

**Action:** introduce a project convention for stub markers (e.g.
`// STUB:` or `// GAP:`) so future audits can grep them instead of
re-doing the structural scan.

## 10. Blockers grouped by use case

| Use case | Primary blockers |
|---|---|
| Shell scripts / `shell.exe` | `fork` / `clone` / `wait4` (Linux); `NtCreateProcess` (NT) |
| Multi-process native apps | NT process/thread family; native `SYS_FORK` / `SYS_EXEC` |
| File mutation (rename / delete) | No FS rename/unlink; no `NtSetInformationFile` (mismapped to seek) |
| Registry reads | All 17 `NtKey*` calls stubbed; advapi32 returns empty strings |
| Network (sockets) | `ws2_32` socket stubs; NIC drivers have no I/O; no `kCapNet*` |
| Async I/O (epoll / select) | `DoEpoll*` all `-ENOSYS`; `select` unimplemented |
| Debugger | `ptrace` `-EPERM`; `NtDebugActiveProcess` stubbed |
| UI dialogs | `MessageBox`, `GetOpenFileName` stubs |
| Audio playback | No wave output; PC speaker only |
| 3D graphics | D3D11/12 landing pads only; no Vulkan ICD |
| ext4 / NTFS data | Read-only |
| Dynamic FS mount | No `mount` / `umount` syscalls |
| File logging via real handles | `ucrtbase fwrite` returns 0 for fd > 2 |
| Cross-process malware techniques | NT process + thread + memory families all stubbed |
| Keylogger / screen-grab / RAT denial tests | No `kCapInput` / `kCapFramebuffer` / `kCapNet` |
| Ransomware rate-limit tests | No `MassFsWriteRate` detector; FAT32 has no unlink to do encrypt-in-place |

## 11. Recommended fill-in order

Cheapest → most-expensive, by impact-per-LOC:

1. ~~**Fix the 5 mismapped NT syscalls**~~ — DONE (commit `ad32498`, see §12). 4 of 5 remapped to `kSysNtNotImpl`; `NtSetInformationFile`'s position-info case left at SYS_FILE_SEEK because that subset is genuinely correct.
2. ~~**Add a `// STUB:` / `// GAP:` convention.**~~ — DONE (CLAUDE.md → "Coding Standards" + first marker on `TranslateRseq`). Future audits grep `// (STUB|GAP):` once enough sites are tagged.
3. ~~**Wire ucrtbase `fwrite` to `SYS_FILE_WRITE` for real file handles.**~~ — DONE (commit `ad32498`).
4. **Add the 3 missing test-relevant capabilities** (`kCapNet`, `kCapInput`, `kCapFramebuffer`) — **PARTIAL**: `kCapNet` + `kCapInput` landed and wired (§12). `kCapFramebuffer` deferred until a user-mode FB-readback or direct-FB-write syscall exists to gate; landing the cap before the gate site would be dead code. Take this slice when adding the first such surface.
5. ~~**Implement registry read syscalls**~~ — **DONE for the read-path subset**: `SYS_REGISTRY = 130` + kernel-side static tree + ntdll `NtOpenKey` / `NtOpenKeyEx` / `NtQueryValueKey` thunks (OBJECT_ATTRIBUTES + UNICODE_STRING parsing, `\Registry\Machine\` / `\Registry\User\` prefix resolution, KEY_VALUE_PARTIAL_INFORMATION packing). End-to-end verified by `reg_fopen_test.exe` reading `ProductName=DuetOS` via both advapi32 (Reg*) AND ntdll (Nt*) paths in the same boot smoke. NtCreateKey / Set / Delete / EnumerateKey / EnumerateValueKey / FlushKey stay NotImpl on purpose (read-only registry, no children walker, no journal).
6. ~~**Implement cross-process VM access**~~ — **DONE**: NtOpenProcess (commit `23b2585`) + NtReadVirtualMemory + NtWriteVirtualMemory + NtQueryVirtualMemory all live. `SYS_PROCESS_VM_READ = 132` / `SYS_PROCESS_VM_WRITE = 133` / `SYS_PROCESS_VM_QUERY = 134` walk the target's `AddressSpace` regions table page-by-page via `AddressSpaceLookupUserFrame` → `mm::PhysToVirt`, bounce bytes through a 256-byte on-stack buffer, and gate the caller-side I/O through `CopyFromUser` / `CopyToUser`. Per-call cap = `kSyscallProcessVmMax = 16 KiB` (one syscall covers PEB / PROCESS_BASIC_INFORMATION / TEB / register context; larger transfers chunk on the caller side). Cap-gated on `kCapDebug` at every entry — re-checked on every read/write/query so a future cap-revocation takes effect immediately. NT-table mapping climbs 27→30. NtQueryVirtualMemory v0 GAP: returns a single-page region (`RegionSize = 4096`) instead of coalescing — the v0 region table doesn't track per-page protection bits, so honest coalescing isn't possible without a schema bump. Partial-copy GAP: a transfer that hits an unmapped target page returns `STATUS_ACCESS_VIOLATION` rather than Windows' `STATUS_PARTIAL_COPY` — the bytes-moved out-pointer carries the truth so any caller can disambiguate. Unlocks the entire "real Windows malware" test surface (debugger probes, process hollowing prep, signature scanning).
7. **Implement thread manipulation** (NtSuspendThread, NtResumeThread, NtSetContextThread, NtGetContextThread) — **DONE** (with documented sub-GAPs). NtSuspendThread + NtResumeThread + NtAlertResumeThread + NtGetContextThread + NtSetContextThread all land end-to-end. Suspend half: `Task::suspend_count` (per-task, mutated under arch::Cli + g_sched_lock); `g_suspended_head/tail` intrusive list; `RunqueuePopRunnable` lazy re-park; `RunqueueOrSuspendPush` wake-path counterpart; `SchedSuspendTask` + `SchedResumeTask` cross-task APIs; `SYS_THREAD_SUSPEND = 135` + `SYS_THREAD_RESUME = 136`. Context half: `SchedFindUserTrapFrame(Task*)` returns the outermost user→kernel TrapFrame at `(stack_base + stack_size) - sizeof(TrapFrame)` (RPL == 3 check rejects kernel-only tasks and threads that haven't yet entered user mode); `Win32Context` struct (first 0x100 bytes of the Microsoft x64 CONTEXT layout — P1Home..P6Home, ContextFlags, MxCsr, Seg×6, EFlags, Dr0..3 + Dr6 + Dr7, Rax..R15, Rip with static_asserts on offsets); `SYS_THREAD_GET_CONTEXT = 137` + `SYS_THREAD_SET_CONTEXT = 138` cap-gated on `kCapDebug`; SET sanitises rflags (force IF=1, clear IOPL/TF/NT) and forces user-mode selectors (cs=0x2B, ss=0x33) so a malicious caller cannot escalate the target to ring 0 or mask interrupts. Five ntdll thunks land (Suspend/Resume/AlertResume/GetContext/SetContext + Zw aliases); build script flips them all to real exports; KNOWN_MAPPINGS gains 5 entries; NT-table mapping climbs 30→35. **Sub-GAPs**: (a) ~~caller-local thread handles only — cross-process Get/SetContext needs NtOpenThread + a foreign thread handle table; that's its own slice.~~ **LIFTED** by NtOpenThread slice — `Win32ForeignThreadHandle win32_foreign_threads[8]` table on Process at base 0x800 disjoint from local thread handles, `SchedFindTaskByTid` in sched, `SYS_THREAD_OPEN = 139` cap-gated on kCapDebug; `LookupThreadHandle` helper reads both ranges so SUSPEND/RESUME/GET/SET_CONTEXT honour foreign handles uniformly; NtClose dispatch grew an arm to ProcessRelease the owner refcount. The full **cross-process** thread hijack pipeline now works (caller in process A holding a NtOpenThread handle to a target in process B). (b) Get/SetContext only honour CONTEXT_INTEGER + CONTEXT_CONTROL classes; CONTEXT_FLOATING_POINT (XMM0..XMM15 + AVX) and CONTEXT_DEBUG_REGISTERS (DR0..3 + DR6 + DR7) bytes pass through unchanged on GET / are read-but-ignored on SET. (c) Killing a suspended task surfaces as KillResult::Blocked. (d) On SMP, suspending a target running on another core needs an IPI. The full malware "thread hijack" pipeline now works end-to-end: NtOpenProcess (→ §11.6 OpenProcess) → NtOpenThread → NtSuspendThread → NtGetContextThread → NtWriteVirtualMemory (→ §11.6 VM family) → NtSetContextThread → NtResumeThread.
8. **Implement section / view APIs** (NtMapViewOfSection, NtUnmapViewOfSection, NtCreateSection) — **DONE** (anonymous / pagefile-backed only). v0 lands an 8-slot global section pool (`g_pool` in `kernel/subsystems/win32/section.cpp`, max 4 MiB / section, refcounted = open-handles + active-mappings). `mm::AddressSpace` grew **borrowed-page** primitives (`AddressSpaceMapBorrowedPage` / `AddressSpaceUnmapBorrowedPage` / `AddressSpaceProbePte`) — install / clear PTEs without touching the regions ledger, so the AS-destroy walker doesn't free section-owned frames. `Process::win32_section_handles[8]` table at base 0x900 (disjoint from every other Win32 handle range). `SYS_SECTION_CREATE = 140`, `SYS_SECTION_MAP = 141`, `SYS_SECTION_UNMAP = 142`. CREATE allocates + zero-fills frames (Windows guarantees zero-init), refcount = 1. MAP supports BOTH self-process (ProcessHandle = NtCurrentProcess() = -1, no extra cap) AND cross-process (foreign target via NtOpenProcess handle, cap-gated on `kCapDebug` — process hollowing is the same threat class as cross-AS VM read/write). MAP installs every page via the borrowed-PTE primitive, retains the section, returns BaseAddress + ViewSize via in/out user pointers. UNMAP walks every live pool entry, finds the one whose `frames[0]` matches `AddressSpaceProbePte(target_as, base_va)`, calls `SectionUnmap`, decrements refcount. Three `__declspec(dllexport)` thunks land in ntdll (`NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection` + `Zw*` aliases). NtClose dispatch grew an arm for the 0x900..0x907 range. NT-table mapping count climbs 36→39. **Sub-GAPs**: (a) file-backed sections (FileHandle != 0) return STATUS_NOT_IMPLEMENTED — needs a fs-page-cache slice. (b) SectionOffset must be 0 (whole-section views only); partial views need offset + length plumbing. (c) PAGE_EXECUTE_READWRITE silently downgrades to RW (W^X enforcement) — process hollowing tests that need RWX must call NtProtectVirtualMemory after-the-fact, when that lands. (d) On process exit, section views aren't tracked per-AS, so a process that exits without unmapping leaks one mapping refcount per view (the section's frames stay allocated until every other holder drops). (e) `SectionUnmapAtVa` matches by frames[0] only — if two distinct sections happen to have the same first frame (impossible in v0 since AllocateFrame returns unique frames, but a future demand-zero scheme could share), it'd unmap the wrong one. Unlocks process hollowing pipeline: NtOpenProcess → NtCreateSection → NtMapViewOfSection(target, view_protect=PAGE_READWRITE) → write shellcode through the local view → (future) NtProtectVirtualMemory(view, PAGE_EXECUTE_READ) → NtSetContextThread → NtResumeThread.
9. **Implement FS mutation** (rename, unlink, symlink) for FAT32 + tmpfs — **DONE** (rename + unlink; symlinks deferred). FAT32 grew `Fat32RenameAtPath` (copy-then-delete via Fat32ReadFile → Fat32CreateAtPath → Fat32DeleteAtPath, bounce buffer cap = 64 KiB on the kernel heap). Tmpfs grew `TmpFsRename` (in-place name swap on the slot — atomic w.r.t. other tmpfs callers since tmpfs has no IRQ-side mutators). `fs::routing` grew `UnlinkForProcess` + `RenameForProcess` that dispatch fat32 paths through `ParseDiskPath` to the new helpers (ramfs is read-only, tmpfs has its own shell-only surface and isn't routed here in v0). New syscalls: `SYS_FILE_UNLINK = 143` + `SYS_FILE_RENAME = 144`, both cap-gated on `kCapFsWrite`. Win32 surface: kernel32 `DeleteFileA/W` + `MoveFileA/W` flipped from `kOffReturnOne` stubs to real syscall thunks; ntdll grew `NtDeleteFile` (extracts the wide ObjectName from OBJECT_ATTRIBUTES, strips `\??\` Win32-namespace prefix, narrows to ASCII, calls SYS_FILE_UNLINK). KNOWN_MAPPINGS gains one row (NtDeleteFile); NT-table mapping count climbs 39 → 40. **Sub-GAPs**: (a) **Symlinks deferred** — FAT32 has no native symlink (NTFS reparse points are a separate slice), tmpfs would need a new entry kind; out of v0 scope, no caller needs them yet. (b) **Non-atomic FAT32 rename** — copy-then-delete leaves a window where a power loss yields both src and dst; needs in-place dirent edit (same-parent-dir fast path) or a journal. (c) **64 KiB rename cap on FAT32** — files larger than the bounce buffer return false; needs streaming cluster-by-cluster copy. (d) **Cross-volume rename refused** — `RenameForProcess` rejects when src/dst are on different `/disk/<idx>` indices; needs an explicit copy fallback. (e) **No implicit overwrite** — both FAT32 and tmpfs reject rename onto an existing destination, mismatching `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`. (f) **Directory rename refused** — only regular files honour rename; FAT32 directory rename needs a `..` patch in the moved subtree. (g) **Status code is lossy** — both syscalls collapse the (missing-src vs existing-dst vs read-only) failure space into a single NTSTATUS each. Unlocks ransomware-shape file mutation tests (open → write → rename → re-open under new name) and the cleanup half of every test that creates temporary FAT32 files.
10. **Implement Linux fork / clone / execve** — **PARTIAL** (CLONE_THREAD same-AS thread create only; fork + execve deferred). v0 lands `DoClone` in `kernel/subsystems/linux/syscall_clone.cpp` honouring the `CLONE_THREAD | CLONE_VM` subset that pthread_create emits — same-AS thread create with caller-supplied child stack. Reuses `SchedCreateUser` + `EnterUserModeThread` (the latter's `xor eax,eax` before iretq already gives the child rax = 0, matching Linux's "child gets 0 from clone" contract). Parent's saved rip is read via `SchedFindUserTrapFrame(CurrentTask())` — same helper §11.7 thread-hijack uses. `CLONE_PARENT_SETTID` honoured (writes new TID through `*ptid` via CopyToUser). Parent gets new TID in rax. Cap-gated on `kCapSpawnThread`. **Sub-GAPs**: (a) **Full fork() deferred** (CLONE_THREAD clear) — needs AS duplication with COW page sharing, copy of regions table, fork-of-handles, fork-of-mmap-cursor, parent/child PID disambiguation. The hardest §11 item; estimated ~800 LOC on its own. (b) **execve() deferred** — needs in-place AS replacement: tear down all current user mappings, reload ELF/PE into the same AS, reset trap frame's rip/rsp/registers. The PE/ELF loader has the building blocks (it spawns fresh tasks with fresh ASes today) but no in-place reload path. Estimated ~500 LOC. (c) **CLONE_SETTLS ignored** — Process has `user_gs_base` but no per-task fs_base; `arch_prctl(SET_FS_BASE)` is the substitute callers should use. (d) **CLONE_CHILD_CLEARTID ignored** — needs a futex engine which doesn't exist; pthread cleanup-via-futex-wake won't fire when a thread exits, so a joining thread will spin until the joinee's exit syscall lands. (e) **flag combinations beyond CLONE_THREAD|CLONE_VM accepted but treated as default** — CLONE_FS, CLONE_FILES, CLONE_SIGHAND, CLONE_SYSVSEM are no-ops because v0 has only one fd table / signal-handler table per Process to begin with. (f) **No clone3** — the newer 5.3+ syscall with the ABI-versioned arg struct returns ENOSYS. (g) **No vfork** — vfork's "child runs in parent's AS until execve" semantics are equivalent to a barrier-suspended fork; v0 returns ENOSYS rather than silently aliasing onto clone(CLONE_THREAD) which has different parent-suspension semantics. Unlocks pthread_create() in glibc/musl-shaped userland binaries.
11. **Implement socket family** (socket / bind / listen / accept / connect / send / recv). ~1 200 LOC + NIC TX/RX paths. Unlocks all network tests.
12. **Implement NIC TX/RX paths** for at least one driver (e1000 is canonical). ~800 LOC. Network now actually works.
13. **NTFS / ext4 write paths.** Each ~2 000 LOC. Lowest priority — read-only is acceptable for v0.

## 12. Landed (to be appended as gaps close)

| Date | Commit | Gap closed | Impact |
|---|---|---|---|
| 2026-04-26 | `ad32498` | NT shim §1.2 mismaps: `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtCreateSemaphore`, `NtReleaseSemaphore` now route to `kSysNtNotImpl` | Closes silent-wrong-semantics class for cross-AS memory ops + counted-semaphore concurrency. Mapped count drops 28→24; honest NotImpl beats silent corruption. `NtSetInformationFile` kept at SYS_FILE_SEEK because the position-info class is genuinely correct |
| 2026-04-26 | `ad32498` | ucrtbase §4.1: `fwrite(fd > 2)` now routes to `SYS_FILE_WRITE` instead of returning 0 | Closes silent-data-loss landmine. Stdio file writes from PEs actually land in the FS now. Unlocks ransomware-shape PE payloads via plain CRT |
| 2026-04-26 | `3948bcd` | Item 4 (partial): `kCapNet` added + wired on the linux BSD-socket family (socket/socketpair/accept/connect/bind/listen/shutdown/get/setsockopt/send*/recv*); `kCapInput` added + wired on `SYS_WIN_GET_KEYSTATE` + `SYS_WIN_GET_CURSOR` | Closes the §6 "missing infrastructure" gap for the Net + Input redteam slices. Sandboxed PEs now get -EACCES from socket-family calls (distinguishable from "stack offline" -ENETDOWN) and a "no key pressed / cursor at origin" deception from the async input pollers. `kCapFramebuffer` deferred — there is no user-mode framebuffer-readback or direct-fb-write syscall today, so the cap would be dead code. Add it together with the first such surface (e.g. screen-grab BitBlt or DRM read) so the cap and its gate land in the same commit. `kCapAudio`/`kCapSignal`/`kCapFork`/`kCapExec` likewise deferred until their backing syscalls exist |
| 2026-04-26 | `3948bcd` | Item 2: `// STUB:` / `// GAP:` convention codified in CLAUDE.md → "Coding Standards"; first demonstration marker on `TranslateRseq` (`kernel/subsystems/translation/translate.cpp:367`) | Future audits can re-derive this inventory from `git grep -nE "// (STUB\|GAP):"` once enough sites have markers. Convention is intentionally not back-applied to TUs whose entire purpose is to house stubs (`kernel/subsystems/linux/syscall_stub.cpp`, the `kSysNtNotImpl` table) — those are documented at the file/table level and per-handler markers would be redundant noise |
| 2026-04-26 | `e60ce80` | Item 5 (kernel half): `SYS_REGISTRY = 130` op-multiplexed syscall + kernel-side static-tree registry mirroring advapi32's well-known keys. Ops landed: `kOpOpenKey`, `kOpQueryValue`, `kOpClose`. NT-syscall table now maps `NtOpenKey` / `NtOpenKeyEx` / `NtQueryValueKey` to `SYS_REGISTRY` (was `kSysNtNotImpl`); `NtClose` keeps its `SYS_FILE_CLOSE` mapping and the kernel-side handler now releases registry handles too via the existing range dispatch. Mapped count climbs 24→26. `[registry-selftest] PASS` line lands in the boot-smoke serial log |
| 2026-04-26 | `40a4230` | Item 5 (userland half — completes the slice): ntdll.dll thunks `NtOpenKey` / `NtOpenKeyEx` / `NtQueryValueKey` land. They parse OBJECT_ATTRIBUTES + UNICODE_STRING, resolve `\Registry\Machine\` / `\Registry\User\` prefix to the predefined HKEY sentinel, low-byte-strip the wide path to ASCII, and issue SYS_REGISTRY with the right op. NtQueryValueKey only honours `KeyValuePartialInformation` (the class every common Windows-side caller asks for); other classes return STATUS_NOT_IMPLEMENTED so callers fall back. `reg_fopen_test.exe` extended with an Nt* path next to its existing Reg* path — boot smoke now logs `[reg-fopen-test] NtQueryValueKey ProductName="DuetOS" (result_len=19)` alongside the advapi32-mediated `ProductName="DuetOS" (type=1, size=7)`. `build-ntdll-dll.sh` flips `NtOpenKey` / `NtOpenKeyEx` / `NtQueryValueKey` from `=NtReturnNotImpl` forwarders to real exports |
| 2026-04-27 | `a2bb164` | Item 6 (NtRead/Write/QueryVirtualMemory — completes the slice): `SYS_PROCESS_VM_READ = 132`, `SYS_PROCESS_VM_WRITE = 133`, `SYS_PROCESS_VM_QUERY = 134` syscalls. Inline handlers in `kernel/syscall/syscall.cpp` cap-gate on `kCapDebug` on every entry, resolve the target via `LookupProcessHandle` (range-checks `kWin32ProcessBase + idx` against `Process::win32_proc_handles[]`), and call a shared `CrossAsTransfer` helper that walks `AddressSpaceLookupUserFrame` page-by-page on the target side and bounces 256-byte chunks through `CopyFromUser` / `CopyToUser` on the caller side. Per-call byte cap `kSyscallProcessVmMax = 16 KiB`. Bytes-moved out-pointer (`r8`) populated on partial copies. Query returns a 48-byte `Win32MemoryBasicInfo` (byte-compatible prefix of MEMORY_BASIC_INFORMATION) — Base/AllocBase = page start, RegionSize = 4096, State = MEM_COMMIT/MEM_FREE, Protect = PAGE_READWRITE for any mapped page. Three `__declspec(dllexport)` thunks land in `userland/libs/ntdll/ntdll.c` with the canonical NT signatures (PHANDLE/ACCESS_MASK/CLIENT_ID gone — these consume the handle from NtOpenProcess directly). `build-ntdll-dll.sh` flips NtRead/Write/Query from `=NtReturnNotImpl` forwarders to real exports + Zw aliases; `tools/win32-compat/gen-nt-shim.py` `KNOWN_MAPPINGS` gains the 3 entries; NT-table mapping count climbs 27→30. **GAPs**: (a) NtQueryVirtualMemory returns single-page regions only — no coalescing because the v0 region table doesn't track per-page protection. (b) Partial copies surface as `STATUS_ACCESS_VIOLATION` not `STATUS_PARTIAL_COPY` — the bytes-moved out-pointer disambiguates. (c) Writes ignore protection — every region is RW from the kernel direct map, so a write to a target's nominally-RO page lands. (d) `kSyscallProcessVmMax = 16 KiB` per call; larger transfers chunk on the caller. Hash backfilled in a follow-up |
| 2026-04-26 | `23b2585` | Item 6 (NtOpenProcess, foundational piece): `SchedFindProcessByPid` (sched.h API, walks running + run-normal + run-idle + sleep + zombie queues under arch::Cli, returns the first `Process*` whose PID matches), `Win32ProcessHandle` table on Process (8 slots at base 0x700, disjoint from every other handle range), `SYS_PROCESS_OPEN = 131` syscall (cap-gated on `kCapDebug` — the same gate that protects breakpoints, since cross-process inspection is the same threat class), `ProcessRetain` on the target so the handle keeps it alive past its task's exit, `DoFileClose`'s by-range dispatch grows a process arm that calls `ProcessRelease`. ntdll.dll thunk `NtOpenProcess` lands with `OBJECT_ATTRIBUTES` + `CLIENT_ID` parsing — only `Pid` is honoured (Tid != 0 with Pid == 0 = STATUS_INVALID_PARAMETER). NT-table mapping climbs 26→27. **NtReadVirtualMemory / NtWriteVirtualMemory / NtQueryVirtualMemory deferred to follow-ups** — each needs the cross-AS PML4 walker + `mm::PhysToVirt` direct-map bouncer on the kernel side, which is its own slice. Foundational handle plumbing is in place |
| 2026-04-27 | `de3f155` | Item 7 (NtSuspendThread / NtResumeThread / NtAlertResumeThread — partial; freeze half of "thread hijack"): `Task::suspend_count: u32` (per-task, mutated under arch::Cli + g_sched_lock); `g_suspended_head/tail` intrusive list (Task::next, mutually exclusive with runqueue / wait queue / sleep queue / zombies); `RunqueuePopRunnable` reroutes suspended-while-Ready tasks lazily off the runqueue onto the suspended list; `RunqueueOrSuspendPush` is the wake-path counterpart that routes by suspend_count (replaces three RunqueuePush call sites — Schedule()'s prev re-enqueue, OnTimerTick's wake-from-sleep, WaitQueueWakeOne). `SchedSuspendTask` / `SchedResumeTask` cross-task control APIs (modeled on `SchedKillByPid`, take Task* + out-PrevCount, return SuspendResult Signaled / NotFound / AlreadyDead). `SYS_THREAD_SUSPEND = 135`, `SYS_THREAD_RESUME = 136` inline handlers in `kernel/syscall/syscall.cpp` accept caller-local thread handles only (kWin32ThreadBase + idx in calling Process's win32_threads[]); the rax = previous count contract matches NT exactly. Three `__declspec(dllexport)` thunks land in `userland/libs/ntdll/ntdll.c` (NtSuspendThread, NtResumeThread, NtAlertResumeThread aliased to Resume because v0 has no APC machinery). `build-ntdll-dll.sh` flips them from NotImpl forwarders to real exports + Zw aliases; `KNOWN_MAPPINGS` gains 3 entries; NT-table mapping count climbs 30→33. **GAPs**: (a) caller-local thread handles only — cross-process suspend needs NtOpenThread + a foreign thread handle table. (b) NtSetContextThread / NtGetContextThread deferred — the 1232-byte CONTEXT struct's population from the suspended task's saved trap frame is its own slice. (c) Killing a suspended task surfaces as KillResult::Blocked (the kill path doesn't auto-resume). (d) SMP needs an IPI to evict a running-on-another-core target. Hash backfilled in a follow-up |
| 2026-04-27 | `c8f1bef` | Item 7 (NtGetContextThread / NtSetContextThread — completes the §11.7 hijack pipeline): `SchedFindUserTrapFrame(Task*)` helper returns the outermost user→kernel TrapFrame at `(stack_base + stack_size) - sizeof(TrapFrame)` (RPL == 3 check on cs filters out kernel-only tasks + threads that haven't yet entered user mode). `Win32Context` struct in `kernel/syscall/syscall.h` mirrors the first 0x100 bytes of Microsoft's x64 CONTEXT layout — P1Home..P6Home, ContextFlags, MxCsr, Seg×6, EFlags, Dr0..3 + Dr6 + Dr7, Rax..R15, Rip — with `static_assert`s on the offsets so a layout drift fails the build. `SYS_THREAD_GET_CONTEXT = 137`, `SYS_THREAD_SET_CONTEXT = 138` cap-gated on `kCapDebug`. Get reads the integer + control regs out of the trap frame into a kernel Win32Context and CopyToUser's the buffer (256 bytes); Set CopyFromUser's into the kernel buffer, then writes back into the trap frame with sanitisation: rflags forces IF=1 + clears IOPL/TF/NT (no privilege escalation through the eflags interface), cs/ss forced to 0x2B/0x33 (no ring-0 iretq via a malicious selector). ContextFlags filter honours INTEGER + CONTROL classes; FLOATING_POINT + DEBUG_REGISTERS bytes pass through unchanged on GET / are ignored on SET. Two `__declspec(dllexport)` thunks land — NtGetContextThread + NtSetContextThread; both read ContextFlags out of the caller's CONTEXT[+0x30] and forward via rdx so the kernel honours the caller's class filter without a winnt.h dependency. `build-ntdll-dll.sh` flips them to real exports + Zw aliases; `KNOWN_MAPPINGS` gains 2 entries; NT-table mapping count climbs 33→35. The full malware "thread hijack" pipeline now works end-to-end: NtOpenProcess → NtSuspendThread → NtGetContextThread → NtWriteVirtualMemory → NtSetContextThread → NtResumeThread. **Sub-GAPs codified at §11 item 7**: caller-local handles only (cross-process needs NtOpenThread); FLOATING_POINT / DEBUG_REGISTERS classes deferred. Hash backfilled in a follow-up |
| 2026-04-27 | `fa24d69` | Item 7 (NtOpenThread — lifts the cross-process sub-GAP): `SchedFindTaskByTid(u64)` walks running + run-normal + run-idle + sleep under arch::Cli (skips zombies — a dead task has no live owning Process to refcount). `Win32ForeignThreadHandle win32_foreign_threads[8]` table on Process at base 0x800 — disjoint from local thread handles (0x400..0x407), process handles (0x700..0x707), and every other Win32 range so the by-range close dispatch picks the right table by handle value alone. Each entry pins a Task* (the foreign thread) AND a Process* (the owner, ProcessRetained at open time so the foreign Task can't be reaped under the inspector's hand). `SYS_THREAD_OPEN = 139` cap-gated on `kCapDebug` — same threat class as NtOpenProcess, since the produced handle unlocks SUSPEND / RESUME / GET / SET_CONTEXT against a target outside the caller's process. `LookupThreadHandle(Process*, u64)` helper in syscall.cpp resolves both handle ranges (local win32_threads and foreign win32_foreign_threads) to a Task* uniformly — SYS_THREAD_SUSPEND / RESUME / GET_CONTEXT / SET_CONTEXT all refactored to call it instead of inlining the local-only lookup. `DoFileClose` (file_syscall.cpp) grew an arm for the 0x800..0x807 range that ProcessReleases the owner so the foreign Process gets reaped per the same contract as win32_proc_handles. ntdll.dll thunk `NtOpenThread` lands with `OBJECT_ATTRIBUTES` + `CLIENT_ID` parsing (only Tid is honoured; Pid is ignored — the kernel resolves Tid against every live task regardless of PID); `build-ntdll-dll.sh` exports both NtOpenThread and ZwOpenThread; `KNOWN_MAPPINGS` gains 1 entry; NT-table mapping count climbs 35→36. The **cross-process** thread hijack pipeline now works end-to-end: NtOpenProcess(target_pid) → NtOpenThread(target_tid) → NtSuspendThread → NtGetContextThread → NtWriteVirtualMemory → NtSetContextThread → NtResumeThread. Hash backfilled in a follow-up |

## Wiring summary

- This doc complements `redteam-coverage-matrix-v0.md` — that one
  describes which **tests** are/aren't possible; this one describes
  which **kernel surfaces** are/aren't implemented.
- When a slice from the matrix's recommended order lands, **both**
  docs need updates: the gap inventory's "Landed" table, and the
  matrix's relevant row(s) flipping from ❌ to ✅.
- Audit re-run cadence: re-do the structural scan whenever the NT
  or Linux syscall tables get regenerated, or quarterly otherwise.
