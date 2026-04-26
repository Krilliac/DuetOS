# Refactor: split the top-5 oversized .cpp files

## Status (2026-04-26)

Branches: `claude/refactor-codebase-VvLO6` (merged via PR #74) and
`claude/continue-refactoring-split-QlCKz` (active).

**Per-split rollup:**

| Split | File | Original | Current | State |
|---|---|---:|---:|---|
| 1 | `kernel/core/shell.cpp`               | 9,769 | 8,458 | ◐ in progress (5 command slices + 5 helper hoists + utility-bucket-1 + env/alias-bucket; ~13.4% trim. Env-table + alias-table + history-ring → shell_state.cpp; path/parse helpers → shell_pathutil.cpp; output formatters → shell_format.cpp; StrEq / StrStartsWith / kInputMax / kHistoryCap inline. CmdBasename / CmdDirname / CmdFlushTlb / CmdMem / CmdMode / CmdHistory / CmdSleep / CmdShutdownNow → shell_utilities.cpp. CmdSet / CmdUnset / CmdGetenv / CmdEnv / CmdAlias / CmdUnalias → shell_core.cpp) |
| 2 | `kernel/subsystems/win32/thunks.cpp`  | 5,684 |   655 | ☑ done (`cae3704`) |
| 3 | `kernel/subsystems/linux/syscall.cpp` | 4,642 | 1,274 | ☑ done (73% reduction; decomposed into 16 per-domain sibling TUs: cred / fd / file / fs_mut / io / misc / mm / path / pathutil / proc / rlimit / sched / sig / stub / time + syscall_internal.h. syscall.cpp itself is now just header + kSys* enum + LinuxSyscallDispatch + SyscallInit + LinuxLogAbiCoverage + thin Linux* public wrappers) |
| 4 | `kernel/fs/fat32.cpp`                 | 3,190 |   300 | ☑ done (decomposed into fat32 + fat32_dir + fat32_lookup + fat32_read + fat32_write + fat32_create + selftest, plus fat32_internal.h and fat32_write_internal.h) |
| 5 | `kernel/drivers/usb/xhci.cpp`         | 2,548 |    76 | ☑ done (decomposed into 14 sibling TUs: admin/complete/context/control/descparse/enum/event/init/input/irq/ring/speed/xfer + xhci_internal.h; xhci.cpp itself is now just file header + namespace scaffolding + global definitions backing the extern decls in the header) |

**Landed** (build-verified through both kernel stages):

| Commit | Effect |
|---|---|
| `cae3704 win32/thunks: extract bytecode + entry table to .inc files` | `thunks.cpp` 5,684 → 655 lines (88% reduction). Bytecode + entry-table bodies live in `thunks_bytecode.inc` + `thunks_table.inc`, `#include`d back into `thunks.cpp`. TU stays whole. |
| `1f5efd1 docs: add Stream Timeout Prevention section to CLAUDE.md` | 5-rule mitigation block (one task at a time, ~150-line write cap, fresh session after 20+ tool calls, short greps, retry shorter on timeout). |
| `736381b fs/fat32: split Fat32SelfTest into a sibling file` | `fat32.cpp` 3,190 → 2,579 lines. SelfTest lives in `fat32_selftest.cpp` (628 lines), uses public Fat32* API only. |
| `0ed4370 fs/fat32: split mutating path into sibling translation unit` | `fat32.cpp` 2,579 → 871 lines. All on-disk mutators (`Fat32WriteInPlace`, `Fat32Append*`, `Fat32Create*`, `Fat32Delete*`, `Fat32Mkdir/RmdirAtPath`, `Fat32Truncate*`) plus their helpers live in `fat32_write.cpp` (1,732 lines). Cross-TU primitives (`g_scratch`, `Fat32Guard`, `ReadCluster`, `WalkDirChain`, `WalkRootIntoSnapshot`, etc.) hoisted into `namespace duetos::fs::fat32::internal` via new `fat32_internal.h` (99 lines). Public `fat32.h` API unchanged. |
| `54ca56d fs/fat32: extract file-content read APIs into fat32_read.cpp` | `fat32.cpp` 871 → 726 lines. `Fat32ReadFile`, `Fat32ReadAt`, `Fat32ReadFileStream` live in new `fat32_read.cpp` (173 lines). No new `internal::` symbols — these consume the existing primitives (`g_scratch`, `Fat32Guard`, `ReadFatEntry`) declared in `fat32_internal.h`. |
| `9ae9964 fs/fat32: extract path lookup into fat32_lookup.cpp` | `fat32.cpp` 726 → 640 lines. `Fat32LookupPath` plus its TU-private `FindCtx` / `FindVisitor` pair live in new `fat32_lookup.cpp` (115 lines). Consumer-only of the existing internal primitives. |
| `794c108 linux-syscall: extract credential handlers into sibling TU` | `syscall.cpp` 4,642 → 4,521 lines (-121). uid/gid/euid/egid/setre*/setres*/getres*/setfs*/groups/cap{get,set} live in new `syscall_cred.cpp` (152 lines), defined in `internal::` namespace. New `syscall_internal.h` (74 lines) carries the cross-TU decls + Linux errno constants (kEPERM..kENOSYS). Dispatcher unchanged via `using namespace internal;`. |
| `81b2ca5 linux-syscall: extract rlimit handlers into sibling TU` | `syscall.cpp` 4,521 → 4,369 lines (-152). getrlimit/setrlimit/prlimit64 + kRlimit* constants + RlimitDefaultsFor helper live in new `syscall_rlimit.cpp` (184 lines). Constants stay TU-private (anon namespace) inside the new file; only the three Do* decls go into `syscall_internal.h`. |
| `4f72b2c linux-syscall: extract scheduler-policy handlers into sibling TU` | `syscall.cpp` 4,369 → 4,219 lines. sched_setaffinity / sched_getaffinity / sched_{get,set}{scheduler,param} / sched_get_priority_{max,min} / sched_rr_get_interval + SCHED_* constants → `syscall_sched.cpp` (187 lines). DoSchedYield stays with proc. |
| `fb3e398 linux-syscall: extract time / clock handlers into sibling TU` | `syscall.cpp` 4,219 → 3,990 lines. NowNs + clock_gettime / gettimeofday / time / nanosleep / times / clock_getres / clock_nanosleep + ReadTsc → `syscall_time.cpp` (209 lines). NowNs decl in internal header (LinuxNowNs wrapper forwards to it). |
| `a95316b linux-syscall: extract signal handlers into sibling TU` | `syscall.cpp` 3,990 → 3,853 lines. rt_sigaction / rt_sigprocmask / sigaltstack / rt_sigreturn / rt_sigpending / rt_sigsuspend / rt_sigtimedwait → `syscall_sig.cpp` (168 lines). Hoists kEINTR / kENFILE / kECHILD into syscall_internal.h alongside the rest of the errno constants. |
| `9ac2254 linux-syscall: extract file-descriptor handlers into sibling TU` | `syscall.cpp` 3,853 → 3,775 lines. dup / dup2 / dup3 / fcntl + TU-private CopyFdSlot helper → `syscall_fd.cpp` (131 lines). |
| `d9e0cb1 linux-syscall: extract process-control handlers into sibling TU` | `syscall.cpp` 3,775 → 3,727 lines. exit / exit_group / getpid / gettid / sched_yield / tgkill / kill / getppid / getpgid / getsid / setpgid / getpgrp / setsid → `syscall_proc.cpp` (140 lines). DoExitGroup + DoGetPid in internal header so LinuxExit / LinuxGetPid wrappers can forward. |
| `1cb2ea4 linux-syscall: extract CWD / path handlers into sibling TU` | `syscall.cpp` 3,727 → 3,657 lines. chdir / fchdir / getcwd → `syscall_path.cpp` (103 lines). utimensat + the *at-family path mutators stay in syscall.cpp pending the StripFatPrefix / CopyAndStripFatPath hoist. |
| `97e7c11 linux-syscall: extract memory-management handlers into sibling TU` | `syscall.cpp` 3,657 → 3,290 lines. brk / mmap / munmap / mprotect / madvise / mremap / msync / mincore / mlock / munlock / mlockall / munlockall + kMapPrivate / kMapAnonymous + PageUp helper → `syscall_mm.cpp` (371 lines). Drops the kENOMEM_ shadow constant — DoMremap now uses kENOMEM directly. |
| `1c2ef92 linux-syscall: extract stub handlers into sibling TU` | `syscall.cpp` 3,290 → 3,147 lines. Contiguous Pipe / Wait / Eventfd / Timerfd / Signalfd / Epoll / Inotify / Fadvise / Readahead block → new `syscall_stub.cpp`. Each returns the canonical Linux errno (-ENFILE / -ECHILD / -ENOSYS) for "we don't have that subsystem". |
| `b46b42f linux-syscall: extract compat / tracing / mount stub group` | `syscall.cpp` 3,147 → 3,028 lines. Extends `syscall_stub.cpp` with the compat / tracing / mount / link / rename group: ptrace / syslog / vhangup / acct / mount / umount2 / sync / syncfs / rename / link / symlink / set_thread_area / get_thread_area / ioprio_get / ioprio_set. |
| `1658b90 linux-syscall: hoist path-strip helpers into shared sibling TU` | `syscall.cpp` 3,028 → 2,964 lines. StripFatPrefix / CopyAndStripFatPath / AtFdCwdOnly + kAtFdCwd / kAtRemoveDir → new `syscall_pathutil.cpp` (65 lines). Unblocks the file / fs_mut / utime slices. |
| `d04e749 linux-syscall: extract file-table handlers into sibling TU` | `syscall.cpp` 2,964 → 2,635 lines. open / close / stat / fstat / lstat / access / openat / newfstatat + TU-private FillStatFromEntry → new `syscall_file.cpp` (291 lines). |
| `656c0b8 linux-syscall: extract FS-mutating handlers into sibling TU` | `syscall.cpp` 2,635 → 2,470 lines. chmod / fchmod / chown / fchown / lchown / utime / mknod / truncate / ftruncate / unlink / mkdir / rmdir + the *at-family (mkdirat / unlinkat / linkat / symlinkat / renameat / renameat2 / fchownat / futimesat / fchmodat / faccessat / faccessat2 / utimensat) → new `syscall_fs_mut.cpp` (306 lines). |
| `4fe7804 linux-syscall: extract I/O handlers into sibling TU` | `syscall.cpp` 2,470 → 2,037 lines. read / write / lseek / ioctl / fsync / fdatasync / pread64 / pwrite64 / readv / writev + kLinuxIoMax → new `syscall_io.cpp` (450 lines). |
| `6fccf1f linux-syscall: extract miscellaneous handlers into sibling TU` | `syscall.cpp` 2,037 → 1,452 lines. Catch-all "misc" group: arch_prctl / uname / set_tid_address / sysinfo / getrandom / futex / personality / pause / flock / get/setpriority / getcpu / prctl / getrusage / poll / select / getdents64 / set_robust_list / get_robust_list / ppoll / pselect6 / readlink → new `syscall_misc.cpp` (534 lines). WriteMsr duplicated TU-locally so the file is self-contained. |
| `84ed53d linux-syscall: collapse scattered breadcrumb comments` | `syscall.cpp` 1,452 → 1,274 lines. Replace ~200 lines of in-line "moved to" stubs with one consolidated note. Update file header comment to describe the actual current layout. |
| `2977dba shell: extract account-management commands into sibling TU` | `shell.cpp` 9,769 → 9,580 lines. users / useradd / userdel / passwd / logout / su / login + RoleName / RoleFromArg → new `shell_security.cpp` (256 lines). Establishes the shell_internal.h scaffolding under `duetos::core::shell::internal` with a `using namespace shell::internal;` directive at the top of shell.cpp. |
| `2ae2b09 shell: extract storage / device-list commands into sibling TU` | `shell.cpp` 9,580 → 9,468 lines. mount / lsblk / lsgpt / lsmod → new `shell_storage.cpp` (164 lines). Fat* family deferred (shares FatLeaf + ParseU64Str with the rest of the shell). |
| `ef5cc27 shell: extract ps / top / free into sibling TU` | `shell.cpp` 9,468 → 9,308 lines. ps / top / free + TU-private SchedStateName → new `shell_process.cpp` (218 lines). Spawn / Kill / Exec / Linuxexec / Translate / Readelf deferred (share path-strip + FAT32-load helpers). |
| `83cb4dc shell: extract trivial banner / status commands into sibling TU` | `shell.cpp` 9,308 → 9,266 lines. about / version / clear / uptime / date → new `shell_core.cpp` (104 lines). |
| `fb792b3 shell: extend shell_core.cpp with yield / uname / whoami / pwd / true / false` | `shell.cpp` 9,266 → 9,222 lines. Six more trivially-small commands appended to `shell_core.cpp`. CmdHostname stays in shell.cpp pending the env-table hoist. |
| `<pending> shell: hoist env-table to shell_internal.h + shell_state.cpp` | `shell.cpp` 9,222 → 9,127 lines (-95). EnvSlot + kEnvSlotCount/kEnvNameMax/kEnvValueMax + g_env[] + EnvFind / EnvSet / EnvUnset → new `shell_state.cpp` (71 lines), declared in `shell_internal.h`. EnvNameEq / EnvCopy stay inline in the header so the alias table still in shell.cpp can keep calling them. CmdHostname follows the env table into `shell_core.cpp`. First helper hoist of the five queued in the plan; unblocks future CmdEnv / CmdSet / CmdUnset / CmdGetenv / `$VAR` substitution extractions. |
| `<pending> shell: hoist path / parse helpers into shell_pathutil.cpp` | `shell.cpp` 9,127 → 9,011 lines (-116). TmpLeaf / FatLeaf / ParseU64Str / ParseInt → new `shell_pathutil.cpp` (135 lines). Pure functions, no state — declared in `shell_internal.h`. Removes both forward-decl blocks (lines ~264-268 + the leftover `bool ParseU64Str(...);` at the top of the memdump region) so siblings can call all four through the existing `using namespace shell::internal;` directive. Unblocks the entire Fat* family + CmdRead + CmdLinuxexec + CmdExec + CmdReadelf + CmdTranslate. |
| `<pending> shell: hoist console output formatters into shell_format.cpp` | `shell.cpp` 9,011 → 8,939 lines (-72). WriteU64Dec / WriteU8TwoDigits / WriteU64Hex / WriteI64Dec → new `shell_format.cpp` (95 lines). Removes the duplicated TU-local copies from shell_core.cpp (-26), shell_security.cpp (-20) and shell_process.cpp (-22). shell_storage.cpp's WriteU64Hex (no "0x" prefix, fixed-width column output) is genuinely different — renamed in place to `WriteHexCol` to disambiguate from the canonical hex printer. Third helper hoist; only alias-table and history-ring hoists remain queued. |
| `<pending> shell: hoist alias-table to shell_internal.h + shell_state.cpp` | `shell.cpp` 8,939 → 8,874 lines (-65). AliasSlot + kAliasSlotCount / kAliasExpansionMax + g_aliases[] + AliasFind / AliasSet / AliasUnset → existing `shell_state.cpp`, declared in `shell_internal.h`. Mirrors the env-table hoist exactly. |
| `<pending> shell: hoist history-ring to shell_internal.h + shell_state.cpp` | `shell.cpp` 8,874 → 8,759 lines (-115). g_history[][] + g_history_head / g_history_count / g_history_cursor + HistoryPush / HistoryAt / HistoryExpand → existing `shell_state.cpp`. kInputMax + kHistoryCap promoted to inline constants in `shell_internal.h`. StrEq + StrStartsWith hoisted as inline (drops the duplicate copy from shell_security.cpp's anon namespace). Final queued helper hoist; the next slice phase is the filesystem / network / debug / hardware / utilities command buckets per the plan layout below. |
| `<pending> shell: extract trivial utility commands into shell_utilities.cpp` | `shell.cpp` 8,759 → 8,581 lines (-178). First post-hoist extraction. CmdBasename + CmdDirname (pure string), CmdFlushTlb (CR3 reload), CmdMem (frame-allocator totals), CmdMode (display-mode query), CmdHistory (uses hoisted history ring), CmdSleep (scheduler block + ShellInterruptRequested), CmdShutdownNow (ACPI S5 + halt fallback) → new `shell_utilities.cpp` (234 lines). Larger utility commands (Cal / Rand / Uuid / Color / Beep / Checksum / Repeat / Expr / Rev / Tac / Nl / Reset) stay in shell.cpp pending hoist of their TU-private helpers (ParseHex32, ParseU16Decimal, ReadFileToBuf, SliceLines, ParseI64). |

**Deferred** to a follow-up session (each warrants its own fresh chat per
the timeout-prevention rules):

- `kernel/core/shell.cpp` (now 8,759 lines) — five command slices
  + all five queued helper hoists have landed:
  - **env-table hoist** ✅ landed — EnvSlot / g_env / EnvFind /
    EnvSet / EnvUnset in `shell_state.cpp`.
  - **path-strip hoist** ✅ landed — TmpLeaf / FatLeaf /
    ParseU64Str / ParseInt in `shell_pathutil.cpp`.
  - **shared output helpers hoist** ✅ landed — WriteU64Dec /
    WriteU8TwoDigits / WriteU64Hex / WriteI64Dec in
    `shell_format.cpp`. shell_storage's `WriteHexCol` is
    semantically distinct (no "0x" prefix) and stays TU-private.
  - **alias-table hoist** ✅ landed — AliasSlot / g_aliases /
    AliasFind / AliasSet / AliasUnset in `shell_state.cpp`.
  - **history-ring hoist** ✅ landed — g_history / g_history_*
    / HistoryPush / HistoryAt / HistoryExpand in
    `shell_state.cpp`. StrEq + StrStartsWith promoted inline
    in `shell_internal.h`; kInputMax + kHistoryCap likewise.

  After those five hoists the remaining buckets follow the original
  plan layout: filesystem (Ls/Cat/Rm/Touch/Cp/Mv/Find/Grep/Head/
  Tail/Wc/Sort/Uniq/Stat/Basename/Dirname/Hexdump), network (Ping/
  Http/Ntp/Nslookup/Nic/Ifconfig/Dhcp/Route/Netscan/Wifi/Arp/Ipv4/
  UsbNet/Net/FwPolicy/FwTrace/CrTrace), debug (Bp/Probe/Inspect/
  DumpState/MemDump/Trace/Addr2Sym/Instr), hardware (Cpuid/Cr/
  Rflags/Tsc/Hpet/Ticks/Msr/Lapic/Smp/Lspci/Heap/Paging/Fb/Smbios/
  Power/Thermal/Hwmon/Gpu/Gfx/Vbe/KbdStats/MouseStats), utilities
  (Cal/Sleep/Reset/Rand/Uuid/Color/Beep/Checksum/Repeat/Expr/Rev/
  Tac/Nl/FlushTlb), and finally the dispatcher (`kCommandSet[]`
  registry + Dispatch).
_(Linux syscall split completed on
`claude/continue-refactoring-split-QlCKz` across 17 commits;
syscall.cpp 4,642 → 1,274 lines.)_

**Resume prompt for a fresh session:**
> The shell split is in progress on
> `claude/continue-refactoring-1s8hF` (and earlier on
> `claude/continue-refactoring-split-QlCKz`). 5 command slices
> (commits `2977dba` → `fb792b3`) + ALL 5 queued helper hoists
> (env-table → shell_state.cpp; path / parse helpers →
> shell_pathutil.cpp; output formatters → shell_format.cpp;
> alias-table → shell_state.cpp; history-ring → shell_state.cpp;
> + StrEq / StrStartsWith / kInputMax / kHistoryCap inline in
> shell_internal.h) have landed. Cumulative effect: shell.cpp
> 9,769 → 8,759 lines (~10.3% trim).
>
> The next session should start the command-bucket extraction
> phase per the plan layout below: filesystem (Ls/Cat/Rm/Touch/
> Cp/Mv/Find/Grep/Head/Tail/Wc/Sort/Uniq/Stat/Basename/Dirname/
> Hexdump), network, debug, hardware, utilities, and finally
> dispatcher. Each bucket can use any of the helpers now in
> shell_internal.h; no further hoists are queued.
>
> Start a fresh `claude/<slug>` branch off main since the
> current branch is long.

---

## Context

The DuetOS tree has five `.cpp` files dramatically over the project's
~500-line guideline. They are not bloated by accident — each grew as
its subsystem grew — but the size now actively impedes review,
navigation, and the kind of "is this dead code?" auditing the
project's anti-bloat rules call for. CLAUDE.md is explicit that the
threshold is a "pause and think" trigger; these files are 5–20× over
it and were never paused on.

| File | Lines | Multiple of guideline |
|------|------:|----------------------:|
| `kernel/core/shell.cpp`                  | 9,769 | ~20× |
| `kernel/subsystems/win32/thunks.cpp`     | 5,684 | ~11× |
| `kernel/subsystems/linux/syscall.cpp`    | 4,642 |  ~9× |
| `kernel/fs/fat32.cpp`                    | 3,190 |  ~6× |
| `kernel/drivers/usb/xhci.cpp`            | 2,548 |  ~5× |

**Goal:** mechanical, behaviour-preserving decomposition into
per-feature files. No API changes, no logic changes, no new abstractions.
The only files affected outside these five are the matching `CMakeLists.txt`
and a small number of new internal `_internal.h` headers.

**Out of scope for this branch:**
- Renaming public symbols or changing public headers' API surface.
- Removing dead code (separate audit task).
- Touching the four other files near the threshold (`main.cpp`,
  `ring3_smoke.cpp`, `net/stack.cpp`, `window_syscall.cpp`) — defer.

## Conventions used by every split

These apply uniformly to all five files below.

1. **Naming:** `<base>_<aspect>.cpp` (matches existing precedent like
   `cdc_ecm.cpp`, `msc_scsi.cpp` in `drivers/usb/`).
2. **Public headers stay unchanged.** `shell.h`, `thunks.h`, `syscall.h`,
   `fat32.h`, `xhci.h` keep their current exported surface.
3. **Internal helpers + shared file-scope state** move into a new private
   header `<base>_internal.h` next to the originals. Only the new `.cpp`
   files include it.
4. **Anonymous-namespace functions** stay anonymous-namespace in their
   destination file. We do not promote anything to external linkage just
   because it now spans a file boundary — instead, callers move with their
   callees, or the helper goes into the internal header as `inline`.
5. **Dispatch tables** stay in one file (typically a renamed core file).
   Splitting the dispatcher is what would change behaviour; we don't.
6. **`CMakeLists.txt`:** add the new `.cpp` files to the same target
   that currently lists the original. No new targets, no new libraries.
7. **clang-format** is run on every new file before commit.
8. **No `.S` files are touched** (per CLAUDE.md, `clang-format` mangles them).
9. **Each file's split is one commit.** Five commits on this branch.
   No cross-file moves in a single commit.

## Split 1 — `kernel/core/shell.cpp` (9,769 → ~9 files)

**Shared state** to extract first into `kernel/core/shell_internal.h`
(+ a small `shell_state.cpp` for the definitions):

- Input/history/interrupt state, lines 118–139 (`g_input`, `g_len`,
  `g_history[]`, `g_interrupt`).
- Env table, lines 707–801 (`EnvSlot`, `g_env[]`, `EnvFind/Set/Unset`).
- Alias table, lines 812–859 (`AliasSlot`, `g_aliases[]`, `AliasFind/Set/Unset`).
- Numeric/parse helpers, lines 231–1157 (`WriteU64Hex`, `WriteU64Dec`,
  `ParseU64Str`, `ParseInt`, etc.) — `inline` in the header.

**Bucket files** (line counts approximate; original line ranges in parentheses):

| New file | Commands / regions | ~lines |
|---|---|---:|
| `shell_core.cpp`        | Help, About, Version, Clear, Uptime, Date, Theme, Mode, Echo, Dmesg, Stats, Mem, History, Sysinfo, Set/Unset/Env, Alias/Unalias, Source, Man, Which, Getenv, Seq, Time, Uname, Whoami, Hostname, Pwd, True, False, Yield | 1,400 |
| `shell_dispatch.cpp`    | `kCommandSet[]` registry + `Dispatch` (8,344–9,349) | 1,100 |
| `shell_filesystem.cpp`  | Ls, Cat, Rm, Touch, Cp, Mv, Find, Grep, Head, Tail, Wc, Sort, Uniq, Stat, Basename, Dirname, Hexdump | 850 |
| `shell_network.cpp`     | Ping, Http, Ntp, Nslookup, Nic, Ifconfig, Dhcp, Route, Netscan, Wifi, Arp, Ipv4, UsbNet, Net, FwPolicy, FwTrace, CrTrace | 1,500 |
| `shell_storage.cpp`     | Fat* (ls/cat/write/append/new/rm/trunc/mkdir/rmdir), Lsblk, Lsgpt, Lsmod, Read, Mount | 600 |
| `shell_debug.cpp`       | Bp, Probe, Inspect (+ subcmds), DumpState, MemDump, Trace, Addr2Sym, Instr | 1,200 |
| `shell_hardware.cpp`    | Cpuid, Cr, Rflags, Tsc, Hpet, Ticks, Msr, Lapic, Smp, Lspci, Heap, Paging, Fb, KbdStats, MouseStats, Smbios, Power, Thermal, Hwmon, Gpu, Gfx, Vbe | 1,100 |
| `shell_process.cpp`     | Ps, Top, Free, Spawn, Kill, Exec, Linuxexec, Translate, Readelf | 650 |
| `shell_security.cpp`    | Guard, AttackSim, Health, Kdbg, Loglevel, Logcolor, Users, Useradd, Userdel, Passwd, Logout, Su, LoginCmd | 300 |
| `shell_utilities.cpp`   | Cal, Sleep, Reset, Rand, Uuid, Color, Beep, Checksum, Repeat, Expr, Rev, Tac, Nl, FlushTlb | 400 |

After the split, `shell.cpp` is deleted; `shell_dispatch.cpp` carries
what remains of the dispatcher entry point. Public `shell.h` API is
unchanged (`ShellInit`, `ShellFeedChar`, etc.).

**Build wiring:** in the kernel `CMakeLists.txt` (the line currently
reading `core/shell.cpp`), replace with the ten new files above.

## Split 2 — `kernel/subsystems/win32/thunks.cpp` (5,684, constrained)

**Architectural constraint discovered during exploration:** the file
contains a `constexpr u8 kThunksBytes[]` byte-array (lines 370–3816,
~3,447 lines) whose offsets are compile-time constants
(`kOff<Name>`, lines 51–369) consumed by a `consteval` hash table at
lines 5470–5493 and by a hard-coded VA in `thunks.h:137`
(`kWin32ThunksVa + 0x8A6`). The bytecode and its consumers must
remain in one translation unit — splitting them across `.cpp` files
would either break offset constants or force them to runtime.

**Mechanical workaround:** physically move the long literals out of the
`.cpp` into preprocessor `#include` files. The translation unit stays
whole, but the file you read shrinks dramatically.

| New file | Content | ~lines |
|---|---|---:|
| `thunks.cpp` (kept)            | Includes, struct defs, lookup functions (5503–5684), `BuildThunkHashTable`, `kSortedThunkHashes` | ~400 |
| `thunks_bytecode.inc`          | The `kThunksBytes[]` literal (lines 370–3816) | ~3,447 |
| `thunks_offsets.inc`           | All `kOff*` constants (lines 51–369) | ~320 |
| `thunks_table_kernel32.inc`    | 353 `ThunkEntry` rows for kernel32.dll | ~360 |
| `thunks_table_ntdll.inc`       | 107 rows | ~110 |
| `thunks_table_user32.inc`      | 86 rows | ~90 |
| `thunks_table_msvcrt.inc`      | 72 rows (vcruntime140 + ucrtbase + api-ms-* + msvcrt) | ~80 |
| `thunks_table_gdi32.inc`       | 47 rows + render bits | ~50 |
| `thunks_table_other.inc`       | advapi32, ole32, dbghelp, shlwapi, bcrypt, winmm, psapi, oleaut32 (~106 rows) | ~120 |

`thunks.cpp` then constructs `kThunksTable[]` as

```cpp
constexpr ThunkEntry kThunksTable[] = {
    #include "thunks_table_kernel32.inc"
    #include "thunks_table_ntdll.inc"
    #include "thunks_table_user32.inc"
    #include "thunks_table_msvcrt.inc"
    #include "thunks_table_gdi32.inc"
    #include "thunks_table_other.inc"
};
```

The order above must preserve the current ordering by ascending offset
into `kThunksBytes` to avoid silently shifting any consumer of the
table. Verify with a one-line `static_assert` on table size matching
the pre-refactor count.

**Build wiring:** the `CMakeLists.txt` entry remains a single
`subsystems/win32/thunks.cpp`. The `.inc` files are not compiled
directly. Add them to the source group / `target_sources` so they
appear in IDE listings, but they participate in the build only via
`#include`.

**Header update:** `thunks.h` is unchanged. `kWin32ThunksVa + 0x8A6`
trampoline VA must stay correct — verify via the existing
`static_assert` at line 3819 that the total bytecode size remains
`0x1048`.

## Split 3 — `kernel/subsystems/linux/syscall.cpp` (4,642 → 15 files)

**Shared state** to extract into `kernel/subsystems/linux/syscall_internal.h`:

- Errno constants (lines 86–100).
- Helper functions (lines 112–322): `WriteMsr`, `PageUp`,
  `FillStatFromEntry`, `StripFatPrefix`, `CopyAndStripFatPath`,
  `AtFdCwdOnly`, `CopyFdSlot`.
- `g_scratch` / `kbuf` buffer declarations (lines ~516–600) — definitions
  stay in the core file.

**Bucket files** under `kernel/subsystems/linux/`:

| New file | Handlers | ~lines |
|---|---|---:|
| `syscall.cpp` (kept as core) | `LinuxSyscallDispatch` switch table, `SyscallInit`, `LinuxLogAbiCoverage`, public wrappers (`LinuxRead`, `LinuxWrite`, …) | 1,200 |
| `syscall_io.cpp`     | `DoRead`, `DoWrite`, `DoPread64`, `DoPwrite64`, `DoReadv`, `DoWritev`, `DoLseek`, `DoIoctl`, `DoFsync`, `DoFdatasync` | 400 |
| `syscall_file.cpp`   | `DoOpen`, `DoClose`, `DoStat`, `DoFstat`, `DoLstat`, `DoAccess`, `DoOpenat`, `DoNewFstatat` | 250 |
| `syscall_fs_mut.cpp` | `DoMkdir`, `DoRmdir`, `DoUnlink`, `DoTruncate`, `DoFtruncate`, `DoChmod`, `DoChown`, `DoUtime`, `DoMknod`, `Do*at` siblings | 350 |
| `syscall_path.cpp`   | `DoChdir`, `DoFchdir`, `DoGetcwd`, `DoUtimensat`, path-strip helpers | 150 |
| `syscall_mm.cpp`     | `DoBrk`, `DoMmap`, `DoMunmap`, `DoMprotect`, `DoMadvise`, `DoMremap`, `DoMsync`, `DoMincore`, `DoMlock`/`DoMunlock`(`all`) | 450 |
| `syscall_proc.cpp`   | `DoGetPid`, `DoExit`, `DoExitGroup`, `DoGet/SetPgid`, `DoGet/SetSid`, `DoSchedYield`, `DoGetTid`, `DoTgkill`, `DoKill`, `DoUmask` | 200 |
| `syscall_sig.cpp`    | `DoRtSigaction`, `DoRtSigprocmask`, `DoRtSigreturn`, `DoSigaltstack`, `DoRtSigpending`, `DoRtSigsuspend`, `DoRtSigtimedwait` | 250 |
| `syscall_time.cpp`   | `DoClockGetTime`, `DoGettimeofday`, `DoTime`, `DoNanosleep`, `DoClockGetres`, `DoClockNanosleep`, `DoTimes`, `NowNs`, `ReadTsc` | 250 |
| `syscall_fd.cpp`     | `DoDup`, `DoDup2`, `DoDup3`, `DoFcntl`, `CopyFdSlot` | 150 |
| `syscall_cred.cpp`   | All Get/Set Uid/Gid/Euid/Egid/Resuid/Resgid/Fsuid/Fsgid/Groups, `DoCapget`/`DoCapset` | 200 |
| `syscall_sched.cpp`  | All `DoSched*` (affinity, scheduler/param, priority Max/Min, RrGetInterval) | 200 |
| `syscall_rlimit.cpp` | `DoGetrlimit`, `DoSetrlimit`, `DoPrlimit64`, `RlimitDefaultsFor` | 150 |
| `syscall_misc.cpp`   | `DoArchPrctl`, `DoUname`, `DoSetTidAddress`, `DoPoll`, `DoSelect`, `DoGetrusage`, `DoSysinfo`, `DoGetRandom`, `DoPause`, `DoFlock`, `DoPersonality`, `Do(Get/Set)priority`, `DoPrctl`, `DoIoprio*`, `DoGetcpu`, `DoFadvise64`, `DoReadahead` | 400 |
| `syscall_stub.cpp`   | All current EINVAL/ENOSYS-returning stubs (`DoPtrace`, `DoSyslog`, `DoMount`, `DoSync`, `DoRename`, `DoLink`, `DoSymlink`, `DoPipe`/`DoPipe2`, `DoWait*`, `DoEventfd`, `DoTimerfd*`, `DoSignalfd`, `DoEpoll*`, `DoInotify*`, `DoSocket`, …) | 500 |

**Build wiring:** the `kernel/CMakeLists.txt` line currently reading
`subsystems/linux/syscall.cpp` is replaced by all of the above.

## Split 4 — `kernel/fs/fat32.cpp` (3,190 → 6 files)

**Shared state** to extract into `kernel/fs/fat32_internal.h`:

- Constants: `kAttr*`, `Trb`-equivalent on-disk structs.
- Inline helpers: `VZero`, `CopyEntry`, `LeU16`, `LeU32`.

`g_fat32_mutex`, `Fat32Guard` (lines 70–111) and `g_scratch[4096]`
(line 124) stay as definitions in the kept core file; declarations
go in the internal header so the new files can use them.

| New file | Functions | ~lines |
|---|---|---:|
| `fat32.cpp` (kept core) | `Fat32Probe`, `g_volumes`, `g_volume_count`, `Fat32Volume`, `Fat32VolumeCount`, `CompletionCodeName`, `ReadSector`, `ReadCluster`, `ReadFatEntry`, `g_fat32_mutex`, `Fat32Guard` defs, `g_scratch` def | 250 |
| `fat32_dir.cpp`     | `WalkDirChain`, `WalkRootIntoSnapshot`, `DecodeEntry`, `DecodeLfnChars`, `FormatShortName`, `ComputeLfnChecksum`, `IsDotEntry`, `NameIEqual`, `LogEntry`, `Fat32ListDirByCluster`, `Fat32FindInRoot` | 450 |
| `fat32_lookup.cpp`  | `Fat32LookupPath`, `FindVisitor`, `FindCtx` | 150 |
| `fat32_read.cpp`    | `Fat32ReadFile`, `Fat32ReadAt`, cluster-walk read paths, `kMaxIoMax` | 250 |
| `fat32_write.cpp`   | `Fat32WriteInPlace`, `Fat32AppendAtPath`, `Fat32TruncateAtPath`, `UpdateEntrySizeInDir`, `WriteFatEntry`, `AllocateFreeCluster`, `ZeroCluster` | 450 |
| `fat32_create.cpp`  | `Fat32CreateAtPath`, `Fat32DeleteAtPath`, `Fat32MkdirAtPath`, `Fat32RmdirAtPath`, `EncodeShortName`, create/rename helpers | 450 |

Public `fat32.h` is unchanged (`Fat32Probe`, `Fat32Volume`,
`Fat32LookupPath`, `Fat32ReadFile`, `Fat32ReadAt`, `Fat32WriteInPlace`,
`Fat32AppendAtPath`, `Fat32TruncateAtPath`, `Fat32CreateAtPath`,
`Fat32DeleteAtPath`, `Fat32MkdirAtPath`, `Fat32RmdirAtPath`,
`Fat32FindInRoot`, `Fat32ListDirByCluster`).

**Build wiring:** in `kernel/CMakeLists.txt`, the line currently reading
`fs/fat32.cpp` becomes the six lines above.

## Split 5 — `kernel/drivers/usb/xhci.cpp` (2,548 → 10 files)

**Shared state** to extract into `kernel/drivers/usb/xhci_internal.h`:

- All MMIO offset constants (`kCapHciVersion`, `kOpUsbCmd`, …).
- All TRB type constants (`kTrbType*`).
- Structs: `Trb`, `ErstEntry`, `Runtime`, `ControllerInfo`, `PortRecord`,
  `DeviceState` — moved to the header so per-aspect files can refer to them.
- Forward declarations of `g_controllers`, `g_devices`, `g_init_done`,
  `g_device_count`. Definitions stay in the kept core file.
- `CompletionCodeName` decl (definition lives in `xhci_complete.cpp`).

| New file | Functions | ~lines |
|---|---|---:|
| `xhci.cpp` (kept core)  | `g_controllers`, `g_devices`, `g_init_done`, `g_device_count` defs, public registration glue, `XhciProbe` shell | 350 |
| `xhci_init.cpp`     | `XhciInit`, `XhciShutdown`, `InitOne`, controller setup, interrupter init, DCBAA setup | 450 |
| `xhci_ring.cpp`     | `EnqueueRingTrb`, `SubmitCmd`, `RingDoorbell`, `PollUntil`, `AllocZeroPage`, `Read/WriteMmio32/64` | 200 |
| `xhci_event.cpp`    | `AdvanceEventRing`, `WaitEvent`, `WaitCmdCompletion`, `XhciPollEvents`, event-ring setup | 250 |
| `xhci_enum.cpp`     | `XhciEnumeratePorts`, `AddressDevice`, `FetchDeviceDescriptor`, `DeviceForSlot`, `AllocDeviceSlot`, `DefaultMaxPacketSize0`, `BuildAddressDeviceInputContext`, `EnableSlot` | 400 |
| `xhci_control.cpp`  | `DoControlIn`, `DoControlNoData`, `FetchAndParseConfig`, `ParseConfigForHidBoot`, `ConfigureEndpoint`, `SetConfiguration` | 350 |
| `xhci_hid.cpp`      | `SetupHidInterruptRing`, `XhciHidSubmit`, `XhciHidPoll`, `XhciConfigureHidEndpoint`, `ClassDispatchHid` | 300 |
| `xhci_bulk.cpp`     | `SetupBulkRings`, `XhciBulkSubmit`, `XhciBulkPoll`, `XhciConfigureBulkEndpoint`, `ClassDispatchMsc`, `ClassDispatchCdc` | 300 |
| `xhci_port.cpp`     | `ResetPort`, `QueryPortStatus`, port state machine | 200 |
| `xhci_complete.cpp` | `CompletionCodeName`, code translation, `TrbEventCache`, error handlers | 200 |

Public `xhci.h` gains the existing transfer-API names that are already
called from outside the driver (`XhciHidSubmit`/`Poll`,
`XhciBulkSubmit`/`Poll`, `XhciEnumeratePorts`) — these are not new
exports, just declarations made explicit so the per-aspect files do
not need to friend each other.

**Build wiring:** in `kernel/CMakeLists.txt`, the `drivers/usb/xhci.cpp`
line is replaced by all ten files above.

## Commit sequence on `claude/refactor-codebase-VvLO6`

One commit per file split. Order chosen to land the lowest-risk
refactors first so a regression in (say) the shell split doesn't
block the simpler ones.

1. `refactor(xhci): split driver into per-aspect files`
2. `refactor(fat32): split filesystem into per-aspect files`
3. `refactor(linux-syscall): split handlers by subsystem`
4. `refactor(win32-thunks): extract bytecode + per-DLL tables to .inc files`
5. `refactor(shell): split into per-domain command files`

Each commit:
- Touches only the files for that one split + the matching
  `CMakeLists.txt` lines + (where applicable) the new `_internal.h`.
- Passes `clang-format --dry-run --Werror` on every changed file.
- Builds cleanly under `cmake --preset x86_64-release`.
- Boots through to the desktop on the QEMU smoke test.

## Verification (per commit and again at the end)

Per the project's pre-commit checks (CLAUDE.md → "Pre-commit checks"):

```bash
# 1. Format
find kernel \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format --dry-run --Werror

# 2. Configure + build
cmake --preset x86_64-release
cmake --build build --parallel $(nproc)

# 3. Tests
( cd build && ctest --output-on-failure )

# 4. QEMU smoke (since this is a behaviour-preserving refactor of code
#    on the boot path, the boot must still complete)
DUETOS_TIMEOUT=20 tools/qemu/run.sh
```

The QEMU smoke is the strongest signal here — every one of these
files runs at boot or first-shell-prompt:

- `xhci.cpp` runs during driver bring-up.
- `fat32.cpp` runs the moment the shell touches a FAT volume.
- `linux/syscall.cpp` runs whenever a Linux-ABI binary is exec'd.
- `win32/thunks.cpp` runs the first time a PE is loaded.
- `shell.cpp` runs as soon as init reaches the shell.

Targeted verifications per split:

- **xhci:** boot must reach the "xHCI controller online" log line,
  HID keyboard must still register on QEMU `-device usb-kbd`.
- **fat32:** shell `fatls /` lists the boot ISO root identically before
  and after.
- **linux/syscall:** `linuxexec /bin/true` (or whatever the canonical
  smoke binary is) returns 0; `inspect syscalls` count unchanged.
- **win32/thunks:** `kThunksBytes` size `static_assert` still passes
  at `0x1048`; `windows-kill.exe` (per
  `.claude/knowledge/pe-real-world-run.md`) still loads, resolves
  imports, and exits cleanly.
- **shell:** every command listed under `help` is still present and
  dispatched (compare `help` output line-by-line).

## Risks and how the plan handles them

- **Hidden inter-section coupling.** Mitigation: extract `_internal.h`
  in the same commit as the split, not later. Anonymous-namespace
  state remains anonymous-namespace — we do not promote linkage.
- **Dispatch reordering changes behaviour.** Mitigation: dispatch
  tables (`shell_dispatch.cpp`, `LinuxSyscallDispatch`,
  `kThunksTable[]`) keep identical ordering. For `kThunksTable[]`,
  add a `static_assert` that the entry count is unchanged.
- **clang-format reformats more than the moved code.** Mitigation:
  format new files only; do not run `clang-format -i` on files we
  didn't touch.
- **`.S` files near the touched code.** Mitigation: never pass
  assembly to `clang-format`.

## Out of scope (explicitly not done here)

- No public API changes.
- No removal of stub/dead code (audit task to follow separately).
- No new abstractions, no helper classes, no template "improvements."
- No build-system changes beyond adding the new source files to
  the same target.






