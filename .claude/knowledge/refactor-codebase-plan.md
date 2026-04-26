# Refactor: split the top-5 oversized .cpp files

## Status (2026-04-26)

Branch: `claude/refactor-codebase-VvLO6`. Pushed to origin.

**Landed** (build-verified through both kernel stages):

| Commit | Effect |
|---|---|
| `cae3704 win32/thunks: extract bytecode + entry table to .inc files` | `thunks.cpp` 5,684 → 655 lines (88% reduction). Bytecode + entry-table bodies live in `thunks_bytecode.inc` + `thunks_table.inc`, `#include`d back into `thunks.cpp`. TU stays whole. |
| `1f5efd1 docs: add Stream Timeout Prevention section to CLAUDE.md` | 5-rule mitigation block (one task at a time, ~150-line write cap, fresh session after 20+ tool calls, short greps, retry shorter on timeout). |
| `736381b fs/fat32: split Fat32SelfTest into a sibling file` | `fat32.cpp` 3,190 → 2,579 lines. SelfTest lives in `fat32_selftest.cpp` (628 lines), uses public Fat32* API only. |

**Deferred** to a follow-up session (each warrants its own fresh chat per
the timeout-prevention rules):

- `kernel/core/shell.cpp` (9,769 lines) — per-domain command extraction
  + shared-state plumbing into `shell_internal.h`. No big data block to
  `.inc`-extract; this is a real function-by-function split.
- `kernel/subsystems/linux/syscall.cpp` (4,642 lines) — split by syscall
  subsystem (io, file, mm, proc, sig, time, fd, cred, sched, rlimit,
  misc, stub).
- `kernel/fs/fat32.cpp` (now 2,579 lines) — finish the per-layer split
  (probe / dir / lookup / read / write / create).
- `kernel/drivers/usb/xhci.cpp` (2,548 lines) — recommend a 4-file
  split (core / init / xfer / enum) rather than the explorer's
  optimistic 10-file plan; `InitOne` orchestrates AddressDevice +
  FetchDeviceDescriptor + FetchAndParseConfig + BringUpHidKeyboard
  + XhciBindMsix + spawns HidPollEntry, all referencing file-scope
  `g_poll_rt[]` / `g_poll_args[]`.

**Resume prompt for a fresh session:**
> Continue the refactor on branch `claude/refactor-codebase-VvLO6`.
> Read `.claude/knowledge/refactor-codebase-plan.md` for context, then
> pick the next file from the deferred list and execute it as a single
> commit (split + CMakeLists update + build verify + commit). Do NOT
> attempt more than one file per session — the rules in CLAUDE.md's
> "Stream Timeout Prevention" section exist for a reason.

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






