# Diagnostics

> **Audience:** Kernel hackers, SREs, anyone debugging a live boot
>
> **Execution context:** Kernel — most APIs are IRQ-safe; a few self-tests
> run from process context during boot
>
> **Maturity:** v0 stable — 22 active modules; UBSAN off by default

## Overview

DuetOS keeps its diagnostic surface in two trees:

- [`kernel/diag/`](../../kernel/diag/) — the **passive** surface: log rings,
  detectors, decoders, persistence. These watch the kernel without changing
  control flow.
- [`kernel/debug/`](../../kernel/debug/) — the **active** surface: software
  and hardware breakpoints, disassembler, watchpoints, tripwires, hot-patch.
  These can halt or modify a running kernel.

A separate, smaller [`kernel/test/`](../../kernel/test/) directory hosts
the boot smoke profile dispatcher. See [QEMU Smoke](../tooling/QEMU-Smoke.md)
for how those profiles are driven from the harness.

The contract every module follows:

- A clean boot is **quiet** at default log levels. The only marks a clean
  boot leaves are `[<subsys>-selftest] PASS (...)` lines on stdout if the
  self-test chose to emit them.
- A regression boot leaves a `WARN` sentinel plus a probe fire plus
  DEBUG-gated detail, all behind the kernel's log-level system. See
  [Logging and Tracing](Logging-And-Tracing.md) for log-level
  configuration.

## Diagnostic Modules — Passive

| Module | Header | What it does | Self-test |
|--------|--------|--------------|-----------|
| `kdbg` | [`kdbg.h`](../../kernel/diag/kdbg.h) | Per-channel debug enable (32 named channels). `KDBG_PRINTF(ch, …)` only fires if the channel is on. | none |
| `gdb_server` | [`gdb_server.h`](../../kernel/diag/gdb_server.h) | GDB remote serial protocol server (g, m, M, s, c, ?, X, Z/z, vCont, qRcmd). | `GdbServerSelfTest()` |
| `gdb_monitor` | [`gdb_monitor.h`](../../kernel/diag/gdb_monitor.h) | DuetOS-aware `monitor` (`qRcmd`) surface: `duet ps/caps/threads/handles/vm/mods/win/win32/reg/probe/kdbg/watch/trip/dump`. Read-only introspection + kernel-owned debug-facility control; reached via `monitor duet …` from stock gdb or `tools/debug/duetos-gdb-monitor.py`. | `GdbMonitorSelfTest()` → `[gdb-monitor-selftest] PASS` |
| `recovery` | [`recovery.h`](../../kernel/diag/recovery.h) | Runtime recovery taxonomy (classes A–F) + `RetryWithBackoff<Fn>` template. | none |
| `minidump` | [`minidump.h`](../../kernel/diag/minidump.h) | Emits Windows-format `.dmp` over debugcon port 0xE9. Persists to NVMe + FAT32. | `MinidumpSelfTest()`, `DiskPersistSelfTest()` |
| `leak_detector` | [`leak_detector.h`](../../kernel/diag/leak_detector.h) | Aggregates per-subsystem resource counters; fires `kLeakAttributable` on process exit if any pinned. | none (read-only of existing counters) |
| `soft_lockup` | [`soft_lockup.h`](../../kernel/diag/soft_lockup.h) | Single-task CPU hog detector (100 ticks ≈ 1 s default). | `SoftLockupSelfTest()` |
| `stress_driver` | [`stress_driver.h`](../../kernel/diag/stress_driver.h) | Boot-time stress harness driven by `stress=` cmdline. | none |
| `ubsan` | [`ubsan.h`](../../kernel/diag/ubsan.h) | UBSAN runtime — 14 handler classes (overflow, shift, OOB, alignment, …). Each incident emits one `[W] diag/ubsan : <kind>` klog line carrying the failing class as the ring-entry message (so the BSOD recent-log tail shows the actual UB class, not a generic placeholder). `type-mismatch` additionally emits one deduped `[ubsan]   tm-detail …` line per call site decoding the access kind (load/store/…), the failing pointer, the required alignment, and which fault it is (`null-deref` / `misaligned` / `obj-too-small`) — the source line alone is misleading when the UB is a misaligned wide access whose attributed line is a plain scalar op. Off by default. | `UbsanSelfTest()` |
| `fault_react` | [`fault_react.h`](../../kernel/diag/fault_react.h) | Self-defensive fault dispatcher (`FaultKind` × `FaultSeverity` → `FaultReaction`). Trap-safe deferred drain. | `FaultReactSelfTest()` |
| `fix_journal` | [`fix_journal.h`](../../kernel/diag/fix_journal.h) | Record-and-defer for STUB/GAP hits at runtime — 1024×128B ring. Macros `FIX_NOTE_STUB()` / `FIX_NOTE_GAP()`. | `FixJournalSelfTest()` |
| `fix_journal_persist` | [`fix_journal_persist.h`](../../kernel/diag/fix_journal_persist.h) | Tier-2/3 persistence to FAT32 `/KERNEL.FIX` and NVMe reserved LBAs. | `FixJournalPersistSelfTest()` |
| `perf_profile` | [`perf_profile.h`](../../kernel/diag/perf_profile.h) | PMU sample ring (4096 × 16 B). Sampling wiring pending. | `PerfProfileSelfTest()` |
| `event_trace` | [`event_trace.h`](../../kernel/diag/event_trace.h) | Lock-free per-CPU event ring (4096 × 32 B). 8 canonical event kinds. | `EventTraceSelfTest()` |
| `heartbeat` | [`heartbeat.h`](../../kernel/diag/heartbeat.h) | Stats thread (`kheartbeat`). Calls `RcuTick`, `RuntimeCheckerTick`, fix-journal flush. | none |
| `hexdump` | [`hexdump.h`](../../kernel/diag/hexdump.h) | Memory/instruction dump helpers; `DumpHexRegionSafe` survives page-faults via extable. | `HexdumpSelfTest()` |
| `log_names` | [`log_names.h`](../../kernel/diag/log_names.h) | Symbolic resolvers (`SyscallName`, `PciVendorName`, `IdtVectorName`, `LinuxSignalName`, `NtStatusName`, …). | none (pure tables) |
| `cleanroom_trace` | [`cleanroom_trace.h`](../../kernel/diag/cleanroom_trace.h) | Dual-region trace: sticky 256-entry boot + rolling 4096-entry tail. | none |
| `crprobe` | [`crprobe.h`](../../kernel/diag/crprobe.h) | Cleanroom-trace exercise — fake Wi-Fi backend asks for an unsatisfiable firmware blob. | `CrProbeRun()` |
| `boot_progress` | [`boot_progress.h`](../../kernel/diag/boot_progress.h) | Early-boot RDTSC markers, pre-HPET. Emits `[boot] tag +δ tsc=…` to COM1. | none |
| `diag_decode` | [`diag_decode.h`](../../kernel/diag/diag_decode.h) | CR/RFLAGS/page-walk decoders + `ClassifyVa()` region tagger. | `VaRegionSelfTest()` |
| `debugcon` | [`debugcon.h`](../../kernel/diag/debugcon.h) | Binary writer to port 0xE9 (QEMU debugcon). | none |
| `runtime_checker` | [`runtime_checker.h`](../../kernel/diag/runtime_checker.h) | Invariant scanner (31 issue types). Periodic from heartbeat. Fires probes on heap corruption, CR drift, stack overflow, fs-write storm. | `RuntimeCheckerInit()` captures baseline |

## Diagnostic Modules — Active

| Module | Header | What it does | Self-test |
|--------|--------|--------------|-----------|
| `breakpoints` | [`breakpoints.h`](../../kernel/debug/breakpoints.h) | Software INT3 + hardware DR0–DR3. `BpInstallSoftware`, `BpInstallHardware`, trap handlers. v0: kernel-mode, .text only, single-CPU. | `BpSelfTest()` |
| `bp_syscall` | [`bp_syscall.h`](../../kernel/debug/bp_syscall.h) | Syscall router for breakpoint install/remove (`SYS_BP_INSTALL=38`, `SYS_BP_REMOVE=39`). Cap-gated `kCapDebug`. | none |
| `disasm` | [`disasm.h`](../../kernel/debug/disasm.h) | x86_64 disassembler. Covers MOV, LEA, ALU, JMP/JCC, CALL, RET, SYSCALL, NOP, HLT, INT3/INT. Gaps: SIMD, string ops, x87, far jumps. | `disasm::SelfTest()` |
| `extable` | [`extable.h`](../../kernel/debug/extable.h) | Exception table — `(rip_start, rip_end, fixup_rip, domain_id)` tuples for "this fault is recoverable, jump here." 32-entry cap. | `ExtableSelfTest()` |
| `extable_bind` | [`extable_bind.h`](../../kernel/debug/extable_bind.h) | Macros wrapping extable registration with a name + domain. | none |
| `hot_patch` | [`hot_patch.h`](../../kernel/debug/hot_patch.h) | Live function patching — 5-byte `JMP rel32` overlay on a `patchable_function_entry` NOP. | `HotPatchSelfTest()` |
| `inspect` | [`inspect.h`](../../kernel/debug/inspect.h) | Reverse-engineering helpers — `inspect syscalls`, `inspect opcodes`, `inspect arm on|off` from the shell. | none |
| `probes` | [`probes.h`](../../kernel/debug/probes.h) | Static probe table (31 IDs). `KBP_PROBE(id, ...)` fires named breakpoint targets. | `ProbeInit()` resets counters |
| `syscall_scan` | [`syscall_scan.h`](../../kernel/debug/syscall_scan.h) | Idiom scanner for `syscall`/`int 0x80`/`int 0x2E`/`sysenter` byte sequences. Recovers preceding `mov eax, imm32`. | none |
| `tripwire` | [`tripwire.h`](../../kernel/debug/tripwire.h) | Named software watchpoints — CRC-32 snapshot + on-demand verify. 16 regions, actions Log / LogEach / Panic. | `TripwireSelfTest()` |
| `watch` | [`watch.h`](../../kernel/debug/watch.h) | Named hardware watchpoints — DR0–DR3 write guards. 4 concurrent, actions LogOnce / LogEachHit / Panic. | `WatchSelfTest()` |
| `dr` | [`dr.h`](../../kernel/debug/dr.h) | Debug-register accessors and DR6/DR7 bit packers. Inline only. | n/a |

## The Probe Table

Static probes are the lowest-friction way to halt a debugger at a known
moment of interest. Defined in [`probes.h`](../../kernel/debug/probes.h) +
[`probes.cpp`](../../kernel/debug/probes.cpp), they have:

- An ID (`ProbeId::kFoo`) chosen so a `git grep kFoo` finds the firing site
- A name (`"diag.foo"`) the shell uses
- A default `ProbeArm` — `Disarmed`, `ArmedLog` (writes a one-liner +
  bumps a counter), or `ArmedSuspend` (stops the world for GDB)

**ArmedLog by default** (high-signal, low-rate):

```
kPanicEnter            kSandboxDenialCap     kWin32StubMiss
kKernelPageFault       kKernelGpf            kKernelUd
kHeapAllocFail         kPhysAllocFail        kSmpApOnline
kBootSelftestFail      kAcpiMcfgTruncated    kPeLoaderOom
kElfLoaderOom          kProbeFail            kTopologyParseFailed
kBootInitWedge         kModuleStateChange    kLeakAttributable
kFixJournaled
```

**Disarmed by default** (medium / high frequency — turn on for a session):

```
kRing3Spawn            kProcessCreate        kProcessDestroy
kPeLoadOk              kElfLoadOk            kThreadExit
kSchedContextSwitch
```

Macro shorthand at firing sites:

```cpp
KBP_PROBE(kHeapAllocFail);
KBP_PROBE_V(kFixJournaled, detector_enum_value);
```

When adding a new probe, follow the
[CLAUDE.md probe contract](../../CLAUDE.md#diagnostic-logging--keep-it-gate-it-probe-it):
one row each in the enum + table, default arm chosen so a clean run stays
silent, pair with a `KLOG_WARN` sentinel where useful.

## The Fix Journal

The fix journal is DuetOS's structured TODO list emitted *by the running
kernel*. When code reaches a `STUB` / `GAP` / "unknown syscall" /
"unmapped thunk" site, it calls `FixJournalRecord(detector, info)` (or
the `FIX_NOTE_STUB` / `FIX_NOTE_GAP` macros) and the call is logged into
a 1024-entry ring with caller RIP, a 128-byte detail blob, and a hit
count.

The persistence layer
([`fix_journal_persist.h`](../../kernel/diag/fix_journal_persist.h)) drains
the in-memory ring to disk via two tiers:

- **Tier 2 — FAT32**: `/KERNEL.FIX` rotated every N records. Operators
  read this from another OS to see what the previous boot stubbed out.
- **Tier 3 — NVMe reserved LBAs**: a fixed range outside any filesystem,
  for the panic-write path when FAT32 isn't safe.

See the [Fix Journal](../security/Fix-Journal.md) page for the operator
workflow.

## Recovery Taxonomy

[`recovery.h`](../../kernel/diag/recovery.h) defines six classes:

| Class | Severity | Action |
|-------|----------|--------|
| A | catastrophic | halt — `arch::Hlt()` after writing a stamp |
| B | driver fault | restart the driver via its `FaultDomain` (see [Driver Domains](../security/Driver-Domains.md)) |
| C | process fault | kill the process, log a structured event |
| D | retry | use `RetryWithBackoff<Fn>` — bounded number of attempts |
| E | reject | refuse the operation, log + return error |
| F | reset | force a chipset reset (used only by the watchdog) |

Subsystems pick their class at the call-site that raises the fault.
`FaultReactDispatch()` consults policy (
[`FaultReactSetPolicy()`](../../kernel/diag/fault_react.h)) to allow
operators to floor reactions globally (e.g. "no Class A in this build").

## Boot Self-Test Orchestration

There is **no** unified `BOOT_SELFTEST` hook. The boot path
([`kernel/core/main.cpp`](../../kernel/core/main.cpp)) calls each
`*SelfTest()` explicitly. A self-test that passes is silent by default;
emit a one-liner explicitly via `arch::SerialWrite` if you want CI to
grep for proof of pass. A self-test that fails fires
`kBootSelftestFail` with an integer encoding the sub-check that tripped.

The full list (~26 self-tests) lives in `main.cpp`; the in-line
sequence is:

```
mm → sync → time → acpi → arch self-tests → diag self-tests → 
debug self-tests → fs → drivers → subsystems → security
```

If you add a new module under `kernel/diag/` or `kernel/debug/`,
its self-test belongs in the appropriate block.

## Threading and Locking

- **Diag ring writers** (kdbg, event_trace, cleanroom_trace,
  fix_journal) use lock-free or per-CPU rings. IRQ-safe.
- **Debug primitives** (breakpoints, watchpoints) modify global state
  (the IDT and DR registers); they take a spinlock with IRQs masked.
- **GDB server** runs from process context. It enters a busy-wait stop
  loop when a probe fires `ArmedSuspend` so the rest of the CPU is
  quiescent while a remote operator pokes registers.
- **Hot-patch** modifies executable text. It quiesces with stop-the-world
  before applying the JMP overlay.

## Machine Check (#MC) Decode

DuetOS has two MCA touch points. The **passive** path is
`runtime_checker`'s periodic bank scan, which clears + reports
*corrected* errors that accumulate silently in `MCi_STATUS` without
ever raising an exception. The **active** path is
[`kernel/arch/x86_64/machine_check.cpp`](../../kernel/arch/x86_64/machine_check.cpp):
when an *uncorrected* error raises a real `#MC` (vector 18), the trap
dispatcher routes the frame to `arch::MachineCheckReport` *before* the
generic register dump. `#MC` is special-cased in `TrapResponseFor` to
`Panic` regardless of ring — a bad DIMM / cache parity / bus error
taken while ring 3 was current is a system-level event, never an
`IsolateTask` or user-SEH delivery.

The decode reads `IA32_MCG_CAP` / `MCG_STATUS` and walks every
`VAL`-set `MCi_STATUS` bank, printing the decoded flags
(`UC`/`EN`/`PCC`/`ADDRV`/…), the MCA error class (TLB / cache / bus /
memory-controller / internal), and `MCi_ADDR` / `MCi_MISC` when valid.
It returns a recoverability verdict:

| Verdict | Condition | Meaning |
|---------|-----------|---------|
| `NoError` | no bank `VAL` | spurious / software-raised / firmware-injected #MC |
| `ContextCorrupt` | a bank has `PCC=1` | processor state gone — unrecoverable |
| `ContextLost` | `MCG_STATUS.RIPV=0` | cannot resume the interrupted flow — unrecoverable |
| `RestartableInfo` | `RIPV=1`, no `PCC` | restartable in principle (see GAP below) |

Runtime-exercisable via `fault-inject mce` (or `FaultClass::MachineCheck`)
— a software `int $18` leaves the banks clean, so the path proves it
routes → decodes → halts without itself triple-faulting on the IST2
machine-check stack. See [Fault Injection](Fault-Injection.md).

## Known Limits / GAPs

- **No #MC recovery path.** Even when the bank decode returns
  `RestartableInfo` (`RIPV=1`, no `PCC` — restartable in principle),
  the dispatcher still halts: DuetOS v0 has no page-poison / SRAR
  recovery (no per-frame poison list, no kill-just-the-poisoned-page
  handler). Conservative contract — data integrity over liveness.
  Revisit when `mm` grows a poison list.
- **UBSAN off by default.** Enable with `ubsan=on` cmdline; rate-limited
  reports otherwise drown the log.
- **`blake2b.cpp` type-mismatch on the auth path (open).** Running
  `su` / any password verify trips `[ubsan] type-mismatch at
  blake2b.cpp` with `tm-detail … fault=misaligned need-align=0x10
  ty='u64'` on an 8-aligned **stack** address. The sched stack setup
  is ABI-correct (16-aligned, padding quad → RSP%16==8 at entry), so
  the 8-byte skew is introduced somewhere on the serial-input-task →
  shell → `AuthLogin` → Argon2id → Blake2b asm/trampoline chain.
  Diagnostic-only (x86 tolerates the access); needs its own slice to
  trace the offending frame — a kernel-wide stack-ABI change is too
  risky to land blind.
- **PMU sampling wiring deferred.** `perf_profile` rings are present and
  exercised by the self-test, but no `OvfInterrupt → PerfRecord` path
  yet.
- **GDB server is stop-only**, no step/cont over SMP. The
  `monitor` (`qRcmd`) `duet …` surface is likewise stop-only —
  commands dispatch from inside the stop loop, so the target must
  be stopped (a breakpoint, Ctrl-C, or the `DUETOS_GDB_DEMO`
  int3), exactly like stock-gdb `monitor`. Reply is a single
  packet, hard-truncated with a `[truncated]` sentinel;
  `O`-packet streaming is deferred.
- **Hot-patch single-target.** No staged rollouts; an apply patches every
  matching `patchable_function_entry` at once.
- **Soft-lockup is single-CPU**; no per-CPU watchdog yet. Adequate while
  SMP AP bring-up is still pending.

## Related Pages

- [Logging and Tracing](Logging-And-Tracing.md) — KLOG levels, sinks
- [Debugger](../tooling/Debugger.md) — the kdbg shell command + GDB
  attach workflow
- [Debugging](../tooling/Debugging.md) — operator-facing intro
- [Fix Journal](../security/Fix-Journal.md) — operator workflow for
  STUB/GAP audit
- [QEMU Smoke](../tooling/QEMU-Smoke.md) — boot smoke profiles
- [Runtime Recovery Strategy](../security/Runtime-Recovery.md) — class
  A–F taxonomy applied to security events
