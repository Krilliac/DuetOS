# Runtime invariant checker v0

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — live, runs every heartbeat + on shell
`health` command. Covers heap, frames, scheduler, control
registers, both stack-canary kinds. Slice 79 added an
enhanced dumping toolkit (instruction bytes, hex regions,
stack windows) for both crash-time and normal-runtime use.

## Why this exists

Normal panic / trap handling catches problems the CPU or the
code itself actively trips on. Plenty of kernel corruption is
silent — it breaks an invariant that a LATER piece of code
will eventually notice, often on the wrong thread, far from
the buggy writer. By the time the downstream consumer panics,
the crash site has zero signal about what caused it.

This checker runs a fixed O(1) battery of invariant tests on
every heartbeat (~5 s) and on shell `health` request. Each
failing test logs a Warn-level klog line with a specific
issue tag — so the boot log pinpoints the class of
corruption immediately, instead of showing a downstream
panic.

## Invariants covered

| Test                         | What it detects                                     |
| ---------------------------- | --------------------------------------------------- |
| `HeapPoolMismatch`            | used + free > pool (bookkeeping drift)             |
| `HeapUnderflow`               | free_count > alloc_count (double-free / overflow)  |
| `HeapFreelistEmpty`           | free list empty but pool not fully used            |
| `HeapFragmentationHigh`       | > 256 free chunks (splinter bug)                   |
| `FramesOverflow`              | free > total in bitmap                             |
| `FramesAllAllocated`          | all frames used (leak or real pressure)            |
| `SchedExitedMoreThanCreated`  | scheduler counter drift                            |
| `SchedReapedMoreThanExited`   | reaper counter drift                               |
| `SchedLiveUnreasonable`       | tasks_live > 256 (leak / fork bomb)                |
| `SchedNoContextSwitches`      | timer not firing after grace period                 |
| `Cr0WpCleared`                | write-protect bit dropped silently                 |
| `Cr4SmepCleared`              | SMEP bit dropped silently                          |
| `Cr4SmapCleared`              | SMAP bit dropped silently                          |
| `EferNxeCleared`              | NXE bit dropped silently                           |
| `StackCanaryZero`             | `__stack_chk_guard` flipped to 0                   |
| `TaskStackOverflow`           | any task's bottom-of-stack sentinel scribbled      |
| `TaskRspOutOfRange`           | task's saved rsp outside its stack bounds          |
| `GdtModified`                 | GDT code/data descriptors changed (A-bit masked)   |
| `KernelTextModified`          | kernel .text spot-check hash changed               |
| `IrqNestingExcessive`         | (stubbed 0 until per-task IRQ accounting lands)    |
| `CounterWentBackwards`        | monotonic u64 counter (heap/sched) regressed      |
| `ClockStalled`                | HPET or LAPIC tick didn't advance between scans    |
| `SyscallMsrHijacked`          | LSTAR/STAR/CSTAR/SYSENTER drifted (rootkit hook)   |
| `FeatureControlUnlocked`      | IA32_FEATURE_CONTROL lock bit cleared              |
| `BootSectorModified`          | MBR/GPT hash changed (disk-persistence malware)    |

## Kernel-stack overflow detection

Every task's kernel stack has two sentinels:

1. The classic `__stack_chk_guard`-based per-function prologue/
   epilogue cookie (compiler-emitted `-fstack-protector-strong`).
   Detects overflow that reaches past locals into saved regs.

2. An 8-byte `0xC0DEB0B0CAFED00D` canary planted at stack_base[0..7]
   at `SchedCreate` time. Detects deep overflow that scribbles
   anywhere in the bottom page of a 16 KiB kernel stack.

Sentinel #1 tripping produces an IMMEDIATE panic. Sentinel #2
was previously only checked by the reaper at task-exit — so
any task that overflowed but didn't yet die would corrupt the
heap (the task struct + stack live in the kernel heap)
silently. This checker now walks the runqueue + sleep queue +
zombie list every heartbeat and verifies every task's
sentinel #2. Overflow detected within 5 s instead of
"eventually maybe never".

## Control-register drift detection

Baseline captured in `RuntimeCheckerInit` right after
`ProtectKernelImage` runs — when W^X + SMEP + SMAP + NXE are
all online. Every scan re-reads CR0 / CR4 / EFER and flags any
baseline-set bit that's now cleared.

This is the ONLY way to detect silent security-feature
drops — the CPU doesn't panic when these clear, it just stops
enforcing. A bug that executes `mov cr4, r8` with the wrong
value (e.g. zero-extending a smaller register) would silently
disable protection. The checker catches it on the next scan.

## Wiring

```
main.cpp:
  ProtectKernelImage()
  RuntimeCheckerInit()        ← captures control-register baseline

heartbeat.cpp:
  RuntimeCheckerTick()        ← every ~5 s
  LogWithValue health_last_scan_issues
  LogWithValue health_issues_total

shell.cpp:
  "health" / "checkup" cmd    ← on-demand scan + per-issue breakdown
```

## Public API

```cpp
namespace customos::core {

enum class HealthIssue : u32 { None, HeapPoolMismatch, ... };
const char* HealthIssueName(HealthIssue);

struct HealthReport {
    u64 scans_run;
    u64 issues_found_total;
    u64 last_scan_issues;
    u64 per_issue_count[16];
    HealthIssue last_issue;
    u64 baseline_captured;
};

void RuntimeCheckerInit();
u64  RuntimeCheckerScan();           // returns # of NEW issues this scan
void RuntimeCheckerTick();           // fire-and-forget variant
const HealthReport& RuntimeCheckerStatusRead();  // by reference (no memcpy)

} // namespace
```

## Design notes

- The 128-byte `per_issue_count` array makes return-by-value
  require `memcpy`. The kernel doesn't have it. Accessor
  returns `const HealthReport&`.
- Each check is branch-independent: one scan tests every
  invariant, so a single report covers everything.
- Scan is microseconds — the heap stats accessor is O(freelist),
  the sched canary walk is O(runqueue + sleep + zombies).
  Tolerable every 5 s.
- Reports LOG at Warn level but do NOT panic. A follow-on slice
  can add escalation (e.g. panic on 2nd consecutive CR-drift
  since those are catastrophic).

## Rootkit / bootkit-specific defenses

The base invariant checker (heap / sched / control regs / IDT /
GDT / .text / stacks / monotonic counters) plus these extensions
give us a layered posture against real-world persistent malware:

### Syscall-hook detection (MSR baseline)

`IA32_LSTAR` / `STAR` / `CSTAR` / `SYSENTER_{CS,EIP}` captured
at boot; any drift = confirmed syscall-table hijack (the
dominant rootkit technique). `IA32_FEATURE_CONTROL` lock bit
gated on CPUID.1.ECX[5] so it doesn't #GP on non-VMX boxes.

### Bootkit / disk-persistence detection

Per-device FNV-1a hash of LBA 0 (MBR / protective MBR) + LBA 1
(GPT primary header) captured at RuntimeCheckerInit. Scan
re-reads + compares; per-finding log line names the offending
device + LBA. 16-device × 2-LBA cap = 32 u64 baselines.

### Write-guard (defense in depth)

`drivers::storage::BlockWriteGuardMode` — `Off / Advisory / Deny`.
Boot arms rules for LBA 0 + LBA 1 per device + flips mode to
Advisory. On any bootkit-indicator finding (`BootSectorModified`
or `SyscallMsrHijacked`), the mode escalates to Deny: subsequent
writes to guarded LBAs return -1 from `BlockDeviceWrite` without
reaching the backend. Every backend (AHCI / NVMe / RAM) is
covered because the gate is at the block-layer boundary.

### Guard subsystem escalation

The existing `security::SetGuardMode(Enforce)` escalation (added
earlier) fires on every security-critical HealthIssue, tightening
future image-load policy. The three new bootkit-specific codes
(`SyscallMsrHijacked` / `FeatureControlUnlocked` /
`BootSectorModified`) all inherit this path + additionally
trigger the block write-guard escalation.

## Tiered response system (slice 77)

A detector firing used to always panic the kernel — which
meant every detector was also a potential DoS primitive if an
attacker could trip it. The response system addresses this by
layering the reaction:

```
enum class HealthResponse { Heal, Isolate, LogOnly, Panic };
HealthResponse ResponseFor(HealthIssue);
```

| Response  | When applied | Mechanism |
| --------- | ------------ | --------- |
| `Heal`    | Bytes whose correct value is known + immutable | Restore from golden baseline captured at init (`g_golden_idt[4096]`, `g_golden_gdt[7]`, baseline u64s for syscall MSRs + CR/EFER bits). Wrmsr-back or byte-copy. Log the finding + the heal outcome. |
| `Isolate` | Corruption scoped to one task | Task walker kills the offending task; kernel continues. |
| `LogOnly` | Not recoverable but not catastrophic | Just the Warn log line + counter bump. |
| `Panic`   | Continued execution accumulates damage OR can't be trusted | Last resort. StackCanaryZero (we got lucky reaching Report), KernelTextModified (executing corrupt code), heap / frame bookkeeping drift. |

The current mapping (see `ResponseFor` in runtime_checker.cpp):

- **Heal**: IDT / GDT / LSTAR / STAR / CSTAR / SYSENTER / CR0.WP / CR4.SMEP / CR4.SMAP / EFER.NXE
- **Isolate**: TaskStackOverflow / TaskRspOutOfRange
- **LogOnly**: ClockStalled / CounterWentBackwards / FramesAllAllocated / HeapFragmentationHigh / BootSectorModified
- **Panic**: StackCanaryZero / KernelTextModified / FeatureControlUnlocked / HeapPoolMismatch / HeapUnderflow / FramesOverflow

### Important security properties preserved

Even on successful heal:

1. **Finding is always logged.** Audit trail intact.
2. **Counter bumps.** The `health` shell command shows per-issue tallies — an attacker flooding with corruption attempts is visible.
3. **Guard escalation still fires.** Security-critical findings still flip `security::SetGuardMode(Enforce)` so subsequent image loads hit the stricter policy.
4. **Block write-guard still escalates.** Bootkit + syscall-MSR findings still flip blockguard to Deny.
5. **Heal failure counter.** Split from success counter — rising `g_heal_failure_count` means an attacker is hammering a detector the kernel can't recover from.

### Diff dumps (slice 78)

When a detector fires, a `[health-diff]` line lists up to 8
mismatching byte positions:

```
[health-diff] IDT byte[0x0] expected=0x70 got=0x8F
[health-diff] GDT byte[0x35] expected=0xF2 got=0xF3
```

The operator sees which vector / descriptor the attacker
targeted + the attacker's written value (which often identifies
the attack tool — real rootkits write known magic). No
post-mortem memory inspection needed.

### Live red-team result with all three layers (detect / diff / heal)

```
[attacksim] --- IDT hijack ---
[health-diff] IDT byte[0x0] expected=0x70 got=0x8F
[health] IDT hash changed since baseline (handler swap or stray write)
[health] ESCALATE: guard -> Enforce
[health] HEAL: restored IDT ... from golden baseline
[attacksim]   PASS

[attacksim] Summary:
  PASS  Bootkit LBA 0 write
  PASS  IDT hijack
  PASS  GDT descriptor swap
  PASS  LSTAR syscall hook
  passed=4 failed=0 skipped=0
```

Kernel stayed alive, heartbeat kept ticking through and past
the attack suite, scans returned clean after each heal. No
panic, no DoS, every attack observable in the log.

## Enhanced dumping toolkit (slice 79)

The diff-dump pattern from slice 78 graduates into a generic
`kernel/core/hexdump.{h,cpp}` helper used by:

- The trap dispatcher — every kernel-mode exception now logs:
  - 16 bytes of instruction at `frame->rip` (so the operator
    sees the literal opcode that faulted without running
    `objdump`).
  - 96 bytes of memory around CR2 on `#PF`, with the faulting
    page itself skipped (it's unmapped by definition).
  - 16 quads of stack starting at `frame->rsp`, symbol-annotated.

- The ring-3 task-kill path — same instruction-bytes dump for
  the user RIP. The plausibility check intentionally REJECTS
  user-mode addresses (any VA outside the higher-half kernel
  region) so a wild user RIP becomes a `<skipped>` log line
  instead of a kernel SMAP fault during the dump.

- The panic path — `DumpDiagnostics` now emits the instruction
  bytes at the panic call site, in addition to the existing
  backtrace + stack dump.

- The shell — three new commands for live inspection:
  - `memdump <hex-addr> [len]` — hex+ASCII dump to COM1.
  - `instr <hex-addr> [len]`   — single-line instruction dump.
  - `dumpstate`                — every subsystem's stats, one record.

### Why a separate plausibility check

`PlausibleKernelAddress(va)` accepts only `[0xFFFFFFFF80000000,
0xFFFFFFFFE0000000)` — direct map + MMIO arena. The low 1 GiB
identity map is excluded even though it's mapped. Reason: under
SMAP, a kernel read of a low-half VA that the current CR3 routes
to a ring-3 page trips a #PF on the read. A naive "low half is
fine, it's identity-mapped" check works pre-userland but turns
the trap dumper into a fault generator the moment a ring-3 task
faults with a sub-1-GiB RIP. Live boot showed exactly this
regression on the first iteration; the fix took every kernel
crash out of the boot smoke (recurring `arch/traps` #PF -> 0).

### Safe-dump skip semantics

`DumpHexRegionSafe(tag, addr, len, skip_page_va)` splits each
16-byte line into one of three outcomes:

| Outcome                     | When                                                |
| --------------------------- | --------------------------------------------------- |
| Hex + ASCII line emitted    | Line VA passes plausibility AND is not in skip page |
| `<unreadable>`              | Line VA fails plausibility                          |
| `<skipped: faulting page>`  | Line VA's page == `skip_page_va`'s page             |

The skip-page parameter is what makes "dump 96 bytes around
CR2" safe: pass `cr2 & ~0xFFF` and the helper walks past the
faulting page without ever dereferencing it.

## Universal IDT coverage + tiered trap response (slice 80)

Two related improvements that close the "exception fell through to
panic" gap:

### Full 256-vector IDT install

`IdtInit` now patches every IDT slot (0..255), backed by stubs for
all 256 vectors in `exceptions.S`. Generated via `.altmacro` +
`.rept` so 206 spurious-vector stubs (48..127, 129..254) take a
dozen lines instead of 206. Slot 128 is the syscall gate
(re-installed DPL=3 by `SyscallInit`); slot 255 is the LAPIC
spurious vector (re-installed by `LapicInit`); both overrides are
full SetGate writes, so the initial DPL=0 install is overwritten
cleanly.

A stray `INT n` / IPI / device-injected interrupt now logs
`[idt] spurious vector 0xN rip=... cs=...` and `iretq`s. Before
this slice, vectors > 47 had Present=0 IDT gates and the CPU
cascaded delivery into #NP — losing the original vector number in
favour of #NP's "selector that #NP'd" error code.

### TrapResponse policy

CPU exceptions (0..31) are now routed through a per-vector +
per-ring policy table (`TrapResponseFor`):

| Outcome           | When                                           |
| ----------------- | ---------------------------------------------- |
| `LogAndContinue`  | Kernel-mode #BP (3) or #DB (1)                |
| `IsolateTask`     | Any user-mode hit (existing task-kill path)   |
| `Panic`           | Kernel-mode anything else (existing crash dump) |

The `LogAndContinue` outcome is what makes in-kernel `int3`
breakpoints and hardware single-step usable without halting the
box — the dispatcher emits one log line and `iretq`s. The
`Panic` outcome is documented as a deliberate last-resort and
matches the runtime-checker's tiered response from slice 77.

### Live boot self-test

`TrapsSelfTest()` runs from `kernel_main` right after `IdtInit`
+ `SyscallInit`. Issues `int3` (kernel-mode #BP) and `int 0x42`
(spurious vector). Both must recover; if either regresses to
panic, the boot log shows the cause instead of the self-test's
OK line. Passing log:

```
[traps] self-test
[trap] #BP Breakpoint (recoverable) rip=0xffffffff80140105 cs=0x8
[idt] spurious vector 0x42 rip=0xffffffff80140107 cs=0x8
[traps] self-test OK — #BP and spurious both recovered
```

## Follow-ups

1. **Guard subsystem escalation** — the security guard currently
   only gates image loads. Tie it to the runtime checker so
   any `HealthIssue::Cr*Cleared` finding flips the guard into
   safe mode + denies every subsequent image load until
   operator intervention.

2. **Per-CPU invariant check** — when SMP is online, each CPU
   has its own GDT/TSS/per-CPU struct; the BSP scan should
   IPI-fan-out a per-CPU scan.

3. **IDT integrity check** — hash the IDT at `RuntimeCheckerInit`
   and compare against the baseline each scan. A rootkit-style
   handler swap would otherwise be invisible.

4. **Kernel-image text hash** — same idea for `.text`. Full
   SHA-256 is too slow; a per-page CRC32 at boot + periodic
   spot-check of N random pages would catch text corruption
   with bounded latency.
