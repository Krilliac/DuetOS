# Redteam coverage matrix — v0

**Type:** Observation + Decision
**Status:** Active
**Last updated:** 2026-04-26

## What it is

End-to-end map of "every malware/rootkit technique we want to detect"
vs. "what the kernel actually exercises today." Built after a full
audit of `kernel/security/attack_sim.cpp` (kernel-mode attacks),
`kernel/proc/ring3_smoke.cpp` (ring-3 hostile probes),
`kernel/diag/runtime_checker.cpp` (detectors), and the Win32 NT
syscall table at `kernel/subsystems/win32/nt_syscall_table_generated.h`.

The motivating ask: "test all the ways actual malware could damage or
access the system." The honest answer is **most of the kernel-side
threat surface is already covered**; the gaps are mostly user-mode
threats that need either new capabilities or unimplemented Win32 APIs
to be testable.

## Coverage matrix

Legend: ✅ tested today · ⚠️ partial · ❌ gap · ⏸ deferred (rationale below)

### Kernel-mode rootkit techniques

| Technique | Vehicle | Detector | Status |
|---|---|---|---|
| Bootkit / MBR overwrite | `attack_sim` AttackBootSector | `BootSectorModified` | ✅ |
| IDT vector hook | `attack_sim` AttackIdt | `IdtModified` | ✅ |
| GDT descriptor swap | `attack_sim` AttackGdt | `GdtModified` | ✅ |
| LSTAR syscall hook | `attack_sim` AttackLstar | `SyscallMsrHijacked` | ✅ |
| SYSENTER_CS hook (legacy) | `attack_sim` AttackSysenterCs | `SyscallMsrHijacked` | ✅ |
| SYSENTER_EIP hook (legacy) | `attack_sim` AttackSysenterEip | `SyscallMsrHijacked` | ✅ |
| STAR / CSTAR scrambling | — | `SyscallMsrHijacked` | ⏸ self-bricking — STAR holds CS:SS for SYSCALL/SYSRET |
| CR0.WP defang (W^X bypass) | `attack_sim` AttackCr0Wp | `Cr0WpCleared` | ✅ |
| CR4.SMEP defang (ret2usr) | `attack_sim` AttackCr4Smep | `Cr4SmepCleared` | ✅ |
| CR4.SMAP defang (user-mem read) | `attack_sim` AttackCr4Smap | `Cr4SmapCleared` | ✅ |
| EFER.NXE defang (data exec) | `attack_sim` AttackEferNxe | `EferNxeCleared` | ✅ |
| Kernel `.text` inline hook | `attack_sim` AttackKernelTextPatch | `KernelTextModified` | ✅ |
| Stack canary defang | `attack_sim` AttackStackCanaryZero (no-stack-protector island via `[[gnu::no_stack_protector]]`; bypasses Panic-class via `RuntimeCheckerBumpIssueCounter_ForTest`) | `StackCanaryZero` | ✅ |
| IA32_FEATURE_CONTROL unlock | — | `FeatureControlUnlocked` | ⏸ locked MSR refuses write; un-triggerable on locked firmware |
| Kernel heap pool corruption | — | `HeapPoolMismatch` / `HeapUnderflow` | ⏸ corrupts allocator bookkeeping; needs scratch heap |
| IRQ storm DoS | — | `IrqStorm` | ⏸ needs >25k software ints; pollutes IRQ stats |
| Task stack overflow / saved-rsp scribble | — | `TaskStackOverflow` / `TaskRspOutOfRange` | ⏸ needs scheduler-quiesce primitive |
| Cross-process VM read/write | `ring3_smoke` SpawnCrossPidProbe (sandboxed task spams SYS_PROCESS_OPEN; cap-gate denies, sandbox-denial threshold reaps) | `kCapDebug` denial counter + `KillReason::SandboxDenialThreshold` | ✅ (gate-side; per-target ACL still deferred for kCapDebug holders) |

### Ring-3 user-mode malware techniques

| Technique | Vehicle | Pass criterion | Status |
|---|---|---|---|
| Sandbox cap denial loop (retry storm) | `ring3_smoke` SpawnHostileProbe | task killed by 100-denials threshold | ✅ |
| W^X violation (write to RX page) | `ring3_smoke` SpawnJailProbeTask | #PF kills task; reaper recovers frames | ✅ |
| NX violation (jump to NX page) | `ring3_smoke` SpawnNxProbeTask | #PF kills task | ✅ |
| Privilege escalation attempt | `ring3_smoke` SpawnPrivProbeTask | #GP kills task | ✅ |
| Bad / undefined interrupt | `ring3_smoke` SpawnBadIntProbeTask | #GP / #UD kills task | ✅ |
| Kernel memory read from ring 3 | `ring3_smoke` SpawnKernelReadProbeTask | SMAP / #PF kills task | ✅ |
| Wild-pointer read fuzz | `ring3_smoke` SpawnPtrFuzzProbeTask | #PF kills task | ✅ |
| Wild-pointer write fuzz | `ring3_smoke` SpawnWriteFuzzProbeTask | #PF kills task | ✅ |
| Hardware breakpoint injection | `ring3_smoke` SpawnBpProbeTask | per-task DR + kCapDebug gate | ✅ |
| CPU-burn DoS | `ring3_smoke` SpawnCpuHogProbe | scheduler tick-budget kill | ✅ |
| Voluntary cap drop + retry | `ring3_smoke` SpawnDropcapsProbe | dropped op denied after SYS_DROPCAPS | ✅ |
| Image-load malware (W+X PE / suspicious imports) | `kernel/security/guard.cpp` (image vetting on every load) | Guard verdict Allow/Warn/Deny | ✅ |
| Cross-process WriteProcessMemory | `ring3_smoke` SpawnCrossPidProbe + handler in syscall.cpp `SYS_PROCESS_VM_WRITE` (cap-gated on `kCapDebug`) | sandbox without kCapDebug: kCapDebug denial → 100-deny threshold reap | ✅ (gate-side; per-target ACL deferred) |
| Thread hijack (Suspend / SetContext / Resume) | handler `SYS_THREAD_SET_CONTEXT` cap-gated on `kCapDebug`; foreign-thread handle table requires SYS_PROCESS_OPEN (also `kCapDebug`) so SUSPEND/RESUME are gated by-construction | sandbox cannot reach a foreign thread handle | ✅ (gate-side; per-target ACL deferred) |
| Foreign-process DR set | SYS_BP_INSTALL is scoped to caller-only by construction (per-task DR save/restore on context switch); cap-gated on `kCapDebug` | sandbox without kCapDebug denied at gate; even with kCapDebug, BP only rides caller's task | ✅ |
| Classic DLL injection (CreateRemoteThread + LoadLibrary) | NtCreateThreadEx → SYS_THREAD_CREATE; thread spawned in CALLER's AS, not foreign — true cross-process injection requires SYS_THREAD_CREATE_REMOTE which is `kSysNtNotImpl` | by-construction caller-only | ⚠️ partial (NtCreateThreadEx hits same-process create; remote-thread variant deferred) |
| Process hollowing | NtMapViewOfSection / NtUnmapViewOfSection (SYS_SECTION_MAP / SYS_SECTION_UNMAP) — cross-AS map gated on `kCapDebug` (see syscall.cpp cap check inside SYS_SECTION_MAP) | sandbox without kCapDebug denied at gate | ✅ (gate-side) |
| Reflective DLL load | `ring3_smoke` SpawnNxProbeTask (jump into RW page) + `mm::AddressSpaceMapUserPage` W^X gate panics on RWX map + `subsystems::linux::DoMprotect` is advisory (no PTE flip) | NX trap kills task; W^X gate prevents RWX mapping; mprotect can't grant exec to writable | ✅ |
| Keylogger | `kCapInput` cap (process.h:147) gates SYS_WIN_GET_KEYSTATE / SYS_WIN_GET_CURSOR / SYS_WIN_GET_MOUSE_DELTA / SYS_STDIN_READ via cap_table.def | sandbox profile lacks kCapInput → denial | ✅ |
| Screen scraper | by-construction: no user-mode syscall exposes raw framebuffer pixels (Screenshot is in-kernel app only); cross-process VM read gated on kCapDebug | no surface to read others' rendered windows | ✅ (by-construction; document; add kCapFramebuffer later if a SYS_FB_READ ever lands) |
| RAT (network bind / reverse shell) | `kCapNet` cap (process.h:129) gates SYS_SOCKET_OP via cap_table.def | sandbox profile lacks kCapNet → denial | ✅ |
| Ransomware (mass FS encrypt) | `attack_sim` × 3 (burst-tier, low-and-slow sustained-tier, canary-touch) + multi-window per-process write-rate guard (1 s / 5 min / 1 h tiers) hooked into Win32 SYS_FILE_WRITE/CREATE + Linux sys_write / copy_file_range; canary / suspicious-extension wall hooked into Win32 + Linux create / unlink / rename / openat-O_CREAT | `MassFsWriteRate{,Sustained,Long}` + `CanaryFileTouched` findings + `FlagCurrentForKill(FsWriteRateExceeded \| CanaryFileTouched)` | ✅ |
| Persistence drop (autostart, fake driver) | `attack_sim` AttackPersistenceDrop + `kernel/security/canary.cpp` PersistenceCheck wired into Win32 + Linux create / unlink / rename / openat-O_CREAT (autostart-equivalent path registry: /etc/init.d/, /.duetos/autostart/, registry Run keys, boot.ini) + image-load vetting via guard.cpp on next boot | `PersistenceDropDetected` HealthIssue (Advisory: log+counter; Deny: kill via `KillReason::PersistenceDrop`) | ✅ |
| Anti-analysis (timing, VM detection) | — | informational only — measurement, not a defence | n/a |

## Gap analysis — what's still open

### 1. Per-target ACL for kCapDebug holders

**Status:** Gates are correct (sandbox without kCapDebug cannot
reach SYS_PROCESS_OPEN / VM_WRITE / SECTION_MAP /
THREAD_SET_CONTEXT). What's still missing is a per-target ACL
once a process HAS kCapDebug — it can currently open ANY pid.

**To fix:**
- Add a per-Process `debug_target_acl` (a small list of pid
  prefixes / explicit pids the holder may target).
- Check at SYS_PROCESS_OPEN.
- Realistic scope: ~120 LOC + 1 probe.

### 2. Heap pool corruption / IRQ storm / Task stack overflow

**Status:** Detectors all live; what's missing is non-self-bricking
attack drivers.

**To fix (heap):** Allocate a scratch heap pool, scribble its
header, run scan, restore. Needs a `HeapCreatePool` API the
allocator doesn't have today.

**To fix (IRQ storm):** Issue `int $vec` × N from a kernel
context, but FIRST snapshot per-vector counters and restore
afterwards so the periodic scan's monotonic guards don't fire
spuriously.

**To fix (task stack):** Pick a non-running task, scribble its
bottom canary, run scan, restore. Needs a scheduler-quiesce
primitive that doesn't yet exist.

### 3. Reflective DLL — variant test

**Status:** ✅ via NX probe + W^X gate + advisory mprotect (no
PTE flip in v0). A determined attacker who finds a future PTE-
flipping VirtualProtect implementation would re-open this; for
now it's structurally closed.

### 4. NtCreateThreadEx remote variant

**Status:** ⚠️ partial — same-process create works (and is
properly cap-gated); a remote-thread variant where the new
thread starts in a foreign Process's AS is `kSysNtNotImpl`.
Closing it would let a probe verify that even with kCapDebug,
the per-target ACL (item 1) gates remote thread injection.

### 5. Coordinated multi-process FS write attack

**Status:** Per-process rate caps are tight; a fork-bomb that
spawns N processes each staying just under the cap is not
covered. Needs a global rate counter + a fork-rate detector.
Estimated ~250 LOC.

### 6. Future: random per-boot kernel-internal canary symbol

**Status:** v1 randomized 4 dynamic canary FILE names per boot.
The kernel's static `kCanaryPaths[]` registry is still source-
readable. v2 idea: compress the static list into a hash table
hashed under the per-boot salt so even reading the kernel
binary doesn't disclose the hash inputs. Out of scope today.

## Wiring summary

- `kernel/security/attack_sim.cpp` — 16 in-suite kernel attacks
  (canary + persistence + stack-canary + ransomware-burst +
  ransomware-low-and-slow + 11 v0 attacks); deferred attacks
  for heap / IRQ storm / task stack documented inline.
- `kernel/security/canary.cpp` — canary path wall + per-boot
  salt + persistence-drop detector. Wired into Win32 routing
  (CreateForProcess / UnlinkForProcess / RenameForProcess /
  WriteForProcess via handle is_canary) + Linux paths
  (DoUnlink / DoRename / DoOpen O_CREAT / DoWrite via fd
  kLinuxFdFlagCanary).
- `kernel/proc/ring3_smoke.cpp` — 12 ring-3 hostile probes
  (added: cross-pid SYS_PROCESS_OPEN flood); dispatched via
  `redteam` / `ring3` shell commands + boot smoke list.
- `kernel/diag/runtime_checker.cpp` — ~28 `HealthIssue`
  detectors, scanned every 5 s + on demand via
  `RuntimeCheckerScan()`. New: `MassFsWriteRateSustained`,
  `MassFsWriteRateLong`, `CanaryFileTouched`,
  `PersistenceDropDetected`. New helper:
  `RuntimeCheckerBumpIssueCounter_ForTest` for attack_sim
  bypass of Panic-class response.
- `kernel/security/guard.cpp` — image-load vetting (W+X,
  suspicious imports, packer entropy).
- `kernel/security/pentest_gui.cpp` — operator-facing GUI for
  running the suites with verdicts
