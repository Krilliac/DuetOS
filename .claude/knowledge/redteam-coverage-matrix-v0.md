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
| Stack canary defang | — | `StackCanaryZero` | ⏸ self-bricks — needs no-stack-protector island |
| IA32_FEATURE_CONTROL unlock | — | `FeatureControlUnlocked` | ⏸ locked MSR refuses write; un-triggerable on locked firmware |
| Kernel heap pool corruption | — | `HeapPoolMismatch` / `HeapUnderflow` | ⏸ corrupts allocator bookkeeping; needs scratch heap |
| IRQ storm DoS | — | `IrqStorm` | ⏸ needs >25k software ints; pollutes IRQ stats |
| Task stack overflow / saved-rsp scribble | — | `TaskStackOverflow` / `TaskRspOutOfRange` | ⏸ needs scheduler-quiesce primitive |
| Cross-process VM read/write | — | (none — would need new detector) | ❌ no kernel-side probe yet; user-mode path needs unimplemented NT syscalls |

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
| Cross-process WriteProcessMemory | — | NT syscalls not implemented (NtWriteVirtualMemory→SYS_WRITE collision; NtOpenProcess kSysNtNotImpl) | ❌ |
| Thread hijack (Suspend / SetContext / Resume) | — | NtSuspendThread / NtSetContextThread kSysNtNotImpl | ❌ |
| Foreign-process DR set | — | needs ring-3 DR setter that targets *another* PID | ❌ |
| Classic DLL injection (CreateRemoteThread + LoadLibrary) | — | NtCreateThreadEx kSysNtNotImpl | ❌ |
| Process hollowing | — | NtMapViewOfSection / NtUnmapViewOfSection kSysNtNotImpl | ❌ |
| Reflective DLL load | — | needs in-process VirtualAlloc(RWX) — would hit NX gate; doable as a self-inject probe | ⚠️ partial (NX probe covers exec-from-RW) |
| Keylogger | — | no `kCapInput` exists; kbd input not capability-gated | ❌ |
| Screen scraper | — | no `kCapFramebuffer` exists; FB not capability-gated | ❌ |
| RAT (network bind / reverse shell) | — | no `kCapNet` exists; sockets not capability-gated | ❌ |
| Ransomware (mass FS encrypt) | — | no FS write-rate detector; no in-kernel crypto exposed to userland | ❌ |
| Persistence drop (autostart, fake driver) | ⚠️ partial via `kernel/security/guard.cpp` import-blacklist on load | per-image vetting on next boot | ⚠️ |
| Anti-analysis (timing, VM detection) | — | informational only — measurement, not a defence | n/a |

## Gap analysis — what each ❌ needs

### 1. Cross-process tampering (WPM / thread hijack / hollowing)

**Blocker:** `NtOpenProcess`, `NtWriteVirtualMemory` (mis-mapped to
SYS_WRITE), `NtSuspendThread`, `NtSetContextThread`, `NtGetContextThread`,
`NtCreateThreadEx`, `NtMapViewOfSection`, `NtUnmapViewOfSection` are
all `kSysNtNotImpl`.

**To fix:**
- Implement these NT syscalls against the existing Process / handle
  table (kernel/proc/process.{h,cpp}). Each needs a capability check
  (e.g. `kCapDebug` for cross-process VM access) and a per-target
  ACL.
- Then add ring-3 PE payloads under `userland/apps/redteam/` that
  attempt each technique; pass = denial / kill.
- Realistic scope: ~6 syscalls × ~80 LOC each + 4 PE payloads.
  One PR per syscall family.

### 2. Keylogger / Screen scraper / RAT

**Blocker:** No capability framework for input devices, framebuffer,
or network sockets. Currently any user process that can syscall can
read kbd / fb / open sockets.

**To fix:**
- Add `kCapInput`, `kCapFramebuffer`, `kCapNet` to
  `kernel/proc/process.h`.
- Gate the relevant syscalls (kbd-read, fb-mmap, socket creation)
  on the new caps.
- Update `CapSetTrusted()` and `CapSetEmpty()` defaults.
- Update existing apps that legitimately use these surfaces to
  request the cap.
- Then add ring-3 probes that try the operations without the cap.
- Realistic scope: ~3 caps + ~10 syscall touch-ups + 3 probes.
  Cross-cutting; needs careful sequencing to avoid breaking
  existing apps.

### 3. Ransomware (mass FS encrypt)

**Blocker:** No FS-write-rate detector, and no policy for "this
process just wrote 1 GiB in 5 seconds — kill it."

**To fix:**
- Add a per-process FS write-rate counter to
  `core::Process` and a `MassFsWriteRate` `HealthIssue`.
- Gate the response on a configurable threshold (Advisory =
  log; Enforce = kill task).
- The ransomware probe can then be a synthetic in-sandbox flood
  (no real crypto needed — the test is the rate, not the algorithm).
- Realistic scope: ~150 LOC across runtime_checker + process +
  ring3_smoke. Self-contained.

### 4. Persistence

**Partial today:** `guard.cpp` checks every image at load time and
can deny based on signature / import / entropy. So a persisted
malicious image that re-runs at next boot would be caught **if**
guard is in Enforce mode.

**Gaps:** No detection of *how* the persistence was achieved — i.e.
which write to which path planted the autostart file.

**To fix:**
- Add path-write tracking in VFS for paths that are autostart-
  equivalent (init scripts, registry-equivalent under DuetOS).
- Add a `PersistenceDropDetected` `HealthIssue`.
- Realistic scope: ~80 LOC. Low risk.

## Recommended slice order

If the user wants to keep extending coverage, the cheapest →
most-expensive order is:

1. **Stack canary defang** (deferred kernel attack) — adds the last
   easy-to-test detector. Needs a no-stack-protector island (~50 LOC).
2. **FS write-rate detector + ransomware probe** — self-contained,
   one new detector + one new ring-3 probe (~150 LOC).
3. **Persistence path-write tracking + drop probe** — adds
   `PersistenceDropDetected` (~80 LOC).
4. **Capability framework expansion** (kCapInput / kCapFramebuffer /
   kCapNet) + 3 ring-3 probes — cross-cutting, needs care
   (~400 LOC across kernel + apps).
5. **Implement the 6 cross-process NT syscalls** — biggest lift, but
   unlocks the entire "Windows malware threat model" set
   (~500 LOC + 4 PE payloads).
6. **Heap / IRQ storm / task stack** kernel attacks — each needs
   bespoke quiesce / scratch state (~200 LOC each).

## Wiring summary

- `kernel/security/attack_sim.cpp` — 11 in-suite kernel attacks
  (5 deferred, documented inline)
- `kernel/proc/ring3_smoke.cpp` — 11 ring-3 hostile probes,
  dispatched via `redteam` shell command + boot smoke list
- `kernel/diag/runtime_checker.cpp` — ~25 `HealthIssue` detectors,
  scanned every 5 s + on demand via `RuntimeCheckerScan()`
- `kernel/security/guard.cpp` — image-load vetting (W+X, suspicious
  imports, packer entropy)
- `kernel/security/pentest_gui.cpp` — operator-facing GUI for
  running the suites with verdicts
