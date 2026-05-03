# Kernel-mode attacker simulation suite — v1

**Type:** Observation + Pattern
**Status:** Active
**Last updated:** 2026-04-26

## What it is

In-kernel red-team gauntlet that mounts attacks a rootkit / kernel-level
malware would attempt and verifies the runtime invariant checker
(`kernel/diag/runtime_checker.cpp`) catches each one. Lives in
`kernel/security/attack_sim.cpp`. Two trigger paths:

- **Boot-time:** `kernel_main` calls `AttackSimRun()` if the kernel was
  built with `-DDUETOS_ATTACK_SIM`. Off in normal builds because each
  finding escalates `Guard` to `Enforce` and the block-write guard to
  `Deny`, which would poison the rest of the boot.
- **On-demand:** `attacksim` / `redteam` shell command
  (`kernel/core/shell.cpp:6440`) runs the same suite from an
  interactive shell so the operator can choose when to trip the
  escalations.

## Per-attack contract

Each attack follows the same five-step recipe (`RunAttack`):

1. **Precheck** (optional) — refuses on a CPU that never had the feature.
   Ex: SMEP attack precheck is `(CR4 & SMEP_BIT) != 0`. Failed precheck
   reports `Skipped`, not `FailNoDetect`.
2. **Snapshot** — record the pre-attack state (MSR value, byte at the
   patched address, etc.) for restore.
3. **Attack** — perform the malicious operation.
4. **Force scan** — call `RuntimeCheckerScan()` directly so detection
   doesn't wait for the next 5-second heartbeat.
5. **Verify + restore** — read the per-issue counter, compare to
   pre-attack baseline, restore the world. A second post-restore scan
   prevents the next attack inheriting a still-pending detection.

## Suite inventory (11 active + 5 deferred)

| # | Attack | Detector that fires | Notes |
|---|---|---|---|
| 1 | Bootkit LBA 0 write | `BootSectorModified` | MUST run first — other findings escalate blockguard to Deny, which would refuse the bootkit's write |
| 2 | IDT vector 0 hijack | `IdtModified` | Single-byte XOR on the live IDT |
| 3 | GDT slot 0 (null desc) scribble | `GdtModified` | Null descriptor is never loaded — safe to corrupt |
| 4 | LSTAR syscall hook | `SyscallMsrHijacked` | Classic rootkit MSR overwrite |
| 5 | SYSENTER_CS hook | `SyscallMsrHijacked` | Legacy 32-bit syscall path; DuetOS uses SYSCALL so safe to scramble |
| 6 | SYSENTER_EIP hook | `SyscallMsrHijacked` | Same — legacy path, no functional impact |
| 7 | CR0.WP defang (W^X bypass) | `Cr0WpCleared` | Auto-healed by `HealControlRegisters` |
| 8 | CR4.SMEP defang (ret2usr enable) | `Cr4SmepCleared` | Skipped if CPU lacks SMEP |
| 9 | CR4.SMAP defang (user-mem read) | `Cr4SmapCleared` | Skipped if CPU lacks SMAP |
| 10 | EFER.NXE defang (data exec) | `EferNxeCleared` | Auto-healed |
| 11 | Kernel `.text` 1-byte patch | `KernelTextModified` | IRQ-off + CR0.WP toggle bracket the write window. Patches `_text_start + 0x40` (dormant boot stub) |
| 17 | Function-branch NOP patch (cap-gate bypass) | `KernelTextModified` | Patches a 2-byte `je` inside a synthetic cap-style gate to `90 90`. Lives in middle `.text` (716 KiB into a 1.14 MiB section). Originally surfaced a detection gap (spot hash blind to mid-section); same slice closed the gap by adding `g_baseline_text_full_hash` + `ComputeTextFullHash` to `runtime_checker.cpp`. Now reports `Pass` with serial-log line `[health] kernel text drift: FULL-only …`. See `branch-nop-attack-v0.md`. |

**Deferred (each needs its own slice):**

- *STAR / CSTAR scrambling* — STAR holds the CS:SS pair SYSCALL/SYSRET
  reads on every entry/exit. Scrambling it crashes the next user-mode
  return before the runtime-checker scan can fire. Needs a synthetic
  bracketed harness that masks IRQs, performs no syscalls, restores,
  then unmasks.
- *Stack canary defang* — zeroing `__stack_chk_guard` self-bricks the
  live kernel; needs a `no_stack_protector` island around the whole
  snapshot/scan path.
- *IA32_FEATURE_CONTROL unlock* — locked MSR refuses the clear write
  (#GP); on unlocked firmware the detector also doesn't check, so the
  slot is meaningless either way.
- *IRQ storm* — needs >25 000 software interrupts into a real handler
  inside one scan window. Doable with `int $vec` × N but pollutes IRQ
  statistics for the rest of boot until the suite gains a
  reset-baselines hook.
- *Heap pool mismatch / underflow* — corrupts kernel allocator
  bookkeeping; clean restore needs a dedicated scratch heap.
- *Task stack overflow / RSP out of range* — needs to scribble a
  non-running task's saved-rsp without racing the scheduler. Wants a
  scheduler-quiesce primitive that doesn't yet exist.

## Pattern: why CR-defang attacks need no manual restore

`CheckControlRegisters` and `HealControlRegisters` (runtime_checker.cpp
~line 329) re-assert every baseline-set bit on every scan. So the
RunAttack flow:

```
attack()             ; CR0 &= ~WP    (bit cleared)
RuntimeCheckerScan() ; detector fires → AttemptHeal → CR0 |= WP
restore()            ; CR0 |= WP   (idempotent — already set)
```

The Restore in attack_sim is a safety net for the case where the
checker decides not to heal (policy quirk or future regression). Useful
defensive programming; not load-bearing for correctness.

## Pattern: kernel `.text` byte patch

The riskiest attack — writing inside the kernel's RX `.text` section.

```
cli
cr0 = ReadCr0(); WriteCr0(cr0 & ~WP)   ; briefly writable
*(_text_start + 0x40) ^= 0xFF
WriteCr0(cr0)                           ; back to RX
sti (only if rflags.IF was set)
```

`_text_start + 0x40` lands inside the multiboot2 entry stub / 32→64
transition code — runs once at boot and stays dormant for the rest of
the session. A one-byte XOR there can't crash a live execution path.
The IRQ-off bracket is for safety: an interrupt handler that fired
during the WP-clear window could exploit the briefly-writable kernel
text.

## Wiring

- `kernel/security/attack_sim.cpp` — suite implementation
- `kernel/security/attack_sim.h` — public `AttackSimRun()` /
  `AttackSimSummary()`
- `kernel/core/main.cpp` — boot-time invocation under
  `DUETOS_ATTACK_SIM`
- `kernel/core/shell.cpp` — `attacksim` / `redteam` shell command
- `kernel/diag/runtime_checker.{cpp,h}` — detectors + per-issue
  counters + `RuntimeCheckerScan()`
