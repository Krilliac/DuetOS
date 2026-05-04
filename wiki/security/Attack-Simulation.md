# Attack Simulation

> **Audience:** Security folks, kernel hackers
>
> **Execution context:** Kernel — boot-time probes + on-demand shell commands
>
> **Maturity:** v1 — 11 active attacks; deferred catalogue tracked

## Overview

DuetOS runs an in-kernel attacker simulation suite at boot to verify
that every defensive control still works. Attacks are **categorised
adversarial probes**: each attack tries one specific subversion (e.g.
patch the IDT, clear CR0.WP, write to `.text`), and the corresponding
detector / panic / refusal is the pass condition.

## Files

- `kernel/security/attack_sim/` — the attack suite
- `kernel/security/pentest/` — pentest probes (ring 3 adversarial)
- `kernel/security/redteam/` — coverage matrix + slice-order roadmap

## Active Attacks (v1)

20 attacks are wired up today:

1. **Bootkit-style boot-vector overwrite**
2. **IDT entry overwrite** (try to redirect a vector)
3. **GDT entry overwrite**
4. **LSTAR (syscall entry) overwrite**
5. **SYSENTER_CS / SYSENTER_EIP overwrite**
6. **CR0.WP clear** (re-enable kernel-write-to-RO)
7. **SMEP disable** (CR4.SMEP)
8. **SMAP disable** (CR4.SMAP)
9. **NXE disable** (EFER.NXE)
10. **`.text` patch** (write into `.text` segment)
11. **Ransom-burst** — multi-window FS-write rate guard
12. **Ransom low-and-slow** — long-window cap + canary-path detector
13. **Stack canary defang** — corrupt the canary, verify panic
14. **Persistence drop** — write to autostart-path registry
15. **Function-branch NOP attack** — patch a `je` to `90 90`,
    verify the spot + full `.text` hash both fire
16. **Function-pointer table overwrite** — replace dispatch entry
17. **Saved-RIP smash** — overwrite a frame's RIP slot
18. **PTE W^X flip** — flip page-table entry from RO to RW+X
19. **Canary-touch** — direct write to a canary file path
20. **Cross-PID** — spawn from one process, attack another

Each attack is paired with a detector. A regression that lets the
attack succeed without the detector firing is a hard boot panic.

The attack suite is wrapped by the **purple-team coverage scorecard**
which snapshots the security event ring before the suite runs and
again after, computes coverage % and runbooks-emitted count, and
publishes a single summary entry. This replaces direct `AttackSimRun`
calls in the `DUETOS_ATTACK_SIM` path.

## Pentest Suite (Ring 3 Adversarial)

`kernel/security/pentest/` runs ring-3 probes that a malicious user
process might attempt:

- **`jail`** — attempt to escape the per-process VFS root
- **`nx`** — attempt to execute on an NX page
- **`priv`** — attempt a privileged syscall without the cap
- **`badint`** — issue an unmapped interrupt vector
- **`kread`** — attempt to read kernel memory from ring 3 (SMAP)
- **`crosspid`** — verify cross-PID gate denial

## Security Team Colours — DuetOS Map

| Team | Colour | Surface |
|------|--------|---------|
| **Red** | Adversarial | `attack_sim/` + `pentest/` probes |
| **Blue** | Detection | 256-entry security event ring (27 EventKinds) |
| **Yellow** | Builder | Capability-gated syscall surface |
| **Purple** | Coverage | Scorecard wrapping AttackSimRun with event-ring snapshot brackets |
| **Green** | Hardening | W^X / SMEP / SMAP / NX / KASLR / CFI / FS write-rate guard |
| **Orange** | Education | Boot self-tests + IR runbook |
| **White** | Policy | Default / Lab / Production / Forensic profiles compose Guard / Persistence / Blockguard modes atomically (`policy show / set / diff` shell command) |

The IR runbook publishes per-EventKind follow-up guidance (summary +
steps + escalation, 20 entries) back to the event ring. A boot-time
self-test enforces coverage so every EventKind has a runbook
entry.

## FS-Write Rate Guard + Canary Wall

A v1 ransomware defence layered above `SYS_FILE_*`:

- **Multi-window byte caps**: 1 s / 5 min / 1 h tiers; a process
  exceeding any tier is killed with `KillReason::FsWriteRate*`.
- **Canary path / suspicious-extension wall**: per-boot dynamic
  canary salt; touching a canary-path file or writing a known-bad
  extension (`.locked`, `.encrypted`, `.crypt`) trips the wall.
- **Persistence-drop detector**: writes to autostart-path registry
  fire `EventKind::PersistenceDrop`.
- **Handle-stamped `is_canary`**: Win32 + Linux fd handles carry the
  flag so a process can't reopen a canary by handle to bypass the
  path check.

Wired into Win32 `SYS_FILE_{WRITE,CREATE}` and Linux
`sys_write / copy_file_range / unlink / rename / openat-O_CREAT`.

## Related Pages

- [W^X / NX Enforcement](WX-Enforcement.md)
- [Sandboxing](Sandboxing.md)
- [Capabilities](Capabilities.md)
- [Runtime Recovery Strategy](Runtime-Recovery.md)
- [Malware Hard-Stop Plan](Malware-Hard-Stop-Plan.md)
