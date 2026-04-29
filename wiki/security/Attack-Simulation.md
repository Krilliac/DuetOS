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

11 attacks are wired up today (per
`.claude/knowledge/attack-sim-kernel-v1.md`):

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
11. **(plus one more, see knowledge file)**

Each attack is paired with a detector. A regression that lets the
attack succeed without the detector firing is a hard boot panic.

## Pentest Suite (Ring 3 Adversarial)

`kernel/security/pentest/` runs ring-3 probes that a malicious user
process might attempt:

- **`jail`** — attempt to escape the per-process VFS root
- **`nx`** — attempt to execute on an NX page
- **`priv`** — attempt a privileged syscall without the cap
- **`badint`** — issue an unmapped interrupt vector
- **`kread`** — attempt to read kernel memory from ring 3 (SMAP)

See `.claude/knowledge/pentest-ring3-adversarial-v0.md`.

## Redteam Coverage Matrix

`.claude/knowledge/redteam-coverage-matrix-v0.md` is the full
malware-technique map vs. existing probes / attacks / detectors,
with gap analysis and a slice-order roadmap. It is the document that
answers "is this attack class covered?"

## Related Pages

- [W^X / NX Enforcement](WX-Enforcement.md)
- [Sandboxing](Sandboxing.md)
- [Capabilities](Capabilities.md)
- [Runtime Recovery Strategy](Runtime-Recovery.md)
- [Malware Hard-Stop Plan](Malware-Hard-Stop-Plan.md)
