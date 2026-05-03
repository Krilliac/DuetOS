# KPTI / Meltdown — settled non-implementation decision

**Type**: Decision
**Status**: Settled — **closed question**, not deferred. Trigger
conditions for re-opening recorded below.
**Last updated**: 2026-05-03 (graduated from `kpti-meltdown-investigation-v0.md`).

## Decision

**DuetOS does not implement Kernel Page Table Isolation, by
design**, on the hardware the project actually targets.

This is not a "we'll get to it" deferral. It's a settled answer
that survives until one of the documented trigger conditions
fires. The wording matters: an investigation doc invites
re-derivation each session; a decision doc tells future sessions
"the question is closed unless evidence X surfaces."

## Why not

The Meltdown attack only retires on CPUs whose
`IA32_ARCH_CAPABILITIES.RDCL_NO` bit is **clear**. Every CPU
DuetOS targets per `hardware-target-matrix.md` reports
`RDCL_NO=1` in silicon:

| Vendor | Generation | RDCL_NO |
|--------|------------|---------|
| Intel | Cascade Lake (2019) and later — Ice Lake, Tiger Lake, Alder Lake, Sapphire Rapids, Raptor Lake | 1 |
| AMD | Zen 1 (2017) and later — Zen+, Zen 2, Zen 3, Zen 4 | 1 |

KPTI was Linux's response to a hardware bug Intel admitted in
January 2018 and fixed in silicon by late 2019. It is a workaround
for **specific older parts**. On the platforms this kernel runs
on, KPTI imposes a 5–30 % syscall cost while mitigating an attack
the hardware already prevents.

## What this kernel does instead

1. **Probe the silicon at boot.** `kernel/arch/x86_64/cpu_mitigations.cpp`
   reads `CPUID(7).EDX[29]` to confirm `IA32_ARCH_CAPABILITIES`
   exists, then reads MSR `0x10A`, then exposes the result via
   `arch::CpuMitigationsGet().needs_kpti` for any future code
   that wants to gate on it.

2. **Surface the result on serial.** A compact one-liner reports
   the boolean per-class state of every mitigation
   (`kpti=safe|needed mds=… ssbd=… taa=…`). Anyone running on a
   pre-2019 Intel or pre-Zen part sees `kpti=needed` immediately.

3. **Refuse to be silent on a vulnerable CPU.** When
   `needs_kpti=true` the probe emits an 8-line ASCII-banner WARN
   block on serial spelling out that the kernel does NOT
   implement KPTI and the operator should not run untrusted
   binaries on that hardware. This is the v0 substitute for
   "actually mitigate." A future session that fires the trigger
   below replaces the WARN with a real implementation.

What this kernel **does not** do, on purpose:

- Maintain a second per-process PML4 with only trampolines
  mapped (the user-only view).
- Swap CR3 on syscall entry / IRQ entry / SYSRET.
- Move the IST stacks into the trampoline page.
- Drive a TLB-shootdown ordering pass that's KPTI-aware.

## Re-open triggers (commit-back to investigation when ANY fires)

1. **Hardware**: a pre-Cascade-Lake Intel or pre-Zen AMD machine
   enters the test fleet (`hardware-target-matrix.md` Tier 1+).
2. **Workload**: a hosting model lands that runs untrusted
   ring-3 code from another tenant on the same kernel — a
   public multi-tenant deployment, a pluggable browser sandbox
   that elects to share an address space, etc.
3. **Spec change**: a new attack class in the Meltdown family
   surfaces that retires even with `RDCL_NO=1` set, OR Linux
   upstream changes its `pti=auto` default in a way that
   surfaces a new mitigation we'd want to mirror.

If any trigger fires, the implementation reference is well-
trodden: `arch/x86/mm/pti.c` in Linux + the Phoronix PTI deep-dive
(both public). Before landing, gate on B2 (real SMP) since the
mitigation interacts with TLB shootdown ordering in a way that's
only verifiable once multi-core is live.

## Why the runtime probe stays even though the mitigation doesn't

The probe is the cheapest possible "did the world change"
detector. A future maintainer who plugs in a Skylake server
gets a one-line boot signal that the assumption underpinning
this decision no longer holds. Without the probe, the question
re-opens silently on the wrong hardware.

## What this entry replaces

- The original "investigation v0" doc that recorded an open
  question with a recommendation. The recommendation
  ("land the runtime check first") is in tree as
  `kernel/arch/x86_64/cpu_mitigations.{h,cpp}`. The question
  itself is closed.
- Plan item E2 in the original kernel-debug-recommendations
  plan (closed 2026-04-28).
- Plan item E2-followup ("Enable KPTI / Meltdown mitigation") in
  `post-debug-recommendations-plan.md` — graduated to this
  settled decision rather than left as a pending follow-on.

## See also

- `kernel/arch/x86_64/cpu_mitigations.cpp` — the silicon probe +
  the loud WARN block when `needs_kpti=true`.
- `hardware-target-matrix.md` — the hardware tier this decision
  rests on.
- `sandbox-overview-v0.md` — the implemented walls (W^X, SMEP /
  SMAP / NX, ASLR, KASLR, capability gates) that DO mitigate
  ring-3 → ring-0 escape on the hardware we target.
