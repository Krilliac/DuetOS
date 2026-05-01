# KPTI / Meltdown — mitigation-status investigation v0

**Type**: Decision + Observation
**Status**: Active — answer recorded, implementation deferred
**Last updated**: 2026-04-27

## Question

The kernel & debug recommendations plan (item E2) asked whether DuetOS
is mitigated against Meltdown (CVE-2017-5754). Goal of this entry: a
yes/no + one-paragraph justification. If yes, no further work; if no,
plan E2 lands a runtime check + a real implementation gated on it.

## Answer

**No — the running kernel is not Meltdown-mitigated.**

The threat is only relevant on CPUs that lack the in-silicon
`RDCL_NO` bit (`IA32_ARCH_CAPABILITIES[0]`). Every Intel core from
Cascade Lake forward (Ice Lake, Tiger Lake, Alder Lake, Sapphire
Rapids, Raptor Lake), and every AMD core from Zen onward, sets
`RDCL_NO` and is inherently safe. So in practice "the kernel is
unmitigated" is only a real bug on pre-2019 Intel client CPUs and
the Skylake / Kaby Lake / Coffee Lake server SKUs that shipped
without the silicon fix.

## Evidence (read in sequence)

1. **Address-space construction shares kernel-half PTEs across every
   process.** `kernel/mm/address_space.h:9-18`:

   > An `AddressSpace` owns a PML4 frame and the user-half (PML4
   > entries 0..255) page-table tree underneath it. The kernel half
   > (entries 256..511) is shared across every address space — at
   > create time we copy the boot PML4's kernel-half entries
   > verbatim, so the new PML4 points at the same PDPTs the
   > kernel-half is built on.

   That copying is exactly what Meltdown exploits: a ring-3
   `mov rax, [kernel_va]` triggers a #PF before the load retires,
   but the speculatively-loaded byte is observable through a
   side-channel cache probe BECAUSE the kernel mapping is present
   in the user PML4 (with `kPagePresent` set, just `kPageUser`
   clear). KPTI is the workaround: maintain a stripped-down user
   PML4 with only the trampolines mapped, swap to the full kernel
   PML4 on syscall entry.

2. **No `RDCL_NO` check anywhere in the tree.** `git grep -nE
   "RDCL_NO|ARCH_CAPABILITIES|IA32_ARCH_CAP"` returns no hits.
   The CPU-features layer (`kernel/arch/x86_64/cpu_info.cpp`)
   doesn't read the `IA32_ARCH_CAPABILITIES` MSR (CPUID(7).EDX bit
   29 indicates whether the MSR exists). The runtime invariant
   checker confirms SMEP / SMAP / NXE — none of those are
   Meltdown-relevant.

3. **No second PML4 per process.** `AddressSpace` (one PML4 per
   process) is the only structure of its kind in `kernel/mm/`.
   `git grep -nE "user_pml4|kernel_pml4|trampoline_pml4"` returns
   no hits. The dispatcher's switch path is "swap CR3 to the new
   AS" with no second swap to a kernel-only view.

4. **The Win32 / Linux subsystems don't bypass this** — they go
   through `mm::AddressSpace*` for every mapping, so they inherit
   whatever Meltdown posture the AS layer has, which is "none".

## Why it's deferred, not actively bad today

- **Hardware tier**: the project's stated minimum target (commodity
  PC hardware from the last several years — see CLAUDE.md "First
  pillars") is a Tiger Lake / Zen 3 era machine. Both have
  `RDCL_NO` set in silicon. The Meltdown attack does not retire on
  these CPUs; the mitigation is a pure cost when it would
  otherwise add ~5–30 % syscall overhead.
- **Bring-up phase**: KPTI is a substantial paging-layer change
  (per-process kernel-only PML4, trampoline-only user PML4,
  IDT/syscall stubs that swap CR3 on entry/exit, IST stack-switch
  rules updated). Landing it before SMP (B2) is real would be
  premature — the mitigation interacts with TLB shootdown ordering
  in a way that's only verifiable once multi-core is exercised.
- **Cost vs benefit**: a runtime check that probes
  `IA32_ARCH_CAPABILITIES.RDCL_NO` and conditionally enables KPTI
  is the right shape (Linux's `pti=auto` behaves this way). Until
  there's a concrete machine in the test fleet that lacks the
  silicon bit, the check would be a no-op everywhere it ran.

## Recommendation

1. **Land the runtime check first** (a separate slice; ~50 lines):
   read CPUID(7).EDX bit 29 to confirm `IA32_ARCH_CAPABILITIES`
   exists, then read MSR 0x10A bit 0 (`RDCL_NO`). Surface as
   `arch::CpuMitigations::needs_kpti` so future work can branch
   on it. Boot-log line: `[cpu] RDCL_NO=1: Meltdown not required`
   or `[cpu] RDCL_NO=0: Meltdown mitigation needed (NOT IMPLEMENTED)`.
2. **Implement KPTI only if a needs-kpti machine enters the test
   fleet** — the design is well-documented (Linux `arch/x86/mm/pti.c`
   + Phoronix PTI deep-dive are the canonical references), but
   landing it speculatively risks regressions on the SMP work and
   the sandbox / W^X / address-space audit tooling.

The plan E2 verification step asks for "a Meltdown-style test (try
to read kernel memory speculatively from ring 3) and confirm it
fails post-mitigation" — that test makes sense only after step 2.
On a `RDCL_NO=1` CPU it would always pass with no mitigation in
place because the silicon kills the speculative load before its
side effect is observable.

## What this entry replaces

Plan item E2 in the original kernel-debug-recommendations plan
(closed 2026-04-28; remaining follow-ons live in
`.claude/knowledge/post-debug-recommendations-plan.md` as
E2-followup). The investigation produced a defensible
"no, deferred" answer with a clear trigger condition for
re-evaluation. Future sessions can read this file instead of
re-deriving the same evidence chain.

## When to revisit

- A pre-Cascade-Lake / pre-Zen target enters the hardware matrix.
- A workload landing on the test fleet legitimately needs the
  Meltdown class of side-channel resistance (typically: a public
  multi-tenant deployment, which is far from current scope).
- Linux upstream changes its `pti=auto` default in a way that
  surfaces a new mitigation class we'd want to mirror.
