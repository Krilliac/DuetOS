#pragma once

#include "util/types.h"

/*
 * DuetOS — CPU silicon-level mitigation status, v0.
 *
 * Sister TU to `cpu_info.h`. Where `cpu_info` answers "what
 * features can we use", this TU answers "which speculative-
 * execution mitigations does this CPU still need from software".
 * The two are intentionally split: feature detection runs early
 * during boot for the rest of the kernel to query; mitigation
 * detection is consulted by a much narrower set of paging /
 * trap-frame paths and benefits from staying out of the
 * common-case query surface.
 *
 * Read sequence:
 *   1. CPUID leaf 7, sub-leaf 0, EDX bit 29 — does the CPU expose
 *      `IA32_ARCH_CAPABILITIES` (MSR 0x10A)? If not, we can't
 *      query silicon-level guarantees and must conservatively
 *      assume software mitigation is required.
 *   2. RDMSR 0x10A — read the bits documented in Intel SDM
 *      Vol. 4, "Architectural MSRs". Bits we currently care
 *      about:
 *        bit 0  RDCL_NO       — Meltdown is not possible (no KPTI).
 *        bit 1  IBRS_ALL      — IBRS provides RSB-protection in addition.
 *        bit 3  SKIP_L1DFL_VMENTRY — VMM doesn't need to flush L1D.
 *        bit 4  SSB_NO        — SSB attacks not possible.
 *        bit 5  MDS_NO        — MDS attacks not possible.
 *        bit 6  IF_PSCHANGE_MC_NO — no MC on PS-change errata.
 *        bit 8  TAA_NO        — TSX async abort not possible.
 *        bit 13 PBRSB_NO      — post-barrier RSB attacks not possible.
 *      All bits beyond what's read are simply ignored — the MSR
 *      reserves them as zero on older silicon, so the absence of
 *      a bit is the conservative answer.
 *
 * Modern targets (Cascade Lake / Ice Lake / Tiger Lake / Alder Lake
 * / Sapphire Rapids; AMD Zen+) set RDCL_NO and most of the others
 * — they're inherently safe in silicon. Pre-2019 Intel client
 * parts and some Skylake-era server SKUs do not, so the kernel
 * needs to know which it's running on before deciding to land
 * software mitigations like KPTI / SSBD / TAA-flush.
 *
 * See `.claude/knowledge/kpti-meltdown-investigation-v0.md` for
 * the project's recorded position on KPTI itself: the mitigation
 * is not implemented; this probe surfaces the question so the
 * follow-up implementation can branch on a real signal rather
 * than a hard-coded assumption.
 */

namespace duetos::arch
{

struct CpuMitigations
{
    /// True if RDMSR 0x10A actually executed. False on CPUs that
    /// don't expose IA32_ARCH_CAPABILITIES — the rest of the
    /// fields stay at their conservative defaults.
    bool arch_capabilities_msr_present;

    /// Raw MSR value (or 0 if !msr_present).
    u64 arch_capabilities;

    /// Software mitigation requirement booleans, derived from the
    /// MSR. The naming convention is "needs_X" — true iff the
    /// kernel still has to do something. A CPU with RDCL_NO=1
    /// reports needs_kpti=false.
    bool needs_kpti;      ///< True iff Meltdown is in-scope. Read from `RDCL_NO==0`.
    bool needs_mds_buf;   ///< True iff MDS-class attacks are in-scope. Read from `MDS_NO==0`.
    bool needs_ssbd;      ///< True iff SSB is in-scope. Read from `SSB_NO==0`.
    bool needs_taa_flush; ///< True iff TSX async abort is in-scope. Read from `TAA_NO==0`.
};

/// Probe `IA32_ARCH_CAPABILITIES` once. Idempotent — second call
/// is a no-op. Safe to call before / after `CpuInfoProbe`. Logs a
/// one-line summary on the boot console (`[cpu] mitigations:
/// kpti=needed mds=safe ssbd=safe taa=safe`).
void CpuMitigationsProbe();

/// Accessor for the cached struct. All fields are zero-initialised
/// before the probe runs, which is the conservative answer
/// (every "needs_X" reads true). Callers MUST NOT branch on this
/// before `CpuMitigationsProbe()` has run; the boot log line is
/// the canonical "probe is done" signal.
const CpuMitigations& CpuMitigationsGet();

} // namespace duetos::arch
