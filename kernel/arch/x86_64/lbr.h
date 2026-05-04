#pragma once

#include "util/types.h"

/*
 * Architectural Last-Branch-Record (LBR) support.
 *
 * Intel SDM Vol. 4 §17.10 — Architectural LBR is the modern,
 * non-model-specific interface for the per-CPU branch trace ring.
 * Detected via CPUID.(EAX=07H,ECX=00H):EDX[19] = ARCH_LBR. When
 * enabled the CPU records the last N taken branches (N = depth
 * supported, 8/16/24/32) into IA32_LBR_FROM_n / TO_n / INFO_n.
 * On panic those records are the most reliable backtrace we can
 * recover when frame pointers are omitted, the rbp chain is
 * corrupted, or asm thunks broke the chain — they're literally
 * the CPU's record of where it was just dispatching from.
 *
 * Legacy LBR (pre-Architectural-LBR family/model dispatch via
 * IA32_DEBUGCTL.LBR + per-model FROM/TO MSRs) is NOT covered. AMD
 * LBR (different MSR layout entirely) is NOT covered. Both are
 * future-tier work — Architectural LBR is the only Intel CPU
 * interface stable enough to ship without a per-CPU dispatch
 * table.
 *
 * Status under emulation: QEMU TCG does NOT implement LBR. CPUID
 * 7.0 EDX[19] reads as 0 there, LbrInitBsp returns false, and the
 * panic-time dump section emits "(unsupported on this CPU)". On
 * real Intel silicon (Goldmont Plus / Ice Lake / Cascade Lake AP
 * onwards) the snapshot will contain real branch records.
 *
 * Context: kernel. Init runs once on the BSP. Snapshot reads can
 * fire from panic / trap / IRQ context — all MSR access is
 * inline and allocation-free.
 */

namespace duetos::arch
{

inline constexpr u32 kLbrMaxEntries = 32;

struct LbrSnapshot
{
    u32 depth;                // # populated entries (0 if LBR unavailable)
    u64 ctl_at_capture;       // IA32_LBR_CTL value when LbrCapture ran
    u64 from[kLbrMaxEntries]; // taken-branch source IPs, entry 0 = newest
    u64 to[kLbrMaxEntries];   // taken-branch destination IPs
    u64 info[kLbrMaxEntries]; // mispredict / cycle metadata (model-defined)
};

/// Detect Architectural LBR via CPUID and, if present, configure
/// the BSP's stack: maximum supported depth, LBR enabled in both
/// kernel + user contexts, no filter (every taken branch
/// recorded). Returns true on success, false on any "not
/// available" branch (CPUID bit clear, depth=0, MSR access denied
/// by hypervisor). Idempotent — subsequent calls are no-ops.
///
/// AP support: not yet wired. The init only configures the
/// calling CPU; per-AP enablement waits until SMP runqueues
/// stabilise.
bool LbrInitBsp();

/// Was LBR successfully enabled by LbrInitBsp on the calling CPU?
/// Cheap (one global load + one local rdmsr).
bool LbrAvailable();

/// Stop further captures by clearing IA32_LBR_CTL.LBREn on the
/// calling CPU. Idempotent. Called from the panic banner so any
/// branches between Cli() and DumpDiagnostics don't pollute the
/// snapshot. No-op when LBR is unavailable.
void LbrFreeze();

/// Read every populated entry into `out`. Entry 0 is the most
/// recent branch. Sets `out.depth = 0` and zeros the arrays when
/// LBR is unavailable. Safe from any context (allocation-free,
/// no locks, RDMSR loop bounded by kLbrMaxEntries).
void LbrCapture(LbrSnapshot& out);

} // namespace duetos::arch
