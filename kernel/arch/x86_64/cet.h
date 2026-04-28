#pragma once

#include "util/types.h"

/*
 * DuetOS — Intel CET (Control-flow Enforcement Technology), v0
 * (plan E1).
 *
 * WHAT
 *   Detects whether the running CPU advertises CET-SS (Shadow
 *   Stack) and CET-IBT (Indirect Branch Tracking), records the
 *   answer in a global, and logs a one-line boot summary.
 *
 *   CET-SS:  CPU maintains a kernel-protected shadow stack
 *            paralleling the regular call stack; mismatch on
 *            RET fires #CP. Shadow-stack pages need a special
 *            page-table flag (`PAGE_SS`).
 *   CET-IBT: indirect branches must land on an `ENDBR64`
 *            instruction; otherwise #CP. Compiler emits ENDBR64
 *            at every indirect-branch target with `-fcf-protection`.
 *
 * WHY
 *   The recommendations plan E1 calls for landing CET. v0 is
 *   the probe + status surface; the actual mitigation enable
 *   (writing `IA32_S_CET` / `IA32_PL0_SSP`, allocating shadow
 *   stacks, recompiling with `-fcf-protection=branch`) is a
 *   separate larger slice that depends on this signal.
 *
 * NOT IN SCOPE
 *   - Enabling CET. Requires shadow-stack page allocation,
 *     IDT-handler ENDBR64 prologues, kernel-image rebuild with
 *     `-fcf-protection=branch`. Tracked as E1-followup.
 *   - User-mode CET (PE / ELF binaries opting in).
 */

namespace duetos::arch
{

struct CetStatus
{
    bool ss_supported;  ///< CPUID(7,0).ECX[7] = CET-SS in silicon.
    bool ibt_supported; ///< CPUID(7,0).EDX[20] = CET-IBT in silicon.
    bool ss_enabled;    ///< IA32_S_CET.SH_STK_EN observed (v0 always false).
    bool ibt_enabled;   ///< IA32_S_CET.ENDBR_EN observed (v0 always false).
};

/// Probe CET support once. Idempotent. Logs a boot-console
/// summary `[cpu] cet: ss=<sup/no> ibt=<sup/no>`.
void CetProbe();

/// Read the cached status. Zero-initialised before `CetProbe`.
const CetStatus& CetGet();

} // namespace duetos::arch
