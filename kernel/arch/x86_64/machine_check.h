#pragma once

/*
 * Machine Check Architecture (#MC, vector 18) decode.
 *
 * The kernel's runtime checker already polls the MCi_STATUS banks
 * for *corrected* errors that accumulate silently. This module
 * covers the other half: when an *uncorrected* error raises a real
 * #MC exception, the trap dispatcher hands the frame here so the
 * operator gets a decoded picture of which hardware failed (which
 * bank, the MCA error code, the faulting physical address, and
 * whether the processor context survived) instead of a bare
 * "** CPU EXCEPTION ** vector 18" with no hardware attribution.
 *
 * Context: trap, IST2 (dedicated machine-check stack — see
 * gdt.h kIstMachineCheck). Raw serial only; klog's ring may not
 * survive a context-corrupting hardware fault, so this mirrors the
 * panic dump's raw-serial contract. One KLOG_ERROR + one probe are
 * fired for the post-mortem ring and an attached GDB.
 */

#include "arch/x86_64/traps.h"
#include "util/types.h"

namespace duetos::arch
{

// Outcome of the #MC bank walk. The dispatcher always halts after a
// #MC (DuetOS v0 has no page-poison / context-recovery path), but
// the verdict tells the operator *why* the box is unrecoverable so
// a DIMM-vs-cache-vs-bus failure is distinguishable from the log.
enum class MachineCheckVerdict : u8
{
    NoError,         // #MC fired but no bank has VAL set (spurious / firmware)
    ContextCorrupt,  // a bank set PCC — processor state is gone
    ContextLost,     // MCG_STATUS.RIPV=0 — cannot resume the interrupted flow
    RestartableInfo, // RIPV=1, no PCC — restartable in principle (see GAP)
};

// Decode IA32_MCG_CAP / MCG_STATUS and every VAL-set MCi_STATUS
// bank to raw serial, fire the post-mortem probe + KLOG, and
// return the recoverability verdict. Pure read-back of the MCA
// MSRs plus serial I/O — no allocation, no locks, safe from the
// #MC trap context.
MachineCheckVerdict MachineCheckReport(const TrapFrame* frame);

} // namespace duetos::arch
