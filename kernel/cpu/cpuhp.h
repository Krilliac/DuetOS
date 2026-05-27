#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — CPU hotplug state machine.
 *
 * Pattern from Linux `kernel/cpu.c`: a linear ordered sequence of
 * per-CPU states (`Offline` ... `Online`) where each subsystem
 * registers `(startup, teardown)` callbacks at a specific state.
 * Bring-up walks forward; takedown walks backward; failure rolls
 * back through every teardown of every state successfully entered.
 *
 * The enum is intentionally sparse (gaps of 10) so subsystems can
 * register at fine-grained sub-states without renumbering. Linux uses
 * the same trick (CPUHP_*_PREPARE, CPUHP_AP_*, CPUHP_AP_ONLINE_*).
 *
 * THIS SLICE creates the framework + migrates the existing per-CPU
 * init hooks into named states. No behaviour change beyond a
 * `[cpuhp] state-machine ready` sentinel and DEBUG-gated per-state
 * transition lines.
 *
 * Subsystem rule: PREPARE states run on the BSP before SIPI;
 * STARTING and ONLINE states run on the target CPU itself, called
 * from `arch::ApEntryFromTrampoline`. The framework does not enforce
 * which CPU runs which range — the caller (`CpuhpBringUp`) is
 * responsible for invoking it on the right CPU.
 *
 * Context: kernel. The transition path is rare (boot + future
 * hot-plug); a single coarse spinlock protects the per-CPU state
 * slot. Callbacks themselves run with the lock dropped so they can
 * acquire other kernel locks freely.
 */

namespace duetos::cpu
{

/// Per-CPU bring-up state. Bring-up walks Offline -> Online.
/// Takedown walks Online -> Offline. Failure during bring-up rolls
/// back through the teardowns of every state successfully reached.
enum class CpuhpState : u16
{
    Offline = 0,

    // Pre-bring-up preparation (runs on BSP before SIPI).
    PrepareAllocStorage = 100, // allocate per-AP PerCpu, GDT bundle, stacks
    PrepareTopology = 110,     // reserve topology slot
    PrepareIpiMailbox = 120,   // allocate IPI mailbox storage

    // AP starting up (runs ON the AP).
    StartingTrampoline = 200,  // long-mode entry done, paging on
    StartingGdt = 210,         // LoadGdtForCurrent
    StartingGsBase = 220,      // WriteMsrGsBase / KernelGsBase
    StartingIdt = 230,         // IdtLoadForCurrent
    StartingCr4 = 240,         // EnableKernelProtectionBitsForThisCpu
    StartingSyscallMsrs = 250, // ProgramSyscallMsrsForCurrentCpu
    StartingLapic = 260,       // LAPIC EN + LapicSendIcr setup
    StartingTopology = 270,    // TopologyInitAp
    StartingScheduler = 280,   // SchedEnterOnAp's idle install

    // Online (runs on AP, then BSP finalises).
    OnlineSched = 300,
    OnlineIpiCall = 310,    // IPI mailbox active
    OnlineSoftLockup = 320, // soft-lockup detector starts ticking for this CPU
    OnlineHeartbeat = 330,  // CPU counted in cpu:online

    Online = 999,
};

/// Subsystem-registered callback. Pure function — no kernel object
/// captures. Receives the target CPU id for cross-CPU PREPARE steps;
/// startups for STARTING-band states ALWAYS run on the target CPU.
///
/// Return ok() to advance; return Err to abort. An aborted bring-up
/// walks the teardown chain backwards.
using CpuhpStartupFn = ::duetos::core::Result<void> (*)(u32 cpu_id);
using CpuhpTeardownFn = ::duetos::core::Result<void> (*)(u32 cpu_id);

/// Maximum sparse slot count. The enum values above must all fit
/// strictly below this. 1000 covers the current band layout
/// (Offline=0, Prepare=100s, Starting=200s, Online=300s..999) with
/// generous headroom for sub-state insertions.
inline constexpr u32 kMaxCpuhpStates = 1000;

/// Register a state's callbacks. `name` is a short stable string
/// for diagnostics ("sched", "ipi-call", "soft-lockup"). nullptr
/// callback means "no-op at this state" — useful when only one
/// direction (just startup, or just teardown) is meaningful.
///
/// Idempotent: same `state + name` re-registers without doubling.
///
/// Lifetime: name string must outlive the registration (use literals).
///
/// Returns true on accept, false on a layout error (state value out
/// of range, no slot available).
bool CpuhpInstall(CpuhpState state, const char* name, CpuhpStartupFn startup, CpuhpTeardownFn teardown);

/// Walk the bring-up chain on `cpu_id` from its current state to
/// Online. Called by BSP for AP bring-up: BSP runs PREPARE states
/// locally, then the AP itself runs STARTING + ONLINE states via the
/// smp trampoline path which calls into this function from
/// `ApEntryFromTrampoline`.
///
/// On Err the teardown chain is walked backwards through every state
/// that ran successfully, restoring the CPU to its pre-bring-up
/// state. The returned error is the startup error that originated
/// the abort.
::duetos::core::Result<void> CpuhpBringUp(u32 cpu_id);

/// Walk the takedown chain on `cpu_id` from Online back to Offline.
/// Used by future hot-unplug. Returns ok on full success, Err with
/// the state that failed teardown (the CPU is left in that state,
/// not progressed further).
///
/// Not used in this slice but exposed so the contract is fixed.
::duetos::core::Result<void> CpuhpTakeDown(u32 cpu_id);

/// Read the current state of `cpu_id`. Returns Offline for invalid ids.
CpuhpState CpuhpStateRead(u32 cpu_id);

/// Mark a CPU online without running the bring-up chain. ONLY for
/// the BSP which is already initialised by the time the framework is
/// set up. Calling this for an AP that hasn't actually been brought
/// up is a bug.
void CpuhpMarkOnline(u32 cpu_id);

/// Diagnostic counters since boot.
struct CpuhpStats
{
    u32 cpus_online;
    u32 bringup_failures_total;
    u32 takedown_failures_total;
    u32 rollbacks_total;
};
CpuhpStats CpuhpStatsRead();

/// Dump the per-CPU state to serial (panic-safe, raw SerialWrite).
/// One line per CPU: `[cpuhp] cpu=0x0 state=Online`.
void CpuhpDumpStates();

/// Self-test. Registers a toy state, simulates a bring-up with a
/// failing intermediate to verify rollback runs the right teardowns.
/// Prints `[cpuhp] self-test OK (...)`.
void CpuhpSelfTest();

/// Stable human name for a state — used by the dumper and the
/// debug-gated per-state-transition log. Always returns a non-null
/// .rodata pointer.
const char* CpuhpStateName(CpuhpState state);

} // namespace duetos::cpu
