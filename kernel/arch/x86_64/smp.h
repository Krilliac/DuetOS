#pragma once

#include "util/types.h"

namespace duetos::cpu
{
struct PerCpu;
}

namespace duetos::mm
{
struct AddressSpace;
}

/*
 * SMP AP bring-up.
 *
 * Current scope:
 *   - MADT LAPIC enumeration identifies BSP + AP candidates
 *     (`acpi::Lapic(i)`).
 *   - `SmpSendIpi` wraps the LAPIC ICR dance; usable by any future
 *     caller (AP wake-up, TLB shootdown, resched-IPI).
 *   - `SmpStartAps` copies the trampoline image to physical 0x8000,
 *     allocates each AP's stack + `PerCpu`, and drives the full
 *     INIT-SIPI-SIPI sequence with an exact generation + CPU-slot token.
 *     The trampoline captures all mutable parameters into registers and
 *     echoes that token before entering C++; the BSP retries SIPI only
 *     while the exact capture acknowledgement is absent.
 *   - AP-side C++ waits for a persistent, slot-specific Initialize gate,
 *     runs the CPUHP chain (GDT/GS/IDT/CR4/syscall MSRs/LAPIC/topology),
 *     publishes the exact ready token, then waits for a Run gate. The BSP
 *     publishes the CPU count, slot limit, and `PerCpu::online` before Run,
 *     so scheduler admission cannot precede routing visibility.
 *   - A failed or timed-out AP is rejected and parks with interrupts
 *     masked. If an AP never acknowledges parameter capture, the BSP stops
 *     launching later APs rather than overwrite the shared trampoline block
 *     that a late AP could still consume.
 *   - An admitted AP calls `SchedEnterOnAp`, installs its idle task and
 *     LAPIC timer, joins TLB shootdown, and enters the scheduler loop.
 *
 * Context: kernel. Run once after SchedInit + IoApicInit +
 * PerCpuInitBsp (BSP's `PerCpu` must be live before APs allocate
 * theirs).
 */

namespace duetos::arch
{

/// Copy the trampoline to physical 0x8000, allocate each AP's stack
/// + per-CPU struct, and drive INIT-SIPI-SIPI for every enabled
/// LAPIC in the MADT other than the BSP's. Returns the number of APs
/// that completed CPUHP initialization, acknowledged the exact attempt
/// token, and were admitted to the scheduler. A capture failure aborts
/// later attempts so the shared trampoline parameters are never reused
/// while an unacknowledged AP may still consume them.
u64 SmpStartAps();

/// Register the AP bring-up sequence as states in the cpu::Cpuhp
/// state machine. The lambdas registered here wrap each historic
/// AP-init step (GDT load, GS base, IDT load, CR4 protection bits,
/// syscall MSRs, LAPIC enable, topology) at its corresponding
/// `cpu::CpuhpState::Starting*` slot. Must run on the BSP BEFORE
/// `SmpStartAps` so the moment an AP enters `ApEntryFromTrampoline`
/// the chain is ready to execute. Idempotent.
void SmpCpuhpRegister();

/// Number of online CPUs (BSP + APs admitted after exact-token CPUHP
/// readiness). BSP is always counted; rejected or parked APs are not.
u64 SmpCpusOnline();

/// Send an arbitrary IPI via the LAPIC Interrupt Command Register.
/// `target_apic_id` is the full 32-bit destination APIC ID (no
/// 8-bit truncation — required for x2APIC). `icr_low` carries the
/// delivery mode + vector + level/trigger bits per Intel SDM Vol.
/// 3A. Routes through `arch::LapicSendIcr`, which is mode-aware
/// (xAPIC: ICR-hi/lo + bounded delivery-status spin; x2APIC: one
/// `wrmsr(0x830)`, no poll).
///
/// Shared by TLB shootdown, resched-IPI, and AP wake-up so they
/// don't reimplement the ICR dance.
void SmpSendIpi(u32 target_apic_id, u32 icr_low);

/// Reschedule-IPI vector. Set by the wake path on a remote CPU's
/// runqueue to prompt that CPU to call Schedule() promptly rather
/// than wait up to one timer tick (10 ms) for its own preemption.
inline constexpr u8 kReschedIpiVector = 0xF8;

/// Fire the reschedule-IPI at `cpu_id`. No-op if `cpu_id` is the
/// current CPU (we'd just be poking ourselves; the wake path's
/// own SetNeedResched is enough). Looks up the target's LAPIC ID
/// via SmpGetPercpu and wraps SmpSendIpi with the fixed-delivery
/// vector encoding. Safe to call with the scheduler lock held —
/// SmpSendIpi blocks only on the LAPIC delivery-status bit, which
/// clears within microseconds on healthy hardware.
void SmpSendReschedIpi(u32 cpu_id);

/// Install the IDT handler for kReschedIpiVector. Called once after
/// IdtInit but before any peer CPU could fire the IPI (i.e. before
/// SmpStartAps). The handler body just sets the current CPU's
/// need_resched flag — the IRQ dispatcher's existing post-EOI
/// check then calls Schedule() before iretq.
void SmpInstallReschedIpiHandler();

/// AP-timer-tick IPI vector. Sibling of `kReschedIpiVector` /
/// `kTlbShootdownIpiVector`. Fired by the BSP once per timer tick ONLY
/// on the PIT-tick fallback path (VirtualBox: the LAPIC timer never
/// delivers, so APs are left with no tick of their own). The handler
/// runs `sched::OnApTimerTick` on the receiving AP — per-CPU CPU-time
/// accounting (what sysmon reads) plus a reschedule request.
inline constexpr u8 kApTimerIpiVector = 0xF7;

/// Install the IDT handler for `kApTimerIpiVector`. Called once
/// alongside `SmpInstallReschedIpiHandler` during early boot, before
/// `SmpStartAps`, so the AP IDT clone inherits the wired vector.
void SmpInstallApTimerIpiHandler();

/// Broadcast the AP-timer tick to every online peer CPU (one ICR write,
/// all-excluding-self). Called from the BSP's `TimerHandler` ONLY when
/// `g_pit_fallback_active` is set and >1 CPU is online — on a healthy
/// boot each AP gets its own LAPIC timer tick, so broadcasting would
/// double-count. Fire-and-forget; safe from IRQ context.
void SmpBroadcastApTimerTick();

/// Broadcast an NMI to every CPU except the calling one. Used by
/// the panic path to halt peer CPUs before dumping diagnostics so
/// they can't keep executing against potentially-corrupt shared
/// state while we're writing the crash banner. Uses the "all
/// excluding self" destination shorthand so no per-CPU loop is
/// needed. Safe to call even on single-CPU systems — the shorthand
/// simply matches zero targets.
///
/// Blocks until delivery-status clears, but will not panic on
/// timeout (see PanicBroadcastNmi's own comment): the panic path
/// is already committed to halting; tolerating a stuck IPI is
/// better than recursing into another panic.
void PanicBroadcastNmi();

/// Bounded busy-wait for peers to acknowledge the panic-broadcast
/// NMI. Call AFTER `PanicBroadcastNmi` and BEFORE the panic-mode
/// SerialWrite stream starts. Polls each online peer's
/// `panic_snapshot_valid` flag (set by the vector-2 handler before
/// it `cli; hlt`s) until it ticks 1 or `spin_budget` pause-iters
/// expire — whichever first. Returns the count of peers that
/// acked. Without this wait the LAPIC IPI delivery latency leaves
/// a window where a peer is still in normal SerialWrite (holding
/// `g_serial_lock`) while this CPU bypasses the lock via
/// `g_serial_panic_mode` and writes raw bytes — the streams
/// interleave at the UART and corrupt the panic dump. Ported
/// pattern: toaruos's `arch_fatal_prepare` halts peers before
/// proceeding with panic output; the bounded wait here is the
/// "and don't proceed until they actually halted" half of that.
u32 PanicWaitPeersHalt(u64 spin_budget);

/// Look up a CPU's PerCpu struct by `cpu_id`. Returns the BSP for
/// `cpu_id == 0` (always non-null after PerCpuInitBsp), the matching
/// AP for higher ids, or nullptr if that slot was never allocated.
/// Used by the panic dump path to walk every peer CPU's snapshot
/// buffer; safe at any context (pure pointer-table read).
cpu::PerCpu* SmpGetPercpu(u32 cpu_id);

/// Highest admitted cpu_id + 1 (i.e. the upper bound of a
/// `for (id = 0; id < SmpCpuIdLimit(); ++id)` loop). Failed attempts
/// burn their private slots, so callers must tolerate holes and check
/// `PerCpu::online`. Returns 1 if only the BSP has come up.
u32 SmpCpuIdLimit();

/// Result of one generation-specific GDB stop rendezvous. CPU ids map
/// directly to bits in each mask (the current architectural cap is 32).
/// `expected_mask` is snapshotted from online peers before the NMI;
/// `acknowledged_mask` contains only peers that release-published this
/// exact generation; `missing_mask` is their difference.
struct GdbStopRendezvous
{
    u64 generation;
    u64 expected_mask;
    u64 acknowledged_mask;
    u64 missing_mask;
    bool complete;
};

/// GDB stop-rendezvous broadcast and bounded collective wait. Publishes a
/// fresh nonzero generation, NMI-broadcasts to all CPUs except the caller,
/// then samples every expected peer at most `spin_budget + 1` times. Peers
/// publish their live trap frame and register snapshot before acknowledging
/// the generation. The returned generation remains active until the matching
/// SmpStopReleaseNmi call.
///
/// Distinct from PanicBroadcastNmi — that one halts peers forever
/// because the calling CPU is committed to going down. This one
/// freezes peers temporarily on a release flag so the calling CPU
/// can safely run the GDB stop loop without peers stomping on
/// shared state, then resume them on debugger continue.
GdbStopRendezvous SmpStopBroadcastNmiAndWait(u64 spin_budget);

/// Release only the matching stop generation. A stale caller cannot clear a
/// newer rendezvous. Returns false if `generation` was zero or no longer owns
/// the active stop.
bool SmpStopReleaseNmi(u64 generation);

/// Acquire-load the active GDB stop generation. Zero means no stop; a peer NMI
/// captures the nonzero value once and acknowledges that exact generation.
u64 SmpGdbStopGeneration();

/// Compatibility predicate for callers that only need active/inactive state.
bool SmpGdbStopActive();

// ---------------------------------------------------------------------------
// TLB shootdown — see kernel/mm/address_space.h for the high-level contract.
// These declarations exist on the arch side because they own the LAPIC IPI
// vector and the per-CPU "current AS" lookup needed to filter recipients.
// ---------------------------------------------------------------------------

/// TLB shootdown IPI vector. Sibling of `kReschedIpiVector`. Lives in the
/// 240..254 range reserved by `traps.cpp` for kernel-internal IPIs.
inline constexpr u8 kTlbShootdownIpiVector = 0xF9;

/// Broadcast a single-address invalidation to every peer CPU whose
/// current CR3 maps `as`. No-op when only the BSP is online (peer set
/// is empty). The caller is responsible for the local `invlpg` — this
/// helper only handles remote CPUs.
void SmpTlbShootdownAddr(mm::AddressSpace* as, u64 virt);

/// Broadcast a per-page invalidation across the half-open range
/// `[virt, virt + len)` to every peer CPU whose current CR3 maps `as`.
/// Same locality rules as SmpTlbShootdownAddr.
void SmpTlbShootdownRange(mm::AddressSpace* as, u64 virt, u64 len);

/// Join this CPU to the TLB-shootdown domain: flush its entire TLB,
/// then mark it a legal shootdown ack target (`PerCpu::tlb_ipi_ready`).
///
/// MUST be called by the CPU itself, exactly once, as the LAST step of
/// its bring-up — immediately before the idle loop's first `sti`, and
/// deliberately still at IF=0. Two constraints pin that placement:
///
///  - Not EARLIER: from the moment the flag flips, peers count this CPU
///    as an ack target, so it must otherwise be fully brought up.
///  - Not with interrupts already ENABLED: the stretch between an AP's
///    trampoline signal and its first scheduled task is the fragile
///    fresh-AP window, and running code at IF=1 there is what forced
///    the lockdep per-task held-set behind the SchedFinishTaskSwitch
///    fresh-AP guard (attempt 1 crashed 3/6 boots with "WaitQueueBlock
///    on non-Running task"). Do not widen it to satisfy this call.
///
/// Flipping the flag at IF=0 is safe: a shootdown arriving in the few
/// instructions before that `sti` leaves its IPI pending on the
/// already-enabled LAPIC and is acked nanoseconds later, far inside the
/// requestor's ~17ms spin budget. The window this closes is
/// milliseconds wide, so the trade is overwhelmingly favourable.
///
/// Idempotent — the flag is monotonic, so repeat calls are no-ops.
/// The BSP is marked ready at PerCpuInitBsp and never calls this.
void SmpTlbShootdownJoin();

/// Install the IDT handler for `kTlbShootdownIpiVector`. Called once
/// alongside `SmpInstallReschedIpiHandler` during early boot, before
/// any AP could fire the IPI.
void SmpInstallTlbShootdownIpiHandler();

} // namespace duetos::arch
