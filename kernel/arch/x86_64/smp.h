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
 * Current scope (as of decision log #023):
 *   - MADT LAPIC enumeration identifies BSP + AP candidates
 *     (`acpi::Lapic(i)`).
 *   - `SmpSendIpi` wraps the LAPIC ICR dance; usable by any future
 *     caller (AP wake-up, TLB shootdown, resched-IPI).
 *   - `SmpStartAps` copies the trampoline image to physical 0x8000,
 *     allocates each AP's stack + `PerCpu`, and drives the full
 *     INIT-SIPI-SIPI sequence. Each AP writes `online_flag` from
 *     `ApEntryFromTrampoline` after installing GSBASE + enabling
 *     its LAPIC; BSP polls with a bounded timeout before moving on.
 *   - AP-side C++ entry halts with interrupts masked — the AP's
 *     LAPIC is live, but the scheduler is not SMP-safe across
 *     context-switch yet (the lock-passing half of the SMP
 *     bring-up plan, Commit D, is still pending — see
 *     `wiki/advanced/SMP-AP-Bringup-Scope.md`).
 *
 * Deferred (see `wiki/advanced/SMP-AP-Bringup-Scope.md`):
 *   - Lock-passing across `ContextSwitch` so a peer CPU can safely
 *     wake tasks that this CPU is about to switch away from.
 *   - `SchedEnterOnAp` — each AP calls `SchedStartIdle("idle-apN")`,
 *     arms its LAPIC timer, and enters the scheduler loop.
 *   - Per-AP TSS + IST (needed alongside ring 3).
 *   - Broadcast-NMI panic halt for Class-A recovery on SMP.
 *
 * Context: kernel. Run once after SchedInit + IoApicInit +
 * PerCpuInitBsp (BSP's `PerCpu` must be live before APs allocate
 * theirs).
 */

namespace duetos::arch
{

/// Copy the trampoline to physical 0x8000, allocate each AP's stack
/// + per-CPU struct, and drive INIT-SIPI-SIPI for every enabled
/// LAPIC in the MADT other than the BSP's. Returns the number of
/// APs that reached `ApEntryFromTrampoline` and flipped their
/// `online_flag` within the bounded polling window.
u64 SmpStartAps();

/// Number of online CPUs (BSP + any APs that successfully entered
/// `ApEntryFromTrampoline`). BSP is always counted; each AP
/// increments this on bring-up.
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

/// Highest cpu_id ever allocated + 1 (i.e. the upper bound of a
/// `for (id = 0; id < SmpCpuIdLimit(); ++id)` loop). 1 if only the
/// BSP has come up.
u32 SmpCpuIdLimit();

/// GDB stop-rendezvous broadcast. Sets the global stop-active flag,
/// then NMI-broadcasts to all CPUs except the caller. Each peer's
/// vector-2 handler observes the flag and enters a release-spin
/// (capturing rip/rsp into its PerCpu's `gdb_snapshot_*` fields)
/// instead of taking the panic-halt path. The calling CPU returns
/// once the IPI has been delivered; the peers stay frozen until
/// SmpStopReleaseNmi clears the flag.
///
/// Distinct from PanicBroadcastNmi — that one halts peers forever
/// because the calling CPU is committed to going down. This one
/// freezes peers temporarily on a release flag so the calling CPU
/// can safely run the GDB stop loop without peers stomping on
/// shared state, then resume them on debugger continue.
void SmpStopBroadcastNmi();

/// Pair of SmpStopBroadcastNmi: clear the stop-active flag. Each
/// peer is spinning on it and exits its NMI handler the moment
/// it observes the clear, returning to the code it was running
/// when the NMI fired.
void SmpStopReleaseNmi();

/// Read of the stop-active flag for the vector-2 NMI handler. Set
/// by SmpStopBroadcastNmi, cleared by SmpStopReleaseNmi. Plain
/// load — the broadcast/release pair issues memory barriers around
/// the flip, so an NMI that arrives between the LAPIC ICR write
/// and this read sees a consistent value.
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

/// Install the IDT handler for `kTlbShootdownIpiVector`. Called once
/// alongside `SmpInstallReschedIpiHandler` during early boot, before
/// any AP could fire the IPI.
void SmpInstallTlbShootdownIpiHandler();

} // namespace duetos::arch
