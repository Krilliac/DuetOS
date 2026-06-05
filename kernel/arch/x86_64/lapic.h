#pragma once

#include "util/types.h"

/*
 * Local APIC — v0.
 *
 * The LAPIC is the per-CPU interrupt controller on every modern x86_64.
 * For now we bring up only the BSP's LAPIC: detect via CPUID, map its
 * 4 KiB MMIO window into the kernel MMIO arena, set the spurious-vector
 * register, and expose register read/write + EOI for downstream code
 * (timer, IPIs once SMP lands, IOAPIC-routed device IRQs).
 *
 * Mode: x2APIC (MSR) is selected automatically whenever CPUID
 * advertises it (the common case on modern HW and the only mode
 * that works when firmware locks x2APIC on); otherwise legacy
 * xAPIC (MMIO). LapicRead/Write/SendIcr are mode-transparent.
 *
 * Scope limits that will be fixed in later commits:
 *   - No TPR / priority management — runs with TPR=0 (accept all).
 *   - >255 APIC IDs need x2APIC MADT (type 9) parsing — legacy
 *     MADT LAPIC records are 8-bit; fine for all current targets.
 *
 * Context: kernel. Init runs once, after PagingInit (needs MapMmio) and
 * after PicDisable (so the 8259 can't sneak an IRQ in during bring-up).
 */

namespace duetos::arch
{

/// LAPIC register offsets in the MMIO window. Each register is 32 bits but
/// must be addressed as a 16-byte aligned u32 — the upper 12 bytes are
/// reserved.
inline constexpr u64 kLapicRegId = 0x020;
inline constexpr u64 kLapicRegVersion = 0x030;
inline constexpr u64 kLapicRegTpr = 0x080;
inline constexpr u64 kLapicRegEoi = 0x0B0;
inline constexpr u64 kLapicRegSvr = 0x0F0; // Spurious-Interrupt Vector
inline constexpr u64 kLapicRegLvtTimer = 0x320;
inline constexpr u64 kLapicRegTimerInit = 0x380;
inline constexpr u64 kLapicRegTimerCount = 0x390;
inline constexpr u64 kLapicRegTimerDivide = 0x3E0;
// Performance monitoring counter LVT entry. When a PMU counter
// overflows, the LAPIC checks this entry and delivers the
// configured interrupt. NMI delivery (bits 10:8 = 0b100) lets
// a PMU overflow fire even while IF is cleared — the basis of
// the NMI watchdog.
inline constexpr u64 kLapicRegLvtPerf = 0x340;

// In-Service Register base. The ISR is 256 bits spread across 8
// 32-bit registers at 0x100, 0x110, ... 0x170; bit `v & 31` of
// register `0x100 + (v >> 5) * 0x10` is set while vector `v` is
// being serviced by this CPU and clears on EOI. x2APIC folds each
// onto MSR 0x810 + (v >> 5), which LapicRead's offset>>4 mapping
// already produces.
inline constexpr u64 kLapicRegIsrBase = 0x100;

/// Detect the LAPIC, map its MMIO window with cache-disable, set the
/// spurious-vector register (vector 0xFF), and globally enable. Panics if
/// the LAPIC is not present (shouldn't happen on x86_64).
void LapicInit();

/// Acknowledge the in-service interrupt. Must be called by the IRQ
/// dispatcher — handlers should NOT call EOI themselves (see traps.h).
void LapicEoi();

/// True iff vector `v`'s In-Service bit is set in this CPU's LAPIC —
/// i.e. the interrupt was hardware-delivered and is awaiting EOI.
/// A software-triggered `int n` and the spurious vector (0xFF) never
/// set an ISR bit, so this returns false for them. The trap
/// dispatcher uses it to decide whether an UNHANDLED vector still
/// needs an EOI (a real device IRQ that latched the ISR would
/// otherwise block every lower-priority vector on this CPU). Returns
/// false before the LAPIC is mapped.
bool LapicInServiceBitSet(u8 v);

/// Raw register access. Caller is responsible for offset validity and
/// register-specific semantics. Transparently dispatches to MMIO
/// (xAPIC) or the corresponding MSR (x2APIC); the MSR address is
/// `0x800 + (reg_offset >> 4)`, which is correct for every register
/// the kernel touches EXCEPT the ICR — IPIs MUST go through
/// `LapicSendIcr`, never `LapicWrite(kLapicRegIcr*)`, because x2APIC
/// folds the ICR into a single 64-bit MSR with no delivery-status.
u32 LapicRead(u64 reg_offset);
void LapicWrite(u64 reg_offset, u32 value);

/// Send an inter-processor interrupt. `dest` is the full APIC ID of
/// the target (ignored when `icr_low` carries a destination
/// shorthand). Mode-aware: xAPIC writes ICR-high then ICR-low and
/// spins on delivery-status; x2APIC issues one `wrmsr(0x830)` with
/// no poll. Bounded and klog-free so the panic / NMI-broadcast
/// paths can use it.
void LapicSendIcr(u32 dest, u32 icr_low);

/// This CPU's APIC ID, normalised across modes: the full 32-bit
/// x2APIC ID, or the xAPIC ID register shifted down out of bits
/// 31:24. Use this instead of open-coding `LapicRead(kLapicRegId)
/// >> 24`, which is wrong in x2APIC mode.
u32 LapicCurrentId();

/// True once the LAPIC is usable (xAPIC: MMIO window mapped;
/// x2APIC: MSR interface enabled). Replaces the old "is the MMIO
/// pointer non-null" check, which is always false in x2APIC mode.
bool LapicIsX2apic();

/// Boot self-test: the APIC mode must be consistent (x2APIC
/// enabled iff CPUID advertises x2APIC) and the mode-normalised
/// LAPIC ID must round-trip against this CPU's recorded
/// `PerCpu::lapic_id`. Emits one
/// `[apic-mode-selftest] PASS (x2apic|xapic)` line; panics on a
/// mismatch. PASSes on every guest (no SKIP).
void ApicModeSelfTest();

/// True once LapicInit has mapped the MMIO window and enabled the
/// APIC. Useful for paths that may run early in boot (notably the
/// panic path) and need to avoid poking an un-mapped LAPIC window.
bool LapicIsReady();

} // namespace duetos::arch
