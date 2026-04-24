#pragma once

#include "../../core/types.h"

/*
 * Local APIC — v0.
 *
 * The LAPIC is the per-CPU interrupt controller on every modern x86_64.
 * For now we bring up only the BSP's LAPIC: detect via CPUID, map its
 * 4 KiB MMIO window into the kernel MMIO arena, set the spurious-vector
 * register, and expose register read/write + EOI for downstream code
 * (timer, IPIs once SMP lands, IOAPIC-routed device IRQs).
 *
 * Scope limits that will be fixed in later commits:
 *   - BSP only. AP LAPICs come up with SMP.
 *   - xAPIC MMIO mode only. x2APIC (MSR-based) is straightforward to add
 *     and recommended on >256-thread systems; defer until it matters.
 *   - No TPR / priority management — runs with TPR=0 (accept all).
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

/// Detect the LAPIC, map its MMIO window with cache-disable, set the
/// spurious-vector register (vector 0xFF), and globally enable. Panics if
/// the LAPIC is not present (shouldn't happen on x86_64).
void LapicInit();

/// Acknowledge the in-service interrupt. Must be called by the IRQ
/// dispatcher — handlers should NOT call EOI themselves (see traps.h).
void LapicEoi();

/// Raw register access. Caller is responsible for offset validity and
/// register-specific semantics.
u32 LapicRead(u64 reg_offset);
void LapicWrite(u64 reg_offset, u32 value);

/// True once LapicInit has mapped the MMIO window and enabled the
/// APIC. Useful for paths that may run early in boot (notably the
/// panic path) and need to avoid poking an un-mapped LAPIC window.
bool LapicIsReady();

} // namespace duetos::arch
