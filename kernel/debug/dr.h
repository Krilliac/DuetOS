#pragma once

#include "../core/types.h"

/*
 * DuetOS — x86_64 debug-register access helpers.
 *
 * DR0..DR3 hold breakpoint linear addresses; DR6 reports which
 * breakpoint condition fired (plus single-step and task-switch
 * bits); DR7 controls enable/type/length for each of the four
 * address slots. DR4/DR5 alias DR6/DR7 on modern CPUs and are
 * not exposed here — use DR6/DR7 directly.
 *
 * All helpers are inline + header-only so the trap-handler path
 * doesn't pay a call in the #DB fast path.
 *
 * Context: ring 0 only. MOV-to/from-DR is #GP from ring 3.
 */

namespace duetos::debug::dr
{

inline u64 ReadDr0()
{
    u64 v;
    asm volatile("mov %%dr0, %0" : "=r"(v));
    return v;
}
inline u64 ReadDr1()
{
    u64 v;
    asm volatile("mov %%dr1, %0" : "=r"(v));
    return v;
}
inline u64 ReadDr2()
{
    u64 v;
    asm volatile("mov %%dr2, %0" : "=r"(v));
    return v;
}
inline u64 ReadDr3()
{
    u64 v;
    asm volatile("mov %%dr3, %0" : "=r"(v));
    return v;
}
inline u64 ReadDr6()
{
    u64 v;
    asm volatile("mov %%dr6, %0" : "=r"(v));
    return v;
}
inline u64 ReadDr7()
{
    u64 v;
    asm volatile("mov %%dr7, %0" : "=r"(v));
    return v;
}

inline void WriteDr0(u64 v)
{
    asm volatile("mov %0, %%dr0" : : "r"(v));
}
inline void WriteDr1(u64 v)
{
    asm volatile("mov %0, %%dr1" : : "r"(v));
}
inline void WriteDr2(u64 v)
{
    asm volatile("mov %0, %%dr2" : : "r"(v));
}
inline void WriteDr3(u64 v)
{
    asm volatile("mov %0, %%dr3" : : "r"(v));
}
inline void WriteDr6(u64 v)
{
    asm volatile("mov %0, %%dr6" : : "r"(v));
}
inline void WriteDr7(u64 v)
{
    asm volatile("mov %0, %%dr7" : : "r"(v));
}

// --- DR6 status bits (read after #DB to identify the cause) ----
// B0..B3: the corresponding DR0..DR3 condition matched (sticky —
// stay set until the handler writes 0 back into DR6).
inline constexpr u64 kDr6B0 = 1ULL << 0;
inline constexpr u64 kDr6B1 = 1ULL << 1;
inline constexpr u64 kDr6B2 = 1ULL << 2;
inline constexpr u64 kDr6B3 = 1ULL << 3;
inline constexpr u64 kDr6Bn = 0xFULL; // mask over B0..B3
// BS: single-step trap (RFLAGS.TF was set when the last
// instruction completed). The trap is the instruction after the
// one that had TF set — i.e. we single-stepped through one insn.
inline constexpr u64 kDr6Bs = 1ULL << 14;
// DR6 "reserved-1" bits that always read as 1 on real HW; we
// mask them out when clearing.
inline constexpr u64 kDr6InitValue = 0xFFFF0FF0ULL;

// --- DR7 control bits -----------------------------------------
// L0/G0..L3/G3: per-slot enable (local / global). We always set
// the Local bit (bits 0,2,4,6) when enabling — per-task scope
// with the G-bit would require context-switch save/restore,
// which phase (1) intentionally skips.
inline constexpr u64 kDr7L0 = 1ULL << 0;
inline constexpr u64 kDr7L1 = 1ULL << 2;
inline constexpr u64 kDr7L2 = 1ULL << 4;
inline constexpr u64 kDr7L3 = 1ULL << 6;
// LE/GE (bits 8, 9) enable "exact data-breakpoint" detection on
// old CPUs; on modern hardware they're no-ops. Set anyway per
// the Intel SDM recommendation for forward-compat.
inline constexpr u64 kDr7Le = 1ULL << 8;
inline constexpr u64 kDr7Ge = 1ULL << 9;
// Bit 10 is always 1 (reserved, MBS). Bits 11-12 are reserved.
// RTM (bit 16) — we don't use TSX.
inline constexpr u64 kDr7Mbs = 1ULL << 10;

// R/W encoding in DR7[17+4n..16+4n] — the 2 bits selecting what
// triggers a match on DRn.
inline constexpr u64 kDr7RwExecute = 0b00;   // instruction fetch (hw exec BP)
inline constexpr u64 kDr7RwWrite = 0b01;     // data write
inline constexpr u64 kDr7RwIo = 0b10;        // I/O access (requires CR4.DE)
inline constexpr u64 kDr7RwReadWrite = 0b11; // data read or write (never fetch)

// LEN encoding in DR7[19+4n..18+4n]. For execute breakpoints
// LEN must be 00 (1 byte).
inline constexpr u64 kDr7Len1 = 0b00;
inline constexpr u64 kDr7Len2 = 0b01;
inline constexpr u64 kDr7Len4 = 0b11;
inline constexpr u64 kDr7Len8 = 0b10; // valid on x86_64 only

// Pack a per-slot (R/W, LEN) pair into its DR7 position. `slot`
// is 0..3. Returns the 4 bits ready to OR into a DR7 value.
inline constexpr u64 MakeDr7SlotBits(unsigned slot, u64 rw, u64 len)
{
    const unsigned shift = 16 + slot * 4;
    return ((rw & 0b11) | ((len & 0b11) << 2)) << shift;
}

// Mask that clears a slot's R/W + LEN nibble so the caller can OR
// in fresh bits.
inline constexpr u64 Dr7SlotMask(unsigned slot)
{
    const unsigned shift = 16 + slot * 4;
    return 0xFULL << shift;
}

// Per-slot L-enable bit for DR7.
inline constexpr u64 Dr7SlotEnableBit(unsigned slot)
{
    return 1ULL << (slot * 2); // L0, L1, L2, L3
}

} // namespace duetos::debug::dr
