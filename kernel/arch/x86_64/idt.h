#pragma once

#include "../../core/types.h"

/*
 * CustomOS x86_64 Interrupt Descriptor Table.
 *
 * A single 256-entry IDT shared by all CPUs (for now — SMP bring-up is a
 * later commit). Vectors 0..31 are wired to the CPU-exception stubs in
 * exceptions.S; the rest are left as non-present gates. Any interrupt on
 * an unconfigured vector will produce a #NP (segment-not-present) or
 * triple-fault, which is what we want while the IRQ layer doesn't exist.
 *
 * Context: kernel, called exactly once during early bring-up, after
 * GdtInit().
 */

namespace customos::arch
{

/// Install the IDT and load it with lidt. Depends on `kKernelCodeSelector`
/// from gdt.h already being the active CS.
void IdtInit();

/// Late-bound gate install for vectors that don't have a matching slot in
/// `isr_stub_table` (e.g. the LAPIC spurious vector at 0xFF). The handler
/// must be a real ISR stub: it has to push a fake error code + vector, set
/// up a TrapFrame, and tail into `isr_common`. Type is fixed to a DPL=0
/// interrupt gate.
void IdtSetGate(u8 vector, u64 handler);

/// Same as IdtSetGate, but installs a DPL=3 interrupt gate — which is what
/// makes `int N` legal from ring 3. Used by the syscall gate at vector
/// 0x80. A DPL=0 gate on a user-reachable vector would #GP(vector) on every
/// `int` from ring 3, which is the correct posture for vectors the user
/// has no business touching; flip to this variant only on vectors that are
/// explicitly part of the user-kernel ABI.
void IdtSetUserGate(u8 vector, u64 handler);

/// Patch an existing gate's IST field so the CPU switches to the
/// indexed IST stack before entering the handler. `ist` is 1..7
/// (0 would disable IST for that gate). Call AFTER IdtInit AND
/// AFTER TssInit — the IST entry in the TSS must hold a valid
/// stack pointer before the first delivery on `vector` or the CPU
/// faults on the empty-stack dereference.
void IdtSetIst(u8 vector, u8 ist);

/// FNV-1a hash over every byte of the 256-entry IDT. Used by the
/// runtime invariant checker to detect any silent modification
/// of the descriptor table (rootkit-style handler swap, data-
/// corruption bug, etc.) after baseline. Called from a stable
/// point AFTER all IDT mutations — typically from
/// `RuntimeCheckerInit`.
u64 IdtHash();

/// Raw byte base of the 4096-byte IDT table. The runtime-checker
/// Heal path uses this to snapshot + restore the table verbatim
/// when a hijack is detected. Not exposed to general callers —
/// direct access bypasses IdtSetGate's validation.
u8* IdtRawBase();

} // namespace customos::arch
