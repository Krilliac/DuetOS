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

/// Patch an existing gate's IST field so the CPU switches to the
/// indexed IST stack before entering the handler. `ist` is 1..7
/// (0 would disable IST for that gate). Call AFTER IdtInit AND
/// AFTER TssInit — the IST entry in the TSS must hold a valid
/// stack pointer before the first delivery on `vector` or the CPU
/// faults on the empty-stack dereference.
void IdtSetIst(u8 vector, u8 ist);

} // namespace customos::arch
