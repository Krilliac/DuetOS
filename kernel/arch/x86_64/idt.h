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

} // namespace customos::arch
