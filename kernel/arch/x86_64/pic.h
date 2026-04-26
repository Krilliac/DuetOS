#pragma once

#include "util/types.h"

/*
 * 8259A Programmable Interrupt Controller — disable.
 *
 * DuetOS uses the LAPIC + (eventually) IOAPIC, not the legacy 8259 PIC.
 * The PIC must still be programmed at boot for two reasons:
 *
 *   1. Its default vector base on a PC is 0x08..0x0F (master) and
 *      0x70..0x77 (slave). 0x08 collides with #DF (double fault); a
 *      stray IRQ before we mask the chips would land on a CPU exception
 *      vector and look like a hardware fault.
 *   2. Some firmware leaves a few IRQ lines unmasked. Even after we
 *      switch to the LAPIC, an unmasked PIC line can fire a spurious
 *      IRQ7/IRQ15 if a device glitches the line.
 *
 * `PicDisable` remaps the chips to 0x20..0x2F (matching the IDT
 * extension in exceptions.S so a stray IRQ now lands on a real handler
 * that just EOIs and returns) and then masks every line. After this the
 * 8259 is functionally inert — only the LAPIC delivers interrupts.
 *
 * Context: kernel, called once during early bring-up before any IRQ
 * source is enabled.
 */

namespace duetos::arch
{

/// Remap and mask the master + slave 8259. Idempotent.
void PicDisable();

} // namespace duetos::arch
