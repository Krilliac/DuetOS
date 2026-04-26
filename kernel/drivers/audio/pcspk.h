#pragma once

#include "util/types.h"

/*
 * DuetOS — PC Speaker driver, v0.
 *
 * Classic 8253/8254 PIT channel 2 driving the motherboard
 * speaker gate at I/O port 0x61. Present on every x86 since
 * 1981; no PCI enumeration, no BAR map, no interrupts. Produces
 * a single tone by programming the PIT divider to divide the
 * 1.193182 MHz base clock down to the target frequency, then
 * enabling the speaker gate.
 *
 * QEMU exposes the speaker only when `-machine pcspk-audiodev=<aud>`
 * is passed; on real hardware it's always wired. Either way the
 * driver programs the PIT correctly — QEMU without a backing
 * audiodev just silently drops the waveform.
 *
 * Scope:
 *   - One-shot `Beep(freq_hz, duration_ms)` — busy-waits for the
 *     duration, then disables the speaker. Blocks the calling
 *     task; don't call from IRQ.
 *   - No channel-1 timer preservation: PC timer is channel 0, so
 *     programming channel 2 doesn't disturb the scheduler tick.
 *
 * Context: kernel. Callable from task context only.
 */

namespace duetos::drivers::audio
{

/// Emit a tone at `freq_hz` (10..20000 sensible) for
/// `duration_ms` milliseconds. Busy-waits using the HPET (or
/// pause-loop fallback). Returns false if frequency is outside
/// the representable PIT divider range.
bool PcSpeakerBeep(u32 freq_hz, u32 duration_ms);

/// Immediate stop — kills any in-progress beep by clearing the
/// speaker gate bits in port 0x61. Safe from IRQ context.
void PcSpeakerStop();

} // namespace duetos::drivers::audio
