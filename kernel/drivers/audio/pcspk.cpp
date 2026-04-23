#include "pcspk.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/hpet.h"

namespace customos::drivers::audio
{

namespace
{

// PIT base clock: 1.193182 MHz (~1193182 Hz). Historical value
// from the 8253 in the original IBM PC — kept for compatibility
// on every x86 since.
constexpr u32 kPitBaseFreq = 1193182;

// I/O ports.
constexpr u16 kPitCh2DataPort = 0x42;
constexpr u16 kPitCmdPort = 0x43;
constexpr u16 kSpeakerPort = 0x61;

// PIT command: channel 2, low-then-high byte access, square-wave
// generator (mode 3), binary counter.
constexpr u8 kPitCmdCh2Squarewave = 0xB6;

// Speaker-gate bits on port 0x61.
constexpr u8 kSpeakerGate = 0x01; // PIT ch2 gate enable
constexpr u8 kSpeakerData = 0x02; // speaker data-line enable

// Busy-wait for `ms` milliseconds using HPET when available,
// pause-spin otherwise. HPET calibration is done at boot; the
// fallback is deterministic-enough for a beep's duration.
void WaitMs(u32 ms)
{
    const u64 period_fs = arch::HpetPeriodFemtoseconds();
    if (period_fs != 0)
    {
        const u64 ticks = (u64(ms) * 1'000'000'000'000ULL) / period_fs;
        const u64 deadline = arch::HpetReadCounter() + ticks;
        while (arch::HpetReadCounter() < deadline)
            asm volatile("pause" ::: "memory");
        return;
    }
    // Fallback: ~3 MHz pause-loop rate on modern CPUs. Off by
    // a factor of 2-4 depending on microarch; good enough for a
    // beep that's "about a tenth of a second."
    for (u64 i = 0; i < u64(ms) * 300'000ULL; ++i)
        asm volatile("pause" ::: "memory");
}

} // namespace

bool PcSpeakerBeep(u32 freq_hz, u32 duration_ms)
{
    if (freq_hz == 0)
        return false;
    const u32 divider = kPitBaseFreq / freq_hz;
    if (divider < 1 || divider > 0xFFFFu)
        return false; // frequency out of range

    // Program PIT channel 2 for a square wave at the target
    // frequency. Mode + access pattern first, then lo-byte +
    // hi-byte of the divider.
    arch::Outb(kPitCmdPort, kPitCmdCh2Squarewave);
    arch::Outb(kPitCh2DataPort, static_cast<u8>(divider & 0xFF));
    arch::Outb(kPitCh2DataPort, static_cast<u8>((divider >> 8) & 0xFF));

    // Enable speaker: read-modify-write port 0x61 to set the
    // gate + data bits without disturbing the other ISA state.
    const u8 prev = arch::Inb(kSpeakerPort);
    arch::Outb(kSpeakerPort, prev | kSpeakerGate | kSpeakerData);

    WaitMs(duration_ms);

    PcSpeakerStop();
    return true;
}

void PcSpeakerStop()
{
    const u8 prev = arch::Inb(kSpeakerPort);
    arch::Outb(kSpeakerPort, prev & static_cast<u8>(~(kSpeakerGate | kSpeakerData)));
}

} // namespace customos::drivers::audio
