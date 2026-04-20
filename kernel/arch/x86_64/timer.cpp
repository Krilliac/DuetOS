#include "timer.h"

#include "cpu.h"
#include "lapic.h"
#include "serial.h"
#include "traps.h"

#include "../../core/klog.h"
#include "../../sched/sched.h"

namespace customos::arch
{

namespace
{

// PIT runs at this nominal frequency on every PC since IBM XT.
constexpr u64 kPitHz = 1193182;

// Calibration interval. 10 ms gives a good signal/noise ratio against the
// PIT's 838 ns granularity, and avoids overflowing the 32-bit LAPIC count
// register on any reasonable CPU (would need a 429 GHz LAPIC to overflow).
constexpr u64 kCalibrationMs = 10;
constexpr u64 kCalibrationCount = (kPitHz * kCalibrationMs) / 1000; // 11932

// LAPIC timer divide configuration: bits 0,1,3 form the exponent. 0b0011
// (= 0x3) divides the bus clock by 16 — a good middle ground that keeps
// the count register in a useful range without sacrificing resolution.
constexpr u32 kLapicTimerDivBy16 = 0x3;

// LVT Timer register layout (Intel SDM Vol. 3A §10.5.1):
//   bits 7:0   vector
//   bit  16    mask (1 = masked)
//   bits 18:17 mode (00 one-shot, 01 periodic, 10 TSC-deadline)
constexpr u32 kLvtTimerMaskBit = 1U << 16;
constexpr u32 kLvtTimerPeriodicBit = 1U << 17;

// PIT control / data ports.
constexpr u16 kPitControlPort = 0x43;
constexpr u16 kPitChannel2Port = 0x42;
constexpr u16 kPitGatePort = 0x61;
constexpr u8 kPitChan2Mode0 = 0xB0; // chan 2 | lobyte/hibyte | mode 0 | binary
constexpr u8 kPitGateOut2Mask = 1U << 5;

// Single-CPU world: the IRQ handler runs on the same core as any reader,
// so a plain u64 is fine — 8-byte loads are atomic on x86_64 and the
// handler can't race with itself. SMP bring-up will swap this for
// std::atomic<u64> (or __atomic_fetch_add) and the read accessor below
// will become an acquire load.
constinit u64 g_ticks = 0;
constinit u64 g_lapic_ticks_per_period = 0;

void TimerHandler()
{
    ++g_ticks;
    sched::OnTimerTick(g_ticks);

    // Liveness heartbeat at 1 Hz. Debug-level so a release preset's
    // kKlogMinLevel filter can drop the per-second spam while still
    // leaving the full trace available during driver-bring-up debug.
    // The kheartbeat thread (every 5 s) gives the richer stats view.
    if ((g_ticks % kTickFrequencyHz) == 0)
    {
        core::LogWithValue(core::LogLevel::Debug, "arch/timer", "tick", g_ticks);
    }

    // Request a reschedule on every tick. The IRQ dispatcher consults this
    // flag (and clears it) AFTER sending EOI, so we don't context-switch
    // away with the LAPIC in-service bit still set for this vector.
    sched::SetNeedResched();
}

// Spin until the PIT channel 2 OUT line goes high (terminal count reached
// in mode 0). Returns immediately if it's already high.
void WaitPitTerminal()
{
    while ((Inb(kPitGatePort) & kPitGateOut2Mask) == 0)
    {
        // Spin. Calibration runs once at boot, with interrupts disabled.
    }
}

// Drive PIT channel 2 in mode 0 (one-shot, OUT goes high at terminal
// count) so we can poll for a known interval without an IRQ. Returns the
// LAPIC current count at the moment OUT2 went high.
u32 CalibrateLapicTimer()
{
    // Enable channel 2 gate, disable speaker. Bit 0 = gate, bit 1 = speaker.
    const u8 gate = (Inb(kPitGatePort) & 0xFC) | 0x01;
    Outb(kPitGatePort, gate);

    // Program channel 2: mode 0, lobyte/hibyte, binary. Mode 0 holds OUT
    // low after the count is loaded and raises OUT to high at terminal
    // count — exactly what we want to poll on.
    Outb(kPitControlPort, kPitChan2Mode0);

    // Configure LAPIC timer: divide-by-16, masked, periodic-cleared. We
    // start it counting just below by writing the initial-count register.
    LapicWrite(kLapicRegTimerDivide, kLapicTimerDivBy16);
    LapicWrite(kLapicRegLvtTimer, kLvtTimerMaskBit | kTimerVector);

    // Load PIT count low byte, then high byte. Loading the high byte
    // commits the count and (re-)starts the channel.
    Outb(kPitChannel2Port, static_cast<u8>(kCalibrationCount & 0xFF));
    Outb(kPitChannel2Port, static_cast<u8>((kCalibrationCount >> 8) & 0xFF));

    // Start the LAPIC timer immediately by writing a max initial count.
    // From this point on, both clocks are running; the difference between
    // PIT-go and LAPIC-go is one I/O write of latency.
    LapicWrite(kLapicRegTimerInit, 0xFFFFFFFFU);

    WaitPitTerminal();

    // Stop the LAPIC timer ASAP and read the residual count.
    LapicWrite(kLapicRegLvtTimer, kLvtTimerMaskBit);
    const u32 residual = LapicRead(kLapicRegTimerCount);
    return 0xFFFFFFFFU - residual;
}

} // namespace

void TimerInit()
{
    // Calibration must run with interrupts disabled — the PIT poll uses
    // CPU cycles for an accurate window. Caller is responsible for the
    // overall IRQ-disabled bring-up; we assert by checking RFLAGS.IF
    // would be too noisy. Document and trust the call order instead.
    const u32 ticks_per_period = CalibrateLapicTimer();
    g_lapic_ticks_per_period = ticks_per_period;

    // Convert calibration window (10 ms) to the desired period.
    const u64 ticks_per_kernel_tick = (static_cast<u64>(ticks_per_period) * 1000) / (kCalibrationMs * kTickFrequencyHz);

    core::LogWithValue(core::LogLevel::Info, "arch/timer", "calibrated lapic_ticks/10ms", ticks_per_period);
    core::LogWithValue(core::LogLevel::Info, "arch/timer", "ticks_per_kernel_tick", ticks_per_kernel_tick);

    // Install handler before unmasking the LVT — otherwise the very first
    // IRQ would land on a null handler and emit an "unhandled vector"
    // diagnostic at line rate.
    IrqInstall(kTimerVector, TimerHandler);

    // Configure periodic mode at the calibrated count. Writing the initial
    // count register starts the timer counting down; on each underflow it
    // both raises an IRQ and reloads from the initial-count value.
    LapicWrite(kLapicRegTimerDivide, kLapicTimerDivBy16);
    LapicWrite(kLapicRegLvtTimer, kLvtTimerPeriodicBit | kTimerVector);
    LapicWrite(kLapicRegTimerInit, static_cast<u32>(ticks_per_kernel_tick));

    core::LogWithValue(core::LogLevel::Info, "arch/timer", "periodic LAPIC timer armed, vector", kTimerVector);
}

u64 TimerTicks()
{
    return g_ticks;
}

} // namespace customos::arch
