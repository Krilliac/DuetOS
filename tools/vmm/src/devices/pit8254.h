// Intel 8254 PIT — only the slices DuetOS actually drives:
//
//  * Channel 2 (ports 0x42/0x43, gate+OUT2 via 0x61): the LAPIC
//    timer calibration reference. The kernel programs mode-0 with a
//    ~10 ms count and busy-polls 0x61 bit5 (OUT2) for terminal
//    count while a WHP-emulated LAPIC counter runs. We model OUT2
//    against the real host clock so that ratio is accurate — this
//    is load-bearing for a correct scheduler tick rate.
//
//  * Channel 0 (ports 0x40/0x43, mode 3): the IOAPIC-routed IRQ0
//    periodic tick the kernel falls back to only if LAPIC-timer
//    delivery verification fails. Implemented so that fallback path
//    isn't a dead end; the VMM owns the timer thread that polls
//    Channel0PeriodNs().
#pragma once

#include <cstdint>

namespace duetos::vmm
{

class Pit8254
{
public:
    static constexpr uint16_t kCh0  = 0x40;
    static constexpr uint16_t kCh2  = 0x42;
    static constexpr uint16_t kCtrl = 0x43;
    static constexpr uint16_t kGate = 0x61;

    bool Handles(uint16_t port) const
    {
        return port == kCh0 || port == kCh2 || port == kCtrl ||
               port == kGate;
    }

    uint32_t In(uint16_t port);
    void Out(uint16_t port, uint32_t value);

    // 0 if channel 0 is not running a periodic tick; otherwise the
    // tick period in nanoseconds. Polled by the VMM timer thread.
    uint64_t Channel0PeriodNs() const;

    // Record/replay hooks. In replay the channel-2 OUT2 bit is
    // driven by the recorded exit-seq (ForceExpire) instead of the
    // host clock, so LAPIC calibration reproduces.
    void SetReplay(bool on) { m_replay = on; }
    void ForceExpire() { m_forcedExpire = true; }
    // Record: returns true exactly once, when the guest first
    // observes channel-2 expiry, so the VMM can log it.
    bool TakeCh2ExpireEdge();

private:
    // 8254 nominal input frequency (Hz).
    static constexpr uint64_t kPitHz = 1193182;

    // Channel 2 (calibration).
    uint8_t  m_ch2Latch = 0;   // 0 = expect lo, 1 = expect hi
    uint16_t m_ch2Count = 0;
    bool     m_ch2Lo    = true;
    bool     m_gateOn   = false;
    uint64_t m_ch2StartNs = 0;
    uint64_t m_ch2IntervalNs = 0;
    bool     m_ch2Armed = false;

    // Channel 0 (periodic fallback tick).
    uint16_t m_ch0Count = 0;
    bool     m_ch0Lo    = true;
    bool     m_ch0Periodic = false;

    // Record/replay.
    bool m_replay = false;
    bool m_forcedExpire = false;
    bool m_ch2Observed = false;
    bool m_ch2EdgePending = false;
};

} // namespace duetos::vmm
