#include "devices/pit8254.h"

#include "host_clock.h"

namespace duetos::vmm
{

namespace
{
uint64_t CountToNs(uint16_t count)
{
    const uint64_t c = (count == 0) ? 65536u : count;
    return c * 1000000000ull / 1193182ull;
}
} // namespace

uint32_t Pit8254::In(uint16_t port)
{
    if (port == kGate)
    {
        uint8_t v = m_gateOn ? 0x01 : 0x00;
        bool expired;
        if (m_replay)
        {
            // Driven by the recorded exit-seq, not the host clock.
            expired = m_forcedExpire;
        }
        else
        {
            expired = m_ch2Armed &&
                      HostNanos() - m_ch2StartNs >= m_ch2IntervalNs;
        }
        if (expired)
        {
            v |= 0x20; // OUT2 high = terminal count reached
            if (!m_ch2Observed)
            {
                m_ch2Observed = true;
                m_ch2EdgePending = true; // record logs this edge
            }
        }
        return v;
    }
    // Counter read-back is not on any path DuetOS exercises; return
    // 0 rather than fabricate a latched value.
    return 0;
}

void Pit8254::Out(uint16_t port, uint32_t value)
{
    const uint8_t b = static_cast<uint8_t>(value & 0xFF);
    switch (port)
    {
    case kCtrl:
    {
        const uint8_t channel = b >> 6;        // 0 = ch0, 2 = ch2
        const uint8_t mode = (b >> 1) & 0x7;   // 0 or 3 in practice
        if (channel == 0)
        {
            m_ch0Lo = true;
            m_ch0Periodic = (mode == 3);
        }
        else if (channel == 2)
        {
            m_ch2Lo = true;
            m_ch2Armed = false; // re-arm on the next count commit
        }
        break;
    }
    case kCh2:
        if (m_ch2Lo)
        {
            m_ch2Count = b;
            m_ch2Lo = false;
        }
        else
        {
            m_ch2Count = static_cast<uint16_t>(
                (m_ch2Count & 0x00FF) | (b << 8));
            m_ch2Lo = true;
            // High-byte write commits + (re)starts the channel
            // (mode 0). Model OUT2 going high after the count's
            // worth of real host time.
            if (m_gateOn)
            {
                m_ch2StartNs = HostNanos();
                m_ch2IntervalNs = CountToNs(m_ch2Count);
                m_ch2Armed = true;
                // Re-arm: a fresh expiry edge will be recorded /
                // replayed for this measurement window.
                m_ch2Observed = false;
                m_forcedExpire = false;
            }
        }
        break;
    case kCh0:
        if (m_ch0Lo)
        {
            m_ch0Count = b;
            m_ch0Lo = false;
        }
        else
        {
            m_ch0Count = static_cast<uint16_t>(
                (m_ch0Count & 0x00FF) | (b << 8));
            m_ch0Lo = true;
        }
        break;
    case kGate:
        m_gateOn = (b & 0x01) != 0;
        break;
    default:
        break;
    }
}

bool Pit8254::TakeCh2ExpireEdge()
{
    const bool e = m_ch2EdgePending;
    m_ch2EdgePending = false;
    return e;
}

uint64_t Pit8254::Channel0PeriodNs() const
{
    if (!m_ch0Periodic)
    {
        return 0;
    }
    return CountToNs(m_ch0Count);
}

} // namespace duetos::vmm
