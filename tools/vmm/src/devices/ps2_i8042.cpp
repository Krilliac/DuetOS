#include "devices/ps2_i8042.h"

namespace duetos::vmm
{
void Ps2I8042::Refill()
{
    if (m_full) return;
    if (!m_kbd.empty())
    {
        m_data = m_kbd.front(); m_kbd.pop_front();
        m_dataIsAux = false; m_full = true;
        if (m_raise) m_raise(1);
    }
    else if (!m_aux.empty())
    {
        m_data = m_aux.front(); m_aux.pop_front();
        m_dataIsAux = true; m_full = true;
        if (m_raise) m_raise(12);
    }
}

uint8_t Ps2I8042::In(uint16_t port)
{
    std::lock_guard<std::mutex> g(m_mx);
    if (port == 0x64)
    {
        uint8_t st = 0;
        if (m_full)      st |= 0x01;
        if (m_dataIsAux) st |= 0x20;
        st |= 0x04; // system-flag: controller passed self-test
        return st;
    }
    uint8_t v = m_data;
    m_full = false;
    Refill();
    return v;
}

void Ps2I8042::Out(uint16_t port, uint8_t v)
{
    std::lock_guard<std::mutex> g(m_mx);
    if (port == 0x60)
    {
        if (m_pendingCmd == 0x60) { m_cfg = v; m_pendingCmd = 0; return; }
        if (m_pendingCmd == 0xD4) { m_pendingCmd = 0; m_aux.push_back(0xFA); Refill(); return; }
        // Device command to keyboard: ACK everything; reset also yields 0xAA.
        m_kbd.push_back(0xFA);
        if (v == 0xFF) m_kbd.push_back(0xAA);
        Refill();
        return;
    }
    // Controller commands via 0x64.
    switch (v)
    {
    case 0x20: m_kbd.push_back(m_cfg); Refill(); break;  // read config
    case 0x60: m_pendingCmd = 0x60; break;               // write config (data follows on 0x60)
    case 0xA7: m_cfg |=  0x20; break;                    // disable port 2
    case 0xA8: m_cfg &= ~0x20; break;                    // enable port 2 (unmute aux)
    case 0xAA: m_kbd.push_back(0x55); Refill(); break;   // controller self-test → pass
    case 0xA9: m_kbd.push_back(0x00); Refill(); break;   // port 2 interface test → pass
    case 0xAB: m_kbd.push_back(0x00); Refill(); break;   // port 1 interface test → pass
    case 0xAD: break;                                     // disable port 1 (no response)
    case 0xAE: break;                                     // enable port 1 (no response)
    case 0xD4: m_pendingCmd = 0xD4; break;               // next byte on 0x60 → aux device
    default:   break;
    }
}

void Ps2I8042::PushKey(const uint8_t* b, size_t n)
{
    std::lock_guard<std::mutex> g(m_mx);
    for (size_t i = 0; i < n; ++i) m_kbd.push_back(b[i]);
    Refill();
}

void Ps2I8042::PushAux(const uint8_t* b, size_t n)
{
    std::lock_guard<std::mutex> g(m_mx);
    for (size_t i = 0; i < n; ++i) m_aux.push_back(b[i]);
    Refill();
}
} // namespace duetos::vmm
