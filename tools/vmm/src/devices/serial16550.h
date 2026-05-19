// 16550 UART (COM1 @ 0x3F8) — the DuetOS debug console. v0 is
// TX-only: guest writes to THR are streamed to the host stdout;
// LSR always reports the transmitter empty so the kernel's early
// serial path never blocks. RX (host stdin -> guest, with the
// receiver IRQ) lands in slice 2.
#pragma once

#include <cstdint>

namespace duetos::vmm
{

class Serial16550
{
public:
    static constexpr uint16_t kBase = 0x3F8;
    static constexpr uint16_t kEnd  = 0x3FF;

    bool Handles(uint16_t port) const
    {
        return port >= kBase && port <= kEnd;
    }

    // I/O-port dispatch. `value` is up to 32 bits; only the low byte
    // is meaningful for the UART.
    uint32_t In(uint16_t port);
    void Out(uint16_t port, uint32_t value);

private:
    uint8_t m_ier  = 0;
    uint8_t m_lcr  = 0;   // bit7 = DLAB
    uint8_t m_mcr  = 0;
    uint8_t m_scr  = 0;
    uint16_t m_divisor = 1;
};

} // namespace duetos::vmm
