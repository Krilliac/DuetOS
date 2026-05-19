// 16550 UART (COM1 @ 0x3F8) — the DuetOS debug console. TX: guest
// writes to THR stream to host stdout; LSR always reports the
// transmitter empty so the kernel's serial path never blocks. RX:
// host stdin bytes are pushed into a FIFO (slice 2); when the guest
// has enabled the receiver-data IRQ, RxIrqPending() lets the VMM
// route IRQ4 through the IOAPIC.
#pragma once

#include <cstdint>
#include <deque>
#include <mutex>

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

    // Called from the host stdin reader thread.
    void PushRx(uint8_t byte);

    // True when the guest enabled the RX-data interrupt and a byte
    // is waiting — the VMM asserts IOAPIC line 4 (COM1 = IRQ4).
    bool RxIrqPending();

private:
    std::mutex          m_rxLock;
    std::deque<uint8_t> m_rx;
    uint8_t  m_ier  = 0;  // bit0 = RX-data-available IRQ enable
    uint8_t  m_lcr  = 0;  // bit7 = DLAB
    uint8_t  m_mcr  = 0;
    uint8_t  m_scr  = 0;
    uint16_t m_divisor = 1;
};

} // namespace duetos::vmm
