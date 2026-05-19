#include "devices/serial16550.h"

#include <cstdio>

namespace duetos::vmm
{

namespace
{
constexpr uint8_t LCR_DLAB = 0x80;
constexpr uint8_t LSR_DR   = 0x01; // data ready
constexpr uint8_t LSR_THRE = 0x20; // transmit holding empty
constexpr uint8_t LSR_TEMT = 0x40; // transmitter empty
} // namespace

uint32_t Serial16550::In(uint16_t port)
{
    const uint16_t off = port - kBase;
    switch (off)
    {
    case 0: // RBR / DLL
    {
        if (m_lcr & LCR_DLAB)
        {
            return m_divisor & 0xFF;
        }
        std::lock_guard<std::mutex> g(m_rxLock);
        if (m_rx.empty())
        {
            return 0;
        }
        uint8_t b = m_rx.front();
        m_rx.pop_front();
        return b;
    }
    case 1: // IER / DLM
        if (m_lcr & LCR_DLAB)
        {
            return (m_divisor >> 8) & 0xFF;
        }
        return m_ier;
    case 2:  // IIR: bit0=0 => interrupt pending; 0x04 => RX data
    {
        std::lock_guard<std::mutex> g(m_rxLock);
        if ((m_ier & 0x01) && !m_rx.empty())
        {
            return 0x04;
        }
        return 0x01;
    }
    case 3:  // LCR
        return m_lcr;
    case 4:  // MCR
        return m_mcr;
    case 5:  // LSR: always ready to TX; DR set when an RX byte waits
    {
        std::lock_guard<std::mutex> g(m_rxLock);
        uint32_t lsr = LSR_THRE | LSR_TEMT;
        if (!m_rx.empty())
        {
            lsr |= LSR_DR;
        }
        return lsr;
    }
    case 6:  // MSR: carrier/DSR/CTS asserted
        return 0xB0;
    case 7:  // scratch
        return m_scr;
    default:
        return 0xFF;
    }
}

void Serial16550::Out(uint16_t port, uint32_t value)
{
    const uint16_t off = port - kBase;
    const uint8_t b = static_cast<uint8_t>(value & 0xFF);
    switch (off)
    {
    case 0:
        if (m_lcr & LCR_DLAB)
        {
            m_divisor = static_cast<uint16_t>((m_divisor & 0xFF00) | b);
        }
        else
        {
            std::fputc(b, stdout);
            std::fflush(stdout);
        }
        break;
    case 1:
        if (m_lcr & LCR_DLAB)
        {
            m_divisor =
                static_cast<uint16_t>((m_divisor & 0x00FF) | (b << 8));
        }
        else
        {
            m_ier = b;
        }
        break;
    case 3:
        m_lcr = b;
        break;
    case 4:
        m_mcr = b;
        break;
    case 7:
        m_scr = b;
        break;
    default:
        break; // FCR / writes to LSR/MSR: ignore
    }
}

void Serial16550::PushRx(uint8_t byte)
{
    std::lock_guard<std::mutex> g(m_rxLock);
    m_rx.push_back(byte);
}

bool Serial16550::RxIrqPending()
{
    std::lock_guard<std::mutex> g(m_rxLock);
    return (m_ier & 0x01) && !m_rx.empty();
}

} // namespace duetos::vmm
