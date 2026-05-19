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
        if (m_lcr & LCR_DLAB)
        {
            return m_divisor & 0xFF;
        }
        return 0; // no RX in v0
    case 1: // IER / DLM
        if (m_lcr & LCR_DLAB)
        {
            return (m_divisor >> 8) & 0xFF;
        }
        return m_ier;
    case 2:  // IIR: no interrupt pending
        return 0x01;
    case 3:  // LCR
        return m_lcr;
    case 4:  // MCR
        return m_mcr;
    case 5:  // LSR: always ready to transmit, never any RX byte
        return LSR_THRE | LSR_TEMT;
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

} // namespace duetos::vmm
