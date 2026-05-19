#include "devices/ioapic.h"

namespace duetos::vmm
{

namespace
{
constexpr uint32_t kRegId  = 0x00;
constexpr uint32_t kRegVer = 0x01;
constexpr uint32_t kRegArb = 0x02;
constexpr uint32_t kRedirBase = 0x10;

constexpr uint64_t kMaskBit = 1ull << 16;
} // namespace

uint32_t IoApic::RegRead(uint32_t reg) const
{
    if (reg == kRegId)
    {
        return (m_id & 0xF) << 24;
    }
    if (reg == kRegVer)
    {
        // version 0x20, max redirection entry = kEntries-1 in 23:16.
        return 0x20u | ((kEntries - 1) << 16);
    }
    if (reg == kRegArb)
    {
        return (m_id & 0xF) << 24;
    }
    if (reg >= kRedirBase && reg < kRedirBase + kEntries * 2)
    {
        const uint32_t idx = (reg - kRedirBase) / 2;
        const uint64_t e = m_redir[idx];
        return (reg & 1) ? static_cast<uint32_t>(e >> 32)
                         : static_cast<uint32_t>(e & 0xFFFFFFFFu);
    }
    return 0;
}

void IoApic::RegWrite(uint32_t reg, uint32_t value)
{
    if (reg == kRegId)
    {
        m_id = (value >> 24) & 0xF;
        return;
    }
    if (reg >= kRedirBase && reg < kRedirBase + kEntries * 2)
    {
        const uint32_t idx = (reg - kRedirBase) / 2;
        uint64_t& e = m_redir[idx];
        if (reg & 1)
        {
            e = (e & 0x00000000FFFFFFFFull) |
                (static_cast<uint64_t>(value) << 32);
        }
        else
        {
            e = (e & 0xFFFFFFFF00000000ull) | value;
        }
    }
    // VER/ARB and unknown registers are read-only / ignored.
}

uint32_t IoApic::Read32(uint64_t gpa)
{
    const uint64_t off = gpa - kBase;
    if (off == 0x00)
    {
        return m_sel;
    }
    if (off == 0x10)
    {
        return RegRead(m_sel);
    }
    return 0;
}

void IoApic::Write32(uint64_t gpa, uint32_t value)
{
    const uint64_t off = gpa - kBase;
    if (off == 0x00)
    {
        m_sel = value & 0xFF;
    }
    else if (off == 0x10)
    {
        RegWrite(m_sel, value);
    }
}

void IoApic::RaiseLine(uint32_t irq)
{
    if (irq >= kEntries || !m_inject)
    {
        return;
    }
    const uint64_t e = m_redir[irq];
    if (e & kMaskBit)
    {
        return; // line masked
    }
    const uint32_t vector = static_cast<uint32_t>(e & 0xFF);
    if (vector < 0x10)
    {
        return; // unprogrammed entry
    }
    const uint32_t dest = static_cast<uint32_t>((e >> 56) & 0xFF);
    const bool level = (e & (1ull << 15)) != 0;
    m_inject(vector, dest, level);
}

} // namespace duetos::vmm
