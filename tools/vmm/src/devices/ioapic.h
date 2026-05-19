// I/O APIC (MMIO @ 0xFEC00000) — 24-entry redirection table. WHP's
// xApic mode emulates the *local* APIC but not the I/O APIC, so the
// VMM owns it: the kernel programs redirection entries through the
// IOREGSEL/IOWIN window, and device IRQ lines (COM1 = IRQ4, PIT
// channel-0 = IRQ0) are translated here into LAPIC interrupt
// requests via the injector.
#pragma once

#include <cstdint>
#include <functional>

#include "mmio_emulator.h"

namespace duetos::vmm
{

class IoApic final : public MmioDevice
{
public:
    static constexpr uint64_t kBase = 0xFEC00000ull;
    static constexpr uint64_t kSize = 0x1000;
    static constexpr uint32_t kEntries = 24;

    bool Handles(uint64_t gpa) const
    {
        return gpa >= kBase && gpa < kBase + kSize;
    }

    // (vector, destApicId, levelTriggered) -> inject into the LAPIC.
    using Injector = std::function<void(uint32_t, uint32_t, bool)>;
    void SetInjector(Injector inj) { m_inject = std::move(inj); }

    uint32_t Read32(uint64_t gpa) override;
    void Write32(uint64_t gpa, uint32_t value) override;

    // Asserts ISA IRQ line `irq`. Edge-triggered device pulse: looks
    // up the redirection entry and injects if unmasked.
    void RaiseLine(uint32_t irq);

private:
    uint32_t RegRead(uint32_t reg) const;
    void RegWrite(uint32_t reg, uint32_t value);

    uint32_t m_sel = 0;
    uint32_t m_id  = 0;
    uint64_t m_redir[kEntries] = {}; // [vector..mask..dest]
    Injector m_inject;
};

} // namespace duetos::vmm
