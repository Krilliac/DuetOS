// Pure MMIO instruction decode + apply. No WHP dependency so it is
// unit-testable (see tests/test_mmio_decode.cpp).
//
// Scope: the instruction forms DuetOS actually issues against the
// IOAPIC window — 32-bit MOV load/store/imm (debug codegen) plus the
// read-modify-write ALU forms release codegen folds the mask/unmask
// loops into (ADD/OR/AND/XOR r/m32, r32). The effective address is
// NOT computed (WHP already hands us the faulting GPA); we only need
// the reg operand, the 32-bit width, and the TRUE instruction length
// for RIP advance.
#include "mmio_emulator.h"

#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace duetos::vmm
{

uint32_t DecodeAndApplyMmio(
    const uint8_t* p, uint32_t len, uint64_t gpa, MmioDevice& dev,
    const std::function<uint64_t(uint32_t)>& getReg,
    const std::function<void(uint32_t, uint64_t)>& setReg)
{
    if (len == 0 || len > 16)
    {
        throw std::runtime_error("MMIO: missing instruction bytes");
    }

    uint32_t i    = 0;
    bool     rexR = false;

    // Legacy prefixes (incl. LOCK 0xF0 — RMW to a device register is
    // idiomatically lock-prefixed; the VMM is single-vCPU so the
    // atomicity guarantee is moot, skipping it is correct here).
    while (i < len &&
           (p[i] == 0x66 || p[i] == 0xF2 || p[i] == 0xF3 ||
            p[i] == 0xF0 || p[i] == 0x2E || p[i] == 0x3E ||
            p[i] == 0x26 || p[i] == 0x64 || p[i] == 0x65 ||
            p[i] == 0x36))
    {
        ++i;
    }
    if (i < len && (p[i] & 0xF0) == 0x40)
    {
        rexR = (p[i] & 0x04) != 0; // REX.R extends the reg field
        ++i;
    }
    if (i >= len)
    {
        throw std::runtime_error("MMIO: truncated instruction");
    }

    const uint8_t opcode = p[i++];
    if (i >= len)
    {
        throw std::runtime_error("MMIO: missing ModRM");
    }
    const uint8_t modrm = p[i++];
    const uint8_t mod   = modrm >> 6;
    const uint8_t rm    = modrm & 7;
    uint8_t       reg   = (modrm >> 3) & 7;
    if (rexR)
    {
        reg |= 0x8;
    }
    if (mod == 3)
    {
        throw std::runtime_error(
            "MMIO: register-direct ModRM (not MMIO)");
    }

    // Consume SIB + displacement so `i` lands past the addressing
    // bytes — this yields the TRUE instruction length (WHP's
    // InstructionByteCount over-reports its 16-byte fetch window for
    // forms its own decoder doesn't recognise).
    if (rm == 4) // SIB byte present
    {
        if (i >= len)
        {
            throw std::runtime_error("MMIO: missing SIB");
        }
        const uint8_t base = p[i++] & 7;
        if (mod == 0 && base == 5)
        {
            i += 4; // disp32, no base register
        }
        else if (mod == 1)
        {
            i += 1; // disp8
        }
        else if (mod == 2)
        {
            i += 4; // disp32
        }
    }
    else
    {
        if (mod == 0 && rm == 5)
        {
            i += 4; // RIP-relative disp32
        }
        else if (mod == 1)
        {
            i += 1; // disp8
        }
        else if (mod == 2)
        {
            i += 4; // disp32
        }
    }

    const uint32_t immLen = (opcode == 0xC7) ? 4u : 0u;
    const uint32_t total  = i + immLen;
    if (total > len)
    {
        throw std::runtime_error(
            "MMIO: instruction exceeds fetched bytes");
    }

    switch (opcode)
    {
    case 0x8B: // MOV r32, r/m32 — load device into reg (zero-extends)
        setReg(reg, dev.Read32(gpa));
        break;

    case 0x89: // MOV r/m32, r32 — store reg into device
        dev.Write32(gpa,
                    static_cast<uint32_t>(getReg(reg) & 0xFFFFFFFFu));
        break;

    case 0xC7: // MOV r/m32, imm32 — store immediate into device
    {
        if ((modrm & 0x38) != 0)
        {
            throw std::runtime_error("MMIO: C7 with reg != /0");
        }
        uint32_t imm = 0;
        std::memcpy(&imm, p + (total - 4), 4); // imm32 is the trailer
        dev.Write32(gpa, imm);
        break;
    }

    // Read-modify-write ALU forms (OP r/m32, r32): release codegen
    // folds the IOAPIC mask-all (`+=`) and unmask (`&= ~`, `|=`)
    // sequences into these. EFLAGS are intentionally NOT updated —
    // GAP: every MMIO consumer here branches on a separate CMP, never
    // on the result of an MMIO RMW. Revisit if that ceases to hold.
    case 0x01: // ADD
    case 0x09: // OR
    case 0x21: // AND
    case 0x31: // XOR
    {
        const uint32_t s =
            static_cast<uint32_t>(getReg(reg) & 0xFFFFFFFFu);
        uint32_t v = dev.Read32(gpa);
        switch (opcode)
        {
        case 0x01: v += s; break;
        case 0x09: v |= s; break;
        case 0x21: v &= s; break;
        case 0x31: v ^= s; break;
        }
        dev.Write32(gpa, v);
        break;
    }

    default:
    {
        // Actionable gap report: opcode, ModRM, GPA, raw bytes — names
        // exactly which form a future decoder addition must handle.
        char buf[160];
        int  n = std::snprintf(
            buf, sizeof(buf),
            "MMIO: unsupported opcode 0x%02X modrm=0x%02X gpa=0x%llx "
            "len=%u bytes=",
            opcode, modrm, static_cast<unsigned long long>(gpa), len);
        for (uint32_t b = 0; b < len && n > 0 &&
                             n < static_cast<int>(sizeof(buf)) - 3;
             ++b)
        {
            n += std::snprintf(buf + n, sizeof(buf) - n, "%02X", p[b]);
        }
        throw std::runtime_error(buf);
    }
    }

    return total;
}

} // namespace duetos::vmm
