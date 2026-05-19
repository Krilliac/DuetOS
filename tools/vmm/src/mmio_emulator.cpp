#include "mmio_emulator.h"

#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace duetos::vmm
{

void EmulateMmio(Partition& part, uint32_t vp,
                 const WHV_MEMORY_ACCESS_CONTEXT& mem, MmioDevice& dev)
{
    const uint8_t* p = mem.InstructionBytes;
    const uint32_t len = mem.InstructionByteCount;
    if (len == 0 || len > 16)
    {
        throw std::runtime_error("MMIO: missing instruction bytes");
    }

    size_t i = 0;
    bool rexR = false;

    // Skip a 0x66/0xF2/0xF3/segment prefix defensively (not expected
    // for the IOAPIC path) then capture an optional REX prefix.
    while (i < len && (p[i] == 0x66 || p[i] == 0xF2 || p[i] == 0xF3 ||
                       p[i] == 0x2E || p[i] == 0x3E || p[i] == 0x26 ||
                       p[i] == 0x64 || p[i] == 0x65 || p[i] == 0x36))
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
    const uint8_t mod = modrm >> 6;
    uint8_t reg = (modrm >> 3) & 7;
    if (rexR)
    {
        reg |= 0x8;
    }
    if (mod == 3)
    {
        throw std::runtime_error("MMIO: register-direct ModRM (not MMIO)");
    }

    const uint64_t gpa = mem.Gpa;

    switch (opcode)
    {
    case 0x8B: // MOV r32, r/m32  — load from device into reg
    {
        const uint32_t val = dev.Read32(gpa);
        part.SetGpr(vp, reg, val); // 32-bit write zero-extends
        break;
    }
    case 0x89: // MOV r/m32, r32  — store reg into device
    {
        const uint32_t val =
            static_cast<uint32_t>(part.GetGpr(vp, reg) & 0xFFFFFFFFu);
        dev.Write32(gpa, val);
        break;
    }
    case 0xC7: // MOV r/m32, imm32 — store immediate into device
    {
        if ((modrm & 0x38) != 0)
        {
            throw std::runtime_error("MMIO: C7 with reg != /0");
        }
        if (i + 4 > len)
        {
            throw std::runtime_error("MMIO: C7 missing imm32");
        }
        uint32_t imm = 0;
        std::memcpy(&imm, p + (len - 4), 4); // imm32 is the trailer
        dev.Write32(gpa, imm);
        break;
    }
    default:
    {
        char buf[64];
        std::snprintf(buf, sizeof(buf),
                      "MMIO: unsupported opcode 0x%02X", opcode);
        throw std::runtime_error(buf);
    }
    }

    part.SetRip(vp, part.GetRip(vp) + len);
}

} // namespace duetos::vmm
