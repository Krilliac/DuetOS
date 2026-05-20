// TDD for the pure MMIO instruction decode/apply core.
//
// Regression origin: the release-build DuetOS kernel programs the
// IOAPIC mask-all loop with `ADD dword [ioregsel], eax` (opcode 0x01),
// a read-modify-write the original decoder (MOV-only) aborted on, and
// WHP reported InstructionByteCount=16 (its fetch window, not the true
// 2-byte length). These tests pin both the RMW effect AND the true
// instruction-length computation used for RIP advance.
#include <cstdint>
#include <functional>
#include <vector>

#include "mmio_emulator.h"
#include "test_main.h"

using duetos::vmm::DecodeAndApplyMmio;
using duetos::vmm::MmioDevice;

namespace
{
// One-cell fake device: Read32 returns the cell, Write32 stores it.
struct FakeDev final : MmioDevice
{
    uint32_t cell      = 0;
    uint64_t lastWrite = 0;
    uint32_t Read32(uint64_t) override { return cell; }
    void     Write32(uint64_t gpa, uint32_t v) override
    {
        cell      = v;
        lastWrite = gpa;
    }
};

// 16 GPRs; index == x86 reg number (incl. REX-extended 8..15).
struct Regs
{
    uint64_t r[16] = {};
    std::function<uint64_t(uint32_t)>       get()
    {
        return [this](uint32_t i) { return r[i]; };
    }
    std::function<void(uint32_t, uint64_t)> set()
    {
        return [this](uint32_t i, uint64_t v) { r[i] = v; };
    }
};

uint32_t Apply(const std::vector<uint8_t>& code, uint64_t gpa,
               FakeDev& dev, Regs& gpr)
{
    // WHP delivers up to 16 fetched bytes; pad to mimic the real
    // InstructionByteCount=16 over-report that triggered the bug.
    std::vector<uint8_t> buf = code;
    buf.resize(16, 0x90);
    return DecodeAndApplyMmio(buf.data(), 16, gpa, dev, gpr.get(),
                              gpr.set());
}
} // namespace

// `01 00` = ADD dword [rax], eax. eax=5, cell=10 -> cell=15, len=2.
TEST(mmio_add_rm32_r32_rmw)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell  = 10;
    gpr.r[0]  = 5; // eax (reg field = 0)
    uint32_t n = Apply({0x01, 0x00}, 0xFEC00000, dev, gpr);
    CHECK_EQ(dev.cell, 15u);
    CHECK_EQ(n, 2u);
}

// `09 00` = OR dword [rax], eax.  0x0F00 | 0x00F0 -> 0x0FF0.
TEST(mmio_or_rm32_r32_rmw)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell = 0x0F00;
    gpr.r[0] = 0x00F0;
    uint32_t n = Apply({0x09, 0x00}, 0xFEC00010, dev, gpr);
    CHECK_EQ(dev.cell, 0x0FF0u);
    CHECK_EQ(n, 2u);
}

// `21 00` = AND dword [rax], eax — the IOAPIC unmask `v &= ~mask` form.
TEST(mmio_and_rm32_r32_rmw)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell = 0xFFFFFFFF;
    gpr.r[0] = 0xFFFEFFFF; // clear bit 16 (the mask pin)
    uint32_t n = Apply({0x21, 0x00}, 0xFEC00010, dev, gpr);
    CHECK_EQ(dev.cell, 0xFFFEFFFFu);
    CHECK_EQ(n, 2u);
}

// `31 00` = XOR dword [rax], eax.
TEST(mmio_xor_rm32_r32_rmw)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell = 0xAAAA5555;
    gpr.r[0] = 0xFFFFFFFF;
    Apply({0x31, 0x00}, 0xFEC00010, dev, gpr);
    CHECK_EQ(dev.cell, 0x5555AAAAu);
}

// Regression: `89 08` = MOV dword [rax], ecx (store). Still works,
// length 2.
TEST(mmio_mov_store_regression)
{
    FakeDev dev;
    Regs    gpr;
    gpr.r[1]  = 0xABCD; // ecx (reg field = 1)
    uint32_t n = Apply({0x89, 0x08}, 0xFEC00000, dev, gpr);
    CHECK_EQ(dev.cell, 0xABCDu);
    CHECK_EQ(n, 2u);
}

// Regression: `8B 08` = MOV ecx, dword [rax] (load) zero-extends.
TEST(mmio_mov_load_regression)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell = 0x1234;
    gpr.r[1] = 0xFFFFFFFFFFFFFFFFull;
    Apply({0x8B, 0x08}, 0xFEC00010, dev, gpr);
    CHECK_EQ(gpr.r[1], 0x1234ull); // upper 32 zeroed
}

// REX.R extends the reg field: `44 01 00` = ADD [rax], r8d.
TEST(mmio_rexr_extends_reg)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell = 1;
    gpr.r[8] = 7; // r8d
    uint32_t n = Apply({0x44, 0x01, 0x00}, 0xFEC00000, dev, gpr);
    CHECK_EQ(dev.cell, 8u);
    CHECK_EQ(n, 3u); // REX + opcode + modrm
}

// True length with disp8: `01 40 10` = ADD [rax+0x10], eax. len 3.
TEST(mmio_len_modrm_disp8)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell = 100;
    gpr.r[0] = 1;
    uint32_t n = Apply({0x01, 0x40, 0x10}, 0xFEC00000, dev, gpr);
    CHECK_EQ(dev.cell, 101u);
    CHECK_EQ(n, 3u);
}

// True length with disp32: `01 80 00 10 00 00` = ADD [rax+0x1000],
// eax. len 6 — proves we do NOT trust WHP's count of 16.
TEST(mmio_len_modrm_disp32)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell = 0;
    gpr.r[0] = 0x55;
    uint32_t n =
        Apply({0x01, 0x80, 0x00, 0x10, 0x00, 0x00}, 0xFEC00000, dev,
              gpr);
    CHECK_EQ(dev.cell, 0x55u);
    CHECK_EQ(n, 6u);
}

// True length with SIB + disp32: `01 04 25 00 00 00 00` =
// ADD [disp32], eax (mod=00,rm=100 SIB, base=101 -> disp32). len 7.
TEST(mmio_len_sib_disp32)
{
    FakeDev dev;
    Regs    gpr;
    dev.cell = 2;
    gpr.r[0] = 3;
    uint32_t n = Apply({0x01, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00},
                       0xFEC00000, dev, gpr);
    CHECK_EQ(dev.cell, 5u);
    CHECK_EQ(n, 7u);
}

// C7 /0 imm32 with disp8: `C7 40 10 EF BE AD DE` =
// MOV dword [rax+0x10], 0xDEADBEEF. imm read from instruction end;
// len 7.
TEST(mmio_c7_imm32_with_disp8)
{
    FakeDev dev;
    Regs    gpr;
    uint32_t n = Apply({0xC7, 0x40, 0x10, 0xEF, 0xBE, 0xAD, 0xDE},
                       0xFEC00010, dev, gpr);
    CHECK_EQ(dev.cell, 0xDEADBEEFu);
    CHECK_EQ(n, 7u);
}
