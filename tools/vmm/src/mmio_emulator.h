// Minimal MMIO instruction emulator. WHP has no built-in MMIO
// emulator: an access to unmapped guest-physical memory produces a
// MemoryAccess exit carrying the faulting instruction bytes, and the
// VMM must execute the instruction's effect itself.
//
// SCOPE (deliberately narrow): the only MMIO DuetOS performs that
// reaches us is the IOAPIC window, accessed through `volatile u32*`
// (see kernel/arch/x86_64/ioapic.cpp). clang lowers that to aligned
// 32-bit MOVs, so we decode exactly:
//   89 /r   MOV r/m32, r32     (store: device <- reg)
//   8B /r   MOV r32, r/m32     (load:  reg <- device)
//   C7 /0   MOV r/m32, imm32   (store immediate)
// with an optional REX prefix (W=0). The effective address is NOT
// computed — WHP already hands us the faulting GPA — so only the
// direction, the reg operand, and the 32-bit width matter. Anything
// outside this set throws (a louder, traceable failure than silent
// misexecution).
#pragma once

#include <cstdint>

#include "whp.h"

namespace duetos::vmm
{

class MmioDevice
{
public:
    virtual ~MmioDevice() = default;
    virtual uint32_t Read32(uint64_t gpa) = 0;
    virtual void Write32(uint64_t gpa, uint32_t value) = 0;
};

// Emulates the faulting instruction described by `mem` against
// `dev`, updating vCPU `vp`'s registers and RIP. Throws
// std::runtime_error on an instruction form outside the scoped set.
void EmulateMmio(Partition& part, uint32_t vp,
                 const WHV_MEMORY_ACCESS_CONTEXT& mem, MmioDevice& dev);

} // namespace duetos::vmm
