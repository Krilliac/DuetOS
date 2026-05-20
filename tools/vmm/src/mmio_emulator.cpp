#include "mmio_emulator.h"

#include <stdexcept>

namespace duetos::vmm
{

// Thin WHP adapter over the pure DecodeAndApplyMmio core: bind the
// register operand to the vCPU's GPRs and advance RIP by the TRUE
// instruction length the core computes (NOT mem.InstructionByteCount,
// which is only WHP's fetch-window size and over-reports for forms its
// own decoder doesn't recognise — that mis-advance silently corrupts
// guest control flow). All decode logic lives in mmio_decode.cpp so it
// is unit-testable without WHP.
void EmulateMmio(Partition& part, uint32_t vp,
                 const WHV_MEMORY_ACCESS_CONTEXT& mem, MmioDevice& dev)
{
    const uint32_t n = DecodeAndApplyMmio(
        mem.InstructionBytes, mem.InstructionByteCount, mem.Gpa, dev,
        [&](uint32_t r) { return part.GetGpr(vp, r); },
        [&](uint32_t r, uint64_t v) { part.SetGpr(vp, r, v); });

    part.SetRip(vp, part.GetRip(vp) + n);
}

} // namespace duetos::vmm
