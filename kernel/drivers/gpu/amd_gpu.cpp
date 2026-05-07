/*
 * DuetOS — AMD Radeon (GFX9+) driver scaffold: implementation.
 *
 * See `amd_gpu.h` for v0 scope. This TU owns the BAR5 mapping
 * for AMD parts — the shared `gpu.cpp` discovery layer maps BAR0
 * (VRAM) but the register file lives at BAR5 on GFX9 onwards.
 */

#include "drivers/gpu/amd_gpu.h"

#include "arch/x86_64/serial.h"
#include "diag/fix_journal.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/paging.h"
#include "mm/zone.h"

namespace duetos::drivers::gpu::amd
{

namespace
{

void* g_mmio_regs = nullptr;
u64 g_mmio_phys = 0;
u64 g_mmio_bytes = 0;
bool g_brought_up = false;

u32 Mmio32(u64 offset)
{
    if (g_mmio_regs == nullptr || offset + 4 > g_mmio_bytes)
        return 0xFFFFFFFFu;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(g_mmio_regs) + offset);
    return *p;
}

const char* GrbmStatusTag(u32 grbm)
{
    if (grbm == 0xFFFFFFFFu)
        return "decode-failed";
    // RDNA2 reports 0x40000000 when idle; older parts report 0.
    if (grbm == 0 || grbm == 0x40000000u)
        return "idle";
    if ((grbm & (1u << 31)) != 0)
        return "gui-busy";
    return "active";
}

} // namespace

void Probe(GpuInfo& g)
{
    if (g_mmio_regs == nullptr)
    {
        // Map BAR5. We need the original PCI device cache to size-
        // probe; gpu.cpp stored bus/dev/func on the GpuInfo for
        // exactly this reason.
        pci::DeviceAddress addr = {};
        addr.bus = g.bus;
        addr.device = g.device;
        addr.function = g.function;
        const pci::Bar bar5 = pci::PciReadBar(addr, 5);
        if (bar5.size == 0 || bar5.is_io)
        {
            arch::SerialWrite("[gpu/amd] BAR5 not present or I/O — driver scaffold inactive\n");
            return;
        }
        const u64 map_bytes = (bar5.size > kAmdMmioCap) ? kAmdMmioCap : bar5.size;
        g_mmio_regs = mm::MapMmio(bar5.address, map_bytes);
        g_mmio_phys = bar5.address;
        g_mmio_bytes = map_bytes;
        if (g_mmio_regs == nullptr)
        {
            arch::SerialWrite("[gpu/amd] BAR5 map failed (MMIO arena exhausted?)\n");
            return;
        }
        arch::SerialWrite("[gpu/amd] BAR5 mapped: phys=");
        arch::SerialWriteHex(g_mmio_phys);
        arch::SerialWrite(" bytes=");
        arch::SerialWriteHex(g_mmio_bytes);
        arch::SerialWrite("\n");
    }

    const u32 grbm = Mmio32(kAmdRegGrbmStatus);
    const u32 rlc = Mmio32(kAmdRegRlcGpmStat);
    arch::SerialWrite("[gpu/amd] GRBM_STATUS=");
    arch::SerialWriteHex(grbm);
    arch::SerialWrite(" (");
    arch::SerialWrite(GrbmStatusTag(grbm));
    arch::SerialWrite(") RLC_GPM_STAT=");
    arch::SerialWriteHex(rlc);
    arch::SerialWrite("\n");

    // Stash the GRBM read so the cross-vendor diagnostic can show
    // it next to Intel's BAR0[0] and NVIDIA's PMC_BOOT_0.
    g.probe_reg = grbm;
    g.mmio_live = (grbm != 0xFFFFFFFFu);
}

::duetos::core::Result<void> Bringup(GpuInfo& g)
{
    KLOG_TRACE_SCOPE("drivers/gpu/amd", "Bringup");
    if (g_brought_up)
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};
    if (g_mmio_regs == nullptr || !g.mmio_live)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};

    auto r = mm::AllocDmaCoherent(kAmdCpRingBytes, mm::Zone::Dma32);
    if (!r.has_value())
        return ::duetos::core::Err{r.error()};
    const mm::DmaBuffer ring = r.value();

    arch::SerialWrite("[gpu/amd] cp_ring_phys=");
    arch::SerialWriteHex(ring.phys);
    arch::SerialWrite(" bytes=");
    arch::SerialWriteHex(kAmdCpRingBytes);
    arch::SerialWrite(" — would write CP_RB0_BASE/_CNTL but MEC firmware loader is gated\n");

    // STUB: Real bring-up loads the MEC firmware blob into a
    // private VRAM region, programs CP_RB0_BASE_HI / CP_RB0_BASE
    // / CP_RB0_CNTL with our ring physical address + log2 size,
    // then signals the SMU to wake the GFX engine. None of those
    // dependencies are wired up in v0.
    FIX_NOTE_STUB("drivers/gpu/amd_gpu.cpp:CP_RB0", "wire MEC firmware load + CP ring submit");
    mm::FreeDmaCoherent(ring);

    return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
}

bool IsBroughtUp()
{
    return g_brought_up;
}

void* MmioRegs()
{
    return g_mmio_regs;
}

} // namespace duetos::drivers::gpu::amd
