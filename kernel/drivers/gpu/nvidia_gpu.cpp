/*
 * DuetOS — NVIDIA GeForce (Turing+) driver scaffold: implementation.
 *
 * See `nvidia_gpu.h` for v0 scope.
 */

#include "drivers/gpu/nvidia_gpu.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/zone.h"

namespace duetos::drivers::gpu::nvidia
{

namespace
{

bool g_brought_up = false;

u32 Mmio32(const GpuInfo& g, u64 offset)
{
    if (g.mmio_virt == nullptr || offset + 4 > g.mmio_size)
        return 0xFFFFFFFFu;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(g.mmio_virt) + offset);
    return *p;
}

const char* PfifoIntrTag(u32 intr)
{
    if (intr == 0xFFFFFFFFu)
        return "decode-failed";
    if (intr == 0)
        return "idle";
    return "pending";
}

} // namespace

void Probe(GpuInfo& g)
{
    if (g.mmio_virt == nullptr)
    {
        arch::SerialWrite("[gpu/nvidia] BAR0 not mapped — probe skipped\n");
        return;
    }

    const u32 boot0 = Mmio32(g, kNvidiaRegPmcBoot0);
    const u32 intren = Mmio32(g, kNvidiaRegPmcIntrEn0);
    const u32 pfifo_intr = Mmio32(g, kNvidiaRegPfifoIntr);
    const u32 pfb = Mmio32(g, kNvidiaRegPfbPriRd);

    arch::SerialWrite("[gpu/nvidia] PMC_BOOT_0=");
    arch::SerialWriteHex(boot0);
    arch::SerialWrite(" PMC_INTR_EN_0=");
    arch::SerialWriteHex(intren);
    arch::SerialWrite(" PFIFO_INTR=");
    arch::SerialWriteHex(pfifo_intr);
    arch::SerialWrite(" (");
    arch::SerialWrite(PfifoIntrTag(pfifo_intr));
    arch::SerialWrite(") PFB[0]=");
    arch::SerialWriteHex(pfb);
    arch::SerialWrite("\n");

    g.probe_reg = boot0;
    g.mmio_live = (boot0 != 0xFFFFFFFFu);
}

::duetos::core::Result<void> Bringup(GpuInfo& g)
{
    KLOG_TRACE_SCOPE("drivers/gpu/nvidia", "Bringup");
    if (g_brought_up)
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};
    if (g.mmio_virt == nullptr || !g.mmio_live)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};

    auto r = mm::AllocDmaCoherent(kNvidiaPushbufBytes, mm::Zone::Dma32);
    if (!r.has_value())
        return ::duetos::core::Err{r.error()};
    const mm::DmaBuffer pb = r.value();

    arch::SerialWrite("[gpu/nvidia] pushbuffer_phys=");
    arch::SerialWriteHex(pb.phys);
    arch::SerialWrite(" bytes=");
    arch::SerialWriteHex(kNvidiaPushbufBytes);
    arch::SerialWrite(" — would arm a PFIFO channel but GSP firmware loader is gated\n");

    // STUB: Real bring-up loads GSP firmware into VRAM, talks to
    // the GSP RPC ring to allocate a channel, then writes the
    // pushbuffer GPA + size into the channel's USERD page. None
    // of that exists in v0.
    mm::FreeDmaCoherent(pb);

    return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
}

bool IsBroughtUp()
{
    return g_brought_up;
}

} // namespace duetos::drivers::gpu::nvidia
