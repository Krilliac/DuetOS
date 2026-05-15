/*
 * DuetOS — NVIDIA GeForce (Turing+) driver scaffold: implementation.
 *
 * See `nvidia_gpu.h` for v0 scope.
 */

#include "drivers/gpu/nvidia_gpu.h"

#include "arch/x86_64/serial.h"
#include "diag/fix_journal.h"
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

// Probe the firmware loader for the standard NVIDIA GSP blobs.
// NVIDIA ships per-asic-named firmware (e.g. `gsp_tu10x.bin`,
// `gsp_ga10x.bin`); a real GSP loader will resolve the asic-
// specific filename from the device-id / PMC_BOOT_42 SKU. For
// the v0 advisory probe we look up generic basenames an operator
// might drop in — every hit is recorded in the boot log +
// `fwtrace show`.
//
// Three blobs of interest today:
//   gsp_rm.bin       — the RM (Resource Manager) firmware payload
//                      that runs on the GSP microcontroller; this
//                      is what open-gpu-kernel-modules pushes
//                      once the bootloader has staged it.
//   gsp_log.bin      — debug-build log channel ucode (optional;
//                      release drivers ship without it).
//   bootloader.bin   — first-stage GSP bootloader some Turing
//                      parts need before gsp_rm.bin can be
//                      pushed. On Ampere+ this is folded into
//                      gsp_rm.bin.
void ProbeFirmwareBlobs()
{
    ProbeFirmwareBlob("nvidia-gpu", "[gpu/nvidia]", "gsp_rm.bin");
    ProbeFirmwareBlob("nvidia-gpu", "[gpu/nvidia]", "gsp_log.bin");
    ProbeFirmwareBlob("nvidia-gpu", "[gpu/nvidia]", "bootloader.bin");
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
    const u32 boot42 = Mmio32(g, kNvidiaRegPmcBoot42);
    const u32 boot8 = Mmio32(g, kNvidiaRegPmcBoot8);
    const u32 intren = Mmio32(g, kNvidiaRegPmcIntrEn0);
    const u32 pfifo_intr = Mmio32(g, kNvidiaRegPfifoIntr);
    const u32 pfb = Mmio32(g, kNvidiaRegPfbPriRd);
    const u32 pbus_intr = Mmio32(g, kNvidiaRegPbusIntr0);

    arch::SerialWrite("[gpu/nvidia] PMC_BOOT_0=");
    arch::SerialWriteHex(boot0);
    arch::SerialWrite(" PMC_BOOT_42=");
    arch::SerialWriteHex(boot42);
    arch::SerialWrite(" PMC_BOOT_8=");
    arch::SerialWriteHex(boot8);
    arch::SerialWrite("\n");
    arch::SerialWrite("[gpu/nvidia] PMC_INTR_EN_0=");
    arch::SerialWriteHex(intren);
    arch::SerialWrite(" PFIFO_INTR=");
    arch::SerialWriteHex(pfifo_intr);
    arch::SerialWrite(" (");
    arch::SerialWrite(PfifoIntrTag(pfifo_intr));
    arch::SerialWrite(") PBUS_INTR_0=");
    arch::SerialWriteHex(pbus_intr);
    arch::SerialWrite(" PFB[0]=");
    arch::SerialWriteHex(pfb);
    arch::SerialWrite("\n");

    g.probe_reg = boot0;
    g.mmio_live = (boot0 != 0xFFFFFFFFu);

    // Firmware probes are advisory. Run them unconditionally —
    // even if the live-register read came back all-ones we still
    // want the operator to know whether they have GSP firmware
    // staged, because the same files apply to a follow-on slice
    // that does the actual GSP push.
    ProbeFirmwareBlobs();
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
    // of that exists in v0 — and unlike Intel / AMD there is no
    // smaller intermediate gate we can land first. Every PFIFO-
    // side effect goes through GSP.
    FIX_NOTE_STUB("drivers/gpu/nvidia_gpu.cpp:GSP_CHANNEL", "wire GSP firmware load + RPC channel submit");
    mm::FreeDmaCoherent(pb);

    return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
}

bool IsBroughtUp()
{
    return g_brought_up;
}

void NvidiaGspSelfTest()
{
    // Walk the GPU records and find an NVIDIA display controller.
    // Self-tests run after `GpuInit` populates the cache.
    const u64 n = GpuCount();
    bool found = false;
    bool live = false;
    for (u64 i = 0; i < n; ++i)
    {
        const GpuInfo& info = Gpu(i);
        if (info.vendor_id == kVendorNvidia)
        {
            found = true;
            live = info.mmio_live;
            break;
        }
    }
    if (!found)
    {
        // Typical QEMU `-vga std` / `-vga virtio` boot. Not a
        // failure — the structural sentinel CI greps for says so
        // explicitly so a regression that loses the NVIDIA record
        // is distinguishable from a host that never had one.
        arch::SerialWrite("[gpu/nvidia/gsp] no NVIDIA device — skipped\n");
        return;
    }

    if (live)
    {
        // We have an NVIDIA controller that decoded PMC_BOOT_0
        // cleanly. PFIFO submission is gated on GSP firmware
        // push (next slice), so "PASS" here means "discovery
        // side of the slice succeeded" — explicitly not "the GPU
        // is executing PM4 / NVC0_* commands."
        arch::SerialWrite("[gpu/nvidia/gsp] selftest PASS (device present, GSP RPC gated)\n");
        return;
    }

    // NVIDIA device present but PMC_BOOT_0 read came back
    // 0xFFFFFFFF — BAR0 decode failed or the device is wedged
    // before any driver touched it. The Probe() path will have
    // already logged the dead chip; we just emit the structural
    // sentinel.
    arch::SerialWrite("[gpu/nvidia/gsp] selftest FAIL (NVIDIA device present, BAR0 decode failed)\n");
}

} // namespace duetos::drivers::gpu::nvidia
