/*
 * DuetOS — Intel iGPU driver scaffold: implementation.
 *
 * See `intel_gpu.h` for v0 scope. The probe pulls a couple of
 * dwords from BAR0 to confirm the controller is decoded; the
 * Bringup() ring scaffold is feature-flagged off in v0.
 */

#include "drivers/gpu/intel_gpu.h"

#include "arch/x86_64/serial.h"
#include "drivers/gpu/intel_gsc_fw.h"
#include "loader/firmware_loader.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/zone.h"

namespace duetos::drivers::gpu::intel
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

// Map the FUSE_STRAP DISPLAY_FUSE field (bits 0..3) to a coarse
// display-version tag. Real i915 reads many more fuse bits; this
// is just a boot-log breadcrumb so the operator sees that the
// driver knows what flavour of GT it's looking at.
const char* FuseDisplayTag(u32 fuse)
{
    const u32 disp = fuse & 0xF;
    switch (disp)
    {
    case 0x0:
        return "disp-disabled";
    case 0x1:
        return "disp-1pipe";
    case 0x2:
        return "disp-2pipe";
    case 0x3:
        return "disp-3pipe";
    default:
        return "disp-unknown";
    }
}

} // namespace

void Probe(GpuInfo& g)
{
    if (g.mmio_virt == nullptr)
    {
        arch::SerialWrite("[gpu/intel] BAR0 not mapped — probe skipped\n");
        return;
    }

    const u32 dword0 = Mmio32(g, kIntelRegGenInfo);
    g.probe_reg = dword0;
    g.mmio_live = (dword0 != 0xFFFFFFFFu);
    if (!g.mmio_live)
    {
        arch::SerialWrite("[gpu/intel] BAR0[0]=0xFFFFFFFF — MMIO decode failed\n");
        return;
    }

    const u32 fuse = Mmio32(g, kIntelRegFuseStrap);
    const u32 gfx_mode = Mmio32(g, kIntelRegGfxMode);
    const u32 pwr = Mmio32(g, kIntelRegPwrWellCtl2);

    arch::SerialWrite("[gpu/intel] gen_info=");
    arch::SerialWriteHex(dword0);
    arch::SerialWrite(" fuse_strap=");
    arch::SerialWriteHex(fuse);
    arch::SerialWrite(" (");
    arch::SerialWrite(FuseDisplayTag(fuse));
    arch::SerialWrite(") gfx_mode=");
    arch::SerialWriteHex(gfx_mode);
    arch::SerialWrite(" pwr_well_ctl2=");
    arch::SerialWriteHex(pwr);
    arch::SerialWrite("\n");

    // Optional: if the operator has installed an Intel GSC firmware
    // image at /lib/firmware/duetos/open/intel-gsc/gsc.bin (or under
    // the vendor namespace), parse it and log the partition summary.
    // We don't yet push the image to the GSC over MEI, so the parse
    // is purely advisory — it tells the operator that a firmware
    // they're carrying around is structurally valid and which
    // partitions it claims. A future MEI-driver slice will turn
    // this into the actual update path.
    {
        ::duetos::core::FwLoadRequest req{};
        req.vendor = "intel-gsc";
        req.basename = "gsc.bin";
        req.min_bytes = kIntelGscFptHeaderBytes + kIntelGscFptEntryBytes;
        req.max_bytes = 0; // accept any size up to u32 max
        auto fw = ::duetos::core::FwLoad(req);
        if (fw.has_value())
        {
            IntelGscFwParsed parsed{};
            auto pr = IntelGscFwParse(fw.value().data, fw.value().size, &parsed);
            if (pr.has_value())
                IntelGscFwLog(parsed);
            else
                KLOG_WARN("drivers/gpu/intel", "GSC firmware image present but parse failed");
            ::duetos::core::FwRelease(fw.value());
        }
    }

    // Probe for the GuC (Graphics microController) and HuC (HEVC
    // microController) firmware blobs. Intel ships these for every
    // Gen9+ GPU; the GuC owns command-submission scheduling and
    // power management, the HuC accelerates HEVC encode. The Linux
    // i915 / Xe drivers lazy-load both during ring bring-up.
    //
    // We don't have a GPU command-ring online yet, so the loads
    // are advisory — the lookup names which firmware files an
    // operator has dropped under
    // /lib/firmware/duetos/open/intel-gpu/ (or
    // /lib/firmware/intel-gpu/), and the boot log records each
    // hit/miss so a follow-up bring-up slice knows what's
    // available.
    auto probe_one = [](const char* basename)
    {
        ::duetos::core::FwLoadRequest req{};
        req.vendor = "intel-gpu";
        req.basename = basename;
        req.min_bytes = 64;
        req.max_bytes = 0;
        auto fw = ::duetos::core::FwLoad(req);
        if (fw.has_value())
        {
            arch::SerialWrite("[gpu/intel] firmware probe ");
            arch::SerialWrite(basename);
            arch::SerialWrite(" present, size=");
            arch::SerialWriteHex(fw.value().size);
            arch::SerialWrite("\n");
            ::duetos::core::FwRelease(fw.value());
        }
        // Misses are silent here — the firmware loader's own trace
        // ring records every attempt, so `fwtrace show` is the
        // right tool when an operator wants to know what failed.
    };
    probe_one("guc.bin");
    probe_one("huc.bin");
}

::duetos::core::Result<void> Bringup(GpuInfo& g)
{
    KLOG_TRACE_SCOPE("drivers/gpu/intel", "Bringup");
    if (g_brought_up)
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};
    if (g.mmio_virt == nullptr || !g.mmio_live)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};

    // Reserve the RCS ring DMA buffer. We allocate it now so the
    // physical address is known + logged even though we don't
    // currently program it into the controller. A follow-up slice
    // will write the dword to RCS_START and flip the enable bit.
    auto r = mm::AllocDmaCoherent(kIntelRingBytes, mm::Zone::Dma32);
    if (!r.has_value())
        return ::duetos::core::Err{r.error()};
    const mm::DmaBuffer ring = r.value();

    arch::SerialWrite("[gpu/intel] rcs_ring_phys=");
    arch::SerialWriteHex(ring.phys);
    arch::SerialWrite(" bytes=");
    arch::SerialWriteHex(kIntelRingBytes);
    arch::SerialWrite(" — would write RCS_START / RCS_CTL but real ring submission is gated\n");

    // STUB: Real bring-up writes RCS_TAIL=0, RCS_HEAD=0,
    // RCS_START=ring.phys, then RCS_CTL=(kIntelRingLengthMask &
    // (kIntelRingBytes-PAGE_SIZE)) | kIntelRingEnable. We don't
    // do that today because we haven't validated this on real
    // silicon — pokes that are wrong on Gen9..Gen13 will corrupt
    // an active engine. Free the buffer so the next Bringup
    // doesn't leak.
    mm::FreeDmaCoherent(ring);

    return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
}

bool IsBroughtUp()
{
    return g_brought_up;
}

} // namespace duetos::drivers::gpu::intel
