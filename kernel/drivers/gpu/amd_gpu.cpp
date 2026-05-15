/*
 * DuetOS — AMD Radeon (GFX9+) driver: implementation.
 *
 * See `amd_gpu.h` for v0 scope. This TU owns the BAR5 mapping
 * for AMD parts — the shared `gpu.cpp` discovery layer maps BAR0
 * (VRAM) but the register file lives at BAR5 on GFX9 onwards.
 */

#include "drivers/gpu/amd_gpu.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/pci/pci.h"
#include "loader/firmware_loader.h"
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

// The CP ring buffer is owned for the lifetime of the boot on
// success. On failure the buffer is freed before this slot is
// touched and `.virt == nullptr` remains the live state.
mm::DmaBuffer g_cp_ring = {};

u32 Mmio32(u64 offset)
{
    if (g_mmio_regs == nullptr || offset + 4 > g_mmio_bytes)
        return 0xFFFFFFFFu;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(g_mmio_regs) + offset);
    return *p;
}

void Mmio32Write(u64 offset, u32 value)
{
    if (g_mmio_regs == nullptr || offset + 4 > g_mmio_bytes)
        return;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(g_mmio_regs) + offset);
    *p = value;
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

// Probe the firmware loader for the standard AMD GFX microcode
// blobs. AMD ships per-asic-named files (e.g. `vega10_pfp.bin`,
// `navi10_mec.bin`); a real MEC firmware loader will resolve the
// asic-specific filename from the device-id. For the v0 advisory
// probe we look up the generic basenames an operator might drop
// in — every hit is recorded in the boot log + `fwtrace show`.
void ProbeFirmwareBlobs()
{
    auto probe_one = [](const char* basename)
    {
        ::duetos::core::FwLoadRequest req{};
        req.vendor = "amd-gpu";
        req.basename = basename;
        req.min_bytes = 64;
        req.max_bytes = 0; // accept up to u32 max
        auto fw = ::duetos::core::FwLoad(req);
        if (fw.has_value())
        {
            arch::SerialWrite("[gpu/amd] firmware probe ");
            arch::SerialWrite(basename);
            arch::SerialWrite(" present, size=");
            arch::SerialWriteHex(fw.value().size);
            arch::SerialWrite("\n");
            ::duetos::core::FwRelease(fw.value());
        }
        // Misses are silent here — the firmware loader's own trace
        // ring records every attempt, so `fwtrace show` is the right
        // tool when an operator wants to know what missed.
    };
    // The five GFX-pipeline microcodes plus SDMA. Any real bring-up
    // needs PFP + ME + CE (or, on newer ASICs, a single PFP + ME
    // pair with the CE merged) before the CP can fetch a single
    // PM4 packet. RLC owns power management; SDMA is the side-band
    // DMA copy engine. None of these are loaded today — the probes
    // exist so an operator dropping a blob into
    // /lib/firmware/duetos/open/amd-gpu/ sees their image in the
    // boot log.
    probe_one("gfx_pfp.bin");
    probe_one("gfx_me.bin");
    probe_one("gfx_ce.bin");
    probe_one("gfx_mec.bin");
    probe_one("gfx_rlc.bin");
    probe_one("sdma.bin");
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

    // Firmware probes are advisory. Run them unconditionally — even
    // if the live-register read came back all-ones we still want
    // the operator to know whether they have AMD ucode files in
    // place, because the same files apply to a follow-on slice
    // that does the real firmware push.
    ProbeFirmwareBlobs();
}

::duetos::core::Result<void> Bringup(GpuInfo& g)
{
    KLOG_TRACE_SCOPE("drivers/gpu/amd", "Bringup");
    if (g_brought_up)
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};
    if (g_mmio_regs == nullptr || !g.mmio_live)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};

    // Allocate the CP ring backing. Zone::Dma32 because mmCP_RB0_BASE
    // / _BASE_HI on GFX9..GFX11 can carry a 48-bit physical address;
    // staying inside Dma32 keeps the readback comparison cheap (the
    // high register reads 0). The frame allocator zeroes the buffer
    // so any future PM4 fetch sees `PACKET3(NOP, 0)`-style padding
    // until a real submitter overwrites it.
    auto r = mm::AllocDmaCoherent(kAmdCpRingBytes, mm::Zone::Dma32);
    if (!r.has_value())
        return ::duetos::core::Err{r.error()};
    g_cp_ring = r.value();

    arch::SerialWrite("[gpu/amd] cp_ring_phys=");
    arch::SerialWriteHex(g_cp_ring.phys);
    arch::SerialWrite(" bytes=");
    arch::SerialWriteHex(kAmdCpRingBytes);
    arch::SerialWrite("\n");

    // Program CP_RB0. Sequence borrowed from amdgpu's
    // `gfx_v9_0_cp_gfx_resume`:
    //   1) Drain the ring control word before changing base. Holding
    //      CNTL=0 also keeps RPTR_WR_ENA disabled while we update the
    //      base, so no concurrent software write can race.
    //   2) Program BASE_HI / BASE. The register stores bits [39:8] /
    //      [47:40] of the physical address — the 4 KiB alignment we
    //      get from AllocDmaCoherent guarantees the low 8 bits are
    //      zero, so the shift is exact.
    //   3) Re-enable with the encoded size + block + RPTR_WR_ENA. We
    //      keep RPTR_WR_ENA set because no PFP firmware is loaded —
    //      with the bit off the read pointer never advances and any
    //      future software inspector that tries to manage RPTR
    //      manually would hit a write-protected register.
    const u32 ring_base_lo = static_cast<u32>(g_cp_ring.phys >> 8);
    const u32 ring_base_hi = static_cast<u32>(g_cp_ring.phys >> 40);
    const u32 cntl = kAmdCpRbCntlSizeFor4KiB | kAmdCpRbCntlBlkszFor16Dw | kAmdCpRbCntlRptrWrEna;

    Mmio32Write(kAmdRegCpRb0Cntl, 0);
    Mmio32Write(kAmdRegCpRb0BaseHi, ring_base_hi);
    Mmio32Write(kAmdRegCpRb0Base, ring_base_lo);
    Mmio32Write(kAmdRegCpRb0Cntl, cntl);

    // Read each register back. The CP register file is responsive
    // for these dwords even before microcode is loaded — the engine
    // mirrors the writes in the configuration block, only the
    // execution side is gated on firmware. A mismatched read-back
    // means our BAR5 map is broken, the device is in a deep reset
    // state, or the GFX9..GFX11 layout assumption doesn't hold for
    // this specific ASIC.
    const u32 rb_base = Mmio32(kAmdRegCpRb0Base);
    const u32 rb_base_hi = Mmio32(kAmdRegCpRb0BaseHi);
    const u32 rb_cntl = Mmio32(kAmdRegCpRb0Cntl);
    const u32 rb_rptr = Mmio32(kAmdRegCpRb0Rptr);

    const bool base_ok = (rb_base == ring_base_lo);
    const bool base_hi_ok = (rb_base_hi == ring_base_hi);
    const bool cntl_ok = (rb_cntl == cntl);

    if (!(base_ok && base_hi_ok && cntl_ok))
    {
        // Register decode failed. Disable the ring (CNTL=0) so the
        // controller isn't left half-programmed, fire the probe so
        // an attached GDB halts here, drop a single WARN sentinel,
        // and leave DEBUG breadcrumbs for triage. Free the buffer.
        Mmio32Write(kAmdRegCpRb0Cntl, 0);
        const u32 packed_diff = (base_ok ? 0u : 0x4u) | (base_hi_ok ? 0u : 0x2u) | (cntl_ok ? 0u : 0x1u);
        KBP_PROBE_V(::duetos::debug::ProbeId::kGpuRingBringupFail, packed_diff);
        KLOG_WARN_V("drivers/gpu/amd", "CP_RB0 readback mismatch (bits: 4=base 2=base_hi 1=cntl)", packed_diff);
        KLOG_DEBUG_V("drivers/gpu/amd", "CP_RB0_BASE     wrote", ring_base_lo);
        KLOG_DEBUG_V("drivers/gpu/amd", "CP_RB0_BASE     read ", rb_base);
        KLOG_DEBUG_V("drivers/gpu/amd", "CP_RB0_BASE_HI  wrote", ring_base_hi);
        KLOG_DEBUG_V("drivers/gpu/amd", "CP_RB0_BASE_HI  read ", rb_base_hi);
        KLOG_DEBUG_V("drivers/gpu/amd", "CP_RB0_CNTL     wrote", cntl);
        KLOG_DEBUG_V("drivers/gpu/amd", "CP_RB0_CNTL     read ", rb_cntl);
        mm::FreeDmaCoherent(g_cp_ring);
        g_cp_ring = {};
        return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
    }

    g_brought_up = true;
    arch::SerialWrite("[gpu/amd/cp] registers programmed phys=");
    arch::SerialWriteHex(g_cp_ring.phys);
    arch::SerialWrite(" cntl=");
    arch::SerialWriteHex(rb_cntl);
    arch::SerialWrite(" rptr=");
    arch::SerialWriteHex(rb_rptr);
    arch::SerialWrite(" (firmware-pending — MEC/PFP/ME push gates the next slice)\n");
    return {};
}

bool IsBroughtUp()
{
    return g_brought_up;
}

void* MmioRegs()
{
    return g_mmio_regs;
}

void AmdCpRingSelfTest()
{
    // Walk the GPU records and find an AMD display controller.
    // Self-tests run after `GpuInit` populates the cache, so by
    // this point every PCI display controller has been classified.
    const u64 n = GpuCount();
    bool found = false;
    for (u64 i = 0; i < n; ++i)
    {
        const GpuInfo& info = Gpu(i);
        if (info.vendor_id == kVendorAmd)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        // Typical QEMU `-vga std` / `-vga virtio` boot. Not a
        // failure — the structural sentinel CI greps for says so
        // explicitly so a regression that loses the AMD record is
        // distinguishable from a host that never had one.
        arch::SerialWrite("[gpu/amd/cp] no AMD device — skipped\n");
        return;
    }

    if (IsBroughtUp())
    {
        arch::SerialWrite("[gpu/amd/cp] selftest PASS (registers programmed, firmware-pending)\n");
        return;
    }

    // AMD device present but bring-up did not converge. The
    // bring-up itself will have fired `kGpuRingBringupFail` and
    // dropped a WARN, so we don't duplicate that here. Fire
    // `kBootSelftestFail` for the canonical boot-selftest GDB
    // break, using an AMD-specific sub-check tag.
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, /*sub-check tag*/ 0xA5Du);
    arch::SerialWrite("[gpu/amd/cp] selftest FAIL (AMD device present, CP not programmed)\n");
}

} // namespace duetos::drivers::gpu::amd
