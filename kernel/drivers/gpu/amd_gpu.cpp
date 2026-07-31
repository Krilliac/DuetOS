/*
 * DuetOS — AMD Radeon (GFX9+) driver: implementation.
 *
 * See `amd_gpu.h` for v0 scope. This TU owns the BAR5 mapping
 * for AMD parts — the shared `gpu.cpp` discovery layer maps BAR0
 * (VRAM) but the register file lives at BAR5 on GFX9 onwards.
 */

#include "drivers/gpu/amd_gpu.h"

#include "drivers/gpu/amd_cp_ucode.h"
#include "drivers/gpu/amd_gpu_cmds.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/gpu/amd_gfx_fw.h"
#include "drivers/pci/pci.h"
#include "loader/firmware_loader.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/paging.h"
#include "mm/zone.h"
#include "time/timekeeper.h"

namespace duetos::drivers::gpu::amd
{

namespace
{

void* g_mmio_regs = nullptr;
u64 g_mmio_phys = 0;
u64 g_mmio_bytes = 0;
bool g_brought_up = false;
bool g_cp_microcode_loaded = false;

// The CP ring buffer is owned for the lifetime of the boot on
// success. On failure the buffer is freed before this slot is
// touched and `.virt == nullptr` remains the live state.
mm::DmaBuffer g_cp_ring = {};

constexpr u32 kAmdCpProbeFailure = 0xFFFFFFFFu;
constexpr u32 kAmdCpProbeSentinel = 0xDEADBEEFu;
constexpr u32 kAmdCpProbeCookie = 0xC0DEC0DEu;
constexpr u64 kAmdCpProbeTimeoutNs = 100ull * 1000ull * 1000ull;
constexpr u32 kAmdCpProbeIterationCap = 1u << 20;

bool DirectCpMicrocodeGeneration(const char* family)
{
    if (family == nullptr || family[0] != 'g' || family[1] != 'f' || family[2] != 'x')
        return false;
    // The direct host-upload path is for GFX9 and GFX10/10.3. GFX11+
    // firmware is PSP-mediated and must not be poked through these
    // legacy UCODE_DATA registers.
    return family[3] == '9' || (family[3] == '1' && family[4] == '0');
}

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
//
// The five GFX-pipeline microcodes plus SDMA. Any real bring-up
// needs PFP + ME + CE (or, on newer ASICs, a single PFP + ME
// pair with the CE merged) before the CP can fetch a single
// PM4 packet. RLC owns power management; SDMA is the side-band
// DMA copy engine. None of these are loaded today — the probes
// exist so an operator dropping a blob into
// /lib/firmware/duetos/open/amd-gpu/ sees their image in the
// boot log.
// Run the shared "is it there?" probe AND the gfx-header parser
// on each blob the loader returns. The parser is freestanding and
// the FwLoad / FwRelease bracketing keeps the blob alive only for
// the parse + log window — the actual upload-time consumer (in the
// follow-on slice) will re-acquire via its own FwLoad.
void ProbeAndParseAmdBlob(const char* basename)
{
    // The shared helper logs presence and size — keep it for parity
    // with the other vendor probes.
    ProbeFirmwareBlob("amd-gpu", "[gpu/amd]", basename);

    ::duetos::core::FwLoadRequest req{};
    req.vendor = "amd-gpu";
    req.basename = basename;
    req.min_bytes = kAmdCommonFwHeaderBytes;
    req.max_bytes = kAmdMaxFwSizeBytes;
    auto fw = ::duetos::core::FwLoad(req);
    if (!fw.has_value())
        return;
    AmdGfxFwParsed parsed{};
    auto r = AmdGfxFwParse(fw.value().data, fw.value().size, &parsed);
    if (r.has_value())
    {
        AmdGfxFwLog(basename, parsed);
    }
    else
    {
        arch::SerialWrite("[gpu/amd-fw] ");
        arch::SerialWrite(basename);
        arch::SerialWrite(" rejected (reason=");
        arch::SerialWriteHex(parsed.reject_reason);
        arch::SerialWrite(")\n");
    }
    ::duetos::core::FwRelease(fw.value());
}

void ProbeFirmwareBlobs()
{
    ProbeAndParseAmdBlob("gfx_pfp.bin");
    ProbeAndParseAmdBlob("gfx_me.bin");
    ProbeAndParseAmdBlob("gfx_ce.bin");
    ProbeAndParseAmdBlob("gfx_mec.bin");
    ProbeAndParseAmdBlob("gfx_rlc.bin");
    ProbeAndParseAmdBlob("sdma.bin");
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
    arch::SerialWrite(" — attempting CP microcode upload\n");
    // Direct CP microcode upload is valid for GFX9/GFX10 only. Real-HW
    // needs gfx_*.bin under the open-firmware path; an incomplete load
    // leaves CP_ME_CNTL halted and therefore cannot reach the PM4 probe.
    if (DirectCpMicrocodeGeneration(g.family))
    {
        const auto ucode = AmdCpLoadMicrocode(MmioRegs());
        g_cp_microcode_loaded = ucode.has_value();
    }
    else
    {
        arch::SerialWrite("[gpu/amd/cp] direct microcode upload gated (generation requires PSP or is unknown)\n");
    }
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

u32 AmdCpWriteDataProbe(u32 cookie)
{
    if (!g_brought_up || !g_cp_microcode_loaded || g_cp_ring.virt == nullptr || g_mmio_regs == nullptr)
        return kAmdCpProbeFailure;

    auto scratch_result = mm::AllocDmaCoherent(mm::kPageSize, mm::Zone::Dma32);
    if (!scratch_result.has_value())
    {
        KLOG_WARN("drivers/gpu/amd", "CP PM4 WRITE_DATA scratch allocation failed");
        return kAmdCpProbeFailure;
    }
    const mm::DmaBuffer scratch = scratch_result.value();
    auto* scratch_word = static_cast<volatile u32*>(scratch.virt);
    *scratch_word = kAmdCpProbeSentinel;

    u32* ring = static_cast<u32*>(g_cp_ring.virt);
    const u32 ring_dwords = static_cast<u32>(kAmdCpRingDwords);
    const u32 ring_mask = ring_dwords - 1u;
    const u32 current_wptr_raw = Mmio32(kAmdRegCpRb0Wptr);
    if (current_wptr_raw == kAmdCpProbeFailure)
    {
        KLOG_WARN("drivers/gpu/amd", "CP PM4 WRITE_DATA WPTR read failed");
        mm::FreeDmaCoherent(scratch);
        return kAmdCpProbeFailure;
    }
    const u32 current_wptr = current_wptr_raw & ring_mask;
    u32 packet_offset = current_wptr;
    constexpr u32 kPacketDwords = sizeof(WriteDataPacket) / sizeof(u32);
    static_assert(kPacketDwords == 5, "WRITE_DATA probe packet size");

    if (packet_offset + kPacketDwords > ring_dwords)
    {
        // A type-3 NOP is one dword. Pad to the end so the CP can wrap
        // without decoding the tail of a split WRITE_DATA packet.
        while (packet_offset < ring_dwords)
            ring[packet_offset++] = EncodePacket3(kPacket3Nop, 0);
        packet_offset = 0;
    }

    const WriteDataPacket packet = EncodeWriteData(scratch.phys, cookie);
    for (u32 i = 0; i < kPacketDwords; ++i)
        ring[packet_offset + i] = packet.dw[i];
    const u32 new_wptr = (packet_offset + kPacketDwords) & ring_mask;

    // Publish the scratch sentinel before the ring packet, then publish
    // the packet before the MMIO doorbell. The ring and scratch are both
    // DMA-coherent, but retain the barriers for non-coherent future ports.
    mm::DmaSyncForDevice(scratch, 0, sizeof(u32));
    mm::DmaSyncForDevice(g_cp_ring, 0, kAmdCpRingBytes);
    Mmio32Write(kAmdRegCpRb0Wptr, new_wptr);

    const u64 start_ns = ::duetos::time::MonotonicNs();
    bool ring_advanced = false;
    u32 observed_rptr = kAmdCpProbeFailure;
    for (u32 iter = 0; iter < kAmdCpProbeIterationCap; ++iter)
    {
        observed_rptr = Mmio32(kAmdRegCpRb0Rptr) & ring_mask;
        if (observed_rptr == new_wptr)
        {
            ring_advanced = true;
            break;
        }
        asm volatile("pause" ::: "memory");
        if (start_ns != 0)
        {
            const u64 now_ns = ::duetos::time::MonotonicNs();
            if (now_ns > start_ns && (now_ns - start_ns) > kAmdCpProbeTimeoutNs)
                break;
        }
    }

    if (!ring_advanced)
    {
        KLOG_WARN_V("drivers/gpu/amd", "CP PM4 WRITE_DATA timeout (RPTR)", observed_rptr);
        KLOG_DEBUG_V("drivers/gpu/amd", "CP PM4 WRITE_DATA target WPTR", new_wptr);
        mm::FreeDmaCoherent(scratch);
        return kAmdCpProbeFailure;
    }

    mm::DmaSyncForCpu(scratch, 0, sizeof(u32));
    const u32 readback = *scratch_word;
    mm::FreeDmaCoherent(scratch);
    return readback;
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
        if (!g_cp_microcode_loaded)
        {
            arch::SerialWrite("[gpu/amd/cp] selftest PASS (registers programmed, firmware-pending)\n");
            return;
        }

        const u32 readback = AmdCpWriteDataProbe(kAmdCpProbeCookie);
        if (readback == kAmdCpProbeCookie)
        {
            arch::SerialWrite("[gpu/amd/cp] selftest PASS (ring online, PM4 WRITE_DATA verified, "
                              "scratch=0xC0DEC0DE)\n");
            return;
        }
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, readback);
        arch::SerialWrite("[gpu/amd/cp] selftest FAIL (PM4 WRITE_DATA readback=");
        arch::SerialWriteHex(readback);
        arch::SerialWrite(")\n");
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
