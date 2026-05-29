/*
 * DuetOS — Intel iGPU driver scaffold: implementation.
 *
 * See `intel_gpu.h` for v0 scope. The probe pulls a couple of
 * dwords from BAR0 to confirm the controller is decoded; the
 * Bringup() ring scaffold is feature-flagged off in v0.
 */

#include "drivers/gpu/intel_gpu.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/gpu/intel_forcewake.h"
#include "drivers/gpu/intel_ggtt.h"
#include "drivers/gpu/intel_gpu_cmds.h"
#include "drivers/gpu/intel_gsc_fw.h"
#include "loader/firmware_loader.h"
#include "log/klog.h"
#include "mm/dma.h"
#include "mm/zone.h"
#include "time/timekeeper.h"

namespace duetos::drivers::gpu::intel
{

namespace
{

bool g_brought_up = false;

// The RCS ring buffer is owned for the lifetime of the boot on
// success — we retain the DmaBuffer here so the controller's
// programmed RCS_START stays valid. On failure the buffer is
// freed before this slot is touched and `.virt == nullptr`
// remains the live state.
mm::DmaBuffer g_rcs_ring = {};

// Scratch dword the MI_STORE_DWORD_IMM probe writes into. One
// DMA-coherent page owned by the driver for the lifetime of the
// boot. Lazily allocated by IntelRcsStoreImmProbe on first call.
// The probe's success signal is the scratch dword reading back
// the value the engine was told to store.
mm::DmaBuffer g_rcs_scratch = {};

// Hand-rolled remembered (driver, info) pointer used by the
// store-imm probe so it doesn't re-walk `gpu.cpp`'s GpuInfo
// records each time. Set by Bringup; consulted by the probe.
const GpuInfo* g_intel_info = nullptr;

u32 Mmio32(const GpuInfo& g, u64 offset)
{
    if (g.mmio_virt == nullptr || offset + 4 > g.mmio_size)
        return 0xFFFFFFFFu;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(g.mmio_virt) + offset);
    return *p;
}

void Mmio32Write(const GpuInfo& g, u64 offset, u32 value)
{
    if (g.mmio_virt == nullptr || offset + 4 > g.mmio_size)
        return;
    auto* p = reinterpret_cast<volatile u32*>(static_cast<u8*>(g.mmio_virt) + offset);
    *p = value;
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
        // Same dead-chip shape as iwlwifi/mt76: a register reads
        // back all-ones, meaning BAR is unmapped or the device is
        // wedged before bring-up could touch it. Route through
        // klog so the ring buffer captures the GPU absence cause.
        KLOG_ERROR("drivers/gpu/intel", "BAR0[0]=0xFFFFFFFF — MMIO decode failed");
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
    // We use the shared `gpu::ProbeFirmwareBlob` helper so the
    // three tier-1 drivers stay consistent on which firmware was
    // found and how it gets reported. Loads are advisory — the
    // lookup names which firmware files an operator has dropped
    // under /lib/firmware/duetos/open/intel-gpu/ , and the boot
    // log records each hit so a follow-up bring-up slice knows
    // what's available. Misses are silent (the firmware loader's
    // own trace ring records every attempt).
    ProbeFirmwareBlob("intel-gpu", "[gpu/intel]", "guc.bin");
    ProbeFirmwareBlob("intel-gpu", "[gpu/intel]", "huc.bin");
}

::duetos::core::Result<void> Bringup(GpuInfo& g)
{
    KLOG_TRACE_SCOPE("drivers/gpu/intel", "Bringup");
    if (g_brought_up)
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};
    if (g.mmio_virt == nullptr || !g.mmio_live)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotReady};

    // Allocate the RCS ring backing. Zone::Dma32 so the engine sees
    // the address inside the 32-bit aperture without GTT
    // intervention — the Render Command Streamer's RCS_START is a
    // 32-bit register on Gen9..Gen13 and is interpreted as a guest-
    // physical address when GTT isn't programmed (i915 calls this
    // "ggtt unbound" mode; for v0 it's exactly what we want).
    // The frame allocator zeroes the buffer, so the ring already
    // holds 1024 `MI_NOOP` (= 0x00000000) entries on return.
    auto r = mm::AllocDmaCoherent(kIntelRingBytes, mm::Zone::Dma32);
    if (!r.has_value())
        return ::duetos::core::Err{r.error()};
    g_rcs_ring = r.value();

    arch::SerialWrite("[gpu/intel] rcs_ring_phys=");
    arch::SerialWriteHex(g_rcs_ring.phys);
    arch::SerialWrite(" bytes=");
    arch::SerialWriteHex(kIntelRingBytes);
    arch::SerialWrite("\n");

    // Program the ring. Sequence matches i915
    // `intel_ring_submission.c::__ring_context_init` minus the
    // GuC / context-state bits we don't have:
    //   1) Drain any prior ring state — CTL=0 first.
    //   2) Reset head + tail to the start of the buffer.
    //   3) Point RCS_START at the buffer's guest-physical base
    //      (must be 4 KiB aligned; AllocDmaCoherent guarantees
    //      page alignment).
    //   4) Re-enable with the length encoded in the high bits:
    //      `length` is (#pages - 1) << 12 — for a 1-page ring
    //      that's 0, AND the enable bit.
    //
    // Slice 1 precondition: real silicon power-gates the GT register
    // block, so hold forcewake on RENDER+GT (the two domains the RCS
    // 0x2000 block straddles) and un-stop the ring before programming
    // it — otherwise the writes below are dropped on metal. Held for
    // the boot. Reached only on a live Intel BAR0 (QEMU never gets
    // here), and on a forcewake-ack miss the HEAD poll below still
    // reports the failure uniformly, so we don't early-return.
    ForcewakeGetForRing(g);
    IntelRingUnstop(g);
    // Slice 2: stand up the GGTT high window (the foundation batch-
    // buffer execution in slice 3 maps its batch + surfaces through).
    // Consumed there; standing it up here is harmless.
    (void)GgttInit(g);

    Mmio32Write(g, kIntelRcsCtl, 0);
    Mmio32Write(g, kIntelRcsTail, 0);
    Mmio32Write(g, kIntelRcsHead, 0);
    Mmio32Write(g, kIntelRcsStart, static_cast<u32>(g_rcs_ring.phys));
    const u32 ctl = (static_cast<u32>(kIntelRingBytes - 0x1000u) & kIntelRingLengthMask) | kIntelRingEnable;
    Mmio32Write(g, kIntelRcsCtl, ctl);

    // Submit: bump TAIL past the first kNoopBatch entries. The ring
    // was zero-filled by the frame allocator, so the buffer already
    // contains MI_NOOPs (opcode 0x00000000) at every dword from
    // offset 0 onward. We still call DmaSyncForDevice to flush any
    // speculative write the CPU may have queued through the cached
    // alias — on x86 this is a compiler barrier; on a future ARM64
    // port it's the cache maintenance op that makes the buffer
    // device-visible.
    constexpr u32 kNoopBatch = 64;
    constexpr u32 kSubmitBytes = kNoopBatch * 4;
    static_assert(kSubmitBytes < kIntelRingBytes, "noop submission must fit inside the ring");

    mm::DmaSyncForDevice(g_rcs_ring, 0, kSubmitBytes);
    Mmio32Write(g, kIntelRcsTail, kSubmitBytes);

    // Poll HEAD until it reaches TAIL or 100 ms elapses, whichever
    // comes first. Each pause + load is ~50-100 ns on a modern
    // Intel core, so the iteration cap (~1M) is roughly the same
    // wall-clock bound — we keep both because MonotonicNs() returns
    // 0 if Timekeeper hasn't selected a source yet, in which case
    // the iteration cap is the only thing standing between us and
    // an infinite loop.
    constexpr u64 kTimeoutNs = 100ull * 1000ull * 1000ull;
    constexpr u32 kIterCap = 1u << 20;
    const u64 start_ns = ::duetos::time::MonotonicNs();
    u32 head = 0;
    bool ring_live = false;
    for (u32 iter = 0; iter < kIterCap; ++iter)
    {
        head = Mmio32(g, kIntelRcsHead);
        if (head == kSubmitBytes)
        {
            ring_live = true;
            break;
        }
        asm volatile("pause" ::: "memory");
        if (start_ns != 0)
        {
            const u64 now_ns = ::duetos::time::MonotonicNs();
            if (now_ns > start_ns && (now_ns - start_ns) > kTimeoutNs)
                break;
        }
    }

    if (!ring_live)
    {
        // Bring-up did not converge. Disable the ring so the
        // controller isn't left fetching from a buffer we're about
        // to free, fire the structural probe so an attached GDB
        // halts here, drop a single WARN sentinel, and leave a
        // DEBUG line with the observed register state so a triage
        // session can re-derive what happened without re-running
        // the boot.
        Mmio32Write(g, kIntelRcsCtl, 0);
        const u32 final_head = Mmio32(g, kIntelRcsHead);
        const u32 final_tail = Mmio32(g, kIntelRcsTail);
        const u32 final_ctl = Mmio32(g, kIntelRcsCtl);
        KBP_PROBE_V(::duetos::debug::ProbeId::kGpuRingBringupFail, final_head);
        KLOG_WARN_V("drivers/gpu/intel", "RCS ring head never caught tail (head)", final_head);
        KLOG_DEBUG_V("drivers/gpu/intel", "RCS final tail", final_tail);
        KLOG_DEBUG_V("drivers/gpu/intel", "RCS final ctl", final_ctl);
        KLOG_DEBUG_V("drivers/gpu/intel", "RCS ring phys", g_rcs_ring.phys);
        mm::FreeDmaCoherent(g_rcs_ring);
        g_rcs_ring = {};
        return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
    }

    g_brought_up = true;
    g_intel_info = &g;
    arch::SerialWrite("[gpu/intel/rcs] ring online head=tail=");
    arch::SerialWriteHex(head);
    arch::SerialWrite(" ctl=");
    arch::SerialWriteHex(ctl);
    arch::SerialWrite(" phys=");
    arch::SerialWriteHex(g_rcs_ring.phys);
    arch::SerialWrite("\n");
    return {};
}

u32 IntelRcsStoreImmProbe(u32 value)
{
    if (!g_brought_up || g_intel_info == nullptr || g_rcs_ring.virt == nullptr)
        return 0xFFFFFFFFu;

    // Lazy-alloc the scratch on first call. One DMA-coherent page;
    // we only need a dword but page-granularity is the allocator's
    // minimum and lets the GPU touch the address through a normal
    // DMA path. Use Zone::Dma32 to match the ring's addressability
    // constraint (RCS_START is 32-bit).
    if (g_rcs_scratch.virt == nullptr)
    {
        auto r = mm::AllocDmaCoherent(0x1000u, mm::Zone::Dma32);
        if (!r.has_value())
        {
            KLOG_WARN("drivers/gpu/intel", "RCS store-imm: scratch alloc failed");
            return 0xFFFFFFFFu;
        }
        g_rcs_scratch = r.value();
    }

    // Build the MI_STORE_DWORD_IMM packet (4 dwords on Gen9+).
    // Layout per Intel's "Render Engine Command Streamer" PRM:
    //   dw0 = opcode (0x20 << 23) | (length=2)  (length is total
    //         dwords minus 2 per Intel convention)
    //   dw1 = address bits 31:0
    //   dw2 = address bits 63:32  (zero for our 32-bit physical
    //         scratch — no GGTT translation needed since we cleared
    //         the use_global_gtt bit)
    //   dw3 = data to store
    const u32 phys_lo = static_cast<u32>(g_rcs_scratch.phys & 0xFFFFFFFFu);
    const u32 phys_hi = static_cast<u32>((g_rcs_scratch.phys >> 32) & 0xFFFFFFFFu);
    u32* ring = static_cast<u32*>(g_rcs_ring.virt);
    const u64 ring_dwords = kIntelRingBytes / 4u;

    // Write the packet starting at the position one after the
    // previous TAIL. The bring-up advanced TAIL to kSubmitBytes
    // (= 64 dwords). We append after that, wrapping if needed.
    const u32 cur_tail = Mmio32(*g_intel_info, kIntelRcsTail);
    u64 ofs_dw = (cur_tail / 4u) % ring_dwords;
    if (ofs_dw + 4 > ring_dwords)
    {
        // Not enough room before wrap — pad with NOOPs to the end
        // and start fresh at offset 0. This keeps the engine
        // executing the right opcodes regardless of where we land
        // in the ring.
        while (ofs_dw < ring_dwords)
            ring[ofs_dw++] = kIntelMiNoop;
        ofs_dw = 0;
    }
    ring[ofs_dw + 0] = kIntelMiStoreDwordImm;
    ring[ofs_dw + 1] = phys_lo;
    ring[ofs_dw + 2] = phys_hi;
    ring[ofs_dw + 3] = value;
    const u32 new_tail = static_cast<u32>(((ofs_dw + 4u) * 4u) % kIntelRingBytes);

    // Zero the scratch dword so a read-back of the old value
    // doesn't mask a failed store.
    auto* scratch = static_cast<volatile u32*>(g_rcs_scratch.virt);
    *scratch = 0xDEADBEEFu;

    mm::DmaSyncForDevice(g_rcs_ring, 0, kIntelRingBytes);
    Mmio32Write(*g_intel_info, kIntelRcsTail, new_tail);

    // Poll HEAD until it catches the new TAIL or 100 ms elapses.
    constexpr u64 kTimeoutNs = 100ull * 1000ull * 1000ull;
    constexpr u32 kIterCap = 1u << 20;
    const u64 start_ns = ::duetos::time::MonotonicNs();
    bool engine_advanced = false;
    for (u32 iter = 0; iter < kIterCap; ++iter)
    {
        if (Mmio32(*g_intel_info, kIntelRcsHead) == new_tail)
        {
            engine_advanced = true;
            break;
        }
        asm volatile("pause" ::: "memory");
        if (start_ns != 0)
        {
            const u64 now = ::duetos::time::MonotonicNs();
            if (now > start_ns && (now - start_ns) > kTimeoutNs)
                break;
        }
    }
    if (!engine_advanced)
    {
        KLOG_WARN("drivers/gpu/intel", "RCS store-imm: HEAD did not catch TAIL");
        return 0xFFFFFFFFu;
    }

    // Sync the scratch back to the CPU and read it. If MI_STORE_DWORD_IMM
    // executed correctly, the scratch holds `value`.
    mm::DmaSyncForCpu(g_rcs_scratch, 0, 4u);
    return *scratch;
}

u32 IntelBatchExecProbe(u32 cookie)
{
    // Escalation rung 3: prove GGTT translation + batch dispatch +
    // execution together. We map a batch page into the GGTT, fill it
    // with [MI_STORE_DWORD_IMM(scratch, cookie) ; MI_BATCH_BUFFER_END],
    // and dispatch it from the ring via MI_BATCH_BUFFER_START(GGTT).
    // If the engine fetched the batch through the GGTT and ran it, the
    // (physical, gtt-bypass) scratch dword reads back `cookie`.
    if (!g_brought_up || g_intel_info == nullptr || g_rcs_ring.virt == nullptr || !GgttReady())
        return 0xFFFFFFFFu;
    const GpuInfo& g = *g_intel_info;

    if (g_rcs_scratch.virt == nullptr)
    {
        auto sr = mm::AllocDmaCoherent(0x1000u, mm::Zone::Dma32);
        if (!sr.has_value())
            return 0xFFFFFFFFu;
        g_rcs_scratch = sr.value();
    }
    auto* scratch = static_cast<volatile u32*>(g_rcs_scratch.virt);
    *scratch = 0xDEADBEEFu;

    auto br = mm::AllocDmaCoherent(0x1000u, mm::Zone::Normal);
    if (!br.has_value())
        return 0xFFFFFFFFu;
    mm::DmaBuffer batch = br.value();
    const u64 batch_va = GgttMapPage(g, batch.phys);
    if (batch_va == 0)
    {
        mm::FreeDmaCoherent(batch);
        return 0xFFFFFFFFu;
    }

    // Build the batch: store the cookie to the physical scratch, then
    // end. The store targets a guest-physical address (GGTT-bypass),
    // matching IntelRcsStoreImmProbe's convention.
    u32* b = static_cast<u32*>(batch.virt);
    b[0] = kIntelMiStoreDwordImm;
    b[1] = static_cast<u32>(g_rcs_scratch.phys & 0xFFFFFFFFu);
    b[2] = static_cast<u32>((g_rcs_scratch.phys >> 32) & 0xFFFFFFFFu);
    b[3] = cookie;
    b[4] = kMiBatchBufferEnd;
    mm::DmaSyncForDevice(batch, 0, 0x1000u);

    // Append MI_BATCH_BUFFER_START to the ring (pad to a qword-even
    // 4-dword slot with one MI_NOOP), then ring the TAIL doorbell.
    const BatchStartPacket pkt = EncodeBatchBufferStart(batch_va, /*ggtt=*/true);
    u32* ring = static_cast<u32*>(g_rcs_ring.virt);
    const u64 ring_dwords = kIntelRingBytes / 4u;
    const u32 cur_tail = Mmio32(g, kIntelRcsTail);
    u64 ofs = (cur_tail / 4u) % ring_dwords;
    if (ofs + 4 > ring_dwords)
    {
        while (ofs < ring_dwords)
            ring[ofs++] = kIntelMiNoop;
        ofs = 0;
    }
    ring[ofs + 0] = pkt.dw[0];
    ring[ofs + 1] = pkt.dw[1];
    ring[ofs + 2] = pkt.dw[2];
    ring[ofs + 3] = kIntelMiNoop;
    const u32 new_tail = static_cast<u32>(((ofs + 4u) * 4u) % kIntelRingBytes);
    mm::DmaSyncForDevice(g_rcs_ring, 0, kIntelRingBytes);
    Mmio32Write(g, kIntelRcsTail, new_tail);

    constexpr u64 kTimeoutNs = 100ull * 1000ull * 1000ull;
    constexpr u32 kIterCap = 1u << 20;
    const u64 start_ns = ::duetos::time::MonotonicNs();
    bool advanced = false;
    for (u32 iter = 0; iter < kIterCap; ++iter)
    {
        if (Mmio32(g, kIntelRcsHead) == new_tail)
        {
            advanced = true;
            break;
        }
        asm volatile("pause" ::: "memory");
        if (start_ns != 0)
        {
            const u64 now = ::duetos::time::MonotonicNs();
            if (now > start_ns && (now - start_ns) > kTimeoutNs)
                break;
        }
    }
    if (!advanced)
    {
        KLOG_WARN("drivers/gpu/intel", "RCS batch-exec: HEAD did not catch TAIL");
        mm::FreeDmaCoherent(batch);
        return 0xFFFFFFFFu;
    }
    mm::DmaSyncForCpu(g_rcs_scratch, 0, 4u);
    const u32 readback = *scratch;
    // The batch's GGTT slot leaks (one high-window entry) — acceptable
    // for a one-shot boot probe; the page itself is freed.
    mm::FreeDmaCoherent(batch);
    return readback;
}

u32 IntelBltColorFillProbe(u32 argb)
{
    // Escalation rung 4: the first ACCELERATED workload. GGTT-map an
    // OFFSCREEN 32-bpp page, XY_COLOR_BLT a solid colour into it, flush,
    // and read pixel[0] back over the CPU mapping. Never touches the
    // live framebuffer (the safe pre-scanout proof). 0xFFFFFFFF on
    // not-ready / failure. Gated; real-HW only.
    if (!g_brought_up || g_intel_info == nullptr || g_rcs_ring.virt == nullptr || !GgttReady())
        return 0xFFFFFFFFu;
    const GpuInfo& g = *g_intel_info;

    auto sr = mm::AllocDmaCoherent(0x1000u, mm::Zone::Normal);
    if (!sr.has_value())
        return 0xFFFFFFFFu;
    mm::DmaBuffer surf = sr.value();
    const u64 surf_va = GgttMapPage(g, surf.phys);
    if (surf_va == 0)
    {
        mm::FreeDmaCoherent(surf);
        return 0xFFFFFFFFu;
    }
    // Pre-clear to a known non-fill value so a stale read can't pass.
    auto* px = static_cast<volatile u32*>(surf.virt);
    for (u32 i = 0; i < 0x1000u / 4u; ++i)
        px[i] = 0xDEADBEEFu;
    mm::DmaSyncForDevice(surf, 0, 0x1000u);

    // Fill an 8x1 rect at (0,0) of a one-page (4096-byte-pitch) surface.
    const ColorBltPacket blt = EncodeColorBlt(surf_va, /*pitch=*/0x1000u, 0, 0, 8, 1, argb);
    u32* ring = static_cast<u32*>(g_rcs_ring.virt);
    const u64 ring_dwords = kIntelRingBytes / 4u;
    const u32 cur_tail = Mmio32(g, kIntelRcsTail);
    u64 ofs = (cur_tail / 4u) % ring_dwords;
    constexpr u64 kNeed = 7u + 3u; // 7-dword BLT + 3-dword MI_FLUSH_DW (even)
    if (ofs + kNeed > ring_dwords)
    {
        while (ofs < ring_dwords)
            ring[ofs++] = kIntelMiNoop;
        ofs = 0;
    }
    for (u32 i = 0; i < 7; ++i)
        ring[ofs + i] = blt.dw[i];
    ring[ofs + 7] = kMiFlushDw; // MI_FLUSH_DW (len 1 -> 3 dwords)
    ring[ofs + 8] = 0;          // post-sync address = none
    ring[ofs + 9] = 0;          // post-sync data = none
    const u32 new_tail = static_cast<u32>(((ofs + kNeed) * 4u) % kIntelRingBytes);
    mm::DmaSyncForDevice(g_rcs_ring, 0, kIntelRingBytes);
    Mmio32Write(g, kIntelRcsTail, new_tail);

    constexpr u64 kTimeoutNs = 100ull * 1000ull * 1000ull;
    constexpr u32 kIterCap = 1u << 20;
    const u64 start_ns = ::duetos::time::MonotonicNs();
    bool advanced = false;
    for (u32 iter = 0; iter < kIterCap; ++iter)
    {
        if (Mmio32(g, kIntelRcsHead) == new_tail)
        {
            advanced = true;
            break;
        }
        asm volatile("pause" ::: "memory");
        if (start_ns != 0)
        {
            const u64 now = ::duetos::time::MonotonicNs();
            if (now > start_ns && (now - start_ns) > kTimeoutNs)
                break;
        }
    }
    if (!advanced)
    {
        KLOG_WARN("drivers/gpu/intel", "RCS blt-fill: HEAD did not catch TAIL");
        mm::FreeDmaCoherent(surf);
        return 0xFFFFFFFFu;
    }
    mm::DmaSyncForCpu(surf, 0, 4u);
    const u32 readback = px[0];
    mm::FreeDmaCoherent(surf); // GGTT slot leaks (one high-window entry) — fine for a one-shot probe
    return readback;
}

bool IsBroughtUp()
{
    return g_brought_up;
}

void IntelRcsRingSelfTest()
{
    // Walk the GPU records and find an Intel display controller.
    // Self-tests run after `GpuInit` populates the cache, so by
    // this point every PCI display controller has been classified.
    const u64 n = GpuCount();
    bool found = false;
    for (u64 i = 0; i < n; ++i)
    {
        const GpuInfo& info = Gpu(i);
        if (info.vendor_id == kVendorIntel)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        // Typical QEMU `-vga std` / `-vga virtio` boot. Not a
        // failure — the structural sentinel CI greps for says so
        // explicitly so a regression that loses the Intel record
        // is distinguishable from a host that never had one.
        arch::SerialWrite("[gpu/intel/rcs] no Intel device — skipped\n");
        return;
    }

    if (IsBroughtUp())
    {
        // Fire one MI_STORE_DWORD_IMM through the ring and verify
        // the scratch dword reads back the value. This goes beyond
        // the MI_NOOP-only liveness check: a wedged-but-running
        // engine could advance HEAD on MI_NOOPs without actually
        // executing meaningful work, but it cannot store a chosen
        // value to a chosen address without honouring the opcode.
        constexpr u32 kStoreImmCookie = 0xC0DEFACEu;
        const u32 readback = IntelRcsStoreImmProbe(kStoreImmCookie);
        if (readback == kStoreImmCookie)
        {
            arch::SerialWrite("[gpu/intel/rcs] selftest PASS (ring online, MI_STORE_DWORD_IMM verified, "
                              "scratch=0xC0DEFACE)\n");
            // Escalation rung 3 (real-HW only): dispatch a GGTT-mapped
            // batch via MI_BATCH_BUFFER_START. Informational — batch
            // execution has never been proven on silicon, so a miss is
            // "not yet working", not a regression; we don't fail the
            // boot on it (unlike the store-imm rung, which a wedged
            // engine genuinely regressing would trip).
            constexpr u32 kBatchCookie = 0xBA7C0DE5u;
            const u32 batch_rb = IntelBatchExecProbe(kBatchCookie);
            if (batch_rb == kBatchCookie)
                arch::SerialWrite("[gpu/intel/cmds] batch-exec PASS (GGTT MI_BATCH_BUFFER_START + store, "
                                  "scratch=0xBA7C0DE5)\n");
            else
            {
                arch::SerialWrite("[gpu/intel/cmds] batch-exec readback=");
                arch::SerialWriteHex(batch_rb);
                arch::SerialWrite(" (GGTT batch dispatch unverified on this part)\n");
            }
            // Escalation rung 4 (real-HW only): the first ACCELERATED
            // workload — XY_COLOR_BLT into an offscreen surface, read
            // the pixel back. Informational (never proven on silicon).
            constexpr u32 kBltColor = 0xFF00FF00u;
            const u32 blt_rb = IntelBltColorFillProbe(kBltColor);
            if (blt_rb == kBltColor)
                arch::SerialWrite("[gpu/intel/cmds] blt-fill PASS (XY_COLOR_BLT offscreen, pixel=0xFF00FF00)\n");
            else
            {
                arch::SerialWrite("[gpu/intel/cmds] blt-fill readback=");
                arch::SerialWriteHex(blt_rb);
                arch::SerialWrite(" (2D BLT unverified on this part)\n");
            }
            return;
        }
        // The bring-up succeeded but the store-imm didn't land.
        // On real Intel hardware that's a regression worth flagging
        // (engine accepts NOOP, refuses or silently drops STORE).
        // On QEMU / virtio (which we already filtered out via the
        // "no Intel device" path earlier) we never get here.
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, readback);
        arch::SerialWrite("[gpu/intel/rcs] selftest FAIL (ring online but MI_STORE_DWORD_IMM readback=");
        arch::SerialWriteHex(readback);
        arch::SerialWrite(")\n");
        return;
    }

    // Intel device present but the bring-up didn't reach the live
    // state. This is the regression case — the bring-up itself
    // will have already fired `kGpuRingBringupFail` and dropped a
    // WARN, so we don't duplicate that here. We still fire
    // `kBootSelftestFail` so the canonical "boot self-test
    // regressed" GDB break catches it.
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, /*sub-check tag*/ 0xC51u);
    arch::SerialWrite("[gpu/intel/rcs] selftest FAIL (Intel device present, ring not online)\n");
}

} // namespace duetos::drivers::gpu::intel
