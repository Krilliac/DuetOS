/*
 * DuetOS — NVIDIA GeForce (Turing+) driver scaffold: implementation.
 *
 * See `nvidia_gpu.h` for v0 scope.
 */

#include "drivers/gpu/nvidia_gpu.h"

#include "arch/x86_64/serial.h"
#include "drivers/gpu/nvidia_gsp_fw.h"
#include "loader/firmware_loader.h"
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
// Probe + parse the nvfw_bin_hdr container on each blob the loader
// returns. Symmetric with the AMD GFX-firmware parser path —
// FwLoad → NvidiaGspFwParse → NvidiaGspFwLog → FwRelease, so an
// operator who dropped a gsp_tu10x.bin (etc.) sees the descriptor
// arch class + payload size in the boot log.
void ProbeAndParseNvidiaBlob(const char* basename)
{
    ProbeFirmwareBlob("nvidia-gpu", "[gpu/nvidia]", basename);

    ::duetos::core::FwLoadRequest req{};
    req.vendor = "nvidia-gpu";
    req.basename = basename;
    req.min_bytes = kNvidiaBinHdrBytes;
    req.max_bytes = kNvidiaMaxGspImageBytes;
    auto fw = ::duetos::core::FwLoad(req);
    if (!fw.has_value())
        return;
    NvidiaGspFwParsed parsed{};
    auto r = NvidiaGspFwParse(fw.value().data, fw.value().size, &parsed);
    if (r.has_value())
    {
        NvidiaGspFwLog(basename, parsed);
    }
    else
    {
        arch::SerialWrite("[gpu/nvidia-fw] ");
        arch::SerialWrite(basename);
        arch::SerialWrite(" rejected (reason=");
        arch::SerialWriteHex(parsed.reject_reason);
        arch::SerialWrite(")\n");
    }
    ::duetos::core::FwRelease(fw.value());
}

void ProbeFirmwareBlobs()
{
    ProbeAndParseNvidiaBlob("gsp_rm.bin");
    ProbeAndParseNvidiaBlob("gsp_log.bin");
    ProbeAndParseNvidiaBlob("bootloader.bin");
}

// Helpers shared by the bring-up state machine and the self-test.
// (Still inside the file-local anonymous namespace opened above.)

// Little-endian store/load — the GSP RPC ring is LE on the wire.
void StoreLe32(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
    p[2] = static_cast<u8>((v >> 16) & 0xFFu);
    p[3] = static_cast<u8>((v >> 24) & 0xFFu);
}

u32 LoadLe32(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

// Additive checksum over `len` payload bytes. Cheap corruption
// guard — matches the open-gpu-kernel-modules RPC checksum, not a
// security primitive.
u32 PayloadChecksum(const u8* payload, u32 len)
{
    u32 sum = 0;
    for (u32 i = 0; i < len; ++i)
        sum += payload[i];
    return sum;
}

bool IsPowerOfTwo(u32 v)
{
    return v != 0 && (v & (v - 1)) == 0;
}

u64 AlignUp(u64 v, u64 align)
{
    return (v + (align - 1)) & ~(align - 1);
}

} // namespace

::duetos::core::Result<void> GspRpcEncode(u8* slot, u32 slot_bytes, u32 function, const u8* payload, u32 payload_len,
                                          u32 sequence)
{
    if (slot == nullptr || (payload == nullptr && payload_len != 0))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    // Header + payload must fit the slot, and total length must not
    // overflow a u32 (payload_len is bounded well below that, but
    // guard the arithmetic anyway).
    if (payload_len > slot_bytes - kGspRpcHeaderBytes || slot_bytes < kGspRpcHeaderBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BufferTooSmall};

    const u32 total = kGspRpcHeaderBytes + payload_len;
    StoreLe32(slot + 0, function);
    StoreLe32(slot + 4, total);
    StoreLe32(slot + 8, sequence);
    StoreLe32(slot + 12, PayloadChecksum(payload, payload_len));
    for (u32 i = 0; i < payload_len; ++i)
        slot[kGspRpcHeaderBytes + i] = payload[i];
    return {};
}

::duetos::core::Result<void> GspRpcDecode(const u8* slot, u32 slot_bytes, GspRpcHeader* out)
{
    if (slot == nullptr || out == nullptr || slot_bytes < kGspRpcHeaderBytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    GspRpcHeader h{};
    h.function = LoadLe32(slot + 0);
    h.length = LoadLe32(slot + 4);
    h.sequence = LoadLe32(slot + 8);
    h.checksum = LoadLe32(slot + 12);
    *out = h;

    // Length must cover at least the header and fit the slot.
    if (h.length < kGspRpcHeaderBytes || h.length > slot_bytes)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    const u32 payload_len = h.length - kGspRpcHeaderBytes;
    if (PayloadChecksum(slot + kGspRpcHeaderBytes, payload_len) != h.checksum)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Corrupt};
    return {};
}

::duetos::core::Result<u32> GspRingAdvance(u32 index, u32 slot_count)
{
    if (!IsPowerOfTwo(slot_count))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    // Power-of-two count: wrap with a mask, no division.
    return (index + 1) & (slot_count - 1);
}

::duetos::core::Result<GspWprLayout> GspComputeWprLayout(u64 vram_end, u64 fw_image_size, u64 radix3_size)
{
    if (vram_end == 0 || fw_image_size == 0 || radix3_size == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // Pack top-down from vram_end: heap, boot-args, radix3, fw image.
    // Each sub-region is page-aligned; the WPR base is the lowest
    // aligned address that still holds the firmware image. We build
    // it bottom-up off a running total of aligned sizes, then anchor
    // wpr_base = vram_end - total so the region ends exactly at the
    // top of VRAM (where FRTS expects WPR2 to sit).
    const u64 fw_aligned = AlignUp(fw_image_size, kGspWprAlign);
    const u64 radix3_aligned = AlignUp(radix3_size, kGspWprAlign);
    const u64 boot_args_aligned = AlignUp(kGspBootArgsBytes, kGspWprAlign);
    const u64 heap_aligned = AlignUp(kGspDefaultHeapBytes, kGspWprAlign);

    const u64 total = fw_aligned + radix3_aligned + boot_args_aligned + heap_aligned;
    if (total >= vram_end) // region would underflow the start of VRAM
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    GspWprLayout out{};
    out.vram_end = vram_end;
    out.wpr_base = vram_end - total;
    out.fw_image_off = out.wpr_base;
    out.fw_image_size = fw_image_size;
    out.radix3_off = out.fw_image_off + fw_aligned;
    out.radix3_size = radix3_size;
    out.boot_args_off = out.radix3_off + radix3_aligned;
    out.heap_off = out.boot_args_off + boot_args_aligned;
    out.heap_size = kGspDefaultHeapBytes;
    return out;
}

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

    // Drive the GSP bring-up state machine as far as it can go
    // without real silicon / a real per-asic firmware blob. Each
    // phase that completes purely in software is performed for real;
    // the first phase that needs hardware returns a precise typed
    // Result and the bring-up unwinds cleanly. `phase` tracks how
    // far we got so the failure log is specific about where the
    // chain terminated.
    GspBringupPhase phase = GspBringupPhase::Idle;

    // Phase 1 — firmware validation (REAL). Load the generic GSP RM
    // blob through the cap-gated firmware loader and run it through
    // the existing container parser. No firmware staged → there is
    // no path forward, so report the absence honestly.
    ::duetos::core::FwLoadRequest req{};
    req.vendor = "nvidia-gpu";
    req.basename = "gsp_rm.bin";
    req.min_bytes = kNvidiaBinHdrBytes;
    req.max_bytes = kNvidiaMaxGspImageBytes;
    auto fw = ::duetos::core::FwLoad(req);
    if (!fw.has_value())
    {
        arch::SerialWrite("[gpu/nvidia] GSP bring-up: gsp_rm.bin absent — no firmware to boot the GSP\n");
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};
    }
    NvidiaGspFwParsed parsed{};
    auto pr = NvidiaGspFwParse(fw.value().data, fw.value().size, &parsed);
    if (!pr.has_value())
    {
        arch::SerialWrite("[gpu/nvidia] GSP bring-up: gsp_rm.bin failed container validation\n");
        ::duetos::core::FwRelease(fw.value());
        return ::duetos::core::Err{pr.error()};
    }
    phase = GspBringupPhase::FirmwareValidated;

    // Phase 2 — WPR layout (REAL math). Compute the write-protected
    // region carve-up from the parsed payload size. We do not have a
    // VRAM size from a live BAR1 walk here, so use the firmware's own
    // declared size to size a representative region; the next slice
    // will plumb the real BAR1 aperture in. The radix-3 page-table
    // size is a function of the payload page count; a conservative
    // 1/64th-of-payload estimate is enough for the layout to be
    // structurally exercised.
    const u64 fw_image_size = parsed.payload_size;
    const u64 radix3_size = (fw_image_size / 64) + kGspWprAlign;
    const u64 representative_vram_end = fw_image_size + radix3_size + kGspBootArgsBytes + kGspDefaultHeapBytes +
                                        (16ull * 1024 * 1024); // headroom below VRAM top
    auto wpr = GspComputeWprLayout(representative_vram_end, fw_image_size, radix3_size);
    ::duetos::core::FwRelease(fw.value());
    if (!wpr.has_value())
        return ::duetos::core::Err{wpr.error()};
    phase = GspBringupPhase::WprLaidOut;

    arch::SerialWrite("[gpu/nvidia] GSP WPR layout: base=");
    arch::SerialWriteHex(wpr.value().wpr_base);
    arch::SerialWrite(" fw_off=");
    arch::SerialWriteHex(wpr.value().fw_image_off);
    arch::SerialWrite(" heap_off=");
    arch::SerialWriteHex(wpr.value().heap_off);
    arch::SerialWrite("\n");

    // Phase 3 — RPC ring allocation (REAL). The command (host->GSP)
    // and message (GSP->host) rings live in host system memory; the
    // GSP is handed their GPAs. Allocate + zero them now so the
    // bring-up exercises the real DMA path.
    GspRpcRing cmd_ring{};
    GspRpcRing msg_ring{};
    auto cr = mm::AllocDmaCoherent(kGspRpcRingBytes, mm::Zone::Dma32);
    if (!cr.has_value())
        return ::duetos::core::Err{cr.error()};
    cmd_ring.dma = cr.value();
    cmd_ring.slot_count = kGspRpcSlotCount;
    cmd_ring.slot_bytes = kGspRpcSlotBytes;

    auto mr = mm::AllocDmaCoherent(kGspRpcRingBytes, mm::Zone::Dma32);
    if (!mr.has_value())
    {
        mm::FreeDmaCoherent(cmd_ring.dma);
        return ::duetos::core::Err{mr.error()};
    }
    msg_ring.dma = mr.value();
    msg_ring.slot_count = kGspRpcSlotCount;
    msg_ring.slot_bytes = kGspRpcSlotBytes;
    phase = GspBringupPhase::RingsAllocated;

    arch::SerialWrite("[gpu/nvidia] GSP RPC rings: cmd_phys=");
    arch::SerialWriteHex(cmd_ring.dma.phys);
    arch::SerialWrite(" msg_phys=");
    arch::SerialWriteHex(msg_ring.dma.phys);
    arch::SerialWrite("\n");

    // Phase 4 — boot the GSP (NEEDS HARDWARE). Staging the firmware +
    // page tables into the WPR, locking it via FWSEC/SEC2 FRTS, and
    // releasing the GSP RISC-V core from reset all require register
    // writes to a live NVIDIA GPU and a real per-asic signed blob.
    // We have neither in this configuration, so the chain stops here
    // — honestly, without faking a boot. The rings + WPR layout we
    // computed are what the next slice feeds into that sequence.
    //
    // GAP: GSP boot (WPR stage + FRTS lock + RISC-V release), RPC
    //      channel open, and PFIFO channel submit all need real
    //      NVIDIA silicon + a signed per-asic gsp_*.bin + the
    //      (undocumented) RPC schema — revisit when the SEC2 booter
    //      slice + a hardware test rig land.
    arch::SerialWrite("[gpu/nvidia] GSP bring-up reached phase=RingsAllocated; "
                      "GSP boot needs real hardware + signed firmware — stopping\n");
    (void)phase; // terminal value captured by the log above
    mm::FreeDmaCoherent(msg_ring.dma);
    mm::FreeDmaCoherent(cmd_ring.dma);

    return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
}

bool IsBroughtUp()
{
    return g_brought_up;
}

// Structural self-test for the GSP bring-up helpers. Exercises the
// pure logic that needs neither hardware nor firmware: RPC header
// encode/decode round-trip, ring-index wrap, and WPR layout math.
// Returns false (and logs which sub-check tripped) on regression.
bool GspStructuralSelfTest()
{
    // 1. RPC encode/decode round-trip with a small payload.
    u8 slot[kGspRpcSlotBytes] = {};
    const u8 payload[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    auto enc = GspRpcEncode(slot, sizeof(slot), kGspRpcFnAllocChannel, payload, sizeof(payload), 7);
    if (!enc.has_value())
    {
        arch::SerialWrite("[nvidia-gsp-selftest] FAIL (encode)\n");
        return false;
    }
    GspRpcHeader hdr{};
    auto dec = GspRpcDecode(slot, sizeof(slot), &hdr);
    if (!dec.has_value() || hdr.function != kGspRpcFnAllocChannel ||
        hdr.length != kGspRpcHeaderBytes + sizeof(payload) || hdr.sequence != 7)
    {
        arch::SerialWrite("[nvidia-gsp-selftest] FAIL (decode round-trip)\n");
        return false;
    }

    // 2. Corruption is caught: flip a payload byte, decode must reject.
    slot[kGspRpcHeaderBytes] ^= 0xFFu;
    if (GspRpcDecode(slot, sizeof(slot), &hdr).has_value())
    {
        arch::SerialWrite("[nvidia-gsp-selftest] FAIL (corruption not caught)\n");
        return false;
    }

    // 3. Oversize payload is refused.
    if (GspRpcEncode(slot, sizeof(slot), kGspRpcFnNop, payload, kGspRpcSlotBytes, 0).has_value())
    {
        arch::SerialWrite("[nvidia-gsp-selftest] FAIL (oversize accepted)\n");
        return false;
    }

    // 4. Ring index wraps at slot_count and rejects non-power-of-two.
    auto adv = GspRingAdvance(kGspRpcSlotCount - 1, kGspRpcSlotCount);
    if (!adv.has_value() || adv.value() != 0 || GspRingAdvance(0, 17).has_value())
    {
        arch::SerialWrite("[nvidia-gsp-selftest] FAIL (ring wrap)\n");
        return false;
    }

    // 5. WPR layout math: sub-regions page-aligned, ordered, ending
    //    exactly at vram_end, and undersized VRAM rejected.
    const u64 vram_end = 256ull * 1024 * 1024;
    auto wpr = GspComputeWprLayout(vram_end, 0x400000, 0x10000);
    if (!wpr.has_value())
    {
        arch::SerialWrite("[nvidia-gsp-selftest] FAIL (wpr layout)\n");
        return false;
    }
    const GspWprLayout& w = wpr.value();
    const bool aligned = (w.wpr_base % kGspWprAlign) == 0 && (w.radix3_off % kGspWprAlign) == 0 &&
                         (w.boot_args_off % kGspWprAlign) == 0 && (w.heap_off % kGspWprAlign) == 0;
    const bool ordered = w.fw_image_off < w.radix3_off && w.radix3_off < w.boot_args_off &&
                         w.boot_args_off < w.heap_off && (w.heap_off + w.heap_size) <= vram_end;
    if (!aligned || !ordered || w.wpr_base != w.fw_image_off)
    {
        arch::SerialWrite("[nvidia-gsp-selftest] FAIL (wpr layout bounds)\n");
        return false;
    }
    if (GspComputeWprLayout(4096, 0x400000, 0x10000).has_value())
    {
        arch::SerialWrite("[nvidia-gsp-selftest] FAIL (undersize vram accepted)\n");
        return false;
    }

    arch::SerialWrite("[nvidia-gsp-selftest] PASS (rpc encode/decode, ring wrap, wpr layout)\n");
    return true;
}

void NvidiaGspSelfTest()
{
    // Structural helpers first — these need no device and run on
    // every boot, so the bring-up math is covered even on the
    // typical QEMU host that has no NVIDIA GPU at all.
    GspStructuralSelfTest();

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
