#include "virtio_gpu.h"

#include "../../arch/x86_64/serial.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../pci/pci.h"

namespace duetos::drivers::gpu
{

namespace
{

// virtio-pci capability (virtio 1.0 §4.1.4):
//   cap + 0  : standard PCI cap header (id=0x09, next)
//   cap + 2  : cap_len (at least 16)
//   cap + 3  : cfg_type (1=common, 2=notify, 3=isr, 4=device, 5=access)
//   cap + 4  : bar (0..5)
//   cap + 5  : id (allows multiple caps of same type)
//   cap + 6  : padding
//   cap + 8  : offset (u32 LE) — byte offset into the BAR
//   cap + 12 : length (u32 LE) — bytes
// For cfg_type == 2 (notify), a trailing u32 at cap + 16 carries
// `notify_off_multiplier`.
constexpr u8 kVirtioCapId = 0x09;
constexpr u8 kVirtioCfgCommon = 1;
constexpr u8 kVirtioCfgNotify = 2;
constexpr u8 kVirtioCfgIsr = 3;
constexpr u8 kVirtioCfgDevice = 4;

// Common config register offsets (virtio 1.0 §4.1.4.3).
constexpr u64 kCcDeviceFeatureSelect = 0x00;
constexpr u64 kCcDeviceFeature = 0x04;
constexpr u64 kCcDeviceStatus = 0x14;
constexpr u64 kCcNumQueues = 0x12;

// Device status bits (virtio 1.0 §2.1).
[[maybe_unused]] constexpr u8 kStatusAck = 0x01;
[[maybe_unused]] constexpr u8 kStatusDriver = 0x02;
[[maybe_unused]] constexpr u8 kStatusDriverOk = 0x04;
[[maybe_unused]] constexpr u8 kStatusFeaturesOk = 0x08;

constinit VirtioGpuLayout g_last = {};

u8 CapRead8(pci::DeviceAddress a, u8 off)
{
    return pci::PciConfigRead8(a, off);
}
u16 CapRead16(pci::DeviceAddress a, u8 off)
{
    return pci::PciConfigRead16(a, off);
}
u32 CapRead32(pci::DeviceAddress a, u8 off)
{
    return pci::PciConfigRead32(a, off);
}

volatile u8* MapCapRegion(pci::DeviceAddress a, u8 bir, u32 offset, u32 length, u64* out_phys)
{
    const pci::Bar bar = pci::PciReadBar(a, bir);
    if (bar.size == 0 || bar.is_io || offset + length > bar.size)
        return nullptr;
    const u64 region_phys = bar.address + offset;
    *out_phys = region_phys;
    // Page-align the map so MapMmio's alignment-granular bounds
    // are respected; return a pointer into the leading-padded
    // region.
    constexpr u64 kPageMask = 0xFFFu;
    const u64 base_phys = region_phys & ~kPageMask;
    const u64 leading = region_phys - base_phys;
    const u64 bytes = (leading + length + kPageMask) & ~kPageMask;
    void* virt = mm::MapMmio(base_phys, bytes);
    if (virt == nullptr)
        return nullptr;
    return static_cast<volatile u8*>(virt) + leading;
}

} // namespace

VirtioGpuLayout VirtioGpuProbe(u8 bus, u8 device, u8 function)
{
    VirtioGpuLayout L = {};
    pci::DeviceAddress addr = {};
    addr.bus = bus;
    addr.device = device;
    addr.function = function;

    // Capabilities list present bit.
    const u16 status = CapRead16(addr, 0x06);
    if ((status & (1U << 4)) == 0)
        return L;
    u8 cursor = CapRead8(addr, 0x34) & 0xFC;
    for (int hops = 0; hops < 48 && cursor != 0; ++hops)
    {
        const u8 id = CapRead8(addr, cursor);
        const u8 next = CapRead8(addr, static_cast<u8>(cursor + 1)) & 0xFC;
        if (id == kVirtioCapId)
        {
            const u8 cap_len = CapRead8(addr, static_cast<u8>(cursor + 2));
            const u8 cfg_type = CapRead8(addr, static_cast<u8>(cursor + 3));
            const u8 bir = CapRead8(addr, static_cast<u8>(cursor + 4));
            const u32 offset = CapRead32(addr, static_cast<u8>(cursor + 8));
            const u32 length = CapRead32(addr, static_cast<u8>(cursor + 12));
            u64 phys = 0;
            volatile u8* mapped = MapCapRegion(addr, bir, offset, length, &phys);
            if (mapped == nullptr)
            {
                arch::SerialWrite("[virtio-gpu] cap cfg_type=");
                arch::SerialWriteHex(cfg_type);
                arch::SerialWrite(" map failed (bar ");
                arch::SerialWriteHex(bir);
                arch::SerialWrite(")\n");
            }
            else
            {
                switch (cfg_type)
                {
                case kVirtioCfgCommon:
                    L.common_cfg = mapped;
                    L.common_cfg_phys = phys;
                    break;
                case kVirtioCfgNotify:
                    L.notify = mapped;
                    L.notify_phys = phys;
                    if (cap_len >= 20)
                    {
                        L.notify_off_multiplier = CapRead32(addr, static_cast<u8>(cursor + 16));
                    }
                    break;
                case kVirtioCfgIsr:
                    L.isr = mapped;
                    L.isr_phys = phys;
                    break;
                case kVirtioCfgDevice:
                    L.device_cfg = mapped;
                    L.device_cfg_phys = phys;
                    break;
                default:
                    break; // ignore pci-access + unknown
                }
            }
        }
        if (next == cursor)
            break;
        cursor = next;
    }

    if (L.common_cfg != nullptr)
    {
        // Reset: write 0 to device_status, read back until 0 to
        // confirm the controller saw it. virtio 1.0 §3.1.1.
        *reinterpret_cast<volatile u8*>(L.common_cfg + kCcDeviceStatus) = 0;
        for (u32 i = 0; i < 1000; ++i)
        {
            if (*reinterpret_cast<volatile u8*>(L.common_cfg + kCcDeviceStatus) == 0)
                break;
            asm volatile("pause" ::: "memory");
        }
        L.device_status_after_reset = *reinterpret_cast<volatile u8*>(L.common_cfg + kCcDeviceStatus);
        L.num_queues = *reinterpret_cast<volatile u16*>(L.common_cfg + kCcNumQueues);
        // Snapshot low-32 of device features.
        *reinterpret_cast<volatile u32*>(L.common_cfg + kCcDeviceFeatureSelect) = 0;
        L.device_features_lo = *reinterpret_cast<volatile u32*>(L.common_cfg + kCcDeviceFeature);
        L.present = true;

        arch::SerialWrite("[virtio-gpu] common_cfg phys=");
        arch::SerialWriteHex(L.common_cfg_phys);
        arch::SerialWrite(" num_queues=");
        arch::SerialWriteHex(L.num_queues);
        arch::SerialWrite(" device_features_lo=");
        arch::SerialWriteHex(L.device_features_lo);
        arch::SerialWrite(" status_after_reset=");
        arch::SerialWriteHex(L.device_status_after_reset);
        arch::SerialWrite("\n");
    }
    else
    {
        arch::SerialWrite("[virtio-gpu] common_cfg capability not found — probe aborted\n");
    }

    g_last = L;
    return L;
}

VirtioGpuLayout VirtioGpuLastLayout()
{
    return g_last;
}

// ======================================================================
// virtio-gpu v1 — split virtqueue + GET_DISPLAY_INFO
// ======================================================================

namespace
{

// Split-virtqueue descriptor (virtio 1.0 §2.6.5). 16 bytes.
struct VirtqDesc
{
    u64 addr;
    u32 len;
    u16 flags;
    u16 next;
};

constexpr u16 kDescNext = 0x1;
constexpr u16 kDescWrite = 0x2;

// Available ring (virtio 1.0 §2.6.6). Variable-length ring[] follows.
struct VirtqAvailHdr
{
    u16 flags;
    u16 idx;
    // u16 ring[queue_size] follows here.
};

// Used-ring element (virtio 1.0 §2.6.8).
struct VirtqUsedElem
{
    u32 id;
    u32 len;
};

// Used ring header (variable-length ring[] follows).
struct VirtqUsedHdr
{
    u16 flags;
    u16 idx;
    // VirtqUsedElem ring[queue_size] follows here.
};

// Chosen queue size. Needs to be a power of 2 and <= the device's
// advertised queue_size. 32 is well under every sane device cap
// (QEMU's virtio-gpu exposes 256) and keeps per-queue memory tiny.
constexpr u16 kQueueSize = 32;

// common_cfg offsets (virtio 1.0 §4.1.4.3) — any we didn't need in
// the probe.
constexpr u64 kCcDriverFeatureSelect = 0x08;
constexpr u64 kCcDriverFeature = 0x0C;
constexpr u64 kCcQueueSelect = 0x16;
constexpr u64 kCcQueueSize = 0x18;
constexpr u64 kCcQueueEnable = 0x1C;
constexpr u64 kCcQueueNotifyOff = 0x1E;
constexpr u64 kCcQueueDesc = 0x20;
constexpr u64 kCcQueueDriver = 0x28;
constexpr u64 kCcQueueDevice = 0x30;

// device_status bits.
constexpr u8 kStsAck = 0x01;
constexpr u8 kStsDriver = 0x02;
constexpr u8 kStsDriverOk = 0x04;
constexpr u8 kStsFeaturesOk = 0x08;
constexpr u8 kStsFailed = 0x80;

// virtio-gpu control commands (virtio 1.0 §5.7.6.7).
constexpr u32 kCmdGetDisplayInfo = 0x0100;

// virtio-gpu response types.
constexpr u32 kRespOkDisplayInfo = 0x1101;

// Control header (virtio 1.0 §5.7.6.8). 24 bytes.
struct GpuCtrlHdr
{
    u32 type;
    u32 flags;
    u64 fence_id;
    u32 ctx_id;
    u8 ring_idx;
    u8 padding[3];
};

// Response to GET_DISPLAY_INFO (virtio 1.0 §5.7.6.4).
struct GpuRespDisplayInfo
{
    GpuCtrlHdr hdr;
    struct
    {
        u32 x;
        u32 y;
        u32 width;
        u32 height;
        u32 enabled;
        u32 flags;
    } pmodes[kVirtioGpuMaxScanouts];
};

struct ControlQ
{
    bool up;
    u16 queue_size;
    u16 last_used_idx; // last `used->idx` we consumed
    u16 next_avail;    // our own increment, written into avail->idx

    ::duetos::mm::PhysAddr desc_phys;
    ::duetos::mm::PhysAddr avail_phys;
    ::duetos::mm::PhysAddr used_phys;
    ::duetos::mm::PhysAddr req_phys;
    ::duetos::mm::PhysAddr resp_phys;

    volatile VirtqDesc* desc;
    volatile VirtqAvailHdr* avail_hdr;
    volatile u16* avail_ring;
    volatile VirtqUsedHdr* used_hdr;
    volatile VirtqUsedElem* used_ring;
    volatile u8* notify_reg;

    // Shared request/response pages. One command is in flight at a
    // time (we poll), so a single page pair suffices.
    u8* req_buf;
    u8* resp_buf;
};

constinit ControlQ g_cq = {};
constinit VirtioDisplayInfo g_last_display = {};

u8 ReadStatus()
{
    return *reinterpret_cast<volatile u8*>(g_last.common_cfg + kCcDeviceStatus);
}

void WriteStatus(u8 v)
{
    *reinterpret_cast<volatile u8*>(g_last.common_cfg + kCcDeviceStatus) = v;
}

void Write16(u64 off, u16 v)
{
    *reinterpret_cast<volatile u16*>(g_last.common_cfg + off) = v;
}

u16 Read16(u64 off)
{
    return *reinterpret_cast<volatile u16*>(g_last.common_cfg + off);
}

void Write32(u64 off, u32 v)
{
    *reinterpret_cast<volatile u32*>(g_last.common_cfg + off) = v;
}

void Write64(u64 off, u64 v)
{
    // common_cfg alignment is 4 bytes (virtio 1.0 §4.1.3), so split
    // 64-bit writes into two 32-bit stores, low half first.
    *reinterpret_cast<volatile u32*>(g_last.common_cfg + off) = static_cast<u32>(v);
    *reinterpret_cast<volatile u32*>(g_last.common_cfg + off + 4) = static_cast<u32>(v >> 32);
}

bool AllocOnePage(::duetos::mm::PhysAddr* phys_out, void** virt_out)
{
    const ::duetos::mm::PhysAddr f = ::duetos::mm::AllocateFrame();
    if (f == ::duetos::mm::kNullFrame)
        return false;
    void* v = ::duetos::mm::PhysToVirt(f);
    // Zero the page — descriptor tables and buffers must start at a
    // known state so stale bits don't look like valid entries.
    u8* bytes = static_cast<u8*>(v);
    for (u64 i = 0; i < 4096; ++i)
        bytes[i] = 0;
    *phys_out = f;
    *virt_out = v;
    return true;
}

bool AllocateQueueRings(ControlQ& q)
{
    // Each ring fits comfortably in one 4 KiB page at queue_size=32:
    //   desc: 32 * 16 = 512 B
    //   avail: 4 + 32*2 = 68 B
    //   used:  4 + 32*8 = 260 B
    void* desc_v = nullptr;
    void* avail_v = nullptr;
    void* used_v = nullptr;
    void* req_v = nullptr;
    void* resp_v = nullptr;
    if (!AllocOnePage(&q.desc_phys, &desc_v))
        return false;
    if (!AllocOnePage(&q.avail_phys, &avail_v))
        return false;
    if (!AllocOnePage(&q.used_phys, &used_v))
        return false;
    if (!AllocOnePage(&q.req_phys, &req_v))
        return false;
    if (!AllocOnePage(&q.resp_phys, &resp_v))
        return false;
    q.desc = static_cast<volatile VirtqDesc*>(desc_v);
    q.avail_hdr = static_cast<volatile VirtqAvailHdr*>(avail_v);
    q.avail_ring = reinterpret_cast<volatile u16*>(static_cast<u8*>(avail_v) + sizeof(VirtqAvailHdr));
    q.used_hdr = static_cast<volatile VirtqUsedHdr*>(used_v);
    q.used_ring = reinterpret_cast<volatile VirtqUsedElem*>(static_cast<u8*>(used_v) + sizeof(VirtqUsedHdr));
    q.req_buf = static_cast<u8*>(req_v);
    q.resp_buf = static_cast<u8*>(resp_v);
    q.queue_size = kQueueSize;
    return true;
}

} // namespace

bool VirtioGpuBringUp()
{
    if (g_cq.up)
        return true;
    if (!g_last.present || g_last.common_cfg == nullptr || g_last.notify == nullptr)
    {
        arch::SerialWrite("[virtio-gpu] bring-up: no common_cfg or notify region — run VirtioGpuProbe first\n");
        return false;
    }

    // Spec step 2 + 3: ACK → DRIVER. Status was zero after reset in
    // VirtioGpuProbe, so start fresh.
    WriteStatus(kStsAck);
    WriteStatus(kStsAck | kStsDriver);

    // Spec step 4: feature negotiation. Accept no features — a
    // bare GET_DISPLAY_INFO has no feature dependencies. Read device
    // features just for the log.
    Write32(kCcDeviceFeatureSelect, 0);
    const u32 feat_lo = *reinterpret_cast<volatile u32*>(g_last.common_cfg + kCcDeviceFeature);
    Write32(kCcDriverFeatureSelect, 0);
    Write32(kCcDriverFeature, 0);
    Write32(kCcDriverFeatureSelect, 1);
    Write32(kCcDriverFeature, 0);
    (void)feat_lo;

    // Spec step 5: FEATURES_OK. Spec step 6: read back and confirm.
    WriteStatus(kStsAck | kStsDriver | kStsFeaturesOk);
    if ((ReadStatus() & kStsFeaturesOk) == 0)
    {
        arch::SerialWrite("[virtio-gpu] bring-up: device rejected empty feature set — FAILED\n");
        WriteStatus(kStsFailed);
        return false;
    }

    // Spec step 7: queue setup. We only need controlq (queue 0).
    Write16(kCcQueueSelect, 0);
    const u16 dev_qsize = Read16(kCcQueueSize);
    if (dev_qsize == 0)
    {
        arch::SerialWrite("[virtio-gpu] bring-up: controlq size=0 — device has no controlq?\n");
        WriteStatus(kStsFailed);
        return false;
    }
    if (dev_qsize < kQueueSize)
    {
        // Honour the device's cap if it's smaller than our default.
        Write16(kCcQueueSize, dev_qsize);
        g_cq.queue_size = dev_qsize;
    }
    else
    {
        Write16(kCcQueueSize, kQueueSize);
        g_cq.queue_size = kQueueSize;
    }

    if (!AllocateQueueRings(g_cq))
    {
        arch::SerialWrite("[virtio-gpu] bring-up: ring allocation failed (out of contiguous frames)\n");
        WriteStatus(kStsFailed);
        return false;
    }

    Write64(kCcQueueDesc, g_cq.desc_phys);
    Write64(kCcQueueDriver, g_cq.avail_phys);
    Write64(kCcQueueDevice, g_cq.used_phys);

    // Compute notify register address. virtio 1.0 §4.1.4.4:
    //   notify_addr = notify_base + queue_notify_off * notify_off_multiplier
    const u16 qno = Read16(kCcQueueNotifyOff);
    const u64 notify_bytes = static_cast<u64>(qno) * static_cast<u64>(g_last.notify_off_multiplier);
    g_cq.notify_reg = g_last.notify + notify_bytes;

    // Enable queue 0 last (spec §3.1.1 step 7).
    Write16(kCcQueueEnable, 1);

    // Spec step 8: DRIVER_OK. Device is now operational.
    WriteStatus(kStsAck | kStsDriver | kStsFeaturesOk | kStsDriverOk);

    g_cq.up = true;
    g_cq.last_used_idx = 0;
    g_cq.next_avail = 0;

    arch::SerialWrite("[virtio-gpu] bring-up OK  queue_size=");
    arch::SerialWriteHex(g_cq.queue_size);
    arch::SerialWrite(" desc_phys=");
    arch::SerialWriteHex(g_cq.desc_phys);
    arch::SerialWrite(" notify_off=");
    arch::SerialWriteHex(qno);
    arch::SerialWrite(" notify_mult=");
    arch::SerialWriteHex(g_last.notify_off_multiplier);
    arch::SerialWrite("\n");
    return true;
}

// Invalidate the cached display info (no memcpy — all fields
// explicit so the kernel freestanding link doesn't need libc).
void ResetLastDisplay()
{
    g_last_display.valid = false;
    g_last_display.active_scanouts = 0;
    for (u32 i = 0; i < kVirtioGpuMaxScanouts; ++i)
    {
        g_last_display.rects[i].x = 0;
        g_last_display.rects[i].y = 0;
        g_last_display.rects[i].width = 0;
        g_last_display.rects[i].height = 0;
        g_last_display.enabled[i] = 0;
        g_last_display.flags[i] = 0;
    }
}

const VirtioDisplayInfo& VirtioGpuGetDisplayInfo()
{
    ResetLastDisplay();
    if (!g_cq.up)
    {
        arch::SerialWrite("[virtio-gpu] GET_DISPLAY_INFO: bring-up has not run\n");
        return g_last_display;
    }

    // Build request in req_buf. GET_DISPLAY_INFO is just the header
    // with type=0x0100; no body.
    auto* req = reinterpret_cast<volatile GpuCtrlHdr*>(g_cq.req_buf);
    req->type = kCmdGetDisplayInfo;
    req->flags = 0;
    req->fence_id = 0;
    req->ctx_id = 0;
    req->ring_idx = 0;
    req->padding[0] = 0;
    req->padding[1] = 0;
    req->padding[2] = 0;

    // Clear response area so we can tell parsed-vs-stale.
    {
        u8* r = g_cq.resp_buf;
        for (u64 i = 0; i < sizeof(GpuRespDisplayInfo); ++i)
            r[i] = 0;
    }

    // Descriptor 0: device-read of req header (24 bytes).
    g_cq.desc[0].addr = g_cq.req_phys;
    g_cq.desc[0].len = sizeof(GpuCtrlHdr);
    g_cq.desc[0].flags = kDescNext;
    g_cq.desc[0].next = 1;

    // Descriptor 1: device-write of response.
    g_cq.desc[1].addr = g_cq.resp_phys;
    g_cq.desc[1].len = sizeof(GpuRespDisplayInfo);
    g_cq.desc[1].flags = kDescWrite;
    g_cq.desc[1].next = 0;

    // Publish on avail ring.
    const u16 slot = g_cq.next_avail % g_cq.queue_size;
    g_cq.avail_ring[slot] = 0;   // head descriptor index
    asm volatile("" ::: "memory");
    g_cq.next_avail = static_cast<u16>(g_cq.next_avail + 1);
    g_cq.avail_hdr->idx = g_cq.next_avail;

    asm volatile("" ::: "memory");

    // Kick the device. virtio-pci modern: write the queue index as
    // u16 to the notify register.
    *reinterpret_cast<volatile u16*>(g_cq.notify_reg) = 0;

    // Poll the used ring. GET_DISPLAY_INFO is synchronous on QEMU
    // (a few µs). Bound the spin so a broken device doesn't wedge
    // the kernel forever — ~1M pause iterations is plenty.
    u64 spins = 0;
    while (g_cq.used_hdr->idx == g_cq.last_used_idx)
    {
        asm volatile("pause" ::: "memory");
        if (++spins > 1'000'000)
        {
            arch::SerialWrite("[virtio-gpu] GET_DISPLAY_INFO: timeout waiting for used ring\n");
            return g_last_display;
        }
    }
    const u16 used_slot = g_cq.last_used_idx % g_cq.queue_size;
    const u32 resp_bytes = g_cq.used_ring[used_slot].len;
    g_cq.last_used_idx = static_cast<u16>(g_cq.last_used_idx + 1);

    asm volatile("" ::: "memory");

    auto* resp = reinterpret_cast<const GpuRespDisplayInfo*>(g_cq.resp_buf);
    if (resp->hdr.type != kRespOkDisplayInfo)
    {
        arch::SerialWrite("[virtio-gpu] GET_DISPLAY_INFO: unexpected resp_type=");
        arch::SerialWriteHex(resp->hdr.type);
        arch::SerialWrite(" (expected 0x1101)  len=");
        arch::SerialWriteHex(resp_bytes);
        arch::SerialWrite("\n");
        return g_last_display;
    }

    g_last_display.valid = true;
    g_last_display.active_scanouts = 0;
    for (u32 i = 0; i < kVirtioGpuMaxScanouts; ++i)
    {
        g_last_display.rects[i].x = resp->pmodes[i].x;
        g_last_display.rects[i].y = resp->pmodes[i].y;
        g_last_display.rects[i].width = resp->pmodes[i].width;
        g_last_display.rects[i].height = resp->pmodes[i].height;
        g_last_display.enabled[i] = resp->pmodes[i].enabled;
        g_last_display.flags[i] = resp->pmodes[i].flags;
        if (resp->pmodes[i].enabled != 0)
            g_last_display.active_scanouts++;
    }

    arch::SerialWrite("[virtio-gpu] GET_DISPLAY_INFO: active_scanouts=");
    arch::SerialWriteHex(g_last_display.active_scanouts);
    arch::SerialWrite("\n");
    for (u32 i = 0; i < kVirtioGpuMaxScanouts; ++i)
    {
        if (g_last_display.enabled[i] == 0)
            continue;
        arch::SerialWrite("  scanout ");
        arch::SerialWriteHex(i);
        arch::SerialWrite(": ");
        arch::SerialWriteHex(g_last_display.rects[i].width);
        arch::SerialWrite("x");
        arch::SerialWriteHex(g_last_display.rects[i].height);
        arch::SerialWrite(" @ (");
        arch::SerialWriteHex(g_last_display.rects[i].x);
        arch::SerialWrite(",");
        arch::SerialWriteHex(g_last_display.rects[i].y);
        arch::SerialWrite(") flags=");
        arch::SerialWriteHex(g_last_display.flags[i]);
        arch::SerialWrite("\n");
    }

    return g_last_display;
}

const VirtioDisplayInfo& VirtioGpuLastDisplayInfo()
{
    return g_last_display;
}

} // namespace duetos::drivers::gpu
