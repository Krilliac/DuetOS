/*
 * DuetOS — virtio-gpu driver (host-emulated GPU): implementation.
 *
 * Companion to virtio_gpu.h — see there for the controller
 * record and the framebuffer surface contract.
 *
 * WHAT
 *   Drives the virtio-gpu PCI device QEMU exposes when run with
 *   `-vga virtio`. Provides a real 2D framebuffer the
 *   compositor renders into and a working flush path
 *   (`TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH`).
 *
 * HOW
 *   Two virtqueues: control (commands) and cursor. Each command
 *   is built into a guest buffer, descriptored into the queue,
 *   and the device is kicked via the doorbell. We poll the
 *   used-ring for completions — interrupt routing is a future
 *   slice.
 *
 *   Resource lifecycle: at init we create one 2D resource
 *   sized to the boot-elected framebuffer dimensions, attach
 *   guest backing, and use it as the scanout target. Every
 *   compositor flush is a transfer + flush pair on that
 *   resource.
 */

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

// Generic command submission over controlq. Builds a two-descriptor
// chain (device-read of req, device-write of resp), kicks the
// device, polls the used ring with a bounded spin, returns true on
// a timely completion. `resp_bytes_out` (optional) captures the
// used-ring len field so callers can verify a variable-length
// response shape.
//
// Supports up to one request + one response per call — enough for
// every GPU command whose backing list fits in the req_buf page
// (which is the case for every 2D-cycle command since ATTACH_BACKING
// only needs a handful of mem_entry records for single-chunk
// resources).
bool SubmitControlq(u32 req_len, u32 resp_len, u32* resp_bytes_out)
{
    if (!g_cq.up)
        return false;
    if (req_len > 4096 || resp_len > 4096)
        return false;

    // Descriptor 0: device-read of request.
    g_cq.desc[0].addr = g_cq.req_phys;
    g_cq.desc[0].len = req_len;
    g_cq.desc[0].flags = kDescNext;
    g_cq.desc[0].next = 1;

    // Descriptor 1: device-write of response.
    g_cq.desc[1].addr = g_cq.resp_phys;
    g_cq.desc[1].len = resp_len;
    g_cq.desc[1].flags = kDescWrite;
    g_cq.desc[1].next = 0;

    const u16 slot = g_cq.next_avail % g_cq.queue_size;
    g_cq.avail_ring[slot] = 0; // head descriptor index
    asm volatile("" ::: "memory");
    g_cq.next_avail = static_cast<u16>(g_cq.next_avail + 1);
    g_cq.avail_hdr->idx = g_cq.next_avail;

    asm volatile("" ::: "memory");

    *reinterpret_cast<volatile u16*>(g_cq.notify_reg) = 0;

    u64 spins = 0;
    while (g_cq.used_hdr->idx == g_cq.last_used_idx)
    {
        asm volatile("pause" ::: "memory");
        if (++spins > 1'000'000)
        {
            arch::SerialWrite("[virtio-gpu] submit: timeout waiting for used ring\n");
            return false;
        }
    }
    const u16 used_slot = g_cq.last_used_idx % g_cq.queue_size;
    const u32 resp_bytes = g_cq.used_ring[used_slot].len;
    g_cq.last_used_idx = static_cast<u16>(g_cq.last_used_idx + 1);

    asm volatile("" ::: "memory");

    if (resp_bytes_out != nullptr)
        *resp_bytes_out = resp_bytes;
    return true;
}

// Zero the request + response buffers (no memset on freestanding
// link) up to the given lengths — caller populates req after.
void ClearIoBuffers(u32 req_len, u32 resp_len)
{
    for (u32 i = 0; i < req_len; ++i)
        g_cq.req_buf[i] = 0;
    for (u32 i = 0; i < resp_len; ++i)
        g_cq.resp_buf[i] = 0;
}

void FillCtrlHdr(volatile GpuCtrlHdr* h, u32 type)
{
    h->type = type;
    h->flags = 0;
    h->fence_id = 0;
    h->ctx_id = 0;
    h->ring_idx = 0;
    h->padding[0] = 0;
    h->padding[1] = 0;
    h->padding[2] = 0;
}

const VirtioDisplayInfo& VirtioGpuGetDisplayInfo()
{
    ResetLastDisplay();
    if (!g_cq.up)
    {
        arch::SerialWrite("[virtio-gpu] GET_DISPLAY_INFO: bring-up has not run\n");
        return g_last_display;
    }

    ClearIoBuffers(sizeof(GpuCtrlHdr), sizeof(GpuRespDisplayInfo));
    FillCtrlHdr(reinterpret_cast<volatile GpuCtrlHdr*>(g_cq.req_buf), kCmdGetDisplayInfo);

    u32 resp_bytes = 0;
    if (!SubmitControlq(sizeof(GpuCtrlHdr), sizeof(GpuRespDisplayInfo), &resp_bytes))
        return g_last_display;

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

// ======================================================================
// virtio-gpu v2 — 2D resource + scanout + transfer + flush
// ======================================================================

namespace
{

// Command numbers (virtio 1.0 §5.7.6.7).
constexpr u32 kCmdResourceCreate2d = 0x0101;
[[maybe_unused]] constexpr u32 kCmdResourceUnref = 0x0102;
constexpr u32 kCmdSetScanout = 0x0103;
constexpr u32 kCmdResourceFlush = 0x0104;
constexpr u32 kCmdTransferToHost2d = 0x0105;
constexpr u32 kCmdResourceAttachBacking = 0x0106;

// Success response for every command below.
constexpr u32 kRespOkNoData = 0x1100;

// Pixel format (virtio 1.0 §5.7.5).
constexpr u32 kFmtB8G8R8A8Unorm = 1;

// Command bodies (virtio 1.0 §5.7.6.x).

struct GpuRect
{
    u32 x;
    u32 y;
    u32 width;
    u32 height;
};

struct ResCreate2d
{
    GpuCtrlHdr hdr;
    u32 resource_id;
    u32 format;
    u32 width;
    u32 height;
};

struct ResUnref
{
    GpuCtrlHdr hdr;
    u32 resource_id;
    u32 padding;
};

struct SetScanout
{
    GpuCtrlHdr hdr;
    GpuRect r;
    u32 scanout_id;
    u32 resource_id;
};

struct ResourceFlush
{
    GpuCtrlHdr hdr;
    GpuRect r;
    u32 resource_id;
    u32 padding;
};

struct TransferToHost2d
{
    GpuCtrlHdr hdr;
    GpuRect r;
    u64 offset;
    u32 resource_id;
    u32 padding;
};

struct MemEntry
{
    u64 addr;
    u32 length;
    u32 padding;
};

// ATTACH_BACKING request: header + (resource_id, nr_entries) + entries[].
// We always use a single contiguous entry in v2.
struct ResourceAttachBacking
{
    GpuCtrlHdr hdr;
    u32 resource_id;
    u32 nr_entries;
    MemEntry entries[1]; // nr_entries = 1 in v2
};

constinit VirtioScanoutInfo g_scanout = {};

// Issue one header-returning command with a prebuilt request. Logs
// a failure line and returns false if the response type isn't
// RESP_OK_NODATA. `label` is purely for log clarity.
bool SubmitHeaderCommand(u32 req_len, const char* label)
{
    u32 resp_bytes = 0;
    if (!SubmitControlq(req_len, sizeof(GpuCtrlHdr), &resp_bytes))
        return false;
    auto* resp = reinterpret_cast<const GpuCtrlHdr*>(g_cq.resp_buf);
    if (resp->type != kRespOkNoData)
    {
        arch::SerialWrite("[virtio-gpu] ");
        arch::SerialWrite(label);
        arch::SerialWrite(": unexpected resp_type=");
        arch::SerialWriteHex(resp->type);
        arch::SerialWrite(" (expected 0x1100)\n");
        return false;
    }
    return true;
}

constexpr u32 kScanoutResourceId = 1;
constexpr u32 kScanoutId = 0;
constexpr u64 kPageSize = 4096;

} // namespace

bool VirtioGpuSetupScanout(u32 width, u32 height)
{
    if (g_scanout.ready && g_scanout.width == width && g_scanout.height == height)
        return true;
    if (g_scanout.ready)
    {
        arch::SerialWrite("[virtio-gpu] setup-scanout: already set up at a different size; "
                          "re-setup not supported in v2\n");
        return false;
    }
    if (!g_cq.up)
    {
        arch::SerialWrite("[virtio-gpu] setup-scanout: bring-up has not run\n");
        return false;
    }
    if (width == 0 || height == 0 || width > 4096 || height > 4096)
    {
        arch::SerialWrite("[virtio-gpu] setup-scanout: invalid dimensions\n");
        return false;
    }

    const u64 pitch = static_cast<u64>(width) * 4;
    const u64 bytes = pitch * height;
    const u64 pages = (bytes + kPageSize - 1) / kPageSize;
    const ::duetos::mm::PhysAddr base = ::duetos::mm::AllocateContiguousFrames(pages);
    if (base == ::duetos::mm::kNullFrame)
    {
        arch::SerialWrite("[virtio-gpu] setup-scanout: could not allocate ");
        arch::SerialWriteHex(pages);
        arch::SerialWrite(" contiguous frames for backing\n");
        return false;
    }
    void* backing_va = ::duetos::mm::PhysToVirt(base);
    // Zero the backing so the first flush shows a predictable colour
    // rather than stale kernel memory.
    for (u64 i = 0; i < bytes; ++i)
        static_cast<u8*>(backing_va)[i] = 0;

    // 1) RESOURCE_CREATE_2D
    {
        ClearIoBuffers(sizeof(ResCreate2d), sizeof(GpuCtrlHdr));
        auto* req = reinterpret_cast<volatile ResCreate2d*>(g_cq.req_buf);
        FillCtrlHdr(&req->hdr, kCmdResourceCreate2d);
        req->resource_id = kScanoutResourceId;
        req->format = kFmtB8G8R8A8Unorm;
        req->width = width;
        req->height = height;
        if (!SubmitHeaderCommand(sizeof(ResCreate2d), "RESOURCE_CREATE_2D"))
            return false;
    }

    // 2) RESOURCE_ATTACH_BACKING (single contiguous entry).
    {
        ClearIoBuffers(sizeof(ResourceAttachBacking), sizeof(GpuCtrlHdr));
        auto* req = reinterpret_cast<volatile ResourceAttachBacking*>(g_cq.req_buf);
        FillCtrlHdr(&req->hdr, kCmdResourceAttachBacking);
        req->resource_id = kScanoutResourceId;
        req->nr_entries = 1;
        req->entries[0].addr = base;
        req->entries[0].length = static_cast<u32>(bytes);
        req->entries[0].padding = 0;
        if (!SubmitHeaderCommand(sizeof(ResourceAttachBacking), "RESOURCE_ATTACH_BACKING"))
            return false;
    }

    // 3) SET_SCANOUT
    {
        ClearIoBuffers(sizeof(SetScanout), sizeof(GpuCtrlHdr));
        auto* req = reinterpret_cast<volatile SetScanout*>(g_cq.req_buf);
        FillCtrlHdr(&req->hdr, kCmdSetScanout);
        req->r.x = 0;
        req->r.y = 0;
        req->r.width = width;
        req->r.height = height;
        req->scanout_id = kScanoutId;
        req->resource_id = kScanoutResourceId;
        if (!SubmitHeaderCommand(sizeof(SetScanout), "SET_SCANOUT"))
            return false;
    }

    g_scanout.ready = true;
    g_scanout.scanout_id = kScanoutId;
    g_scanout.resource_id = kScanoutResourceId;
    g_scanout.width = width;
    g_scanout.height = height;
    g_scanout.pitch = static_cast<u32>(pitch);
    g_scanout.backing_phys = base;
    g_scanout.backing_bytes = bytes;
    g_scanout.backing_va = backing_va;

    arch::SerialWrite("[virtio-gpu] setup-scanout OK  res=");
    arch::SerialWriteHex(kScanoutResourceId);
    arch::SerialWrite(" scanout=");
    arch::SerialWriteHex(kScanoutId);
    arch::SerialWrite(" ");
    arch::SerialWriteHex(width);
    arch::SerialWrite("x");
    arch::SerialWriteHex(height);
    arch::SerialWrite("  backing phys=");
    arch::SerialWriteHex(base);
    arch::SerialWrite("/");
    arch::SerialWriteHex(bytes);
    arch::SerialWrite(" va=");
    arch::SerialWriteHex(reinterpret_cast<u64>(backing_va));
    arch::SerialWrite("\n");
    return true;
}

const VirtioScanoutInfo& VirtioGpuScanoutInfo()
{
    return g_scanout;
}

bool VirtioGpuFlushScanout(u32 x, u32 y, u32 w, u32 h)
{
    if (!g_scanout.ready)
        return false;
    // Clip to the resource extent — the host rejects rects outside.
    if (x >= g_scanout.width || y >= g_scanout.height)
        return false;
    if (x + w > g_scanout.width)
        w = g_scanout.width - x;
    if (y + h > g_scanout.height)
        h = g_scanout.height - y;
    if (w == 0 || h == 0)
        return true; // nothing to flush

    // 1) TRANSFER_TO_HOST_2D — copy dirty rect from guest backing
    //    into host resource.
    {
        ClearIoBuffers(sizeof(TransferToHost2d), sizeof(GpuCtrlHdr));
        auto* req = reinterpret_cast<volatile TransferToHost2d*>(g_cq.req_buf);
        FillCtrlHdr(&req->hdr, kCmdTransferToHost2d);
        req->r.x = x;
        req->r.y = y;
        req->r.width = w;
        req->r.height = h;
        req->offset = static_cast<u64>(y) * g_scanout.pitch + static_cast<u64>(x) * 4;
        req->resource_id = g_scanout.resource_id;
        req->padding = 0;
        if (!SubmitHeaderCommand(sizeof(TransferToHost2d), "TRANSFER_TO_HOST_2D"))
            return false;
    }

    // 2) RESOURCE_FLUSH — tell the host to composite the resource
    //    to the scanout's display surface.
    {
        ClearIoBuffers(sizeof(ResourceFlush), sizeof(GpuCtrlHdr));
        auto* req = reinterpret_cast<volatile ResourceFlush*>(g_cq.req_buf);
        FillCtrlHdr(&req->hdr, kCmdResourceFlush);
        req->r.x = x;
        req->r.y = y;
        req->r.width = w;
        req->r.height = h;
        req->resource_id = g_scanout.resource_id;
        req->padding = 0;
        if (!SubmitHeaderCommand(sizeof(ResourceFlush), "RESOURCE_FLUSH"))
            return false;
    }
    return true;
}

} // namespace duetos::drivers::gpu
