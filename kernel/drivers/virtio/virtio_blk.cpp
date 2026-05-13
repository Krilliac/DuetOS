#include "drivers/storage/block.h"
#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"

/*
 * virtio-blk — block device.
 *
 * One requestq virtqueue. Each request is a three-descriptor
 * chain:
 *
 *   desc[0]  driver-write    virtio_blk_outhdr (16 B)
 *   desc[1]  device-write    data buffer (count * sector_size B)
 *   desc[2]  device-write    status byte (1 B)
 *
 * The driver presents the header (operation + LBA) and a buffer
 * (device fills on read, driver fills on write); the device
 * writes the status byte (0=OK, 1=IO_ERR, 2=UNSUPP) on
 * completion. We poll the used ring — IRQ wire-up is the next
 * slice.
 *
 * v0 ships read + write through a shared `VirtioBlkBlockRequest`
 * helper; the only differences between read and write are the
 * header `type` (kBlkTypeIn vs kBlkTypeOut) and the data
 * descriptor's `kVirtqDescWrite` flag (set on read, cleared on
 * write — read is "device writes our buffer", write is "device
 * reads our buffer"). Devices that advertise `VIRTIO_BLK_F_RO`
 * keep the read-only path: `BlockOps.write` is still wired but
 * VirtioBlkBlockRequest fails fast on the RO check. Capacity
 * comes from `device_cfg + 0` (8-byte u64); sector size is
 * 512 unless `VIRTIO_BLK_F_BLK_SIZE` is offered (read from
 * `device_cfg + 20` in that case).
 *
 * Per-process / multi-queue locking is GAP: v0 assumes a
 * single in-flight request at a time, which holds for the
 * boot path (one shell, no parallel I/O). A real driver gates
 * the request chain on a spinlock and uses multiple chains
 * concurrently.
 */

namespace duetos::drivers::virtio
{

// VIRTIO_BLK_F_* — driver opts into a small set. SEG_MAX +
// BLK_SIZE + RO are the ones the read/write path uses.
inline constexpr u64 kBlkFeatureSegMax = 1ULL << 2;
inline constexpr u64 kBlkFeatureGeometry = 1ULL << 4;
inline constexpr u64 kBlkFeatureRo = 1ULL << 5;
inline constexpr u64 kBlkFeatureBlkSize = 1ULL << 6;

namespace
{

// virtio_blk_outhdr layout (virtio 1.0 §5.2.6). 16 bytes.
constexpr u32 kBlkTypeIn = 0;    // read from device
constexpr u32 kBlkTypeOut = 1;   // write to device
constexpr u32 kBlkTypeFlush = 4; // commit any in-flight writes
constexpr u8 kBlkStatusOk = 0;

struct BlkReqHdr
{
    u32 type;
    u32 reserved;
    u64 sector;
};

struct DeviceState
{
    bool up;
    bool read_only;
    u8 _pad[6];

    VirtioPciLayout layout;
    VirtioQueue q;

    // Header + status backing — header lives in the first 16
    // bytes of a 4 KiB page, status in the byte after. Single
    // page covers both because descriptor phys-addresses can
    // point at arbitrary offsets within a frame.
    mm::PhysAddr hdr_phys;
    u8* hdr_virt;

    u32 sector_size;
    u64 sector_count;
};

constinit DeviceState g_blk = {};

i32 VirtioBlkBlockRequest(DeviceState* dev, u64 lba, u32 count, void* buf, bool is_write)
{
    if (dev == nullptr || !dev->up || buf == nullptr || count == 0)
        return -1;
    if (is_write && dev->read_only)
        return -1;

    // The block layer already bounds-checked against sector_count
    // before calling here. The data buffer must be in the kernel
    // direct map so VirtToPhys yields its DMA-reachable address —
    // BlockDeviceRead/Write's contract states this explicitly.
    const u64 byte_len = u64(count) * dev->sector_size;
    const mm::PhysAddr data_phys = mm::VirtToPhys(buf);
    if (data_phys == 0)
    {
        KLOG_WARN("drivers/virtio/blk", "VirtToPhys returned 0; buf not in direct map?");
        return -1;
    }

    // Populate header at offset 0, status at offset 16 of the
    // shared scratch page. Status is reset to a sentinel the
    // device must overwrite — we use 0xFF, well outside the
    // legal {OK, IO_ERR, UNSUPP} range.
    auto* hdr = reinterpret_cast<BlkReqHdr*>(dev->hdr_virt);
    hdr->type = is_write ? kBlkTypeOut : kBlkTypeIn;
    hdr->reserved = 0;
    hdr->sector = lba;
    u8* status = dev->hdr_virt + 16;
    *status = 0xFF;

    VirtqDesc* d = const_cast<VirtqDesc*>(dev->q.desc);
    // Chain head — header, driver-write.
    d[0].addr = dev->hdr_phys;
    d[0].len = 16;
    d[0].flags = kVirtqDescNext;
    d[0].next = 1;
    // Data — direction depends on op: device-write for reads
    // (kVirtqDescWrite set), driver-write for writes (no Write
    // flag).
    d[1].addr = data_phys;
    d[1].len = static_cast<u32>(byte_len);
    d[1].flags = static_cast<u16>(kVirtqDescNext | (is_write ? 0 : kVirtqDescWrite));
    d[1].next = 2;
    // Status — device-write, 1 byte.
    d[2].addr = dev->hdr_phys + 16;
    d[2].len = 1;
    d[2].flags = kVirtqDescWrite;
    d[2].next = 0;

    VirtioQueuePublish(&dev->layout, &dev->q, /*desc_head=*/0);
    for (u32 spin = 0; spin < 5000000; ++spin)
    {
        u32 head = 0;
        u32 used_len = 0;
        if (VirtioQueueTryPop(&dev->q, &head, &used_len))
        {
            if (*status == kBlkStatusOk)
                return 0;
            KLOG_WARN_V("drivers/virtio/blk", "request completed non-OK", static_cast<u64>(*status));
            return -1;
        }
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/virtio/blk", "request poll timed out");
    return -1;
}

i32 VirtioBlkBlockRead(void* cookie, u64 lba, u32 count, void* buf)
{
    return VirtioBlkBlockRequest(static_cast<DeviceState*>(cookie), lba, count, buf, /*is_write=*/false);
}

i32 VirtioBlkBlockWrite(void* cookie, u64 lba, u32 count, const void* buf)
{
    // Write data is driver-write in the chain (host reads from
    // the buffer), so the device doesn't touch our buffer — the
    // const_cast strips the C-side promise, not the actual
    // mutability. Safe because the descriptor flags omit
    // kVirtqDescWrite for the data descriptor on a write.
    return VirtioBlkBlockRequest(static_cast<DeviceState*>(cookie), lba, count, const_cast<void*>(buf),
                                 /*is_write=*/true);
}

i32 VirtioBlkBlockFlush(void* cookie)
{
    auto* dev = static_cast<DeviceState*>(cookie);
    if (dev == nullptr || !dev->up)
        return -1;
    // VIRTIO_BLK_T_FLUSH: header.sector is ignored, no data
    // descriptor — the chain is header + status only. Reuse the
    // shared scratch page; sector field set to 0 for cleanliness.
    auto* hdr = reinterpret_cast<BlkReqHdr*>(dev->hdr_virt);
    hdr->type = kBlkTypeFlush;
    hdr->reserved = 0;
    hdr->sector = 0;
    u8* status = dev->hdr_virt + 16;
    *status = 0xFF;

    VirtqDesc* d = const_cast<VirtqDesc*>(dev->q.desc);
    d[0].addr = dev->hdr_phys;
    d[0].len = 16;
    d[0].flags = kVirtqDescNext;
    d[0].next = 1;
    d[1].addr = dev->hdr_phys + 16;
    d[1].len = 1;
    d[1].flags = kVirtqDescWrite;
    d[1].next = 0;

    VirtioQueuePublish(&dev->layout, &dev->q, /*desc_head=*/0);
    for (u32 spin = 0; spin < 5000000; ++spin)
    {
        u32 head = 0;
        u32 used_len = 0;
        if (VirtioQueueTryPop(&dev->q, &head, &used_len))
            return (*status == kBlkStatusOk) ? 0 : -1;
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/virtio/blk", "flush poll timed out");
    return -1;
}

constinit const duetos::drivers::storage::BlockOps kBlkOps = {
    /*.read = */ &VirtioBlkBlockRead,
    /*.write = */ &VirtioBlkBlockWrite,
    /*.flush = */ &VirtioBlkBlockFlush,
};

} // namespace

bool VirtioBlkProbe(const VirtioPciLayout& L)
{
    if (g_blk.up)
    {
        // Second virtio-blk device — v0 supports only one. The
        // probe still acks/drives the device so it doesn't sit
        // half-negotiated, but skips registration.
        KLOG_WARN("drivers/virtio/blk", "second device detected; v0 supports only one");
        return false;
    }

    VirtioPciLayout layout = L;
    const u64 dev_features =
        (static_cast<u64>(layout.device_features_hi) << 32) | static_cast<u64>(layout.device_features_lo);
    u64 want = kFeatureVersion1;
    want |= dev_features & (kBlkFeatureSegMax | kBlkFeatureGeometry | kBlkFeatureRo | kBlkFeatureBlkSize);

    if (!VirtioNegotiate(&layout, want))
    {
        KLOG_WARN("drivers/virtio/blk", "feature negotiation failed");
        return false;
    }

    // virtio_blk_config layout (virtio 1.0 §5.2.4):
    //   u64 capacity (sectors of 512B, or of blk_size if F_BLK_SIZE)
    //   u32 size_max, seg_max, ...
    //   u32 blk_size at offset 20 (when F_BLK_SIZE negotiated)
    u64 capacity = 0;
    u32 sector_size = 512;
    if (layout.device_cfg != nullptr)
    {
        // Capacity is 8 bytes at offset 0; do two 32-bit reads to
        // match the 4-byte alignment guarantee.
        const u32 lo = *reinterpret_cast<volatile u32*>(layout.device_cfg + 0);
        const u32 hi = *reinterpret_cast<volatile u32*>(layout.device_cfg + 4);
        capacity = (static_cast<u64>(hi) << 32) | lo;
        if ((want & kBlkFeatureBlkSize) != 0)
        {
            const u32 bs = *reinterpret_cast<volatile u32*>(layout.device_cfg + 20);
            if (bs >= 512 && bs <= 4096 && (bs & (bs - 1)) == 0)
                sector_size = bs;
        }
    }
    if (capacity == 0)
    {
        KLOG_WARN("drivers/virtio/blk", "device reports zero capacity; skipping registration");
        return false;
    }

    if (!VirtioQueueSetup(&layout, &g_blk.q, /*queue_index=*/0, kVirtqDefaultSize))
    {
        KLOG_WARN("drivers/virtio/blk", "requestq setup failed");
        return false;
    }

    // One shared header + status page. Single in-flight request
    // (see file-level GAP comment) means we don't need per-call
    // allocation here.
    const mm::PhysAddr hdr_phys = mm::AllocateFrame();
    if (hdr_phys == mm::kNullFrame)
    {
        KLOG_WARN("drivers/virtio/blk", "header page alloc failed");
        return false;
    }
    g_blk.hdr_phys = hdr_phys;
    g_blk.hdr_virt = static_cast<u8*>(mm::PhysToVirt(hdr_phys));
    for (u64 i = 0; i < 4096; ++i)
        g_blk.hdr_virt[i] = 0;

    g_blk.layout = layout;
    g_blk.sector_size = sector_size;
    g_blk.sector_count = capacity;
    g_blk.read_only = ((want & kBlkFeatureRo) != 0);
    g_blk.up = true;

    duetos::drivers::storage::BlockDesc desc{};
    desc.name = "vblk0";
    desc.ops = &kBlkOps;
    desc.cookie = &g_blk;
    desc.sector_size = sector_size;
    desc.sector_count = capacity;
    const u32 h = duetos::drivers::storage::BlockDeviceRegister(desc);
    if (h == duetos::drivers::storage::kBlockHandleInvalid)
    {
        KLOG_WARN("drivers/virtio/blk", "BlockDeviceRegister failed");
        g_blk.up = false;
        return false;
    }

    KLOG_INFO_2V("drivers/virtio/blk", "attached as block device", "sectors", capacity, "sector-size",
                 static_cast<u64>(sector_size));
    // GAP: VIRTIO_BLK_T_FLUSH is not yet exposed — the
    // BlockOps vtable doesn't carry a `flush` slot today.
    // Single-in-flight request assumption: shared header page
    // + no per-call locking means concurrent BlockDeviceRead /
    // Write calls would corrupt each other's descriptors. Boot-
    // smoke workload is single-thread, so this is observed-safe
    // for v0; a future slice that issues concurrent I/O needs
    // either a per-call header alloc or a spinlock around the
    // request path.
    return true;
}

} // namespace duetos::drivers::virtio
