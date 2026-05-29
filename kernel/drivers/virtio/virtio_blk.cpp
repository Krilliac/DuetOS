#include "drivers/storage/block.h"
#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "sched/sched.h"

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
 * Concurrent callers are serialised on a per-device sleeping
 * `req_lock`: the shared header page + the single descriptor
 * chain (descriptors 0..2) are reused per request, so two
 * callers racing would corrupt each other's chain. The lock
 * is a sched::Mutex rather than a SpinLock because the holder
 * busy-polls the device for completion (up to ~5M `pause`
 * iterations) — spinning with IRQs disabled across that window
 * would starve the timer/scheduler; a contending caller sleeps
 * instead. GAP: still one in-flight request at a time (one
 * descriptor chain). A throughput slice that wants real
 * parallelism needs multiple chains + IRQ-driven completion;
 * correctness under concurrency is no longer the blocker.
 */

namespace duetos::drivers::virtio
{

// VIRTIO_BLK_F_* — driver opts into a small set. SEG_MAX +
// BLK_SIZE + RO are the ones the read/write path uses.
inline constexpr u64 kBlkFeatureSegMax = 1ULL << 2;
inline constexpr u64 kBlkFeatureGeometry = 1ULL << 4;
inline constexpr u64 kBlkFeatureRo = 1ULL << 5;
inline constexpr u64 kBlkFeatureBlkSize = 1ULL << 6;
// VIRTIO_BLK_F_DISCARD (bit 13) — host accepts deallocate hints.
// virtio 1.2 §5.2.5. Required for the SSD-style "unlink == TRIM"
// path; QEMU's qcow2/raw backends both honour it on host SSDs.
inline constexpr u64 kBlkFeatureDiscard = 1ULL << 13;

namespace
{

// virtio_blk_outhdr layout (virtio 1.0 §5.2.6). 16 bytes.
constexpr u32 kBlkTypeIn = 0;       // read from device
constexpr u32 kBlkTypeOut = 1;      // write to device
constexpr u32 kBlkTypeFlush = 4;    // commit any in-flight writes
constexpr u32 kBlkTypeDiscard = 11; // virtio 1.2 §5.2.6 — deallocate ranges
constexpr u8 kBlkStatusOk = 0;

// One virtio_blk_discard_write_zeroes range, 16 bytes per spec.
// We issue one range per call, matching the NVMe/AHCI drivers'
// v0 patterns — coalescing waits for a workload showing the
// per-command overhead matters.
struct BlkDiscardRange
{
    u64 sector; // starting LBA in 512-byte units
    u32 num_sectors;
    u32 flags; // bit 0 = unmap, bit 1 = write-zeroes (we leave both clear)
};
static_assert(sizeof(BlkDiscardRange) == 16, "virtio-blk discard range descriptor must be 16 bytes");

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
    bool discard;
    u8 _pad[5];

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

    // Serialises the shared header page + the reused descriptor
    // chain across concurrent BlockDeviceRead/Write/Flush callers.
    // Uncontended fast path is a single CAS — no cost on the
    // single-threaded boot path.
    duetos::sched::Mutex req_lock;
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

    // The shared header page + the single descriptor chain are
    // reused per request — serialise concurrent callers. Lock is
    // taken AFTER the cheap argument validation above (which
    // touches no shared state) so a bad call returns without ever
    // contending. Single return point below keeps lock/unlock
    // balanced across every exit.
    duetos::sched::MutexLock(&dev->req_lock);

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
    i32 rc = -1;
    for (u32 spin = 0; spin < 5000000; ++spin)
    {
        u32 head = 0;
        u32 used_len = 0;
        if (VirtioQueueTryPop(&dev->q, &head, &used_len))
        {
            if (*status == kBlkStatusOk)
                rc = 0;
            else
                KLOG_WARN_V("drivers/virtio/blk", "request completed non-OK", static_cast<u64>(*status));
            duetos::sched::MutexUnlock(&dev->req_lock);
            return rc;
        }
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/virtio/blk", "request poll timed out");
    duetos::sched::MutexUnlock(&dev->req_lock);
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

    // Shares the header page + descriptor chain with the read/write
    // path — same per-device serialisation, same single-exit
    // lock/unlock discipline.
    duetos::sched::MutexLock(&dev->req_lock);

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
        {
            const i32 rc = (*status == kBlkStatusOk) ? 0 : -1;
            duetos::sched::MutexUnlock(&dev->req_lock);
            return rc;
        }
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/virtio/blk", "flush poll timed out");
    duetos::sched::MutexUnlock(&dev->req_lock);
    return -1;
}

// VIRTIO_BLK_T_DISCARD with a single 16-byte range descriptor.
// Chain shape: header (driver-write 16 B) -> range payload
// (driver-write 16 B) -> status (device-write 1 B). The range
// payload reuses the shared scratch page at offset 32 — past
// both the header (0..15) and the status byte (16) — so the
// existing single-in-flight serialisation still covers it.
i32 VirtioBlkBlockDiscard(void* cookie, u64 lba, u32 count)
{
    auto* dev = static_cast<DeviceState*>(cookie);
    if (dev == nullptr || !dev->up)
        return -1;
    if (count == 0)
        return -1;
    if (!dev->discard)
        return 0; // Hint dropped — caller treats this as success.
    if (dev->read_only)
        return -1;

    duetos::sched::MutexLock(&dev->req_lock);

    auto* hdr = reinterpret_cast<BlkReqHdr*>(dev->hdr_virt);
    hdr->type = kBlkTypeDiscard;
    hdr->reserved = 0;
    hdr->sector = 0; // ignored for discard — range is in the payload
    u8* status = dev->hdr_virt + 16;
    *status = 0xFF;

    auto* range = reinterpret_cast<BlkDiscardRange*>(dev->hdr_virt + 32);
    range->sector = lba;
    range->num_sectors = count;
    range->flags = 0;

    VirtqDesc* d = const_cast<VirtqDesc*>(dev->q.desc);
    d[0].addr = dev->hdr_phys;
    d[0].len = 16;
    d[0].flags = kVirtqDescNext;
    d[0].next = 1;
    d[1].addr = dev->hdr_phys + 32;
    d[1].len = sizeof(BlkDiscardRange);
    d[1].flags = kVirtqDescNext;
    d[1].next = 2;
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
            const i32 rc = (*status == kBlkStatusOk) ? 0 : -1;
            if (rc != 0)
                KLOG_WARN_V("drivers/virtio/blk", "discard completed non-OK", static_cast<u64>(*status));
            duetos::sched::MutexUnlock(&dev->req_lock);
            return rc;
        }
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/virtio/blk", "discard poll timed out");
    duetos::sched::MutexUnlock(&dev->req_lock);
    return -1;
}

constinit const duetos::drivers::storage::BlockOps kBlkOps = {
    /*.read = */ &VirtioBlkBlockRead,
    /*.write = */ &VirtioBlkBlockWrite,
    /*.flush = */ &VirtioBlkBlockFlush,
    /*.discard = */ &VirtioBlkBlockDiscard,
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
    want |= dev_features &
            (kBlkFeatureSegMax | kBlkFeatureGeometry | kBlkFeatureRo | kBlkFeatureBlkSize | kBlkFeatureDiscard);

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

    // Spec §3.1.1 step 8 — queue is up, finalise the device.
    VirtioMarkDriverOk(&layout);

    // One shared header + status page. Single in-flight request
    // (see file-level GAP comment) means we don't need per-call
    // allocation here.
    auto hdr_phys_r = mm::TryAllocateFrame();
    if (!hdr_phys_r)
    {
        KLOG_WARN("drivers/virtio/blk", "header page alloc failed");
        return false;
    }
    const mm::PhysAddr hdr_phys = hdr_phys_r.value();
    g_blk.hdr_phys = hdr_phys;
    g_blk.hdr_virt = static_cast<u8*>(mm::PhysToVirt(hdr_phys));
    for (u64 i = 0; i < 4096; ++i)
        g_blk.hdr_virt[i] = 0;

    g_blk.layout = layout;
    g_blk.sector_size = sector_size;
    g_blk.sector_count = capacity;
    g_blk.read_only = ((want & kBlkFeatureRo) != 0);
    g_blk.discard = ((want & kBlkFeatureDiscard) != 0);
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
    // Concurrent BlockDeviceRead / Write / Flush are now safe —
    // each serialises on g_blk.req_lock around the shared header
    // page + descriptor chain. Read / Write / Flush are all wired
    // through the BlockOps vtable. Higher throughput (multiple
    // in-flight chains + IRQ-driven completion instead of the
    // bounded poll) is a roadmap item, not a correctness GAP.
    return true;
}

} // namespace duetos::drivers::virtio
