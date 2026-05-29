#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"

namespace duetos::drivers::virtio
{

namespace
{

// Common-config register offsets for queue management (virtio 1.0
// §4.1.4.3). Duplicated from virtio_pci.cpp's anon ns rather than
// exposed in the header because they are an internal detail of
// the transport; flipping to a different transport (MMIO) would
// reuse the same struct shapes but different offsets.
constexpr u64 kCcQueueSelect = 0x16;
constexpr u64 kCcQueueSize = 0x18;
constexpr u64 kCcQueueEnable = 0x1C;
constexpr u64 kCcQueueNotifyOff = 0x1E;
constexpr u64 kCcQueueDesc = 0x20;
constexpr u64 kCcQueueDriver = 0x28;
constexpr u64 kCcQueueDevice = 0x30;
constexpr u64 kCcDeviceStatus = 0x14;

// 64-bit writes must split into two 32-bit stores (virtio 1.0
// §4.1.3.1; the common_cfg is 4-byte aligned, not 8-byte).
void Write64(volatile u8* base, u64 off, u64 v)
{
    *reinterpret_cast<volatile u32*>(base + off) = static_cast<u32>(v);
    *reinterpret_cast<volatile u32*>(base + off + 4) = static_cast<u32>(v >> 32);
}

void Write16(volatile u8* base, u64 off, u16 v)
{
    *reinterpret_cast<volatile u16*>(base + off) = v;
}

u16 Read16(volatile u8* base, u64 off)
{
    return *reinterpret_cast<volatile u16*>(base + off);
}

// Allocate one zero-filled 4 KiB frame and hand back its phys + a
// kernel-virt pointer (via the kernel direct map). Returns false
// on OOM.
bool AllocZeroPage(u64* phys_out, void** virt_out)
{
    auto f_r = mm::TryAllocateFrame();
    if (!f_r)
        return false;
    const mm::PhysAddr f = f_r.value();
    void* v = mm::PhysToVirt(f);
    u8* bytes = static_cast<u8*>(v);
    for (u64 i = 0; i < 4096; ++i)
        bytes[i] = 0;
    *phys_out = f;
    *virt_out = v;
    return true;
}

} // namespace

bool VirtioQueueSetup(VirtioPciLayout* L, VirtioQueue* q, u16 queue_index, u16 want_size)
{
    if (L == nullptr || q == nullptr || !L->present || L->common_cfg == nullptr || L->notify == nullptr)
        return false;

    // Select the queue and read the device's max size. queue_size
    // is the device's hard cap; we pick min(want, advertised) but
    // also enforce our own kVirtqDefaultSize ceiling so the v0
    // single-page allocation invariant holds.
    Write16(L->common_cfg, kCcQueueSelect, queue_index);
    const u16 dev_max = Read16(L->common_cfg, kCcQueueSize);
    if (dev_max == 0)
    {
        KLOG_WARN_V("drivers/virtio/queue", "queue not available on device", static_cast<u64>(queue_index));
        return false;
    }
    u16 size = want_size;
    if (size == 0 || size > dev_max)
        size = dev_max;
    if (size > kVirtqDefaultSize)
        size = kVirtqDefaultSize;

    // Allocate the three ring regions. Each fits in a single page
    // at queue_size=32; see header.
    void* desc_v = nullptr;
    void* avail_v = nullptr;
    void* used_v = nullptr;
    if (!AllocZeroPage(&q->desc_phys, &desc_v))
        return false;
    if (!AllocZeroPage(&q->avail_phys, &avail_v))
        return false;
    if (!AllocZeroPage(&q->used_phys, &used_v))
        return false;

    q->queue_index = queue_index;
    q->queue_size = size;
    q->last_used_idx = 0;
    q->next_avail = 0;
    q->desc = static_cast<volatile VirtqDesc*>(desc_v);
    q->avail_hdr = static_cast<volatile VirtqAvailHdr*>(avail_v);
    q->avail_ring = reinterpret_cast<volatile u16*>(static_cast<u8*>(avail_v) + sizeof(VirtqAvailHdr));
    q->used_hdr = static_cast<volatile VirtqUsedHdr*>(used_v);
    q->used_ring = reinterpret_cast<volatile VirtqUsedElem*>(static_cast<u8*>(used_v) + sizeof(VirtqUsedHdr));

    // Publish the ring physical addresses + size to the device.
    Write16(L->common_cfg, kCcQueueSize, size);
    Write64(L->common_cfg, kCcQueueDesc, q->desc_phys);
    Write64(L->common_cfg, kCcQueueDriver, q->avail_phys);
    Write64(L->common_cfg, kCcQueueDevice, q->used_phys);
    q->notify_off = Read16(L->common_cfg, kCcQueueNotifyOff);
    Write16(L->common_cfg, kCcQueueEnable, 1);

    q->up = true;
    KLOG_INFO_2V("drivers/virtio/queue", "queue ready", "qid", static_cast<u64>(queue_index), "size",
                 static_cast<u64>(size));
    return true;
}

void VirtioMarkDriverOk(VirtioPciLayout* L)
{
    if (L == nullptr || L->common_cfg == nullptr)
        return;
    const u8 cur = *reinterpret_cast<volatile u8*>(L->common_cfg + kCcDeviceStatus);
    *reinterpret_cast<volatile u8*>(L->common_cfg + kCcDeviceStatus) = static_cast<u8>(cur | kStatusDriverOk);
}

void VirtioQueuePublish(VirtioPciLayout* L, VirtioQueue* q, u16 desc_head)
{
    if (L == nullptr || q == nullptr || !q->up || L->notify == nullptr)
        return;

    // Slot in the available ring. `idx` is monotonic; modulo by
    // queue_size when indexing.
    const u16 slot = q->next_avail % q->queue_size;
    q->avail_ring[slot] = desc_head;

    // Spec §2.6.13: writer must publish descriptor content and
    // ring[slot] BEFORE bumping avail->idx, and the device must
    // see the new avail->idx before the notify write. The kernel
    // is single-CPU during this v0 path, but a `mfence` keeps
    // store ordering correct across any CPU model.
    asm volatile("mfence" ::: "memory");
    q->next_avail = static_cast<u16>(q->next_avail + 1);
    q->avail_hdr->idx = q->next_avail;
    asm volatile("mfence" ::: "memory");

    // Notify the device. The notify register address is:
    //   notify_addr = notify_base + (queue_notify_off * notify_off_multiplier)
    // We snapshotted notify_off during VirtioQueueSetup.
    const u64 off = static_cast<u64>(q->notify_off) * L->notify_off_multiplier;
    *reinterpret_cast<volatile u16*>(L->notify + off) = q->queue_index;
}

bool VirtioQueueTryPop(VirtioQueue* q, u32* out_desc_head, u32* out_used_len)
{
    if (q == nullptr || !q->up)
        return false;
    const u16 dev_idx = q->used_hdr->idx;
    if (dev_idx == q->last_used_idx)
        return false;
    const u16 slot = q->last_used_idx % q->queue_size;
    const VirtqUsedElem e = const_cast<VirtqUsedElem&>(q->used_ring[slot]);
    q->last_used_idx = static_cast<u16>(q->last_used_idx + 1);
    if (out_desc_head != nullptr)
        *out_desc_head = e.id;
    if (out_used_len != nullptr)
        *out_used_len = e.len;
    return true;
}

} // namespace duetos::drivers::virtio
