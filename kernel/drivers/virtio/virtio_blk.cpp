#include "drivers/storage/block.h"
#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/traps.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

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
 * completion.
 *
 * Read + write share `VirtioBlkBlockRequest`; the only
 * differences are the header `type` (kBlkTypeIn vs kBlkTypeOut)
 * and the data descriptor's `kVirtqDescWrite` flag (set on read,
 * cleared on write — read is "device writes our buffer", write is
 * "device reads our buffer"). Devices that advertise
 * `VIRTIO_BLK_F_RO` keep the read-only path: `BlockOps.write` is
 * still wired but VirtioBlkBlockRequest fails fast on the RO
 * check. Capacity comes from `device_cfg + 0` (8-byte u64);
 * sector size is 512 unless `VIRTIO_BLK_F_BLK_SIZE` is offered
 * (read from `device_cfg + 20` in that case).
 *
 * Completion + concurrency model:
 *
 *   - The 32-entry requestq is pre-partitioned into kBlkSlots
 *     fixed slots of kBlkDescsPerSlot contiguous descriptors
 *     (slot s owns descs 3s..3s+2; used-ring id / 3 maps a
 *     completion back to its slot). The shared 4 KiB header page
 *     is carved the same way: 64 bytes per slot (request header
 *     at +0, status byte at +16, discard-range payload at +32).
 *     Up to kBlkSlots requests are genuinely in flight at once.
 *   - `vq_lock` (IRQ-safe spinlock) guards the slot claim/release
 *     bitmap, the avail-ring publish (next_avail / avail->idx /
 *     doorbell) and used-ring pops. Descriptor + header fills run
 *     OUTSIDE the lock — the claimed slot is exclusively owned.
 *   - When the probe binds an MSI-X vector, completions are
 *     IRQ-driven: the handler drains the used ring under vq_lock,
 *     marks slots done, and wakes the waiters parked on
 *     `cq_wait`. Waiters block with a small tick timeout; the
 *     timeout bounds the cross-CPU lost-wakeup window.
 *   - When MSI-X is unavailable (irq_vector == 0) the driver
 *     falls back to the fully-serialised polling path: `req_lock`
 *     (a sleeping Mutex, taken only in poll mode) admits one
 *     request at a time and the waiter drains the used ring
 *     itself. Poll mode loses nothing — without an IRQ there is
 *     no wakeup to parallelise around.
 *
 * GAP: config-change interrupts are not consumed (the device's
 * MSI-X config vector stays parked at NO_VECTOR), so a runtime
 * capacity resize goes unnoticed — revisit if a hot-resize
 * workload appears. A request that times out abandons its slot;
 * the slot is quarantined until the device's late completion
 * arrives (ClaimSlot then reclaims it) so a stalled device
 * degrades capacity instead of corrupting a successor request.
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

// Request-slot geometry. Every request shape (read/write, flush,
// discard) fits in 3 descriptors, so the 32-entry queue is
// pre-partitioned into 10 slots of 3 contiguous descriptors each
// (descs 30/31 unused). The shared 4 KiB header page is carved
// into 64-byte regions, one per slot.
constexpr u32 kBlkSlots = 10;
constexpr u32 kBlkDescsPerSlot = 3;
constexpr u32 kBlkSlotStride = 64;
constexpr u32 kBlkSlotStatusOff = 16;
constexpr u32 kBlkSlotDiscardOff = 32;
static_assert(kBlkSlots * kBlkDescsPerSlot <= kVirtqDefaultSize, "slot partition must fit the queue");
static_assert(kBlkSlots * kBlkSlotStride <= 4096, "slot scratch regions must fit one page");

// Completion budget: ~2 s at the 100 Hz scheduler tick. Matches
// the old ~5M-pause poll budget in spirit; tick-based so IRQ-mode
// waiters can sleep instead of burning CPU.
constexpr u64 kBlkBudgetTicks = 200;
// Per-block chunk while waiting. Bounds the cross-CPU lost-wakeup
// window (ISR wake landing between a waiter's re-check and its
// enqueue) to one chunk.
constexpr u64 kBlkWaitChunkTicks = 2;

// One in-flight request slot. `in_use`/`abandoned` are guarded by
// vq_lock; `done` is written by the ISR (under vq_lock) and read
// lock-free by the waiter.
struct ReqSlot
{
    volatile u8 done;
    volatile u8 abandoned;
    u8 in_use;
    u8 _pad;
};

struct DeviceState
{
    bool up;
    bool read_only;
    bool discard;
    u8 irq_vector;        // bound MSI-X IDT vector; 0 = polling mode
    u8 num_slots;         // usable slots: min(kBlkSlots, queue_size / 3)
    bool irq_path_logged; // one-shot "irq-completion path active" sentinel
    u8 _pad[2];

    VirtioPciLayout layout;
    VirtioQueue q;

    // Slot scratch backing — one 4 KiB page carved into 64-byte
    // per-slot regions (header at +0, status at +16, discard range
    // at +32). Single page because descriptor phys-addresses can
    // point at arbitrary offsets within a frame.
    mm::PhysAddr hdr_phys;
    u8* hdr_virt;

    u32 sector_size;
    u32 block_handle; // BlockDeviceRegister handle (self-test lookup)
    u64 sector_count;

    // Completions consumed inside the ISR since boot. Diagnostic +
    // self-test evidence that the IRQ path is genuinely live.
    u64 irq_completions;

    ReqSlot slots[kBlkSlots];

    // Guards: slot claim/release, avail publish (next_avail /
    // avail->idx / doorbell), used-ring pops. IRQ-safe — the MSI-X
    // handler takes it; task-side holders run with IRQs off for
    // the (short) critical section.
    sync::SpinLock vq_lock;

    duetos::sched::WaitQueue cq_wait;        // ISR → completion waiters
    duetos::sched::WaitQueue slot_free_wait; // slot release → claim waiters

    // Poll-mode only (irq_vector == 0): admits one request at a
    // time, preserving the fully-serialised stage-1 behaviour.
    // The IRQ-mode data path never takes it.
    duetos::sched::Mutex req_lock;
};

constinit DeviceState g_blk = {};

// --- IRQ-driven completion + multi-in-flight slot machinery -----------------

// MSI-X handler. IRQ context: the dispatcher performs the EOI —
// this handler must not, and it must not log (serial under an IRQ
// is how soft-lockups start; the waiter side owns the one-shot
// "irq path active" sentinel). Work is bounded: at most num_slots
// used-ring entries can ever be outstanding.
void VirtioBlkIrqHandler()
{
    auto flags = sync::SpinLockAcquire(g_blk.vq_lock);
    u32 id = 0;
    u32 used_len = 0;
    while (VirtioQueueTryPop(&g_blk.q, &id, &used_len))
    {
        const u32 slot = id / kBlkDescsPerSlot;
        if (slot < kBlkSlots)
            g_blk.slots[slot].done = 1;
        ++g_blk.irq_completions;
    }
    sync::SpinLockRelease(g_blk.vq_lock, flags);
    // IRQ context runs with interrupts disabled, satisfying the
    // WaitQueue wake contract.
    duetos::sched::WaitQueueWakeAll(&g_blk.cq_wait);
}

// Claim a free request slot, blocking (bounded) when all are in
// flight. Returns the slot index, or -1 on timeout. A slot whose
// waiter abandoned it (completion timeout) is reclaimed once the
// device's late completion finally lands (`done` flips) — before
// that, its scratch region may still be a DMA target and must not
// be reused.
i32 ClaimSlot(DeviceState* dev)
{
    const u64 deadline = duetos::arch::TimerTicks() + kBlkBudgetTicks;
    for (;;)
    {
        {
            auto flags = sync::SpinLockAcquire(dev->vq_lock);
            for (u32 s = 0; s < dev->num_slots; ++s)
            {
                ReqSlot& sl = dev->slots[s];
                if (sl.in_use == 0 || (sl.abandoned != 0 && sl.done != 0))
                {
                    sl.in_use = 1;
                    sl.abandoned = 0;
                    sl.done = 0;
                    sync::SpinLockRelease(dev->vq_lock, flags);
                    return static_cast<i32>(s);
                }
            }
            sync::SpinLockRelease(dev->vq_lock, flags);
        }
        if (duetos::arch::TimerTicks() >= deadline)
            return -1;
        // Every slot busy: park until a release. The chunked
        // timeout bounds the lost-wakeup window (a slot freed
        // between the scan above and the block self-recovers on
        // the next chunk). Block contract: interrupts disabled
        // across the enqueue. The IF state on resume is whatever
        // the switching-out peer carried — re-enable explicitly so
        // this loop (and our caller) never proceeds IRQs-off.
        duetos::arch::Cli();
        duetos::sched::WaitQueueBlockTimeout(&dev->slot_free_wait, kBlkWaitChunkTicks);
        duetos::arch::Sti();
    }
}

// Release a slot after its completion was consumed (`abandoned ==
// false`) or quarantine it after a timeout (`abandoned == true` —
// see ClaimSlot for the reclaim).
void ReleaseSlot(DeviceState* dev, u32 slot, bool abandoned)
{
    {
        auto flags = sync::SpinLockAcquire(dev->vq_lock);
        if (abandoned)
        {
            dev->slots[slot].abandoned = 1;
        }
        else
        {
            dev->slots[slot].in_use = 0;
            dev->slots[slot].abandoned = 0;
        }
        sync::SpinLockRelease(dev->vq_lock, flags);
    }
    if (!abandoned)
    {
        // Task-context wake: the WaitQueue contract wants
        // interrupts off across the call.
        duetos::arch::Cli();
        duetos::sched::WaitQueueWakeOne(&dev->slot_free_wait);
        duetos::arch::Sti();
    }
}

// Shared completion wait — the one helper behind read/write/flush/
// discard, modeled on nvme.cpp's SubmitAndWait tail. IRQ mode
// blocks on cq_wait (the ISR marks the slot done); polling mode
// drains the used ring inline. Returns true once `slots[slot].done`
// is set, false on budget exhaustion.
bool WaitForSlot(DeviceState* dev, u32 slot)
{
    const u64 deadline = duetos::arch::TimerTicks() + kBlkBudgetTicks;
    for (;;)
    {
        if (dev->slots[slot].done != 0)
            return true;
        if (duetos::arch::TimerTicks() >= deadline)
            return false;
        if (dev->irq_vector != 0)
        {
            // Lost-wakeup guard: re-check the done flag with
            // interrupts off before committing to the block — a
            // same-CPU ISR cannot fire inside the Cli window, and
            // the chunked timeout bounds the cross-CPU case.
            duetos::arch::Cli();
            if (dev->slots[slot].done != 0)
            {
                duetos::arch::Sti();
                continue;
            }
            duetos::sched::WaitQueueBlockTimeout(&dev->cq_wait, kBlkWaitChunkTicks);
            // Resume IF state is the switching-out peer's — force
            // IRQs back on so the loop never spins IRQs-off.
            duetos::arch::Sti();
        }
        else
        {
            // Polling fallback: no ISR pops the used ring, so the
            // waiter does. req_lock serialises poll-mode requests,
            // but vq_lock is still taken for pop consistency with
            // the (possible) IRQ-mode siblings of a future device.
            auto flags = sync::SpinLockAcquire(dev->vq_lock);
            u32 id = 0;
            u32 used_len = 0;
            while (VirtioQueueTryPop(&dev->q, &id, &used_len))
            {
                const u32 s = id / kBlkDescsPerSlot;
                if (s < kBlkSlots)
                    dev->slots[s].done = 1;
            }
            sync::SpinLockRelease(dev->vq_lock, flags);
            if (dev->slots[slot].done == 0)
                asm volatile("pause" ::: "memory");
        }
    }
}

// One request, fully described. The middle descriptor is the data
// buffer for read/write, the range payload for discard, or absent
// (mid_len == 0) for flush.
struct BlkSubmit
{
    u32 hdr_type;
    u64 sector;
    u64 mid_phys;
    u32 mid_len;
    bool mid_device_writes; // kVirtqDescWrite on the middle descriptor
    bool is_discard;        // payload synthesised into the slot region
    u64 discard_lba;
    u32 discard_count;
};

// Claim a slot, build its descriptor chain, publish, wait, and
// release. Returns 0 on an OK status byte, -1 on timeout / non-OK.
i32 VirtioBlkSubmitAndWait(DeviceState* dev, const BlkSubmit& sub)
{
    const bool poll_mode = (dev->irq_vector == 0);
    if (poll_mode)
        duetos::sched::MutexLock(&dev->req_lock);

    const i32 slot_i = ClaimSlot(dev);
    if (slot_i < 0)
    {
        if (poll_mode)
            duetos::sched::MutexUnlock(&dev->req_lock);
        KLOG_WARN_V("drivers/virtio/blk", "no free request slot within budget; type", static_cast<u64>(sub.hdr_type));
        return -1;
    }
    const u32 slot = static_cast<u32>(slot_i);

    // Fill the slot's scratch region + descriptor triple OUTSIDE
    // vq_lock — the claim gives exclusive ownership of both.
    u8* base = dev->hdr_virt + slot * kBlkSlotStride;
    const mm::PhysAddr base_phys = dev->hdr_phys + slot * kBlkSlotStride;
    auto* hdr = reinterpret_cast<BlkReqHdr*>(base);
    hdr->type = sub.hdr_type;
    hdr->reserved = 0;
    hdr->sector = sub.sector;
    // Status is reset to a sentinel the device must overwrite —
    // 0xFF, well outside the legal {OK, IO_ERR, UNSUPP} range.
    volatile u8* status = base + kBlkSlotStatusOff;
    *status = 0xFF;

    u64 mid_phys = sub.mid_phys;
    u32 mid_len = sub.mid_len;
    if (sub.is_discard)
    {
        auto* range = reinterpret_cast<BlkDiscardRange*>(base + kBlkSlotDiscardOff);
        range->sector = sub.discard_lba;
        range->num_sectors = sub.discard_count;
        range->flags = 0;
        mid_phys = base_phys + kBlkSlotDiscardOff;
        mid_len = sizeof(BlkDiscardRange);
    }

    VirtqDesc* d = const_cast<VirtqDesc*>(dev->q.desc);
    const u16 head = static_cast<u16>(slot * kBlkDescsPerSlot);
    u16 di = head;
    // Chain head — request header, driver-write.
    d[di].addr = base_phys;
    d[di].len = 16;
    d[di].flags = kVirtqDescNext;
    d[di].next = static_cast<u16>(di + 1);
    if (mid_len != 0)
    {
        ++di;
        d[di].addr = mid_phys;
        d[di].len = mid_len;
        d[di].flags = static_cast<u16>(kVirtqDescNext | (sub.mid_device_writes ? kVirtqDescWrite : 0));
        d[di].next = static_cast<u16>(di + 1);
    }
    // Status — device-write, 1 byte.
    ++di;
    d[di].addr = base_phys + kBlkSlotStatusOff;
    d[di].len = 1;
    d[di].flags = kVirtqDescWrite;
    d[di].next = 0;

    // Publish under vq_lock — serialises next_avail / avail->idx /
    // the notify doorbell across concurrent submitters.
    {
        auto flags = sync::SpinLockAcquire(dev->vq_lock);
        VirtioQueuePublish(&dev->layout, &dev->q, head);
        sync::SpinLockRelease(dev->vq_lock, flags);
    }

    const bool completed = WaitForSlot(dev, slot);
    i32 rc = -1;
    if (completed)
    {
        const u8 st = *status;
        if (st == kBlkStatusOk)
            rc = 0;
        else
            KLOG_WARN_2V("drivers/virtio/blk", "request completed non-OK", "status", static_cast<u64>(st), "type",
                         static_cast<u64>(sub.hdr_type));
        if (!poll_mode && !dev->irq_path_logged)
        {
            dev->irq_path_logged = true;
            KLOG_INFO_V("drivers/virtio/blk", "irq-completion path active; vector", static_cast<u64>(dev->irq_vector));
        }
    }
    else
    {
        KLOG_WARN_2V("drivers/virtio/blk", "request wait timed out", "type", static_cast<u64>(sub.hdr_type), "slot",
                     static_cast<u64>(slot));
    }

    ReleaseSlot(dev, slot, /*abandoned=*/!completed);
    if (poll_mode)
        duetos::sched::MutexUnlock(&dev->req_lock);
    return rc;
}

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

    BlkSubmit sub = {};
    sub.hdr_type = is_write ? kBlkTypeOut : kBlkTypeIn;
    sub.sector = lba;
    sub.mid_phys = data_phys;
    sub.mid_len = static_cast<u32>(byte_len);
    // Direction depends on op: device-write for reads (the device
    // fills our buffer), driver-write for writes.
    sub.mid_device_writes = !is_write;
    return VirtioBlkSubmitAndWait(dev, sub);
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
    // descriptor — the chain is header + status only (mid_len ==
    // 0). Sector field set to 0 for cleanliness.
    BlkSubmit sub = {};
    sub.hdr_type = kBlkTypeFlush;
    sub.sector = 0;
    return VirtioBlkSubmitAndWait(dev, sub);
}

// VIRTIO_BLK_T_DISCARD with a single 16-byte range descriptor.
// Chain shape: header (driver-write 16 B) -> range payload
// (driver-write 16 B) -> status (device-write 1 B). The range
// payload lives in the claimed slot's scratch region at offset
// 32 — SubmitAndWait synthesises it once the slot is known.
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

    BlkSubmit sub = {};
    sub.hdr_type = kBlkTypeDiscard;
    sub.sector = 0; // ignored for discard — range is in the payload
    sub.is_discard = true;
    sub.discard_lba = lba;
    sub.discard_count = count;
    return VirtioBlkSubmitAndWait(dev, sub);
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

    // Slot partition: every request shape fits 3 descriptors, so
    // queue_size/3 slots, capped at kBlkSlots. A device whose max
    // queue can't even hold one chain is unusable.
    u8 num_slots = static_cast<u8>(g_blk.q.queue_size / kBlkDescsPerSlot);
    if (num_slots > kBlkSlots)
        num_slots = kBlkSlots;
    if (num_slots == 0)
    {
        KLOG_WARN_V("drivers/virtio/blk", "queue too small for one request chain; size",
                    static_cast<u64>(g_blk.q.queue_size));
        return false;
    }

    // MSI-X completion routing. Must land between VirtioQueueSetup
    // and VirtioMarkDriverOk (the device latches queue_msix_vector
    // before DRIVER_OK). Either failure falls back to polling —
    // the driver works either way, IRQ mode just stops burning the
    // CPU and unlocks real request parallelism.
    u8 irq_vector = 0;
    {
        auto bind = pci::PciMsixBindSimple(layout.addr, /*entry_index=*/0, VirtioBlkIrqHandler, /*out_route=*/nullptr);
        if (bind.has_value())
        {
            if (VirtioQueueMsixVectorSet(&layout, &g_blk.q, /*msix_entry=*/0))
            {
                irq_vector = bind.value();
                KLOG_INFO_V("drivers/virtio/blk", "MSI-X bound; IRQ-driven completion armed, vector",
                            static_cast<u64>(irq_vector));
            }
            else
            {
                // Device refused the per-queue route: release the
                // IDT vector so the dispatcher doesn't hold a dead
                // handler, and poll.
                duetos::arch::IrqInstall(bind.value(), nullptr);
                KLOG_WARN("drivers/virtio/blk", "device refused queue MSI-X vector — polling mode");
            }
        }
        else
        {
            KLOG_INFO("drivers/virtio/blk", "MSI-X unavailable — polling mode");
        }
    }

    // Spec §3.1.1 step 8 — queue is up, finalise the device.
    VirtioMarkDriverOk(&layout);

    // One shared scratch page, carved into kBlkSlots 64-byte
    // per-slot regions (header / status / discard payload — see
    // the slot-geometry constants).
    auto hdr_phys_r = mm::AllocateFrame();
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
    g_blk.irq_vector = irq_vector;
    g_blk.num_slots = num_slots;
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
    g_blk.block_handle = h;

    KLOG_INFO_2V("drivers/virtio/blk", "attached as block device", "sectors", capacity, "sector-size",
                 static_cast<u64>(sector_size));
    KLOG_INFO_2V("drivers/virtio/blk", "completion mode", "irq-vector(0=poll)", static_cast<u64>(irq_vector),
                 "request-slots", static_cast<u64>(num_slots));
    // Read / Write / Flush / Discard are all wired through the
    // BlockOps vtable. Concurrent callers are safe: up to
    // num_slots requests fly in parallel under IRQ completion;
    // poll mode serialises on req_lock (see the file-level
    // comment for the full model).
    return true;
}

// ===================================================================
// Boot self-test — IRQ-driven completion + multi-in-flight.
//
// Sibling pattern: BlockOwnedRegionSelfTest (block.h). Spawns
// kStLanes worker tasks doing interleaved BlockDeviceRead/Write
// of distinct patterned LBAs against vblk0, so several requests
// are genuinely in flight at once, then verifies contents and
// that completions flowed through the ISR. Write-mode only when
// the disk is writable AND carries no partition signature (the
// QEMU scratch image is raw zeros; a partitioned virtio disk is
// somebody's data — read-only checks in that case).
// ===================================================================

namespace
{

constexpr u32 kStLanes = 3;
constexpr u32 kStRounds = 8;
constexpr u64 kStLbaBase = 1024;
constexpr u64 kStLaneStride = 16;

struct StWorkerCtx
{
    u32 lane;
    u32 handle;
    u64 lba;
    u32 verify_bytes; // min(sector_size, 4096)
    bool write_mode;
};

StWorkerCtx g_st_ctx[kStLanes];
volatile u8 g_st_done[kStLanes];
volatile u8 g_st_fail[kStLanes]; // 0 = ok, else sub-check code
volatile u32 g_st_reqs[kStLanes];

void SerialWriteDec(u64 v)
{
    char buf[21];
    u32 i = 20;
    buf[20] = '\0';
    do
    {
        buf[--i] = static_cast<char>('0' + (v % 10));
        v /= 10;
    } while (v != 0 && i > 0);
    duetos::arch::SerialWrite(&buf[i]);
}

void StFail(u64 code)
{
    KLOG_WARN_V("drivers/virtio/blk", "selftest FAIL — sub-check", code);
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, code);
    duetos::arch::SerialWrite("[virtio-blk-selftest] FAIL\n");
}

void VirtioBlkSelfTestWorker(void* arg)
{
    auto* ctx = static_cast<StWorkerCtx*>(arg);
    auto wbuf_r = mm::AllocateFrame();
    auto rbuf_r = mm::AllocateFrame();
    if (!wbuf_r || !rbuf_r)
    {
        if (wbuf_r)
            mm::FreeFrame(wbuf_r.value());
        if (rbuf_r)
            mm::FreeFrame(rbuf_r.value());
        g_st_fail[ctx->lane] = 2;
        g_st_done[ctx->lane] = 1;
        return;
    }
    u8* wbuf = static_cast<u8*>(mm::PhysToVirt(wbuf_r.value()));
    u8* rbuf = static_cast<u8*>(mm::PhysToVirt(rbuf_r.value()));
    const u32 n = ctx->verify_bytes;

    using duetos::drivers::storage::BlockDeviceRead;
    using duetos::drivers::storage::BlockDeviceWrite;

    for (u32 round = 0; round < kStRounds && g_st_fail[ctx->lane] == 0; ++round)
    {
        if (ctx->write_mode)
        {
            // Distinct per-lane / per-round pattern so a slot or
            // descriptor mix-up across in-flight requests shows up
            // as a miscompare, not a silent pass.
            for (u32 i = 0; i < n; ++i)
                wbuf[i] = static_cast<u8>((ctx->lane * 0x35u) ^ (round * 0x5Bu) ^ i);
            if (BlockDeviceWrite(ctx->handle, ctx->lba, 1, wbuf) != 0)
            {
                g_st_fail[ctx->lane] = 3;
                break;
            }
            g_st_reqs[ctx->lane] = g_st_reqs[ctx->lane] + 1;
            for (u32 i = 0; i < n; ++i)
                rbuf[i] = 0;
            if (BlockDeviceRead(ctx->handle, ctx->lba, 1, rbuf) != 0)
            {
                g_st_fail[ctx->lane] = 4;
                break;
            }
            g_st_reqs[ctx->lane] = g_st_reqs[ctx->lane] + 1;
            for (u32 i = 0; i < n; ++i)
            {
                if (rbuf[i] != wbuf[i])
                {
                    g_st_fail[ctx->lane] = 5;
                    break;
                }
            }
        }
        else
        {
            // Read-only lane: the content is unverifiable, but the
            // request must still round-trip through the IRQ path.
            if (BlockDeviceRead(ctx->handle, ctx->lba, 1, rbuf) != 0)
            {
                g_st_fail[ctx->lane] = 4;
                break;
            }
            g_st_reqs[ctx->lane] = g_st_reqs[ctx->lane] + 1;
        }
        // Yield between rounds so the lanes genuinely interleave
        // instead of one lane draining its rounds back-to-back.
        duetos::sched::SchedYield();
    }

    mm::FreeFrame(wbuf_r.value());
    mm::FreeFrame(rbuf_r.value());
    g_st_done[ctx->lane] = 1;
}

} // namespace

void VirtioBlkSelfTest()
{
    using namespace duetos::drivers::storage;

    if (!g_blk.up)
        return; // no virtio-blk on this machine — nothing to test
    if (g_blk.irq_vector == 0)
    {
        // Polling mode is a legitimate fallback (no MSI-X on this
        // transport); the IRQ path simply isn't testable here.
        KLOG_DEBUG("drivers/virtio/blk", "selftest skipped — polling mode (no MSI-X)");
        return;
    }

    const u32 handle = g_blk.block_handle;
    bool write_mode = BlockDeviceIsWritable(handle) && !g_blk.read_only &&
                      g_blk.sector_count >= kStLbaBase + kStLanes * kStLaneStride + 1;

    // Partition-signature check: GptProbe adopts disks via the LBA-0
    // 0xAA55 signature (MBR or GPT protective MBR). A disk carrying
    // one is somebody's data — keep the lanes read-only. The QEMU
    // scratch image is raw zeros, so write-mode runs there. The
    // probe read also covers the "device readable at all" gate.
    {
        auto sig_r = mm::AllocateFrame();
        if (!sig_r)
        {
            KLOG_WARN("drivers/virtio/blk", "selftest skipped — frame alloc failed");
            return;
        }
        u8* sig = static_cast<u8*>(mm::PhysToVirt(sig_r.value()));
        if (BlockDeviceRead(handle, 0, 1, sig) != 0)
        {
            mm::FreeFrame(sig_r.value());
            StFail(1);
            return;
        }
        if (g_blk.sector_size >= 512 && sig[510] == 0x55 && sig[511] == 0xAA)
            write_mode = false;
        mm::FreeFrame(sig_r.value());
    }

    if (write_mode)
    {
        // Register the scratch range as DuetOS-owned so the test
        // passes even when the owned-write chokepoint is armed in
        // Deny mode (the test IS a legitimate writer of this raw
        // scratch region).
        BlockOwnedRegionAdd(handle, kStLbaBase, kStLanes * kStLaneStride, "virtio-blk-selftest");
    }

    const u32 verify_bytes = (g_blk.sector_size <= 4096) ? g_blk.sector_size : 4096;
    for (u32 lane = 0; lane < kStLanes; ++lane)
    {
        g_st_done[lane] = 0;
        g_st_fail[lane] = 0;
        g_st_reqs[lane] = 0;
        g_st_ctx[lane].lane = lane;
        g_st_ctx[lane].handle = handle;
        // Write lanes scribble well past any boot-sector tooling
        // might care about; read-only lanes (partitioned or tiny
        // disk) stay within the always-valid low LBAs instead —
        // capacity != 0 was checked at probe time.
        g_st_ctx[lane].lba = write_mode ? (kStLbaBase + lane * kStLaneStride) : (lane % g_blk.sector_count);
        g_st_ctx[lane].verify_bytes = verify_bytes;
        g_st_ctx[lane].write_mode = write_mode;
        if (duetos::sched::SchedCreate(&VirtioBlkSelfTestWorker, &g_st_ctx[lane], "vblk-selftest") == nullptr)
        {
            // Mark the unspawned lane done/failed so the join loop
            // below doesn't wait the full budget for it.
            g_st_fail[lane] = 6;
            g_st_done[lane] = 1;
        }
    }

    // Join with a generous budget (the lanes sleep on the IRQ wait
    // queue, not the CPU). 1000 ticks ≈ 10 s at the 100 Hz tick.
    const u64 deadline = duetos::arch::TimerTicks() + 1000;
    bool all_done = false;
    while (!all_done)
    {
        all_done = true;
        for (u32 lane = 0; lane < kStLanes; ++lane)
        {
            if (g_st_done[lane] == 0)
                all_done = false;
        }
        if (all_done)
            break;
        if (duetos::arch::TimerTicks() >= deadline)
        {
            StFail(7); // worker(s) wedged — IRQ completion never woke them
            return;
        }
        duetos::sched::SchedSleepTicks(1);
    }

    u64 total_reqs = 0;
    for (u32 lane = 0; lane < kStLanes; ++lane)
    {
        if (g_st_fail[lane] != 0)
        {
            StFail(g_st_fail[lane]);
            return;
        }
        total_reqs += g_st_reqs[lane];
    }

    // The point of the test: completions must have flowed through
    // the ISR, not a poll loop. irq_completions only advances
    // inside VirtioBlkIrqHandler.
    if (g_blk.irq_completions == 0)
    {
        StFail(8);
        return;
    }

    duetos::arch::SerialWrite("[virtio-blk-selftest] PASS (irq-completion, ");
    SerialWriteDec(total_reqs);
    duetos::arch::SerialWrite(" requests)\n");
}

} // namespace duetos::drivers::virtio
