/*
 * DuetOS — xHCI driver: TRB ring + frame-allocation primitives.
 *
 * Sibling TU. Houses the canonical xHCI 1.2 §4.9 producer-side
 * ring helpers — Link-TRB wrap, command-ring submit, event-ring
 * advance — plus the small frame-allocation + register-poll
 * utilities used everywhere else in the driver.
 *
 *   AllocZeroPage    — one zeroed 4 KiB frame for a ring
 *   PollUntil        — busy-wait for an MMIO predicate
 *   RingDoorbell     — DB[idx] write
 *   EnqueueRingTrb   — generic ring producer with Link wrap
 *   SubmitCmd        — EnqueueRingTrb on the command ring + DB[0]
 *   AdvanceEventRing — bump consumer index + ERDP write-back
 *
 * No controller state is owned here — every call takes the
 * Runtime / ring it should poke as an argument.
 */

#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "drivers/usb/xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{


// Allocate one zeroed 4 KiB frame; return both phys + kernel-virtual
// pointer. Returns false on out-of-memory.
bool AllocZeroPage(mm::PhysAddr* out_phys, void** out_virt)
{
    const mm::PhysAddr phys = mm::AllocateFrame();
    if (phys == mm::kNullFrame)
        return false;
    void* virt = mm::PhysToVirt(phys);
    if (virt == nullptr)
        return false;
    auto* p = static_cast<volatile u8*>(virt);
    for (u64 i = 0; i < mm::kPageSize; ++i)
        p[i] = 0;
    *out_phys = phys;
    *out_virt = virt;
    return true;
}

// Wait for a u32 MMIO register to satisfy `(value & mask) == match`.
// Returns true if the predicate held within `iters` polls. iters is
// a busy-loop count; tuned conservatively (1M ≈ tens of ms on QEMU)
// because we're called from boot context with the timer not yet
// running self-test logic that would care about the exact wall time.
bool PollUntil(volatile u8* base, u64 reg_off, u32 mask, u32 match, u64 iters)
{
    for (u64 i = 0; i < iters; ++i)
    {
        const u32 v = ReadMmio32(base, reg_off);
        if ((v & mask) == match)
            return true;
        // tight-spin: a `pause` reduces power + signals the CPU
        // we're in a wait loop.
        asm volatile("pause" : : : "memory");
    }
    return false;
}

// Doorbell write. xHCI DB[0] rings the command ring; DB[slot_id] rings
// a device's endpoints. `target` is the DB Target field (bits 0..7);
// stream_id is 0 for non-stream endpoints.
void RingDoorbell(Runtime& rt, u32 db_index, u32 target, u32 stream_id)
{
    rt.db_base[db_index] = (stream_id << 16) | (target & 0xFF);
}

// Enqueue one TRB into a ring and return the physical address of the
// enqueued slot. The ring's last slot is reserved for a Link TRB
// that was installed at ring setup; when the producer would write
// there we instead flip its cycle bit (so the controller follows
// the link) and wrap the producer index to 0 with a toggled cycle.
// This is the canonical TRB ring protocol from xHCI 1.2 §4.9.
u64 EnqueueRingTrb(Trb* ring, u64 ring_phys, u32 slots, u32& idx, u32& cycle, u32 type, u32 param_lo, u32 param_hi,
                   u32 status, u32 extra_control)
{
    // If we're about to land on the Link TRB slot, refresh its
    // cycle bit to match the current producer cycle (so the
    // consumer follows it), then wrap. Link TRB's type + TC bit
    // were set at ring init; only bit 0 (cycle) moves here.
    if (idx == slots - 1)
    {
        ring[slots - 1].control = (ring[slots - 1].control & ~1u) | (cycle & 1u);
        idx = 0;
        cycle ^= 1;
    }
    Trb& slot = ring[idx];
    slot.param_lo = param_lo;
    slot.param_hi = param_hi;
    slot.status = status;
    slot.control = (type << 10) | (extra_control & ~1u) | (cycle & 1u);
    const u64 phys = ring_phys + u64(idx) * sizeof(Trb);
    ++idx;
    return phys;
}

u64 SubmitCmd(Runtime& rt, u32 type, u32 param_lo, u32 param_hi, u32 status, u32 extra_control)
{
    const u64 phys = EnqueueRingTrb(rt.cmd_ring, rt.cmd_phys, rt.cmd_slots, rt.cmd_idx, rt.cmd_cycle, type, param_lo,
                                    param_hi, status, extra_control);
    if (phys == 0)
        return 0;
    RingDoorbell(rt, 0, 0);
    return phys;
}

// Advance the consumer side of the event ring and push the updated
// dequeue pointer back to ERDP (with the "event handler busy" bit
// cleared — write 1 to clear per spec).
void AdvanceEventRing(Runtime& rt)
{
    ++rt.evt_idx;
    if (rt.evt_idx >= rt.evt_slots)
    {
        rt.evt_idx = 0;
        rt.evt_cycle ^= 1;
    }
    const u64 erdp = rt.evt_phys + u64(rt.evt_idx) * sizeof(Trb);
    WriteMmio64(rt.intr0, /*kIntrErdpLo=*/0x18, erdp | (1ull << 3));
}

} // namespace duetos::drivers::usb::xhci::internal
