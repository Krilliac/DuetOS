/*
 * DuetOS — xHCI driver: event-ring consumer + side cache.
 *
 * Sibling TU. Houses the synchronous event-ring waiters
 * (WaitEvent, WaitCmdCompletion) plus the TU-private side cache
 * that lets concurrent bulk-waiters claim Transfer Events the
 * primary HidPollEntry consumer didn't route to a HID endpoint.
 *
 * The cache is a fixed-size (32-slot) flat array; the public
 * functions are the only documented entry points. Both the cache
 * struct and the array are anonymous-namespace here — only Stash
 * and Take cross TU boundaries (declared in xhci_internal.h).
 */

#include "xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

namespace
{

// One slot in the side cache. `valid` is the in-use flag; the
// other fields are the relevant pieces of the original Transfer
// Event TRB (completion code + short-packet residual + the TRB
// length we put on the wire, used by the bulk path's "did we
// underrun?" check).
struct TrbEventCacheEntry
{
    volatile u64 trb_phys;
    volatile u32 completion_code;
    volatile u32 residual;
    volatile u32 trb_len;
    volatile u8 valid;
};

constinit TrbEventCacheEntry g_trb_event_cache[32] = {};

} // namespace

void TrbEventCacheStash(u64 trb_phys, u32 completion_code, u32 residual, u32 trb_len)
{
    for (auto& e : g_trb_event_cache)
    {
        if (e.valid)
            continue;
        e.trb_phys = trb_phys;
        e.completion_code = completion_code;
        e.residual = residual;
        e.trb_len = trb_len;
        e.valid = 1;
        return;
    }
    // Cache full — drop oldest (slot 0) so we always have room.
    g_trb_event_cache[0].trb_phys = trb_phys;
    g_trb_event_cache[0].completion_code = completion_code;
    g_trb_event_cache[0].residual = residual;
    g_trb_event_cache[0].trb_len = trb_len;
    g_trb_event_cache[0].valid = 1;
}

bool TrbEventCacheTake(u64 trb_phys, u32* completion_code, u32* residual, u32* trb_len)
{
    for (auto& e : g_trb_event_cache)
    {
        if (e.valid && e.trb_phys == trb_phys)
        {
            if (completion_code)
                *completion_code = e.completion_code;
            if (residual)
                *residual = e.residual;
            if (trb_len)
                *trb_len = e.trb_len;
            e.valid = 0;
            e.trb_phys = 0;
            return true;
        }
    }
    return false;
}

bool WaitEvent(Runtime& rt, u64 expect_phys, u32 expect_type, Trb* out, u64 iters)
{
    for (u64 i = 0; i < iters; ++i)
    {
        const Trb& e = rt.evt_ring[rt.evt_idx];
        const bool valid = (e.control & 1u) == (rt.evt_cycle & 1u);
        if (!valid)
        {
            asm volatile("pause" : : : "memory");
            continue;
        }
        const u32 type = (e.control >> 10) & 0x3F;
        const u64 ptr = (u64(e.param_hi) << 32) | u64(e.param_lo);
        if (type == expect_type && ptr == expect_phys)
        {
            if (out != nullptr)
                *out = e;
            AdvanceEventRing(rt);
            return true;
        }
        // Non-matching event. If it's another Transfer Event, stash
        // it into the side cache so a concurrent XhciBulkPoll waiter
        // can claim it. Other event types (port status, command
        // completions destined for the synchronous command path)
        // are dropped — those callers either run during init when
        // no other consumer exists, or have their own dedicated
        // pollers.
        if (type == kTrbTypeTransferEvent)
        {
            const u32 code = (e.status >> 24) & 0xFF;
            const u32 residual = e.status & 0x00FFFFFF;
            TrbEventCacheStash(ptr, code, residual, /*trb_len=*/0);
        }
        AdvanceEventRing(rt);
    }
    return false;
}

bool WaitCmdCompletion(Runtime& rt, u64 expect_phys, u32* out_status, u8* out_slot_id)
{
    Trb e{};
    if (!WaitEvent(rt, expect_phys, kTrbTypeCmdCompletion, &e, 4'000'000))
        return false;
    if (out_status != nullptr)
        *out_status = e.status;
    if (out_slot_id != nullptr)
        *out_slot_id = u8((e.control >> 24) & 0xFF);
    return true;
}

} // namespace duetos::drivers::usb::xhci::internal
