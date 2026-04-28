/*
 * DuetOS — dynamic event tracer, v0 (plan D2).
 *
 * See `event_trace.h` for the public contract. This TU owns the
 * ring storage, the lockless append path, and the snapshot
 * walker. v0 is single-ring (one global buffer); per-CPU rings
 * land with B2 SMP — until then a single ring is correct on
 * BSP-only boot.
 *
 * Append ordering note: the writer publishes (tick, kind,
 * arg0, arg1) into a slot, THEN bumps `g_total` so a reader who
 * sees a high `g_total` either (a) sees the slot fully written
 * or (b) is racing and may observe a partial slot. The reader
 * tolerates (b) by re-reading the kind field as the last gate —
 * we write `kind` LAST, so a reader who sees `kind != 0` knows
 * the slot is fully populated.
 */

#include "diag/event_trace.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "time/tick.h"

namespace duetos::diag
{

namespace
{

constinit EventRecord g_ring[kEventRingCapacity] = {};
constinit u64 g_total = 0; ///< Total appends ever; modulo capacity = current head.

} // namespace

void EventTrace(u32 kind, u64 arg0, u64 arg1)
{
    if (kind == kEventNone)
    {
        // Sentinel rejected — the snapshot path uses kind != 0
        // as the "slot is populated" gate, so writing 0 would
        // create a torn-slot signal that a real reader can't
        // distinguish from "not yet written".
        return;
    }
    // Atomic fetch-add — the slot index is the OLD head value;
    // the writer owns it exclusively until the kind store below
    // republishes it.
    const u64 idx = __atomic_fetch_add(&g_total, 1, __ATOMIC_SEQ_CST);
    EventRecord& slot = g_ring[idx % kEventRingCapacity];
    slot.tick = ::duetos::time::TickCount();
    slot._pad0 = 0;
    slot.arg0 = arg0;
    slot.arg1 = arg1;
    // Compiler barrier: the kind store must be after the payload
    // stores so a reader observing kind != 0 sees the full
    // record. On x86 plain stores are sequentially consistent
    // w.r.t. each other, so a barrier alone (no fence) is enough.
    asm volatile("" ::: "memory");
    slot.kind = kind;
}

u64 EventTraceTotalRecords()
{
    return __atomic_load_n(&g_total, __ATOMIC_SEQ_CST);
}

u32 EventTraceLiveCount()
{
    const u64 total = EventTraceTotalRecords();
    return (total < kEventRingCapacity) ? static_cast<u32>(total) : kEventRingCapacity;
}

u32 EventTraceSnapshot(EventRecord* out, u32 out_capacity)
{
    if (out == nullptr || out_capacity == 0)
    {
        return 0;
    }
    const u64 total = EventTraceTotalRecords();
    const u32 live = EventTraceLiveCount();
    const u32 to_copy = (live < out_capacity) ? live : out_capacity;
    if (to_copy == 0)
    {
        return 0;
    }
    // Walk oldest-first. When `total < capacity`, the oldest is
    // index 0; when `total >= capacity`, the oldest is index
    // `total % capacity` (the slot the next writer will
    // overwrite).
    const u64 oldest_idx = (total < kEventRingCapacity) ? 0 : (total % kEventRingCapacity);
    for (u32 i = 0; i < to_copy; ++i)
    {
        const u32 src = static_cast<u32>((oldest_idx + i) % kEventRingCapacity);
        // Re-read kind first as the torn-slot gate; if a writer
        // is mid-append on this slot, we may see kind == 0 and
        // bail out early. The records we've already copied are
        // still valid.
        const u32 kind = __atomic_load_n(&g_ring[src].kind, __ATOMIC_SEQ_CST);
        if (kind == kEventNone)
        {
            return i;
        }
        out[i] = g_ring[src];
    }
    return to_copy;
}

const char* EventKindName(u32 kind)
{
    switch (kind)
    {
    case kEventNone:
        return "(none)";
    case kEventSyscallEnter:
        return "syscall-enter";
    case kEventSyscallExit:
        return "syscall-exit";
    case kEventSchedSwitch:
        return "sched-switch";
    case kEventIrq:
        return "irq";
    case kEventPageFault:
        return "page-fault";
    case kEventMutexAcquire:
        return "mutex-acquire";
    case kEventMutexRelease:
        return "mutex-release";
    case kEventCustom:
        return "custom";
    default:
        return "?";
    }
}

void EventTraceSelfTest()
{
    arch::SerialWrite("[event-trace] self-test: append + snapshot + ordering\n");

    const u64 baseline_total = EventTraceTotalRecords();
    const u32 baseline_live = EventTraceLiveCount();

    // Reject the sentinel. Total must NOT advance.
    EventTrace(kEventNone, 0xdead, 0xbeef);
    if (EventTraceTotalRecords() != baseline_total)
    {
        core::Panic("diag/event-trace", "self-test: kEventNone advanced total");
    }

    // Append three records and verify total / live advanced
    // accordingly.
    EventTrace(kEventCustom, 0x1111, 0x2222);
    EventTrace(kEventCustom, 0x3333, 0x4444);
    EventTrace(kEventCustom, 0x5555, 0x6666);
    if (EventTraceTotalRecords() != baseline_total + 3)
    {
        core::Panic("diag/event-trace", "self-test: total did not advance by 3");
    }
    const u32 new_live = EventTraceLiveCount();
    if (new_live != baseline_live + 3 && new_live != kEventRingCapacity)
    {
        // Either we grew live count by 3 (under-cap), or we hit
        // the cap. Both are valid outcomes.
        core::Panic("diag/event-trace", "self-test: live count not consistent with append count");
    }

    // Snapshot the trailing 3 records and verify their args came
    // back in order. Use a small scratch buffer so the snapshot
    // walks only the fresh entries.
    EventRecord buf[3] = {};
    const u32 baseline_to_snap = (baseline_live < (kEventRingCapacity - 3)) ? baseline_live : (kEventRingCapacity - 3);
    EventRecord all_buf[kEventRingCapacity];
    const u32 got = EventTraceSnapshot(all_buf, kEventRingCapacity);
    if (got < 3)
    {
        core::Panic("diag/event-trace", "self-test: snapshot returned fewer than 3 records");
    }
    // Look at the LAST 3 records — those must be ours.
    for (u32 i = 0; i < 3; ++i)
    {
        buf[i] = all_buf[got - 3 + i];
    }
    if (buf[0].arg0 != 0x1111 || buf[0].arg1 != 0x2222)
    {
        core::Panic("diag/event-trace", "self-test: record 0 args wrong");
    }
    if (buf[1].arg0 != 0x3333 || buf[1].arg1 != 0x4444)
    {
        core::Panic("diag/event-trace", "self-test: record 1 args wrong");
    }
    if (buf[2].arg0 != 0x5555 || buf[2].arg1 != 0x6666)
    {
        core::Panic("diag/event-trace", "self-test: record 2 args wrong");
    }
    if (buf[0].kind != kEventCustom || buf[1].kind != kEventCustom || buf[2].kind != kEventCustom)
    {
        core::Panic("diag/event-trace", "self-test: recorded kind mismatch");
    }
    // Ticks must be monotonic non-decreasing across the three
    // records (TickCount only advances forward).
    if (buf[1].tick < buf[0].tick || buf[2].tick < buf[1].tick)
    {
        core::Panic("diag/event-trace", "self-test: recorded ticks not monotonic");
    }

    // Kind-name resolution.
    if (EventKindName(kEventCustom)[0] == '?')
    {
        core::Panic("diag/event-trace", "self-test: kind name for custom resolved to '?'");
    }
    if (EventKindName(0xDEAD'BEEFu)[0] != '?')
    {
        core::Panic("diag/event-trace", "self-test: unknown kind did not resolve to '?'");
    }

    (void)baseline_to_snap;

    arch::SerialWrite("[event-trace] self-test OK (append + snapshot + ordering + kind-name).\n");
}

} // namespace duetos::diag
