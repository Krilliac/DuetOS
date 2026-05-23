#include "diag/tlb_history.h"

#include "arch/x86_64/serial.h"
#include "time/tick.h"
#include "util/symbols.h"

namespace duetos::diag
{

namespace
{

alignas(64) constinit TlbHistoryEntry g_ring[kTlbHistorySlots] = {};

// Monotonic write counter. Slot = counter % kTlbHistorySlots.
// Lock-free: an `__atomic_fetch_add` returns the index unique to
// this writer. Two writers landing in the same slot is impossible
// because they each got a distinct counter value.
constinit u64 g_counter = 0;

} // namespace

void TlbHistoryRecord(u64 src_rip, u32 src_cpu, u64 as_ptr, u64 va_start, u64 va_end)
{
    const u64 idx = __atomic_fetch_add(&g_counter, 1, __ATOMIC_RELAXED) % kTlbHistorySlots;
    TlbHistoryEntry* e = &g_ring[idx];
    // Mark invalid while we write — a panic mid-write reading the
    // entry should skip it rather than print torn fields.
    __atomic_store_n(&e->valid, 0u, __ATOMIC_RELEASE);
    e->tick = ::duetos::time::TickCount();
    e->va_start = va_start;
    e->va_end = va_end;
    e->src_rip = src_rip;
    e->as_ptr = as_ptr;
    e->src_cpu = src_cpu;
    __atomic_store_n(&e->valid, 1u, __ATOMIC_RELEASE);
}

u64 TlbHistoryCount()
{
    return __atomic_load_n(&g_counter, __ATOMIC_RELAXED);
}

void TlbHistoryDump()
{
    const u64 total = TlbHistoryCount();
    if (total == 0)
    {
        // No shootdowns yet — UP boots or before SMP-online stay
        // silent. Could happen on a panic that fires before SMP
        // bringup completes.
        return;
    }
    ::duetos::arch::SerialWrite("[panic] --- TLB shootdown history (last ");
    if (total <= kTlbHistorySlots)
        ::duetos::arch::SerialWriteHex(total);
    else
        ::duetos::arch::SerialWriteHex(static_cast<u64>(kTlbHistorySlots));
    ::duetos::arch::SerialWrite(" of ");
    ::duetos::arch::SerialWriteHex(total);
    ::duetos::arch::SerialWrite(" total) ---\n");

    // Walk newest first. The most recent write is at (counter - 1) %
    // slots; step backwards 64 times. Skip slots whose `valid` is 0
    // (boot prefix before the ring filled, or a write in progress).
    const u64 newest = (total - 1) % kTlbHistorySlots;
    for (u32 i = 0; i < kTlbHistorySlots; ++i)
    {
        const u64 idx = (newest + kTlbHistorySlots - i) % kTlbHistorySlots;
        const TlbHistoryEntry* e = &g_ring[idx];
        if (__atomic_load_n(&e->valid, __ATOMIC_ACQUIRE) == 0)
            continue;
        ::duetos::arch::SerialWrite("  [");
        ::duetos::arch::SerialWriteHex(e->tick);
        ::duetos::arch::SerialWrite("] cpu=");
        ::duetos::arch::SerialWriteHex(static_cast<u64>(e->src_cpu));
        ::duetos::arch::SerialWrite(" as=");
        ::duetos::arch::SerialWriteHex(e->as_ptr);
        ::duetos::arch::SerialWrite(" va=[");
        ::duetos::arch::SerialWriteHex(e->va_start);
        ::duetos::arch::SerialWrite(",");
        ::duetos::arch::SerialWriteHex(e->va_end);
        ::duetos::arch::SerialWrite(") src_rip=");
        // WriteAddressWithSymbol emits the hex + a function+offset
        // suffix if the address resolves; falls back to bare hex.
        // No trailing newline — we add ours below.
        ::duetos::core::WriteAddressWithSymbol(e->src_rip);
        ::duetos::arch::SerialWrite("\n");
    }
}

} // namespace duetos::diag
