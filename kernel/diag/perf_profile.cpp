/*
 * DuetOS — PMU sample profiler, v0 (plan D3).
 *
 * See `perf_profile.h` for the contract. The sampling source
 * (PMU NMI overflow) is NOT wired in this slice — landing the
 * ring + dump first lets the future wiring be a one-line call
 * to `PerfRecord(frame->rip)` from inside the NMI handler.
 */

#include "diag/perf_profile.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "time/tick.h"

namespace duetos::diag
{

namespace
{

constinit PerfSample g_ring[kPerfRingCapacity] = {};
constinit u64 g_total = 0;

} // namespace

void PerfRecord(u64 rip)
{
    if (rip == 0)
    {
        // Treat 0 as the torn-slot gate (matches event_trace's
        // approach). Zero RIP is only ever observed in genuinely
        // broken state; dropping it from the profile is the
        // right call.
        return;
    }
    const u64 idx = __atomic_fetch_add(&g_total, 1, __ATOMIC_SEQ_CST);
    PerfSample& slot = g_ring[idx % kPerfRingCapacity];
    slot.tick = ::duetos::time::TickCount();
    asm volatile("" ::: "memory");
    slot.rip = rip; // last so a torn-slot reader observes rip=0
}

u64 PerfTotalSamples()
{
    return __atomic_load_n(&g_total, __ATOMIC_SEQ_CST);
}

u32 PerfLiveCount()
{
    const u64 total = PerfTotalSamples();
    return (total < kPerfRingCapacity) ? static_cast<u32>(total) : kPerfRingCapacity;
}

u32 PerfSnapshot(PerfSample* out, u32 out_capacity)
{
    if (out == nullptr || out_capacity == 0)
    {
        return 0;
    }
    const u64 total = PerfTotalSamples();
    const u32 live = PerfLiveCount();
    const u32 to_copy = (live < out_capacity) ? live : out_capacity;
    if (to_copy == 0)
    {
        return 0;
    }
    const u64 oldest_idx = (total < kPerfRingCapacity) ? 0 : (total % kPerfRingCapacity);
    for (u32 i = 0; i < to_copy; ++i)
    {
        const u32 src = static_cast<u32>((oldest_idx + i) % kPerfRingCapacity);
        const u64 rip = __atomic_load_n(&g_ring[src].rip, __ATOMIC_SEQ_CST);
        if (rip == 0)
        {
            return i; // torn slot — bail with what we have
        }
        out[i] = g_ring[src];
    }
    return to_copy;
}

void PerfReset()
{
    for (u32 i = 0; i < kPerfRingCapacity; ++i)
    {
        g_ring[i] = PerfSample{};
    }
    g_total = 0;
}

void PerfProfileSelfTest()
{
    arch::SerialWrite("[perf] self-test: append + snapshot + ordering\n");

    const u64 baseline = PerfTotalSamples();
    PerfRecord(0); // sentinel rejected
    if (PerfTotalSamples() != baseline)
    {
        core::Panic("diag/perf", "self-test: rip=0 advanced total");
    }

    PerfRecord(0xDEAD'BEEF'1111ULL);
    PerfRecord(0xDEAD'BEEF'2222ULL);
    PerfRecord(0xDEAD'BEEF'3333ULL);
    if (PerfTotalSamples() != baseline + 3)
    {
        core::Panic("diag/perf", "self-test: total didn't advance by 3");
    }

    PerfSample buf[kPerfRingCapacity];
    const u32 got = PerfSnapshot(buf, kPerfRingCapacity);
    if (got < 3)
    {
        core::Panic("diag/perf", "self-test: snapshot returned fewer than 3 records");
    }
    if (buf[got - 3].rip != 0xDEAD'BEEF'1111ULL || buf[got - 2].rip != 0xDEAD'BEEF'2222ULL ||
        buf[got - 1].rip != 0xDEAD'BEEF'3333ULL)
    {
        core::Panic("diag/perf", "self-test: trailing 3 RIPs don't match in order");
    }
    if (buf[got - 2].tick < buf[got - 3].tick || buf[got - 1].tick < buf[got - 2].tick)
    {
        core::Panic("diag/perf", "self-test: ticks not monotonic");
    }

    arch::SerialWrite("[perf] self-test OK (append + snapshot + ordering verified).\n");
}

} // namespace duetos::diag
