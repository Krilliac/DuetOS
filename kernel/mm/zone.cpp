/*
 * DuetOS — memory zones, v0 scaffolding (plan C1).
 *
 * See `zone.h` for the public contract. v0 forwards every
 * allocation to the existing global frame allocator; the zone
 * argument is recorded in stats but doesn't yet route to a
 * separate underlying region. The day per-zone pools land,
 * this TU is the only place callers' shape changes.
 */

#include "mm/zone.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"

namespace duetos::mm
{

namespace
{

constinit ZoneStats g_stats[static_cast<u32>(Zone::Count)] = {};

bool IsValid(Zone z)
{
    return static_cast<u32>(z) < static_cast<u32>(Zone::Count);
}

} // namespace

const char* ZoneName(Zone z)
{
    switch (z)
    {
    case Zone::Dma:
        return "dma";
    case Zone::Dma32:
        return "dma32";
    case Zone::Normal:
        return "normal";
    case Zone::Mmio:
        return "mmio";
    default:
        return "?";
    }
}

PhysAddr AllocateZoneFrame(Zone zone)
{
    if (!IsValid(zone))
    {
        KLOG_WARN_V("mm/zone", "AllocateZoneFrame: invalid zone enumerator", static_cast<u64>(zone));
        return kNullFrame;
    }
    if (zone == Zone::Mmio)
    {
        // Reserved enumerator — no backing pool.
        ++g_stats[static_cast<u32>(zone)].oom;
        KLOG_ONCE_WARN("mm/zone", "AllocateZoneFrame: Mmio zone has no backing pool");
        return kNullFrame;
    }
    const PhysAddr f = AllocateFrame();
    if (f == kNullFrame)
    {
        ++g_stats[static_cast<u32>(zone)].oom;
        KLOG_WARN_S("mm/zone", "AllocateZoneFrame: out of frames", "zone", ZoneName(zone));
    }
    else
    {
        ++g_stats[static_cast<u32>(zone)].allocs;
        KLOG_TRACE_V("mm/zone", "AllocateZoneFrame: granted frame", f);
    }
    return f;
}

void FreeZoneFrame(Zone zone, PhysAddr frame)
{
    if (!IsValid(zone) || frame == kNullFrame)
    {
        KLOG_DEBUG("mm/zone", "FreeZoneFrame: ignored (invalid zone or null frame)");
        return;
    }
    FreeFrame(frame);
    ++g_stats[static_cast<u32>(zone)].frees;
    KLOG_TRACE_V("mm/zone", "FreeZoneFrame: returned frame", frame);
}

ZoneStats ZoneStatsRead(Zone zone)
{
    if (!IsValid(zone))
    {
        return {};
    }
    return g_stats[static_cast<u32>(zone)];
}

void ZoneSelfTest()
{
    KLOG_TRACE_SCOPE("mm/zone", "ZoneSelfTest");
    KLOG_INFO("mm/zone", "self-test: per-zone allocate + free + stats");
    arch::SerialWrite("[mm/zone] self-test: per-zone allocate + free + stats\n");

    for (u32 i = 0; i < static_cast<u32>(Zone::Count); ++i)
    {
        const Zone z = static_cast<Zone>(i);
        const ZoneStats before = ZoneStatsRead(z);
        const PhysAddr f = AllocateZoneFrame(z);
        if (z == Zone::Mmio)
        {
            // Mmio always fails — verify oom advanced + frame
            // returned kNullFrame.
            if (f != kNullFrame)
            {
                core::Panic("mm/zone", "self-test: mmio returned non-null frame");
            }
            const ZoneStats after = ZoneStatsRead(z);
            if (after.oom != before.oom + 1)
            {
                core::Panic("mm/zone", "self-test: mmio oom counter didn't advance");
            }
            continue;
        }
        if (f == kNullFrame)
        {
            core::Panic("mm/zone", "self-test: allocate returned null on a normal zone");
        }
        FreeZoneFrame(z, f);
        const ZoneStats after = ZoneStatsRead(z);
        if (after.allocs != before.allocs + 1)
        {
            core::Panic("mm/zone", "self-test: allocs counter didn't advance");
        }
        if (after.frees != before.frees + 1)
        {
            core::Panic("mm/zone", "self-test: frees counter didn't advance");
        }
    }

    arch::SerialWrite("[mm/zone] self-test OK (4 zones × allocate + free + stats verified).\n");
    KLOG_INFO("mm/zone", "self-test OK (4 zones x allocate + free + stats verified)");
}

} // namespace duetos::mm
