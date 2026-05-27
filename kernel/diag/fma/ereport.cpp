#include "diag/fma/ereport.h"

#include "cpu/percpu.h"
#include "sched/sched.h"

namespace duetos::diag::fma
{

namespace
{

// The ring itself. Fixed BSS. Slot indexed by `head % kEreportRingSize`.
// Head bumps atomically on every `EreportPost`; once head exceeds the
// ring size we are in steady-state wrap mode (oldest entry overwritten
// silently — `events_dropped` ticks for the first overrun and every
// subsequent overwrite).
constinit Ereport g_ring[kEreportRingSize] = {};

// Monotonic head counter. Bumped via __atomic_add_fetch(..., ACQ_REL)
// so that:
//   - Posters race-free claim distinct slot indices.
//   - The walker reads a stable snapshot of head, then walks slots
//     [head-N .. head) under the program-order rule (the slot stores
//     are sequenced after the head bump's prior value but BEFORE
//     publication of the new head, so a reader that observes head=N
//     can safely read slot (N-1)).
constinit u64 g_head = 0;

// Lifetime stats.
constinit u64 g_events_total = 0;
constinit u64 g_events_dropped = 0;
constinit u64 g_diagnoses_total = 0;
constinit u64 g_suspects_identified = 0;

// Copy at most `cap-1` chars from `src` into `dst`, NUL-terminating.
// Returns nothing — the slot's detector field has a fixed size and a
// truncated label is fine.
void CopyDetector(char* dst, u32 cap, const char* src)
{
    if (cap == 0)
    {
        return;
    }
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < cap && src[i] != '\0'; ++i)
        {
            dst[i] = src[i];
        }
    }
    dst[i] = '\0';
}

} // namespace

void EreportPost(EreportClass cls, EreportSeverity sev, u64 target_id, u64 aux0, u64 aux1, const char* detector)
{
    // Claim a unique slot. The atomic returns the NEW head — the
    // slot WE wrote to is at (new_head - 1) % ring_size.
    const u64 new_head = __atomic_add_fetch(&g_head, 1, __ATOMIC_ACQ_REL);
    const u64 slot_idx = (new_head - 1) % kEreportRingSize;

    Ereport& slot = g_ring[slot_idx];

    // Once head exceeds the ring size, every post overwrites a slot
    // that was previously valid. Bump the drop count so consumers
    // know how many older events fell out the back.
    if (new_head > kEreportRingSize)
    {
        __atomic_add_fetch(&g_events_dropped, 1, __ATOMIC_RELAXED);
    }

    slot.timestamp_ticks = sched::SchedNowTicks();
    slot.cls = cls;
    slot.severity = sev;
    slot._pad0 = 0;
    slot.source_cpu = cpu::CurrentCpuIdOrBsp();
    slot.target_id = target_id;
    slot.aux0 = aux0;
    slot.aux1 = aux1;
    CopyDetector(slot.detector, sizeof(slot.detector), detector);

    __atomic_add_fetch(&g_events_total, 1, __ATOMIC_RELAXED);
}

EreportStats EreportStatsRead()
{
    return EreportStats{
        .events_total = __atomic_load_n(&g_events_total, __ATOMIC_RELAXED),
        .events_dropped = __atomic_load_n(&g_events_dropped, __ATOMIC_RELAXED),
        .diagnoses_total = __atomic_load_n(&g_diagnoses_total, __ATOMIC_RELAXED),
        .suspects_identified = __atomic_load_n(&g_suspects_identified, __ATOMIC_RELAXED),
    };
}

void EreportWalk(u32 max, EreportWalkCb cb, void* cookie)
{
    if (cb == nullptr || max == 0)
    {
        return;
    }

    // Snapshot the head. The slot at index (head-1) is the newest;
    // we walk backwards from there for up to `max` entries or until
    // we run out of valid history (head < ring size means we haven't
    // wrapped yet; only walk what was actually written).
    const u64 head = __atomic_load_n(&g_head, __ATOMIC_ACQUIRE);
    if (head == 0)
    {
        return;
    }

    const u64 available = (head < kEreportRingSize) ? head : kEreportRingSize;
    const u64 to_walk = (max < available) ? max : available;

    for (u64 i = 0; i < to_walk; ++i)
    {
        const u64 slot_idx = (head - 1 - i) % kEreportRingSize;
        cb(g_ring[slot_idx], cookie);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers exposed to the diagnosis engine via diagnose.cpp inclusion.
// Kept here so the counters live in one TU; `diagnose.cpp` declares the
// extern visibility of these helpers.
// ---------------------------------------------------------------------------

void EreportNoteDiagnosisRun()
{
    __atomic_add_fetch(&g_diagnoses_total, 1, __ATOMIC_RELAXED);
}

void EreportNoteSuspectIdentified()
{
    __atomic_add_fetch(&g_suspects_identified, 1, __ATOMIC_RELAXED);
}

} // namespace duetos::diag::fma
