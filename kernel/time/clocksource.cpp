/*
 * DuetOS — clocksource registry, v0 (plan A2).
 *
 * See `clocksource.h` for the public contract. This TU owns the
 * fixed-size registry, the best-rating selector, and the boot
 * self-test.
 */

#include "time/clocksource.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sync/seqlock.h"
#include "util/result.h"
#include "util/string.h"
#include "util/types.h"

namespace duetos::time
{

namespace
{

const Clocksource* g_registry[kMaxClocksources] = {};
u32 g_registry_count = 0;
// `g_current` is a single 8-byte pointer load — atomic on x86 —
// but a SeqLock is added (plan B1-followup) so a future clock-
// source hot-swap path can publish a NEW pointer + auxiliary
// state (e.g. invariant-TSC scaling factors that haven't been
// stamped into the source struct itself) under one writer
// guard. Today only `ClocksourceRefreshCurrent` writes; readers
// can grab a coherent (pointer, scale) pair through the seqlock
// retry loop the day calibration becomes a hot path.
const Clocksource* g_current = nullptr;
sync::SeqLock g_current_lock = {};

using duetos::core::StrEqual;

[[noreturn]] void PanicCs(const char* what)
{
    core::Panic("time/clocksource", what);
}

} // namespace

::duetos::core::Result<void> ClocksourceRegister(const Clocksource* cs)
{
    if (cs == nullptr || cs->name == nullptr || cs->read_ns == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    if (g_registry_count >= kMaxClocksources)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    g_registry[g_registry_count++] = cs;
    return {};
}

u32 ClocksourceCount()
{
    return g_registry_count;
}

const Clocksource* ClocksourceGet(u32 index)
{
    if (index >= g_registry_count)
    {
        return nullptr;
    }
    return g_registry[index];
}

const Clocksource* ClocksourceFind(const char* name)
{
    for (u32 i = 0; i < g_registry_count; ++i)
    {
        if (StrEqual(g_registry[i]->name, name))
        {
            return g_registry[i];
        }
    }
    return nullptr;
}

const Clocksource* ClocksourceSelectBest()
{
    const Clocksource* best = nullptr;
    for (u32 i = 0; i < g_registry_count; ++i)
    {
        const Clocksource* cs = g_registry[i];
        if (!cs->monotonic)
        {
            continue;
        }
        if (best == nullptr || cs->rating > best->rating)
        {
            best = cs;
        }
    }
    return best;
}

const Clocksource* ClocksourceCurrent()
{
    // Seqlock-coherent read. v0 the clocksource pointer is the
    // only protected field, so a torn read can only happen if a
    // writer is mid-Refresh — the loop converges in O(1) for the
    // single-CPU boot case.
    const Clocksource* snap;
    u32 seq;
    do
    {
        seq = sync::SeqLockBeginRead(g_current_lock);
        snap = g_current;
    } while (!sync::SeqLockEndRead(g_current_lock, seq));
    return snap;
}

void ClocksourceRefreshCurrent()
{
    sync::SeqLockWriteGuard g(g_current_lock);
    g_current = ClocksourceSelectBest();
}

namespace
{

// Self-test scratch state. The two stub providers are file-static
// so their function pointers stay valid while the registry holds
// references. The counter pretends to advance one tick per call so
// `read_ns` returns a non-trivial sequence.
u64 g_st_mono_counter = 0;
u64 g_st_nonmono_counter = 0;

u64 StMonoReadNs()
{
    return ++g_st_mono_counter * 10;
}

u64 StMonoResolutionNs()
{
    return 10;
}

u64 StNonmonoReadNs()
{
    return ++g_st_nonmono_counter;
}

u64 StNonmonoResolutionNs()
{
    return 1;
}

// Ratings are deliberately well above any real clocksource (HPET=250,
// invariant TSC=300). The self-test runs after timekeeper registration,
// so any rating that wouldn't outrank both HPET and TSC would let
// SelectBest pick the real provider over the stub and trip the
// "SelectBest did not pick the monotonic provider" assertion below.
constinit Clocksource g_st_mono = {"selftest-mono", StMonoReadNs, StMonoResolutionNs, true, 1000};
constinit Clocksource g_st_nonmono = {"selftest-nonmono", StNonmonoReadNs, StNonmonoResolutionNs, false, 2000};

} // namespace

void ClocksourceSelfTest()
{
    arch::SerialWrite("[time] clocksource self-test: register / find / select-best\n");

    const u32 baseline_count = g_registry_count;

    if (ClocksourceRegister(&g_st_mono).has_value() == false)
    {
        PanicCs("Register monotonic provider failed");
    }
    if (ClocksourceRegister(&g_st_nonmono).has_value() == false)
    {
        PanicCs("Register non-monotonic provider failed");
    }
    if (g_registry_count != baseline_count + 2)
    {
        PanicCs("Registry count drifted");
    }

    // Bad-argument paths.
    if (ClocksourceRegister(nullptr).has_value())
    {
        PanicCs("Register accepted nullptr");
    }
    Clocksource bad{};
    bad.name = nullptr;
    bad.read_ns = StMonoReadNs;
    if (ClocksourceRegister(&bad).has_value())
    {
        PanicCs("Register accepted null name");
    }
    bad.name = "x";
    bad.read_ns = nullptr;
    if (ClocksourceRegister(&bad).has_value())
    {
        PanicCs("Register accepted null read_ns");
    }

    // Find by name.
    if (ClocksourceFind("selftest-mono") != &g_st_mono)
    {
        PanicCs("Find by name (mono) failed");
    }
    if (ClocksourceFind("selftest-nonmono") != &g_st_nonmono)
    {
        PanicCs("Find by name (nonmono) failed");
    }
    if (ClocksourceFind("does-not-exist") != nullptr)
    {
        PanicCs("Find returned non-null for missing name");
    }

    // SelectBest must skip the higher-rated non-monotonic in
    // favour of the lower-rated monotonic.
    const Clocksource* best = ClocksourceSelectBest();
    if (best != &g_st_mono)
    {
        PanicCs("SelectBest did not pick the monotonic provider");
    }

    // read_ns advances strictly.
    const u64 t0 = best->read_ns();
    const u64 t1 = best->read_ns();
    if (t1 <= t0)
    {
        PanicCs("Monotonic read_ns did not advance");
    }
    if (best->resolution_ns() != 10)
    {
        PanicCs("Resolution accessor returned wrong value");
    }

    arch::SerialWrite("[time] clocksource self-test OK (registry, find, select-best verified).\n");
}

} // namespace duetos::time
