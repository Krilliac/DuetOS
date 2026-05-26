#include "diag/kpath.h"

#include "debug/probes.h"
#include "diag/fix_journal.h"
#include "core/init.h"
#include "log/klog.h"
#include "util/types.h"

/*
 * KPath — implementation.
 *
 * Sections:
 *   .kpath_sites — read-only KPathSite records, one per call site.
 *   .kpath_hits  — mutable u64 counters, parallel-indexed.
 *
 * Linker emits `__kpath_sites_start/_end` and
 * `__kpath_hits_start/_end` (see kernel/arch/x86_64/linker.ld).
 * The macro stamps both records into both sections from the same
 * TU so the two arrays line up by index — but each site ALSO
 * carries an explicit `hits_ptr` so we never rely on the linker
 * to preserve cross-section ordering.
 *
 * Auto-enrolled tables:
 *   g_kpath_syscall_hits[256] — bumped from SyscallDispatch.
 *   g_kpath_vector_hits[256]  — bumped from TrapDispatch.
 *   InitcallRecord::invoke_count — already counted; we just
 *     surface it through the unified iterator.
 *   g_probe_fires[ProbeId]    — via ProbeList(); surfaced as
 *     Probe-category virtual rows.
 *   FixRecord::repeat_count   — via FixJournalSnapshot();
 *     surfaced as Fix-category virtual rows.
 */

extern "C" const ::duetos::diag::KPathSite __kpath_sites_start[];
extern "C" const ::duetos::diag::KPathSite __kpath_sites_end[];
extern "C" ::duetos::u64 __kpath_hits_start[];
extern "C" ::duetos::u64 __kpath_hits_end[];

namespace duetos::diag
{

// Global enable flag — macro fire path short-circuits when zero.
// Default 1 so KPATH() macros fire from the first instruction of
// the kernel (before KPathInit runs we may already have hit a
// few sites — the counters are zero-initialised in BSS so those
// early bumps land correctly without any explicit init).
volatile u8 g_kpath_enabled = 1;

namespace
{

// Auto-enrolled dispatch surfaces.
::duetos::u64 g_kpath_syscall_hits[256] = {};
::duetos::u64 g_kpath_vector_hits[256] = {};

bool g_inited = false;

} // namespace

const char* KPathCatName(KPathCat c)
{
    switch (c)
    {
    case KPathCat::None:
        return "none";
    case KPathCat::Manual:
        return "manual";
    case KPathCat::Syscall:
        return "syscall";
    case KPathCat::Vector:
        return "vector";
    case KPathCat::Initcall:
        return "initcall";
    case KPathCat::Probe:
        return "probe";
    case KPathCat::Fix:
        return "fix";
    case KPathCat::SelfTest:
        return "selftest";
    case KPathCat::Branch:
        return "branch";
    }
    return "?";
}

void KPathInit()
{
    // Idempotent — re-entry from a stray initcall is a no-op
    // rather than a panic. The fire path's first bump may have
    // already landed in BSS-zeroed `.kpath_hits` cells before we
    // get here; that's the intended early-boot semantics.
    if (g_inited)
    {
        return;
    }
    g_inited = true;
    g_kpath_enabled = 1;

    // We intentionally do NOT zero `.kpath_hits` or the
    // auto-enrolled tables — they start zero-initialised in BSS
    // and any pre-init fires are valid recorded paths.

    const ::duetos::u64 site_count = static_cast<::duetos::u64>(__kpath_sites_end - __kpath_sites_start);
    KLOG_INFO_V("diag", "KPathInit: ledger online (sites)", site_count);
}

void KPathSetEnabled(bool on)
{
    g_kpath_enabled = on ? 1u : 0u;
}

bool KPathIsEnabled()
{
    return g_kpath_enabled != 0;
}

void KPathHitSyscall(::duetos::u64 num)
{
    if (g_kpath_enabled == 0)
    {
        return;
    }
    if (num < 256)
    {
        __atomic_add_fetch(&g_kpath_syscall_hits[num], 1ull, __ATOMIC_RELAXED);
    }
}

void KPathHitVector(::duetos::u32 v)
{
    if (g_kpath_enabled == 0)
    {
        return;
    }
    if (v < 256)
    {
        __atomic_add_fetch(&g_kpath_vector_hits[v], 1ull, __ATOMIC_RELAXED);
    }
}

::duetos::u64 KPathSyscallHits(::duetos::u32 num)
{
    return (num < 256) ? __atomic_load_n(&g_kpath_syscall_hits[num], __ATOMIC_RELAXED) : 0ull;
}

::duetos::u64 KPathVectorHits(::duetos::u32 v)
{
    return (v < 256) ? __atomic_load_n(&g_kpath_vector_hits[v], __ATOMIC_RELAXED) : 0ull;
}

::duetos::u64 KPathSiteHits(const KPathSite& s)
{
    if (s.hits_ptr == nullptr)
    {
        return 0;
    }
    return __atomic_load_n(s.hits_ptr, __ATOMIC_RELAXED);
}

KPathVisitStats KPathSnapshotStats()
{
    KPathVisitStats st{};

    // Real .kpath_sites entries — total + how many fired.
    for (const KPathSite* s = __kpath_sites_start; s < __kpath_sites_end; ++s)
    {
        st.sites_total++;
        if (KPathSiteHits(*s) > 0)
        {
            st.sites_visited++;
        }
    }

    // Auto-enrolled syscall + vector tables.
    for (::duetos::u32 i = 0; i < 256; ++i)
    {
        if (KPathSyscallHits(i) > 0)
        {
            st.syscalls_visited++;
        }
        if (KPathVectorHits(i) > 0)
        {
            st.vectors_visited++;
        }
    }

    // Initcalls — invoke_count is bumped by RunPhase already.
    const ::duetos::u32 ic_count = ::duetos::core::InitcallCount();
    for (::duetos::u32 i = 0; i < ic_count; ++i)
    {
        const ::duetos::core::InitcallRecord* r = ::duetos::core::InitcallGet(i);
        if (r != nullptr && r->invoke_count > 0)
        {
            st.initcalls_visited++;
        }
    }

    // Probes — walk the live table.
    ::duetos::debug::ProbeInfo probe_buf[static_cast<::duetos::u64>(::duetos::debug::ProbeId::kCount)] = {};
    const ::duetos::u64 probe_count =
        ::duetos::debug::ProbeList(probe_buf, static_cast<::duetos::u64>(::duetos::debug::ProbeId::kCount));
    for (::duetos::u64 i = 0; i < probe_count; ++i)
    {
        if (probe_buf[i].fire_count > 0)
        {
            st.probes_visited++;
        }
    }

    // Fix-journal — total unique records (any detector).
    const FixJournalStats fjs = FixJournalGetStats();
    st.fix_records = static_cast<::duetos::u32>(fjs.records_unique);

    return st;
}

namespace
{

bool ForEachReal(KPathForEachFn cb, void* ctx)
{
    for (const KPathSite* s = __kpath_sites_start; s < __kpath_sites_end; ++s)
    {
        KPathIterRow row{};
        row.category = static_cast<KPathCat>(s->category);
        row.name = (s->name != nullptr) ? s->name : "?";
        row.file = (s->file != nullptr) ? s->file : "?";
        row.line = s->line;
        row.hits = KPathSiteHits(*s);
        row.syscall_nr = 0xFFFFu;
        row.vector_nr = 0xFFFFu;
        if (!cb(row, ctx))
        {
            return false;
        }
    }
    return true;
}

bool ForEachSyscall(KPathForEachFn cb, void* ctx)
{
    for (::duetos::u32 i = 0; i < 256; ++i)
    {
        const ::duetos::u64 hits = KPathSyscallHits(i);
        if (hits == 0)
        {
            continue;
        }
        KPathIterRow row{};
        row.category = KPathCat::Syscall;
        row.name = "syscall";
        row.file = "kernel/syscall/syscall.cpp";
        row.line = 0;
        row.hits = hits;
        row.syscall_nr = i;
        row.vector_nr = 0xFFFFu;
        if (!cb(row, ctx))
        {
            return false;
        }
    }
    return true;
}

bool ForEachVector(KPathForEachFn cb, void* ctx)
{
    for (::duetos::u32 i = 0; i < 256; ++i)
    {
        const ::duetos::u64 hits = KPathVectorHits(i);
        if (hits == 0)
        {
            continue;
        }
        KPathIterRow row{};
        row.category = KPathCat::Vector;
        row.name = "vector";
        row.file = "kernel/arch/x86_64/traps.cpp";
        row.line = 0;
        row.hits = hits;
        row.syscall_nr = 0xFFFFu;
        row.vector_nr = i;
        if (!cb(row, ctx))
        {
            return false;
        }
    }
    return true;
}

bool ForEachInitcall(KPathForEachFn cb, void* ctx)
{
    const ::duetos::u32 n = ::duetos::core::InitcallCount();
    for (::duetos::u32 i = 0; i < n; ++i)
    {
        const ::duetos::core::InitcallRecord* r = ::duetos::core::InitcallGet(i);
        if (r == nullptr || r->name == nullptr)
        {
            continue;
        }
        KPathIterRow row{};
        row.category = KPathCat::Initcall;
        row.name = r->name;
        row.file = "kernel/core/init.cpp";
        row.line = 0;
        row.hits = r->invoke_count;
        row.syscall_nr = 0xFFFFu;
        row.vector_nr = 0xFFFFu;
        if (!cb(row, ctx))
        {
            return false;
        }
    }
    return true;
}

bool ForEachProbe(KPathForEachFn cb, void* ctx)
{
    ::duetos::debug::ProbeInfo buf[static_cast<::duetos::u64>(::duetos::debug::ProbeId::kCount)] = {};
    const ::duetos::u64 n =
        ::duetos::debug::ProbeList(buf, static_cast<::duetos::u64>(::duetos::debug::ProbeId::kCount));
    for (::duetos::u64 i = 0; i < n; ++i)
    {
        KPathIterRow row{};
        row.category = KPathCat::Probe;
        row.name = (buf[i].name != nullptr) ? buf[i].name : "?";
        row.file = "kernel/debug/probes.cpp";
        row.line = 0;
        row.hits = buf[i].fire_count;
        row.syscall_nr = 0xFFFFu;
        row.vector_nr = 0xFFFFu;
        if (!cb(row, ctx))
        {
            return false;
        }
    }
    return true;
}

bool ForEachFix(KPathForEachFn cb, void* ctx, bool panic_safe)
{
    FixRecord recs[64] = {};
    const ::duetos::u64 want = sizeof(recs) / sizeof(recs[0]);
    const ::duetos::u64 n = panic_safe ? FixJournalSnapshotPanicSafe(recs, want) : FixJournalSnapshot(recs, want);
    for (::duetos::u64 i = 0; i < n; ++i)
    {
        if (recs[i].magic != kFixRecordMagic)
        {
            continue;
        }
        KPathIterRow row{};
        row.category = KPathCat::Fix;
        row.name = recs[i].source_pin;
        row.file = FixDetectorName(static_cast<FixDetector>(recs[i].detector));
        row.line = 0;
        row.hits = recs[i].repeat_count;
        row.syscall_nr = 0xFFFFu;
        row.vector_nr = 0xFFFFu;
        if (!cb(row, ctx))
        {
            return false;
        }
    }
    return true;
}

} // namespace

void KPathForEach(KPathForEachFn cb, void* ctx)
{
    if (cb == nullptr)
    {
        return;
    }
    if (!ForEachReal(cb, ctx))
        return;
    if (!ForEachSyscall(cb, ctx))
        return;
    if (!ForEachVector(cb, ctx))
        return;
    if (!ForEachInitcall(cb, ctx))
        return;
    if (!ForEachProbe(cb, ctx))
        return;
    (void)ForEachFix(cb, ctx, false);
}

void KPathForEachPanicSafe(KPathForEachFn cb, void* ctx)
{
    if (cb == nullptr)
    {
        return;
    }
    if (!ForEachReal(cb, ctx))
        return;
    if (!ForEachSyscall(cb, ctx))
        return;
    if (!ForEachVector(cb, ctx))
        return;
    if (!ForEachInitcall(cb, ctx))
        return;
    if (!ForEachProbe(cb, ctx))
        return;
    (void)ForEachFix(cb, ctx, true);
}

} // namespace duetos::diag
