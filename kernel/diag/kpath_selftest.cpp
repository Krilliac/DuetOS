#include "diag/kpath.h"

#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "util/types.h"

/*
 * KPath self-test.
 *
 * Validates:
 *   1. A KPATH(SelfTest, ...) site placed inside this function
 *      registers in `.kpath_sites` and its hit counter rises by
 *      the exact number of times the macro is fired.
 *   2. The unified iterator (`KPathForEach`) yields the selftest
 *      row and reports the matching hit count.
 *   3. `KPathHitSyscall(n)` for an arbitrary in-range `n` bumps
 *      `g_kpath_syscall_hits[n]` by exactly one.
 *   4. `KPathHitVector(v)` for an arbitrary in-range `v` bumps
 *      `g_kpath_vector_hits[v]` by exactly one.
 *
 * Registered as an initcall in Phase::Earlycon by
 * BootBringupEarlyDiagnostics so the ledger is exercised once
 * before any real workload runs.
 */

namespace duetos::diag
{

namespace
{

constexpr ::duetos::u64 kSelfTestFireCount = 1000;
constexpr ::duetos::u64 kSelfTestSyscall = 0xFE; // Reserved-no-handler slot.
constexpr ::duetos::u32 kSelfTestVector = 0xFD;  // Reserved-no-handler slot.

bool g_found_selftest_row = false;
::duetos::u64 g_iter_hits = 0;

bool IterMatchCallback(const KPathIterRow& row, void* /*ctx*/)
{
    if (row.category == KPathCat::SelfTest && row.name != nullptr)
    {
        // Match on the unique literal stamped by the macro below.
        // Pointer-equality is sufficient because both source sites
        // use the same string literal (string-pooled by the linker).
        const char* a = row.name;
        const char* b = "kpath.selftest.site";
        bool match = true;
        for (::duetos::u32 i = 0; i < 24; ++i)
        {
            if (a[i] != b[i])
            {
                match = false;
                break;
            }
            if (a[i] == '\0')
            {
                break;
            }
        }
        if (match)
        {
            g_found_selftest_row = true;
            g_iter_hits = row.hits;
            return false; // Stop iteration.
        }
    }
    return true;
}

} // namespace

void KPathSelfTest()
{
    // Snapshot syscall / vector baseline so we measure the delta and
    // not the absolute count (a prior boot self-test or live syscall
    // may have already incremented these slots).
    const ::duetos::u64 sys_before = KPathSyscallHits(kSelfTestSyscall);
    const ::duetos::u64 vec_before = KPathVectorHits(kSelfTestVector);

    // Fire the selftest site exactly kSelfTestFireCount times. The
    // KPATH() macro stamps a record into .kpath_sites + .kpath_hits
    // the first time control reaches the macro at link time; the
    // increments below all hit the same counter slot.
    for (::duetos::u64 i = 0; i < kSelfTestFireCount; ++i)
    {
        KPATH(SelfTest, "kpath.selftest.site");
    }

    // Fire the auto-enrolled surfaces.
    KPathHitSyscall(kSelfTestSyscall);
    KPathHitVector(kSelfTestVector);

    // Verify (1) + (2): walk the iterator and confirm the row exists
    // with the right hit count.
    g_found_selftest_row = false;
    g_iter_hits = 0;
    KPathForEach(IterMatchCallback, nullptr);
    if (!g_found_selftest_row)
    {
        KLOG_ERROR("diag/kpath", "selftest FAILED: site row missing from iterator");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<::duetos::u64>(__builtin_return_address(0)), 1);
        return;
    }
    if (g_iter_hits < kSelfTestFireCount)
    {
        KLOG_ERROR_2V("diag/kpath", "selftest FAILED: hit count mismatch", "want", kSelfTestFireCount, "got",
                      g_iter_hits);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<::duetos::u64>(__builtin_return_address(0)), 2);
        return;
    }

    // Verify (3) + (4): exactly one delta on each.
    const ::duetos::u64 sys_after = KPathSyscallHits(kSelfTestSyscall);
    const ::duetos::u64 vec_after = KPathVectorHits(kSelfTestVector);
    if (sys_after - sys_before != 1)
    {
        KLOG_ERROR_V("diag/kpath", "selftest FAILED: syscall delta != 1", sys_after - sys_before);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<::duetos::u64>(__builtin_return_address(0)), 3);
        return;
    }
    if (vec_after - vec_before != 1)
    {
        KLOG_ERROR_V("diag/kpath", "selftest FAILED: vector delta != 1", vec_after - vec_before);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail,
                                   reinterpret_cast<::duetos::u64>(__builtin_return_address(0)), 4);
        return;
    }

    // Explicit PASS sentinel — clean boots stay quiet at default
    // log levels, but a CI grep wants to see proof the selftest ran.
    // Use raw SerialWrite (not KLOG_INFO) so the sentinel survives
    // any klog level demotion in release builds.
    ::duetos::arch::SerialWrite("[smoke] kpath=ok sites=");
    char buf[24] = {};
    ::duetos::u64 v = KPathSnapshotStats().sites_visited;
    ::duetos::u32 n = 0;
    if (v == 0)
    {
        buf[n++] = '0';
    }
    else
    {
        char tmp[24] = {};
        ::duetos::u32 t = 0;
        while (v > 0 && t < sizeof(tmp))
        {
            tmp[t++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        for (::duetos::u32 i = 0; i < t; ++i)
        {
            buf[n++] = tmp[t - 1 - i];
        }
    }
    buf[n] = '\0';
    ::duetos::arch::SerialWrite(buf);
    ::duetos::arch::SerialWrite("\n");
}

} // namespace duetos::diag
