// tests/host/test_saturating.cpp
//
// Hosted unit tests for kernel/util/saturating.h — the saturating
// integer arithmetic primitives that wiki/security/Linux-CVE-Audit.md
// Classes M (parser size wraps) and BB (general integer overflow on
// size) lean on. Recent kernel changes wired these into the imageview
// width×height×4 decode path; a regression here would silently re-
// introduce the OOB write the imageview commit closed.
//
// The header is mostly template + inline code, so the test can
// instantiate the templates directly. The one out-of-line symbol
// `SatLogClamp` lives in `saturating.cpp` and pulls in serial / klog /
// symbol-table deps that don't fit a host build, so we stub it here —
// the test asserts the algebraic contract, not the log emit.
//
// Contracts pinned:
//   SatAdd:
//     - in-range → ordinary sum
//     - overflow → clamps to type-max
//   SatSub:
//     - in-range → ordinary diff
//     - underflow → clamps to 0 (unsigned)
//   SatMul:
//     - in-range → ordinary product
//     - overflow → clamps to type-max
//     - works on u8 / u16 / u32 / u64
//   Saturating<T> wrapper:
//     - operator++ / -- clamp at the type edges
//     - operator+= / -= / *= go through SatAdd / SatSub / SatMul
//     - implicit conversion to T returns the underlying value
//   SatAtomicAdd:
//     - non-overflowing add commits and returns the new value
//     - overflow clamps to type-max and stores it
//     - at-max + n stays at type-max (no spurious bump)
//
// Note: SatLogClamp is stubbed (sat_log_count tracks how many
// clamps fired). The test relies on that count to verify that the
// clamp PATH was actually exercised (so a future regression that
// silently turned a clamp into a wrap would show up as a "no
// clamp" + "wrong value" double failure).

#include "host_test_helper.h"
#include "util/saturating.h"

#include <atomic>

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using duetos::util::SatAdd;
using duetos::util::SatAtomicAdd;
using duetos::util::SatMul;
using duetos::util::SatSub;
using duetos::util::SatU16;
using duetos::util::SatU32;
using duetos::util::SatU64;
using duetos::util::SatU8;
using duetos::util::Saturating;

// Host-side stub for the diagnostic log emit. The kernel TU links
// against arch::SerialWrite and core::ResolveAddress; the host test
// can't, so we provide a stub that just counts clamp events. Use
// `g_sat_log_count` in assertions that verify the clamp path was
// taken.
static u64 g_sat_log_count = 0;

namespace duetos::util
{
void SatLogClamp(const char* /*tag*/, u64 /*attempted*/, u64 /*clamped*/, void* /*caller_rip*/)
{
    ++g_sat_log_count;
}
} // namespace duetos::util

static void reset_log()
{
    g_sat_log_count = 0;
}

int main()
{
    // ----- SatAdd -----------------------------------------------
    // In-range add: ordinary sum, no clamp log.
    {
        reset_log();
        EXPECT_EQ(SatAdd<u32>(5u, 7u), 12u);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }
    // u32 add overflow: max + 1 clamps to max, log fires.
    {
        reset_log();
        EXPECT_EQ(SatAdd<u32>(0xFFFFFFFFu, 1u), 0xFFFFFFFFu);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u32 add overflow with both operands large: clamps to max.
    {
        reset_log();
        EXPECT_EQ(SatAdd<u32>(0x80000000u, 0x80000000u), 0xFFFFFFFFu);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u64 add overflow: max + 1 clamps to max.
    {
        reset_log();
        EXPECT_EQ(SatAdd<u64>(0xFFFFFFFFFFFFFFFFull, 1ull), 0xFFFFFFFFFFFFFFFFull);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u8 add overflow: 255 + 1 clamps to 255.
    {
        reset_log();
        EXPECT_EQ(SatAdd<u8>(255u, 1u), 255u);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u16 add overflow at 65535 + 1.
    {
        reset_log();
        EXPECT_EQ(SatAdd<u16>(65535u, 1u), 65535u);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }

    // ----- SatSub -----------------------------------------------
    // In-range sub: ordinary diff, no clamp log.
    {
        reset_log();
        EXPECT_EQ(SatSub<u32>(10u, 3u), 7u);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }
    // u32 sub underflow: 0 - 1 clamps to 0, log fires.
    {
        reset_log();
        EXPECT_EQ(SatSub<u32>(0u, 1u), 0u);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u32 sub underflow with smaller minuend: 5 - 100 clamps to 0.
    {
        reset_log();
        EXPECT_EQ(SatSub<u32>(5u, 100u), 0u);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u64 sub underflow.
    {
        reset_log();
        EXPECT_EQ(SatSub<u64>(0ull, 1ull), 0ull);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u8 sub equal: 5 - 5 = 0, no clamp.
    {
        reset_log();
        EXPECT_EQ(SatSub<u8>(5u, 5u), 0u);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }

    // ----- SatMul -----------------------------------------------
    // In-range mul: ordinary product, no clamp.
    {
        reset_log();
        EXPECT_EQ(SatMul<u32>(100u, 200u), 20000u);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }
    // u32 mul overflow at the imageview width×height edge.
    {
        reset_log();
        EXPECT_EQ(SatMul<u32>(0x10000u, 0x10000u), 0xFFFFFFFFu);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u64 mul overflow — the case the imageview commit pins.
    // 2^32 × 2^32 = 2^64 → overflows u64 → clamps to max.
    {
        reset_log();
        EXPECT_EQ(SatMul<u64>(1ull << 32, 1ull << 32), 0xFFFFFFFFFFFFFFFFull);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u64 mul edge: max × 2 → clamps.
    {
        reset_log();
        EXPECT_EQ(SatMul<u64>(0xFFFFFFFFFFFFFFFFull, 2ull), 0xFFFFFFFFFFFFFFFFull);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // u64 mul by 1 — identity, no clamp.
    {
        reset_log();
        EXPECT_EQ(SatMul<u64>(0xFFFFFFFFFFFFFFFFull, 1ull), 0xFFFFFFFFFFFFFFFFull);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }
    // u64 mul by 0 — zero, no clamp.
    {
        reset_log();
        EXPECT_EQ(SatMul<u64>(0xFFFFFFFFFFFFFFFFull, 0ull), 0ull);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }

    // ----- Saturating<T> wrapper --------------------------------
    // Implicit construction + cast back to underlying.
    {
        SatU32 c{42u};
        EXPECT_EQ(static_cast<u32>(c), 42u);
    }
    // operator+= in range.
    {
        reset_log();
        SatU32 c{100u};
        c += 50u;
        EXPECT_EQ(static_cast<u32>(c), 150u);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }
    // operator+= overflow.
    {
        reset_log();
        SatU32 c{0xFFFFFFFEu};
        c += 100u;
        EXPECT_EQ(static_cast<u32>(c), 0xFFFFFFFFu);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // operator-= underflow.
    {
        reset_log();
        SatU16 c{10u};
        c -= 100u;
        EXPECT_EQ(static_cast<u16>(c), 0u);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // operator*= overflow.
    {
        reset_log();
        SatU32 c{0x10000u};
        c *= 0x10000u;
        EXPECT_EQ(static_cast<u32>(c), 0xFFFFFFFFu);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // operator++ at max: pins value, logs clamp.
    {
        reset_log();
        SatU8 c{255u};
        ++c;
        EXPECT_EQ(static_cast<u8>(c), 255u);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // operator++ pre vs post: post returns OLD value, pre returns
    // NEW. Both saturate.
    {
        reset_log();
        SatU8 c{254u};
        const SatU8 prev = c++;
        EXPECT_EQ(static_cast<u8>(prev), 254u);
        EXPECT_EQ(static_cast<u8>(c), 255u);
        EXPECT_EQ(g_sat_log_count, 0ull); // 254→255 doesn't clamp
        c++;
        EXPECT_EQ(static_cast<u8>(c), 255u);
        EXPECT_EQ(g_sat_log_count, 1ull); // 255→255 clamps
    }
    // operator-- at 0: pins value, logs clamp.
    {
        reset_log();
        SatU16 c{0u};
        --c;
        EXPECT_EQ(static_cast<u16>(c), 0u);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // operator-- post returns OLD value.
    {
        reset_log();
        SatU32 c{1u};
        const SatU32 prev = c--;
        EXPECT_EQ(static_cast<u32>(prev), 1u);
        EXPECT_EQ(static_cast<u32>(c), 0u);
    }

    // ----- SatAtomicAdd -----------------------------------------
    // In-range atomic add commits, returns new value.
    {
        reset_log();
        u64 v = 100ull;
        const u64 r = SatAtomicAdd<u64>(&v, 50ull);
        EXPECT_EQ(r, 150ull);
        EXPECT_EQ(v, 150ull);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }
    // Atomic add overflow: clamps to max, store reflects it.
    {
        reset_log();
        u32 v = 0xFFFFFFFEu;
        const u32 r = SatAtomicAdd<u32>(&v, 5u);
        EXPECT_EQ(r, 0xFFFFFFFFu);
        EXPECT_EQ(v, 0xFFFFFFFFu);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // At-max + n: stays at max, logs.
    {
        reset_log();
        u64 v = 0xFFFFFFFFFFFFFFFFull;
        const u64 r = SatAtomicAdd<u64>(&v, 1ull);
        EXPECT_EQ(r, 0xFFFFFFFFFFFFFFFFull);
        EXPECT_EQ(v, 0xFFFFFFFFFFFFFFFFull);
        EXPECT_EQ(g_sat_log_count, 1ull);
    }
    // At-max + 0: no overflow, no clamp.
    {
        reset_log();
        u32 v = 0xFFFFFFFFu;
        const u32 r = SatAtomicAdd<u32>(&v, 0u);
        EXPECT_EQ(r, 0xFFFFFFFFu);
        EXPECT_EQ(v, 0xFFFFFFFFu);
        EXPECT_EQ(g_sat_log_count, 0ull);
    }

    return duetos_host_test::finish_main("test_saturating");
}
