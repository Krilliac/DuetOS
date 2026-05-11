// tests/host/test_nospec.cpp
//
// Hosted unit tests for kernel/util/nospec.h — the two
// CVE-audit primitives:
//
//   - util::MaskedIndex(idx, bound)   — Spectre v1 (bounds-check
//     bypass) mitigation. Returns idx when idx < bound, 0 otherwise,
//     computed without a data-dependent branch the speculator can
//     mispredict.
//
//   - util::RefcountIncSaturating(&n) — saturating refcount
//     increment that stops at UINT32_MAX / UINT64_MAX. Used to
//     prevent the CVE-2016-0728-class overflow-to-UAF pattern.
//
// Both are header-only and freestanding-clean, so this test
// instantiates them directly from the kernel header — no kernel
// TU link required. The contract guarantees these tests pin:
//
//   MaskedIndex:
//     - idx <  bound  → returns idx
//     - idx == bound  → returns 0
//     - idx >  bound  → returns 0
//     - bound == 0    → always returns 0 (no UB on the subtract)
//     - branchless    → not directly observable from C++, but a
//                       failure of the (idx, bound) → expected
//                       contract is automatically a failure of
//                       the branchless property.
//
//   RefcountIncSaturating:
//     - n < ceiling  → increments, returns true
//     - n == ceiling → leaves at ceiling, returns false
//     - works at both 32 and 64 bit widths.
//
// Regression net for the Class N follow-up slice that applied
// MaskedIndex across every audited Win32/Linux dispatch site. If
// a future refactor of nospec.h changes the mask formula or the
// saturation ceiling, this test catches it before the kernel
// build hides the bug under a layer of correctly-bounded but
// speculatively-leaky array loads.

#include "host_test_helper.h"
#include "util/nospec.h"

using duetos::u32;
using duetos::u64;
using duetos::util::MaskedIndex;
using duetos::util::MaskedIndex32;
using duetos::util::RefcountIncSaturating;

int main()
{
    // MaskedIndex(u64) — happy path: in-range index returns itself.
    {
        EXPECT_EQ(MaskedIndex(0u, 16u), 0u);
        EXPECT_EQ(MaskedIndex(1u, 16u), 1u);
        EXPECT_EQ(MaskedIndex(15u, 16u), 15u);
    }

    // MaskedIndex(u64) — boundary: idx == bound is out-of-range and
    // must return 0 even though the architectural check elsewhere
    // would have already returned -EINVAL. The mask is a
    // defence-in-depth second gate; both must agree on the
    // "blocked" verdict.
    {
        EXPECT_EQ(MaskedIndex(16u, 16u), 0u);
    }

    // MaskedIndex(u64) — out-of-range index must zero out.
    {
        EXPECT_EQ(MaskedIndex(17u, 16u), 0u);
        EXPECT_EQ(MaskedIndex(1024u, 16u), 0u);
        EXPECT_EQ(MaskedIndex(static_cast<u64>(-1), 16u), 0u);
    }

    // MaskedIndex(u64) — bound = 0 corner case. idx - 0 = idx, sign
    // bit zero (positive), so mask = 0. Result must be 0 for any
    // idx. Important: kernel callers should never actually pass
    // bound = 0, but the mask must not UB on the subtract.
    {
        EXPECT_EQ(MaskedIndex(0u, 0u), 0u);
        EXPECT_EQ(MaskedIndex(1u, 0u), 0u);
        EXPECT_EQ(MaskedIndex(static_cast<u64>(-1), 0u), 0u);
    }

    // MaskedIndex(u64) — large 64-bit bounds still work. The
    // sign-bit-replication trick relies on the subtract wrapping
    // into the top half of u64 only when idx < bound; verify with
    // a deliberately-large bound.
    {
        constexpr u64 kHuge = 1ULL << 32;
        EXPECT_EQ(MaskedIndex(0u, kHuge), 0u);
        EXPECT_EQ(MaskedIndex(kHuge - 1, kHuge), kHuge - 1);
        EXPECT_EQ(MaskedIndex(kHuge, kHuge), 0u);
        EXPECT_EQ(MaskedIndex(kHuge + 1, kHuge), 0u);
    }

    // MaskedIndex32(u32) — same contract, narrow type. Most kernel
    // callers use the 32-bit form for handle-table dispatch where
    // the capacity fits in a u32.
    {
        EXPECT_EQ(MaskedIndex32(0u, 64u), 0u);
        EXPECT_EQ(MaskedIndex32(63u, 64u), 63u);
        EXPECT_EQ(MaskedIndex32(64u, 64u), 0u);
        EXPECT_EQ(MaskedIndex32(65u, 64u), 0u);
        EXPECT_EQ(MaskedIndex32(static_cast<u32>(-1), 64u), 0u);
    }

    // MaskedIndex32(u32) — bound covers near-full u32 range. Sign
    // bit on i32 is bit 31; verify the formula doesn't accidentally
    // pull a 64-bit-only shift trick that would break here.
    {
        constexpr u32 kNearMax = 0x7FFFFFFFu;
        EXPECT_EQ(MaskedIndex32(0u, kNearMax), 0u);
        EXPECT_EQ(MaskedIndex32(kNearMax - 1, kNearMax), kNearMax - 1);
        EXPECT_EQ(MaskedIndex32(kNearMax, kNearMax), 0u);
        EXPECT_EQ(MaskedIndex32(static_cast<u32>(-1), kNearMax), 0u);
    }

    // RefcountIncSaturating(u32*) — happy path increments.
    {
        u32 n = 0;
        EXPECT_TRUE(RefcountIncSaturating(&n));
        EXPECT_EQ(n, 1u);
        EXPECT_TRUE(RefcountIncSaturating(&n));
        EXPECT_EQ(n, 2u);
    }

    // RefcountIncSaturating(u32*) — saturates at UINT32_MAX. The
    // contract: at the ceiling, return false and DO NOT mutate.
    {
        u32 n = 0xFFFFFFFEu;
        EXPECT_TRUE(RefcountIncSaturating(&n));
        EXPECT_EQ(n, 0xFFFFFFFFu);
        EXPECT_FALSE(RefcountIncSaturating(&n));
        EXPECT_EQ(n, 0xFFFFFFFFu); // unchanged after refusal
        EXPECT_FALSE(RefcountIncSaturating(&n));
        EXPECT_EQ(n, 0xFFFFFFFFu); // still unchanged after second refusal
    }

    // RefcountIncSaturating(u64*) — same contract on the 64-bit
    // overload. The kobject refcount path uses u32 today but the
    // helper exists in both widths in case a wider refcount class
    // lands.
    {
        u64 n = 0;
        EXPECT_TRUE(RefcountIncSaturating(&n));
        EXPECT_EQ(n, 1ull);
    }

    {
        u64 n = 0xFFFFFFFFFFFFFFFEull;
        EXPECT_TRUE(RefcountIncSaturating(&n));
        EXPECT_EQ(n, 0xFFFFFFFFFFFFFFFFull);
        EXPECT_FALSE(RefcountIncSaturating(&n));
        EXPECT_EQ(n, 0xFFFFFFFFFFFFFFFFull); // unchanged at ceiling
    }

    return duetos_host_test::finish_main("test_nospec");
}
