// tests/host/test_text_hash.cpp
//
// Hosted unit test for the kernel `.text` integrity-check
// algorithm in `kernel/diag/runtime_checker.cpp`. Specifically
// proves the gap fix landed alongside the function-branch
// NOP-patch attack in attack_sim.cpp:
//
//   - The original `ComputeTextSpotHash` (FNV-1a over the first
//     and last 4 KiB) is **blind** to a single-byte modification
//     in the middle of the section. Confirmed by patching a
//     middle byte: spot hash unchanged.
//
//   - The new `ComputeTextFullHash` (FNV-1a over the entire
//     section) **detects** the same modification. Confirmed by
//     patching the same middle byte: full hash drifts.
//
//   - Both hashes detect a head-window or tail-window
//     modification, classifying the drift as `SPOT+FULL`.
//
//   - Both hashes return to baseline after the byte is restored.
//
// The check functions in runtime_checker.cpp pull in many kernel
// dependencies (klog, fault_react, arch::SerialWrite, etc.) that
// would not link under a host build. We avoid that by reproducing
// the two hash functions verbatim from runtime_checker.cpp here —
// they're tiny (single-loop FNV-1a, no kernel state) and the
// algorithm is what the test cares about. If the kernel-side
// hash function ever changes, this file must be updated to track
// it; treat that as a feature, not a bug — divergence between
// production and test would silently kill the coverage.

#include "host_test_helper.h"

#include <cstddef>
#include <cstdint>

namespace
{

using u8 = std::uint8_t;
using u64 = std::uint64_t;

// FNV-1a constants — same values as runtime_checker.cpp.
constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
constexpr u64 kFnvPrime = 0x100000001b3ULL;
constexpr u64 kSpotBytes = 4096;

// Mirror of `ComputeTextSpotHash`. Hashes the first and last
// 4 KiB of `[s, e)`; if the section is shorter than 8 KiB, just
// hashes the head once.
u64 ComputeTextSpotHash(const u8* s, const u8* e)
{
    u64 h = kFnvOffset;
    const u64 text_bytes = static_cast<u64>(e - s);
    const u64 head_bytes = (text_bytes < kSpotBytes) ? text_bytes : kSpotBytes;
    for (u64 i = 0; i < head_bytes; ++i)
    {
        h ^= s[i];
        h *= kFnvPrime;
    }
    if (text_bytes > 2 * kSpotBytes)
    {
        for (u64 i = 0; i < kSpotBytes; ++i)
        {
            h ^= e[-static_cast<std::int64_t>(kSpotBytes) + static_cast<std::int64_t>(i)];
            h *= kFnvPrime;
        }
    }
    return h;
}

// Mirror of `ComputeTextFullHash`. Hashes every byte in `[s, e)`.
u64 ComputeTextFullHash(const u8* s, const u8* e)
{
    u64 h = kFnvOffset;
    for (const u8* p = s; p < e; ++p)
    {
        h ^= *p;
        h *= kFnvPrime;
    }
    return h;
}

// Match the production `CheckKernelText` decision: report which
// hash classes are drifting.
enum class DriftClass
{
    None,
    SpotOnly,
    FullOnly,
    SpotAndFull,
};

DriftClass ClassifyDrift(u64 spot_now, u64 spot_baseline, u64 full_now, u64 full_baseline)
{
    const bool spot = (spot_now != spot_baseline);
    const bool full = (full_now != full_baseline);
    if (spot && full)
        return DriftClass::SpotAndFull;
    if (spot)
        return DriftClass::SpotOnly;
    if (full)
        return DriftClass::FullOnly;
    return DriftClass::None;
}

} // namespace

int main()
{
    // Synthetic `.text` buffer: 16 KiB of deterministic content.
    // Big enough that head + tail spot windows (4 KiB each) leave
    // an 8 KiB middle that the spot hash cannot see.
    constexpr std::size_t kTextSize = 16 * 1024;
    static u8 text[kTextSize];
    for (std::size_t i = 0; i < kTextSize; ++i)
        text[i] = static_cast<u8>(i * 31 + 7);

    const u8* const s = text;
    const u8* const e = text + kTextSize;

    // Capture baselines — same step `RuntimeCheckerInit` performs
    // at boot.
    const u64 baseline_spot = ComputeTextSpotHash(s, e);
    const u64 baseline_full = ComputeTextFullHash(s, e);

    // Sanity check: spot and full are different functions, so the
    // baselines should differ on this 16 KiB buffer.
    EXPECT_NE(baseline_spot, baseline_full);

    // ============================================================
    // Case 1: middle-section byte patched.
    //
    // This is the function-branch NOP-patch attack's profile:
    // a single byte written in the middle of `.text`, outside
    // both 4 KiB spot windows. The legacy spot hash MUST be
    // blind; the new full hash MUST detect.
    // ============================================================
    {
        constexpr std::size_t kMidOffset = 8 * 1024; // squarely in the middle
        const u8 saved = text[kMidOffset];
        text[kMidOffset] = static_cast<u8>(saved ^ 0x90);

        const u64 spot_now = ComputeTextSpotHash(s, e);
        const u64 full_now = ComputeTextFullHash(s, e);

        EXPECT_EQ(spot_now, baseline_spot); // spot blind — gap proven
        EXPECT_NE(full_now, baseline_full); // full sees it — gap closed
        EXPECT_EQ(ClassifyDrift(spot_now, baseline_spot, full_now, baseline_full), DriftClass::FullOnly);

        text[kMidOffset] = saved;
        EXPECT_EQ(ComputeTextSpotHash(s, e), baseline_spot);
        EXPECT_EQ(ComputeTextFullHash(s, e), baseline_full);
    }

    // ============================================================
    // Case 2: head-window byte patched.
    //
    // Existing `AttackKernelTextPatch` (kernel/security/
    // attack_sim.cpp) targets `_text_start + 0x40` — squarely
    // inside the head spot window. Both hashes should drift,
    // classifying as `SpotAndFull`.
    // ============================================================
    {
        constexpr std::size_t kHeadOffset = 0x40;
        const u8 saved = text[kHeadOffset];
        text[kHeadOffset] = static_cast<u8>(~saved);

        const u64 spot_now = ComputeTextSpotHash(s, e);
        const u64 full_now = ComputeTextFullHash(s, e);

        EXPECT_NE(spot_now, baseline_spot);
        EXPECT_NE(full_now, baseline_full);
        EXPECT_EQ(ClassifyDrift(spot_now, baseline_spot, full_now, baseline_full), DriftClass::SpotAndFull);

        text[kHeadOffset] = saved;
        EXPECT_EQ(ComputeTextSpotHash(s, e), baseline_spot);
        EXPECT_EQ(ComputeTextFullHash(s, e), baseline_full);
    }

    // ============================================================
    // Case 3: tail-window byte patched. Same SpotAndFull classification.
    // ============================================================
    {
        const std::size_t kTailOffset = kTextSize - 1;
        const u8 saved = text[kTailOffset];
        text[kTailOffset] = static_cast<u8>(~saved);

        const u64 spot_now = ComputeTextSpotHash(s, e);
        const u64 full_now = ComputeTextFullHash(s, e);

        EXPECT_NE(spot_now, baseline_spot);
        EXPECT_NE(full_now, baseline_full);
        EXPECT_EQ(ClassifyDrift(spot_now, baseline_spot, full_now, baseline_full), DriftClass::SpotAndFull);

        text[kTailOffset] = saved;
        EXPECT_EQ(ComputeTextSpotHash(s, e), baseline_spot);
        EXPECT_EQ(ComputeTextFullHash(s, e), baseline_full);
    }

    // ============================================================
    // Case 4: clean state stays clean (no false positives).
    // ============================================================
    EXPECT_EQ(ClassifyDrift(ComputeTextSpotHash(s, e), baseline_spot, ComputeTextFullHash(s, e), baseline_full),
              DriftClass::None);

    return ::duetos_host_test::finish_main(__FILE__);
}
