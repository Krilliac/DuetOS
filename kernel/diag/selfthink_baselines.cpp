#include "diag/selfthink_baselines.h"

#include "debug/probes.h"
#include "log/klog.h"

namespace duetos::diag::selfthink::baselines
{

namespace
{

constexpr u32 kMinSamplesForAnomaly = 8;

// Per-metric ring of samples + head + populated count + cumulative
// anomaly fire count. Lives in .bss; total ≈ 5 metrics × (256 × 8
// + 16) ≈ 10.3 KiB. The ring is intentionally small enough that
// a full-pass mean/variance recompute on every anomaly check is
// cheaper than maintaining incremental sums (Welford runs into
// integer-rounding noise at scale and the overhead is invisible
// against a kselfthink wake budget).
struct MetricRing
{
    u64 samples[kRingSize];
    u32 head;
    u32 populated;
    u64 anomalies_observed;
};

MetricRing g_rings[static_cast<u32>(MetricId::Count)] = {};

bool ValidId(MetricId id)
{
    return static_cast<u32>(id) < static_cast<u32>(MetricId::Count);
}

// Integer square root via Newton's method. The mean magnitudes
// involved (< 2^40) converge in fewer than a dozen iterations;
// bounded loop guard at 32 to be defensive. Returns 0 for 0,
// monotonic for positive inputs.
u64 IntSqrt(u64 n)
{
    if (n == 0)
        return 0;
    u64 x = n;
    // Initial guess: rough upper bound that's safe for any u64.
    u64 r = (n >= (1ULL << 32)) ? (1ULL << 32) : n;
    for (u32 i = 0; i < 32; ++i)
    {
        const u64 next = (r + x / r) / 2;
        if (next >= r)
            break;
        r = next;
    }
    return r;
}

} // namespace

const char* MetricName(MetricId id)
{
    switch (id)
    {
    case MetricId::FreeFrames:
        return "free_frames";
    case MetricId::HeapUsedPct:
        return "heap_used_pct";
    case MetricId::RunnableTasks:
        return "runnable_tasks";
    case MetricId::Count:
        return "?";
    }
    return "?";
}

void Sample(MetricId id, u64 value)
{
    if (!ValidId(id))
        return;
    MetricRing& r = g_rings[static_cast<u32>(id)];
    r.samples[r.head % kRingSize] = value;
    r.head++;
    if (r.populated < kRingSize)
        ++r.populated;
}

Stats Read(MetricId id)
{
    Stats s = {};
    if (!ValidId(id))
        return s;
    const MetricRing& r = g_rings[static_cast<u32>(id)];
    s.count = r.populated;
    s.anomalies_observed = r.anomalies_observed;
    if (r.populated == 0)
        return s;

    // Most-recent sample lives at slot (head - 1) mod ring.
    const u32 last_idx = (r.head + kRingSize - 1) % kRingSize;
    s.last = r.samples[last_idx];

    // Walk the populated tail of the ring computing sum, then
    // pass two computes sum-of-squared-deviations. Two passes are
    // simpler and immune to the integer-overflow trap that a
    // single-pass sum-of-squares hits at scale.
    u64 sum = 0;
    for (u32 i = 0; i < r.populated; ++i)
        sum += r.samples[i];
    s.mean = sum / r.populated;

    if (r.populated >= 2)
    {
        u64 ss = 0;
        for (u32 i = 0; i < r.populated; ++i)
        {
            const u64 v = r.samples[i];
            const u64 d = (v >= s.mean) ? (v - s.mean) : (s.mean - v);
            ss += d * d;
        }
        s.variance = ss / (r.populated - 1);
        s.stddev = IntSqrt(s.variance);
    }
    return s;
}

bool IsAnomaly(MetricId id, u64 value, u32 k_factor)
{
    if (!ValidId(id))
        return false;
    const Stats s = Read(id);
    if (s.count < kMinSamplesForAnomaly)
        return false;

    const u64 d = (value >= s.mean) ? (value - s.mean) : (s.mean - value);
    const u64 bound = static_cast<u64>(k_factor) * s.stddev;

    // Below the noise floor: stddev underflowed to 0 because the
    // window contains identical samples. A non-zero deviation
    // from a zero-stddev mean is itself anomalous — the metric
    // moved when its history says it shouldn't have.
    if (s.stddev == 0)
        return d != 0;

    return d > bound;
}

bool IsAnomaly(MetricId id, u64 value)
{
    return IsAnomaly(id, value, kDefaultK);
}

void RecordAnomaly(MetricId id)
{
    if (!ValidId(id))
        return;
    g_rings[static_cast<u32>(id)].anomalies_observed++;
}

void SelfTest()
{
    using duetos::core::Log;
    using duetos::core::LogLevel;
    using duetos::core::LogWithValue;

    // Use FreeFrames as the test channel. Existing samples (if
    // kselfthink has already begun feeding it) are preserved —
    // the test injects on top and recomputes; the trailing
    // operator output sees the appended values normally.
    constexpr MetricId test_id = MetricId::FreeFrames;

    // Push 16 samples clustered tightly around 1000, then
    // verify 1001 is in-window and 5000 is flagged.
    const u32 prev_pop = g_rings[static_cast<u32>(test_id)].populated;
    for (u32 i = 0; i < 16; ++i)
        Sample(test_id, 1000 + (i % 3));

    const Stats s_after_inliers = Read(test_id);
    if (s_after_inliers.count < kMinSamplesForAnomaly)
    {
        Log(LogLevel::Error, "diag/selfthink-baselines", "selftest: insufficient samples after inject");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 1);
        return;
    }

    // A near-mean value must NOT flag.
    if (IsAnomaly(test_id, s_after_inliers.mean, kDefaultK))
    {
        LogWithValue(LogLevel::Error, "diag/selfthink-baselines", "selftest: mean flagged anomaly mean",
                     s_after_inliers.mean);
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 2);
        return;
    }

    // A far-out value MUST flag — but only if there's enough
    // history to support a confident call AND the prior boot's
    // populated samples haven't already produced a wide stddev
    // that absorbs 5000 as a regular reading. Skip the assertion
    // when the latter is true (selftest is observational under
    // ambient noise).
    if (prev_pop == 0)
    {
        if (!IsAnomaly(test_id, 5000, kDefaultK))
        {
            Log(LogLevel::Error, "diag/selfthink-baselines", "selftest: outlier 5000 not flagged on clean ring");
            ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest),
                                       3);
            return;
        }
    }

    // IntSqrt sanity: small known values.
    if (IntSqrt(0) != 0 || IntSqrt(1) != 1 || IntSqrt(4) != 2 || IntSqrt(100) != 10 || IntSqrt(10000) != 100)
    {
        Log(LogLevel::Error, "diag/selfthink-baselines", "selftest: IntSqrt mismatch");
        ::duetos::debug::ProbeFire(::duetos::debug::ProbeId::kBootSelftestFail, reinterpret_cast<u64>(&SelfTest), 4);
        return;
    }

    LogWithValue(LogLevel::Info, "diag/selfthink-baselines", "selftest pass populated", s_after_inliers.count);
}

} // namespace duetos::diag::selfthink::baselines
