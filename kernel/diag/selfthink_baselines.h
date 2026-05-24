#pragma once

#include "util/types.h"

/*
 * DuetOS — rolling per-metric baselines for the selfthink loop.
 *
 * The runtime_checker fires invariant tests with hard-coded
 * thresholds (CR0.WP cleared, heap pool mismatch, MSR
 * mutation). That catches binary corruption and "should never
 * happen" states cleanly, but it can't see workload-relative
 * drift — a free-frame count of 5000 might be fine on one
 * workload and an emergency on another. This module adds the
 * second leg: a 256-sample rolling history per tracked metric,
 * mean + sample standard deviation computed on demand, and an
 * `BaselineAnomaly(metric, value)` predicate that returns true
 * when `value` deviates more than `k * stddev` from `mean`
 * (k = 3 by default).
 *
 * Five metrics are tracked initially. Each is fed once per
 * kselfthink tick (~1 s); the per-tick cost is one add into the
 * ring + one head bump. Anomaly detection is O(N) over the
 * 256-sample ring on demand — sub-microsecond on a modern x86.
 *
 * Anomalies append to the selfthink causal chain as
 * `CausalKind::Anomaly` entries so an operator sees the metric
 * id, the offending value, and the deviation score in the same
 * `selfthink causality` output that lists probe fires and
 * autonomic actions.
 *
 * Integer math throughout — the kernel has no FP unit on by
 * default in the trap path, and the magnitudes involved (free
 * frames < 2^20, syscall counts < 2^24) fit comfortably with
 * the 256-sample window.
 *
 * Context: kernel. Sample + read are safe from any context.
 */

namespace duetos::diag::selfthink::baselines
{

/// Number of samples kept per metric. 256 fits cleanly in cache,
/// gives enough history to compute a meaningful stddev for slow
/// metrics, and bounds the on-demand recompute cost.
inline constexpr u32 kRingSize = 256;

/// Anomaly detection k — value flags if |value - mean| > k * stddev.
/// 3 is the classic "three-sigma" rule of thumb; configurable so a
/// future operator-facing knob can tighten it for a stricter watch.
inline constexpr u32 kDefaultK = 3;

/// Metric identifiers. Add one row here + one case in the metric-
/// name switch in the .cpp + one caller in selfthink.cpp that
/// drives the sample.
enum class MetricId : u8
{
    FreeFrames = 0,    // mm::FreeFramesCount()
    HeapUsedPct = 1,   // ResmonSnapshot::heap_used_pct
    RunnableTasks = 2, // SchedStats::tasks_live
    // Future metric slots — uncomment + wire in selfthink.cpp's
    // kselfthink loop once the kernel exposes a syscall-total /
    // total-IRQ accessor. The classifier and ring infrastructure
    // are metric-agnostic; only the enum + the sampler add code.
    //   SyscallRate, IrqRate
    Count,
};

const char* MetricName(MetricId id);

/// Stats snapshot for one metric.
struct Stats
{
    u32 count;              // populated samples in the ring (capped at kRingSize)
    u64 last;               // most-recent sample
    u64 mean;               // arithmetic mean over populated samples
    u64 variance;           // sample variance (M2 / (count - 1))
    u64 stddev;             // integer sqrt of variance
    u64 anomalies_observed; // cumulative anomaly fires for this metric
};

/// Append a new sample. Wrap-safe ring; no allocation.
void Sample(MetricId id, u64 value);

/// True if `value` is more than `k_factor * stddev` away from the
/// metric's current mean. Recomputes mean/variance fresh from the
/// ring (one walk). Returns false if fewer than 8 samples are
/// populated (insufficient history to call anomaly).
bool IsAnomaly(MetricId id, u64 value, u32 k_factor);

/// Convenience wrapper using kDefaultK.
bool IsAnomaly(MetricId id, u64 value);

/// Increment the per-metric anomaly counter. Called by selfthink
/// after a positive `IsAnomaly` so the stats accumulate visibly.
void RecordAnomaly(MetricId id);

/// Read the current stats snapshot. Recomputes mean/variance/stddev
/// on demand (cheap — single 256-element pass). Safe from any
/// context.
Stats Read(MetricId id);

/// Boot self-test. Feeds a known distribution + outliers and
/// asserts the classifier flags exactly the outliers. Emits
/// `[selfthink-baselines] selftest pass`.
void SelfTest();

} // namespace duetos::diag::selfthink::baselines
