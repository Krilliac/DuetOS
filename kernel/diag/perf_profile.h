#pragma once

#include "util/types.h"

/*
 * DuetOS — PMU sample profiler, v0 scaffolding (plan D3).
 *
 * WHAT
 *   A "perf-record-equivalent" sample profiler. The PMU
 *   counter (the same one the NMI watchdog uses) overflows
 *   every N unhalted-core-cycles; on overflow, the NMI handler
 *   captures the interrupted RIP into a fixed-size ring. An
 *   operator dumps the ring after a workload has run; the
 *   embedded symbol table resolves each RIP to a function
 *   name + offset. The dump is the "where is the kernel
 *   spending its time" answer.
 *
 * SCOPE FOR v0
 *   - Sample storage + dump-walker. Single global ring,
 *     per-CPU upgrade lands with B2 SMP.
 *   - The actual NMI-driven sampling is NOT wired in this
 *     slice — that requires changing the NMI watchdog's
 *     overflow-handling to optionally feed samples instead
 *     of (or in addition to) the pet-counter check, plus a
 *     way to reload the counter from inside the NMI without
 *     racing the watchdog's threshold. Tracked as
 *     D3-followup.
 *   - The shell-side `perf dump` command lands when D3 itself
 *     is wired live; the API + storage exist now so the day a
 *     sample lands the dump path already works.
 *
 * THE RING
 *   Records are 16-byte (rip + tick). 4096 entries × 16 B =
 *   64 KiB BSS. Append is lockless atomic-RMW on the head
 *   index, same shape as `event_trace`.
 */

namespace duetos::diag
{

inline constexpr u32 kPerfRingCapacity = 4096;

struct PerfSample
{
    u64 rip;  ///< Interrupted instruction pointer.
    u64 tick; ///< `time::TickCount()` at the moment of capture.
};

/// Append one sample. Lockless atomic-RMW; safe from NMI / IRQ
/// / task context. Wraps on overflow (oldest sample evicted).
/// Designed to be cheap enough to call from inside the PMU NMI
/// handler — single fetch_add + 2 stores.
void PerfRecord(u64 rip);

/// Total samples ever captured.
u64 PerfTotalSamples();

/// Number of samples currently observable in the ring (capped
/// at `kPerfRingCapacity`).
u32 PerfLiveCount();

/// Walk the ring oldest-first. Same snapshot-and-walk shape as
/// `EventTraceSnapshot`: returns the count actually copied;
/// races with concurrent `PerfRecord` may produce slightly
/// out-of-order samples.
u32 PerfSnapshot(PerfSample* out, u32 out_capacity);

/// Boot-time self-test. Synthesises a few samples, asserts
/// counters advance, snapshots the ring, verifies the
/// recorded RIPs come back in order. Panics on mismatch.
void PerfProfileSelfTest();

} // namespace duetos::diag
