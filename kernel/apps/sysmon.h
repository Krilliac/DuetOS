#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS System Monitor — v0.
 *
 * Rolling-window readout of the things About shows as a snapshot:
 * kernel-heap usage, free-run / fragmentation, alive window count,
 * uptime. The point is the *time series* — About answers "what is
 * the heap right now"; Sysmon answers "is the heap leaking" because
 * the operator can watch the trace shift over the last ~64 samples.
 *
 * v0 surface:
 *   - Header line: uptime + alive windows + heap pool
 *   - Two stacked sparkline panels:
 *       1. Heap-used (% of pool, 0..100)
 *       2. Heap-fragmentation proxy (free_chunk_count / 32 clamped)
 *   - Footer hint: F5 force-refresh, C clear ring
 *
 * Why two panels — heap-used + fragmentation are the two failure
 * modes a long-running kernel cares about; tying them to the same
 * x-axis lets an operator correlate "alloc storm" against "heap
 * fragments getting shorter".
 *
 * Storage: a fixed-size ring of `kSysmonRingDepth` samples; the
 * ui-ticker thread writes one sample per 1 Hz tick and the draw
 * path reads the ring. No per-sample timestamp — samples are
 * uniform 1 Hz so the ring index IS the time axis.
 *
 * Context: kernel. Sample-collection is wired to the existing
 * ui-ticker (see `core/main.cpp`); DrawFn runs under the
 * compositor lock from WindowDrawAllOrdered.
 */

namespace duetos::apps::sysmon
{

/// How many samples the rolling ring retains. 64 is wide enough
/// to see "the last minute" at the 1 Hz sample rate, narrow enough
/// to fit the typical 360 px content area at 4 px per sample.
inline constexpr duetos::u32 kSysmonRingDepth = 64;

/// Install Sysmon state on `handle`. Registers the content-draw
/// + key handlers; no widgets, no scrollbar.
void SysmonInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the Sysmon window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle SysmonWindow();

/// Sample the live system state and append to the ring. Called
/// by the ui-ticker once per second; safe to call more often
/// (each call simply pushes a new sample). No-op if Init hasn't
/// run yet.
void SysmonTick();

/// Keyboard handler. F5 forces an immediate sample push (useful
/// when an operator wants to see a delta after a manual stress
/// step); 'C' / 'c' clears the ring back to the empty state.
/// Returns true iff consumed.
bool SysmonFeedChar(char c);

/// Boot-time self-test. Round-trips ring-push / ring-read /
/// ring-clear with a synthetic sample sequence and asserts
/// monotone newest-first order. Pure compute; runs unconditionally.
void SysmonSelfTest();

} // namespace duetos::apps::sysmon
