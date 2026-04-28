#pragma once

#include "util/types.h"

/*
 * DuetOS — dynamic event tracer, v0 (plan D2).
 *
 * WHAT
 *   A lockless single-writer-per-CPU ring of fixed-size trace
 *   events. Used as the "perf-record-equivalent" lightweight
 *   tracer: instrumentation points anywhere in the kernel call
 *   `EventTrace(kind, a, b)`, the call appends a record to the
 *   current CPU's ring with a `time::TickCount()` timestamp, and
 *   the operator dumps the buffer through a shell command after
 *   reproducing whatever scenario they want to inspect.
 *
 * WHY THIS, NOT A FULL FTRACE
 *   Linux's ftrace is ~5 KLOC of dynamic-instrumentation
 *   machinery (recordmcount, function tracing, dynamic patching,
 *   per-CPU ring buffers with reader/writer concurrency, …).
 *   v0 captures the 90% case (operator-instrumented call sites,
 *   short post-hoc dumps) at well under 300 lines. The trace
 *   points are MANUAL — there's no auto-instrumentation; that's
 *   a feature, not a limitation. Manual points stay where the
 *   author put them and don't drift into the boot path.
 *
 * SCOPE FOR v0
 *   - Single global ring (per-CPU upgrade lands with B2 SMP, so
 *     the ring cell is per-task scope today).
 *   - Each event carries `kind` (caller-defined u32), `arg0`,
 *     `arg1` (u64s), and an automatically-stamped tick count.
 *   - Lockless append via atomic-RMW on the head index. Reads
 *     for dump go through a snapshot-and-walk pattern with no
 *     lock — they may observe a torn record only if the writer
 *     is mid-append; the dump path tolerates that with a
 *     "valid_count" gate (write the metadata last).
 *   - No filtering; dump-all only. A `kind`-filter knob lands
 *     when a workload demands it.
 *
 * NOT IN SCOPE
 *   - Per-CPU rings, multi-reader concurrency, kernel-stack
 *     unwinding per event, dynamic patching of trace points.
 *
 * USAGE PATTERN
 *
 *     // From any kernel code, hot or cold:
 *     duetos::diag::EventTrace(kEventSyscallEnter, syscall_nr, arg0);
 *
 *     // Operator: `tracer dump` shell command walks the ring
 *     // and prints `[trace] tick=N kind=K arg0=A0 arg1=A1`.
 */

namespace duetos::diag
{

/// Capacity of the event ring. 4096 entries × 32 bytes/entry =
/// 128 KiB BSS — affordable, gives a useful window for anything
/// short of a full-system dump. Bumping this is one constant.
inline constexpr u32 kEventRingCapacity = 4096;

/// Caller-defined event kind. The kernel reserves the low 256
/// values for canonical call sites (see `EventKind` below);
/// drivers / subsystems pick u32s outside that range.
inline constexpr u32 kEventKindReserved = 0x00FF'FFFFu;

/// Canonical event kinds. Stable u32 values — instrumentation
/// data may persist across kernel rebuilds (e.g. an operator
/// captures + ships a trace; the post-hoc analyser must
/// recognise the kind).
enum EventKind : u32
{
    kEventNone = 0,         ///< Reserved sentinel; never recorded.
    kEventSyscallEnter = 1, ///< arg0=nr, arg1=arg0 to the syscall.
    kEventSyscallExit = 2,  ///< arg0=nr, arg1=rax return.
    kEventSchedSwitch = 3,  ///< arg0=prev_tid, arg1=next_tid.
    kEventIrq = 4,          ///< arg0=vector, arg1=cpu.
    kEventPageFault = 5,    ///< arg0=cr2, arg1=error_code.
    kEventMutexAcquire = 6, ///< arg0=mutex_addr, arg1=tid.
    kEventMutexRelease = 7, ///< arg0=mutex_addr, arg1=tid.
    kEventCustom = 8,       ///< arg0/arg1 entirely caller-defined.

    kEventKindCount,
};

struct EventRecord
{
    u64 tick;  ///< `time::TickCount()` at the moment of recording.
    u32 kind;  ///< EventKind or a u32 outside the reserved range.
    u32 _pad0; ///< Align arg0 to 8.
    u64 arg0;
    u64 arg1;
};

/// Append one event. Lockless atomic-RMW on the ring head;
/// cheap (single fetch_add + 4 stores). Safe from any context
/// (IRQ, NMI, task). Discards the oldest record on overflow —
/// a steady-state writer never blocks.
void EventTrace(u32 kind, u64 arg0, u64 arg1);

/// Total events ever recorded since boot (including overwritten
/// ones). Cheap u64 load.
u64 EventTraceTotalRecords();

/// Number of events currently observable in the ring (capped at
/// `kEventRingCapacity`).
u32 EventTraceLiveCount();

/// Reset every CPU's ring + total counter back to fresh-boot
/// state. Pairs with no-op init for fault-domain registration:
/// `RestartDriverDomain("event-trace")` re-baselines the ring.
void EventTraceReset();

/// Walk the ring oldest-first into `out` (caller-owned buffer).
/// Copies up to `out_capacity` records; returns the number
/// actually copied. Concurrent writers may produce a slightly
/// out-of-order sample — callers consuming this for human
/// inspection get a coherent snapshot of "the most recent N
/// events"; a more exact form would lock-out writers, which we
/// deliberately don't.
u32 EventTraceSnapshot(EventRecord* out, u32 out_capacity);

/// Stable human-readable name for a kind. Returns "?" for
/// unknown kinds. Used by the shell `tracer dump` printer.
const char* EventKindName(u32 kind);

/// Boot-time self-test. Records a few synthetic events, asserts
/// EventTraceLiveCount and EventTraceTotalRecords advance,
/// snapshots the buffer and verifies the recorded kinds match
/// the synthesised inputs in order. Panics on mismatch.
void EventTraceSelfTest();

} // namespace duetos::diag
