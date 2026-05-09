#pragma once

#include "sched/sched.h"
#include "util/types.h"

/*
 * DuetOS — kernel work pool, v0.
 *
 * WHAT
 *   A reusable pool of N kernel worker threads that pull work
 *   items from a shared bounded FIFO. Subsystems that today
 *   spawn one-shot worker tasks (browser fetch, bench wakers,
 *   ad-hoc background scans) can instead enqueue function +
 *   argument pairs and let the pool's workers run them
 *   concurrently across CPUs.
 *
 * WHY
 *   The scheduler already exposes everything needed to spawn
 *   threads, but every caller that wants async work has to:
 *     1. Define a worker entry function,
 *     2. SchedCreate a single-purpose task,
 *     3. Hand-roll its termination + cleanup story.
 *   Three callers doing this by hand isn't bad. Twenty is. A
 *   pool consolidates the lifecycle, lets the kernel cap the
 *   number of background threads centrally, and — critically —
 *   exploits SMP for items that have no inter-dependencies.
 *
 * SHAPE
 *   - One pool owns N worker threads + one bounded queue.
 *   - Each work item is `(WorkFn fn, void* arg)` — caller-defined
 *     callback + opaque cookie. The pool never inspects `arg`.
 *   - Submit blocks the caller when the queue is full (back-
 *     pressure). TrySubmit fails fast.
 *   - Drain blocks until the queue is empty AND every worker is
 *     idle — a one-shot synchronisation point.
 *   - Shutdown drains, signals workers to exit, joins by waiting
 *     for the worker count to drop to zero, frees the pool.
 *
 * THREADING
 *   All public entry points are safe from any kernel context
 *   that can take a sched::Mutex. Work-item callbacks run on a
 *   worker thread's kernel stack — they can sleep, take locks,
 *   issue further Submit calls, and call into the rest of the
 *   kernel exactly as a SchedCreate'd task would.
 *
 * SCOPE LIMITS (v0)
 *   - No priority bands. Every item is FIFO. A future slice can
 *     add a priority field if a workload needs it.
 *   - No per-item cancellation. Once submitted, an item runs.
 *     Callers who need cancellation embed a flag in `arg`.
 *   - Workers run at TaskPriority::Normal. A pool dedicated to
 *     idle-class background scans would have to plumb the
 *     priority through Create — not needed yet.
 */

namespace duetos::sched
{

using WorkFn = void (*)(void* arg);

struct WorkPool;

/// Allocate a pool with `worker_count` worker threads and a
/// queue of capacity `queue_capacity`. `name_prefix` is used to
/// label the worker tasks (`"<prefix>-N"`); the storage must
/// outlive the pool — typically a static string literal.
///
/// Returns nullptr if any of: worker_count == 0,
/// queue_capacity == 0, allocation failure, or worker spawn
/// failure. On worker-spawn failure the partially-constructed
/// pool is torn down (any workers already running are signalled
/// to exit) before nullptr is returned, so a failed Create
/// never leaks threads.
WorkPool* WorkPoolCreate(u32 worker_count, u32 queue_capacity, const char* name_prefix);

/// Block until a queue slot is available, then enqueue
/// `(fn, arg)`. Wakes one idle worker. `fn` must be non-null.
void WorkPoolSubmit(WorkPool* p, WorkFn fn, void* arg);

/// Non-blocking submit. Returns true on success, false if the
/// queue is full. Useful for IRQ-context-style callers that
/// must not sleep — though the pool itself takes a sched::Mutex
/// so genuine IRQ context is still off-limits.
bool WorkPoolTrySubmit(WorkPool* p, WorkFn fn, void* arg);

/// Block until the queue is empty AND every worker has finished
/// the item it was running at the moment Drain was called.
/// Multiple callers can drain concurrently — each waits on the
/// same condition; all wake when the pool is fully idle.
///
/// Items submitted DURING a Drain extend the wait (the contract
/// is "queue empty + workers idle at observation time", not "no
/// work was ever in flight"). Callers that need a quiescence
/// barrier should stop submitting before calling Drain.
void WorkPoolDrain(WorkPool* p);

/// Drain, signal every worker to exit, wait for the worker
/// count to drop to zero, then free the pool. After Shutdown
/// returns, `p` is invalid and must not be reused.
///
/// Submitting to a pool mid-Shutdown is a kernel bug and
/// triggers a KASSERT — callers must coordinate so all
/// producers have stopped before Shutdown is invoked.
void WorkPoolShutdown(WorkPool* p);

/// Snapshot of items currently queued (not counting items being
/// executed by workers right now). Racy under SMP — for
/// diagnostics only.
u32 WorkPoolPending(const WorkPool* p);

/// Snapshot of workers that are currently executing an item
/// (i.e. between dequeue and item-completion). Racy under SMP.
u32 WorkPoolActive(const WorkPool* p);

/// Boot-time self-test. Creates a 4-worker pool with a small
/// queue, submits 256 items each of which atomically increments
/// a shared counter, drains, then asserts the counter equals
/// 256 and pending == 0 / active == 0. Tears the pool down via
/// Shutdown. Panics on any mismatch — exercises Submit's
/// blocking behaviour (queue is intentionally smaller than the
/// item count), worker fan-out, and Drain quiescence.
void WorkPoolSelfTest();

} // namespace duetos::sched
