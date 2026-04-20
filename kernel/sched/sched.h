#pragma once

#include "../core/types.h"

/*
 * CustomOS kernel scheduler — v0.
 *
 * Round-robin, single CPU, kernel-mode threads only. Drives context
 * switches off the 100 Hz LAPIC timer tick plus explicit SchedYield()
 * calls. Userland processes, per-CPU runqueues, priorities, and
 * work-stealing all come later.
 *
 * Scope limits that will be fixed in later commits:
 *   - No userland. Every task runs in ring 0 on its own kernel stack.
 *   - No priorities. FIFO runqueue, picked head on every reschedule.
 *   - Sleep is tick-based (`SchedSleepTicks`, woken by the timer IRQ).
 *     Event-driven blocking goes through `WaitQueue` / `Mutex`.
 *   - Not SMP. g_current_task is global; spinlocks come with APs.
 *   - Preemption only at IRQ boundaries (the timer). Kernel code cannot
 *     be preempted in the middle of a non-IRQ critical section.
 *
 * Context: kernel. Init runs once, after TimerInit. After Init, any
 * kernel subsystem can SchedCreate a worker thread.
 */

namespace customos::sched
{

using TaskEntry = void (*)(void* arg);

enum class TaskState : u8
{
    Ready,    // on the runqueue, waiting for a slot
    Running,  // currently on a CPU
    Sleeping, // on the sleep queue, woken by the timer tick
    Blocked,  // on a WaitQueue, woken by explicit WaitQueueWake*
    Dead,     // SchedExit called; stack + task struct reclaimable
};

struct Task;

/// Bootstrap the scheduler. Wraps the currently-running code (kernel_main)
/// as task 0 — the idle/boot task. Safe to call SchedCreate afterwards.
void SchedInit();

/// Spawn a new kernel thread. Allocates a Task struct and a dedicated
/// kernel stack, primes the stack so the first context switch lands on
/// `entry(arg)`, and enqueues the task. Returns the task (for debugging
/// / future join support).
Task* SchedCreate(TaskEntry entry, void* arg, const char* name);

/// Voluntary yield. Pushes current task to the tail of the runqueue and
/// switches to the head (if any other task is ready).
void SchedYield();

/// Block the current task for at least `ticks` timer ticks (100 Hz clock
/// today). A value of 0 behaves like SchedYield().
void SchedSleepTicks(u64 ticks);

/// Terminate the current task. Marks it Dead, reclaims nothing in v0 (a
/// reaper thread lands later), and switches away — never returns.
[[noreturn]] void SchedExit();

/// Called from the IRQ dispatcher after EOI if `g_need_resched` is set.
/// Picks the next runnable task; does nothing if there's only one. Safe
/// to call from any kernel context with interrupts disabled.
void Schedule();

/// Flag set by the timer IRQ (or any preemption source) to request that
/// the IRQ dispatcher call Schedule() before iretq.
void SetNeedResched();
bool TakeNeedResched(); // read-and-clear

/// Timer IRQ hook. Called exactly once per timer tick from interrupt
/// context after the global tick counter is incremented.
void OnTimerTick(u64 now_ticks);

/// Pointer to the currently-executing task. Never null after SchedInit.
Task* CurrentTask();

/// Diagnostics — cheap snapshots.
struct SchedStats
{
    u64 context_switches; // lifetime
    u64 tasks_live;       // current length of the runqueue + running task
    u64 tasks_sleeping;   // current number of sleeping tasks
    u64 tasks_blocked;    // current number of tasks on wait queues
    u64 tasks_created;    // lifetime
    u64 tasks_exited;     // lifetime (Dead count)
    u64 tasks_reaped;     // lifetime (Task structs + stacks KFree'd by reaper)
};
SchedStats SchedStatsRead();

/// Start the dead-task reaper kernel thread. Run once after SchedInit +
/// the keyboard/driver init pass. The reaper sleeps on a WaitQueue;
/// SchedExit enqueues dead tasks to a zombie list and wakes it. This
/// closes the "Dead tasks leak" note in sched-blocking-primitives-v0.
void SchedStartReaper();

/// Spawn the per-CPU idle task. On the BSP, call once after SchedInit
/// so the runqueue is never empty when the boot task (or any other
/// task) blocks. The idle task does `sti; hlt` forever — it consumes
/// no CPU while halted, but its presence on the runqueue means
/// Schedule() always has a fallback to pick. On SMP, each AP's
/// bring-up will call this again with a distinct `name` per CPU.
void SchedStartIdle(const char* name);

/*
 * Wait queues — event-driven blocking.
 *
 * A task can block on a WaitQueue until another task (or IRQ handler)
 * wakes it. Unlike Sleeping, the wake is not tied to the timer: the
 * waker decides when. Callers of WaitQueueBlock MUST hold interrupts
 * disabled (arch::Cli) to ensure the "check condition, then block"
 * race is closed. The wake side must also run with interrupts off;
 * callers from task context should arch::Cli/Sti themselves.
 *
 * Zero-initialize a WaitQueue to the empty state — no explicit Init
 * function is required.
 */
struct WaitQueue
{
    Task* head;
    Task* tail;
};

/// Block the current task on `wq` and schedule. Returns once another task
/// (or IRQ handler) calls WaitQueueWakeOne / WaitQueueWakeAll. Caller
/// must hold interrupts disabled across the enqueue → Schedule pair.
void WaitQueueBlock(WaitQueue* wq);

/// Wake the single longest-waiting task on `wq` (FIFO). No-op on empty
/// queue. Callable from IRQ context; caller holds interrupts disabled.
/// Returns the Task* that was woken, or nullptr if the queue was empty.
Task* WaitQueueWakeOne(WaitQueue* wq);

/// Wake every task on `wq` in FIFO order. Same interrupt contract as
/// WaitQueueWakeOne. Returns the number of tasks woken.
u64 WaitQueueWakeAll(WaitQueue* wq);

/*
 * Mutex — sleeping lock with FIFO fairness.
 *
 * Holds `owner == nullptr` when free. Callers of Lock either claim the
 * lock (fast path) or block on `waiters` until Unlock hands the lock
 * off. There is no spin-then-block hybrid; the expectation is that
 * critical sections are small enough that blocking is cheap compared
 * to contention on a real spinlock.
 *
 * Recursion is NOT supported — the same task locking a mutex it
 * already owns will deadlock. Add an owning-re-entry check if a caller
 * needs that (or, better, refactor so it doesn't).
 */
struct Mutex
{
    Task* owner;
    WaitQueue waiters;
};

void MutexLock(Mutex* m);
void MutexUnlock(Mutex* m);
/// Non-blocking acquire. Returns true on success, false if already held.
bool MutexTryLock(Mutex* m);

} // namespace customos::sched
