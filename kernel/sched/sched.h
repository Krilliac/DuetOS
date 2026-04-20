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
 *   - Sleep is tick-based only (`SchedSleepTicks`) and run from the timer
 *     IRQ wake path. Generic wait-queues / mutex blocking come later.
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
    Ready,   // on the runqueue, waiting for a slot
    Running, // currently on a CPU
    Sleeping,
    Dead, // SchedExit called; stack + task struct reclaimable
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
    u64 tasks_created;    // lifetime
    u64 tasks_exited;     // lifetime (Dead count)
};
SchedStats SchedStatsRead();

} // namespace customos::sched
