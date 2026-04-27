#pragma once

#include "util/types.h"

namespace duetos::mm
{
struct AddressSpace; // forward decl; defined in kernel/mm/address_space.h
}

namespace duetos::arch
{
struct TrapFrame; // forward decl; defined in kernel/arch/x86_64/traps.h
}

namespace duetos::core
{
struct Process; // forward decl; defined in kernel/proc/process.h
}

/*
 * DuetOS kernel scheduler — v0.
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

namespace duetos::sched
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

enum class TaskPriority : u8
{
    Normal = 0, // default for everything that does real work
    Idle = 1,   // picked only when no Normal task is Ready — dedicated
                // per-CPU idle tasks live here so they don't round-robin
                // CPU time with actual workloads
};

struct Task;

/// Bootstrap the scheduler. Wraps the currently-running code (kernel_main)
/// as task 0 — the idle/boot task. Safe to call SchedCreate afterwards.
void SchedInit();

/// Spawn a new kernel thread. Allocates a Task struct and a dedicated
/// kernel stack, primes the stack so the first context switch lands on
/// `entry(arg)`, and enqueues the task at the given priority. Returns
/// the task (for debugging / future join support). Default priority
/// is Normal — real workloads, drivers, reapers, workers. Pass
/// TaskPriority::Idle for per-CPU idle tasks (ones that should only
/// run when no Normal task is Ready).
Task* SchedCreate(TaskEntry entry, void* arg, const char* name, TaskPriority priority = TaskPriority::Normal);

/// Spawn a new task bound to a `core::Process`. The process owns the
/// address space; the task holds one reference on the process. The
/// scheduler caches `process->as` on the task so the CR3 flip on
/// context-switch remains a single pointer load — per-task AS
/// lookup never indirects through the Process on the hot path.
///
/// The AS must already have any required user mappings (code, stack)
/// installed via `mm::AddressSpaceMapUserPage` BEFORE calling
/// SchedCreateUser — the task's entry function sees them installed
/// when it calls `arch::EnterUserMode`.
///
/// `entry` runs in ring 0 on a fresh kernel stack (same as
/// SchedCreate); it's expected to set TSS.RSP0 and call
/// arch::EnterUserMode to drop to ring 3.
///
/// On task death, the reaper calls `core::ProcessRelease` on the
/// task's process pointer — the process's destructor then drops
/// the AS reference (tearing it down if the process was the last
/// holder).
Task* SchedCreateUser(TaskEntry entry, void* arg, const char* name, core::Process* process);

/// Accessor for the Task's owning process pointer. nullptr for
/// kernel-only tasks (workers, reaper, idle). Used by syscall
/// handlers via `core::CurrentProcess()` to cap-check.
core::Process* TaskProcess(Task* t);

/// Find the first live `core::Process*` with `pid == target_pid`.
/// Walks every queue (running, normal-runqueue, idle-runqueue,
/// sleep-queue, zombies) under arch::Cli to keep the lists stable
/// during the scan. Returns nullptr if no task with that PID is
/// alive — including the case where the task exists but is a
/// kernel-only task (`process == nullptr`).
///
/// Does NOT bump the returned Process's refcount. Callers that
/// need to hold the reference past the immediate scan window
/// must call `core::ProcessRetain` while the scheduler is still
/// CLI-quiet — typically inside the same syscall handler.
///
/// Used by SYS_PROCESS_OPEN (NtOpenProcess) to translate a PID
/// into a Process pointer the kernel can hand back as a handle.
core::Process* SchedFindProcessByPid(u64 target_pid);

/// Find the first live Task with `id == target_tid`. Walks the
/// same lists as SchedFindProcessByPid (running + run-normal +
/// run-idle + sleep) under arch::Cli. Skips zombies — a
/// dead task has no live Process to retain, so the cross-
/// process thread-handle opener would have nothing to refcount.
/// Returns nullptr if no live task matches.
///
/// Caller is responsible for capturing the task's owning
/// Process* and calling `core::ProcessRetain` on it before the
/// CLI window closes — otherwise a concurrent reaper could
/// free the Task struct under the caller's hand.
Task* SchedFindTaskByTid(u64 target_tid);

/// True iff the task's state is Dead. Used by syscalls that track
/// thread-handle signaling (WaitForSingleObject on a CreateThread
/// handle, WaitForMultipleObjects, GetExitCodeThread) — the
/// scheduler's zombie list is the single source of truth for
/// "this thread has exited." Safe against a null pointer.
bool TaskIsDead(const Task* t);

/// Canonical reasons a kernel subsystem can request task
/// termination via `FlagCurrentForKill(reason)`. Used by
/// Schedule() for the single-line reason log when it converts
/// a flagged task into a zombie. Extend at the tail — the
/// integer value is a stable handle for logs / future ABI.
enum class KillReason : u8
{
    TickBudget = 1,             // CPU-tick budget exhausted
    SandboxDenialThreshold = 2, // too many cap-denials
    UserKill = 3,               // shell `kill <pid>` / operator-initiated
    // Add new reasons at the end.
};

const char* KillReasonName(KillReason r);

/// Flag the current task for termination at next resched. The
/// reason is stored on the task and used by Schedule() when it
/// converts the task into a zombie — so the kill log line names
/// WHY the task died, not just that it did.
///
/// Same mechanism for every cause: set the flag + need_resched,
/// Schedule() catches on re-enqueue. Callable from any kernel
/// or syscall context; no-op if there's no current task.
void FlagCurrentForKill(KillReason reason);

/// Voluntary yield. Pushes current task to the tail of the runqueue and
/// switches to the head (if any other task is ready).
void SchedYield();

/// Block the current task for at least `ticks` timer ticks (100 Hz clock
/// today). A value of 0 behaves like SchedYield().
void SchedSleepTicks(u64 ticks);

/// Block the current task until the timer's tick counter reaches
/// `deadline_tick`. If the counter has already passed `deadline_tick`
/// by the time the call runs, behaves like SchedYield(). Useful for
/// periodic tasks that want to fire on a fixed cadence without drift
/// (increment deadline by `period` each iteration instead of
/// sleeping `period` at the end of each loop body).
void SchedSleepUntil(u64 deadline_tick);

/// Current value of the scheduler's tick counter (also exposed by
/// `arch::TimerTicks()`; this is the scheduler-visible copy, updated
/// inside `OnTimerTick`). Use as the base for building a deadline
/// to pass to `SchedSleepUntil`.
u64 SchedNowTicks();

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

/// Opaque identity of the currently-executing task. Monotonically
/// assigned at SchedCreate and never reused — the boot task is 0, then
/// 1, 2, 3, … in creation order. Used by SYS_GETPID and any future
/// diagnostic that wants to name a task without exposing the Task*
/// itself. Returns ~0 if called before SchedInit.
u64 CurrentTaskId();

/// Read the task ID of an arbitrary `Task*`. Returns 0 for nullptr.
/// Used by Win32 custom-diagnostics deadlock-detection to record a
/// mutex's owner edge in the wait graph without exposing Task's
/// layout.
u64 TaskId(const Task* t);

/// Read the human-readable name of an arbitrary `Task*`. Returns
/// `"<null>"` for nullptr and `"<noname>"` for a task whose name
/// pointer was never set. The returned C-string is owned by the
/// task and remains valid for the task's lifetime — it points
/// into the same `name` field the scheduler logs print. Used by
/// the crash-dump path to label the current task on a panic.
const char* TaskName(const Task* t);

/// Top (high address) of the current task's kernel stack. Returns 0 for
/// the boot task (it never had a scheduler-managed kernel stack — it
/// runs on the boot.S stack, which is irrelevant for ring-3 RSP0
/// purposes). Used by the ring-3 entry path: the caller passes this to
/// arch::TssSetRsp0 before iretq so the first interrupt from user mode
/// lands on a valid kernel stack.
u64 SchedCurrentKernelStackTop();

/*
 * Per-task user-VM bookkeeping has moved into `mm::AddressSpace`.
 *
 * Rationale: with per-process page tables, the unit that owns user
 * pages is the address space, not the task. Multiple tasks of the
 * same process (future thread support) share an AS and therefore
 * share its mappings; freeing user pages only when the LAST task
 * dies is the only correct semantics. The reaper now releases the
 * AS reference on task death; the AS itself is responsible for
 * walking its region table and returning frames at refcount-zero.
 *
 * Code that used to call `sched::RegisterUserVmRegion(virt, frame)`
 * after a `mm::MapPage` should now call
 * `mm::AddressSpaceMapUserPage(as, virt, frame, flags)` — one call
 * that both installs the mapping AND records ownership.
 */

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
    u64 total_ticks;      // lifetime — number of timer ticks since boot
    u64 idle_ticks;       // lifetime — ticks spent in the idle task (both BSP and AP)
};
SchedStats SchedStatsRead();

// Read-only view of one task for ps-style enumeration. Fields
// are snapshots copied at the moment SchedEnumerate visits the
// task; no pointer-chasing across the boundary so callbacks can
// safely write to the console / framebuffer.
struct SchedTaskInfo
{
    u64 id;
    const char* name; // borrowed; points into the task's stable name field
    u64 wake_tick;    // valid for Sleeping / timed-Blocked, else 0
    u64 stack_size;
    // Cumulative tick-count this task has consumed on-CPU since
    // creation. Divide by `SchedTotalTicks()` for a since-boot
    // CPU-%; a `top`-style periodic delta is built by the shell.
    u64 ticks_run;
    u8 state;        // TaskState cast to u8 (Ready/Running/Sleeping/Blocked/Dead)
    u8 priority;     // TaskPriority cast to u8
    bool is_running; // true if this is the currently-scheduled task
    u8 _pad[5];
};

/// Enumerate every known task — runqueues (Normal + Idle),
/// sleep queue, zombie list, and the currently-running task.
/// `cb` is invoked once per task with a snapshot; safe to call
/// Console* / printf-equivalents from inside the callback.
/// Internally brackets the walk with CLI to protect against
/// the timer tick mutating the lists mid-visit.
using SchedEnumCb = void (*)(const SchedTaskInfo& info, void* cookie);
void SchedEnumerate(SchedEnumCb cb, void* cookie);

struct StackHealth
{
    u64 canary_broken;    // # tasks whose stack-bottom sentinel scribbled
    u64 rsp_out_of_range; // # tasks whose saved rsp is outside their stack
};

/// Walk every live task and verify both the 8-byte stack-overflow
/// canary at `stack_base[0..7]` AND the saved rsp against the
/// task's [stack_base, stack_base + stack_size) bounds. Returns
/// a breakdown of findings — a non-zero canary_broken means at
/// least one kernel stack overflowed; a non-zero rsp_out_of_range
/// means a wild store or uninitialized save corrupted a task's
/// control block. The runtime checker calls this every scan so
/// overflow / rsp drift is caught long before the reaper would
/// notice at task exit.
StackHealth SchedCheckTaskStacks();

/// Result of a cross-task kill request.
enum class KillResult : u8
{
    Signaled = 0,    // Task found and flagged for termination
    NotFound = 1,    // No task with that PID
    Protected = 2,   // Task is special (idle / reaper / PID 0)
    AlreadyDead = 3, // Task is in the zombie list
    Blocked = 4,     // Task is Blocked — v0 can't detach safely
};
const char* KillResultName(KillResult r);

/// Flag a non-current task by PID for termination. For Running
/// / Ready targets, the kill activates the next time Schedule()
/// runs. For Sleeping targets, the task is lifted off the sleep
/// queue and re-queued Ready so it runs and dies on its next
/// slot. Blocked targets are not detached in v0 — the caller
/// gets a Blocked result code and should try again after the
/// task is woken by something else.
KillResult SchedKillByPid(u64 pid);

/// Walk every live task and signal each one whose owning Process
/// matches `target` for termination. Used by NtTerminateProcess
/// on a foreign target to bring the entire process down (every
/// thread in the task group). Returns the count of tasks that
/// were signalled — 0 if `target` has no live tasks. Skips
/// AlreadyDead / Blocked / Protected tasks (those statuses are
/// the same per-task contract as SchedKillByPid).
u64 SchedKillByProcess(core::Process* target);

/// Locate the outermost user→kernel TrapFrame on a target task's
/// kernel stack. Returns nullptr when the task has no kernel
/// stack (boot / idle), never entered user mode (cs.rpl != 3),
/// or has a corrupted stack_size. Used by NtGetContextThread /
/// NtSetContextThread to read or rewrite the user RIP / RSP /
/// GP regs that an iretq from this frame will restore.
///
/// Caller must ensure the target is suspended (not actively
/// pushing onto its own kernel stack); SchedSuspendTask is the
/// supported way. The single-CPU assumption is the same as the
/// rest of the cross-task control APIs — the caller is the
/// running task; the target is by construction not running.
arch::TrapFrame* SchedFindUserTrapFrame(Task* t);

/// Result of a cross-task suspend / resume request. NotFound is
/// reserved for caller-side handle resolution failures (the
/// scheduler itself never sees a null target on the success
/// path); the kernel APIs return Signaled for the typical
/// "found, count adjusted" case and AlreadyDead when the target
/// is in the zombie list.
enum class SuspendResult : u8
{
    Signaled = 0,
    NotFound = 1,
    AlreadyDead = 2,
};

/// Increment a target's NT-style suspend count. Returns the
/// previous count (0 = was running normally) via `prev_count_out`.
/// Self-suspend bumps the count and lets the caller continue
/// running — the parking happens at the next yield. For other
/// targets the suspend is lazy: a Ready task gets re-parked the
/// next time Schedule() pops it; a Sleeping / Blocked task gets
/// re-parked at wake time. Target == nullptr returns NotFound.
///
/// Single-CPU correctness: the suspender is the running task by
/// definition, so the target is by construction NOT running, and
/// no IPI is needed. SMP follow-up will need an IPI to evict a
/// target running on another core.
SuspendResult SchedSuspendTask(Task* target, u32* prev_count_out);

/// Decrement a target's suspend count. Returns the previous
/// count via `prev_count_out`. When the count reaches zero AND
/// the target was parked on the suspended list, it gets pushed
/// back onto the runqueue Ready. A resume with prior count == 0
/// is a no-op (matching NT — NtResumeThread returns 0 and stays
/// at 0 in that case).
SuspendResult SchedResumeTask(Task* target, u32* prev_count_out);

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

/// Block the current task on `wq` with a tick-based timeout. Returns
/// when either (a) another task or IRQ handler calls
/// WaitQueueWake{One,All}, or (b) `ticks` timer ticks have elapsed.
/// Same interrupt contract as WaitQueueBlock. A `ticks == 0` value
/// behaves like SchedYield — no actual block.
///
/// Return value: true if woken by an explicit wake, false if woken
/// by the timer. Callers that can resynthesise the answer from their
/// guarded condition can ignore it; callers that need to distinguish
/// "I got the event I was waiting for" from "I gave up" (I/O retry
/// paths, driver command-completion waits) use it to branch.
bool WaitQueueBlockTimeout(WaitQueue* wq, u64 ticks);

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

/*
 * Condition variable — drop-mutex-and-block with safe re-acquire.
 *
 * Standard producer/consumer pattern:
 *
 *     MutexLock(&m);
 *     while (!ready) CondvarWait(&cv, &m);
 *     // m is held here; `ready` was true.
 *
 *     // producer:
 *     MutexLock(&m);
 *     ready = true;
 *     CondvarSignal(&cv);
 *     MutexUnlock(&m);
 *
 * `CondvarWait` atomically hands off the mutex (with FIFO fairness
 * identical to MutexUnlock — the longest-waiting lock contender
 * becomes the new owner) AND enqueues the caller on `cv->waiters`.
 * No signal-between-release-and-block race window.
 *
 * Zero-initialise a Condvar to the empty state — no explicit Init
 * is required.
 */
struct Condvar
{
    WaitQueue waiters;
};

/// Drop `m` (with MutexUnlock hand-off semantics), block on `cv`,
/// re-acquire `m` on wake. Caller MUST hold `m` at entry; panics
/// otherwise.  Spurious wakeups are possible under the current
/// wait-queue primitives — always re-check your condition in a
/// `while (!condition) CondvarWait(...)` loop, never a plain `if`.
void CondvarWait(Condvar* cv, Mutex* m);

/// Timed variant — blocks at most `ticks` timer ticks before
/// resuming. Same atomicity contract as CondvarWait (mutex hand-off
/// + self-enqueue under a single sched_lock hold), plus also goes
/// onto the sleep queue. Returns true if woken by an explicit
/// CondvarSignal / CondvarBroadcast, false if woken by timeout.
/// `ticks == 0` is a test-and-drop: same as calling Unlock +
/// Yield + Lock. Re-check your guarded condition after return —
/// a true return doesn't prove the condition still holds by the
/// time you re-acquire `m`.
bool CondvarWaitTimeout(Condvar* cv, Mutex* m, u64 ticks);

/// Wake the single longest-waiting task on `cv`. No-op on empty
/// queue. Typical pattern is to call this WITH the companion mutex
/// held — guarantees the signalled waiter sees whatever state
/// change the signaller made before signalling.
void CondvarSignal(Condvar* cv);

/// Wake every task on `cv`. Returns the number of tasks woken.
u64 CondvarBroadcast(Condvar* cv);

} // namespace duetos::sched
