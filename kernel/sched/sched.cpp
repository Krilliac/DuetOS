/*
 * DuetOS — kernel scheduler: implementation.
 *
 * Companion to sched.h — see there for Task struct, scheduling
 * classes, and the public API (`Create`, `Yield`, `Sleep`,
 * `Exit`, wait queues, mutexes).
 *
 * WHAT
 *   Round-robin scheduler with per-CPU runqueues. Drives
 *   preemption from the LAPIC timer tick. Owns the Task table
 *   (fixed-size pool, no dynamic growth at v0), the per-CPU
 *   `current` pointer, the global wait-queue list, and the
 *   blocking-primitive plumbing (mutex / event / sleep / join).
 *
 * HOW
 *   `Schedule()` is called from the timer-tick handler and from
 *   any explicit yield path. It picks the next runnable Task
 *   from the current CPU's runqueue and calls `ContextSwitch`
 *   (in sched/context_switch.S) to swap stacks. The chosen
 *   task's RSP is loaded; whatever was pushed there last (the
 *   callee-saved set + return address) is popped and returned
 *   to.
 *
 *   Task lifecycle banners (`// === create / fork / wait / exit`)
 *   group the lifecycle entry points. Wait-queue helpers
 *   (`WaitQueueWait`, `WaitQueueWake`) sit in their own banner
 *   — they're shared by mutex / event / sleep.
 *
 * WHY THIS FILE IS LARGE
 *   Scheduler v0 + blocking primitives v0 + per-CPU bring-up
 *   + Win32 thread-create plumbing all live here. Each is a
 *   handful of functions; the count adds up. Splitting per
 *   concern would scatter related state (the Task table and
 *   the wait-queue list both need to walk the same set), so
 *   they stay co-located.
 */

#include "sched/sched.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/traps.h"
#include "diag/event_trace.h"
#include "diag/fix_journal.h"
#include "diag/kdbg.h"
#include "diag/kpath.h"
#include "diag/soft_lockup.h"
#include "sched/loadavg.h"
#include "sync/rcu.h"
#include "log/klog.h"
#include "core/panic.h"
#include "proc/process.h"
#include "diag/recovery.h"
#include "cpu/critical.h"
#include "cpu/percpu.h"
#include "cpu/topology.h"
#include "debug/probes.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "security/guard.h"
#include "mm/kheap.h"
#include "mm/kstack.h"
#include "mm/paging.h"
#include "sync/spinlock.h"
#include "time/tick.h"
#include "util/debug_assert.h"
#include "util/string.h"
#include "util/compiler.h"

namespace duetos::sched
{

// ContextSwitch is defined in context_switch.S. Signature: save callee-
// saved regs + rsp into *old_rsp_slot, adopt new_rsp, pop and return.
extern "C" void ContextSwitch(u64* old_rsp_slot, u64 new_rsp);

struct Task
{
    u64 id;
    TaskState state;
    u64 rsp;        // saved stack pointer (0 while running)
    u8* stack_base; // lowest address of the kernel stack
    u64 stack_size;
    // Deadline for Sleeping and timed-Blocked tasks — 0 for every
    // other state, and reset to 0 by the wake path so a task that
    // comes back Ready has a clean slate.
    u64 wake_tick;
    const char* name;
    // `next` threads the runqueue, a WaitQueue, or the zombie list —
    // mutually exclusive; at most one of those is the task's home
    // at any given moment.
    Task* next;
    // `sleep_next` / `sleep_prev` form a SEPARATE doubly-linked
    // intrusive list used only for the sleep queue. Kept out of
    // `next` so a task can be parked on BOTH a wait queue (via
    // `next`) and the sleep queue (via `sleep_{next,prev}`)
    // simultaneously — that's how WaitQueueBlockTimeout implements
    // "wake me on event OR on timer, whichever comes first." The
    // `sleep_prev` link lets SleepqueueRemove unlink in O(1)
    // (a timed waiter being woken explicitly is the common case);
    // without it, removal had to re-walk the sorted list looking
    // for the predecessor.
    Task* sleep_next;
    Task* sleep_prev;
    // Back-pointer to the WaitQueue a Blocked task is currently on
    // (nullptr otherwise). Lets OnTimerTick unlink a timed-waiter
    // from its wait queue when the timeout path wakes it first.
    WaitQueue* waiting_on;
    // Transient flag set by the timer path when a timed wait
    // expires, cleared by the wait-queue path when an explicit
    // wake pre-empts the timeout. Read by WaitQueueBlockTimeout
    // the moment Schedule() resumes the waiter — the value after
    // that is undefined, since the slot is reused on the next
    // wait.
    bool wake_by_timeout;
    // Scheduling priority. Normal tasks round-robin on the Normal
    // runqueue; Idle tasks only run when Normal is empty. Set
    // once at SchedCreate and never changed — priority inheritance
    // / real-time class would need a mutable field.
    TaskPriority priority;

    // Per-process address space. nullptr means "kernel AS" (the
    // boot PML4) — used by every kernel-only thread (workers,
    // reaper, idle, keyboard reader, etc.). A non-null AS means
    // this task holds a process reference that transitively owns
    // the AS: the reaper calls core::ProcessRelease on process,
    // which drops the AS reference, which runs the AS destructor
    // if it was the last holder.
    //
    // Schedule() publishes task->as to CR3 on every switch-in via
    // AddressSpaceActivate. Same-AS switches (kernel→kernel) hit
    // the fast-path and do not touch CR3 — no TLB flush paid for
    // a scheduler decision that doesn't change the address space.
    // We cache the AS pointer on the Task (rather than always
    // dereferencing process->as) so the context-switch hot path
    // stays one load.
    mm::AddressSpace* as;

    // Owning process. nullptr for kernel-only tasks. Set once at
    // SchedCreateUser; the reaper ProcessReleases it on death.
    // Used by CurrentProcess() for cap lookup.
    core::Process* process;

    // Flag set by any kernel subsystem that wants this task
    // killed at next resched. Historical name was tick_exhausted
    // because the tick-budget path set it first; now the cap-
    // denial threshold, future audit-triggered kills, etc. all
    // route through the same flag. Checked by Schedule() on each
    // re-enqueue; when set, the task is diverted to the zombie
    // list instead of being put back on the runqueue, and the
    // reaper tears it down normally. Irrelevant for kernel-only
    // tasks (process == nullptr — they have neither budgets nor
    // sandbox policies).
    bool kill_requested;
    // Why the kill was requested. Populated alongside
    // kill_requested; Schedule() reads this to log a meaningful
    // reason when it converts the task into a zombie. Only valid
    // when kill_requested is true.
    KillReason kill_reason;

    // One-shot boot context: this Task exists ONLY to give a CPU's
    // first Schedule() a non-null `prev`; its rsp / stack_base are
    // placeholders and it must NEVER go on a runqueue. The AP boot
    // sentinel (CreateApBootSentinel) sets this. Schedule() drops
    // such a task instead of re-enqueuing it — otherwise a peer CPU
    // pops the fake task and ContextSwitches into garbage on the AP
    // trampoline stack: an SMP task double-run that surfaces as
    // intermittent MUTEX-NONOWNER / sched-class spinlock
    // self-deadlock (reproduced by tools/qemu/gui-fuzz.sh). Zeroed
    // by the memset every Task allocation runs, so normal tasks
    // default to false.
    bool no_requeue;

    // First-run flag. True from SchedCreate until SchedFinishTaskSwitch
    // runs for the first time on this task — i.e. true while the
    // SchedCreate-primed stack layout (planted &SchedTaskTrampoline at
    // slot_top-8, planted entry-fn at slot_top-16) is still intact and
    // about to be consumed by ContextSwitch's pop sequence. Flipped to
    // false by SchedFinishTaskSwitch on the trampoline's first-entry
    // path — past that point, the rbx slot at slot_top-16 is general
    // stack memory the task may write through.
    //
    // ScheduleLockedHandoff's proactive rbx-slot validator gates on
    // this flag: with it true, the slot MUST hold a kernel-text
    // function pointer; with it false, the slot is anything.
    bool first_run;

    // CPU-time accounting. `ticks_run` accumulates one tick per
    // OnTimerTick call where this task was the current task; it
    // is the authoritative "how much CPU time has this consumed
    // since creation?" number. `schedin_tick` is the tick value
    // at the most recent switch-in — Schedule() uses it to
    // compute the delta for the outgoing task instead of tripping
    // a per-tick increment inside OnTimerTick (which runs on
    // every clock interrupt and must stay cheap).
    //
    // Both fields are read by SchedEnumerate so `ps` / `top` can
    // render CPU-% per task. Idle tasks accumulate too — that's
    // how SchedIdleTicks() can report system-wide idle fraction.
    u64 ticks_run;
    u64 schedin_tick;

    // Win32 LastError slot. Windows stores this in the TEB at
    // offset 0x68 and every thread gets an independent value. We
    // don't expose a full writable TEB yet, so the scheduler-owned
    // Task is the narrowest kernel-owned per-thread home. Syscalls
    // SYS_GETLASTERROR / SYS_SETLASTERROR read/write this field.
    u32 win32_last_error;
    u32 _pad_win32_last_error;

    // Win32 TLS (Thread-Local Storage) per-thread slot values.
    // The slot ALLOCATION bitmap (`Process::tls_slot_in_use`) is
    // per-process — TlsAlloc returns a slot index every thread in
    // the process shares. The stored VALUE per slot, by contract,
    // is per-thread: thread A's TlsSetValue(slot=5, x) must NOT
    // be observable by thread B's TlsGetValue(slot=5). v0 stored
    // values on Process and shared across threads — correct only
    // for single-threaded programs. Storing per-thread closes the
    // gap. T6-01 (partial): full PE TLS callbacks + static-TLS
    // template still defer; this is the runtime-API half.
    //
    // 512 bytes per Task. With ~30 tasks at peak the cost is ~15
    // KiB, which the kheap absorbs without notice. Kernel-only
    // tasks (idle, workers, reaper) never call TlsAlloc / Set /
    // Get and leave the array zero-initialised.
    u64 win32_tls_slot_value[kWin32TlsCap];

    // Linux-ABI FS.base (MSR_FS_BASE). Meaningful only for tasks
    // whose process has abi_flavor == kAbiLinux — that's where
    // musl plants its TLS anchor via arch_prctl(ARCH_SET_FS).
    // Saved by the scheduler just before ContextSwitch and
    // restored immediately after, so each Linux task sees its own
    // TLS regardless of what other tasks ran in between. Kernel-
    // only and native tasks leave this at 0 and never touch
    // MSR_FS_BASE; the save/restore is a no-op for them.
    u64 fs_base;

    // Per-task user GSBASE override (T6-01 per-thread half). 0 =
    // "use this task's Process::user_gs_base" (the shared-TEB
    // model — every existing PE main thread). A worker thread
    // created by SYS_THREAD_CREATE for a TLS-using PE gets its
    // OWN TEB and sets this to that per-thread TEB VA. The
    // scheduler restores the resolved value into the
    // KERNEL_GS_BASE MSR right after every ContextSwitch so the
    // task's return-to-user swapgs loads the correct per-thread
    // TEB regardless of what ran in between. (This also fixes a
    // latent bug: previously KERNEL_GS_BASE retained whichever
    // task last trapped from user, correct only because all
    // threads of the single Win32 process shared one TEB.)
    u64 user_gs_base_override;

    // Per-task IRQ nesting depth. Saved/restored across context
    // switch so the global g_irq_depth tracks "how deep is the
    // CURRENT task's nesting" correctly: a task A that blocks
    // mid-IRQ-handler, is switched out, and later resumed has
    // its depth preserved. Without this, the global counter
    // leaked monotonically every time Schedule() abandoned a
    // dispatch frame.
    u64 irq_depth;

    // Per-task debug-register state (DR0..DR3 + DR7). Mirrors
    // the fs_base idiom: saved from the CPU just before
    // ContextSwitch, restored into the CPU right after so each
    // task's breakpoint set follows it across switches. Tasks
    // without any breakpoints leave these zero — the save/
    // restore is one read + one write per register and costs a
    // handful of cycles in the non-debug case. DR6 is not
    // saved: it's a status register the CPU manages across
    // #DB delivery, and the breakpoint handler writes it back
    // to its init value before returning anyway.
    u64 dr0;
    u64 dr1;
    u64 dr2;
    u64 dr3;
    u64 dr7;

    // NT-style suspend count. Read/written by SchedSuspendTask /
    // SchedResumeTask under arch::Cli. While this is non-zero,
    // the scheduler refuses to pick the task off the runqueue —
    // RunqueuePopRunnable detects suspended pops and re-parks
    // them on g_suspended_head. Sleeping / blocked tasks remain
    // on their wait/sleep queue while suspended; the wake path
    // routes them through the same re-parker.
    //
    // Only the cross-task control APIs (SchedSuspendTask /
    // SchedResumeTask) and the wake path (RunqueueOrSuspendPush)
    // mutate this. Every mutator runs under arch::Cli + the
    // sched lock; reads outside the scheduler are racy by design
    // (a snapshot for diagnostics is fine).
    u32 suspend_count;

    // CPU this task most recently ran on (or, for never-yet-run
    // tasks, the CPU that spawned them). Used by the wake path to
    // route the task back onto the same CPU's runqueue — preserves
    // cache affinity across sleep/wake cycles. Updated by Schedule()
    // each time the task is switched IN. Initialised to the spawning
    // CPU in SchedCreateInternal. Work-stealing in commit 6 may
    // override the routing decision when a peer CPU is idle.
    u32 last_cpu;

    // Adaptive-mutex on-CPU flag. 1 while the task is the
    // currently-running task on SOME CPU; 0 otherwise (Ready in the
    // runqueue, Blocked / Sleeping on a wait or sleep queue, Dead).
    // Set with __ATOMIC_RELEASE on the resuming task right before
    // ContextSwitch, cleared with __ATOMIC_RELEASE on the outgoing
    // task right before ContextSwitch. The adaptive mutex slow path
    // reads this with __ATOMIC_ACQUIRE on a foreign CPU to decide
    // "spin (owner still running, release imminent)" vs "park (owner
    // is off-CPU; spinning would burn cycles waiting for a
    // reschedule)". u8 not bool so the layout is explicit; one byte
    // packs cheaply alongside the existing u32 last_cpu.
    u8 on_cpu;

    // Hard CPU affinity: bit (1u << cpu_id) set => the task is
    // permitted to run on that CPU. kAffinityAll (~0u) means "no
    // restriction" and is the default for every task, so every
    // placement decision below is byte-for-byte identical to the
    // pre-affinity scheduler unless a mask is explicitly narrowed
    // via SchedSetAffinityMask / the Linux sched_setaffinity
    // thunk. u32 covers acpi::kMaxCpus; widen with that cap.
    u32 affinity_mask;

    // Per-task syscall trail. Ring of the most recent
    // kSyscallTrailSize syscalls (newest at trail_head - 1, mod
    // size). Pushed by SyscallTrailRecord from each dispatcher,
    // consumed by DumpCurrentTaskSyscallTrail on panic. Storage
    // is inline so kernel-only tasks pay the (modest) memory
    // cost but never write to it; the dumper skips empty rings.
    struct SyscallTrailEntry
    {
        u32 nr;
        u8 abi;
        u8 _pad[3];
        u64 args[4];
        u64 ret;
        u64 ts_tick;
    };
    SyscallTrailEntry trail[kSyscallTrailSize];
    // Next slot to write; the most recent entry is `trail[(trail_head - 1) % size]`
    // and `trail_count` clamps how many entries are valid (so the
    // dumper doesn't walk into pre-init zeros).
    u32 trail_head;
    u32 trail_count;

    // T6-02 kernel→user SEH delivery recursion guard.
    // `seh_last_rip` is the faulting RIP the previous kernel-built
    // EXCEPTION_RECORD was delivered for; `seh_repeat` counts
    // consecutive deliveries at the SAME faulting RIP. A handler
    // that legitimately catches a fault resumes at a *different*
    // RIP (the __except block), so a rising `seh_repeat` means the
    // dispatcher or a handler is wedged re-faulting the identical
    // instruction. Once it crosses kSehMaxRepeat the trap path
    // stops delivering and falls back to task-kill — the unhandled
    // path must terminate, not loop forever in ntdll. Reset to zero
    // on a distinct fault RIP.
    u64 seh_last_rip;
    u32 seh_repeat;
    u32 _pad_seh;

    // Lockdep held-class stack, parked here across ContextSwitch.
    // A sleeping mutex is held across switches; a single global
    // held stack conflated two tasks' independent mutexes into a
    // false lock-order inversion. The scheduler snapshots the
    // running task's held set into the outgoing Task just before
    // ContextSwitch and restores the resumed task's in
    // SchedFinishTaskSwitch (after the fresh-AP guard, Running
    // tasks only). memset-zero on alloc = empty set, which is the
    // correct held state for a fresh task.
    ::duetos::sync::LockClass lockdep_held[::duetos::sync::kLockdepHeldMax];
    u32 lockdep_held_depth;
};

namespace
{

using arch::Halt;
using arch::SerialWrite;
using arch::SerialWriteHex;

constexpr u64 kKernelStackBytes = 64 * 1024; // 64 KiB per task — bumped from 16 KiB on
                                             // 2026-04-25 because the PE-loader path
                                             // (~5 KiB DllImage[48] preload local +
                                             // recursive page-table walks during
                                             // AddressSpaceMapUserPage) overflowed the
                                             // 16 KiB cap on the second PE spawn.
                                             // See mm/kstack.h.

// Canary planted at the lowest 8 bytes of every task's kernel stack.
// Stack grows DOWN, so the canary sits at the EDGE of overflow: if
// the task's deepest push ever reaches into [stack_base, stack_base+8)
// the canary gets scribbled and the reaper notices on task exit. This
// doesn't catch overflow the instant it happens (no #PF without guard
// pages) but turns "mysterious heap corruption" into a named panic
// with the task's identity attached.
constexpr u64 kStackCanary = 0xC0DEB0B0CAFED00DULL;

// Two-level priority queue: Normal and Idle. Schedule() drains
// Normal first; Idle tasks only run when Normal is empty. Each
// queue is FIFO round-robin within its priority band. Promoting
// beyond two levels (real-time class, per-priority timeslicing)
// is deferred until a workload needs it (see decision log #010).
//
// As of commit 2 of the SMP refactor, the runqueue head/tail
// pointers live in cpu::PerCpu (one set per CPU). This file's
// RunqueuePushOn / RunqueuePop helpers below take a target PerCpu
// argument so wake paths can enqueue on the task's `last_cpu` for
// cache affinity. The lock granularity is unchanged for now —
// every enqueue / pop still happens under g_sched_lock; per-CPU
// runqueue spinlocks are a follow-up optimisation.
//
// Helper: typed accessor wrappers around the void* slots in PerCpu
// so call sites don't need to cast on every reference.
inline Task*& RunqHeadNormal(cpu::PerCpu* p)
{
    return reinterpret_cast<Task*&>(p->runq_head_normal);
}
inline Task*& RunqTailNormal(cpu::PerCpu* p)
{
    return reinterpret_cast<Task*&>(p->runq_tail_normal);
}
inline Task*& RunqHeadIdle(cpu::PerCpu* p)
{
    return reinterpret_cast<Task*&>(p->runq_head_idle);
}
inline Task*& RunqTailIdle(cpu::PerCpu* p)
{
    return reinterpret_cast<Task*&>(p->runq_tail_idle);
}

constinit Task* g_sleep_head = nullptr; // sorted by wake_tick (ascending)
constinit u64 g_tick_now = 0;
constinit u64 g_next_task_id = 0;
constinit u64 g_context_switches = 0;
// g_tasks_* counters moved to PerCpu::sched_tasks_*. Reads sum
// across all online CPUs (see SchedStatsRead); writes target
// cpu::CurrentCpu()'s per-CPU slot. Increments and decrements may
// land on different CPUs but the cross-CPU sum stays correct.

// Per-CPU stat counter accessors. Inlined to keep the hot
// scheduler paths compact; cpu::CurrentCpu() lowers to a single
// gs:[0] load on x86, so this is byte-equivalent to the prior
// global increment.
DUETOS_NO_SANITIZE_WRAP inline void SchedCpuIncLive()
{
    ++cpu::CurrentCpu()->sched_tasks_live;
}
DUETOS_NO_SANITIZE_WRAP inline void SchedCpuDecLive()
{
    --cpu::CurrentCpu()->sched_tasks_live;
}
DUETOS_NO_SANITIZE_WRAP inline void SchedCpuIncSleeping()
{
    ++cpu::CurrentCpu()->sched_tasks_sleeping;
}
DUETOS_NO_SANITIZE_WRAP inline void SchedCpuDecSleeping()
{
    --cpu::CurrentCpu()->sched_tasks_sleeping;
}
DUETOS_NO_SANITIZE_WRAP inline void SchedCpuIncBlocked()
{
    ++cpu::CurrentCpu()->sched_tasks_blocked;
}
DUETOS_NO_SANITIZE_WRAP inline void SchedCpuDecBlocked()
{
    --cpu::CurrentCpu()->sched_tasks_blocked;
}
inline void SchedCpuIncCreated()
{
    ++cpu::CurrentCpu()->sched_tasks_created;
}
inline void SchedCpuIncReaped()
{
    ++cpu::CurrentCpu()->sched_tasks_reaped;
}

// Cross-CPU sum walks for read-side. Used by SchedStatsRead; cold
// path (operator runs `top` or `ps`), no atomic ops needed since
// caller observes a snapshot whose precision is best-effort.
DUETOS_NO_SANITIZE_WRAP inline u64 SchedSumLive()
{
    u64 sum = 0;
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 id = 0; id < limit; ++id)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(id);
        if (p != nullptr)
            sum += p->sched_tasks_live;
    }
    return sum;
}
DUETOS_NO_SANITIZE_WRAP inline u64 SchedSumSleeping()
{
    u64 sum = 0;
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 id = 0; id < limit; ++id)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(id);
        if (p != nullptr)
            sum += p->sched_tasks_sleeping;
    }
    return sum;
}
DUETOS_NO_SANITIZE_WRAP inline u64 SchedSumBlocked()
{
    u64 sum = 0;
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 id = 0; id < limit; ++id)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(id);
        if (p != nullptr)
            sum += p->sched_tasks_blocked;
    }
    return sum;
}
inline u64 SchedSumCreated()
{
    u64 sum = 0;
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 id = 0; id < limit; ++id)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(id);
        if (p != nullptr)
            sum += p->sched_tasks_created;
    }
    return sum;
}
inline u64 SchedSumReaped()
{
    u64 sum = 0;
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 id = 0; id < limit; ++id)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(id);
        if (p != nullptr)
            sum += p->sched_tasks_reaped;
    }
    return sum;
}
// System-wide CPU accounting. `g_total_ticks` counts every timer
// tick since boot; `g_idle_ticks` counts the subset where the idle
// task was on-CPU. Their ratio is the system CPU-busy fraction —
// reported by the heartbeat and by the `top` shell command.
constinit u64 g_total_ticks = 0;
constinit u64 g_idle_ticks = 0;

// Zombie list — tasks that called SchedExit and are off-CPU, waiting
// for the reaper to free their struct + stack. Linked through Task::next
// (reused from runqueue/waitqueue — a task is only ever on one list).
constinit Task* g_zombies = nullptr;
constinit WaitQueue g_reaper_wq{};
constinit u64 g_tasks_exited = 0;

// Single global scheduler lock protecting every mutation of:
//   - g_run_head / g_run_tail
//   - g_sleep_head
//   - g_zombies
//   - any WaitQueue head/tail
//   - g_tasks_* counters
//
// SMP correctness: Schedule() HOLDS this lock across the
// ContextSwitch call via the lock-passing handshake — the source
// CPU writes the lock pointer + saved IRQ flags into its PerCpu
// `ctxsw_lock_to_release` slot before ContextSwitch, and the
// resumed code (SchedFinishTaskSwitch, called either from
// Schedule()'s post-switch path or from SchedTaskTrampoline on a
// fresh-task first-run) drains the slot and releases. Closes the
// race where a peer CPU could wake `prev` between an early lock
// release and the actual stack swap, then dispatch prev while
// we're still on its stack. Mirrors Linux's prepare_task_switch /
// finish_task_switch pattern.
//
// Tagged with `kLockClassSched` so the lockdep-lite locking-order
// graph (sync/lockdep.h) records every "lock-X-was-held when sched
// was acquired" pairing. Untagged locks pay nothing; the scheduler
// runqueue is THE most contended global, so it gets first.
constinit sync::SpinLock g_sched_lock{
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassSched};

// Current() and NeedResched() moved to cpu::PerCpu. Per-CPU accessors
// keep call sites terse and read unambiguously: Current() is the
// currently-running task on THIS CPU; NeedResched() is THIS CPU's
// pending-reschedule flag. BSP's slot is initialised in SchedInit;
// APs initialise their own in the AP bring-up trampoline.
inline Task*& Current()
{
    return cpu::CurrentCpu()->current_task;
}
inline bool& NeedResched()
{
    return cpu::CurrentCpu()->need_resched;
}

[[noreturn]] void PanicSched(const char* message)
{
    core::Panic("sched", message);
}

// Low-level helpers — assume the caller holds g_sched_lock. Internal
// "_Locked" suffix would be Linux-style but in our file-local scope
// the expectation is encoded by staying inside the anonymous namespace
// and calling only from functions that acquire the lock themselves.
// Resolve a task's target CPU for enqueue. Falls back to the
// current CPU when last_cpu is out of range (boot tasks created
// before any switch sets last_cpu, plus any future hot-unplug
// scenario where the task's previous CPU is gone). Both BSP and
// any AP that has joined the scheduler have a live PerCpu
// pointer registered in arch::SmpGetPercpu.
// "No affinity restriction" sentinel. A task at this mask is
// allowed on every CPU, so TaskAllowedOn is unconditionally true
// and all placement paths collapse to their pre-affinity form.
constexpr u32 kAffinityAll = ~0u;

// True iff `t` is permitted to run on `cpu_id`. Always true for an
// unrestricted task (the default), so the common path pays only a
// shift + and.
inline bool TaskAllowedOn(const Task* t, u32 cpu_id)
{
    if (t->affinity_mask == kAffinityAll)
    {
        return true;
    }
    if (cpu_id >= 32u)
    {
        return false; // mask is 32 bits wide (acpi::kMaxCpus)
    }
    return ((t->affinity_mask >> cpu_id) & 1u) != 0u;
}

// Lowest-indexed online CPU permitted by `t`'s mask, or nullptr if
// the mask excludes every online CPU (caller-validated not to
// happen for a live task; defensive only).
cpu::PerCpu* FirstAllowedPerCpu(const Task* t)
{
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p != nullptr && TaskAllowedOn(t, i))
        {
            return p;
        }
    }
    return nullptr;
}

cpu::PerCpu* TargetPerCpuFor(Task* t)
{
    cpu::PerCpu* p = arch::SmpGetPercpu(t->last_cpu);
    if (p == nullptr)
    {
        p = cpu::CurrentCpu();
    }
    // If `last_cpu` points at a slot whose AP isn't actually
    // servicing a runqueue yet (e.g. mid-SmpStartAps, between
    // `g_ap_percpus[cpu_id] = ap_pcpu` and `WaitForApOnline`),
    // re-home to a guaranteed-live slot. Walking forward to the
    // BSP (slot 0, always online) is safe because the next active
    // load balancer pass corrects any drift away from `last_cpu`.
    // Same predicate `PickClusterPlacement` uses below.
    if (p != nullptr && !p->online)
    {
        cpu::PerCpu* bsp = arch::SmpGetPercpu(0);
        if (bsp != nullptr && bsp->online)
        {
            p = bsp;
        }
    }
    // Honor a narrowed affinity mask: if last_cpu (or the
    // CurrentCpu fallback) is not permitted, retarget to the
    // lowest allowed online CPU. Unrestricted tasks skip this
    // entirely, so the default routing is unchanged.
    if (t->affinity_mask != kAffinityAll && (p == nullptr || !TaskAllowedOn(t, p->cpu_id)))
    {
        cpu::PerCpu* allowed = FirstAllowedPerCpu(t);
        if (allowed != nullptr)
        {
            p = allowed;
        }
    }
    return p;
}

void RunqueuePushOn(cpu::PerCpu* target, Task* t)
{
    // Documented-but-unchecked precondition (see the "Caller holds
    // g_sched_lock" block above): every enqueue funnels here, so a
    // caller that forgot the lock corrupts a per-CPU runqueue
    // race-silently. Debug-panic / release-warn — a missed lock is
    // a development-time concurrency bug, not a security hole.
    sync::SpinLockAssertHeld(g_sched_lock);
    // A null task on the runqueue would panic Schedule() later with
    // a less informative call site. Catch the bad caller here.
    KASSERT(t != nullptr, "sched", "RunqueuePush(nullptr)");
    KASSERT(target != nullptr, "sched", "RunqueuePushOn(nullptr target)");
    // A Dead task must never re-enter the runqueue — it has no stack,
    // its AS is gone, and the reaper holds the only legitimate
    // reference. Silently accepting it would crash the next Schedule().
    KASSERT(t->state != TaskState::Dead, "sched", "RunqueuePush of Dead task");
    t->next = nullptr;
    Task*& head = (t->priority == TaskPriority::Idle) ? RunqHeadIdle(target) : RunqHeadNormal(target);
    Task*& tail = (t->priority == TaskPriority::Idle) ? RunqTailIdle(target) : RunqTailNormal(target);
    // Singly-linked-list invariant: head and tail are null together
    // or non-null together. If only one is null the table is already
    // corrupt — taking the `tail == nullptr` branch below would
    // orphan the existing chain (every queued Task silently lost).
    // O(1), debug-only: the always-on KASSERTs above already cover
    // the security-critical bad-task cases.
    DEBUG_ASSERT((head == nullptr) == (tail == nullptr), "sched", "runqueue head/tail nullness disagree");
    if (tail == nullptr)
    {
        head = tail = t;
    }
    else
    {
        tail->next = t;
        tail = t;
    }
    if (t->priority != TaskPriority::Idle)
    {
        ++target->runq_normal_len;
    }
}

// Wake-time placement: prefer the task's `last_cpu` for cache
// affinity, but if it's loaded relative to its same-cluster peers,
// route the wake to the least-loaded peer in that cluster. The
// threshold (`kClusterPlacementMargin`) prevents oscillation —
// migrating on a one-task delta would ping-pong tasks between
// equally-loaded CPUs and burn cache for no win. Two is the
// smallest delta that guarantees the destination's queue length
// after the push is strictly less than the source's queue length
// before the push, so an idle peer is always a better landing
// spot than an already-loaded `last_cpu`.
//
// Same-cluster only: cross-cluster routing is handled by the
// existing work-stealing pass-1 fallback. Wake placement is the
// hot path; we don't want to import a NUMA / package-cross cost
// just because a peer happens to be idle.
//
// Caller holds g_sched_lock — same critical section as the
// Push that follows, so the snapshot of every peer's
// runq_normal_len is consistent. No lock-granularity dance is
// required today; the post-split-per-CPU world will need a
// try-lock probe instead.
constexpr u32 kClusterPlacementMargin = 2;

// SMT-spreading penalty. Set equal to kClusterPlacementMargin so a
// fully-idle physical core always wins placement over a logical CPU
// whose SMT sibling is busy, with the same no-oscillation
// equilibrium the margin comment above relies on: an idle logical
// CPU on a busy core then looks exactly as loaded as a logical CPU
// on an idle core that already has kClusterPlacementMargin tasks
// queued.
constexpr u32 kSmtSiblingPenalty = 2;

// Hybrid (P/E-core) bias. An E-core is treated as more loaded ONLY
// while a P-core still has spare capacity, so latency-sensitive
// Normal-band work fills idle P-cores first but E-cores are still
// used once every P-core is busy (no E-core starvation). Equal to
// kClusterPlacementMargin for the same no-oscillation equilibrium
// argument as the SMT penalty. Zero on non-hybrid machines (every
// core_class is kCoreClassUnknown), so the path is inert there.
constexpr u32 kHybridEcorePenalty = 2;

// True iff some online CPU is a P-core with an empty Normal queue.
bool IdlePerfCoreExists()
{
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 i = 0; i < limit; ++i)
    {
        const cpu::Topology* ti = cpu::TopologyForCpu(i);
        if (ti == nullptr || ti->core_class != cpu::kCoreClassPerf)
        {
            continue;
        }
        cpu::PerCpu* pi = arch::SmpGetPercpu(i);
        if (pi != nullptr && pi->runq_normal_len == 0)
        {
            return true;
        }
    }
    return false;
}

// Effective Normal-band load for placement/balance decisions: the
// raw runqueue length plus, independently:
//   * kSmtSiblingPenalty when an SMT sibling of `p` already has
//     Normal-band work, and
//   * kHybridEcorePenalty when `p` is an E-core and an idle P-core
//     is available.
// On non-SMT / non-hybrid / undecoded-topology CPUs neither
// predicate ever fires, the penalty is 0, and this returns
// p->runq_normal_len verbatim — so every caller stays byte-for-byte
// identical to the pre-topology scheduler on UMA / legacy boots.
u32 EffectiveLoad(cpu::PerCpu* p)
{
    const u32 base = p->runq_normal_len;
    const cpu::Topology* t = cpu::TopologyForCpu(p->cpu_id);
    if (t == nullptr)
    {
        return base;
    }

    u32 smt_penalty = 0;
    if (t->core_group != cpu::kTopologyUnknownCoreGroup && t->smt_sibling_count != 0)
    {
        const u32 limit = arch::SmpCpuIdLimit();
        for (u32 i = 0; i < limit; ++i)
        {
            if (i == p->cpu_id)
            {
                continue;
            }
            const cpu::Topology* st = cpu::TopologyForCpu(i);
            if (st == nullptr || st->core_group != t->core_group)
            {
                continue;
            }
            cpu::PerCpu* sib = arch::SmpGetPercpu(i);
            if (sib != nullptr && sib->runq_normal_len > 0)
            {
                smt_penalty = kSmtSiblingPenalty; // sibling busy
                break;
            }
        }
    }

    u32 hybrid_penalty = 0;
    if (t->core_class == cpu::kCoreClassEff && IdlePerfCoreExists())
    {
        hybrid_penalty = kHybridEcorePenalty;
    }

    return base + smt_penalty + hybrid_penalty;
}

// `t` (when non-null) lets the placement honor a hard affinity
// mask — peers the task may not run on are skipped. Callers that
// don't carry a task (e.g. the SMT self-test) pass nullptr and get
// the unfiltered behavior.
cpu::PerCpu* PickClusterPlacement(cpu::PerCpu* preferred, Task* t = nullptr)
{
    if (preferred == nullptr)
    {
        return nullptr;
    }
    if (preferred->runq_normal_len < kClusterPlacementMargin)
    {
        return preferred; // preferred CPU is light enough; keep affinity
    }
    const u16 cluster = preferred->cluster_id;
    const u32 limit = arch::SmpCpuIdLimit();
    cpu::PerCpu* best = preferred;
    u32 best_len = EffectiveLoad(preferred);
    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* peer = arch::SmpGetPercpu(i);
        if (peer == nullptr || peer == preferred)
        {
            continue;
        }
        if (!peer->online)
        {
            // Slot is allocated (visible to SmpGetPercpu) but the
            // AP hasn't signalled online yet — routing a wake here
            // would park the task on a runqueue nobody drains.
            // Belt-and-braces with the SmpStartAps `g_cpu_id_limit`
            // deferred-bump; either alone closes the 2026-05-22
            // SMP=8 `aps=?` race, both together survive a future
            // online-after-allocation reordering.
            continue;
        }
        if (peer->cluster_id != cluster)
        {
            continue; // cross-cluster routing handled by work-stealing
        }
        if (t != nullptr && !TaskAllowedOn(t, peer->cpu_id))
        {
            continue; // affinity mask forbids this CPU
        }
        const u32 peer_len = EffectiveLoad(peer);
        // `peer_len < best_len` first so the unsigned `best_len -
        // peer_len` only evaluates when it can't underflow (&& short-
        // circuits). The old operand order computed the wrapped
        // difference before the guard, a benign-result but real
        // unsigned underflow (-fsanitize=integer sub-overflow).
        if (peer_len < best_len && best_len - peer_len >= kClusterPlacementMargin)
        {
            best = peer;
            best_len = peer_len;
        }
    }
    return best;
}

// Convenience wrapper: route to the task's last_cpu (cache
// affinity), shifting to a less-loaded peer in the same cluster
// when last_cpu is busier than its neighbours by more than
// `kClusterPlacementMargin`. Used by every wake-side enqueue.
// When the target CPU is different from the current CPU, fire a
// reschedule-IPI so the peer notices the wake within microseconds
// rather than waiting up to one timer tick (10 ms) for its own
// preemption point.
void RunqueuePush(Task* t)
{
    cpu::PerCpu* preferred = TargetPerCpuFor(t);
    cpu::PerCpu* target = (t->priority == TaskPriority::Idle) ? preferred : PickClusterPlacement(preferred, t);
#if DUETOS_SCHED_ROUTING_TRACE
    // Flag-gated routing trace. Attributes the wake-side decision
    // (source CPU, last_cpu hint, preferred = TargetPerCpuFor's
    // pick, target = PickClusterPlacement's pick) so an SMP routing
    // regression — like the 2026-05-22 SmpStartAps-onto-offline-AP
    // hang — is one grep away in the log instead of an hour of
    // probe injection. Always DEBUG level so a release boot with
    // the flag forgotten on doesn't flood. Note: `target` may
    // legitimately be nullptr if every candidate failed the
    // affinity / online checks; the trace renders that as cpu=~0
    // so the line stays one-shot regardless.
    {
        cpu::PerCpu* self = cpu::CurrentCpu();
        const u32 self_id = (self != nullptr) ? self->cpu_id : 0xFFFFFFFFu;
        const u32 last_cpu = t->last_cpu;
        const u32 preferred_id = (preferred != nullptr) ? preferred->cpu_id : 0xFFFFFFFFu;
        const u32 target_id = (target != nullptr) ? target->cpu_id : 0xFFFFFFFFu;
        const char* prio = (t->priority == TaskPriority::Idle) ? "idle" : "normal";
        KLOG_DEBUG_V("sched/route", "wake src=", static_cast<u64>(self_id));
        KLOG_DEBUG_V("sched/route", "  last_cpu=", static_cast<u64>(last_cpu));
        KLOG_DEBUG_V("sched/route", "  preferred=", static_cast<u64>(preferred_id));
        KLOG_DEBUG_V("sched/route", "  target=", static_cast<u64>(target_id));
        KLOG_DEBUG_S("sched/route", "  task", "name", (t->name != nullptr) ? t->name : "<anon>");
        KLOG_DEBUG_S("sched/route", "  prio", "class", prio);
    }
#endif
    if (target != preferred)
    {
        // Routed away from last_cpu — update it so the next wake
        // starts from the new home rather than re-paying the
        // re-route cost on every wake. Affinity follows the
        // most recent dispatch, same contract as the work-
        // stealing path's `head->last_cpu = self_id` update.
        t->last_cpu = target->cpu_id;
    }
    RunqueuePushOn(target, t);
    cpu::PerCpu* self = cpu::CurrentCpu();
    if (self != nullptr && target != self)
    {
        arch::SmpSendReschedIpi(target->cpu_id);
    }
}

// Walk every Task on every CPU's runqueue (Normal then Idle band,
// per CPU). Caller holds g_sched_lock for the duration. The visitor
// returns true to stop early (used by find-by-pid / find-by-tid),
// false to continue. Helper return value mirrors that — true if any
// visit asked to stop. Centralises the per-CPU iteration so the
// rest of the file doesn't open-code `for (cpu_id = 0; ...) { for
// (Task* ...) }` everywhere.
template <typename F> bool ForEachRunqueueTask(F&& fn)
{
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p == nullptr)
        {
            continue;
        }
        for (Task* t = RunqHeadNormal(p); t != nullptr; t = t->next)
        {
            if (fn(t))
            {
                return true;
            }
        }
        for (Task* t = RunqHeadIdle(p); t != nullptr; t = t->next)
        {
            if (fn(t))
            {
                return true;
            }
        }
    }
    return false;
}

// Pops the highest-priority-available Ready task from THIS CPU's
// runqueue. Normal drains before Idle — an Idle task only runs
// when Normal is empty. Work-stealing across peer CPUs is a
// commit-6 follow-up; today an empty local runqueue means this
// CPU has no work and falls through to its idle task.
Task* RunqueuePop()
{
    // Dequeue funnel — same documented g_sched_lock precondition as
    // RunqueuePushOn; an unlocked pop races every concurrent push.
    sync::SpinLockAssertHeld(g_sched_lock);
    cpu::PerCpu* p = cpu::CurrentCpu();
    Task* t = RunqHeadNormal(p);
    if (t != nullptr)
    {
        RunqHeadNormal(p) = t->next;
        if (RunqHeadNormal(p) == nullptr)
        {
            RunqTailNormal(p) = nullptr;
        }
        t->next = nullptr;
        // Mirror the increment in RunqueuePushOn — Normal-band only.
        // KASSERT in case of double-pop / leak: a non-zero counter
        // should never go negative on a real pop path.
        KASSERT(p->runq_normal_len > 0, "sched", "RunqueuePop: normal_len underflow");
        --p->runq_normal_len;
        return t;
    }
    t = RunqHeadIdle(p);
    if (t != nullptr)
    {
        RunqHeadIdle(p) = t->next;
        if (RunqHeadIdle(p) == nullptr)
        {
            RunqTailIdle(p) = nullptr;
        }
        t->next = nullptr;
        return t;
    }
    return nullptr;
}

// Suspended-task list. Tasks here have suspend_count > 0 AND
// were popped off the runqueue (or rerouted from a wake path)
// because the scheduler refuses to dispatch them. Threaded on
// `Task::next` — a suspended task is on exactly this list, NOT
// on the runqueue / wait queue / sleep queue / zombies.
//
// Lifecycle:
//   - SchedSuspendTask increments the count. If the task is on
//     the runqueue, RunqueuePopRunnable will reroute it the next
//     time Schedule() runs. If it's Sleeping / Blocked, it stays
//     where it is — when it would otherwise be woken, the wake
//     path checks suspend_count and reroutes here.
//   - SchedResumeTask decrements. When it hits zero, the task
//     gets unlinked from this list and pushed onto the runqueue.
//
// Single-CPU correctness: no IPI needed because the SUSPENDER is
// the running task; the SUSPENDEE cannot also be running. A real
// SMP design needs an IPI to evict a target running on another
// core; that lands with the rest of the SMP scheduler work.
constinit Task* g_suspended_head = nullptr;
constinit Task* g_suspended_tail = nullptr;

void SuspendedListPush(Task* t)
{
    t->next = nullptr;
    if (g_suspended_tail == nullptr)
    {
        g_suspended_head = g_suspended_tail = t;
    }
    else
    {
        g_suspended_tail->next = t;
        g_suspended_tail = t;
    }
}

// Remove `t` from the suspended list. Returns true iff `t` was
// found and unlinked. O(N) walk — N stays tiny in practice (at
// most as many threads as a single process spawned).
bool SuspendedListRemove(Task* t)
{
    Task* prev = nullptr;
    for (Task* it = g_suspended_head; it != nullptr; prev = it, it = it->next)
    {
        if (it == t)
        {
            if (prev == nullptr)
            {
                g_suspended_head = it->next;
            }
            else
            {
                prev->next = it->next;
            }
            if (g_suspended_tail == it)
            {
                g_suspended_tail = prev;
            }
            it->next = nullptr;
            return true;
        }
    }
    return false;
}

// Lift one Normal-band Ready task off a peer CPU's runqueue.
// Called from RunqueuePopRunnable's empty-local-queue fallback.
// Walks peers in two passes: pass 0 visits only peers that share
// `self`'s cluster_id (NUMA node, or package on UMA boxes); pass 1
// covers cross-cluster peers. Within each pass, the same round-
// robin step starting from cpu_id+1 is preserved, so on a single-
// cluster system the behaviour is identical to the pre-clustering
// scheduler — pass 0 finds every peer, pass 1 finds none.
// Idle tasks are pinned per-CPU and never stolen.
//
// Caller must hold g_sched_lock — every per-CPU runqueue is
// covered by the same global lock today, so cross-CPU access
// is safe without try-lock dancing. When the lock granularity
// splits per-CPU later, this function will need try-lock + a
// fallback iteration order to avoid AB/BA deadlock.
Task* StealNormalFromPeer()
{
    // Cross-CPU runqueue mutator: reaches into a peer CPU's queue.
    // The "Caller must hold g_sched_lock" contract above is what
    // makes that safe today; enforce it rather than just document.
    sync::SpinLockAssertHeld(g_sched_lock);
    cpu::PerCpu* self = cpu::CurrentCpu();
    if (self == nullptr)
    {
        return nullptr;
    }
    const u32 limit = arch::SmpCpuIdLimit();
    if (limit <= 1)
    {
        return nullptr; // UP — no peers to steal from
    }
    const u32 self_id = self->cpu_id;
    const u16 self_cluster = self->cluster_id;
    for (int pass = 0; pass < 2; ++pass)
    {
        const bool same_cluster_only = (pass == 0);
        for (u32 step = 1; step < limit; ++step)
        {
            const u32 peer_id = (self_id + step) % limit;
            cpu::PerCpu* peer = arch::SmpGetPercpu(peer_id);
            if (peer == nullptr)
            {
                continue;
            }
            const bool same_cluster = (peer->cluster_id == self_cluster);
            if (same_cluster_only && !same_cluster)
            {
                continue;
            }
            if (!same_cluster_only && same_cluster)
            {
                continue; // already visited in pass 0
            }
            Task* head = RunqHeadNormal(peer);
            if (head == nullptr)
            {
                continue;
            }
            // Walk the peer's Normal queue looking for the first
            // task whose affinity mask allows execution on `self_id`.
            // The peer's head might be affinity-pinned away from us
            // (e.g. a worker pinned to a specific NUMA node); a
            // deeper task that IS allowed here should still be
            // stealable. Bounded walk caps worst-case time spent
            // here under a peer queue that's entirely pinned away —
            // kStealScanCap (32) covers the vast majority of real
            // queues; beyond that we accept "no steal this round"
            // and the next periodic balance picks up the slack.
            //
            // Single-pass: track `prev` so the chosen task can be
            // unlinked without re-walking. `prev == nullptr`
            // identifies the head case so the head pointer gets
            // updated.
            constexpr u32 kStealScanCap = 32;
            Task* prev = nullptr;
            Task* victim = nullptr;
            u32 scanned = 0;
            for (Task* t = head; t != nullptr && scanned < kStealScanCap; t = t->next, ++scanned)
            {
                if (TaskAllowedOn(t, self_id))
                {
                    victim = t;
                    break;
                }
                prev = t;
            }
            if (victim == nullptr)
            {
                // Every reachable task in this peer's queue is
                // affinity-pinned away from us (or the queue is
                // deeper than the scan cap). Try the next peer.
                continue;
            }
            // Unlink `victim` from the peer's queue.
            if (prev == nullptr)
            {
                // Head case — same fast-path as the original
                // implementation when the head is the chosen task.
                RunqHeadNormal(peer) = victim->next;
            }
            else
            {
                prev->next = victim->next;
            }
            if (RunqHeadNormal(peer) == nullptr)
            {
                RunqTailNormal(peer) = nullptr;
            }
            else if (victim == RunqTailNormal(peer))
            {
                // Stole the tail (a deeper-than-head allowed task
                // happened to be last in the queue). The new tail
                // is the predecessor we tracked.
                RunqTailNormal(peer) = prev;
            }
            victim->next = nullptr;
            KASSERT(peer->runq_normal_len > 0, "sched", "Steal: peer normal_len underflow");
            --peer->runq_normal_len;
            // Update affinity so the next wake routes to us — keeps
            // hot tasks on whichever CPU is actually running them.
            victim->last_cpu = self_id;
            return victim;
        }
    }
    return nullptr;
}

// Periodic active load balancer — pull-half.
//
// Distinct from `StealNormalFromPeer` (which fires only when the
// local runqueue is empty) and from `PickClusterPlacement` (which
// fires only on a wake-side enqueue). Periodic balance covers the
// remaining case: both CPUs have work, neither is going idle, and
// no new wake events are arriving — long-running compute tasks
// piled onto one CPU while a same-cluster peer has plenty of slack.
// Without this, a workload with N long-running threads spawned on
// one CPU never spreads even if N idle peers are available.
//
// Margin reasoning: `kBalanceMargin = 4` means a peer must have at
// least 4 more Normal-band Ready tasks than self before we migrate.
// Stealing one drops the delta to 2, which exactly equals
// `kClusterPlacementMargin` — the wake-placement floor. So the
// periodic balancer settles at the same equilibrium the wake-side
// code targets, with no further oscillation.
//
// Same-cluster only: cross-cluster work-stealing already covers
// the truly-idle peer; cross-cluster active migration costs more
// in cache miss than the imbalance saves. Cross-cluster steady-
// state imbalance is the operator's signal to call SchedSetAffinity,
// not the scheduler's to chase silently across NUMA nodes.
constexpr u32 kBalanceMargin = 4;
constexpr u64 kBalancePeriodTicks = 8; // 80 ms at 100 Hz — cheap enough every CPU.
constexpr u32 kBalanceNoVictim = ~0u;

// PowerSave stretches the active-balancer period by this factor:
// 8 → 32 ticks (320 ms). Fewer cross-CPU walks/migrations/IPIs on
// a battery box; the cost is slower load convergence, never wrong
// scheduling. Plain byte global (x86_64 byte load/store is atomic;
// this is a hint set rarely from one task, read on every tick —
// same racy-but-fine contract as g_total_ticks).
constexpr u64 kPowerSaveBalanceFactor = 4;
constinit u8 g_sched_power_bias = static_cast<u8>(PowerBias::Performance);

// Pure decision: returns the cpu_id of the heaviest same-cluster
// peer whose `runq_normal_len` strictly exceeds `self_len + margin
// - 1` (i.e. by at least `kBalanceMargin`). Returns `kBalanceNoVictim`
// if no peer qualifies (UP system, no same-cluster peer, every peer
// within the margin). Caller holds g_sched_lock so the per-CPU
// length snapshot is consistent with the runqueue contents.
u32 PickBalanceVictim(u32 self_cpu, u16 self_cluster, u32 self_len)
{
    const u32 limit = arch::SmpCpuIdLimit();
    if (limit <= 1)
    {
        return kBalanceNoVictim;
    }
    u32 best_id = kBalanceNoVictim;
    u32 best_len = self_len + kBalanceMargin - 1; // strictly-greater required
    for (u32 i = 0; i < limit; ++i)
    {
        if (i == self_cpu)
        {
            continue;
        }
        cpu::PerCpu* peer = arch::SmpGetPercpu(i);
        if (peer == nullptr)
        {
            continue;
        }
        if (peer->cluster_id != self_cluster)
        {
            continue;
        }
        // EffectiveLoad (not raw length) so an SMT-paired peer
        // looks heavier and is drained first — that is the
        // correct SMT-spreading direction. `self_len` stays raw
        // (caller passes runq_normal_len); the asymmetry is
        // deliberate and collapses to identity on non-SMT.
        const u32 peer_len = EffectiveLoad(peer);
        if (peer_len > best_len)
        {
            best_id = i;
            best_len = peer_len;
        }
    }
    return best_id;
}

// Lift one Normal-band Ready task off the heaviest qualifying peer
// and enqueue it on `self`. Returns the migrated Task* or nullptr
// when no peer is heavy enough. Caller holds g_sched_lock; mirrors
// `StealNormalFromPeer`'s pop/push contract exactly so the runqueue
// invariants (counter, tail pointer, intrusive-link nulling, affinity
// update) stay identical to the existing steal path.
Task* BalancePullOnce(cpu::PerCpu* self)
{
    // Cross-CPU runqueue mutator (mirrors StealNormalFromPeer's
    // pop/push contract). Same documented g_sched_lock precondition.
    sync::SpinLockAssertHeld(g_sched_lock);
    if (self == nullptr)
    {
        return nullptr;
    }
    const u32 victim_id = PickBalanceVictim(self->cpu_id, self->cluster_id, self->runq_normal_len);
    if (victim_id == kBalanceNoVictim)
    {
        return nullptr;
    }
    cpu::PerCpu* victim = arch::SmpGetPercpu(victim_id);
    if (victim == nullptr)
    {
        return nullptr; // PickBalanceVictim already filtered nulls; defensive belt
    }
    Task* head = RunqHeadNormal(victim);
    KASSERT(head != nullptr, "sched", "BalancePullOnce: victim normal_len > 0 but head null");
    if (!TaskAllowedOn(head, self->cpu_id))
    {
        // The heaviest peer's head is pinned away from us. Skip
        // this balance tick rather than migrate onto a forbidden
        // CPU. GAP: same head-only limitation as the steal path.
        return nullptr;
    }
    RunqHeadNormal(victim) = head->next;
    if (RunqHeadNormal(victim) == nullptr)
    {
        RunqTailNormal(victim) = nullptr;
    }
    head->next = nullptr;
    KASSERT(victim->runq_normal_len > 0, "sched", "BalancePullOnce: victim normal_len underflow");
    --victim->runq_normal_len;
    head->last_cpu = self->cpu_id;
    RunqueuePushOn(self, head);
    return head;
}

// IRQ-context hook fired from `OnTimerTick`. Phase-shifted per CPU
// so different CPUs don't all race for the same heaviest peer on
// the same tick. Pulls at most one task per tick — a heavily
// overloaded peer drains incrementally over multiple periods,
// which keeps the migration cost bounded even when several CPUs
// converge on it. No NeedResched flag: the migrated task lands
// at the tail of `self`'s runqueue and will be picked when the
// current task naturally yields or hits its tick budget; forcing
// a context switch here would add ping-pong without improving
// throughput.
//
// UP short-circuit BEFORE taking `g_sched_lock`: with one CPU there
// is no peer to migrate from, and the unnecessary acquire/release
// every `kBalancePeriodTicks` (12 Hz at 100 Hz/8) churns the lockdep
// held-stack (depth `kLockdepHeldMax = 8`) enough to surface stale
// overflow conditions long after boot. `SmpCpuIdLimit()` is a
// monotonically-stable u32 read once APs are up; safe lock-free.
void PeriodicBalanceTick()
{
    if (arch::SmpCpuIdLimit() <= 1)
    {
        return;
    }
    cpu::PerCpu* self = cpu::CurrentCpu();
    if (self == nullptr)
    {
        return;
    }
    sync::SpinLockGuard guard(g_sched_lock);
    (void)BalancePullOnce(self);
}

// Drain runqueue until a non-suspended task is found OR the
// runqueue is empty. Suspended tasks popped along the way are
// re-parked on g_suspended_head with state = Blocked. The wake
// path uses RunqueueOrSuspendPush below to skip the runqueue
// entirely for known-suspended tasks; this loop is the safety
// net for tasks suspended WHILE on the runqueue (Ready state),
// which the suspender doesn't relocate eagerly.
//
// On an empty local runqueue, attempts to steal one Normal-band
// task from a peer CPU (commit-6 work-stealing). Idle tasks are
// per-CPU and not eligible to steal — falling through to the
// caller's nullptr handling lets Schedule() pick our own idle.
Task* RunqueuePopRunnable()
{
    while (true)
    {
        Task* t = RunqueuePop();
        if (t == nullptr)
        {
            // Try to steal a Normal-band task from a peer before
            // giving up. If no peer has work, the caller falls
            // back to this CPU's idle.
            t = StealNormalFromPeer();
            if (t == nullptr)
            {
                return nullptr;
            }
            // Stolen task is Ready — same state contract as a
            // local pop. Fall through to the suspend check.
        }
        // Affinity backstop. Enqueue/steal/balance paths already
        // refuse to place a task on a forbidden CPU, but a runtime
        // SchedSetAffinityMask can narrow the mask AFTER the task
        // was queued here. Rather than run it on a now-forbidden
        // CPU, re-home it to an allowed one and keep draining.
        // Unrestricted tasks (the default) always pass, so this is
        // a no-op on the common path. GAP: a task that is already
        // *running* when its mask changes finishes its current
        // slice here; it migrates at its next reschedule, not
        // instantly (no cross-CPU preemption kick in v0).
        cpu::PerCpu* self = cpu::CurrentCpu();
        if (self != nullptr && !TaskAllowedOn(t, self->cpu_id))
        {
            cpu::PerCpu* tgt = TargetPerCpuFor(t);
            if (tgt != nullptr && tgt != self)
            {
                t->last_cpu = tgt->cpu_id;
                RunqueuePushOn(tgt, t);
                arch::SmpSendReschedIpi(tgt->cpu_id);
                continue;
            }
            // No distinct allowed CPU resolvable (shouldn't happen
            // for a validated mask) — fall through and run it here
            // rather than drop the task on the floor.
        }
        if (t->suspend_count == 0)
        {
            return t;
        }
        // Suspended task drained off the runqueue. Park it on
        // the suspended list; the resume path will move it back.
        t->state = TaskState::Blocked;
        SuspendedListPush(t);
    }
}

// Wake-path counterpart to RunqueuePush: route a newly-runnable
// task to either the runqueue (typical) or the suspended list
// (when its suspend_count is non-zero). Used by every site that
// transitions Sleeping/Blocked → Ready (timer wake, WaitQueue
// wake, the resume path's complement). The Ready vs. Blocked
// state is set inside this helper so callers don't have to
// branch on suspend_count themselves.
void RunqueueOrSuspendPush(Task* t)
{
    if (t->suspend_count != 0)
    {
        t->state = TaskState::Blocked;
        SuspendedListPush(t);
    }
    else
    {
        t->state = TaskState::Ready;
        RunqueuePush(t);
    }
}

void SleepqueueInsert(Task* t)
{
    t->sleep_next = nullptr;
    t->sleep_prev = nullptr;
    if (g_sleep_head == nullptr || t->wake_tick < g_sleep_head->wake_tick)
    {
        t->sleep_next = g_sleep_head;
        if (g_sleep_head != nullptr)
            g_sleep_head->sleep_prev = t;
        g_sleep_head = t;
        return;
    }

    Task* it = g_sleep_head;
    while (it->sleep_next != nullptr && it->sleep_next->wake_tick <= t->wake_tick)
    {
        it = it->sleep_next;
    }
    t->sleep_next = it->sleep_next;
    t->sleep_prev = it;
    if (it->sleep_next != nullptr)
        it->sleep_next->sleep_prev = t;
    it->sleep_next = t;
}

// Remove a task from the sleep queue. Used when an explicit wake
// beats the timer path for a timed waiter. O(1) via the
// sleep_prev back-pointer maintained by SleepqueueInsert; without
// it removal was an O(n) walk to find the predecessor.
void SleepqueueRemove(Task* t)
{
    Task* prev = t->sleep_prev;
    Task* next = t->sleep_next;
    if (prev != nullptr)
        prev->sleep_next = next;
    else if (g_sleep_head == t)
        g_sleep_head = next;
    if (next != nullptr)
        next->sleep_prev = prev;
    t->sleep_next = nullptr;
    t->sleep_prev = nullptr;
}

// Remove a task from a specific wait queue. Used when a timeout
// fires for a timed waiter and needs to detach from its wait
// queue before going onto the runqueue.
void WaitQueueUnlink(WaitQueue* wq, Task* t)
{
    if (wq->head == t)
    {
        wq->head = t->next;
        if (wq->head == nullptr)
        {
            wq->tail = nullptr;
        }
        t->next = nullptr;
        return;
    }

    Task* it = wq->head;
    while (it != nullptr && it->next != t)
    {
        it = it->next;
    }
    if (it != nullptr)
    {
        it->next = t->next;
        if (wq->tail == t)
        {
            wq->tail = it;
        }
    }
    t->next = nullptr;
}

// Wrap-safe tick deadline compare. Works as long as nobody sleeps for more
// than 2^63-1 ticks in one call (orders of magnitude beyond practical use).
DUETOS_NO_SANITIZE_WRAP bool TickReached(u64 now, u64 deadline)
{
    return static_cast<i64>(now - deadline) >= 0;
}

// Forward decl — defined in the wait-queue block further down.
// Schedule() needs it for the tick-budget kill path (it already
// holds g_sched_lock and can't call the non-_Locked variant that
// would re-acquire). Must be extern-linkage inside this anon
// namespace; the definition below has the same linkage.
Task* WaitQueueWakeOneLocked(WaitQueue* wq);

// Defined in context_switch.S. The first `ret` out of ContextSwitch for a
// freshly-created task lands here. Reads the entry function and argument
// from the callee-saved registers the SchedCreate stack primer planted
// there, calls the entry, and tail-calls SchedExitC if the entry ever
// returns (instead of faulting on garbage above the stack).
extern "C" void SchedTaskTrampoline();

// Extern "C" shim so the .S trampoline doesn't have to know C++ mangling.
extern "C" [[noreturn]] void SchedExitC();

} // namespace

// Linker-emitted bounds of the kernel `.text` section.
// SchedTaskTrampolineValidateEntry compares against these to catch a
// corrupted entry-function plant before the trampoline indirect-calls
// it. Declared file-scope C-linkage so the validator below can refer
// to them without re-importing through the anonymous namespace.
extern "C" duetos::u8 _text_start[];
extern "C" duetos::u8 _text_end[];

// Called from SchedTaskTrampoline (kernel/sched/context_switch.S) on
// the fresh-task first-run path, immediately before `call rbx` would
// dispatch the planted entry function. The caller passes rbx as `entry`
// — if it's not inside [_text_start, _text_end) the plant was
// corrupted (concurrent SchedCreate scribble, slot reuse without
// re-plant, slab class collision) and the impending indirect call
// would land at a wild address. The trap path can't attribute that
// fault back to the trampoline because the wild RIP is the only
// thing the iretq frame carries. Catching here names the offender
// (CPU, task ptr, planted entry, current rbp) and halts with a real
// banner. Observed 2026-05-22: ~1/10 SMP=8 boots hit a fresh AP
// idle's first dispatch with rbx pointing at low-id-map (0x101e) or
// .bss (0xffffffff8132axxx) on the panicking CPU.
extern "C" void SchedTaskTrampolineValidateEntry(void* entry)
{
    using namespace duetos;
    const u64 fn = reinterpret_cast<u64>(entry);
    const u64 lo = reinterpret_cast<u64>(_text_start);
    const u64 hi = reinterpret_cast<u64>(_text_end);
    if (fn >= lo && fn < hi)
        return;
    KBP_PROBE_V(::duetos::debug::ProbeId::kSchedTrampolineWildEntry, fn);
    arch::SerialWrite("[sched/trampoline] WILD entry fn — refusing dispatch  cpu=");
    arch::SerialWriteHex(cpu::CurrentCpuIdOrBsp());
    arch::SerialWrite("  task=");
    {
        sched::Task* self = sched::Current();
        arch::SerialWriteHex(reinterpret_cast<u64>(self));
        if (self != nullptr)
        {
            arch::SerialWrite("  id=");
            arch::SerialWriteHex(self->id);
            arch::SerialWrite("  name=\"");
            arch::SerialWrite(self->name != nullptr ? self->name : "<null>");
            arch::SerialWrite("\"");
        }
    }
    arch::SerialWrite("  entry=");
    arch::SerialWriteHex(fn);
    arch::SerialWrite("  text=[");
    arch::SerialWriteHex(lo);
    arch::SerialWrite("..");
    arch::SerialWriteHex(hi);
    arch::SerialWrite(")\n");
    core::PanicWithValue("sched/trampoline", "planted entry function out of kernel text range", fn);
}

// Lock-pass drain. Called from two places:
//   1. Schedule(), immediately after ContextSwitch returns (we're on
//      the resumed task's stack).
//   2. SchedTaskTrampoline (context_switch.S), as the first instruction
//      a fresh task ever runs — before the entry function fires.
//
// Reads this CPU's PerCpu slot — written by the source side of the
// switch under g_sched_lock — and releases the lock with the saved
// IRQ flags. The slot is per-CPU because it identifies "the lock THIS
// CPU just acquired in Schedule()"; the resumed task is irrelevant to
// the release decision. nullptr slot = nothing to release (a fresh AP
// joining the scheduler hits this path with the slot still cleared
// from PerCpuInitBsp / SmpStartAps initialisation).
extern "C" void SchedFinishTaskSwitch()
{
    cpu::PerCpu* pcpu = cpu::CurrentCpu();
    void* lock_ptr = pcpu->ctxsw_lock_to_release;
    if (lock_ptr == nullptr)
    {
        // Fresh AP joining the scheduler: per-CPU / current_task not
        // yet armed, nothing to release, no held set to restore.
        // Attempt 1 ran the lockdep restore ABOVE this guard and an
        // intermittent AP-bringup race faulted inside Current() on
        // the not-yet-established PerCpu (Roadmap: "Lockdep held-set
        // must be per-task" attempt 1, reverted). Past this point
        // pcpu is established (the existing release code below relies
        // on exactly that) and lock_ptr == &g_sched_lock, i.e. a
        // real task is resuming.
        //
        // BEFORE returning, mark current_task (if any) as past first-
        // run. The trampoline-first-entry path on a fresh AP idle
        // arrives here with no lock-pass slot and would otherwise
        // leave first_run=true forever — the proactive rbx-slot
        // validator would then false-fire on the idle task's SECOND
        // switch-in (slot already consumed by the first run, content
        // is general stack memory). Idempotent on resume (already
        // false).
        if (pcpu->current_task != nullptr)
            pcpu->current_task->first_run = false;
        return;
    }
    // Reinstate THIS task's lockdep held set BEFORE the
    // SpinLockRelease below — it calls LockdepBeforeRelease and
    // pops kLockClassSched, which must come off this task's set
    // (fresh tasks are seeded with [kLockClassSched]; resumed
    // tasks snapshotted it in Schedule()). Validate Running state:
    // a non-NULL-but-non-Running current_task on a perturbed
    // AP-bringup path must not touch the held stack (the attempt-1
    // WaitQueueBlock-on-non-Running assert).
    {
        Task* self = pcpu->current_task;
        if (self != nullptr && self->state == TaskState::Running)
            ::duetos::sync::LockdepHeldRestore(self->lockdep_held, self->lockdep_held_depth);
        // Trampoline first-entry consumed the planted SchedCreate
        // stack frame — past this point, slot_top-16 (rbx slot) and
        // slot_top-24 (rbp slot) are general stack memory and the
        // proactive validator in ScheduleLockedHandoff stops looking
        // at them. Idempotent on resume (already false). Lives here
        // and not later in the function so an early-return path
        // before the SpinLockRelease can't leave it stuck-true; lives
        // INSIDE the `current_task != nullptr` arm so the fresh-AP
        // early-return path (no current_task) doesn't NPE.
        if (self != nullptr)
            self->first_run = false;
    }
    sync::IrqFlags flags{.rflags = pcpu->ctxsw_lock_flags};
    pcpu->ctxsw_lock_to_release = nullptr;
    pcpu->ctxsw_lock_flags = 0;
    sync::SpinLockRelease(*static_cast<sync::SpinLock*>(lock_ptr), flags);

    // SMP-safe zombie handoff. If the task we just switched AWAY
    // from called `SchedExit`, it deferred its zombie-push to here
    // — by now `ContextSwitch` has fully committed the rsp swap
    // and the dying task is provably off-CPU on every peer, so the
    // reaper can safely `FreeKernelStack` its pages. See
    // `SchedExit`'s comment for the race this closes (SMP=8
    // saturation UAF at RIP=0xdedede...).
    //
    // Acquire `g_sched_lock` for the list mutation + waitqueue
    // wake — same lock the rest of the scheduler holds for these
    // operations. The lock was released a few lines up via
    // `SpinLockRelease`, so we're not nested; this re-acquire is
    // legal.
    Task* dying = static_cast<Task*>(pcpu->ctxsw_dying_task_to_zombie);
    if (dying != nullptr)
    {
        pcpu->ctxsw_dying_task_to_zombie = nullptr;
        sync::SpinLockGuard guard(g_sched_lock);
        dying->next = g_zombies;
        g_zombies = dying;
        WaitQueueWakeOneLocked(&g_reaper_wq);
    }
}

void SchedInit()
{
    KLOG_TRACE_SCOPE("sched", "SchedInit");
    KLOG_INFO("sched", "SchedInit: bringing scheduler online");
    auto* boot_task = static_cast<Task*>(mm::KMalloc(sizeof(Task)));
    if (boot_task == nullptr)
    {
        KLOG_ERROR("sched", "SchedInit: KMalloc failed for boot task");
        PanicSched("KMalloc failed for boot task");
    }
    // Zero the struct before any field assignment. Same reasoning
    // as ProcessCreate / AddressSpaceCreate: KMalloc returns memory
    // post-C2-frame-poison (0xDE bytes) and the explicit field
    // assignments below don't cover every field — anything left
    // unset would carry the poison and dereference garbage.
    memset(boot_task, 0, sizeof(Task));

    boot_task->id = g_next_task_id++;
    boot_task->state = TaskState::Running;
    boot_task->rsp = 0; // populated on first context switch out
    boot_task->stack_base = nullptr;
    boot_task->stack_size = 0;
    boot_task->wake_tick = 0;
    boot_task->name = "kboot";
    boot_task->next = nullptr;
    boot_task->sleep_next = nullptr;
    boot_task->sleep_prev = nullptr;
    boot_task->waiting_on = nullptr;
    boot_task->wake_by_timeout = false;
    boot_task->priority = TaskPriority::Normal;
    boot_task->as = nullptr;                         // kernel AS — boot PML4
    boot_task->process = nullptr;                    // kernel-only — no owning process
    boot_task->kill_requested = false;               // kernel tasks never hit a budget
    boot_task->kill_reason = KillReason::TickBudget; // unused when kill_requested=false
    boot_task->suspend_count = 0;                    // boot/kernel tasks never get suspended
    boot_task->win32_last_error = 0;                 // ERROR_SUCCESS, per-thread Win32 slot
    boot_task->last_cpu = cpu::CurrentCpu()->cpu_id; // BSP pin — boot task only ever runs here
    boot_task->affinity_mask = kAffinityAll;         // unrestricted by default
    // Boot task is the currently-running task on this CPU from the
    // moment SchedInit returns. Mark on_cpu=1 so the adaptive-mutex
    // slow path on a peer CPU sees the correct state if it observes
    // the boot task as a mutex holder before the first real context
    // switch flips the flag. RELEASE pairs with the ACQUIRE the
    // slow path uses to read.
    __atomic_store_n(&boot_task->on_cpu, 1u, __ATOMIC_RELEASE);

    Current() = boot_task;
    SchedCpuIncCreated();
    SchedCpuIncLive();

    SerialWrite("[sched] online; task 0 is \"kboot\"\n");
    KLOG_INFO("sched", "online; task 0 is kboot");
}

namespace
{

// Shared body for SchedCreate / SchedCreateUser. The only difference
// between the two callers is the task's address space (kernel-only
// tasks pass nullptr; ring-3-bound tasks pass a freshly-created AS)
// and whether they own a Process (kernel-only: nullptr; user tasks:
// the caller-supplied Process). `process` MUST be assigned before
// the runqueue push — once the task is enqueued, a preemption on
// another CPU (or, with LAPIC timer preemption, even the same CPU)
// can pull it off the queue and start running it. If `t->process`
// is still nullptr at that point, Ring3UserEntry's `CurrentProcess()`
// returns null and panics with "Ring3UserEntry without a Process".
Task* SchedCreateInternal(TaskEntry entry, void* arg, const char* name, TaskPriority priority, mm::AddressSpace* as,
                          core::Process* process = nullptr)
{
    KASSERT(entry != nullptr, "sched", "SchedCreate null entry fn");
    KASSERT(name != nullptr, "sched", "SchedCreate null name");

    auto* t = static_cast<Task*>(mm::KMalloc(sizeof(Task)));
    if (t == nullptr)
    {
        // Debug: panic — fail loud so the OOM is impossible to
        // miss during development. Release: log it and return
        // nullptr; SchedCreate's signature is already nullable
        // and every existing caller fire-and-forgets the result.
        // A failed worker thread is preferable to a halted box.
        core::DebugPanicOrWarn("sched", "KMalloc failed for Task");
        return nullptr;
    }
    // Zero the struct first; explicit assignments below overwrite the
    // fields we care about, but any field NOT covered would otherwise
    // read 0xDE-byte freed-page poison.
    memset(t, 0, sizeof(Task));

    // Kernel stacks come from the guard-paged arena, not the heap:
    // a 4 KiB unmapped page sits just below every slot's usable
    // range so overflow #PFs immediately instead of scribbling the
    // next heap chunk. See mm/kstack.h for the arena layout.
    static_assert(kKernelStackBytes == mm::kKernelStackUsableBytes,
                  "sched kernel stack size must match kstack arena slot");
    auto* stack = static_cast<u8*>(mm::AllocateKernelStack(kKernelStackBytes));
    if (stack == nullptr)
    {
        // Same shape as the Task-alloc failure above. The Task
        // struct was just allocated; KFree it before returning so
        // we don't leak on the release path.
        core::DebugPanicOrWarn("sched", "AllocateKernelStack failed for kernel stack");
        mm::KFree(t);
        return nullptr;
    }

    // Plant the canary at the low edge of the (usable) stack BEFORE
    // priming the entry frame at the top. The guard page sits below
    // THIS address; a spill that reaches the canary but not the guard
    // page is an unlikely large-frame-skip but cheap to keep covered.
    *reinterpret_cast<u64*>(stack) = kStackCanary;

    t->id = g_next_task_id++;
    t->state = TaskState::Ready;
    t->first_run = true; // SchedFinishTaskSwitch flips this to false on first entry
    t->stack_base = stack;
    t->stack_size = kKernelStackBytes;
    t->wake_tick = 0;
    t->name = name;
    t->next = nullptr;
    t->sleep_next = nullptr;
    t->sleep_prev = nullptr;
    t->waiting_on = nullptr;
    t->wake_by_timeout = false;
    t->priority = priority;
    t->as = as;
    t->process = process; // user tasks: caller's Process; kernel tasks: nullptr
    t->kill_requested = false;
    t->kill_reason = KillReason::TickBudget;
    t->ticks_run = 0;
    t->schedin_tick = 0;
    t->win32_last_error = 0; // ERROR_SUCCESS, per-thread Win32 slot
    t->fs_base = 0;
    t->user_gs_base_override = 0;
    t->seh_last_rip = 0;
    t->seh_repeat = 0;
    t->_pad_seh = 0;
    t->irq_depth = 0;
    // No breakpoints on a fresh task. DR7 = 0 disables every slot
    // (the architecture's MBS bit 10 flips to 1 on the first real
    // install via the breakpoint manager — at that point DR7 is
    // no longer zero and the load on next context-switch-in will
    // carry the real value).
    t->dr0 = 0;
    t->dr1 = 0;
    t->dr2 = 0;
    t->dr3 = 0;
    t->dr7 = 0;
    t->suspend_count = 0;
    // Default affinity: spawn on the spawning CPU. The wake path
    // routes via this field; first ContextSwitch into the task
    // updates it to whichever CPU actually picks the task off the
    // runqueue (in v0 same as spawn CPU since tasks don't migrate
    // until commit-6 work-stealing).
    t->last_cpu = cpu::CurrentCpu()->cpu_id;
    // Default: no affinity restriction. SchedSetAffinityMask /
    // the Linux sched_setaffinity thunk narrow this later.
    t->affinity_mask = kAffinityAll;

    // Seed the lockdep held set with the scheduler lock. This task
    // will first run at SchedTaskTrampoline -> SchedFinishTaskSwitch,
    // which releases the g_sched_lock the launching Schedule()
    // acquired on its behalf (the lock-pass handshake). Modelling
    // the fresh task as already "holding" kLockClassSched makes
    // that first release balanced — without this the release would
    // hit an empty held set and (harmlessly but noisily) WARN
    // "release with no matching held entry" once per task spawn.
    t->lockdep_held[0] = ::duetos::sync::kLockClassSched;
    t->lockdep_held_depth = 1;

    // Build the initial stack. ContextSwitch pops r15, r14, r13, r12,
    // rbp, rbx and then rets. So from bottom to top of the pre-planted
    // stack we need:
    //   r15 = 0
    //   r14 = 0
    //   r13 = 0
    //   r12 = 0
    //   rbp = arg                     (trampoline consumes as rdi)
    //   rbx = entry                   (trampoline calls as rbx)
    //   return address = SchedTaskTrampoline
    //
    // Stack-alignment contract (SysV x86-64): a `call` must execute
    // with RSP % 16 == 0 so the callee is entered at RSP % 16 == 8.
    // `SchedTaskTrampoline` is hand-written asm with NO realigning
    // prologue — its first instruction after `endbr64` is a `call`.
    // It must therefore be ENTERED with RSP % 16 == 0. ContextSwitch
    // pops 6 quads (r15,r14,r13,r12,rbp,rbx) then `ret`s (a 7th pop)
    // — an odd number of quads — so the trampoline is entered with
    // the same 16-alignment phase the planted `ret`-target quad sits
    // at. We align the top of stack to 16 and push an EVEN number of
    // quads below the ret target (ret-target + 6 saved regs = 7;
    // the ret-target quad itself lands on a 16-aligned slot). An
    // extra "alignment pad" quad here would invert the phase: the
    // trampoline would be entered at RSP % 16 == 8 and its `call`s
    // would violate the ABI, leaving every task entry (and its whole
    // call tree) 8 bytes out of phase — every 16-aligned stack local
    // misaligned. (That was a real bug: UBSan misalign flood from
    // TrayFlyoutRedraw's `Row rows[6]` on every compose with the
    // tray flyout open.) So: NO pad quad.
    u8* sp = stack + kKernelStackBytes;
    // 16-byte align the top of the stack.
    sp = reinterpret_cast<u8*>(reinterpret_cast<uptr>(sp) & ~uptr{15});

    auto push_quad = [&](u64 value)
    {
        sp -= sizeof(u64);
        *reinterpret_cast<u64*>(sp) = value;
    };

    push_quad(reinterpret_cast<u64>(&SchedTaskTrampoline)); // ret target
    push_quad(reinterpret_cast<u64>(entry));                // rbx
    push_quad(reinterpret_cast<u64>(arg));                  // rbp
    push_quad(0);                                           // r12
    push_quad(0);                                           // r13
    push_quad(0);                                           // r14
    push_quad(0);                                           // r15

    t->rsp = reinterpret_cast<u64>(sp);

    {
        sync::SpinLockGuard guard(g_sched_lock);
        RunqueuePush(t);
        SchedCpuIncCreated();
        SchedCpuIncLive();
    }

    // Multi-write sentinel — bracket so two concurrent SchedCreates
    // on different CPUs don't split each other's lines at the UART
    // (observed under SMP=8 stress as
    // `[sched] created task id=[sched] created task id=0x...0x...
    // name="" name=""`).
    {
        arch::SerialLineGuard guard;
        SerialWrite("[sched] created task id=");
        SerialWriteHex(t->id);
        SerialWrite(" name=\"");
        SerialWrite(name);
        SerialWrite("\" rsp=");
        SerialWriteHex(t->rsp);
        SerialWrite(" as=");
        SerialWriteHex(reinterpret_cast<u64>(as));
        SerialWrite("\n");
    }

    return t;
}

} // namespace

Task* SchedCreate(TaskEntry entry, void* arg, const char* name, TaskPriority priority)
{
    KLOG_INFO_S("sched", "SchedCreate: kernel task", "name", name);
    // Name-based security gate. No image bytes to scan at this
    // layer — that happens in the loader before entry is ever
    // handed to the scheduler — so this catches only filename
    // denylist hits. Returns a null Task if the guard denies.
    if (!duetos::security::GateThread(duetos::security::ImageKind::KernelThread, name))
    {
        KLOG_WARN_S("sched", "SchedCreate denied by image guard", "name", name);
        return nullptr;
    }
    return SchedCreateInternal(entry, arg, name, priority, /*as=*/nullptr);
}

Task* SchedCreateUser(TaskEntry entry, void* arg, const char* name, core::Process* process)
{
    KLOG_INFO_S("sched", "SchedCreateUser: ring-3 task", "name", name);
    KASSERT(process != nullptr, "sched", "SchedCreateUser without Process");
    KASSERT(process->as != nullptr, "sched", "SchedCreateUser Process has no AS");

    if (!duetos::security::GateThread(duetos::security::ImageKind::UserThread, name))
    {
        // The caller handed us its Process reference expecting
        // the Task to absorb it. No Task was created — the ref
        // would leak (AS + Process struct + PID slot held forever)
        // unless we release it here on the gate-denial exit path.
        KLOG_WARN_S("sched", "SchedCreateUser denied by image guard", "name", name);
        core::ProcessRelease(process);
        return nullptr;
    }

    // Hand `process` to the internal helper so `t->process` is set
    // BEFORE the runqueue push. A post-push assignment loses to a
    // preemption that pulls the new task off the runqueue between
    // SchedCreateInternal returning and the assignment landing —
    // the new task then enters Ring3UserEntry, hits the
    // `CurrentProcess() == nullptr` gate, and panics.
    Task* t = SchedCreateInternal(entry, arg, name, TaskPriority::Normal, process->as, process);
    if (t == nullptr)
    {
        // SchedCreateInternal failed (Task/kstack OOM — warn, not
        // panic, in release). The caller handed us its Process ref
        // expecting the Task to absorb it; no Task exists to do so,
        // so release it here or the whole AS + Process + PID slot
        // leaks forever — and the trigger is memory pressure, so the
        // leak would compound the very condition that caused it.
        KLOG_WARN_S("sched", "SchedCreateUser: task alloc failed, releasing process ref", "name", name);
        core::ProcessRelease(process);
        return nullptr;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kRing3Spawn, process->pid);
    // Refcount discipline: ProcessCreate returned refcount=1 (one
    // for the creating caller). The caller hands that reference off
    // to this Task — no retain needed. Subsequent Tasks that want
    // to share the Process (future thread spawn) must ProcessRetain
    // before calling SchedCreateUser with an already-owned process.
    return t;
}

core::Process* TaskProcess(Task* t)
{
    if (t == nullptr)
    {
        return nullptr;
    }
    return t->process;
}

bool SchedSehDeliveryAllowed(Task* t, u64 fault_rip)
{
    // Backstop bound on consecutive kernel SEH deliveries at the
    // SAME faulting instruction. An *unhandled* exception already
    // terminates in user mode (KiUserExceptionDispatcher's
    // no-handler path calls SYS_EXIT), so this guard is not what
    // ends a normal unhandled fault — it only catches the
    // pathological case where the dispatcher / RtlRestoreContext
    // ITSELF faults (broken ntdll, corrupt user stack): that loop
    // re-faults at one constant RIP as fast as the CPU spins and
    // blows the bound in microseconds. A legitimate program that
    // faults-and-handles at the same RIP does real work between
    // faults and recurs far slower, so a high bound never trips on
    // it (the seh_pe veh-repeatable case does 3). A distinct fault
    // RIP resets the counter.
    static constexpr u32 kSehMaxRepeat = 4096;
    if (t == nullptr)
    {
        return false;
    }
    if (fault_rip == t->seh_last_rip)
    {
        ++t->seh_repeat;
    }
    else
    {
        t->seh_last_rip = fault_rip;
        t->seh_repeat = 0;
    }
    return t->seh_repeat < kSehMaxRepeat;
}

void SchedSetUserGsOverride(Task* t, u64 gs_base)
{
    if (t == nullptr)
    {
        return;
    }
    t->user_gs_base_override = gs_base;
}

bool TaskIsDead(const Task* t)
{
    return t != nullptr && t->state == TaskState::Dead;
}

bool TaskIsOnCpu(const Task* t)
{
    if (t == nullptr)
    {
        return false;
    }
    // Read with ACQUIRE so a peer CPU spinning on this flag pairs
    // cleanly with the RELEASE-store the context-switch path
    // performs around the same `next->state = Running` /
    // `prev->state = Ready` transitions. AdaptiveMutex's slow path
    // is the dominant caller.
    return __atomic_load_n(&t->on_cpu, __ATOMIC_ACQUIRE) != 0;
}

arch::TrapFrame* SchedFindUserTrapFrame(Task* t)
{
    // Locate the outermost user→kernel TrapFrame on a target's
    // kernel stack. This is the frame the CPU pushed when the
    // task last entered the kernel (timer preemption / int 0x80
    // syscall / page fault from user mode). RSP0 was set by
    // Schedule() to (stack_base + stack_size) on every switch-
    // in, so the CPU's first push lands at exactly that address
    // minus 40 bytes (ss/rsp/rflags/cs/rip), then the per-vector
    // stub pushes vector + error_code (16 bytes) and isr_common
    // pushes 15 GPRs (120 bytes). Total = sizeof(TrapFrame) =
    // 176 bytes. That bottom of the trap frame is the highest
    // possible TrapFrame* on the stack.
    //
    // Returns nullptr when:
    //   - the target has no kernel stack (boot / idle task);
    //   - the target never entered user mode (cs at the
    //     reserved offset has RPL != 3 — uninitialised garbage
    //     OR a frame from a kernel-mode trap delivered before
    //     any user-mode entry happened);
    //   - the target's stack_size is too small to hold the
    //     frame (a corrupted Task struct).
    //
    // Single-CPU correctness: the caller is the running task,
    // so the target is by construction NOT running and its
    // kernel stack is quiescent. On SMP, the IPI dance that
    // evicts a target from another core would need to fence
    // any pending stack writes before this read; that's a
    // follow-up.
    if (t == nullptr || t->stack_base == nullptr)
    {
        return nullptr;
    }
    if (t->stack_size < sizeof(arch::TrapFrame))
    {
        return nullptr;
    }
    const u64 stack_top = reinterpret_cast<u64>(t->stack_base) + t->stack_size;
    auto* tf = reinterpret_cast<arch::TrapFrame*>(stack_top - sizeof(arch::TrapFrame));
    // RPL == 3 confirms the frame came from a user→kernel
    // entry. Any other value (0 = ring 0, garbage from an
    // uninitialised stack region) means there is no valid
    // user CONTEXT to read or write.
    if ((tf->cs & 0x3) != 0x3)
    {
        return nullptr;
    }
    return tf;
}

void FlagCurrentForKill(KillReason reason)
{
    Task* t = Current();
    if (t == nullptr)
    {
        return;
    }
    // Schedule() converts (kill_requested == true) on re-enqueue
    // into a Dead transition. The reason is logged there.
    // Setting the flag is atomic from this context (single-CPU,
    // same core). On SMP the flag is per-task, so only this CPU's
    // Schedule() reads it for this task.
    t->kill_requested = true;
    t->kill_reason = reason;
    NeedResched() = true;
}

const char* KillReasonName(KillReason r)
{
    switch (r)
    {
    case KillReason::TickBudget:
        return "TickBudget";
    case KillReason::SandboxDenialThreshold:
        return "SandboxDenialThreshold";
    case KillReason::UserKill:
        return "UserKill";
    case KillReason::FsWriteRateExceeded:
        return "FsWriteRateExceeded";
    case KillReason::CanaryFileTouched:
        return "CanaryFileTouched";
    case KillReason::PersistenceDrop:
        return "PersistenceDrop";
    default:
        KLOG_ONCE_WARN("sched", "KillReasonName: unrecognised KillReason enumerator");
        return "<unknown>";
    }
}

// Core scheduler step with g_sched_lock ALREADY HELD by the caller
// (lock_flags is the value the caller's SpinLockAcquire returned).
// Defined immediately after Schedule(); forward-declared here so
// Schedule() and the blocking primitives below can route through it.
void ScheduleLockedHandoff(sync::IrqFlags lock_flags);

void Schedule()
{
    KPATH_HOT(Manual, "sched.schedule.entry");
    if (Current() == nullptr)
    {
        // pre-SchedInit timer tick (shouldn't happen, but be safe).
        // Log once so a recurring null-current pattern is visible
        // without burying the boot log in tick-rate spam.
        KPATH(Branch, "sched.schedule.no_current");
        KLOG_ONCE_WARN("sched", "Schedule called with no current task (pre-SchedInit?)");
        return;
    }

    // Acquire the scheduler lock manually (rather than via SpinLockGuard)
    // so we can hand it off across ContextSwitch — see the lock-passing
    // dance below. The lock covers the pick + state transitions; all
    // per-CPU register handoffs (TSS.RSP0, AS activate, FS_BASE, IRQ
    // depth, DR*) can correctly run while it's held.
    sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_sched_lock);
    ScheduleLockedHandoff(lock_flags);
}

// Same scheduler step as Schedule(), but the caller already holds
// g_sched_lock (and passes the flags its SpinLockAcquire returned).
// This is the SMP-correct blocking primitive: a task that wants to
// sleep marks itself Blocked + enqueues onto its wait queue AND
// deschedules under ONE continuous g_sched_lock hold — no gap. The
// old `{ SpinLockGuard g(g_sched_lock); enqueue; } Schedule();`
// shape released the lock between the enqueue and Schedule()'s
// re-acquire; on SMP a peer CPU could pop+wake the task into a
// runqueue in that gap, and a third CPU could then dispatch it
// while it was still executing this stack — two live copies of one
// task, surfacing as intermittent MUTEX-NONOWNER / sched-class
// spinlock self-deadlock (reliably reproduced by tools/qemu/
// gui-fuzz.sh). The lock rides the existing ctxsw_lock_to_release
// hand-off and is dropped by SchedFinishTaskSwitch on the resumed
// task, exactly as for a Schedule()-initiated switch.
void ScheduleLockedHandoff(sync::IrqFlags lock_flags)
{
    Task* prev = nullptr;
    Task* next = nullptr;

    next = RunqueuePopRunnable();
    if (next == nullptr)
    {
        if (Current()->state != TaskState::Running)
        {
            // Last-resort fallback: this CPU's idle task is always
            // available, even when the runqueue's Idle band has
            // momentarily emptied. The race we close: a polling
            // task (e1000-rx-poll, mock-isp-pump, reaper) wakes on
            // an AP, runs briefly, calls SchedSleepTicks; between
            // the previous Schedule() popping idle and the next
            // preemption re-enqueueing the previous task, the
            // runqueue can show all-empty. Without this fallback
            // we'd panic "no runnable task available" — observed
            // intermittently under SMP (~3/10 debug-preset boots).
            cpu::PerCpu* self = cpu::CurrentCpu();
            Task* idle = (self != nullptr) ? self->idle_task : nullptr;
            // One-line probe (raw serial, lock-safe) before deciding
            // whether to dispatch idle or escalate to panic. Lets a
            // post-mortem distinguish "fallback fired" (idle dispatched
            // silently — no log) from "fallback whiffed" (one of the
            // guards rejected the idle pointer — line emitted).
            if (idle == nullptr || idle == Current() || idle->state == TaskState::Dead)
            {
                // Diagnostic line so the AP-bringup race window is
                // visible in the boot log (the standard fallback below
                // is silent on the happy path). Captures the failing
                // CPU's `self`, its idle pointer, and the offending
                // state — exactly the four values needed to tell
                // "idle_task was never published" from "idle drifted
                // to Dead" from "current is idle and we'd loop". Do
                // NOT attempt a foreign-CPU idle here: idle tasks own
                // their home CPU's stack (per CLAUDE.md "Idle tasks
                // are per-CPU and not eligible to steal"), and
                // dispatching one across CPUs reproduces the SMP
                // double-run + DEBUG_ASSERT chain that the per-CPU
                // pinning fixes in the first place.
                arch::SerialWrite("[sched-fallback] no idle available — self=");
                arch::SerialWriteHex(reinterpret_cast<u64>(self));
                arch::SerialWrite(" cpu_id=");
                arch::SerialWriteHex(self != nullptr ? static_cast<u64>(self->cpu_id) : 0xFFFFFFFFu);
                arch::SerialWrite(" idle=");
                arch::SerialWriteHex(reinterpret_cast<u64>(idle));
                arch::SerialWrite(" idle_state=");
                arch::SerialWriteHex(idle != nullptr ? static_cast<u64>(idle->state) : 0xFFFFFFFFu);
                arch::SerialWrite(" cur=");
                arch::SerialWriteHex(reinterpret_cast<u64>(Current()));
                arch::SerialWrite("\n");
                sync::SpinLockRelease(g_sched_lock, lock_flags);
                PanicSched("no runnable task available");
            }
            // Standard fallback: dispatch this CPU's own idle. The
            // idle task may have been popped earlier (state Running
            // or Ready depending on where the scheduler last left
            // it). Force it to Ready so the rest of the handoff
            // sees a clean state machine; the bottom of this
            // function flips it to Running.
            idle->state = TaskState::Ready;
            next = idle;
        }
        else
        {
            sync::SpinLockRelease(g_sched_lock, lock_flags);
            return;
        }
    }
    // Invariant: a task pulled off the runqueue should have been
    // Ready (the only state push paths normally set). Historically
    // this was a DEBUG_ASSERT-panic, which intermittently fired in
    // the SMP AP-join tail (~20% of debug boots): a peer CPU's
    // tick-wake / steal / load-balance can briefly observe a task
    // with stale state between push and the subsequent state
    // transition. The dispatch path below force-writes state to
    // Running unconditionally, so the bad-state observation is
    // cosmetic for the actual switch — but a panic in debug builds
    // breaks the boot.
    //
    // Self-heal: log a one-line WARN with enough detail (task id,
    // name, observed state) to localise the upstream offender on a
    // future debug session, force state to Ready so the dispatcher's
    // book-keeping stays internally consistent, and continue. The
    // release build was already doing exactly this silently.
    if (__builtin_expect(next->state != TaskState::Ready, 0))
    {
        arch::SerialWrite("[sched] WARN: popped task not Ready; state=");
        arch::SerialWriteHex(static_cast<u64>(next->state));
        arch::SerialWrite(" id=");
        arch::SerialWriteHex(next->id);
        arch::SerialWrite(" name=\"");
        arch::SerialWrite(next->name != nullptr ? next->name : "<unknown>");
        arch::SerialWrite("\" cpu=");
        cpu::PerCpu* dbg_self = cpu::CurrentCpu();
        arch::SerialWriteHex(dbg_self != nullptr ? static_cast<u64>(dbg_self->cpu_id) : 0xFFu);
        arch::SerialWrite("\n");
        next->state = TaskState::Ready;
    }

    prev = Current();
    if (prev->state == TaskState::Running)
    {
        if (prev->kill_requested)
        {
            SerialWrite("[sched] killing task id=");
            SerialWriteHex(prev->id);
            SerialWrite(" name=\"");
            SerialWrite(prev->name);
            SerialWrite("\" reason=");
            SerialWrite(KillReasonName(prev->kill_reason));
            SerialWrite("\n");
            // CPU-tick budget ran out (flagged by OnTimerTick). Treat
            // identically to SchedExit but inline — we're already
            // inside Schedule()'s locked section, calling SchedExit
            // here would re-enter the lock and fight the state
            // machine. Transition Running → Dead, push to zombies,
            // wake the reaper.
            prev->state = TaskState::Dead;
            ++g_tasks_exited;
            SchedCpuDecLive();
            prev->next = g_zombies;
            g_zombies = prev;
            // Wake the reaper; it's blocked on g_reaper_wq and
            // noticing a new zombie needs a wake. WaitQueueWakeOne
            // itself acquires g_sched_lock — but we already hold
            // it. Use the _Locked variant to avoid recursive lock.
            WaitQueueWakeOneLocked(&g_reaper_wq);
        }
        else if (prev->no_requeue)
        {
            // One-shot boot context (AP boot sentinel). It exists
            // only so THIS first Schedule() had a valid `prev`;
            // from here the CPU runs real tasks and never returns
            // to the trampoline stack. Abandon it: NOT requeued
            // (a peer CPU popping it would ContextSwitch into a
            // placeholder rsp — the SMP double-run), NOT zombied
            // (never on g_zombies, so the reaper never frees it;
            // one tiny Task struct per AP, by design "never
            // inspected"). Flip to Dead so any later state read is
            // consistent.
            prev->state = TaskState::Dead;
        }
        else
        {
            // RunqueueOrSuspendPush sets state appropriately:
            // Ready when suspend_count == 0 (the typical path)
            // or Blocked + onto g_suspended when the task was
            // suspended while it was the running task. Self-
            // suspend is the only way the latter happens on
            // single-CPU — a different task suspending us
            // can't preempt us, so we always reach this point
            // after our own SchedSuspendTask call.
            RunqueueOrSuspendPush(prev);
        }
    }
    // Dead tasks are NOT re-enqueued; their Task struct + stack live on
    // until the reaper reclaims them.

    next->state = TaskState::Running;
    next->last_cpu = cpu::CurrentCpu()->cpu_id; // pin affinity to this CPU for next wake
    Current() = next;
    ++g_context_switches;

    // Adaptive-mutex on-CPU flag handoff. Cleared on the outgoing
    // task BEFORE ContextSwitch (it is about to stop running on this
    // CPU); set on the resuming task right before its rsp is loaded.
    // Both stores carry RELEASE ordering so a peer CPU reading the
    // flag with ACQUIRE sees a value consistent with the rest of the
    // task state at that moment — in particular, a clear is paired
    // with the state flip out of Running above, and a set is paired
    // with the assignment of Running + Current() = next on this CPU.
    //
    // Order matters: clear `prev` first (it is no longer the owner
    // of this CPU), then set `next` (it is). On single-CPU early boot
    // these atomics are still cheap; on SMP they close the race a
    // spinning adaptive-mutex waiter on a peer CPU would otherwise
    // see ("flag says on-cpu, but the task is parked on a wait queue").
    if (prev != next)
    {
        __atomic_store_n(&prev->on_cpu, 0u, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&next->on_cpu, 1u, __ATOMIC_RELEASE);

    // Lock-passing handoff. The lock STAYS HELD across ContextSwitch;
    // SchedFinishTaskSwitch (called below on the resumed task's stack,
    // or from SchedTaskTrampoline on a fresh-task first-run) reads this
    // CPU's slot and releases. Closes the SMP race where a peer CPU
    // could wake `prev` between an early lock release and the actual
    // stack swap, then dispatch prev while we're still on its stack.
    {
        cpu::PerCpu* pcpu = cpu::CurrentCpu();
        pcpu->ctxsw_lock_to_release = &g_sched_lock;
        pcpu->ctxsw_lock_flags = lock_flags.rflags;
    }

    // Publish `next`'s kernel-stack top to the BSP's TSS.RSP0 slot.
    // RSP0 is the stack the CPU auto-switches to on a user→kernel
    // privilege transition; without this update every subsequent
    // ring-3 interrupt would land on whichever task happened to set
    // it last — fine for a single ring-3 task (the old contract)
    // but wrong as soon as two user-mode tasks coexist, because the
    // second task's stack frames could overwrite the first task's
    // in-flight trap frame.
    //
    // Tasks with stack_base == nullptr are the boot task (and the
    // boot task alone); it runs exclusively in ring 0, so RSP0 is
    // never consulted while it's `Current()`. Skipping the update
    // for it keeps the boot path from needing a fake RSP0. On SMP,
    // each AP will update its own TSS via its own per-CPU slot —
    // this path is BSP-only today and will need a per-CPU wrapper
    // on AP scheduler join.
    if (next->stack_base != nullptr)
    {
        const u64 rsp0 = reinterpret_cast<u64>(next->stack_base) + next->stack_size;
        arch::TssSetRsp0(rsp0);
        // Mirror into the per-CPU slot that the Linux-ABI syscall
        // entry stub reads. `syscall` doesn't consult the TSS, so
        // the two entry paths need separate storage for the same
        // "this task's kernel stack top" value.
        cpu::CurrentCpu()->kernel_rsp = rsp0;
    }

    // Activate the next task's address space. nullptr means "kernel
    // AS" (the boot PML4 — every kernel-only task uses it). The
    // call is a no-op when next->as already matches this CPU's
    // current AS, so the common kernel→kernel switch pays no CR3
    // write and no TLB flush. Switching INTO a user task or BACK
    // to a kernel-only task across user-task boundaries is the
    // only path that actually writes CR3.
    //
    // Critical: must happen BEFORE ContextSwitch. The next task's
    // first instruction after ContextSwitch may be in user space
    // (via the iretq inside arch::EnterUserMode at the trampoline
    // tail) or it may dereference its own user-half pointers via
    // the kernel-side direct map (PhysToVirt — kernel half — is
    // always valid, but a user pointer in next->rsp's frame would
    // read stale TLB entries from prev's AS without the flip).
    mm::AddressSpaceActivate(next->as);

    // FS_BASE snapshot. Linux tasks own MSR_FS_BASE (musl's TLS
    // anchor); every context switch needs to stash the outgoing
    // task's value and restore the incoming task's. No-op for
    // kernel threads and native user tasks — they leave fs_base
    // at 0 and don't touch the MSR.
    constexpr u32 kMsrFsBase = 0xC0000100;
    {
        u32 lo, hi;
        asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(kMsrFsBase));
        prev->fs_base = (static_cast<u64>(hi) << 32) | lo;
    }

    // IRQ-depth handoff. Stash the outgoing task's current
    // global depth, then load the incoming task's saved depth
    // into the global so IrqNestDepth() reflects the resumed
    // task's nesting. Without this the global leaks monotonically
    // across switches (see traps.cpp comments).
    prev->irq_depth = arch::IrqNestDepthRaw();
    arch::IrqNestDepthSet(next->irq_depth);

    // Debug-register handoff. Save outgoing task's DR0..DR3 + DR7
    // from the CPU, then write the incoming task's values in.
    // Tasks that never set a breakpoint leave these at zero (no
    // slots enabled in DR7) so the load is a harmless "disable
    // all four and clear addresses" sequence. See
    // kernel/debug/breakpoints.h for the manager that drives
    // the install path.
    asm volatile("mov %%dr0, %0" : "=r"(prev->dr0));
    asm volatile("mov %%dr1, %0" : "=r"(prev->dr1));
    asm volatile("mov %%dr2, %0" : "=r"(prev->dr2));
    asm volatile("mov %%dr3, %0" : "=r"(prev->dr3));
    asm volatile("mov %%dr7, %0" : "=r"(prev->dr7));
    asm volatile("mov %0, %%dr0" : : "r"(next->dr0));
    asm volatile("mov %0, %%dr1" : : "r"(next->dr1));
    asm volatile("mov %0, %%dr2" : : "r"(next->dr2));
    asm volatile("mov %0, %%dr3" : : "r"(next->dr3));
    asm volatile("mov %0, %%dr7" : : "r"(next->dr7));

    KBP_PROBE_V(::duetos::debug::ProbeId::kSchedContextSwitch, next->id);
    // D2 instrumentation. arg0 = prev tid, arg1 = next tid.
    // Cheap (single fetch_add + 2 stores in the ring path);
    // safe to do here because we've already done the runqueue
    // bookkeeping and are about to swap stacks.
    ::duetos::diag::EventTrace(::duetos::diag::kEventSchedSwitch, prev->id, next->id);
    // Park the outgoing task's lockdep held set (sleeping mutexes
    // held across this switch) so it doesn't pollute the next
    // task's view on the shared stack. Restored per-task in
    // SchedFinishTaskSwitch. The trailing kLockClassSched entry
    // (g_sched_lock, acquired by this Schedule()) rides along and
    // is balanced by the release in SchedFinishTaskSwitch.
    prev->lockdep_held_depth = ::duetos::sync::LockdepHeldSnapshot(prev->lockdep_held, ::duetos::sync::kLockdepHeldMax);

    // Trampoline-RA slot integrity check. SchedCreate plants
    // `&SchedTaskTrampoline` at the highest 8 bytes of every fresh
    // task's stack (slot_top - 8 = stack_base + 0xfff8 within the
    // 64 KiB usable region of the 68 KiB slot). For a KERNEL-ONLY
    // task, that slot must hold &SchedTaskTrampoline for the
    // task's entire lifetime. The trampoline asm reserves 16 bytes
    // at entry (`sub rsp, 16`) so RSP never sits at slot_top while
    // IRQs are enabled — every IRQ frame's SS push therefore lands
    // at slot_top - 24, never at slot_top - 8. The planted RA is
    // preserved across the whole trampoline.
    //
    // (Ring-3 tasks legitimately have it overwritten by syscall
    // entry pushes — RSP0 = slot_top, the saved-SS slot at
    // slot_top-8 lands exactly on the planted RA slot. False
    // positive: 0x33 (= user SS) is what we'd see, observed in
    // the smoke test that prompted this scope-narrowing.)
    //
    // The canary13 wild-RIP shape (rip inside the task's own
    // kstack at offset 0x10fe7) was the same family of bug: a
    // hardware IRQ-frame SS push (= kKernelDataSelector = 0x10)
    // scribbled the planted RA when an IRQ fired with RSP=slot_top
    // inside the trampoline. Restricting to `next->as == nullptr`
    // keeps the check on the right suspects while shedding the
    // syscall-entry false positives.
    //
    // Validate the slot on every switch-in: if the current value
    // isn't &SchedTaskTrampoline, the trampoline's RSP-protection
    // regressed or something else wrote to the slot.
    if (next->stack_base != nullptr && next->stack_size == kKernelStackBytes && next->as == nullptr)
    {
        const u64 slot_top = reinterpret_cast<u64>(next->stack_base) + kKernelStackBytes;
        u64* trampoline_ra_slot = reinterpret_cast<u64*>(slot_top - 8);
        const u64 observed = *trampoline_ra_slot;
        const u64 tramp_base = reinterpret_cast<u64>(&SchedTaskTrampoline);
        if (observed != tramp_base)
        {
            arch::SerialLineGuard guard;
            arch::SerialWrite("[sched] TRAMPOLINE RA SLOT scribbled  cpu=");
            arch::SerialWriteHex(cpu::CurrentCpuIdOrBsp());
            arch::SerialWrite("  next_task=");
            arch::SerialWriteHex(reinterpret_cast<u64>(next));
            arch::SerialWrite("  id=");
            arch::SerialWriteHex(next->id);
            arch::SerialWrite("  name=\"");
            arch::SerialWrite(next->name ? next->name : "<null>");
            arch::SerialWrite("\"  slot=");
            arch::SerialWriteHex(reinterpret_cast<u64>(trampoline_ra_slot));
            arch::SerialWrite("  tramp_base=");
            arch::SerialWriteHex(tramp_base);
            arch::SerialWrite("  observed=");
            arch::SerialWriteHex(observed);
            arch::SerialWrite("\n");
            core::PanicWithValue("sched", "trampoline RA slot scribbled — wild RIP precursor", observed);
        }

        // Sibling check: rbx slot at slot_top - 16 holds the planted
        // entry function pointer for a never-first-run task. SchedCreate
        // writes it as a full u64 (push_quad(reinterpret_cast<u64>(entry))
        // in SchedCreateInternal). A 32-bit truncation / partial scribble
        // is silently dispatched by the trampoline's `call *%rbx` —
        // the trampoline-side validator (SchedTaskTrampolineValidateEntry)
        // checks rbx-the-REGISTER after the pop, not the slot it came
        // from, so a corruption that happens DURING the pop sequence's
        // 8-byte read window or that lingered from an earlier scribble
        // we caught the RA slot for but not the rbx slot is silent.
        //
        // Observed once on `claude/assembly-files-review-ju0dI` as a
        // #PF at instruction fetch of 0x00000000803b9ae3 — the exact
        // low-canonical mirror of a high-half kernel symbol — with
        // CS=0x08 (kernel) and no preceding `[sched/trampoline] WILD
        // entry fn` banner: the validator never ran because the bad
        // value got into rbx via the pop, not via a corruption between
        // validate and `call rbx`.
        //
        // Gate: check the rbx slot ONLY when this is provably the
        // task's first dispatch (the SchedCreate-primed stack layout
        // is still in place). Two independent indicators must agree:
        //
        //   1. next->first_run is true (SchedFinishTaskSwitch hasn't
        //      run on this task yet).
        //   2. next->rsp == slot_top - 56, the exact value
        //      SchedCreate planted (7 pushed quads at the top of the
        //      stack, last push = r15 slot). Any subsequent
        //      ContextSwitch save overwrites this with a much lower
        //      value (deep into the task's actual frames).
        //
        // Requiring both eliminates the false-positive class observed
        // during this slice's first dry run: an early-boot task
        // (seq-writer / e1000-rx-poll) whose first dispatch happened
        // via a path where first_run hadn't yet flipped to false but
        // whose top-of-stack memory had already been touched, leaving
        // a stale value at slot_top-16. The rsp-match check anchors
        // the validator to "literally just-primed, never run" so a
        // log-only warning (below) is genuinely actionable.
        //
        // WARN + probe (not panic). The trampoline-side
        // SchedTaskTrampolineValidateEntry catches the same wild rbx
        // after ContextSwitch -> pop -> `call rbx` and HARD-PANICS,
        // so a true-positive here would just panic one site later
        // with the same actionable banner. Demoting this site to
        // warn-only retires the boot-regression risk while still
        // surfacing the corruption shape — the probe fires for the
        // attached GDB stub, the warn line names the offender for
        // the boot log, and the next session investigating an
        // intermittent boot scribble has a structured starting
        // point.
        if (next->first_run && next->rsp == slot_top - 56)
        {
            u64* entry_slot = reinterpret_cast<u64*>(slot_top - 16);
            const u64 entry_observed = *entry_slot;
            const u64 lo = reinterpret_cast<u64>(_text_start);
            const u64 hi = reinterpret_cast<u64>(_text_end);
            if (entry_observed < lo || entry_observed >= hi)
            {
                KBP_PROBE_V(::duetos::debug::ProbeId::kSchedTrampolineWildEntry, entry_observed);
                arch::SerialLineGuard guard;
                arch::SerialWrite("[sched] TRAMPOLINE RBX SLOT pre-dispatch scribble  cpu=");
                arch::SerialWriteHex(cpu::CurrentCpuIdOrBsp());
                arch::SerialWrite("  next_task=");
                arch::SerialWriteHex(reinterpret_cast<u64>(next));
                arch::SerialWrite("  id=");
                arch::SerialWriteHex(next->id);
                arch::SerialWrite("  name=\"");
                arch::SerialWrite(next->name ? next->name : "<null>");
                arch::SerialWrite("\"  slot=");
                arch::SerialWriteHex(reinterpret_cast<u64>(entry_slot));
                arch::SerialWrite("  text=[");
                arch::SerialWriteHex(lo);
                arch::SerialWrite("..");
                arch::SerialWriteHex(hi);
                arch::SerialWrite(")  observed=");
                arch::SerialWriteHex(entry_observed);
                arch::SerialWrite("  ra_slot=");
                arch::SerialWriteHex(*reinterpret_cast<u64*>(slot_top - 8));
                arch::SerialWrite("\n");
                arch::SerialWrite("[sched]   trampoline-side validator will hard-panic on call *%rbx\n");
                // No panic here: SchedTaskTrampolineValidateEntry
                // panics on the actual `call rbx` site, which is
                // the authoritative gate. This warn is the early-
                // surfacing diagnostic; the panic is downstream.
            }
        }
    }

    ContextSwitch(&prev->rsp, next->rsp);
    // When we return here, we're executing on a DIFFERENT task's
    // stack — whichever task got switched in to run us. The local
    // `prev` on our new stack was bound at THAT task's last
    // Schedule() call and does NOT refer to "the task that just
    // swapped to us." Use Current() instead — the scheduler wrote
    // it to the incoming task BEFORE the stack flip, so Current()
    // here is the task that just resumed.
    //
    // First thing on the new stack: drain the lock-pass slot. The
    // SOURCE-CPU side of THIS Schedule() call (which may have been a
    // different physical Schedule() invocation, on this same CPU,
    // some time in the past — whenever this task was switched out)
    // wrote the slot before its ContextSwitch. We release it here
    // BEFORE touching any other shared state so the scheduler is
    // unlocked promptly after the resumption.
    SchedFinishTaskSwitch();
    {
        const u64 v = Current()->fs_base;
        const u32 lo = static_cast<u32>(v);
        const u32 hi = static_cast<u32>(v >> 32);
        asm volatile("wrmsr" : : "c"(kMsrFsBase), "a"(lo), "d"(hi));
    }
    // Restore this task's user GSBASE into the KERNEL_GS_BASE MSR
    // (0xC0000102). While in the kernel the user gs base is parked
    // there (the entry swapgs put it there); the return-to-user
    // swapgs loads it back. Writing it per-resume makes the TEB
    // base correct per-task: the resolved value is the task's
    // per-thread TEB override if set, else its Process's shared
    // TEB (every existing PE main thread — unchanged behaviour),
    // else 0 for native/Linux/kernel tasks (they enter with gs=0
    // and never read a TEB, so 0 is the same value EnterUserMode
    // already gives them). GSBASE itself (the kernel per-CPU
    // pointer) is untouched.
    {
        constexpr u32 kMsrKernelGsBase = 0xC0000102;
        Task* cur = Current();
        u64 gs = cur->user_gs_base_override;
        if (gs == 0 && cur->process != nullptr)
            gs = cur->process->user_gs_base;
        const u32 lo = static_cast<u32>(gs);
        const u32 hi = static_cast<u32>(gs >> 32);
        asm volatile("wrmsr" : : "c"(kMsrKernelGsBase), "a"(lo), "d"(hi));
    }
}

void SchedYield()
{
    KLOG_TRACE("sched", "SchedYield: voluntary preempt");
    // Yielding from inside a preempt-off critical section is a
    // contract violation — the whole point of `cpu::CriticalEnter`
    // is that the caller chose not to be migrated. The deferred-
    // preempt drain on `CriticalExit` is the legitimate path; an
    // explicit yield must be balanced against the critnest counter
    // first.
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "SchedYield from inside critical section",
                       cpu::CriticalNesting());
    arch::Cli();
    Schedule();
    arch::Sti();
}

void SchedSleepTicks(u64 ticks)
{
    KLOG_TRACE_V("sched", "SchedSleepTicks: parking task for ticks", ticks);
    // Sleeping inside a preempt-off critical section is a contract
    // violation — the task would never be reachable for wake without
    // first dropping critnest, which the sleeper can't do because
    // it's no longer on-CPU.
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "SchedSleepTicks from inside critical section",
                       cpu::CriticalNesting());
    if (ticks == 0)
    {
        SchedYield();
        return;
    }

    // State flip + sleep-queue insert + deschedule under ONE
    // continuous g_sched_lock hold (see ScheduleLockedHandoff). The
    // old shape released the lock between SleepqueueInsert and
    // Schedule()'s re-acquire; a peer CPU's OnTimerTick could fire
    // the wake in that gap and a third CPU dispatch this task while
    // it was still executing this stack — the double-run that
    // surfaced as MUTEX-NONOWNER under gui-fuzz (SchedSleepTicks is
    // the hottest blocking path: every worker / reader / ticker).
    sync::IrqFlags f = sync::SpinLockAcquire(g_sched_lock);
    Task* current = Current();
    current->state = TaskState::Sleeping;
    // Saturate (same idiom as WaitQueueBlockTimeout): an unclamped
    // sum can wrap to 0, which is the "not a timed waiter" sentinel
    // and would make the sleeper wake immediately instead of after
    // the requested interval.
    current->wake_tick = (ticks > (~u64(0) - g_tick_now)) ? ~u64(0) : (g_tick_now + ticks);
    SleepqueueInsert(current);
    SchedCpuIncSleeping();
    ScheduleLockedHandoff(f);
}

void SchedSleepUntil(u64 deadline_tick)
{
    // Wrap-safe deadline compare. Task-visible ticks are the same
    // monotonically-increasing counter that OnTimerTick publishes,
    // so "passed" means (i64)(g_tick_now - deadline) >= 0.
    KLOG_TRACE_V("sched", "SchedSleepUntil: deadline_tick", deadline_tick);
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "SchedSleepUntil from inside critical section",
                       cpu::CriticalNesting());
    arch::Cli();
    if (TickReached(g_tick_now, deadline_tick))
    {
        KLOG_DEBUG("sched", "SchedSleepUntil: deadline already passed - yielding");
        arch::Sti();
        SchedYield();
        return;
    }
    arch::Sti();

    // Same no-gap discipline as SchedSleepTicks: hold g_sched_lock
    // from the state flip through the deschedule so a peer-CPU
    // timer wake can't double-run this task.
    sync::IrqFlags f = sync::SpinLockAcquire(g_sched_lock);
    Task* current = Current();
    current->state = TaskState::Sleeping;
    current->wake_tick = deadline_tick;
    SleepqueueInsert(current);
    SchedCpuIncSleeping();
    ScheduleLockedHandoff(f);
}

u64 SchedNowTicks()
{
    return g_tick_now;
}

void SchedExit()
{
    KLOG_INFO("sched", "SchedExit: task entering termination path");
    // A task can't exit while owning a critical section — there's
    // no Exit pair on the dying side to drain the per-CPU counter.
    // Leaving critnest > 0 across the post-switch onto a different
    // task would silently disable preemption forever on this CPU.
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "SchedExit with critnest != 0", cpu::CriticalNesting());
    arch::Cli();
    Task* self = Current();
    // SchedExit must fire exactly once per task. A second call would
    // double-decrement sched_tasks_live, double-push onto the zombie list
    // (corrupting the intrusive `next` link), and re-arm the reaper
    // on an already-reaped slot. The public contract is [[noreturn]]
    // so this should be structurally unreachable; the assert catches
    // any future path that forgets (e.g., a syscall handler that
    // calls SchedExit and then falls through).
    KASSERT(self->state != TaskState::Dead, "sched", "SchedExit called twice on same task");
    self->state = TaskState::Dead;
    ++g_tasks_exited;
    SchedCpuDecLive();
    KBP_PROBE_V(::duetos::debug::ProbeId::kThreadExit, self->id);

    // Recovery Class C extension point — ring-3 process kill will grow
    // this to tear down address space / fds / caps / ipc.
    core::OnTaskExited();

    // SMP-safe handoff to the reaper: stash `self` into the per-CPU
    // `ctxsw_dying_task_to_zombie` slot instead of pushing to
    // `g_zombies` directly. `SchedFinishTaskSwitch` — which runs on
    // the NEW task's stack AFTER `ContextSwitch` has committed the
    // rsp swap — promotes the deferred entry to `g_zombies` and
    // wakes the reaper.
    //
    // Without this defer, the reaper on a peer CPU could observe
    // `self` in `g_zombies` and call `FreeKernelStack(self->stack_base)`
    // WHILE this CPU was mid-`ContextSwitch`, still executing on the
    // very stack pages the reaper just unmapped. Symptom: SMP=8
    // saturation `#GP at RIP=0xdedede...` with every register/stack
    // quad reading as kheap freed-poison — observed 2026-05-22 as
    // the dominant intermittent panic shape.
    //
    // The historical comment here said "SMP bring-up will need to
    // also verify the task isn't `Running` on a peer CPU before the
    // reaper touches it." That moment came; this is the
    // implementation. The defer slot is per-CPU and only mutated
    // from the same CPU (here at exit, `SchedFinishTaskSwitch` on
    // any subsequent switch), so no cross-CPU race on the slot
    // itself.
    cpu::PerCpu* pcpu = cpu::CurrentCpu();
    pcpu->ctxsw_dying_task_to_zombie = self;

    // Schedule() will not re-enqueue a Dead task, so this is a one-way
    // switch. If the runqueue is empty we'll loop here, still on the
    // dying task's stack — but by then the boot task (idle) should be
    // runnable; if not, we have bigger problems than the reaper.
    for (;;)
    {
        Schedule();
    }
}

void SetNeedResched()
{
    NeedResched() = true;
}

bool TakeNeedResched()
{
    const bool v = NeedResched();
    NeedResched() = false;
    return v;
}

void OnTimerTick(u64 now_ticks)
{
    g_tick_now = now_ticks;

    // Tick-budget accounting for the currently-running task's
    // process. Every tick this task is Running counts against
    // its process's CPU-time budget. When the budget is exhausted,
    // flag the task to be terminated at next resched — we do NOT
    // call SchedExit here (this is IRQ context; Schedule() would
    // switch away before LAPIC EOI, leaving the in-service bit
    // stuck). The flag is read by Schedule() which converts a
    // budget-exhausted task into a Dead one on re-enqueue.
    //
    // Kernel-only tasks (process == nullptr) don't have a budget
    // — they're trusted runtime threads (reaper, idle, workers).
    // Tick-budget accounting for the currently-running task's process.
    // Every tick the task was Running counts against its process's CPU
    // budget. When exhausted, flag the task — Schedule() reads the flag
    // and converts a budget-burned task into a Dead one on next resched
    // (we deliberately don't call SchedExit here; this is IRQ context
    // and SchedExit ends in a Schedule that would switch-away before
    // LAPIC EOI, leaving the in-service bit stuck).
    //
    // Kernel-only tasks (process == nullptr) don't have budgets —
    // they're trusted runtime threads (reaper, idle, workers).
    Task* cur = Current();
    // CPU-time accounting: charge ONE tick to whichever task was on
    // the CPU when the timer fired. Idle tasks charge normally — the
    // idle share of boot is the system-wide "how busy is the OS?"
    // signal. No additional work in the hot path: one load + one
    // store per tick.
    if (cur != nullptr)
    {
        ++cur->ticks_run;
        ++g_total_ticks;
        if (cur->priority == TaskPriority::Idle)
        {
            ++g_idle_ticks;
        }
    }
    // Soft-lockup detector (plan D4). Cheap (load + compare).
    // Idle / kernel-boot tasks pass TID=0 which the detector
    // ignores. A long-running same-TID streak across the
    // threshold (~1 second) emits one warning per streak.
    // Per-CPU idle tasks own real TIDs (e.g. "idle-bsp", "idle-N");
    // collapse them to the TID=0 sentinel so the detector treats
    // every idle task as the legitimate "always on-CPU" case
    // rather than warning every time the BSP idles for 1s.
    const bool cur_is_idle = (cur != nullptr) && (cur->priority == TaskPriority::Idle);
    // Pass the task name so the soft-lockup warning can identify the
    // offender by name rather than just by TID — TIDs are reused
    // after reaping (a TID killed early in boot gets reassigned
    // later), and `val=<tid>` alone is opaque in the log. The
    // detector substitutes "<unknown>" when name is nullptr, so
    // passing nullptr for the idle slot is harmless even though
    // that path early-returns inside the detector anyway.
    const char* cur_name = (cur != nullptr) ? cur->name : nullptr;
    diag::SoftLockupTick(now_ticks, (cur != nullptr && !cur_is_idle) ? TaskId(cur) : 0, cur_name);
    sync::RcuTick();
    // D2 instrumentation. arg0 = vector (32 = LAPIC timer),
    // arg1 = current_tid. Tagging IRQs lets a tracer dump
    // correlate "which task got preempted" with the syscall +
    // mutex events around it.
    ::duetos::diag::EventTrace(::duetos::diag::kEventIrq, 32, (cur != nullptr) ? TaskId(cur) : 0);
    if (cur != nullptr && cur->process != nullptr)
    {
        core::Process* proc = cur->process;
        ++proc->ticks_used;
        if (proc->ticks_used >= proc->tick_budget && !cur->kill_requested)
        {
            cur->kill_requested = true;
            cur->kill_reason = KillReason::TickBudget;
            arch::SerialWrite("[sched] tick budget exhausted pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite("\n");
            NeedResched() = true;
        }
    }

    bool woke_any = false;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        while (g_sleep_head != nullptr && TickReached(now_ticks, g_sleep_head->wake_tick))
        {
            Task* woken = g_sleep_head;
            g_sleep_head = woken->sleep_next;
            if (g_sleep_head != nullptr)
                g_sleep_head->sleep_prev = nullptr;
            woken->sleep_next = nullptr;
            woken->sleep_prev = nullptr;
            SchedCpuDecSleeping();

            // If the task was on a wait queue with a timeout, the
            // timer won the race — detach from the wait queue and
            // flag the wake as a timeout so WaitQueueBlockTimeout
            // reports `false` to its caller. Plain Sleeping tasks
            // have waiting_on == nullptr and pass through untouched.
            if (woken->state == TaskState::Blocked)
            {
                WaitQueue* wq = woken->waiting_on;
                KASSERT(wq != nullptr, "sched", "Blocked task without waiting_on");
                WaitQueueUnlink(wq, woken);
                woken->waiting_on = nullptr;
                woken->wake_by_timeout = true;
                SchedCpuDecBlocked();
            }

            woken->wake_tick = 0;
            woken->next = nullptr;
            // Suspended tasks stay parked even when the timer
            // would otherwise wake them — RunqueueOrSuspendPush
            // routes to g_suspended_head in that case and sets
            // state = Blocked instead of Ready.
            RunqueueOrSuspendPush(woken);
            woke_any = true;
        }
    }

    if (woke_any)
    {
        NeedResched() = true;
    }

    // Periodic active load balancer. Runs every `kBalancePeriodTicks`
    // on each CPU, phase-shifted by `cpu_id` so different CPUs don't
    // all converge on the same heaviest peer in the same tick. Pulls
    // one Ready task from the heaviest same-cluster peer when the
    // local CPU is light by `kBalanceMargin` or more. See the comment
    // block above `PickBalanceVictim` for the design rationale.
    //
    // Cost in the common case: one load (CurrentCpu), one modulo,
    // one branch. Spinlock + cross-CPU walk only on the firing tick.
    {
        cpu::PerCpu* tick_cpu = cpu::CurrentCpu();
        if (tick_cpu != nullptr)
        {
            const u64 phase = static_cast<u64>(tick_cpu->cpu_id);
            // Effective period stretches under PowerSave (one byte
            // read + branch; no function call on the hot path).
            const u64 period = (g_sched_power_bias == static_cast<u8>(PowerBias::PowerSave))
                                   ? (kBalancePeriodTicks * kPowerSaveBalanceFactor)
                                   : kBalancePeriodTicks;
            if ((now_ticks + phase) % period == 0)
            {
                PeriodicBalanceTick();
            }
        }
    }

    // Loadavg sample: once every 5 seconds, walk every CPU's
    // Normal runqueue counting nodes (plus the running task if
    // it's not idle), then
    // feed the count into the EWMA. The gate keeps the per-tick
    // cost at one compare + one branch in the common case. The
    // sched lock covers list-traversal vs. concurrent enqueue —
    // already taken briefly above for the sleep-queue work, so the
    // contention cost is a second short critical section.
    {
        static volatile u64 s_last_sample = 0;
        const u64 kSamplePeriod = 5ULL * ::duetos::time::TickHz();
        // Signed-diff form: `now_ticks - s_last_sample` is unsigned,
        // so once `now_ticks` wraps past UINT64_MAX -> 0 the
        // straight comparison would produce a huge positive value
        // and immediately satisfy the condition forever, or the
        // opposite (depending on the wrap distance), freezing
        // loadavg sampling. Cast through i64 so the comparison
        // works across the wrap. Mirrors the TickReached pattern
        // at line ~993.
        if (static_cast<i64>(now_ticks - s_last_sample) >= static_cast<i64>(kSamplePeriod))
        {
            s_last_sample = now_ticks;
            u32 runnable = 0;
            {
                sync::SpinLockGuard guard(g_sched_lock);
                // Walk every CPU's Normal runqueue. Loadavg counts
                // Normal-band runnables only — Idle tasks always
                // qualify as a system-idle indicator, not as "load."
                const u32 cpu_limit = arch::SmpCpuIdLimit();
                for (u32 i = 0; i < cpu_limit; ++i)
                {
                    cpu::PerCpu* p = arch::SmpGetPercpu(i);
                    if (p == nullptr)
                    {
                        continue;
                    }
                    // O(1) read of the Normal-band length — the
                    // counter is maintained by the push / pop /
                    // steal paths under the same g_sched_lock we
                    // hold here, so the read is consistent with
                    // the runqueue contents.
                    runnable += p->runq_normal_len;
                }
                if (cur != nullptr && cur->state == TaskState::Running && cur->priority != TaskPriority::Idle)
                {
                    ++runnable;
                }
            }
            ::duetos::sched::LoadavgUpdate(runnable);
        }
    }

    // One-shot SMP-health sentinel. cpu::CurrentCpu() now recovers a
    // non-kernel GSBASE on a non-BSP CPU by LAPIC-ID resolution
    // instead of the old "assume BSP" mis-attribution that drove the
    // intermittent SMP double-run (an AP reading/writing the BSP's
    // current_task / ctxsw lock-pass slot). A clean boot never trips
    // this; the first trip leaves a gated WARN + probe so a future
    // swapgs / AP-GS-reestablishment regression is caught without an
    // operator re-adding prints. Checked here rather than at the
    // detection site because klog tags every line via
    // CurrentCpuIdOrBsp(), which would re-enter CurrentCpu() while
    // GSBASE is still stale (unbounded recursion). The timer handler
    // runs post-entry-swapgs, so GSBASE is kernel-valid here. One
    // volatile read + branch on the hot path until it trips once.
    {
        static volatile bool s_gsbase_warned = false;
        if (!s_gsbase_warned)
        {
            const u64 fc = cpu::CurrentCpuGsbaseFallbackCount();
            if (fc != 0)
            {
                s_gsbase_warned = true;
                KBP_PROBE_V(::duetos::debug::ProbeId::kCurrentCpuGsbaseFallback, fc);
                KLOG_WARN_V("cpu/percpu",
                            "CurrentCpu LAPIC-resolved a non-kernel GSBASE on a non-BSP "
                            "CPU (swapgs / AP-GS gap; recovered) — REGRESSION, count",
                            fc);
            }
        }
    }
}

Task* CurrentTask()
{
    // Early boot self-tests can ask "what process is current?" before
    // PerCpuInitBsp installs GSBASE. Treat that phase as kernel-only
    // context instead of dereferencing an uninitialised GSBASE value.
    if (!cpu::BspInstalled())
    {
        return nullptr;
    }
    return Current();
}

u64 CurrentTaskId()
{
    Task* self = Current();
    if (self == nullptr)
    {
        return ~0ULL;
    }
    return self->id;
}

u32 CurrentTaskWin32LastError()
{
    Task* self = CurrentTask();
    if (self == nullptr)
    {
        return 0;
    }
    return self->win32_last_error;
}

u32 SetCurrentTaskWin32LastError(u32 err)
{
    Task* self = CurrentTask();
    if (self == nullptr)
    {
        return 0;
    }
    const u32 previous = self->win32_last_error;
    self->win32_last_error = err;
    return previous;
}

u64 CurrentTaskTlsSlotValue(u32 idx)
{
    Task* self = CurrentTask();
    if (self == nullptr)
    {
        return 0;
    }
    if (idx >= kWin32TlsCap)
    {
        // Win32 thunks bake idx into the call site, so an OOB read
        // is a shim bug — log the first occurrence so the
        // regression surfaces in the boot log, then fall through to
        // the documented "read 0" behaviour so the caller doesn't
        // observe a crash + the rest of the boot proceeds.
        KLOG_ONCE_WARN_V("sched", "TlsGetValue idx out of range", idx);
        return 0;
    }
    return self->win32_tls_slot_value[idx];
}

void SetCurrentTaskTlsSlotValue(u32 idx, u64 value)
{
    Task* self = CurrentTask();
    if (self == nullptr)
    {
        return;
    }
    if (idx >= kWin32TlsCap)
    {
        KLOG_ONCE_WARN_V("sched", "TlsSetValue idx out of range", idx);
        return;
    }
    self->win32_tls_slot_value[idx] = value;
}

u64 TaskId(const Task* t)
{
    return (t != nullptr) ? t->id : 0;
}

const char* TaskName(const Task* t)
{
    if (t == nullptr)
    {
        return "<null>";
    }
    return (t->name != nullptr) ? t->name : "<noname>";
}

// Online-CPU bit window: bits [0, SmpCpusOnline()) set. Used to
// reject masks that select no existing CPU and to clamp a caller
// mask to CPUs that actually exist on this box.
static u32 OnlineCpuMask()
{
    const u32 online = static_cast<u32>(arch::SmpCpusOnline());
    if (online == 0)
    {
        return 0u;
    }
    if (online >= 32u)
    {
        return ~0u;
    }
    return (1u << online) - 1u;
}

bool SchedSetAffinityMask(Task* t, u32 mask)
{
    if (t == nullptr)
    {
        // Exposed to the Linux/Win32 affinity thunks; a null Task
        // is a kernel-side translation bug, not a user mistake.
        // Surface it once so the regression is visible.
        KLOG_ONCE_WARN("sched", "SchedSetAffinityMask called with null task");
        return false;
    }
    const u32 online_bits = OnlineCpuMask();
    const u32 effective = mask & online_bits;
    if (effective == 0u)
    {
        // The mask selects no CPU that exists on this box. Either
        // a bad user mask (their bug, returned via the boolean) or
        // the thunk advertised the wrong CPU count (our bug). Log
        // once with the offending mask so an audit can tell apart.
        KLOG_ONCE_WARN_V("sched", "SchedSetAffinityMask selects no online CPU", mask);
        return false;
    }

    sync::SpinLockGuard guard(g_sched_lock);
    // Store the all-online set as kAffinityAll so every placement
    // path stays on its byte-for-byte unrestricted fast path when
    // the caller didn't actually restrict anything.
    t->affinity_mask = (effective == online_bits) ? kAffinityAll : effective;
    // If the task's routing hint now points at a forbidden CPU,
    // retarget it to the lowest allowed one so the next wake lands
    // correctly. A task that is Ready on a now-forbidden runqueue
    // is re-homed lazily by the RunqueuePopRunnable backstop.
    if (!TaskAllowedOn(t, t->last_cpu))
    {
        for (u32 i = 0; i < 32u; ++i)
        {
            if ((effective >> i) & 1u)
            {
                t->last_cpu = i;
                break;
            }
        }
    }
    return true;
}

u32 SchedGetAffinityMask(Task* t)
{
    if (t == nullptr)
    {
        return 0u;
    }
    sync::SpinLockGuard guard(g_sched_lock);
    // Expand the "unrestricted" sentinel to the concrete online
    // set so callers (the Linux sched_getaffinity thunk) see the
    // CPUs the task can actually land on, not 0xFFFFFFFF.
    return (t->affinity_mask == kAffinityAll) ? OnlineCpuMask() : t->affinity_mask;
}

bool SchedSetAffinity(Task* t, u32 cpu_id)
{
    // Back-compat single-CPU pin: a hard mask of exactly one CPU.
    if (cpu_id >= 32u)
    {
        KLOG_ONCE_WARN_V("sched", "SchedSetAffinity cpu_id out of range", cpu_id);
        return false;
    }
    return SchedSetAffinityMask(t, 1u << cpu_id);
}

namespace
{

const char* SyscallAbiName(u8 abi)
{
    switch (abi)
    {
    case kSyscallAbiNative:
        return "native";
    case kSyscallAbiLinux:
        return "linux";
    case kSyscallAbiWin32:
        return "win32";
    }
    return "?";
}

} // namespace

void SyscallTrailRecord(u8 abi, u32 nr, u64 arg0, u64 arg1, u64 arg2, u64 arg3, u64 ret)
{
    Task* self = Current();
    if (self == nullptr)
    {
        return; // pre-SchedInit syscall, or non-task context — drop
    }
    const u32 idx = self->trail_head % kSyscallTrailSize;
    Task::SyscallTrailEntry& e = self->trail[idx];
    e.nr = nr;
    e.abi = abi;
    e.args[0] = arg0;
    e.args[1] = arg1;
    e.args[2] = arg2;
    e.args[3] = arg3;
    e.ret = ret;
    e.ts_tick = ::duetos::time::TickCount();
    self->trail_head = idx + 1;
    if (self->trail_count < kSyscallTrailSize)
    {
        self->trail_count++;
    }
}

void SyscallTrailSelfTest()
{
    Task* self = Current();
    if (self == nullptr)
    {
        arch::SerialWrite("[sched] syscall-trail self-test SKIPPED (no current task)\n");
        return;
    }
    // Snapshot existing state and restore on exit so the test
    // never destroys live trail data.
    const u32 saved_head = self->trail_head;
    const u32 saved_count = self->trail_count;

    self->trail_head = 0;
    self->trail_count = 0;

    SyscallTrailRecord(kSyscallAbiNative, /*nr=*/1, 0xa, 0xb, 0xc, 0xd, 0x100);
    SyscallTrailRecord(kSyscallAbiLinux, /*nr=*/2, 0x1, 0x2, 0x3, 0x4, 0x200);
    SyscallTrailRecord(kSyscallAbiWin32, /*nr=*/3, 0xfeed, 0xbeef, 0xdead, 0xcafe, 0x300);

    if (self->trail_count != 3 || self->trail_head != 3)
    {
        core::PanicWithValue("sched/trail", "self-test: count/head mismatch", self->trail_count);
    }
    const Task::SyscallTrailEntry& newest = self->trail[2];
    if (newest.nr != 3 || newest.abi != kSyscallAbiWin32 || newest.ret != 0x300)
    {
        core::PanicWithValue("sched/trail", "self-test: newest entry wrong", newest.ret);
    }
    // Wrap-around test: push kSyscallTrailSize more entries,
    // verify count clamps and head wraps.
    for (u32 i = 0; i < kSyscallTrailSize; ++i)
    {
        SyscallTrailRecord(kSyscallAbiNative, 100 + i, 0, 0, 0, 0, 0xfa00 + i);
    }
    if (self->trail_count != kSyscallTrailSize)
    {
        core::PanicWithValue("sched/trail", "self-test: count not clamped to size", self->trail_count);
    }
    arch::SerialWrite("[sched] syscall-trail self-test OK (record + wrap + count clamp)\n");

    // Wipe synthetic data + restore pre-test state.
    for (u32 i = 0; i < kSyscallTrailSize; ++i)
    {
        self->trail[i] = Task::SyscallTrailEntry{};
    }
    self->trail_head = saved_head;
    self->trail_count = saved_count;
}

void LoadBalanceSelfTest()
{
    // Cap the per-CPU snapshot at the same bound the rest of the
    // scheduler uses for SMP iteration. arch::SmpCpuIdLimit() returns
    // the highest cpu_id ever allocated + 1; v0 SMP keeps that small.
    // KASSERT below catches the day someone bumps the SMP cap past
    // the inline-snapshot size without bumping this constant.
    constexpr u32 kMaxCpus = 64;
    u32 saved_len[kMaxCpus] = {0};

    sync::SpinLockGuard guard(g_sched_lock);

    cpu::PerCpu* self = cpu::CurrentCpu();
    if (self == nullptr)
    {
        arch::SerialWrite("[sched-loadbalance-selftest] SKIP (no CurrentCpu — pre-SchedInit)\n");
        return;
    }
    const u32 limit = arch::SmpCpuIdLimit();
    KASSERT(limit <= kMaxCpus, "sched", "LoadBalanceSelfTest: SmpCpuIdLimit > kMaxCpus");

    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        saved_len[i] = (p != nullptr) ? p->runq_normal_len : 0;
    }

    // Test 1: UP / single-CPU short-circuit. PickBalanceVictim must
    // return kBalanceNoVictim regardless of synthetic length when
    // there are no peers — the limit<=1 branch fires first.
    if (limit <= 1)
    {
        const u32 picked = PickBalanceVictim(self->cpu_id, self->cluster_id, 0);
        KASSERT(picked == kBalanceNoVictim, "sched", "LoadBalanceSelfTest: UP did not short-circuit");
        arch::SerialWrite("[sched-loadbalance-selftest] PASS (UP)\n");
        return;
    }

    // Test 2: locate a same-cluster peer. The boot toplogy always
    // assigns at least one peer to each CPU's cluster on multi-CPU
    // boots (every CPU is cluster 0 by default; SRAT/NUMA splits
    // produce ≥2 CPUs per cluster, never a singleton).
    u32 peer_id = kBalanceNoVictim;
    for (u32 i = 0; i < limit; ++i)
    {
        if (i == self->cpu_id)
        {
            continue;
        }
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p != nullptr && p->cluster_id == self->cluster_id)
        {
            peer_id = i;
            break;
        }
    }
    KASSERT(peer_id != kBalanceNoVictim, "sched", "LoadBalanceSelfTest: no same-cluster peer (bad topology)");
    cpu::PerCpu* peer = arch::SmpGetPercpu(peer_id);

    // Force EVERY non-self CPU's length to 0 first, then set peer's
    // length per sub-test. Without this, a CPU other than the chosen
    // peer (typically CPU 2/3 with live tasks queued from the boot
    // tail) carries its natural runq_normal_len through the test,
    // and PickBalanceVictim — which scans ALL same-cluster peers and
    // picks the heaviest — selects that incidental CPU instead of
    // (or in addition to) the synthetic peer. Repro'd under
    // gui-fuzz.sh as
    //     [panic] sched: KASSERT failed: LoadBalanceSelfTest:
    //     sub-margin peer selected
    // (test 2b, where the synthetic peer is sub-margin so the
    // expected outcome is "no victim", but an unrelated CPU's
    // natural EffectiveLoad exceeded the margin). The saved_len[]
    // snapshot at the top of the function already lets us restore
    // every CPU at the tail; this just extends the "controlled
    // environment" the test needs while it runs.
    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p != nullptr && i != self->cpu_id && i != peer_id)
        {
            p->runq_normal_len = 0;
        }
    }
    // Force self's length to 0 so the margin arithmetic is unambiguous.
    self->runq_normal_len = 0;

    // 2a — peer exactly AT the margin: balancer must select it.
    peer->runq_normal_len = kBalanceMargin;
    {
        const u32 picked = PickBalanceVictim(self->cpu_id, self->cluster_id, 0);
        KASSERT(picked == peer_id, "sched", "LoadBalanceSelfTest: peer at margin not selected");
    }

    // 2b — peer one BELOW the margin: balancer must skip.
    peer->runq_normal_len = kBalanceMargin - 1;
    {
        const u32 picked = PickBalanceVictim(self->cpu_id, self->cluster_id, 0);
        KASSERT(picked == kBalanceNoVictim, "sched", "LoadBalanceSelfTest: sub-margin peer selected");
    }

    // 2c — peer well above the margin: still selected (sanity vs.
    // an off-by-one that would clamp `best_len`).
    peer->runq_normal_len = kBalanceMargin * 4;
    {
        const u32 picked = PickBalanceVictim(self->cpu_id, self->cluster_id, 0);
        KASSERT(picked == peer_id, "sched", "LoadBalanceSelfTest: high-load peer not selected");
    }

    // Restore originals before releasing the lock.
    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p != nullptr)
        {
            p->runq_normal_len = saved_len[i];
        }
    }

    arch::SerialWrite("[sched-loadbalance-selftest] PASS\n");
}

void SmtPlacementSelfTest()
{
    constexpr u32 kMaxCpus = 64;
    u32 saved_len[kMaxCpus] = {0};

    sync::SpinLockGuard guard(g_sched_lock);

    cpu::PerCpu* self = cpu::CurrentCpu();
    if (self == nullptr)
    {
        arch::SerialWrite("[smt-placement-selftest] SKIP (no CurrentCpu — pre-SchedInit)\n");
        return;
    }
    const u32 limit = arch::SmpCpuIdLimit();
    KASSERT(limit <= kMaxCpus, "sched", "SmtPlacementSelfTest: SmpCpuIdLimit > kMaxCpus");

    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        saved_len[i] = (p != nullptr) ? p->runq_normal_len : 0;
    }

    // SKIP when the guest exposes no SMT siblings (the flat
    // -smp N / single-CPU regression boots). Nothing to verify;
    // the byte-for-byte non-SMT path is exercised by every other
    // scheduler self-test on that topology.
    bool any_smt = false;
    for (u32 i = 0; i < limit; ++i)
    {
        const cpu::Topology* t = cpu::TopologyForCpu(i);
        if (t != nullptr && t->smt_sibling_count > 0)
        {
            any_smt = true;
            break;
        }
    }
    if (!any_smt)
    {
        arch::SerialWrite("[smt-placement-selftest] SKIP (non-SMT guest)\n");
        return;
    }

    // Locate an SMT pair (a, b) sharing a core_group, plus a CPU c
    // on a *different* valid core_group in the same cluster as a
    // (PickClusterPlacement only considers same-cluster peers).
    u32 a_id = kBalanceNoVictim;
    u32 b_id = kBalanceNoVictim;
    u32 c_id = kBalanceNoVictim;
    for (u32 i = 0; i < limit && a_id == kBalanceNoVictim; ++i)
    {
        const cpu::Topology* ti = cpu::TopologyForCpu(i);
        cpu::PerCpu* pi = arch::SmpGetPercpu(i);
        if (ti == nullptr || pi == nullptr || ti->core_group == cpu::kTopologyUnknownCoreGroup ||
            ti->smt_sibling_count == 0)
        {
            continue;
        }
        for (u32 j = 0; j < limit; ++j)
        {
            if (j == i)
            {
                continue;
            }
            const cpu::Topology* tj = cpu::TopologyForCpu(j);
            cpu::PerCpu* pj = arch::SmpGetPercpu(j);
            if (tj == nullptr || pj == nullptr)
            {
                continue;
            }
            if (tj->core_group == ti->core_group && b_id == kBalanceNoVictim)
            {
                b_id = j; // SMT sibling of i
            }
            else if (tj->core_group != cpu::kTopologyUnknownCoreGroup && tj->core_group != ti->core_group &&
                     pj->cluster_id == pi->cluster_id && c_id == kBalanceNoVictim)
            {
                c_id = j; // distinct physical core, same cluster
            }
        }
        if (b_id != kBalanceNoVictim && c_id != kBalanceNoVictim)
        {
            a_id = i;
        }
        else
        {
            b_id = kBalanceNoVictim;
            c_id = kBalanceNoVictim;
        }
    }
    if (a_id == kBalanceNoVictim)
    {
        arch::SerialWrite("[smt-placement-selftest] SKIP (no sibling+distinct-core triple)\n");
        return;
    }

    cpu::PerCpu* a = arch::SmpGetPercpu(a_id);
    cpu::PerCpu* b = arch::SmpGetPercpu(b_id);
    cpu::PerCpu* c = arch::SmpGetPercpu(c_id);

    // Clean slate so the penalty arithmetic is unambiguous.
    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p != nullptr)
        {
            p->runq_normal_len = 0;
        }
    }

    // Invariant 1 — sibling penalty: a idle but its sibling b
    // busy makes a's effective load == kSmtSiblingPenalty, while
    // c's physical core is fully idle so its effective load is 0.
    a->runq_normal_len = 0;
    b->runq_normal_len = 1;
    KASSERT(EffectiveLoad(a) == kSmtSiblingPenalty, "sched", "SmtPlacementSelfTest: sibling penalty not applied");
    KASSERT(EffectiveLoad(c) == 0, "sched", "SmtPlacementSelfTest: idle distinct core penalized");

    // Invariant 2 — placement prefers a distinct physical core:
    // with b busy and c idle, a fully-idle core must beat an SMT
    // sibling of a busy core even when a sits exactly at the
    // cluster-placement margin (so the raw short-circuit doesn't
    // fire).
    a->runq_normal_len = kClusterPlacementMargin;
    b->runq_normal_len = 1;
    c->runq_normal_len = 0;
    {
        cpu::PerCpu* picked = PickClusterPlacement(a);
        KASSERT(picked == c, "sched", "SmtPlacementSelfTest: placement did not prefer distinct core");
    }

    // Invariant 3 — non-SMT identity: any core_group==unknown CPU
    // must see EffectiveLoad == raw runq_normal_len (the legacy
    // byte-for-byte path). Skipped when every CPU decoded SMT.
    for (u32 i = 0; i < limit; ++i)
    {
        const cpu::Topology* t = cpu::TopologyForCpu(i);
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (t == nullptr || p == nullptr || t->core_group != cpu::kTopologyUnknownCoreGroup)
        {
            continue;
        }
        p->runq_normal_len = 7;
        KASSERT(EffectiveLoad(p) == 7, "sched", "SmtPlacementSelfTest: non-SMT CPU not identity");
        p->runq_normal_len = 0;
        break;
    }

    // Invariant 4 — exactly one smt_primary per core_group.
    for (u32 i = 0; i < limit; ++i)
    {
        const cpu::Topology* ti = cpu::TopologyForCpu(i);
        if (ti == nullptr || ti->core_group == cpu::kTopologyUnknownCoreGroup)
        {
            continue;
        }
        // Only audit the group from its first occurrence.
        bool first = true;
        for (u32 k = 0; k < i; ++k)
        {
            const cpu::Topology* tk = cpu::TopologyForCpu(k);
            if (tk != nullptr && tk->core_group == ti->core_group)
            {
                first = false;
                break;
            }
        }
        if (!first)
        {
            continue;
        }
        u32 primaries = 0;
        for (u32 j = 0; j < limit; ++j)
        {
            const cpu::Topology* tj = cpu::TopologyForCpu(j);
            if (tj != nullptr && tj->core_group == ti->core_group && tj->smt_primary == 1)
            {
                ++primaries;
            }
        }
        KASSERT(primaries == 1, "sched", "SmtPlacementSelfTest: core_group lacks exactly one primary");
    }

    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p != nullptr)
        {
            p->runq_normal_len = saved_len[i];
        }
    }

    arch::SerialWrite("[smt-placement-selftest] PASS\n");
}

void AffinityMaskSelfTest()
{
    const u32 limit = arch::SmpCpuIdLimit();
    if (limit < 2)
    {
        arch::SerialWrite("[affinity-mask-selftest] SKIP (need >=2 CPUs)\n");
        return;
    }

    // Pick an allowed CPU A and a distinct forbidden CPU F that
    // are both online.
    u32 cpu_a = limit; // sentinel
    u32 cpu_f = limit;
    for (u32 i = 0; i < limit; ++i)
    {
        if (arch::SmpGetPercpu(i) == nullptr)
        {
            continue;
        }
        if (cpu_a == limit)
        {
            cpu_a = i;
        }
        else if (cpu_f == limit)
        {
            cpu_f = i;
            break;
        }
    }
    if (cpu_a == limit || cpu_f == limit)
    {
        arch::SerialWrite("[affinity-mask-selftest] SKIP (need 2 online CPUs)\n");
        return;
    }

    // --- Phase A: mask API (these take g_sched_lock internally,
    // so must run WITHOUT the lock held). ---
    Task probe;
    memset(&probe, 0, sizeof(Task));
    probe.priority = TaskPriority::Normal;
    probe.last_cpu = cpu_f;
    probe.affinity_mask = kAffinityAll;

    KASSERT(!SchedSetAffinityMask(&probe, 0u), "sched", "AffinityMaskSelfTest: empty mask accepted");
    KASSERT(!SchedSetAffinityMask(nullptr, 1u), "sched", "AffinityMaskSelfTest: null task accepted");
    KASSERT(SchedSetAffinityMask(&probe, 1u << cpu_a), "sched", "AffinityMaskSelfTest: valid pin rejected");
    KASSERT(!TaskAllowedOn(&probe, cpu_f), "sched", "AffinityMaskSelfTest: forbidden CPU still allowed");
    KASSERT(TaskAllowedOn(&probe, cpu_a), "sched", "AffinityMaskSelfTest: allowed CPU rejected");
    // Pinning away from last_cpu must retarget the routing hint.
    KASSERT(probe.last_cpu == cpu_a, "sched", "AffinityMaskSelfTest: last_cpu not retargeted");
    // getaffinity expands the sentinel; a single-CPU pin reads back exactly.
    KASSERT(SchedGetAffinityMask(&probe) == (1u << cpu_a), "sched", "AffinityMaskSelfTest: getaffinity mismatch");
    // An all-online mask collapses to the unrestricted sentinel.
    Task probe_all;
    memset(&probe_all, 0, sizeof(Task));
    probe_all.priority = TaskPriority::Normal;
    KASSERT(SchedSetAffinityMask(&probe_all, ~0u), "sched", "AffinityMaskSelfTest: all-mask rejected");
    KASSERT(TaskAllowedOn(&probe_all, cpu_f), "sched", "AffinityMaskSelfTest: all-mask not unrestricted");

    // --- Phase B: placement honors the mask (lock held + runq
    // snapshot, same idiom as the other scheduler self-tests). ---
    constexpr u32 kMaxCpus = 64;
    u32 saved_len[kMaxCpus] = {0};
    sync::SpinLockGuard guard(g_sched_lock);
    KASSERT(limit <= kMaxCpus, "sched", "AffinityMaskSelfTest: SmpCpuIdLimit > kMaxCpus");
    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        saved_len[i] = (p != nullptr) ? p->runq_normal_len : 0;
        if (p != nullptr)
        {
            p->runq_normal_len = 0;
        }
    }

    // probe is pinned to cpu_a only, but its routing hint and a
    // light forbidden CPU would otherwise attract placement.
    cpu::PerCpu* pa = arch::SmpGetPercpu(cpu_a);
    cpu::PerCpu* pf = arch::SmpGetPercpu(cpu_f);
    pa->runq_normal_len = kClusterPlacementMargin; // not the early light-CPU short-circuit
    pf->runq_normal_len = 0;                       // most attractive by load

    cpu::PerCpu* tgt = TargetPerCpuFor(&probe);
    KASSERT(tgt == pa, "sched", "AffinityMaskSelfTest: TargetPerCpuFor ignored mask");

    cpu::PerCpu* placed = PickClusterPlacement(pa, &probe);
    KASSERT(placed != pf, "sched", "AffinityMaskSelfTest: placement chose forbidden CPU");
    KASSERT(placed != nullptr && TaskAllowedOn(&probe, placed->cpu_id), "sched",
            "AffinityMaskSelfTest: placement result not allowed");

    // Unrestricted identity: an all-mask task routes exactly as a
    // null-task call (byte-for-byte pre-affinity behavior).
    probe_all.last_cpu = cpu_f;
    KASSERT(TargetPerCpuFor(&probe_all) == pf, "sched", "AffinityMaskSelfTest: unrestricted retargeted");
    KASSERT(PickClusterPlacement(pa, &probe_all) == PickClusterPlacement(pa, nullptr), "sched",
            "AffinityMaskSelfTest: unrestricted not identical to no-task");

    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p != nullptr)
        {
            p->runq_normal_len = saved_len[i];
        }
    }
    arch::SerialWrite("[affinity-mask-selftest] PASS\n");
}

void HybridPlacementSelfTest()
{
    const u32 limit = arch::SmpCpuIdLimit();
    u32 e_cpu = limit; // an E-core
    u32 p_cpu = limit; // a P-core
    for (u32 i = 0; i < limit; ++i)
    {
        const cpu::Topology* ti = cpu::TopologyForCpu(i);
        if (ti == nullptr || arch::SmpGetPercpu(i) == nullptr)
        {
            continue;
        }
        if (ti->core_class == cpu::kCoreClassEff && e_cpu == limit)
        {
            e_cpu = i;
        }
        else if (ti->core_class == cpu::kCoreClassPerf && p_cpu == limit)
        {
            p_cpu = i;
        }
    }
    if (e_cpu == limit || p_cpu == limit)
    {
        // QEMU never models Intel hybrid; this is the universal
        // path here. Same honest SKIP contract as the SMT test.
        arch::SerialWrite("[hybrid-placement-selftest] SKIP (non-hybrid guest)\n");
        return;
    }

    constexpr u32 kMaxCpus = 64;
    u32 saved_len[kMaxCpus] = {0};
    sync::SpinLockGuard guard(g_sched_lock);
    KASSERT(limit <= kMaxCpus, "sched", "HybridPlacementSelfTest: SmpCpuIdLimit > kMaxCpus");
    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        saved_len[i] = (p != nullptr) ? p->runq_normal_len : 0;
        if (p != nullptr)
        {
            p->runq_normal_len = 0;
        }
    }
    cpu::PerCpu* pe = arch::SmpGetPercpu(e_cpu);
    cpu::PerCpu* pp = arch::SmpGetPercpu(p_cpu);

    // Idle P-core present => the E-core carries the hybrid penalty
    // and the P-core does not.
    KASSERT(EffectiveLoad(pe) == kHybridEcorePenalty, "sched",
            "HybridPlacementSelfTest: E-core penalty not applied while P-core idle");
    KASSERT(EffectiveLoad(pp) == 0, "sched", "HybridPlacementSelfTest: idle P-core penalized");

    // Every P-core busy => no idle P-core, so the E-core penalty
    // lifts (E-cores are used rather than starved).
    for (u32 i = 0; i < limit; ++i)
    {
        const cpu::Topology* ti = cpu::TopologyForCpu(i);
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (ti != nullptr && p != nullptr && ti->core_class == cpu::kCoreClassPerf)
        {
            p->runq_normal_len = 1;
        }
    }
    KASSERT(EffectiveLoad(pe) == 0, "sched", "HybridPlacementSelfTest: E-core penalized with no idle P-core");

    for (u32 i = 0; i < limit; ++i)
    {
        cpu::PerCpu* p = arch::SmpGetPercpu(i);
        if (p != nullptr)
        {
            p->runq_normal_len = saved_len[i];
        }
    }
    arch::SerialWrite("[hybrid-placement-selftest] PASS\n");
}

void IdlePowerSelfTest()
{
    // Wiring check: the CPU-feature table must be populated and
    // the MONITOR bit must agree with a fresh CPUID.1:ECX[3], so
    // the idle path's gate reflects reality. Then report which
    // idle path every CPU's IdleMain selected. Unlike the
    // topology self-tests this PASSes on QEMU (real signal, not a
    // SKIP) — the boot-log analyzer greps the sentinel.
    const arch::CpuInfo& ci = arch::CpuInfoGet();
    KASSERT(ci.valid, "sched", "IdlePowerSelfTest: CpuInfo not initialised");

    u32 eax = 1, ebx = 0, ecx = 0, edx = 0;
    asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
    const bool cpuid_monitor = ((ecx >> 3) & 1u) != 0u;
    const bool feat_monitor = arch::CpuHas(arch::kCpuFeatMonitor);
    KASSERT(cpuid_monitor == feat_monitor, "sched", "IdlePowerSelfTest: MONITOR feature gate disagrees with CPUID");

    if (feat_monitor)
    {
        arch::SerialWrite("[idle-power-selftest] PASS (mwait)\n");
    }
    else
    {
        arch::SerialWrite("[idle-power-selftest] PASS (hlt-fallback)\n");
    }
}

void DumpCurrentTaskSyscallTrail()
{
    Task* self = Current();
    if (self == nullptr || self->trail_count == 0)
    {
        return;
    }
    arch::SerialWrite("  syscall trail (last ");
    arch::SerialWriteHex(static_cast<u64>(self->trail_count));
    arch::SerialWrite(" syscalls, newest first):\n");
    // Walk newest -> oldest. trail_head points at the next slot
    // to write; the most recent entry is at (trail_head - 1).
    const u32 count = self->trail_count;
    for (u32 i = 0; i < count; ++i)
    {
        const u32 idx = (self->trail_head + kSyscallTrailSize - 1 - i) % kSyscallTrailSize;
        const Task::SyscallTrailEntry& e = self->trail[idx];
        arch::SerialWrite("    [");
        arch::SerialWriteHex(static_cast<u64>(i));
        arch::SerialWrite("] abi=");
        arch::SerialWrite(SyscallAbiName(e.abi));
        arch::SerialWrite(" nr=");
        arch::SerialWriteHex(static_cast<u64>(e.nr));
        arch::SerialWrite(" args=(");
        for (u32 a = 0; a < 4; ++a)
        {
            if (a != 0)
            {
                arch::SerialWrite(", ");
            }
            arch::SerialWriteHex(e.args[a]);
        }
        arch::SerialWrite(") -> ret=");
        arch::SerialWriteHex(e.ret);
        arch::SerialWrite(" tick=");
        arch::SerialWriteHex(e.ts_tick);
        arch::SerialWrite("\n");
    }
}

u64 SchedCurrentKernelStackTop()
{
    Task* self = Current();
    if (self == nullptr || self->stack_base == nullptr)
    {
        return 0;
    }
    return reinterpret_cast<u64>(self->stack_base) + self->stack_size;
}

SchedStats SchedStatsRead()
{
    return SchedStats{
        .context_switches = g_context_switches,
        .tasks_live = SchedSumLive(),
        .tasks_sleeping = SchedSumSleeping(),
        .tasks_blocked = SchedSumBlocked(),
        .tasks_created = SchedSumCreated(),
        .tasks_exited = g_tasks_exited,
        .tasks_reaped = SchedSumReaped(),
        .total_ticks = g_total_ticks,
        .idle_ticks = g_idle_ticks,
    };
}

const char* SchedPowerBiasName(PowerBias b)
{
    switch (b)
    {
    case PowerBias::Performance:
        return "performance";
    case PowerBias::Balanced:
        return "balanced";
    case PowerBias::PowerSave:
        return "powersave";
    }
    return "?";
}

PowerBias SchedPowerBias()
{
    return static_cast<PowerBias>(g_sched_power_bias);
}

u64 SchedBalancePeriodTicks()
{
    return (SchedPowerBias() == PowerBias::PowerSave) ? (kBalancePeriodTicks * kPowerSaveBalanceFactor)
                                                      : kBalancePeriodTicks;
}

void SchedSetPowerBias(PowerBias b)
{
    if (static_cast<u8>(b) == g_sched_power_bias)
    {
        return;
    }
    g_sched_power_bias = static_cast<u8>(b);
    KLOG_INFO_S("sched", "power bias changed", "to", SchedPowerBiasName(b));
}

namespace
{

void EmitTask(const Task* t, SchedEnumCb cb, void* cookie, bool is_running)
{
    if (t == nullptr)
        return;
    SchedTaskInfo info;
    info.id = t->id;
    info.name = t->name;
    info.wake_tick = t->wake_tick;
    info.stack_size = t->stack_size;
    info.ticks_run = t->ticks_run;
    info.owner_pid = (t->process != nullptr) ? t->process->pid : 0;
    info.state = static_cast<u8>(t->state);
    info.priority = static_cast<u8>(t->priority);
    info.is_running = is_running;
    info.has_process = (t->process != nullptr);
    for (u32 i = 0; i < sizeof(info._pad); ++i)
        info._pad[i] = 0;
    cb(info, cookie);
}

// Walk a singly-linked list threaded by `next`. De-dup against
// the already-emitted current task so the running thread isn't
// printed twice when it also sits on a runqueue head.
void EmitList(Task* head, SchedEnumCb cb, void* cookie, const Task* skip)
{
    for (Task* t = head; t != nullptr; t = t->next)
    {
        if (t == skip)
            continue;
        EmitTask(t, cb, cookie, false);
    }
}

} // namespace

const char* KillResultName(KillResult r)
{
    switch (r)
    {
    case KillResult::Signaled:
        return "Signaled";
    case KillResult::NotFound:
        return "NotFound";
    case KillResult::Protected:
        return "Protected";
    case KillResult::AlreadyDead:
        return "AlreadyDead";
    case KillResult::Blocked:
        return "Blocked";
    default:
        KLOG_ONCE_WARN("sched", "KillResultName: unrecognised KillResult enumerator");
        return "<unknown>";
    }
}

namespace
{

bool SchedNameEq(const char* a, const char* b)
{
    for (u32 i = 0; i < 64; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
    return true;
}

bool SchedNameStarts(const char* s, const char* prefix)
{
    for (u32 i = 0;; ++i)
    {
        if (prefix[i] == '\0')
            return true;
        if (s[i] != prefix[i])
            return false;
    }
}

// Task is considered "protected" if killing it would break
// kernel invariants: the boot task (pid 0), the reaper (we
// need it to clean up zombies — including the very task we'd
// be killing), and any idle task (empty runqueue would panic
// Schedule()).
bool IsProtectedTask(const Task* t)
{
    if (t == nullptr)
        return true;
    if (t->id == 0)
        return true;
    if (t->name == nullptr)
        return false;
    if (SchedNameEq(t->name, "reaper"))
        return true;
    if (SchedNameStarts(t->name, "idle-"))
        return true;
    return false;
}

// Detach `t` from g_sleep_head. O(1) via the sleep_prev back-
// pointer; no-op if t isn't on the list (both links nullptr).
// Caller holds CLI.
void SleepQueueRemove(Task* t)
{
    // A task on the list always has prev != nullptr OR is the
    // head. Off-list tasks have both nullptr AND aren't the
    // head, so this safely no-ops them.
    if (t->sleep_prev == nullptr && g_sleep_head != t)
        return;
    Task* prev = t->sleep_prev;
    Task* next = t->sleep_next;
    if (prev != nullptr)
        prev->sleep_next = next;
    else
        g_sleep_head = next;
    if (next != nullptr)
        next->sleep_prev = prev;
    t->sleep_next = nullptr;
    t->sleep_prev = nullptr;
    // With per-CPU counters the prior "decrement only if >0" guard
    // would need a cross-CPU sum-walk on the hot path. Drop the
    // guard: the caller already established `t` was on the sleep
    // queue (early-return above for off-list tasks), so the
    // decrement is matched. Per-CPU partial sums may go transiently
    // negative if the increment landed on a different CPU; the
    // cross-CPU sum stays correct.
    SchedCpuDecSleeping();
}

} // namespace

KillResult SchedKillByPid(u64 pid)
{
    arch::Cli();

    // Walk every possible home of a Task* with this id. Ordered
    // so the hottest cases (running + ready runqueues) hit first.
    Task* target = nullptr;
    Task* cur = Current();
    if (cur != nullptr && cur->id == pid)
    {
        target = cur;
    }
    if (target == nullptr)
    {
        ForEachRunqueueTask(
            [&](Task* t)
            {
                if (t->id == pid)
                {
                    target = t;
                    return true;
                }
                return false;
            });
    }
    if (target == nullptr)
    {
        for (Task* t = g_sleep_head; t != nullptr; t = t->sleep_next)
        {
            if (t->id == pid)
            {
                target = t;
                break;
            }
        }
    }
    if (target == nullptr)
    {
        // Zombie list is linked via `next`; walking it just for
        // a report-as-dead case keeps the caller's model clean.
        for (Task* t = g_zombies; t != nullptr; t = t->next)
        {
            if (t->id == pid)
            {
                arch::Sti();
                return KillResult::AlreadyDead;
            }
        }
        arch::Sti();
        return KillResult::NotFound;
    }

    if (IsProtectedTask(target))
    {
        arch::Sti();
        return KillResult::Protected;
    }
    if (target->state == TaskState::Dead)
    {
        arch::Sti();
        return KillResult::AlreadyDead;
    }
    // Blocked tasks sit on a WaitQueue threaded via `next`. We
    // don't have a safe cross-queue detach primitive in v0 — the
    // producer that owns the WaitQueue might be mid-enqueue. So
    // mark the flag but DON'T try to move the task; the next
    // wake (from its normal producer) will see kill_requested
    // and terminate. Report the constraint to the caller.
    target->kill_requested = true;
    target->kill_reason = KillReason::UserKill;
    if (target->state == TaskState::Blocked)
    {
        arch::Sti();
        return KillResult::Blocked;
    }
    // Sleeping: lift off the sleep queue + re-queue Ready so
    // the task runs and takes the kill path on its next slot.
    if (target->state == TaskState::Sleeping)
    {
        SleepQueueRemove(target);
        target->wake_tick = 0;
        target->state = TaskState::Ready;
        RunqueuePush(target);
    }
    // Ready / Running tasks don't need repositioning — they'll
    // hit Schedule() naturally and die there.
    arch::Sti();
    return KillResult::Signaled;
}

u64 SchedKillByProcess(core::Process* target)
{
    if (target == nullptr)
        return 0;
    arch::Cli();
    // Collect TIDs first so we can release the cli window before
    // calling SchedKillByPid (which takes its own cli). Cap at 32
    // — the win32 thread-handle table is 8, plus the main task,
    // plus a generous margin for Linux clone(CLONE_THREAD) work.
    constexpr u32 kMaxTidsPerKill = 32;
    u64 tids[kMaxTidsPerKill];
    u32 ntids = 0;
    auto collect = [&](Task* t)
    {
        if (t == nullptr || t->process != target)
            return;
        if (t->state == TaskState::Dead)
            return;
        if (ntids < kMaxTidsPerKill)
            tids[ntids++] = t->id;
    };
    Task* cur = Current();
    collect(cur);
    ForEachRunqueueTask(
        [&](Task* t)
        {
            collect(t);
            return false;
        });
    for (Task* t = g_sleep_head; t != nullptr; t = t->sleep_next)
        collect(t);
    arch::Sti();

    u64 signalled = 0;
    for (u32 i = 0; i < ntids; ++i)
    {
        const KillResult r = SchedKillByPid(tids[i]);
        if (r == KillResult::Signaled || r == KillResult::Blocked)
            ++signalled;
    }
    return signalled;
}

SuspendResult SchedSuspendTask(Task* target, u32* prev_count_out)
{
    if (target == nullptr)
    {
        return SuspendResult::NotFound;
    }
    arch::Cli();
    sync::SpinLockGuard guard(g_sched_lock);
    if (target->state == TaskState::Dead)
    {
        arch::Sti();
        return SuspendResult::AlreadyDead;
    }
    if (target == Current())
    {
        // Self-suspend on single-CPU: the count goes up, the
        // task continues running until its next yield. At that
        // yield Schedule()'s prev re-enqueue path routes it
        // through RunqueueOrSuspendPush, which sees the non-zero
        // count and parks it on g_suspended.
        if (prev_count_out != nullptr)
        {
            *prev_count_out = target->suspend_count;
        }
        ++target->suspend_count;
        arch::Sti();
        return SuspendResult::Signaled;
    }
    if (prev_count_out != nullptr)
    {
        *prev_count_out = target->suspend_count;
    }
    ++target->suspend_count;
    // For Ready tasks the suspend takes effect lazily — the next
    // RunqueuePopRunnable that touches the task drops it onto
    // the suspended list. For Sleeping / Blocked tasks the
    // suspend takes effect at wake time via RunqueueOrSuspendPush.
    // No eager relocation needed in either case.
    arch::Sti();
    return SuspendResult::Signaled;
}

SuspendResult SchedResumeTask(Task* target, u32* prev_count_out)
{
    if (target == nullptr)
    {
        return SuspendResult::NotFound;
    }
    arch::Cli();
    sync::SpinLockGuard guard(g_sched_lock);
    if (target->state == TaskState::Dead)
    {
        arch::Sti();
        return SuspendResult::AlreadyDead;
    }
    if (prev_count_out != nullptr)
    {
        *prev_count_out = target->suspend_count;
    }
    if (target->suspend_count == 0)
    {
        // Resume on an unsuspended task is a no-op that returns
        // 0 (matching NT — NtResumeThread on a thread with count
        // 0 returns 0 and stays 0).
        arch::Sti();
        return SuspendResult::Signaled;
    }
    --target->suspend_count;
    if (target->suspend_count == 0)
    {
        // Last reference dropped. If the task was parked on
        // g_suspended, move it back onto the runqueue Ready.
        // If it's elsewhere (still Sleeping / Blocked on a real
        // wait queue, because the suspend was applied while it
        // was sleeping and we never moved it), the natural wake
        // path already handles it now that suspend_count is 0.
        if (SuspendedListRemove(target))
        {
            target->state = TaskState::Ready;
            RunqueuePush(target);
        }
    }
    arch::Sti();
    return SuspendResult::Signaled;
}

// Walk every list that holds a Task and check two invariants:
//   1. The 8-byte stack-bottom canary at stack_base[0..7] still
//      matches kStackCanary — a broken canary is a confirmed
//      kernel-stack overflow.
//   2. The saved rsp is inside [stack_base, stack_base + size) —
//      an out-of-range rsp means the task's control block was
//      scribbled or the switch primer got corrupted, and
//      resuming it would triple-fault.
//
// Each finding is logged individually with the offending task's
// identity. Returns both counts so the runtime checker can
// surface them as distinct HealthIssue codes.
StackHealth SchedCheckTaskStacks()
{
    StackHealth out = {};
    auto check = [&out](const Task* t)
    {
        if (t == nullptr)
            return;
        if (t->stack_base == nullptr)
            return; // boot/idle task — no stack to check
        const u64 got = *reinterpret_cast<const u64*>(t->stack_base);
        if (got != kStackCanary)
        {
            ++out.canary_broken;
            arch::SerialWrite("[health] STACK OVERFLOW detected task=");
            arch::SerialWrite(t->name ? t->name : "<anon>");
            arch::SerialWrite(" id=");
            arch::SerialWriteHex(t->id);
            arch::SerialWrite(" expected=");
            arch::SerialWriteHex(kStackCanary);
            arch::SerialWrite(" got=");
            arch::SerialWriteHex(got);
            arch::SerialWrite("\n");
        }
        // rsp of 0 means the task is currently running — its rsp
        // lives in the CPU, not the control block, so skip the
        // range check for it. Dead tasks on the zombie list also
        // have rsp==0 after SchedExit blitzes the frame.
        if (t->rsp != 0)
        {
            const u64 base = reinterpret_cast<u64>(t->stack_base);
            const u64 top = base + t->stack_size;
            if (t->rsp < base || t->rsp >= top)
            {
                ++out.rsp_out_of_range;
                arch::SerialWrite("[health] RSP OUT OF RANGE task=");
                arch::SerialWrite(t->name ? t->name : "<anon>");
                arch::SerialWrite(" id=");
                arch::SerialWriteHex(t->id);
                arch::SerialWrite(" rsp=");
                arch::SerialWriteHex(t->rsp);
                arch::SerialWrite(" stack=[");
                arch::SerialWriteHex(base);
                arch::SerialWrite("..");
                arch::SerialWriteHex(top);
                arch::SerialWrite(")\n");
            }
        }
    };
    arch::Cli();
    check(Current());
    ForEachRunqueueTask(
        [&](Task* t)
        {
            check(t);
            return false;
        });
    for (Task* t = g_sleep_head; t != nullptr; t = t->sleep_next)
        check(t);
    for (Task* t = g_zombies; t != nullptr; t = t->next)
        check(t);
    arch::Sti();
    return out;
}

void SchedEnumerate(SchedEnumCb cb, void* cookie)
{
    if (cb == nullptr)
        return;
    // Debug app self-tests run before PerCpuInitBsp/SchedInit. At
    // that point there is no task graph to enumerate, and touching
    // Current() would dereference an uninitialised GSBASE value.
    if (!cpu::BspInstalled())
        return;
    // Brief CLI window so the timer IRQ + WaitQueueWake* can't
    // splice the lists mid-walk. The callback runs inside the
    // critical section — this is fine for Console writes
    // (byte-sized stores) but would not be for anything that
    // can block.
    arch::Cli();
    const Task* running = Current();
    if (running != nullptr)
    {
        EmitTask(running, cb, cookie, true);
    }
    // Walk every CPU's Normal then Idle runqueue. EmitList already
    // skips the running task by pointer comparison, so iterating
    // every per-CPU queue is safe even though `running` is on this
    // CPU's currently-active slot, not on a runqueue at all.
    {
        const u32 cpu_limit = arch::SmpCpuIdLimit();
        for (u32 i = 0; i < cpu_limit; ++i)
        {
            cpu::PerCpu* p = arch::SmpGetPercpu(i);
            if (p == nullptr)
            {
                continue;
            }
            EmitList(RunqHeadNormal(p), cb, cookie, running);
            EmitList(RunqHeadIdle(p), cb, cookie, running);
        }
    }
    // Sleep queue is threaded by sleep_next, not next — walk
    // that separately.
    for (Task* t = g_sleep_head; t != nullptr; t = t->sleep_next)
    {
        if (t == running)
            continue;
        EmitTask(t, cb, cookie, false);
    }
    EmitList(g_zombies, cb, cookie, running);
    arch::Sti();
}

bool SchedIsPidZombie(u64 target_pid)
{
    arch::Cli();
    bool hit = false;
    for (Task* t = g_zombies; t != nullptr; t = t->next)
    {
        if (t->process != nullptr && t->process->pid == target_pid)
        {
            hit = true;
            break;
        }
    }
    arch::Sti();
    return hit;
}

u64 SchedCountChildrenOfPid(u64 parent_pid)
{
    if (!cpu::BspInstalled())
    {
        return 0;
    }
    auto count_in = [&](Task* head, bool follow_sleep) -> u64
    {
        u64 n = 0;
        for (Task* t = head; t != nullptr; t = follow_sleep ? t->sleep_next : t->next)
        {
            if (t->process != nullptr && t->process->linux_parent_pid == parent_pid)
                ++n;
        }
        return n;
    };

    arch::Cli();
    u64 total = 0;
    Task* running = Current();
    if (running != nullptr && running->process != nullptr && running->process->linux_parent_pid == parent_pid)
        ++total;
    ForEachRunqueueTask(
        [&](Task* t)
        {
            if (t->process != nullptr && t->process->linux_parent_pid == parent_pid)
            {
                ++total;
            }
            return false;
        });
    total += count_in(g_sleep_head, true);
    arch::Sti();
    return total;
}

core::Process* SchedFindProcessByPid(u64 target_pid)
{
    if (!cpu::BspInstalled())
    {
        return nullptr;
    }
    auto match = [&](Task* t) -> core::Process*
    {
        if (t == nullptr)
        {
            return nullptr;
        }
        core::Process* p = t->process;
        if (p == nullptr)
        {
            return nullptr;
        }
        if (p->pid != target_pid)
        {
            return nullptr;
        }
        return p;
    };

    arch::Cli();
    core::Process* hit = nullptr;
    Task* running = Current();
    if ((hit = match(running)) != nullptr)
    {
        arch::Sti();
        return hit;
    }
    ForEachRunqueueTask(
        [&](Task* t)
        {
            hit = match(t);
            return hit != nullptr;
        });
    if (hit == nullptr)
    {
        for (Task* t = g_sleep_head; t != nullptr && hit == nullptr; t = t->sleep_next)
        {
            hit = match(t);
        }
    }
    if (hit == nullptr)
    {
        for (Task* t = g_zombies; t != nullptr && hit == nullptr; t = t->next)
        {
            hit = match(t);
        }
    }
    arch::Sti();
    return hit;
}

Task* SchedFindTaskByTid(u64 target_tid)
{
    if (!cpu::BspInstalled())
    {
        return nullptr;
    }
    // Same walk shape as SchedFindProcessByPid — every list that
    // can hold a Task. Returns the first task whose id matches.
    // Caller must hold a stable reference to the task's owning
    // Process (via ProcessRetain) before SchedFindTaskByTid
    // returns, otherwise the task could be reaped and the Task*
    // freed under the caller's hand. The intended caller is
    // SYS_THREAD_OPEN, which captures the owning Process* via
    // task->process and ProcessRetains it inside the same
    // arch::Cli window before this function returns.
    arch::Cli();
    auto match = [&](Task* t) -> Task* { return (t != nullptr && t->id == target_tid) ? t : nullptr; };
    Task* hit = match(Current());
    if (hit != nullptr)
    {
        arch::Sti();
        return hit;
    }
    ForEachRunqueueTask(
        [&](Task* t)
        {
            hit = match(t);
            return hit != nullptr;
        });
    if (hit == nullptr)
    {
        for (Task* t = g_sleep_head; t != nullptr && hit == nullptr; t = t->sleep_next)
        {
            hit = match(t);
        }
    }
    // Skip zombies — opening a handle on a dead task is a v0
    // GAP we don't service. The kernel zeroes a Process* once
    // the task is in the zombie list (the reaper holds the
    // last refcount), so there'd be no Process to retain
    // even if we tried.
    arch::Sti();
    return hit;
}

// ---------------------------------------------------------------------------
// Dead-task reaper
//
// Runs as a dedicated kernel thread. Sleeps on g_reaper_wq; woken by
// SchedExit whenever a task flips to Dead. Consumes the zombie list
// one at a time and KFrees each task's stack + Task struct.
//
// Why a dedicated thread rather than inline cleanup in SchedExit:
// the dying task is still running on its own stack. Freeing the
// stack from within SchedExit would pull the rug out from under the
// very function doing the freeing. The reaper runs on a DIFFERENT
// stack, so by the time it sees a zombie, that zombie is off-CPU
// and its stack is safe to free.
//
// v0 is lazy — one reap per wake. Batching when many tasks exit at
// once is a straightforward follow-up (the zombie list is already
// a LIFO singly-linked list; we could drain it entirely per wake).
// ---------------------------------------------------------------------------
namespace
{

[[noreturn]] void ReaperMain(void*)
{
    for (;;)
    {
        arch::Cli();
        while (g_zombies == nullptr)
        {
            WaitQueueBlock(&g_reaper_wq);
        }

        // Detach the entire zombie list. `SchedFinishTaskSwitch`
        // adds new zombies under `g_sched_lock` (the SMP-safe
        // deferred-zombie handoff that closes the reaper-frees-
        // running-stack UAF), so the detach must hold the same
        // lock to observe a consistent list head. Single-CPU
        // boots are unaffected; SMP boots no longer race the
        // producer.
        //
        // Zombies are now provably off-CPU by construction —
        // `SchedFinishTaskSwitch` only promotes them AFTER the
        // outgoing `ContextSwitch` has committed — so the order
        // we free them in still doesn't matter. Draining the
        // list in one pass avoids N wake-up round trips when a
        // burst of tasks exits at once.
        Task* drained = nullptr;
        {
            sync::IrqFlags lf = sync::SpinLockAcquire(g_sched_lock);
            drained = g_zombies;
            g_zombies = nullptr;
            sync::SpinLockRelease(g_sched_lock, lf);
        }
        arch::Sti();

        // KFree happens AFTER we Sti so the heap path is not running
        // with interrupts disabled (the heap is not required to be
        // IRQ-safe today, but holding CLI across KFree locks out the
        // timer for longer than the reap itself).
        while (drained != nullptr)
        {
            Task* dead = drained;
            drained = dead->next;
            dead->next = nullptr;

            // Drop the task's process reference. The Process owns
            // the AS — ProcessRelease drops its AS reference, and
            // when the last holder goes away the AS destructor
            // walks the region table, returns every backing user
            // frame, walks the user-half page tables to free
            // intermediate PDPT/PD/PT pages, and frees the PML4
            // frame. Tasks with process == nullptr (kernel-only
            // workers, idle, reaper's own thread) fall through
            // with no state change.
            //
            // AS-only tasks (process == nullptr but as != nullptr)
            // don't exist today but the fallback path is preserved
            // so a future helper that spawns a ring-3 thread
            // without a surrounding Process (testing, diagnostics)
            // still gets its AS reaped.
            //
            // Must happen BEFORE freeing the Task struct — we read
            // the pointers out of it — and AFTER the dying task is
            // off-CPU (which it is by construction: SchedExit only
            // enqueues to the zombie list once Schedule() has
            // switched away).
            if (dead->process != nullptr)
            {
                core::ProcessRelease(dead->process);
                dead->process = nullptr;
                dead->as = nullptr; // process owned it; pointer is now dangling, clear it
            }
            else
            {
                mm::AddressSpaceRelease(dead->as);
                dead->as = nullptr;
            }

            // Stack_base can be nullptr for the boot task (task 0);
            // defensive null-check even though task 0 should never
            // exit. Every other task got a canary planted at
            // stack_base in SchedCreate — verify before freeing so
            // any overflow that stayed above the guard page still
            // surfaces here as a named panic.
            if (dead->stack_base != nullptr)
            {
                const u64 canary = *reinterpret_cast<const u64*>(dead->stack_base);
                if (canary != kStackCanary)
                {
                    core::PanicWithValue("sched/reaper", "stack canary corrupted (task overflow?)", canary);
                }
                mm::FreeKernelStack(dead->stack_base, dead->stack_size);
            }
            mm::KFree(dead);
            SchedCpuIncReaped();

            core::LogWithValue(core::LogLevel::Info, "sched/reaper", "reaped task id", SchedSumReaped());
        }
    }
}

} // namespace

void SchedStartReaper()
{
    SchedCreate(&ReaperMain, nullptr, "reaper");
    core::Log(core::LogLevel::Info, "sched/reaper", "reaper thread online");
}

// ---------------------------------------------------------------------------
// Idle task
//
// The round-robin runqueue must never be empty while any task is
// Sleeping or Blocked — Schedule() panics with "no runnable task
// available" if the only non-Running task on the system just blocked.
// The boot task used to paper over this by being a perpetually-
// Running fallback, but as soon as kernel_main calls SchedSleepTicks
// (e.g. inside SmpStartAps's INIT→SIPI spacing) the boot task is no
// longer Running, and if no worker has been created yet we crash.
//
// SchedStartIdle spawns a dedicated kernel thread that does `sti;
// hlt` forever. It's a normal round-robin participant — nothing
// special — but because it never blocks and never exits, the
// runqueue always has at least one member to hand out. When it runs,
// it halts until the next IRQ, so it consumes effectively no CPU.
//
// SMP: each AP calls SchedStartIdle("idle-apN") from
// ApEntryFromTrampoline once its PerCpu / LAPIC timer are armed.
// That's how we ensure every CPU has a local fallback without
// having to special-case scheduler state for empty runqueues.
// ---------------------------------------------------------------------------
namespace
{

// Low-power idle. MONITOR/MWAIT lets the core drop into an
// MWAIT-C1 power state that is at least as deep as a bare HLT
// (and lower-power on most parts) while keeping identical wake
// semantics: `Sti()` is issued before this, so a normal unmasked
// IRQ (timer tick / reschedule IPI) breaks MWAIT exactly as it
// breaks HLT and the dispatcher runs on the same events.
//
// MWAIT ECX MUST be 0: the only non-zero bit (bit0, "treat a
// masked interrupt as a break-event") is an OPTIONAL extension
// gated on CPUID.5:ECX[1]. Passing ECX=1 on a CPU/hypervisor
// that doesn't implement the extension #GPs — and because the
// fault handler returns to the same MWAIT, that recurses until
// the idle task's kernel stack hits its guard page (the
// idle-bsp#5 overflow this replaced). ECX=0 needs no leaf-5
// feature and, with IF=1 from Sti(), is exactly HLT-equivalent.
// EAX=0 = C1 hint (conservative, no deep-C-state latency). The
// caller only sets use_mwait when CPUID leaf 5 actually exists.
// Falls back to HLT verbatim when MWAIT is unavailable.
// MWAIT is safe to use only if CPUID advertises MONITOR (leaf 1
// ECX[3]) AND the MONITOR/MWAIT enumeration leaf (5) actually
// exists. Some hypervisors set ECX[3] but expose no leaf 5; using
// MWAIT there is undefined. Belt-and-suspenders with the ECX=0
// fix above.
inline bool MwaitUsable()
{
    if (!arch::CpuHas(arch::kCpuFeatMonitor))
    {
        return false;
    }
    u32 max_leaf, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(max_leaf), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    return max_leaf >= 5u;
}

inline void CpuIdleLowPower(volatile u8* monitor_cell, bool use_mwait)
{
    if (use_mwait)
    {
        asm volatile("monitor" ::"a"(monitor_cell), "c"(0), "d"(0));
        asm volatile("mwait" ::"a"(0), "c"(0));
    }
    else
    {
        asm volatile("hlt");
    }
}

[[noreturn]] void IdleMain(void*)
{
    const bool use_mwait = MwaitUsable();
    volatile u8 monitor_cell = 0; // per-idle-task (per-CPU) MONITOR line
    for (;;)
    {
        // Drain any RCU callbacks queued on THIS CPU before
        // halting. The grace contract guarantees no reader is
        // mid-walk over the freed objects, and the idle task is
        // by definition not in any RCU read-side critical
        // section. Cost: one uncontended per-CPU SpinLock acquire
        // and a count==0 check when the queue is empty.
        //
        // If callbacks DO fire, they consume time on this CPU
        // that would otherwise be spent halted — turning idle
        // cycles into useful reclamation work. Each AP runs its
        // own copy of this loop, so reclamation parallelises
        // across the box at zero scheduling cost.
        sync::RcuReclaimLocal();
        arch::Sti();
        CpuIdleLowPower(&monitor_cell, use_mwait);
    }
}

} // namespace

void SchedStartIdle(const char* name)
{
    KASSERT(name != nullptr, "sched", "SchedStartIdle null name");
    Task* idle = SchedCreate(&IdleMain, nullptr, name, TaskPriority::Idle);
    // Pin the idle task to the CPU that is starting it. The rest of
    // the scheduler treats idle tasks as strictly per-CPU ("Idle
    // tasks are per-CPU and not eligible to steal"), but SchedCreate
    // defaults affinity_mask to kAffinityAll — an unpinned idle task
    // can then be popped / load-balanced onto a DIFFERENT CPU. When
    // two CPUs end up sharing one idle task's stack / Task struct
    // the result is a task running on two CPUs at once, surfacing
    // as the intermittent MUTEX-NONOWNER the gui-fuzz harness
    // reproduces under SMP. SchedStartIdle runs on the owning CPU
    // (BSP from SchedInit, each AP from SchedEnterOnAp), so
    // CurrentCpu() is the correct home. Direct mask store (not
    // SchedSetAffinityMask) — the task was just created, nothing
    // is contending it yet, and the heavier re-home path is
    // needless this early.
    if (idle != nullptr)
    {
        cpu::PerCpu* self = cpu::CurrentCpu();
        if (self != nullptr)
        {
            idle->affinity_mask = (1u << self->cpu_id);
            // Publish the per-CPU idle task pointer. Read by
            // ScheduleLockedHandoff as a last-resort dispatch
            // target — see PerCpu::idle_task in cpu/percpu.h for
            // the race this closes.
            self->idle_task = idle;
            // Open the wake/balance/steal gate: from here on,
            // peer CPUs may route tasks to this CPU. This MUST
            // be the last write before the Log call below — see
            // PerCpu::scheduler_ready in cpu/percpu.h.
            self->scheduler_ready = true;
            // One-line raw-serial breadcrumb so a post-mortem can
            // confirm which PerCpu slot got armed with which idle
            // task. The "no runnable task available" panic on an
            // SMP boot consistently shows `self->idle_task == 0` on
            // one AP — this line lets us see whether SchedStartIdle
            // wrote to that AP's slot (panic = race) or wrote to a
            // peer's slot (panic = CurrentCpu mis-resolution).
            // Raw serial because we hold no locks and want zero
            // re-entry risk; klog routes through Tee.
            arch::SerialWrite("[sched/idle] armed cpu_id=");
            arch::SerialWriteHex(static_cast<u64>(self->cpu_id));
            arch::SerialWrite(" perpcu=");
            arch::SerialWriteHex(reinterpret_cast<u64>(self));
            arch::SerialWrite(" idle=");
            arch::SerialWriteHex(reinterpret_cast<u64>(idle));
            arch::SerialWrite("\n");
        }
    }
    core::Log(core::LogLevel::Info, "sched/idle", "idle task online");
}

namespace
{

// Mint a non-runnable boot sentinel for an AP about to enter the
// scheduler. Schedule()'s null-current check (sched.cpp top) panics
// without a current task; we need a placeholder so the AP's first
// Schedule() call has somewhere to record `prev->rsp`. The sentinel
// is never re-resumed (state never flips back to Ready), so its
// trampoline-stack frame is leaked-by-design; bounded at 16 KiB ×
// kMaxAps. Documented at the SmpStartAps allocation site.
Task* CreateApBootSentinel(u32 cpu_id)
{
    auto* t = static_cast<Task*>(mm::KMalloc(sizeof(Task)));
    if (t == nullptr)
    {
        PanicSched("KMalloc failed for AP boot sentinel");
    }
    memset(t, 0, sizeof(Task));
    t->id = g_next_task_id++;
    t->state = TaskState::Running;
    // NEVER re-enqueue this fake task. Without this, the AP's first
    // Schedule() sees prev==sentinel in state Running and
    // RunqueueOrSuspendPush()es it onto the GLOBAL runqueue; a peer
    // CPU then pops it and ContextSwitches into a placeholder rsp on
    // the AP trampoline stack — two CPUs executing one stack, the
    // SMP double-run behind the intermittent MUTEX-NONOWNER / sched
    // spinlock self-deadlock.
    t->no_requeue = true;
    t->rsp = 0;              // populated by ContextSwitch's first store
    t->stack_base = nullptr; // sentinel is on the trampoline stack — never inspected
    t->stack_size = 0;
    t->name = "ap-boot";
    t->priority = TaskPriority::Normal;
    t->last_cpu = cpu_id;
    t->affinity_mask = kAffinityAll;
    return t;
}

// Build a per-AP idle name "idle-apN" without pulling in stdio.
// Caller's buffer must be ≥16 bytes; result is null-terminated.
void FormatIdleApName(char (&out)[16], u32 cpu_id)
{
    out[0] = 'i';
    out[1] = 'd';
    out[2] = 'l';
    out[3] = 'e';
    out[4] = '-';
    out[5] = 'a';
    out[6] = 'p';
    // Decimal cpu_id (kMaxCpus = 32, so max 2 digits).
    char buf[8];
    u32 n = 0;
    u32 v = cpu_id;
    if (v == 0)
    {
        buf[n++] = '0';
    }
    while (v != 0)
    {
        buf[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    u32 w = 7;
    while (n > 0 && w < 16)
    {
        out[w++] = buf[--n];
    }
    if (w >= 16)
    {
        w = 15;
    }
    out[w] = '\0';
}

} // namespace

[[noreturn]] void SchedEnterOnAp(u32 cpu_id)
{
    // AP-bringup tracer. Raw serial; pairs with the smp.cpp
    // "[arch/smp] AP pre-enter" line above, and locates whether
    // SchedStartIdle even started for a given cpu_id.
    // SerialLineGuard around each multi-write sentinel: without it
    // a peer CPU's loadtest/stress lines slip between our Write*
    // calls and split the sentinel across two physical lines
    // (observed 2026-05-22 under SMP=8 stress).
    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[sched/smp] SchedEnterOnAp begin cpu_id=");
        arch::SerialWriteHex(static_cast<u64>(cpu_id));
        arch::SerialWrite("\n");
    }
    // 1. Spawn this CPU's idle task. The Ready→runqueue push routes
    //    via t->last_cpu; SchedCreate sets last_cpu to the spawning
    //    CPU (which is THIS AP), so the idle lands on the AP's own
    //    runqueue.
    char name[16];
    FormatIdleApName(name, cpu_id);
    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[sched/smp] calling SchedStartIdle cpu_id=");
        arch::SerialWriteHex(static_cast<u64>(cpu_id));
        arch::SerialWrite("\n");
    }
    SchedStartIdle(name);
    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[sched/smp] SchedStartIdle returned cpu_id=");
        arch::SerialWriteHex(static_cast<u64>(cpu_id));
        arch::SerialWrite("\n");
    }

    // 2. Mint a boot sentinel so Schedule() has a non-null `prev`
    //    on its first call. Install as current_task BEFORE arming
    //    the LAPIC timer — once the timer fires, the IRQ handler
    //    enters Schedule() and dereferences Current().
    Task* sentinel = CreateApBootSentinel(cpu_id);
    cpu::CurrentCpu()->current_task = sentinel;

    // 3. Arm THIS CPU's LAPIC timer at 100 Hz. Vector 0x20 is
    //    already wired in the shared IDT; this just programs the
    //    AP's own LAPIC MMIO registers.
    arch::LapicTimerStartOnCurrent();

    KLOG_WARN_S("sched/smp", "AP scheduler-join complete; entering idle loop", "cpu", name);

    // 4. Drop into idle. The first timer IRQ on this CPU enters
    //    Schedule(), pulls a runnable task off this CPU's runqueue
    //    (or our just-spawned idle if no work is waiting), and
    //    never returns to this stack frame.
    const bool use_mwait = MwaitUsable();
    volatile u8 monitor_cell = 0;
    for (;;)
    {
        arch::Sti();
        CpuIdleLowPower(&monitor_cell, use_mwait);
    }
}

// ---------------------------------------------------------------------------
// Wait queues
//
// A WaitQueue is a singly-linked FIFO of Tasks parked in state Blocked.
// Callers uphold the interrupt-disabled contract so the "check then block"
// race is closed against IRQ-context wakers. See sched.h for the contract.
// ---------------------------------------------------------------------------

namespace
{

// Caller must hold g_sched_lock. Enqueue Current() on `wq` (FIFO)
// and flip it Blocked — the exact critical section WaitQueueBlock
// runs, minus the lock acquire. Factored out (mirrors why
// WaitQueueWakeOneLocked exists) so a caller that already holds
// g_sched_lock can splice "decide to wait" together with another
// state mutation — e.g. the mutex owner-check — into ONE
// indivisible region. Without that splice, MutexLock's owner test
// and its enqueue straddle a lock gap that a hand-off on another
// CPU races (the #-gui-fuzz MUTEX-NONOWNER / sched self-deadlock).
void WaitQueueBlockCurrentLocked(WaitQueue* wq)
{
    sync::SpinLockAssertHeld(g_sched_lock);
    Task* t = Current();
    // No current task means there is nothing to block (the
    // bootstrap / idle-handoff window before a real task is
    // installed). Bail before dereferencing — mirrors the
    // `if (t == nullptr) return;` guard every other Current()
    // consumer in this file uses. Without it, `t->state` below is
    // a NULL member-access (caught by -fsanitize=undefined's
    // type-mismatch as a null-deref of `Task`).
    if (t == nullptr)
    {
        return;
    }
    // The currently-executing task is necessarily Running. A
    // caller that reached this path with state already flipped
    // to Blocked / Sleeping / Dead would be re-enqueued on this
    // wait queue while still on another list (runqueue, sleep
    // queue, or zombies), corrupting whichever list holds it.
    KASSERT(t->state == TaskState::Running, "sched", "WaitQueueBlockCurrentLocked on non-Running task");
    t->state = TaskState::Blocked;
    t->next = nullptr;
    t->waiting_on = wq;
    t->wake_by_timeout = false;
    if (wq->tail == nullptr)
    {
        wq->head = wq->tail = t;
    }
    else
    {
        wq->tail->next = t;
        wq->tail = t;
    }
    SchedCpuIncBlocked();
}

} // namespace

void WaitQueueBlock(WaitQueue* wq)
{
    KASSERT(wq != nullptr, "sched", "WaitQueueBlock null queue");
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "WaitQueueBlock from inside critical section",
                       cpu::CriticalNesting());

    // Acquire manually + hold the lock straight through the
    // deschedule. The old guard-scope-then-Schedule() shape left an
    // SMP gap between the enqueue and Schedule()'s re-acquire (see
    // ScheduleLockedHandoff). The lock is handed off across the
    // context switch and released by SchedFinishTaskSwitch when this
    // task is later resumed.
    sync::IrqFlags f = sync::SpinLockAcquire(g_sched_lock);
    WaitQueueBlockCurrentLocked(wq);
    ScheduleLockedHandoff(f);
    // Woken. Our state was flipped back to Running by the scheduler +
    // the waker pushed us onto the runqueue before we got here.
}

bool WaitQueueBlockTimeout(WaitQueue* wq, u64 ticks)
{
    KASSERT(wq != nullptr, "sched", "WaitQueueBlockTimeout null queue");
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "WaitQueueBlockTimeout from inside critical section",
                       cpu::CriticalNesting());

    // Zero ticks: no wait at all — yield and declare it a timeout.
    // Callers should not rely on this as a "cheap test" — use
    // WaitQueueWakeOne's return value to poke the queue cheaply.
    if (ticks == 0)
    {
        SchedYield();
        return false;
    }

    // Continuous g_sched_lock hold from the state flip + dual
    // enqueue THROUGH the deschedule (see ScheduleLockedHandoff).
    // Both wake arms (WaitQueueWakeOne, OnTimerTick) take
    // g_sched_lock, so neither can fire until this task is genuinely
    // off-CPU — closing the SMP double-run window.
    sync::IrqFlags f = sync::SpinLockAcquire(g_sched_lock);
    {
        Task* t = Current();
        // Same invariant as WaitQueueBlock: the caller is the
        // currently-executing task, so state must be Running. A
        // non-Running task would get enqueued here while still on
        // its home list (runqueue, sleep queue, or zombies) and
        // corrupt whichever holds it.
        KASSERT(t->state == TaskState::Running, "sched", "WaitQueueBlockTimeout on non-Running task");
        t->state = TaskState::Blocked;
        t->next = nullptr;
        // Saturate the deadline rather than wrap. Without the clamp,
        // `g_tick_now + ticks` could overflow u64 (e.g., a Linux ABI
        // caller passing nsec_to_ticks(LLONG_MAX)); the wake-tick
        // comparator uses signed-diff arithmetic and would then read
        // the wrapped deadline as already-elapsed, making the wait
        // return immediately instead of blocking.
        t->wake_tick = (ticks > (~u64(0) - g_tick_now)) ? ~u64(0) : (g_tick_now + ticks);
        t->waiting_on = wq;
        t->wake_by_timeout = false;

        // Enqueue on the wait queue (FIFO, same as WaitQueueBlock).
        if (wq->tail == nullptr)
        {
            wq->head = wq->tail = t;
        }
        else
        {
            wq->tail->next = t;
            wq->tail = t;
        }
        SchedCpuIncBlocked();

        // Enqueue on the sleep queue so the timer path can fire
        // if nobody wakes us first. Both lists hold the same
        // Task* — the two wake paths race, and whichever wins
        // unlinks the loser.
        SleepqueueInsert(t);
        SchedCpuIncSleeping();
    }

    ScheduleLockedHandoff(f);

    // Woken by one of two paths. `wake_by_timeout` was written by
    // whichever path fired first (OnTimerTick sets true,
    // WaitQueueWakeOne clears false). Read once here — the field
    // is reused on the next wait.
    const bool timed_out = Current()->wake_by_timeout;
    return !timed_out;
}

namespace
{

// Caller must hold g_sched_lock. Pulls the head of `wq`, does all
// the book-keeping (sleep-queue unlink for timed waiters, counters,
// state flip, runqueue push), and returns the woken Task*.
// Factored out so CondvarWait can call it under its own held lock
// to splice the mutex hand-off + self-enqueue atomically.
Task* WaitQueueWakeOneLocked(WaitQueue* wq)
{
    // "Caller must hold g_sched_lock" (above): this does a runqueue
    // push as part of the wake, so an unlocked call races the
    // scheduler. The _Locked suffix is the contract — assert it.
    sync::SpinLockAssertHeld(g_sched_lock);
    Task* t = wq->head;
    if (t == nullptr)
    {
        return nullptr;
    }
    wq->head = t->next;
    if (wq->head == nullptr)
    {
        wq->tail = nullptr;
    }
    t->next = nullptr;

    if (t->wake_tick != 0)
    {
        SleepqueueRemove(t);
        SchedCpuDecSleeping();
    }
    t->waiting_on = nullptr;
    t->wake_tick = 0;
    t->wake_by_timeout = false;
    // Suspended waiters get reparked instead of unblocked.
    RunqueueOrSuspendPush(t);
    SchedCpuDecBlocked();
    return t;
}

} // namespace

Task* WaitQueueWakeOne(WaitQueue* wq)
{
    KASSERT(wq != nullptr, "sched", "WaitQueueWakeOne null queue");

    Task* t = nullptr;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        t = WaitQueueWakeOneLocked(wq);
        if (t == nullptr)
        {
            return nullptr;
        }
    }

    // If the wake happens from a non-IRQ context, leaving need_resched set
    // lets the very next timer tick preempt us into the woken task. If
    // it's from IRQ context, the dispatcher already checks need_resched
    // after EOI. Either path converges. need_resched is per-CPU, so
    // setting it outside the lock is safe.
    NeedResched() = true;
    return t;
}

u64 WaitQueueWakeAll(WaitQueue* wq)
{
    KASSERT(wq != nullptr, "sched", "WaitQueueWakeAll null queue");

    // Drain the queue under a single lock acquire. The old loop
    // called WaitQueueWakeOne per waiter, which re-took
    // g_sched_lock N times; that's the dominant cost on a
    // broadcast wake (CondVar broadcast, barrier release) when
    // N is large. Setting need_resched once at the end matches
    // the per-wake semantics since it's a per-CPU edge-trigger
    // flag — repeated stores within one critical section are
    // indistinguishable from one.
    u64 count = 0;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        while (WaitQueueWakeOneLocked(wq) != nullptr)
        {
            ++count;
        }
    }
    if (count != 0)
    {
        NeedResched() = true;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Mutex
//
// Owner pointer doubles as the "locked" flag. An unowned mutex has
// owner == nullptr and empty waiters. Lock contention parks the caller on
// the waiters queue; Unlock hands the lock directly to the longest-waiting
// task (FIFO fairness), avoiding the thundering-herd pattern of "wake all,
// everyone re-races for the lock."
// ---------------------------------------------------------------------------

void MutexLock(Mutex* m)
{
    KASSERT(m != nullptr, "sched", "MutexLock null mutex");
    // Sleeping-mutex acquire inside a preempt-off critical section
    // is a contract violation — the park path goes through
    // ScheduleLockedHandoff which would deschedule us while
    // critnest > 0, silently disabling preemption forever on the
    // CPU that picks us back up.
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "MutexLock from inside critical section",
                       cpu::CriticalNesting());

    // Lockdep edge-walk before the wait/acquire — the "held → this"
    // edge is recorded against any tagged SpinLock / Mutex this task
    // already holds. Untagged mutexes short-circuit inside the hook.
    ::duetos::sync::LockdepBeforeAcquire(m->class_id);

    // Owner test + (fast acquire | slow-path enqueue) MUST be one
    // indivisible region with respect to MutexUnlock's hand-off. A
    // bare arch::Cli() only masks IRQs on THIS CPU — on SMP it is
    // not mutual exclusion, so a concurrent MutexUnlock on another
    // CPU could clear m->owner (its `m->owner = nullptr` step),
    // letting this CPU's owner==nullptr test take the fast path and
    // claim the lock, only for the unlocker's hand-off to then
    // overwrite m->owner with a woken waiter — two tasks believing
    // they hold it, surfacing later as MUTEX-NONOWNER / a
    // sched-class spinlock self-deadlock. Holding g_sched_lock
    // across the decision (the same lock the hand-off and the
    // wait-queue enqueue take) closes that window — exactly the
    // pattern CondvarWait already uses.
    // Acquire g_sched_lock manually (not via SpinLockGuard): on the
    // contended path the lock must ride the context switch via
    // ScheduleLockedHandoff, so it is NOT released here — it is
    // dropped by SchedFinishTaskSwitch when this task is resumed
    // owning the mutex. On the fast path we release it ourselves.
    // The owner test + the (fast claim | slow enqueue) decision +
    // the deschedule are now ONE continuous hold, with no gap an
    // Unlock hand-off or a peer-CPU waker can slip into.
    sync::IrqFlags f = sync::SpinLockAcquire(g_sched_lock);
    // Self-deadlock guard (the owning-re-entry check sched.h's
    // Mutex doc explicitly asks for). Recursion is unsupported: if
    // the caller already owns `m`, the else-branch would block it
    // on m->waiters waiting for an unlock that only it could issue
    // — that task never runs again, and anything waiting on it
    // cascades into a system-wide hang. Always-on (KASSERT): an
    // unrecoverable hang is catastrophic in release too.
    // Predicate is owner==nullptr || owner!=Current — NOT
    // owner!=Current alone: during early boot Current() is nullptr
    // and the uncontended owner is also nullptr, so the naive form
    // would panic every pre-scheduler mutex acquire (slab uses a
    // sched::Mutex before tasks exist). A self-deadlock requires a
    // non-null owner equal to the running task.
    KASSERT(m->owner == nullptr || m->owner != Current(), "sched",
            "self-deadlock: MutexLock of a mutex this task already owns");
    if (m->owner == nullptr)
    {
        // Fast path: uncontended acquire.
        m->owner = Current();
        sync::SpinLockRelease(g_sched_lock, f);
    }
    else
    {
        // Slow path: enqueue self on the waiters queue and
        // deschedule under the SAME hold the owner test ran under,
        // so neither an Unlock hand-off nor a peer-CPU waker can
        // slip between "decide to wait" and "actually off-CPU".
        // Unlock's hand-off sets m->owner = us BEFORE waking us, so
        // there's nothing to redo here — the lock is already ours
        // when ScheduleLockedHandoff returns (on our resumed stack).
        WaitQueueBlockCurrentLocked(&m->waiters);
        ScheduleLockedHandoff(f);
    }

    // After successful acquire — push onto the lockdep held stack.
    ::duetos::sync::LockdepAfterAcquire(m->class_id);

    // Event-tracer instrumentation. arg0 = mutex pointer (so a
    // tracer dump can correlate acquire / release pairs);
    // arg1 = current task id.
    ::duetos::diag::EventTrace(::duetos::diag::kEventMutexAcquire, reinterpret_cast<u64>(m), CurrentTaskId());
}

bool MutexTryLock(Mutex* m)
{
    KASSERT(m != nullptr, "sched", "MutexTryLock null mutex");

    // Same SMP rationale as MutexLock: the owner test + claim must
    // run under g_sched_lock or a concurrent hand-off on another
    // CPU races the read-modify-write of m->owner.
    bool ok = false;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        ok = (m->owner == nullptr);
        if (ok)
        {
            m->owner = Current();
        }
    }
    if (ok)
    {
        // Treat a successful try-lock as a full acquire for lockdep —
        // we hold it now, so the held stack must reflect that. Skip
        // BeforeAcquire on the failing path so we don't record a
        // never-acquired edge.
        ::duetos::sync::LockdepBeforeAcquire(m->class_id);
        ::duetos::sync::LockdepAfterAcquire(m->class_id);
    }
    return ok;
}

bool MutexLockTimed(Mutex* m, u64 ticks)
{
    KASSERT(m != nullptr, "sched", "MutexLockTimed null mutex");

    // Lockdep edge-walk before the wait/acquire — even on the timed
    // path, the "held → this" edge is real once we decide to wait.
    // Matches MutexLock; the held-stack push (LockdepAfterAcquire)
    // fires only on the success arm so a timed-out attempt never
    // appears to be held.
    ::duetos::sync::LockdepBeforeAcquire(m->class_id);

    arch::Cli();
    // Same self-deadlock guard as MutexLock: an owner that re-enters
    // here skips the fast path and blocks on m->waiters waiting for
    // its own unlock — best case it burns the full timeout and then
    // wrongly returns false for a mutex it actually holds. Recursion
    // is unsupported (sched.h Mutex doc); make the contract uniform
    // across every blocking acquire entry point.
    // owner==nullptr || owner!=Current — see the MutexLock guard for
    // why the nullptr disjunct is load-bearing (early-boot Current()).
    KASSERT(m->owner == nullptr || m->owner != Current(), "sched",
            "self-deadlock: MutexLockTimed of a mutex this task already owns");
    if (m->owner == nullptr)
    {
        // Fast path: uncontended acquire.
        m->owner = Current();
        arch::Sti();
        ::duetos::sync::LockdepAfterAcquire(m->class_id);
        ::duetos::diag::EventTrace(::duetos::diag::kEventMutexAcquire, reinterpret_cast<u64>(m), CurrentTaskId());
        return true;
    }

    // Slow path with timeout. MutexUnlock's hand-off sets m->owner
    // = us BEFORE WaitQueueWakeOne wakes us, so a `true` return
    // means the lock is already ours. A `false` return means the
    // timer fired first and unlinked us from m->waiters before any
    // unlock could pick us — m->owner is unchanged.
    const bool got = WaitQueueBlockTimeout(&m->waiters, ticks);
    arch::Sti();

    if (got)
    {
        ::duetos::sync::LockdepAfterAcquire(m->class_id);
        ::duetos::diag::EventTrace(::duetos::diag::kEventMutexAcquire, reinterpret_cast<u64>(m), CurrentTaskId());
    }
    return got;
}

void MutexUnlock(Mutex* m)
{
    KASSERT(m != nullptr, "sched", "MutexUnlock null mutex");

    // Pop from lockdep held stack BEFORE the owner pointer changes —
    // mirrors the SpinLockRelease ordering.
    ::duetos::sync::LockdepBeforeRelease(m->class_id);

    // The owner test, the m->owner clear, and the hand-off
    // (wake-one + ownership transfer) are ONE region under
    // g_sched_lock. A bare arch::Cli() was insufficient on SMP:
    // between `m->owner = nullptr` and the hand-off's
    // `m->owner = next`, a MutexLock on another CPU saw owner ==
    // nullptr and claimed the lock via the fast path, so the
    // hand-off then handed the SAME mutex to a second task. The
    // surviving symptom was an intermittent MUTEX-NONOWNER (the
    // double-claimer's later Unlock) or a sched-class spinlock
    // self-deadlock — both reproduced by the gui-fuzz harness.
    // WaitQueueWakeOneLocked (vs the public WaitQueueWakeOne)
    // keeps the wake inside the same hold instead of dropping and
    // retaking g_sched_lock mid-transfer.
    bool nonowner = false;
    Task* bad_owner = nullptr;
    bool handed_off = false;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        if (m->owner != Current())
        {
            nonowner = true;
            bad_owner = m->owner;
        }
        else
        {
            m->owner = nullptr;
            // Hand-off: wake the longest waiter AND transfer
            // ownership directly. Without hand-off a freshly-woken
            // waiter would re-acquire a lock we just cleared,
            // racing any Lock in the gap; hand-off guarantees FIFO
            // progress.
            Task* next = WaitQueueWakeOneLocked(&m->waiters);
            if (next != nullptr)
            {
                m->owner = next;
                handed_off = true;
            }
        }
    }

    if (nonowner)
    {
        // Caller-side contract violation. Debug builds panic so the
        // bad caller is found; release builds log and return
        // without having mutated m. Kept OUT of the g_sched_lock
        // region: serial writes + the panic path must not run with
        // the scheduler lock held. The raw-serial breadcrumb names
        // the mutex, its lockdep class, the actual owner, the bad
        // caller and its return address — the detector pattern that
        // cracked the #283 spinlock self-deadlock.
        const u64 caller_rip = reinterpret_cast<u64>(__builtin_return_address(0));
        arch::SerialWrite("[sched] MUTEX-NONOWNER m=");
        arch::SerialWriteHex(reinterpret_cast<u64>(m));
        arch::SerialWrite(" class=");
        arch::SerialWriteHex(static_cast<u64>(m->class_id));
        arch::SerialWrite(" actual_owner_tid=");
        arch::SerialWriteHex((bad_owner != nullptr) ? bad_owner->id : 0);
        arch::SerialWrite(" caller_tid=");
        arch::SerialWriteHex(CurrentTaskId());
        arch::SerialWrite(" caller_rip=");
        arch::SerialWriteHex(caller_rip);
        arch::SerialWrite("\n");
        core::DebugPanicOrWarn("sched", "MutexUnlock by non-owner");
        return;
    }

    // A non-IRQ-context wake leaves need_resched set so the next
    // timer tick preempts into the woken waiter; from IRQ context
    // the dispatcher already re-checks it after EOI. need_resched
    // is per-CPU, so setting it outside the lock is safe — this
    // mirrors what the public WaitQueueWakeOne did for us before.
    if (handed_off)
    {
        NeedResched() = true;
    }

    ::duetos::diag::EventTrace(::duetos::diag::kEventMutexRelease, reinterpret_cast<u64>(m), CurrentTaskId());
}

// ---------------------------------------------------------------------------
// Condition variable
//
// Splices three existing primitives under a single sched_lock hold:
//   1. Hand off the companion mutex (FIFO wake of m->waiters, owner
//      pointer re-assigned atomically — same semantics as MutexUnlock
//      except inlined so the whole sequence is indivisible from the
//      scheduler's point of view).
//   2. Enqueue the caller on cv->waiters (state = Blocked).
// Then Schedule() switches away. On wake the task re-acquires m via
// the standard MutexLock path.
//
// The critical invariant: steps 1 and 2 happen under the same
// sched_lock hold, so a CondvarSignal that runs between them is
// impossible — either the signal sees cv->waiters already holding
// us (and wakes us), or it sees cv->waiters empty (and is a no-op,
// which is fine because the companion mutex still blocks the
// signaller from having produced anything we were waiting for).
// ---------------------------------------------------------------------------

void CondvarWait(Condvar* cv, Mutex* m)
{
    KASSERT(cv != nullptr, "sched", "CondvarWait null condvar");
    KASSERT(m != nullptr, "sched", "CondvarWait null mutex");
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "CondvarWait from inside critical section",
                       cpu::CriticalNesting());

    arch::Cli();
    if (m->owner != Current())
    {
        // Caller broke the condvar contract — must hold the
        // companion mutex when calling Wait. Debug: panic.
        // Release: log, re-enable interrupts, and return without
        // dequeuing onto cv. The caller is buggy, but at least the
        // kernel doesn't enqueue a wait that could later be woken
        // and reacquire a mutex this task never owned.
        arch::Sti();
        core::DebugPanicOrWarn("sched", "CondvarWait called without the companion mutex held");
        return;
    }

    // Drop the lockdep held-stack entry for `m` here, mirroring the
    // owner transfer below. The caller pushed `m` onto the stack
    // when it called MutexLock; the post-wake MutexLock(m) below
    // will push it again. Without this pop, every CondvarWait
    // leaks one orphan held-stack entry per call, which slowly
    // poisons the lockdep view and surfaces as spurious
    // "release with no matching held entry" warnings much later.
    ::duetos::sync::LockdepBeforeRelease(m->class_id);

    // Mutex hand-off + self-enqueue + deschedule under ONE
    // continuous g_sched_lock hold (see ScheduleLockedHandoff). The
    // old guard-scope-then-Schedule() shape reopened the SMP
    // double-run gap that the hand-off was specifically written to
    // avoid; routing the deschedule through ScheduleLockedHandoff
    // keeps the whole sequence indivisible from a peer CPU's view.
    sync::IrqFlags f = sync::SpinLockAcquire(g_sched_lock);
    {
        // Atomic mutex hand-off: wake the longest-waiting contender
        // and transfer ownership directly to it. Same FIFO-fairness
        // semantics as MutexUnlock; inlined so no sched_lock
        // re-entry is needed.
        Task* successor = WaitQueueWakeOneLocked(&m->waiters);
        m->owner = successor; // nullptr if no contender, fine

        // Enqueue self on the condvar's waiters.
        Task* t = Current();
        t->state = TaskState::Blocked;
        t->next = nullptr;
        t->wake_tick = 0;
        t->waiting_on = &cv->waiters;
        t->wake_by_timeout = false;
        if (cv->waiters.tail == nullptr)
        {
            cv->waiters.head = cv->waiters.tail = t;
        }
        else
        {
            cv->waiters.tail->next = t;
            cv->waiters.tail = t;
        }
        SchedCpuIncBlocked();
    }

    ScheduleLockedHandoff(f);
    // Woken by CondvarSignal / CondvarBroadcast. Interrupts are
    // still disabled; re-enable before re-acquiring the mutex so
    // MutexLock's slow path doesn't run with IF=0 across a
    // context switch.
    arch::Sti();
    MutexLock(m);
}

bool CondvarWaitTimeout(Condvar* cv, Mutex* m, u64 ticks)
{
    KASSERT(cv != nullptr, "sched", "CondvarWaitTimeout null condvar");
    KASSERT(m != nullptr, "sched", "CondvarWaitTimeout null mutex");
    KASSERT_WITH_VALUE(cpu::CriticalNesting() == 0, "sched", "CondvarWaitTimeout from inside critical section",
                       cpu::CriticalNesting());

    // Zero ticks: drop the lock, yield, re-acquire — report as
    // timeout so the caller doesn't treat a missed signal as a
    // real one.
    if (ticks == 0)
    {
        MutexUnlock(m);
        SchedYield();
        MutexLock(m);
        return false;
    }

    arch::Cli();
    if (m->owner != Current())
    {
        // Same contract as CondvarWait above. Release builds
        // surface the violation through klog and report a
        // timeout-style false return so the caller sees a
        // recoverable signal instead of a phantom wakeup.
        arch::Sti();
        core::DebugPanicOrWarn("sched", "CondvarWaitTimeout called without the companion mutex held");
        return false;
    }

    // Same lockdep accounting as CondvarWait: drop `m` from the
    // held-stack before the transfer, MutexLock(m) on wake will
    // re-push.
    ::duetos::sync::LockdepBeforeRelease(m->class_id);

    // One continuous g_sched_lock hold across hand-off + dual
    // enqueue + deschedule, same SMP rationale as CondvarWait /
    // WaitQueueBlockTimeout.
    sync::IrqFlags f = sync::SpinLockAcquire(g_sched_lock);
    {
        // Atomic mutex hand-off (identical to CondvarWait).
        Task* successor = WaitQueueWakeOneLocked(&m->waiters);
        m->owner = successor;

        // Enqueue self on condvar's waiters with a deadline, and
        // also on the sleep queue — the timer path is the second
        // wake arm, exactly like WaitQueueBlockTimeout.
        Task* t = Current();
        t->state = TaskState::Blocked;
        t->next = nullptr;
        // Saturate exactly like WaitQueueBlockTimeout (line ~3417):
        // an unclamped g_tick_now + ticks can wrap to 0 for a huge
        // (Linux-ABI-reachable) timeout, and wake_tick == 0 is the
        // "not a timed waiter" sentinel — WaitQueueWakeOneLocked
        // would then skip the sleep-queue unlink and leave this task
        // linked on the sleep list while it runs, corrupting the
        // intrusive sleep_next/sleep_prev chain.
        t->wake_tick = (ticks > (~u64(0) - g_tick_now)) ? ~u64(0) : (g_tick_now + ticks);
        t->waiting_on = &cv->waiters;
        t->wake_by_timeout = false;
        if (cv->waiters.tail == nullptr)
        {
            cv->waiters.head = cv->waiters.tail = t;
        }
        else
        {
            cv->waiters.tail->next = t;
            cv->waiters.tail = t;
        }
        SchedCpuIncBlocked();

        SleepqueueInsert(t);
        SchedCpuIncSleeping();
    }

    ScheduleLockedHandoff(f);
    // Woken. Read the timeout flag once — it's only valid for
    // this one wait and will be overwritten on the next block.
    const bool timed_out = Current()->wake_by_timeout;
    arch::Sti();
    MutexLock(m);
    return !timed_out;
}

void CondvarSignal(Condvar* cv)
{
    KASSERT(cv != nullptr, "sched", "CondvarSignal null condvar");
    // WaitQueueWakeOne moves the head task to Ready + sets
    // need_resched. The signal is valid whether or not the caller
    // holds the companion mutex — the canonical pattern is to hold
    // it so the signalled waiter sees a consistent guarded state
    // when it re-acquires, but we don't enforce that.
    WaitQueueWakeOne(&cv->waiters);
}

u64 CondvarBroadcast(Condvar* cv)
{
    KASSERT(cv != nullptr, "sched", "CondvarBroadcast null condvar");
    return WaitQueueWakeAll(&cv->waiters);
}

} // namespace duetos::sched

extern "C" [[noreturn]] void SchedExitC()
{
    duetos::sched::SchedExit();
}
