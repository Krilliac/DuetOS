#include "sched.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../core/process.h"
#include "../core/recovery.h"
#include "../cpu/percpu.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../security/guard.h"
#include "../mm/kheap.h"
#include "../mm/paging.h"
#include "../sync/spinlock.h"

namespace customos::sched
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
    // `sleep_next` is a SEPARATE intrusive link used only for the
    // sleep queue. Kept out of `next` so a task can be parked on
    // BOTH a wait queue (via `next`) and the sleep queue (via
    // `sleep_next`) simultaneously — that's how
    // WaitQueueBlockTimeout implements "wake me on event OR on
    // timer, whichever comes first."
    Task* sleep_next;
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

    // Linux-ABI FS.base (MSR_FS_BASE). Meaningful only for tasks
    // whose process has abi_flavor == kAbiLinux — that's where
    // musl plants its TLS anchor via arch_prctl(ARCH_SET_FS).
    // Saved by the scheduler just before ContextSwitch and
    // restored immediately after, so each Linux task sees its own
    // TLS regardless of what other tasks ran in between. Kernel-
    // only and native tasks leave this at 0 and never touch
    // MSR_FS_BASE; the save/restore is a no-op for them.
    u64 fs_base;
};

namespace
{

using arch::Halt;
using arch::SerialWrite;
using arch::SerialWriteHex;

constexpr u64 kKernelStackBytes = 16 * 1024; // 16 KiB per task — plenty for v0

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
constinit Task* g_run_head_normal = nullptr;
constinit Task* g_run_tail_normal = nullptr;
constinit Task* g_run_head_idle = nullptr;
constinit Task* g_run_tail_idle = nullptr;
constinit Task* g_sleep_head = nullptr; // sorted by wake_tick (ascending)
constinit u64 g_tick_now = 0;
constinit u64 g_next_task_id = 0;
constinit u64 g_context_switches = 0;
constinit u64 g_tasks_live = 0;
constinit u64 g_tasks_sleeping = 0;
constinit u64 g_tasks_blocked = 0;
constinit u64 g_tasks_created = 0;
constinit u64 g_tasks_reaped = 0;
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
// On single CPU today this is a no-op: callers that matter are
// already CLI'd, so there's no concurrency to guard against. The
// value is enforcing a single locking discipline across every
// mutation point so SMP bring-up (Commit D in smp-ap-bringup-scope)
// has uniform ground truth — "this lock protects the runqueue" —
// rather than a per-site bolt-on.
//
// IMPORTANT gap: Schedule() does NOT hold this lock across the
// ContextSwitch call. The lock covers RunqueuePop/Push and the
// state transitions; it's released before ContextSwitch. On single
// CPU that's fine (CLI prevents concurrent IRQs on this core). On
// SMP, another CPU could wake `prev` between the release and the
// context switch, then try to schedule INTO prev while we're still
// on prev's stack. Commit D fixes via lock-passing-across-switch,
// mirroring Linux's finish_task_switch pattern.
constinit sync::SpinLock g_sched_lock{};

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
void RunqueuePush(Task* t)
{
    t->next = nullptr;
    Task*& head = (t->priority == TaskPriority::Idle) ? g_run_head_idle : g_run_head_normal;
    Task*& tail = (t->priority == TaskPriority::Idle) ? g_run_tail_idle : g_run_tail_normal;
    if (tail == nullptr)
    {
        head = tail = t;
    }
    else
    {
        tail->next = t;
        tail = t;
    }
}

// Pops the highest-priority-available Ready task. Normal drains
// before Idle — an Idle task only runs when Normal is empty.
Task* RunqueuePop()
{
    Task* t = g_run_head_normal;
    if (t != nullptr)
    {
        g_run_head_normal = t->next;
        if (g_run_head_normal == nullptr)
        {
            g_run_tail_normal = nullptr;
        }
        t->next = nullptr;
        return t;
    }
    t = g_run_head_idle;
    if (t != nullptr)
    {
        g_run_head_idle = t->next;
        if (g_run_head_idle == nullptr)
        {
            g_run_tail_idle = nullptr;
        }
        t->next = nullptr;
        return t;
    }
    return nullptr;
}

void SleepqueueInsert(Task* t)
{
    t->sleep_next = nullptr;
    if (g_sleep_head == nullptr || t->wake_tick < g_sleep_head->wake_tick)
    {
        t->sleep_next = g_sleep_head;
        g_sleep_head = t;
        return;
    }

    Task* it = g_sleep_head;
    while (it->sleep_next != nullptr && it->sleep_next->wake_tick <= t->wake_tick)
    {
        it = it->sleep_next;
    }
    t->sleep_next = it->sleep_next;
    it->sleep_next = t;
}

// Remove a task from the sleep queue. Used when an explicit wake
// beats the timer path for a timed waiter. Linear walk — fine for
// the sleep queue sizes we expect; becomes a hotspot only if
// thousands of timed waits are outstanding at once.
void SleepqueueRemove(Task* t)
{
    if (g_sleep_head == t)
    {
        g_sleep_head = t->sleep_next;
        t->sleep_next = nullptr;
        return;
    }

    Task* it = g_sleep_head;
    while (it != nullptr && it->sleep_next != t)
    {
        it = it->sleep_next;
    }
    if (it != nullptr)
    {
        it->sleep_next = t->sleep_next;
    }
    t->sleep_next = nullptr;
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
bool TickReached(u64 now, u64 deadline)
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

void SchedInit()
{
    auto* boot_task = static_cast<Task*>(mm::KMalloc(sizeof(Task)));
    if (boot_task == nullptr)
    {
        PanicSched("KMalloc failed for boot task");
    }

    boot_task->id = g_next_task_id++;
    boot_task->state = TaskState::Running;
    boot_task->rsp = 0; // populated on first context switch out
    boot_task->stack_base = nullptr;
    boot_task->stack_size = 0;
    boot_task->wake_tick = 0;
    boot_task->name = "kboot";
    boot_task->next = nullptr;
    boot_task->sleep_next = nullptr;
    boot_task->waiting_on = nullptr;
    boot_task->wake_by_timeout = false;
    boot_task->priority = TaskPriority::Normal;
    boot_task->as = nullptr;                         // kernel AS — boot PML4
    boot_task->process = nullptr;                    // kernel-only — no owning process
    boot_task->kill_requested = false;               // kernel tasks never hit a budget
    boot_task->kill_reason = KillReason::TickBudget; // unused when kill_requested=false

    Current() = boot_task;
    g_tasks_created = 1;
    g_tasks_live = 1;

    SerialWrite("[sched] online; task 0 is \"kboot\"\n");
}

namespace
{

// Shared body for SchedCreate / SchedCreateUser. The only difference
// between the two callers is the task's address space — kernel-only
// tasks pass nullptr; ring-3-bound tasks pass a freshly-created AS.
Task* SchedCreateInternal(TaskEntry entry, void* arg, const char* name, TaskPriority priority, mm::AddressSpace* as)
{
    KASSERT(entry != nullptr, "sched", "SchedCreate null entry fn");
    KASSERT(name != nullptr, "sched", "SchedCreate null name");

    auto* t = static_cast<Task*>(mm::KMalloc(sizeof(Task)));
    if (t == nullptr)
    {
        PanicSched("KMalloc failed for Task");
    }

    auto* stack = static_cast<u8*>(mm::KMalloc(kKernelStackBytes));
    if (stack == nullptr)
    {
        PanicSched("KMalloc failed for kernel stack");
    }

    // Plant the canary at the low edge of the stack BEFORE priming
    // the entry frame at the top. No part of the stack primer reaches
    // down this far, so writing the canary here is never redundant
    // with the per-task context the trampoline reads.
    *reinterpret_cast<u64*>(stack) = kStackCanary;

    t->id = g_next_task_id++;
    t->state = TaskState::Ready;
    t->stack_base = stack;
    t->stack_size = kKernelStackBytes;
    t->wake_tick = 0;
    t->name = name;
    t->next = nullptr;
    t->sleep_next = nullptr;
    t->waiting_on = nullptr;
    t->wake_by_timeout = false;
    t->priority = priority;
    t->as = as;
    t->process = nullptr; // populated by SchedCreateUser for user tasks
    t->kill_requested = false;
    t->kill_reason = KillReason::TickBudget;
    t->ticks_run = 0;
    t->schedin_tick = 0;
    t->fs_base = 0;

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
    //   padding quad                  (keep stack 16-aligned at entry)
    u8* sp = stack + kKernelStackBytes;
    // 16-byte align the top of the stack.
    sp = reinterpret_cast<u8*>(reinterpret_cast<uptr>(sp) & ~uptr{15});

    auto push_quad = [&](u64 value)
    {
        sp -= sizeof(u64);
        *reinterpret_cast<u64*>(sp) = value;
    };

    push_quad(0);                                           // alignment pad
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
        ++g_tasks_created;
        ++g_tasks_live;
    }

    SerialWrite("[sched] created task id=");
    SerialWriteHex(t->id);
    SerialWrite(" name=\"");
    SerialWrite(name);
    SerialWrite("\" rsp=");
    SerialWriteHex(t->rsp);
    SerialWrite(" as=");
    SerialWriteHex(reinterpret_cast<u64>(as));
    SerialWrite("\n");

    return t;
}

} // namespace

Task* SchedCreate(TaskEntry entry, void* arg, const char* name, TaskPriority priority)
{
    // Name-based security gate. No image bytes to scan at this
    // layer — that happens in the loader before entry is ever
    // handed to the scheduler — so this catches only filename
    // denylist hits. Returns a null Task if the guard denies.
    if (!customos::security::GateThread(customos::security::ImageKind::KernelThread, name))
    {
        return nullptr;
    }
    return SchedCreateInternal(entry, arg, name, priority, /*as=*/nullptr);
}

Task* SchedCreateUser(TaskEntry entry, void* arg, const char* name, core::Process* process)
{
    KASSERT(process != nullptr, "sched", "SchedCreateUser without Process");
    KASSERT(process->as != nullptr, "sched", "SchedCreateUser Process has no AS");

    if (!customos::security::GateThread(customos::security::ImageKind::UserThread, name))
    {
        // The caller handed us its Process reference expecting
        // the Task to absorb it. No Task was created — the ref
        // would leak (AS + Process struct + PID slot held forever)
        // unless we release it here on the gate-denial exit path.
        core::ProcessRelease(process);
        return nullptr;
    }

    Task* t = SchedCreateInternal(entry, arg, name, TaskPriority::Normal, process->as);
    t->process = process;
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
    }
    return "<unknown>";
}

void Schedule()
{
    if (Current() == nullptr)
    {
        return; // pre-SchedInit timer tick (shouldn't happen, but be safe)
    }

    Task* prev = nullptr;
    Task* next = nullptr;
    {
        // Acquire the scheduler lock ONLY for the pick + state-transition
        // phase. We release BEFORE ContextSwitch — see the SMP gap note
        // on g_sched_lock: on single CPU this is safe (CLI serialises),
        // on SMP Commit D adds the lock-passing-across-switch dance.
        sync::SpinLockGuard guard(g_sched_lock);

        next = RunqueuePop();
        if (next == nullptr)
        {
            if (Current()->state != TaskState::Running)
            {
                PanicSched("no runnable task available");
            }
            return;
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
                --g_tasks_live;
                prev->next = g_zombies;
                g_zombies = prev;
                // Wake the reaper; it's blocked on g_reaper_wq and
                // noticing a new zombie needs a wake. WaitQueueWakeOne
                // itself acquires g_sched_lock — but we already hold
                // it. Use the _Locked variant to avoid recursive lock.
                WaitQueueWakeOneLocked(&g_reaper_wq);
            }
            else
            {
                prev->state = TaskState::Ready;
                RunqueuePush(prev);
            }
        }
        // Dead tasks are NOT re-enqueued; their Task struct + stack live on
        // until the reaper reclaims them.

        next->state = TaskState::Running;
        Current() = next;
        ++g_context_switches;
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

    ContextSwitch(&prev->rsp, next->rsp);
    // When we return here, we're executing on a DIFFERENT task's
    // stack — whichever task got switched in to run us. The local
    // `prev` on our new stack was bound at THAT task's last
    // Schedule() call and does NOT refer to "the task that just
    // swapped to us." Use Current() instead — the scheduler wrote
    // it to the incoming task BEFORE the stack flip, so Current()
    // here is the task that just resumed.
    {
        const u64 v = Current()->fs_base;
        const u32 lo = static_cast<u32>(v);
        const u32 hi = static_cast<u32>(v >> 32);
        asm volatile("wrmsr" : : "c"(kMsrFsBase), "a"(lo), "d"(hi));
    }
}

void SchedYield()
{
    arch::Cli();
    Schedule();
    arch::Sti();
}

void SchedSleepTicks(u64 ticks)
{
    if (ticks == 0)
    {
        SchedYield();
        return;
    }

    arch::Cli();
    Task* current = Current();
    current->state = TaskState::Sleeping;
    current->wake_tick = g_tick_now + ticks;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        SleepqueueInsert(current);
        ++g_tasks_sleeping;
    }
    Schedule();
    arch::Sti();
}

void SchedSleepUntil(u64 deadline_tick)
{
    // Wrap-safe deadline compare. Task-visible ticks are the same
    // monotonically-increasing counter that OnTimerTick publishes,
    // so "passed" means (i64)(g_tick_now - deadline) >= 0.
    arch::Cli();
    if (TickReached(g_tick_now, deadline_tick))
    {
        arch::Sti();
        SchedYield();
        return;
    }

    Task* current = Current();
    current->state = TaskState::Sleeping;
    current->wake_tick = deadline_tick;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        SleepqueueInsert(current);
        ++g_tasks_sleeping;
    }
    Schedule();
    arch::Sti();
}

u64 SchedNowTicks()
{
    return g_tick_now;
}

void SchedExit()
{
    arch::Cli();
    Task* self = Current();
    self->state = TaskState::Dead;
    ++g_tasks_exited;
    --g_tasks_live;

    // Recovery Class C extension point — ring-3 process kill will grow
    // this to tear down address space / fds / caps / ipc.
    core::OnTaskExited();

    // Push onto the zombie list. Important: we do NOT KFree ourselves
    // here — we're still running on our own stack. The reaper does
    // the free from ITS stack, after Schedule() puts us off-CPU.
    //
    // Single-CPU safety argument: once Schedule() below context-switches
    // away, this task's Current() assignment is gone and only the
    // zombie pointer references the struct. The reaper inspecting the
    // zombie list after this point is safe — no other code can touch
    // us. SMP bring-up will need to also verify the task isn't
    // `Running` on a peer CPU before the reaper touches it.
    self->next = g_zombies;
    g_zombies = self;

    // Wake the reaper if it's parked.
    WaitQueueWakeOne(&g_reaper_wq);

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
            woken->sleep_next = nullptr;
            --g_tasks_sleeping;

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
                --g_tasks_blocked;
            }

            woken->wake_tick = 0;
            woken->state = TaskState::Ready;
            woken->next = nullptr;
            RunqueuePush(woken);
            woke_any = true;
        }
    }

    if (woke_any)
    {
        NeedResched() = true;
    }
}

Task* CurrentTask()
{
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
        .tasks_live = g_tasks_live,
        .tasks_sleeping = g_tasks_sleeping,
        .tasks_blocked = g_tasks_blocked,
        .tasks_created = g_tasks_created,
        .tasks_exited = g_tasks_exited,
        .tasks_reaped = g_tasks_reaped,
        .total_ticks = g_total_ticks,
        .idle_ticks = g_idle_ticks,
    };
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
    info.state = static_cast<u8>(t->state);
    info.priority = static_cast<u8>(t->priority);
    info.is_running = is_running;
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
    }
    return "<unknown>";
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

// Detach `t` from g_sleep_head (threaded by sleep_next).
// No-op if t isn't on the list. Caller holds CLI.
void SleepQueueRemove(Task* t)
{
    Task** pp = &g_sleep_head;
    while (*pp != nullptr)
    {
        if (*pp == t)
        {
            *pp = t->sleep_next;
            t->sleep_next = nullptr;
            if (g_tasks_sleeping > 0)
                --g_tasks_sleeping;
            return;
        }
        pp = &(*pp)->sleep_next;
    }
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
        for (Task* t = g_run_head_normal; t != nullptr; t = t->next)
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
        for (Task* t = g_run_head_idle; t != nullptr; t = t->next)
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
    for (Task* t = g_run_head_normal; t != nullptr; t = t->next)
        check(t);
    for (Task* t = g_run_head_idle; t != nullptr; t = t->next)
        check(t);
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
    EmitList(g_run_head_normal, cb, cookie, running);
    EmitList(g_run_head_idle, cb, cookie, running);
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

        // Detach the entire zombie list under CLI. Zombies are all
        // off-CPU by construction (SchedExit enqueues only AFTER
        // Schedule() has switched away from the dying task), so the
        // order we free them in doesn't matter. Draining the list in
        // one pass avoids N wake-up round trips when a burst of tasks
        // exits at once.
        Task* drained = g_zombies;
        g_zombies = nullptr;
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
            // stack overflow surfaces as a named panic here instead
            // of as downstream heap-magic corruption later.
            if (dead->stack_base != nullptr)
            {
                const u64 canary = *reinterpret_cast<const u64*>(dead->stack_base);
                if (canary != kStackCanary)
                {
                    core::PanicWithValue("sched/reaper", "stack canary corrupted (task overflow?)", canary);
                }
                mm::KFree(dead->stack_base);
            }
            mm::KFree(dead);
            ++g_tasks_reaped;

            core::LogWithValue(core::LogLevel::Info, "sched/reaper", "reaped task id", g_tasks_reaped);
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

[[noreturn]] void IdleMain(void*)
{
    for (;;)
    {
        arch::Sti();
        asm volatile("hlt");
    }
}

} // namespace

void SchedStartIdle(const char* name)
{
    KASSERT(name != nullptr, "sched", "SchedStartIdle null name");
    SchedCreate(&IdleMain, nullptr, name, TaskPriority::Idle);
    core::Log(core::LogLevel::Info, "sched/idle", "idle task online");
}

// ---------------------------------------------------------------------------
// Wait queues
//
// A WaitQueue is a singly-linked FIFO of Tasks parked in state Blocked.
// Callers uphold the interrupt-disabled contract so the "check then block"
// race is closed against IRQ-context wakers. See sched.h for the contract.
// ---------------------------------------------------------------------------

void WaitQueueBlock(WaitQueue* wq)
{
    KASSERT(wq != nullptr, "sched", "WaitQueueBlock null queue");

    {
        sync::SpinLockGuard guard(g_sched_lock);
        Task* t = Current();
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
        ++g_tasks_blocked;
    }

    Schedule();
    // Woken. Our state was flipped back to Running by Schedule() + the
    // waker pushed us onto the runqueue before we got here.
}

bool WaitQueueBlockTimeout(WaitQueue* wq, u64 ticks)
{
    KASSERT(wq != nullptr, "sched", "WaitQueueBlockTimeout null queue");

    // Zero ticks: no wait at all — yield and declare it a timeout.
    // Callers should not rely on this as a "cheap test" — use
    // WaitQueueWakeOne's return value to poke the queue cheaply.
    if (ticks == 0)
    {
        SchedYield();
        return false;
    }

    {
        sync::SpinLockGuard guard(g_sched_lock);
        Task* t = Current();
        t->state = TaskState::Blocked;
        t->next = nullptr;
        t->wake_tick = g_tick_now + ticks;
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
        ++g_tasks_blocked;

        // Enqueue on the sleep queue so the timer path can fire
        // if nobody wakes us first. Both lists hold the same
        // Task* — the two wake paths race, and whichever wins
        // unlinks the loser.
        SleepqueueInsert(t);
        ++g_tasks_sleeping;
    }

    Schedule();

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
        --g_tasks_sleeping;
    }
    t->waiting_on = nullptr;
    t->wake_tick = 0;
    t->wake_by_timeout = false;
    t->state = TaskState::Ready;
    RunqueuePush(t);
    --g_tasks_blocked;
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

    u64 count = 0;
    while (WaitQueueWakeOne(wq) != nullptr)
    {
        ++count;
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

    arch::Cli();
    if (m->owner == nullptr)
    {
        // Fast path: uncontended acquire.
        m->owner = Current();
    }
    else
    {
        // Slow path: block on the waiters queue. Unlock's hand-off sets
        // m->owner = us BEFORE waking us, so there's nothing to redo
        // here — the lock is already ours when WaitQueueBlock returns.
        WaitQueueBlock(&m->waiters);
    }
    arch::Sti();
}

bool MutexTryLock(Mutex* m)
{
    KASSERT(m != nullptr, "sched", "MutexTryLock null mutex");

    arch::Cli();
    const bool ok = (m->owner == nullptr);
    if (ok)
    {
        m->owner = Current();
    }
    arch::Sti();
    return ok;
}

void MutexUnlock(Mutex* m)
{
    KASSERT(m != nullptr, "sched", "MutexUnlock null mutex");

    arch::Cli();
    if (m->owner != Current())
    {
        PanicSched("MutexUnlock by non-owner");
    }
    m->owner = nullptr;

    // Hand-off: if there's a waiter, wake one AND transfer ownership to it
    // directly. Without hand-off, a freshly-woken waiter would have to re-
    // acquire a lock we just cleared, racing against any task that calls
    // Lock in the gap. Hand-off guarantees FIFO progress.
    Task* next = WaitQueueWakeOne(&m->waiters);
    if (next != nullptr)
    {
        m->owner = next;
    }
    arch::Sti();
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

    arch::Cli();
    if (m->owner != Current())
    {
        PanicSched("CondvarWait called without the companion mutex held");
    }

    {
        sync::SpinLockGuard guard(g_sched_lock);

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
        ++g_tasks_blocked;
    }

    Schedule();
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
        PanicSched("CondvarWaitTimeout called without the companion mutex held");
    }

    {
        sync::SpinLockGuard guard(g_sched_lock);

        // Atomic mutex hand-off (identical to CondvarWait).
        Task* successor = WaitQueueWakeOneLocked(&m->waiters);
        m->owner = successor;

        // Enqueue self on condvar's waiters with a deadline, and
        // also on the sleep queue — the timer path is the second
        // wake arm, exactly like WaitQueueBlockTimeout.
        Task* t = Current();
        t->state = TaskState::Blocked;
        t->next = nullptr;
        t->wake_tick = g_tick_now + ticks;
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
        ++g_tasks_blocked;

        SleepqueueInsert(t);
        ++g_tasks_sleeping;
    }

    Schedule();
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

} // namespace customos::sched

extern "C" [[noreturn]] void SchedExitC()
{
    customos::sched::SchedExit();
}
