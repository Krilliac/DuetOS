#include "sched.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../core/recovery.h"
#include "../cpu/percpu.h"
#include "../mm/kheap.h"
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
    u64 wake_tick; // valid only while state == Sleeping
    const char* name;
    Task* next; // runqueue link (intrusive)
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

constinit Task* g_run_head = nullptr;   // next to run
constinit Task* g_run_tail = nullptr;   // append here
constinit Task* g_sleep_head = nullptr; // sorted by wake_tick (ascending)
constinit u64 g_tick_now = 0;
constinit u64 g_next_task_id = 0;
constinit u64 g_context_switches = 0;
constinit u64 g_tasks_live = 0;
constinit u64 g_tasks_sleeping = 0;
constinit u64 g_tasks_blocked = 0;
constinit u64 g_tasks_created = 0;
constinit u64 g_tasks_reaped = 0;

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
    if (g_run_tail == nullptr)
    {
        g_run_head = g_run_tail = t;
    }
    else
    {
        g_run_tail->next = t;
        g_run_tail = t;
    }
}

Task* RunqueuePop()
{
    Task* t = g_run_head;
    if (t == nullptr)
    {
        return nullptr;
    }
    g_run_head = t->next;
    if (g_run_head == nullptr)
    {
        g_run_tail = nullptr;
    }
    t->next = nullptr;
    return t;
}

void SleepqueueInsert(Task* t)
{
    t->next = nullptr;
    if (g_sleep_head == nullptr || t->wake_tick < g_sleep_head->wake_tick)
    {
        t->next = g_sleep_head;
        g_sleep_head = t;
        return;
    }

    Task* it = g_sleep_head;
    while (it->next != nullptr && it->next->wake_tick <= t->wake_tick)
    {
        it = it->next;
    }
    t->next = it->next;
    it->next = t;
}

// Wrap-safe tick deadline compare. Works as long as nobody sleeps for more
// than 2^63-1 ticks in one call (orders of magnitude beyond practical use).
bool TickReached(u64 now, u64 deadline)
{
    return static_cast<i64>(now - deadline) >= 0;
}

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

    Current() = boot_task;
    g_tasks_created = 1;
    g_tasks_live = 1;

    SerialWrite("[sched] online; task 0 is \"kboot\"\n");
}

Task* SchedCreate(TaskEntry entry, void* arg, const char* name)
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
    SerialWrite("\n");

    return t;
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
            prev->state = TaskState::Ready;
            RunqueuePush(prev);
        }
        // Dead tasks are NOT re-enqueued; their Task struct + stack live on
        // until the reaper reclaims them.

        next->state = TaskState::Running;
        Current() = next;
        ++g_context_switches;
    }

    ContextSwitch(&prev->rsp, next->rsp);
    // When we return here, `prev` is running again (it may have been
    // scheduled out and back in an arbitrary number of times).
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

    bool woke_any = false;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        while (g_sleep_head != nullptr && TickReached(now_ticks, g_sleep_head->wake_tick))
        {
            Task* woken = g_sleep_head;
            g_sleep_head = woken->next;
            woken->next = nullptr;
            woken->state = TaskState::Ready;
            RunqueuePush(woken);
            --g_tasks_sleeping;
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
    };
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

        // Pop one zombie under CLI. KFree happens AFTER we Sti so the
        // heap path is not running with interrupts disabled (the heap
        // is not required to be IRQ-safe today, but holding CLI across
        // KFree locks out the timer for longer than the reap itself).
        Task* dead = g_zombies;
        g_zombies = dead->next;
        dead->next = nullptr;
        arch::Sti();

        // Stack_base can be nullptr for the boot task (task 0); defensive
        // null-check even though task 0 should never exit. Every other
        // task got a canary planted at stack_base in SchedCreate —
        // verify before freeing so stack overflow surfaces as a named
        // panic here instead of as downstream heap-magic corruption
        // later.
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

} // namespace

void SchedStartReaper()
{
    SchedCreate(&ReaperMain, nullptr, "reaper");
    core::Log(core::LogLevel::Info, "sched/reaper", "reaper thread online");
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

Task* WaitQueueWakeOne(WaitQueue* wq)
{
    KASSERT(wq != nullptr, "sched", "WaitQueueWakeOne null queue");

    Task* t = nullptr;
    {
        sync::SpinLockGuard guard(g_sched_lock);
        t = wq->head;
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
        t->state = TaskState::Ready;
        RunqueuePush(t);
        --g_tasks_blocked;
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

} // namespace customos::sched

extern "C" [[noreturn]] void SchedExitC()
{
    customos::sched::SchedExit();
}
