#include "sched.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../mm/kheap.h"

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
    const char* name;
    Task* next; // runqueue link (intrusive)
};

namespace
{

using arch::Halt;
using arch::SerialWrite;
using arch::SerialWriteHex;

constexpr u64 kKernelStackBytes = 16 * 1024; // 16 KiB per task — plenty for v0

constinit Task* g_current = nullptr;
constinit Task* g_run_head = nullptr; // next to run
constinit Task* g_run_tail = nullptr; // append here
constinit u64 g_next_task_id = 0;
constinit u64 g_context_switches = 0;
constinit u64 g_tasks_live = 0;
constinit u64 g_tasks_created = 0;
constinit u64 g_tasks_exited = 0;
constinit bool g_need_resched = false;

[[noreturn]] void PanicSched(const char* message)
{
    SerialWrite("\n[panic] sched: ");
    SerialWrite(message);
    SerialWrite("\n");
    Halt();
}

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
    boot_task->name = "kboot";
    boot_task->next = nullptr;

    g_current = boot_task;
    g_tasks_created = 1;
    g_tasks_live = 1;

    SerialWrite("[sched] online; task 0 is \"kboot\"\n");
}

Task* SchedCreate(TaskEntry entry, void* arg, const char* name)
{
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

    t->id = g_next_task_id++;
    t->state = TaskState::Ready;
    t->stack_base = stack;
    t->stack_size = kKernelStackBytes;
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

    RunqueuePush(t);
    ++g_tasks_created;
    ++g_tasks_live;

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
    if (g_current == nullptr)
    {
        return; // pre-SchedInit timer tick (shouldn't happen, but be safe)
    }

    // Pick the next runnable task. If the runqueue is empty, keep
    // running the current task — no one else wants the CPU.
    Task* next = RunqueuePop();
    if (next == nullptr)
    {
        return;
    }

    Task* prev = g_current;
    if (prev->state == TaskState::Running)
    {
        prev->state = TaskState::Ready;
        RunqueuePush(prev);
    }
    // Dead tasks are NOT re-enqueued; their Task struct + stack live on
    // until a future reaper reclaims them (see Notes in sched.h).

    next->state = TaskState::Running;
    g_current = next;
    ++g_context_switches;

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

void SchedExit()
{
    arch::Cli();
    g_current->state = TaskState::Dead;
    ++g_tasks_exited;
    --g_tasks_live;
    // Schedule() will not re-enqueue a Dead task, so this is a one-way
    // switch. If the runqueue is empty, we'll loop here forever, which
    // is also correct — SchedExit must never return.
    for (;;)
    {
        Schedule();
        // Shouldn't reach here (Schedule() won't return into a Dead
        // task), but if it does, re-enter the dead-task loop.
    }
}

void SetNeedResched()
{
    g_need_resched = true;
}

bool TakeNeedResched()
{
    const bool v = g_need_resched;
    g_need_resched = false;
    return v;
}

Task* CurrentTask()
{
    return g_current;
}

SchedStats SchedStatsRead()
{
    return SchedStats{
        .context_switches = g_context_switches,
        .tasks_live = g_tasks_live,
        .tasks_created = g_tasks_created,
        .tasks_exited = g_tasks_exited,
    };
}

} // namespace customos::sched

extern "C" [[noreturn]] void SchedExitC()
{
    customos::sched::SchedExit();
}
