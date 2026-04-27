/*
 * Linux pipe(2) / pipe2(2) / eventfd(2) / eventfd2(2) — v0.
 *
 * Three new LinuxFd kinds land here (state values 3, 4, 5):
 *   state=3 → pipe-read end,  first_cluster = pipe pool index
 *   state=4 → pipe-write end, first_cluster = pipe pool index
 *   state=5 → eventfd,        first_cluster = eventfd pool index
 *
 * Pools are kernel-resident, fixed-cap (16 each). Refcounting:
 *   - Pipe.read_refs / write_refs counted per LinuxFd slot
 *     pointing at this pipe. When BOTH hit zero the buf is
 *     freed and the slot returns to the pool.
 *   - When read_refs hits 0: WakeAll write_wq so blocked
 *     writers see EPIPE.
 *   - When write_refs hits 0: WakeAll read_wq so blocked
 *     readers see EOF.
 *
 * Concurrency: every pool mutation runs under arch::Cli — v0
 * is single-CPU on the runqueue side; the WaitQueue requires
 * IRQ-off across the enqueue → Schedule pair anyway. SMP work
 * is its own future slice; documented as a sub-GAP.
 *
 * Blocking model: WaitQueueBlock on empty/full. Caller-loop
 * reissues until the count side allows progress (matches the
 * canonical "while (cond) wait" pattern). No O_NONBLOCK
 * support in v0 — pipe2(O_NONBLOCK) accepts the flag silently
 * but still blocks; sub-GAP.
 *
 * Wired into syscall_io.cpp's DoRead / DoWrite / syscall_file.cpp's
 * DoClose dispatch by state value — see those files for the new
 * arms.
 */

#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/syscall_pipe.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u32 kPipeBufBytes = 4096;
constexpr u32 kPipePoolCap = 16;
constexpr u32 kEventfdPoolCap = 16;

// EPIPE / EAGAIN constants in the negative-errno encoding the
// rest of the Linux subsystem uses. Match the values in
// syscall_internal.h's kEXXX block.
constexpr i64 kEpipe = -32;
constexpr i64 kEagain = -11;

struct Pipe
{
    bool in_use;
    u8 _pad[3];
    u32 read_refs;
    u32 write_refs;
    u32 head;
    u32 tail;
    u32 count;
    u8* buf; // KMalloc'd kPipeBufBytes
    sched::WaitQueue read_wq;
    sched::WaitQueue write_wq;
};

struct Eventfd
{
    bool in_use;
    u8 _pad[3];
    u32 refs;
    u64 counter;
    u32 flags; // EFD_SEMAPHORE etc.
    u32 _pad2;
    sched::WaitQueue read_wq;
};

Pipe g_pipe_pool[kPipePoolCap];
Eventfd g_eventfd_pool[kEventfdPoolCap];

// ============================================================
// Pipe pool helpers
// ============================================================

i32 PipeAlloc()
{
    arch::Cli();
    for (u32 i = 0; i < kPipePoolCap; ++i)
    {
        if (!g_pipe_pool[i].in_use)
        {
            Pipe& p = g_pipe_pool[i];
            arch::Sti();
            // KMalloc outside the cli/sti — the heap allocator
            // itself disables interrupts as needed; holding cli
            // across a heap alloc would extend the IRQ-off
            // window unnecessarily.
            u8* b = static_cast<u8*>(mm::KMalloc(kPipeBufBytes));
            if (b == nullptr)
                return -1;
            arch::Cli();
            // Re-check after the alloc — another CPU could have
            // claimed the slot. v0 is single-CPU but this keeps
            // the helper SMP-correct on the day SMP lands.
            if (g_pipe_pool[i].in_use)
            {
                arch::Sti();
                mm::KFree(b);
                return -1;
            }
            p.buf = b;
            p.in_use = true;
            p.read_refs = 1;
            p.write_refs = 1;
            p.head = 0;
            p.tail = 0;
            p.count = 0;
            p.read_wq.head = nullptr;
            p.read_wq.tail = nullptr;
            p.write_wq.head = nullptr;
            p.write_wq.tail = nullptr;
            arch::Sti();
            return static_cast<i32>(i);
        }
    }
    arch::Sti();
    return -1;
}

void PipeMaybeFree(u32 idx)
{
    // Caller already holds cli.
    Pipe& p = g_pipe_pool[idx];
    if (p.read_refs == 0 && p.write_refs == 0 && p.in_use)
    {
        u8* b = p.buf;
        p.in_use = false;
        p.buf = nullptr;
        // Free outside cli — same rationale as alloc.
        arch::Sti();
        mm::KFree(b);
        arch::Cli();
    }
}

} // namespace

void PipeReleaseRead(u32 idx)
{
    if (idx >= kPipePoolCap)
        return;
    arch::Cli();
    Pipe& p = g_pipe_pool[idx];
    if (!p.in_use || p.read_refs == 0)
    {
        arch::Sti();
        return;
    }
    --p.read_refs;
    if (p.read_refs == 0)
        sched::WaitQueueWakeAll(&p.write_wq);
    PipeMaybeFree(idx);
    arch::Sti();
}

void PipeReleaseWrite(u32 idx)
{
    if (idx >= kPipePoolCap)
        return;
    arch::Cli();
    Pipe& p = g_pipe_pool[idx];
    if (!p.in_use || p.write_refs == 0)
    {
        arch::Sti();
        return;
    }
    --p.write_refs;
    if (p.write_refs == 0)
        sched::WaitQueueWakeAll(&p.read_wq);
    PipeMaybeFree(idx);
    arch::Sti();
}

i64 PipeRead(u32 idx, u64 user_dst, u64 len)
{
    if (idx >= kPipePoolCap || len == 0)
        return 0;
    Pipe& p = g_pipe_pool[idx];
    u8 stage[256];
    arch::Cli();
    while (p.in_use && p.count == 0)
    {
        if (p.write_refs == 0)
        {
            arch::Sti();
            return 0; // EOF — every writer closed
        }
        sched::WaitQueueBlock(&p.read_wq);
        // WaitQueueBlock returns with interrupts in the
        // caller's pre-block state. We re-enter cli at the
        // top of the loop body.
        arch::Cli();
    }
    if (!p.in_use)
    {
        arch::Sti();
        return 0;
    }
    u64 to_read = (len < p.count) ? len : p.count;
    if (to_read > sizeof(stage))
        to_read = sizeof(stage);
    for (u64 i = 0; i < to_read; ++i)
    {
        stage[i] = p.buf[p.tail];
        p.tail = (p.tail + 1) % kPipeBufBytes;
        --p.count;
    }
    sched::WaitQueueWakeOne(&p.write_wq);
    arch::Sti();
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, to_read))
        return kEFAULT;
    return static_cast<i64>(to_read);
}

i64 PipeWrite(u32 idx, u64 user_src, u64 len)
{
    if (idx >= kPipePoolCap || len == 0)
        return 0;
    Pipe& p = g_pipe_pool[idx];
    u8 stage[256];
    u64 to_stage = (len < sizeof(stage)) ? len : sizeof(stage);
    if (!mm::CopyFromUser(stage, reinterpret_cast<const void*>(user_src), to_stage))
        return kEFAULT;

    arch::Cli();
    while (p.in_use && p.count == kPipeBufBytes)
    {
        if (p.read_refs == 0)
        {
            arch::Sti();
            return kEpipe;
        }
        sched::WaitQueueBlock(&p.write_wq);
        arch::Cli();
    }
    if (!p.in_use || p.read_refs == 0)
    {
        arch::Sti();
        return kEpipe;
    }
    const u64 free_slots = kPipeBufBytes - p.count;
    u64 to_write = (to_stage < free_slots) ? to_stage : free_slots;
    for (u64 i = 0; i < to_write; ++i)
    {
        p.buf[p.head] = stage[i];
        p.head = (p.head + 1) % kPipeBufBytes;
        ++p.count;
    }
    sched::WaitQueueWakeOne(&p.read_wq);
    arch::Sti();
    return static_cast<i64>(to_write);
}

// ============================================================
// Eventfd pool helpers
// ============================================================

namespace
{

i32 EventfdAlloc(u64 initval, u32 flags)
{
    arch::Cli();
    for (u32 i = 0; i < kEventfdPoolCap; ++i)
    {
        if (!g_eventfd_pool[i].in_use)
        {
            Eventfd& e = g_eventfd_pool[i];
            e.in_use = true;
            e.refs = 1;
            e.counter = initval;
            e.flags = flags;
            e.read_wq.head = nullptr;
            e.read_wq.tail = nullptr;
            arch::Sti();
            return static_cast<i32>(i);
        }
    }
    arch::Sti();
    return -1;
}

} // namespace

void EventfdRelease(u32 idx)
{
    if (idx >= kEventfdPoolCap)
        return;
    arch::Cli();
    Eventfd& e = g_eventfd_pool[idx];
    if (!e.in_use || e.refs == 0)
    {
        arch::Sti();
        return;
    }
    --e.refs;
    if (e.refs == 0)
    {
        // Wake any blocked readers — they'll see 0 / EAGAIN.
        sched::WaitQueueWakeAll(&e.read_wq);
        e.in_use = false;
        e.counter = 0;
    }
    arch::Sti();
}

i64 EventfdRead(u32 idx, u64 user_dst, u64 len)
{
    if (idx >= kEventfdPoolCap)
        return kEINVAL;
    if (len < 8)
        return kEINVAL; // eventfd reads/writes are u64-sized
    Eventfd& e = g_eventfd_pool[idx];
    constexpr u32 kEfdSemaphore = 0x1;
    arch::Cli();
    while (e.in_use && e.counter == 0)
    {
        sched::WaitQueueBlock(&e.read_wq);
        arch::Cli();
    }
    if (!e.in_use)
    {
        arch::Sti();
        return 0;
    }
    u64 out;
    if ((e.flags & kEfdSemaphore) != 0)
    {
        out = 1;
        e.counter -= 1;
    }
    else
    {
        out = e.counter;
        e.counter = 0;
    }
    arch::Sti();
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), &out, sizeof(out)))
        return kEFAULT;
    return 8;
}

i64 EventfdWrite(u32 idx, u64 user_src, u64 len)
{
    if (idx >= kEventfdPoolCap)
        return kEINVAL;
    if (len < 8)
        return kEINVAL;
    u64 in;
    if (!mm::CopyFromUser(&in, reinterpret_cast<const void*>(user_src), sizeof(in)))
        return kEFAULT;
    if (in == static_cast<u64>(-1))
        return kEINVAL; // 0xFF..FF reserved per eventfd(2)
    Eventfd& e = g_eventfd_pool[idx];
    arch::Cli();
    if (!e.in_use)
    {
        arch::Sti();
        return kEINVAL;
    }
    // Saturate at u64-1 if the add would overflow. Real Linux
    // blocks instead; v0 saturates so writes never spuriously
    // hang. Sub-GAP — non-blocking semantics by accident.
    const u64 cap = static_cast<u64>(-1) - 1;
    if (e.counter > cap - in)
        e.counter = cap;
    else
        e.counter += in;
    sched::WaitQueueWakeOne(&e.read_wq);
    arch::Sti();
    return 8;
}

// ============================================================
// Syscall handlers — DoPipe / DoPipe2 / DoEventfd / DoEventfd2
// ============================================================

i64 DoPipe(u64 user_fds)
{
    return DoPipe2(user_fds, /*flags=*/0);
}

i64 DoPipe2(u64 user_fds, u64 flags)
{
    (void)flags; // O_NONBLOCK / O_CLOEXEC ignored in v0 (sub-GAP)
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    // Find two free LinuxFd slots starting at fd 3 (0/1/2 are
    // tty-reserved). Linux semantics: lowest two free fds.
    u32 r_fd = 16;
    u32 w_fd = 16;
    for (u32 i = 3; i < 16; ++i)
    {
        if (p->linux_fds[i].state != 0)
            continue;
        if (r_fd == 16)
            r_fd = i;
        else if (w_fd == 16)
        {
            w_fd = i;
            break;
        }
    }
    if (r_fd == 16 || w_fd == 16)
        return kEMFILE;

    const i32 idx = PipeAlloc();
    if (idx < 0)
        return kENFILE;

    p->linux_fds[r_fd].state = 3;
    p->linux_fds[r_fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[r_fd].size = 0;
    p->linux_fds[r_fd].offset = 0;
    p->linux_fds[r_fd].path[0] = '\0';

    p->linux_fds[w_fd].state = 4;
    p->linux_fds[w_fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[w_fd].size = 0;
    p->linux_fds[w_fd].offset = 0;
    p->linux_fds[w_fd].path[0] = '\0';

    u32 fds[2];
    fds[0] = r_fd;
    fds[1] = w_fd;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_fds), fds, sizeof(fds)))
    {
        // User pointer bad — roll back the fds + the pool entry.
        p->linux_fds[r_fd].state = 0;
        p->linux_fds[w_fd].state = 0;
        PipeReleaseRead(static_cast<u32>(idx));
        PipeReleaseWrite(static_cast<u32>(idx));
        return kEFAULT;
    }

    arch::SerialWrite("[linux/pipe] r_fd=");
    arch::SerialWriteHex(r_fd);
    arch::SerialWrite(" w_fd=");
    arch::SerialWriteHex(w_fd);
    arch::SerialWrite(" pool_idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite("\n");
    return 0;
}

i64 DoEventfd(u64 initval)
{
    return DoEventfd2(initval, /*flags=*/0);
}

i64 DoEventfd2(u64 initval, u64 flags)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 fd = 16;
    for (u32 i = 3; i < 16; ++i)
    {
        if (p->linux_fds[i].state == 0)
        {
            fd = i;
            break;
        }
    }
    if (fd == 16)
        return kEMFILE;
    const i32 idx = EventfdAlloc(initval, static_cast<u32>(flags));
    if (idx < 0)
        return kENFILE;
    p->linux_fds[fd].state = 5;
    p->linux_fds[fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    p->linux_fds[fd].path[0] = '\0';
    arch::SerialWrite("[linux/eventfd] fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" pool_idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite(" initval=");
    arch::SerialWriteHex(initval);
    arch::SerialWrite("\n");
    return static_cast<i64>(fd);
}

} // namespace duetos::subsystems::linux::internal
