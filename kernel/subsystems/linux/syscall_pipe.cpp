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
#include "ipc/kfile.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u32 kPipeBufBytes = 4096;
constexpr u32 kPipePoolCap = 16;
constexpr u32 kEventfdPoolCap = 16;

// EPIPE constant in the negative-errno encoding the rest of the
// Linux subsystem uses. Matches the value in syscall_internal.h's
// kEXXX block.
constexpr i64 kEpipe = -32;

struct Pipe
{
    bool in_use;
    bool closing;
    u8 _pad[3];
    u32 read_refs;
    u32 write_refs;
    u32 pins;
    u32 head;
    u32 tail;
    u32 count;
    // Monotonic predicate epochs bridge the pipe lock to scheduler enqueue.
    // Producers publish the matching epoch before waking the queue; consumers
    // snapshot it while holding g_pipe_lock and revalidate under g_sched_lock.
    u64 read_sequence;
    u64 write_sequence;
    u8* buf; // KMalloc'd kPipeBufBytes
    sched::WaitQueue read_wq;
    sched::WaitQueue write_wq;
};

struct Eventfd
{
    bool in_use;
    bool closing;
    u8 _pad[3];
    u32 refs;
    u32 pins;
    u64 counter;
    u64 read_sequence;
    u32 flags; // EFD_SEMAPHORE etc.
    u32 _pad2;
    sched::WaitQueue read_wq;
};

Pipe g_pipe_pool[kPipePoolCap];
Eventfd g_eventfd_pool[kEventfdPoolCap];
constinit sync::SpinLock g_pipe_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};

u64 WaitSequenceSnapshotLocked(const u64* sequence)
{
    return __atomic_load_n(sequence, __ATOMIC_ACQUIRE);
}

void WaitSequencePublishLocked(u64* sequence)
{
    const u64 observed = __atomic_load_n(sequence, __ATOMIC_RELAXED);
    if (observed != ~u64{0})
        __atomic_store_n(sequence, observed + 1, __ATOMIC_RELEASE);
}

// ============================================================
// Pipe pool helpers
// ============================================================
// PipeAlloc moved out of the anonymous namespace below so the
// header declaration (used by Win32 CreatePipe routing as well
// as Linux pipe2) can resolve to a single definition.

u8* TakePipeFreeLocked(Pipe& p)
{
    // Caller already holds cli.
    // Caller holds g_pipe_lock.
    if (p.read_refs != 0 || p.write_refs != 0 || p.pins != 0 || !p.in_use)
        return nullptr;
    if (p.in_use)
    {
        u8* b = p.buf;
        p.in_use = false;
        p.closing = false;
        p.buf = nullptr;
        p.read_sequence = 0;
        p.write_sequence = 0;
        return b;
        // Free outside cli — same rationale as alloc.
    }
    return nullptr;
}

void FinishPipeFree(u8* buf)
{
    if (buf != nullptr)
        mm::KFree(buf);
}

struct PipePin
{
    u32 idx;
    Pipe* pipe;

    explicit PipePin(u32 value) : idx(value), pipe(nullptr)
    {
        if (value >= kPipePoolCap)
            return;
        sync::SpinLockGuard guard(g_pipe_lock);
        Pipe& p = g_pipe_pool[value];
        if (p.in_use && !p.closing && p.pins != ~0U)
        {
            ++p.pins;
            pipe = &p;
        }
    }

    ~PipePin()
    {
        if (pipe == nullptr)
            return;
        auto flags = sync::SpinLockAcquire(g_pipe_lock);
        Pipe& p = g_pipe_pool[idx];
        if (p.pins > 0)
            --p.pins;
        u8* buf = TakePipeFreeLocked(p);
        sync::SpinLockRelease(g_pipe_lock, flags);
        FinishPipeFree(buf);
    }

    explicit operator bool() const { return pipe != nullptr; }
};

struct EventfdPin
{
    u32 idx;
    Eventfd* eventfd;

    explicit EventfdPin(u32 value) : idx(value), eventfd(nullptr)
    {
        if (value >= kEventfdPoolCap)
            return;
        sync::SpinLockGuard guard(g_pipe_lock);
        Eventfd& e = g_eventfd_pool[value];
        if (e.in_use && !e.closing && e.pins != ~0U)
        {
            ++e.pins;
            eventfd = &e;
        }
    }

    ~EventfdPin()
    {
        if (eventfd == nullptr)
            return;
        sync::SpinLockGuard guard(g_pipe_lock);
        Eventfd& e = g_eventfd_pool[idx];
        if (e.pins > 0)
            --e.pins;
        if (e.pins == 0 && e.refs == 0)
        {
            e.in_use = false;
            e.closing = false;
            e.counter = 0;
            e.read_sequence = 0;
        }
    }

    explicit operator bool() const { return eventfd != nullptr; }
};

[[maybe_unused]] void PipeMaybeFree(u32 idx)
{
    if (idx >= kPipePoolCap)
        return;
    auto flags = sync::SpinLockAcquire(g_pipe_lock);
    u8* buf = TakePipeFreeLocked(g_pipe_pool[idx]);
    sync::SpinLockRelease(g_pipe_lock, flags);
    FinishPipeFree(buf);
}

} // namespace

#if 0 // superseded by the pinned, SMP-safe implementations below
[[maybe_unused]] i32 PipeAllocLegacy()
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
#endif

i32 PipeAlloc()
{
    u8* b = static_cast<u8*>(mm::KMalloc(kPipeBufBytes));
    if (b == nullptr)
        return -1;
    auto flags = sync::SpinLockAcquire(g_pipe_lock);
    for (u32 i = 0; i < kPipePoolCap; ++i)
    {
        if (g_pipe_pool[i].in_use)
            continue;
        Pipe& p = g_pipe_pool[i];
        p.buf = b;
        p.in_use = true;
        p.closing = false;
        p.read_refs = 1;
        p.write_refs = 1;
        p.pins = 0;
        p.head = 0;
        p.tail = 0;
        p.count = 0;
        p.read_sequence = 1;
        p.write_sequence = 1;
        p.read_wq.head = nullptr;
        p.read_wq.tail = nullptr;
        p.write_wq.head = nullptr;
        p.write_wq.tail = nullptr;
        sync::SpinLockRelease(g_pipe_lock, flags);
        return static_cast<i32>(i);
    }
    sync::SpinLockRelease(g_pipe_lock, flags);
    mm::KFree(b);
    return -1;
}

#if 0 // superseded legacy bodies retained for source comparison
[[maybe_unused]] void PipeRetainReadLegacy(u32 idx)
{
    if (idx >= kPipePoolCap)
        return;
    arch::Cli();
    Pipe& p = g_pipe_pool[idx];
    if (p.in_use)
        ++p.read_refs;
    arch::Sti();
}

[[maybe_unused]] void PipeRetainWriteLegacy(u32 idx)
{
    if (idx >= kPipePoolCap)
        return;
    arch::Cli();
    Pipe& p = g_pipe_pool[idx];
    if (p.in_use)
        ++p.write_refs;
    arch::Sti();
}

[[maybe_unused]] void PipeReleaseReadLegacy(u32 idx)
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

[[maybe_unused]] void PipeReleaseWriteLegacy(u32 idx)
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
#endif

bool PipeRetainRead(u32 idx)
{
    if (idx >= kPipePoolCap)
        return false;
    sync::SpinLockGuard guard(g_pipe_lock);
    Pipe& p = g_pipe_pool[idx];
    if (p.in_use && !p.closing && p.read_refs != ~0U)
    {
        ++p.read_refs;
        return true;
    }
    return false;
}

bool PipeRetainWrite(u32 idx)
{
    if (idx >= kPipePoolCap)
        return false;
    sync::SpinLockGuard guard(g_pipe_lock);
    Pipe& p = g_pipe_pool[idx];
    if (p.in_use && !p.closing && p.write_refs != ~0U)
    {
        ++p.write_refs;
        return true;
    }
    return false;
}

void PipeReleaseRead(u32 idx)
{
    if (idx >= kPipePoolCap)
        return;
    auto flags = sync::SpinLockAcquire(g_pipe_lock);
    Pipe& p = g_pipe_pool[idx];
    if (!p.in_use || p.read_refs == 0)
    {
        sync::SpinLockRelease(g_pipe_lock, flags);
        return;
    }
    --p.read_refs;
    if (p.read_refs == 0)
    {
        WaitSequencePublishLocked(&p.write_sequence);
        sched::WaitQueueWakeAll(&p.write_wq);
        if (p.write_refs == 0)
            p.closing = true;
    }
    u8* buf = TakePipeFreeLocked(p);
    sync::SpinLockRelease(g_pipe_lock, flags);
    FinishPipeFree(buf);
}

void PipeReleaseWrite(u32 idx)
{
    if (idx >= kPipePoolCap)
        return;
    auto flags = sync::SpinLockAcquire(g_pipe_lock);
    Pipe& p = g_pipe_pool[idx];
    if (!p.in_use || p.write_refs == 0)
    {
        sync::SpinLockRelease(g_pipe_lock, flags);
        return;
    }
    --p.write_refs;
    if (p.write_refs == 0)
    {
        WaitSequencePublishLocked(&p.read_sequence);
        sched::WaitQueueWakeAll(&p.read_wq);
        if (p.read_refs == 0)
            p.closing = true;
    }
    u8* buf = TakePipeFreeLocked(p);
    sync::SpinLockRelease(g_pipe_lock, flags);
    FinishPipeFree(buf);
}

bool PipeWaitCancellable(sched::WaitQueue* wq, const u64* sequence, u64 observed_sequence)
{
    // A saturated sequence can no longer prove that no producer raced this
    // wait. Retain bounded polling as a fail-closed fallback: it still exposes
    // cancellation, but cannot park forever after a lost producer wake.
    if (observed_sequence == ~u64{0})
    {
        return sched::WaitQueueBlockTimeoutCancellable(wq, 1) != sched::WaitQueueBlockResult::Cancelled;
    }
    return sched::WaitQueueBlockIfSequenceUnchangedCancellable(wq, sequence, observed_sequence) !=
           sched::WaitQueueBlockResult::Cancelled;
}

i64 PipeRead(u32 idx, u64 user_dst, u64 len)
{
    if (idx >= kPipePoolCap || len == 0)
        return 0;
    PipePin pin(idx);
    if (!pin)
        return 0;
    u8 stage[256];
    while (true)
    {
        auto flags = sync::SpinLockAcquire(g_pipe_lock);
        Pipe& p = *pin.pipe;
        if (!p.in_use)
        {
            sync::SpinLockRelease(g_pipe_lock, flags);
            return 0;
        }
        if (p.count == 0)
        {
            if (p.write_refs == 0)
            {
                sync::SpinLockRelease(g_pipe_lock, flags);
                return 0;
            }
            sched::WaitQueue* wq = &p.read_wq;
            const u64 observed_sequence = WaitSequenceSnapshotLocked(&p.read_sequence);
            sync::SpinLockRelease(g_pipe_lock, flags);
            if (!PipeWaitCancellable(wq, &p.read_sequence, observed_sequence))
                return kEINTR;
            continue;
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
        WaitSequencePublishLocked(&p.write_sequence);
        sched::WaitQueueWakeOne(&p.write_wq);
        sync::SpinLockRelease(g_pipe_lock, flags);
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, to_read))
            return kEFAULT;
        return static_cast<i64>(to_read);
    }
}

#if 0 // superseded legacy body retained for source comparison
[[maybe_unused]] i64 PipeReadLegacy(u32 idx, u64 user_dst, u64 len)
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
#endif

i64 PipeWrite(u32 idx, u64 user_src, u64 len)
{
    if (idx >= kPipePoolCap || len == 0)
        return 0;
    u8 stage[256];
    const u64 to_stage = (len < sizeof(stage)) ? len : sizeof(stage);
    if (!mm::CopyFromUser(stage, reinterpret_cast<const void*>(user_src), to_stage))
        return kEFAULT;
    PipePin pin(idx);
    if (!pin)
        return kEpipe;
    while (true)
    {
        auto flags = sync::SpinLockAcquire(g_pipe_lock);
        Pipe& p = *pin.pipe;
        if (!p.in_use || p.read_refs == 0)
        {
            sync::SpinLockRelease(g_pipe_lock, flags);
            return kEpipe;
        }
        if (p.count == kPipeBufBytes)
        {
            sched::WaitQueue* wq = &p.write_wq;
            const u64 observed_sequence = WaitSequenceSnapshotLocked(&p.write_sequence);
            sync::SpinLockRelease(g_pipe_lock, flags);
            if (!PipeWaitCancellable(wq, &p.write_sequence, observed_sequence))
                return kEINTR;
            continue;
        }
        const u64 free_slots = kPipeBufBytes - p.count;
        const u64 to_write = (to_stage < free_slots) ? to_stage : free_slots;
        for (u64 i = 0; i < to_write; ++i)
        {
            p.buf[p.head] = stage[i];
            p.head = (p.head + 1) % kPipeBufBytes;
            ++p.count;
        }
        WaitSequencePublishLocked(&p.read_sequence);
        sched::WaitQueueWakeOne(&p.read_wq);
        sync::SpinLockRelease(g_pipe_lock, flags);
        return static_cast<i64>(to_write);
    }
}

#if 0 // superseded legacy body retained for source comparison
[[maybe_unused]] i64 PipeWriteLegacy(u32 idx, u64 user_src, u64 len)
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
#endif

i64 PipeReadKernel(u32 idx, u8* dst, u64 len)
{
    if (idx >= kPipePoolCap || len == 0 || dst == nullptr)
        return 0;
    PipePin pin(idx);
    if (!pin)
        return 0;
    while (true)
    {
        auto flags = sync::SpinLockAcquire(g_pipe_lock);
        Pipe& p = *pin.pipe;
        if (!p.in_use)
        {
            sync::SpinLockRelease(g_pipe_lock, flags);
            return 0;
        }
        if (p.count == 0)
        {
            if (p.write_refs == 0)
            {
                sync::SpinLockRelease(g_pipe_lock, flags);
                return 0;
            }
            sched::WaitQueue* wq = &p.read_wq;
            const u64 observed_sequence = WaitSequenceSnapshotLocked(&p.read_sequence);
            sync::SpinLockRelease(g_pipe_lock, flags);
            if (!PipeWaitCancellable(wq, &p.read_sequence, observed_sequence))
                return kEINTR;
            continue;
        }
        const u64 to_read = (len < p.count) ? len : p.count;
        for (u64 i = 0; i < to_read; ++i)
        {
            dst[i] = p.buf[p.tail];
            p.tail = (p.tail + 1) % kPipeBufBytes;
            --p.count;
        }
        WaitSequencePublishLocked(&p.write_sequence);
        sched::WaitQueueWakeOne(&p.write_wq);
        sync::SpinLockRelease(g_pipe_lock, flags);
        return static_cast<i64>(to_read);
    }
}

#if 0 // superseded legacy body retained for source comparison
[[maybe_unused]] i64 PipeReadKernelLegacy(u32 idx, u8* dst, u64 len)
{
    if (idx >= kPipePoolCap || len == 0 || dst == nullptr)
        return 0;
    Pipe& p = g_pipe_pool[idx];
    arch::Cli();
    while (p.in_use && p.count == 0)
    {
        if (p.write_refs == 0)
        {
            arch::Sti();
            return 0; // EOF — every writer closed
        }
        sched::WaitQueueBlock(&p.read_wq);
        arch::Cli();
    }
    if (!p.in_use)
    {
        arch::Sti();
        return 0;
    }
    const u64 to_read = (len < p.count) ? len : p.count;
    for (u64 i = 0; i < to_read; ++i)
    {
        dst[i] = p.buf[p.tail];
        p.tail = (p.tail + 1) % kPipeBufBytes;
        --p.count;
    }
    sched::WaitQueueWakeOne(&p.write_wq);
    arch::Sti();
    return static_cast<i64>(to_read);
}
#endif

i64 PipeWriteKernel(u32 idx, const u8* src, u64 len)
{
    if (idx >= kPipePoolCap || len == 0 || src == nullptr)
        return 0;
    PipePin pin(idx);
    if (!pin)
        return kEpipe;
    while (true)
    {
        auto flags = sync::SpinLockAcquire(g_pipe_lock);
        Pipe& p = *pin.pipe;
        if (!p.in_use || p.read_refs == 0)
        {
            sync::SpinLockRelease(g_pipe_lock, flags);
            return kEpipe;
        }
        if (p.count == kPipeBufBytes)
        {
            sched::WaitQueue* wq = &p.write_wq;
            const u64 observed_sequence = WaitSequenceSnapshotLocked(&p.write_sequence);
            sync::SpinLockRelease(g_pipe_lock, flags);
            if (!PipeWaitCancellable(wq, &p.write_sequence, observed_sequence))
                return kEINTR;
            continue;
        }
        const u64 free_slots = kPipeBufBytes - p.count;
        const u64 to_write = (len < free_slots) ? len : free_slots;
        for (u64 i = 0; i < to_write; ++i)
        {
            p.buf[p.head] = src[i];
            p.head = (p.head + 1) % kPipeBufBytes;
            ++p.count;
        }
        WaitSequencePublishLocked(&p.read_sequence);
        sched::WaitQueueWakeOne(&p.read_wq);
        sync::SpinLockRelease(g_pipe_lock, flags);
        return static_cast<i64>(to_write);
    }
}

#if 0 // superseded legacy body retained for source comparison
[[maybe_unused]] i64 PipeWriteKernelLegacy(u32 idx, const u8* src, u64 len)
{
    if (idx >= kPipePoolCap || len == 0 || src == nullptr)
        return 0;
    Pipe& p = g_pipe_pool[idx];
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
    const u64 to_write = (len < free_slots) ? len : free_slots;
    for (u64 i = 0; i < to_write; ++i)
    {
        p.buf[p.head] = src[i];
        p.head = (p.head + 1) % kPipeBufBytes;
        ++p.count;
    }
    sched::WaitQueueWakeOne(&p.read_wq);
    arch::Sti();
    return static_cast<i64>(to_write);
}
#endif

// splice / tee — kernel-bypass byte movement between two pipe
// rings. No CopyFromUser/CopyToUser bounce; no per-byte loops on
// the slow path because the rings are already kernel-owned and
// already 4 KiB-bounded.
//
// Both operations match Linux's single-iteration shape: one call
// moves at most one transfer's worth of bytes (≤ len, ≤ source
// count, ≤ destination free). The caller's read/write loop
// drives the next iteration. This matches glibc / sendfile's
// expectation and keeps the kernel-side state machine simple.
//
// Source-side EOF (every writer closed) returns 0 as PipeRead
// would. Destination-side disconnect (every reader closed)
// returns -EPIPE.
#if 0 // superseded legacy bodies retained for source comparison
[[maybe_unused]] i64 PipeSpliceFromPipeLegacy(u32 dst_idx, u32 src_idx, u64 len)
{
    if (dst_idx >= kPipePoolCap || src_idx >= kPipePoolCap || len == 0)
        return 0;
    if (dst_idx == src_idx)
        return -22; // -EINVAL — splice into itself is meaningless
    Pipe& src = g_pipe_pool[src_idx];
    Pipe& dst = g_pipe_pool[dst_idx];
    arch::Cli();
    // Source-side: block once if the ring is empty AND there are
    // still writers (otherwise it's EOF or a torn pool slot).
    while (src.in_use && src.count == 0)
    {
        if (src.write_refs == 0)
        {
            arch::Sti();
            return 0; // EOF
        }
        sched::WaitQueueBlock(&src.read_wq);
        arch::Cli();
    }
    if (!src.in_use)
    {
        arch::Sti();
        return 0;
    }
    if (!dst.in_use || dst.read_refs == 0)
    {
        arch::Sti();
        return kEpipe;
    }
    const u64 src_avail = src.count;
    const u64 dst_free = kPipeBufBytes - dst.count;
    u64 to_move = (len < src_avail) ? len : src_avail;
    if (to_move > dst_free)
        to_move = dst_free;
    for (u64 i = 0; i < to_move; ++i)
    {
        dst.buf[dst.head] = src.buf[src.tail];
        dst.head = (dst.head + 1) % kPipeBufBytes;
        ++dst.count;
        src.tail = (src.tail + 1) % kPipeBufBytes;
        --src.count;
    }
    if (to_move > 0)
    {
        sched::WaitQueueWakeOne(&dst.read_wq);
        sched::WaitQueueWakeOne(&src.write_wq);
    }
    arch::Sti();
    return static_cast<i64>(to_move);
}

[[maybe_unused]] i64 PipeTeeFromPipeLegacy(u32 dst_idx, u32 src_idx, u64 len)
{
    if (dst_idx >= kPipePoolCap || src_idx >= kPipePoolCap || len == 0)
        return 0;
    if (dst_idx == src_idx)
        return -22;
    Pipe& src = g_pipe_pool[src_idx];
    Pipe& dst = g_pipe_pool[dst_idx];
    arch::Cli();
    while (src.in_use && src.count == 0)
    {
        if (src.write_refs == 0)
        {
            arch::Sti();
            return 0; // EOF
        }
        sched::WaitQueueBlock(&src.read_wq);
        arch::Cli();
    }
    if (!src.in_use)
    {
        arch::Sti();
        return 0;
    }
    if (!dst.in_use || dst.read_refs == 0)
    {
        arch::Sti();
        return kEpipe;
    }
    const u64 src_avail = src.count;
    const u64 dst_free = kPipeBufBytes - dst.count;
    u64 to_copy = (len < src_avail) ? len : src_avail;
    if (to_copy > dst_free)
        to_copy = dst_free;
    // Walk src starting at tail without consuming. Wraps the same
    // way the source ring does.
    u32 src_cursor = src.tail;
    for (u64 i = 0; i < to_copy; ++i)
    {
        dst.buf[dst.head] = src.buf[src_cursor];
        dst.head = (dst.head + 1) % kPipeBufBytes;
        ++dst.count;
        src_cursor = (src_cursor + 1) % kPipeBufBytes;
    }
    if (to_copy > 0)
        sched::WaitQueueWakeOne(&dst.read_wq);
    arch::Sti();
    return static_cast<i64>(to_copy);
}
#endif

// ============================================================
// Eventfd pool helpers
// ============================================================

namespace
{

} // namespace

i64 PipeSpliceFromPipe(u32 dst_idx, u32 src_idx, u64 len)
{
    if (dst_idx >= kPipePoolCap || src_idx >= kPipePoolCap || len == 0 || dst_idx == src_idx)
        return (dst_idx == src_idx) ? -22 : 0;
    PipePin dst_pin(dst_idx);
    PipePin src_pin(src_idx);
    if (!dst_pin || !src_pin)
        return 0;
    while (true)
    {
        auto flags = sync::SpinLockAcquire(g_pipe_lock);
        Pipe& dst = *dst_pin.pipe;
        Pipe& src = *src_pin.pipe;
        if (!src.in_use || !dst.in_use || dst.read_refs == 0)
        {
            sync::SpinLockRelease(g_pipe_lock, flags);
            return src.in_use ? kEpipe : 0;
        }
        if (src.count == 0)
        {
            if (src.write_refs == 0)
            {
                sync::SpinLockRelease(g_pipe_lock, flags);
                return 0;
            }
            sched::WaitQueue* wq = &src.read_wq;
            const u64 observed_sequence = WaitSequenceSnapshotLocked(&src.read_sequence);
            sync::SpinLockRelease(g_pipe_lock, flags);
            if (!PipeWaitCancellable(wq, &src.read_sequence, observed_sequence))
                return kEINTR;
            continue;
        }
        const u64 src_avail = src.count;
        const u64 dst_free = kPipeBufBytes - dst.count;
        u64 to_move = (len < src_avail) ? len : src_avail;
        if (to_move > dst_free)
            to_move = dst_free;
        for (u64 i = 0; i < to_move; ++i)
        {
            dst.buf[dst.head] = src.buf[src.tail];
            dst.head = (dst.head + 1) % kPipeBufBytes;
            ++dst.count;
            src.tail = (src.tail + 1) % kPipeBufBytes;
            --src.count;
        }
        if (to_move > 0)
        {
            WaitSequencePublishLocked(&dst.read_sequence);
            WaitSequencePublishLocked(&src.write_sequence);
            sched::WaitQueueWakeOne(&dst.read_wq);
            sched::WaitQueueWakeOne(&src.write_wq);
        }
        sync::SpinLockRelease(g_pipe_lock, flags);
        return static_cast<i64>(to_move);
    }
}

i64 PipeTeeFromPipe(u32 dst_idx, u32 src_idx, u64 len)
{
    if (dst_idx >= kPipePoolCap || src_idx >= kPipePoolCap || len == 0 || dst_idx == src_idx)
        return (dst_idx == src_idx) ? -22 : 0;
    PipePin dst_pin(dst_idx);
    PipePin src_pin(src_idx);
    if (!dst_pin || !src_pin)
        return 0;
    while (true)
    {
        auto flags = sync::SpinLockAcquire(g_pipe_lock);
        Pipe& dst = *dst_pin.pipe;
        Pipe& src = *src_pin.pipe;
        if (!src.in_use || !dst.in_use || dst.read_refs == 0)
        {
            sync::SpinLockRelease(g_pipe_lock, flags);
            return src.in_use ? kEpipe : 0;
        }
        if (src.count == 0)
        {
            if (src.write_refs == 0)
            {
                sync::SpinLockRelease(g_pipe_lock, flags);
                return 0;
            }
            sched::WaitQueue* wq = &src.read_wq;
            const u64 observed_sequence = WaitSequenceSnapshotLocked(&src.read_sequence);
            sync::SpinLockRelease(g_pipe_lock, flags);
            if (!PipeWaitCancellable(wq, &src.read_sequence, observed_sequence))
                return kEINTR;
            continue;
        }
        const u64 dst_free = kPipeBufBytes - dst.count;
        u64 to_copy = (len < src.count) ? len : src.count;
        if (to_copy > dst_free)
            to_copy = dst_free;
        u32 src_cursor = src.tail;
        for (u64 i = 0; i < to_copy; ++i)
        {
            dst.buf[dst.head] = src.buf[src_cursor];
            dst.head = (dst.head + 1) % kPipeBufBytes;
            ++dst.count;
            src_cursor = (src_cursor + 1) % kPipeBufBytes;
        }
        if (to_copy > 0)
        {
            WaitSequencePublishLocked(&dst.read_sequence);
            sched::WaitQueueWakeOne(&dst.read_wq);
        }
        sync::SpinLockRelease(g_pipe_lock, flags);
        return static_cast<i64>(to_copy);
    }
}

namespace
{

#if 0 // superseded legacy body retained for source comparison
[[maybe_unused]] i32 EventfdAllocLegacy(u64 initval, u32 flags)
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
#endif

i32 EventfdAlloc(u64 initval, u32 flags)
{
    sync::SpinLockGuard guard(g_pipe_lock);
    for (u32 i = 0; i < kEventfdPoolCap; ++i)
    {
        Eventfd& e = g_eventfd_pool[i];
        if (e.in_use)
            continue;
        e.in_use = true;
        e.closing = false;
        e.refs = 1;
        e.pins = 0;
        e.counter = initval;
        e.read_sequence = 1;
        e.flags = flags;
        e.read_wq.head = nullptr;
        e.read_wq.tail = nullptr;
        return static_cast<i32>(i);
    }
    return -1;
}

} // namespace

#if 0 // superseded legacy bodies retained for source comparison
[[maybe_unused]] void EventfdRetainLegacy(u32 idx)
{
    if (idx >= kEventfdPoolCap)
        return;
    arch::Cli();
    Eventfd& e = g_eventfd_pool[idx];
    if (e.in_use)
        ++e.refs;
    arch::Sti();
}

[[maybe_unused]] void EventfdReleaseLegacy(u32 idx)
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

[[maybe_unused]] i64 EventfdReadLegacy(u32 idx, u64 user_dst, u64 len)
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

// ============================================================
// Non-blocking readiness probes — for epoll_wait
// ============================================================

[[maybe_unused]] bool PipeReadReadyLegacy(u32 idx)
{
    if (idx >= kPipePoolCap)
        return false;
    arch::Cli();
    Pipe& p = g_pipe_pool[idx];
    const bool ready = p.in_use && (p.count > 0 || p.write_refs == 0);
    arch::Sti();
    return ready;
}

[[maybe_unused]] bool PipeWriteReadyLegacy(u32 idx)
{
    if (idx >= kPipePoolCap)
        return false;
    arch::Cli();
    Pipe& p = g_pipe_pool[idx];
    // EPIPE-ready (every reader gone) also counts as "won't block"
    // — write will fail immediately.
    const bool ready = p.in_use && (p.count < kPipeBufBytes || p.read_refs == 0);
    arch::Sti();
    return ready;
}

[[maybe_unused]] bool EventfdReadyLegacy(u32 idx)
{
    if (idx >= kEventfdPoolCap)
        return false;
    arch::Cli();
    Eventfd& e = g_eventfd_pool[idx];
    const bool ready = e.in_use && e.counter > 0;
    arch::Sti();
    return ready;
}

[[maybe_unused]] i64 EventfdWriteLegacy(u32 idx, u64 user_src, u64 len)
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
#endif

// ============================================================
// Syscall handlers — DoPipe / DoPipe2 / DoEventfd / DoEventfd2
// ============================================================

void EventfdRetain(u32 idx)
{
    if (idx >= kEventfdPoolCap)
        return;
    sync::SpinLockGuard guard(g_pipe_lock);
    Eventfd& e = g_eventfd_pool[idx];
    if (e.in_use && !e.closing && e.refs != ~0U)
        ++e.refs;
}

void EventfdRelease(u32 idx)
{
    if (idx >= kEventfdPoolCap)
        return;
    sync::SpinLockGuard guard(g_pipe_lock);
    Eventfd& e = g_eventfd_pool[idx];
    if (!e.in_use || e.refs == 0)
        return;
    --e.refs;
    if (e.refs == 0)
    {
        e.closing = true;
        WaitSequencePublishLocked(&e.read_sequence);
        sched::WaitQueueWakeAll(&e.read_wq);
        if (e.pins == 0)
        {
            e.in_use = false;
            e.closing = false;
            e.counter = 0;
            e.read_sequence = 0;
        }
    }
}

i64 EventfdRead(u32 idx, u64 user_dst, u64 len)
{
    if (idx >= kEventfdPoolCap || len < 8)
        return kEINVAL;
    EventfdPin pin(idx);
    if (!pin)
        return 0;
    constexpr u32 kEfdSemaphore = 0x1;
    while (true)
    {
        auto flags = sync::SpinLockAcquire(g_pipe_lock);
        Eventfd& e = *pin.eventfd;
        if (!e.in_use || e.closing)
        {
            sync::SpinLockRelease(g_pipe_lock, flags);
            return 0;
        }
        if (e.counter == 0)
        {
            sched::WaitQueue* wq = &e.read_wq;
            const u64 observed_sequence = WaitSequenceSnapshotLocked(&e.read_sequence);
            sync::SpinLockRelease(g_pipe_lock, flags);
            if (!PipeWaitCancellable(wq, &e.read_sequence, observed_sequence))
                return kEINTR;
            continue;
        }
        u64 out;
        if ((e.flags & kEfdSemaphore) != 0)
        {
            out = 1;
            --e.counter;
        }
        else
        {
            out = e.counter;
            e.counter = 0;
        }
        sync::SpinLockRelease(g_pipe_lock, flags);
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), &out, sizeof(out)))
            return kEFAULT;
        return 8;
    }
}

bool PipeReadReady(u32 idx)
{
    if (idx >= kPipePoolCap)
        return false;
    sync::SpinLockGuard guard(g_pipe_lock);
    const Pipe& p = g_pipe_pool[idx];
    return p.in_use && !p.closing && (p.count > 0 || p.write_refs == 0);
}

bool PipeWriteReady(u32 idx)
{
    if (idx >= kPipePoolCap)
        return false;
    sync::SpinLockGuard guard(g_pipe_lock);
    const Pipe& p = g_pipe_pool[idx];
    return p.in_use && !p.closing && (p.count < kPipeBufBytes || p.read_refs == 0);
}

bool EventfdReady(u32 idx)
{
    if (idx >= kEventfdPoolCap)
        return false;
    sync::SpinLockGuard guard(g_pipe_lock);
    const Eventfd& e = g_eventfd_pool[idx];
    return e.in_use && !e.closing && e.counter > 0;
}

i64 EventfdWrite(u32 idx, u64 user_src, u64 len)
{
    if (idx >= kEventfdPoolCap || len < 8)
        return kEINVAL;
    u64 in = 0;
    if (!mm::CopyFromUser(&in, reinterpret_cast<const void*>(user_src), sizeof(in)))
        return kEFAULT;
    if (in == static_cast<u64>(-1))
        return kEINVAL;
    EventfdPin pin(idx);
    if (!pin)
        return kEINVAL;
    sync::SpinLockGuard guard(g_pipe_lock);
    Eventfd& e = *pin.eventfd;
    if (!e.in_use || e.closing)
        return kEINVAL;
    const u64 cap = static_cast<u64>(-1) - 1;
    e.counter = (e.counter > cap - in) ? cap : e.counter + in;
    WaitSequencePublishLocked(&e.read_sequence);
    sched::WaitQueueWakeOne(&e.read_wq);
    return 8;
}

i64 DoPipe(u64 user_fds)
{
    return DoPipe2(user_fds, /*flags=*/0);
}

i64 DoPipe2(u64 user_fds, u64 flags)
{
    // Linux open-flag bits we honour: O_CLOEXEC (0x80000) — stamps
    // the cloexec bit on both ends; O_NONBLOCK (0x800) — accepted
    // as a no-op (v0 pipes are blocking, sub-GAP).
    constexpr u64 kO_CLOEXEC = 0x80000;
    constexpr u64 kO_NONBLOCK = 0x800;
    if ((flags & ~(kO_CLOEXEC | kO_NONBLOCK)) != 0)
        return kEINVAL;

    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    const i32 idx = PipeAlloc();
    if (idx < 0)
        return kENFILE;

    auto read_file_result = ::duetos::ipc::KFileCreate(::duetos::ipc::KFileKind::PipeRead, static_cast<u32>(idx),
                                                       &PipeReleaseRead, nullptr, 0);
    if (!read_file_result.has_value())
    {
        PipeReleaseRead(static_cast<u32>(idx));
        PipeReleaseWrite(static_cast<u32>(idx));
        return kENOMEM;
    }
    auto write_file_result = ::duetos::ipc::KFileCreate(::duetos::ipc::KFileKind::PipeWrite, static_cast<u32>(idx),
                                                        &PipeReleaseWrite, nullptr, 0);
    if (!write_file_result.has_value())
    {
        ::duetos::ipc::KObjectRelease(&read_file_result.value()->base);
        PipeReleaseWrite(static_cast<u32>(idx));
        return kENOMEM;
    }

    core::Process::LinuxFd read_payload{};
    read_payload.state = 3;
    read_payload.first_cluster = static_cast<u32>(idx);
    core::Process::LinuxFd write_payload{};
    write_payload.state = 4;
    write_payload.first_cluster = static_cast<u32>(idx);
    if ((flags & kO_CLOEXEC) != 0)
    {
        read_payload.flags = core::Process::kLinuxFdFlagCloexec;
        write_payload.flags = core::Process::kLinuxFdFlagCloexec;
    }

    core::LinuxFdPrepared read_prepared{};
    core::LinuxFdPrepared write_prepared{};
    constexpr u32 kO_RDONLY = 0;
    constexpr u32 kO_WRONLY = 1;
    const u32 pipe_status_flags = static_cast<u32>(flags & kO_NONBLOCK);
    if (!core::LinuxFdPrepare(&read_prepared, read_payload, &read_file_result.value()->base,
                              kO_RDONLY | pipe_status_flags))
    {
        ::duetos::ipc::KObjectRelease(&read_file_result.value()->base);
        ::duetos::ipc::KObjectRelease(&write_file_result.value()->base);
        return kENFILE;
    }
    if (!core::LinuxFdPrepare(&write_prepared, write_payload, &write_file_result.value()->base,
                              kO_WRONLY | pipe_status_flags))
    {
        core::LinuxFdPreparedRelease(&read_prepared);
        ::duetos::ipc::KObjectRelease(&write_file_result.value()->base);
        return kENFILE;
    }

    u32 r_fd = 0;
    u32 w_fd = 0;
    core::LinuxFdAcquired read_acquired{};
    core::LinuxFdAcquired write_acquired{};
    if (!core::LinuxFdBindPairLowest(p, 3, &read_prepared, &write_prepared, &r_fd, &w_fd, &read_acquired,
                                     &write_acquired))
    {
        core::LinuxFdPreparedRelease(&read_prepared);
        core::LinuxFdPreparedRelease(&write_prepared);
        return kEMFILE;
    }

    // The acquired outputs pin both exact published identities across the
    // user copy, making an EFAULT rollback generation-safe under close/reuse.
    u32 fds[2];
    fds[0] = r_fd;
    fds[1] = w_fd;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_fds), fds, sizeof(fds)))
    {
        core::LinuxFdDetached read_detached{};
        core::LinuxFdDetached write_detached{};
        if (core::LinuxFdUnbindAcquired(p, r_fd, &read_acquired, &read_detached))
            core::LinuxFdDetachedRelease(&read_detached);
        if (core::LinuxFdUnbindAcquired(p, w_fd, &write_acquired, &write_detached))
            core::LinuxFdDetachedRelease(&write_detached);
        core::LinuxFdAcquiredRelease(&read_acquired);
        core::LinuxFdAcquiredRelease(&write_acquired);
        return kEFAULT;
    }

    core::LinuxFdAcquiredRelease(&read_acquired);
    core::LinuxFdAcquiredRelease(&write_acquired);

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
    constexpr u64 kEFD_CLOEXEC = 0x80000;
    constexpr u64 kEFD_NONBLOCK = 0x800;
    constexpr u64 kEFD_SEMAPHORE = 0x1;
    if ((flags & ~(kEFD_CLOEXEC | kEFD_NONBLOCK | kEFD_SEMAPHORE)) != 0)
        return kEINVAL;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    const i32 idx = EventfdAlloc(initval, static_cast<u32>(flags));
    if (idx < 0)
        return kENFILE;

    auto kfile_result = ::duetos::ipc::KFileCreate(::duetos::ipc::KFileKind::Eventfd, static_cast<u32>(idx),
                                                   &EventfdRelease, nullptr, 0);
    if (!kfile_result.has_value())
    {
        EventfdRelease(static_cast<u32>(idx));
        return kENOMEM;
    }

    core::Process::LinuxFd payload{};
    payload.state = 5;
    payload.first_cluster = static_cast<u32>(idx);
    core::LinuxFdPrepared prepared{};
    constexpr u32 kO_RDWR = 2;
    const u32 eventfd_status_flags = kO_RDWR | static_cast<u32>(flags & kEFD_NONBLOCK);
    if (!core::LinuxFdPrepare(&prepared, payload, &kfile_result.value()->base, eventfd_status_flags))
    {
        ::duetos::ipc::KObjectRelease(&kfile_result.value()->base);
        return kENFILE;
    }
    const i32 fd = core::LinuxFdBindLowest(p, 3, &prepared, (flags & kEFD_CLOEXEC) != 0);
    if (fd < 0)
    {
        core::LinuxFdPreparedRelease(&prepared);
        return kEMFILE;
    }
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
