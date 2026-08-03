/*
 * SysV msg queues + POSIX message queues — v0.
 *
 * Both engines share the same shape: bounded message ring per queue,
 * KMalloc'd on demand, blocking via WaitQueue. Differences:
 *
 *   SysV MQ — keyed by i32 IPC key (or IPC_PRIVATE = 0). Each
 *     message has a `mtype` prefix (long; positive). Receivers can
 *     filter by mtype: 0 = any; > 0 = exact match; < 0 = any
 *     mtype <= |mtype|. New LinuxFd state NOT used; SysV msg
 *     queues use a positive generation-bearing public ID directly, not a
 *     per-process fd. The ID names the family, slot, and exact incarnation.
 *
 *   POSIX MQ — keyed by name string ("/foo"). Each message has an
 *     unsigned priority (0..max); receivers see the highest-priority
 *     pending message. New LinuxFd state 13 = mq_open descriptor.
 *
 * v0 caps: 8 queues per family, 16 messages per queue, 1024-byte
 * messages. Bounded by KMalloc on first use.
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/kfile.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "time/tick.h"
#include "util/nospec.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u32 kSysvMqPoolCap = 8;
constexpr u32 kPosixMqPoolCap = 8;
constexpr u32 kMqMsgsPerQueue = 16;
constexpr u32 kMqMaxMsgBytes = 1024;
constexpr u32 kPosixMqNameCap = 64;
static_assert(kSysvMqPoolCap == kSysvIpcIdPoolCapacity);

constexpr u64 kIpcCreat = 0x200;
constexpr u64 kIpcExcl = 0x400;
constexpr u64 kIpcNowait = 0x800;
constexpr u64 kIpcRmid = 0;
constexpr u64 kIpcStat = 2;
constexpr i64 kSysvMqAllocBusy = -2;

// SysV message: long mtype prefix + payload bytes.
struct SysvMsg
{
    i64 mtype;
    u32 len;
    u32 _pad;
    u8 body[kMqMaxMsgBytes];
};

struct SysvMq
{
    bool in_use;
    bool marked_destroy;
    bool initializing;
    bool closing;
    u32 pins;
    u64 incarnation;
    u64 wait_sequence;
    i32 key;
    u32 head;
    u32 tail;
    u32 count;
    u32 _pad2;
    SysvMsg* ring; // KMalloc'd kMqMsgsPerQueue entries
    sched::WaitQueue read_wq;
    sched::WaitQueue write_wq;
};

// POSIX message: priority + payload.
struct PosixMsg
{
    u32 prio;
    u32 len;
    u8 body[kMqMaxMsgBytes];
};

struct PosixMq
{
    bool in_use;
    bool initializing;
    bool closing;
    u8 _pad;
    u32 refs;
    u32 pins;
    u64 wait_sequence;
    char name[kPosixMqNameCap];
    u32 max_msgs; // current ring cap
    u32 max_msg_bytes;
    u32 count;
    u32 _pad2;
    PosixMsg* ring; // KMalloc'd
    sched::WaitQueue read_wq;
    sched::WaitQueue write_wq;
};

SysvMq g_sysv_pool[kSysvMqPoolCap];
PosixMq g_posix_pool[kPosixMqPoolCap];
constinit sync::SpinLock g_sysv_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};
constinit sync::SpinLock g_posix_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};

// Predicate epochs live in the static pool slots and are deliberately never
// reset. Producers serialize through the owning subsystem lock, publish with
// release ordering, and then wake. Once saturated, callers fall back to a
// one-tick cancellable retry rather than risking a permanently lost wake.
void WaitSequencePublishLocked(u64* sequence)
{
    const u64 observed = __atomic_load_n(sequence, __ATOMIC_RELAXED);
    if (observed != ~u64{0})
        __atomic_store_n(sequence, observed + 1, __ATOMIC_RELEASE);
}

u64 WaitSequenceSnapshotLocked(const u64* sequence)
{
    return __atomic_load_n(sequence, __ATOMIC_ACQUIRE);
}

bool WaitForSequenceChangeCancellable(sched::WaitQueue* wq, const u64* sequence, u64 observed_sequence)
{
    const sched::WaitQueueBlockResult result =
        observed_sequence == ~u64{0}
            ? sched::WaitQueueBlockIfSequenceUnchangedTimeoutCancellable(wq, sequence, observed_sequence, 1)
            : sched::WaitQueueBlockIfSequenceUnchangedCancellable(wq, sequence, observed_sequence);
    return result != sched::WaitQueueBlockResult::Cancelled;
}

struct LinuxFdAcquiredGuard
{
    core::LinuxFdAcquired* acquired;

    ~LinuxFdAcquiredGuard() { core::LinuxFdAcquiredRelease(acquired); }
};

struct PosixMqPin
{
    u32 idx;
    PosixMq* queue;

    explicit PosixMqPin(u32 value) : idx(value), queue(nullptr)
    {
        if (value >= kPosixMqPoolCap)
            return;
        sync::SpinLockGuard guard(g_posix_lock);
        PosixMq& q = g_posix_pool[value];
        if (q.in_use && !q.initializing && !q.closing)
        {
            ++q.pins;
            queue = &q;
        }
    }

    ~PosixMqPin()
    {
        if (queue == nullptr)
            return;
        auto flags = sync::SpinLockAcquire(g_posix_lock);
        PosixMq& q = g_posix_pool[idx];
        if (q.pins > 0)
            --q.pins;
        PosixMsg* ring = nullptr;
        if (q.pins == 0 && q.refs == 0 && !q.in_use && q.closing)
        {
            ring = q.ring;
            q.ring = nullptr;
            q.closing = false;
            q.count = 0;
        }
        sync::SpinLockRelease(g_posix_lock, flags);
        if (ring != nullptr)
            mm::KFree(ring);
    }

    explicit operator bool() const { return queue != nullptr; }
};

struct SysvMqPin
{
    u32 idx;
    SysvMq* queue;

    explicit SysvMqPin(u32 value) : idx(value), queue(nullptr)
    {
        if (value >= kSysvMqPoolCap)
            return;
        sync::SpinLockGuard guard(g_sysv_lock);
        SysvMq& q = g_sysv_pool[value];
        if (q.in_use && !q.initializing && !q.closing)
        {
            ++q.pins;
            queue = &q;
        }
    }

    ~SysvMqPin()
    {
        if (queue == nullptr)
            return;
        auto flags = sync::SpinLockAcquire(g_sysv_lock);
        SysvMq& q = g_sysv_pool[idx];
        if (q.pins > 0)
            --q.pins;
        SysvMsg* ring = nullptr;
        if (q.pins == 0 && !q.in_use && q.closing)
        {
            ring = q.ring;
            q.ring = nullptr;
            q.closing = false;
            q.count = 0;
        }
        sync::SpinLockRelease(g_sysv_lock, flags);
        if (ring != nullptr)
            mm::KFree(ring);
    }

    explicit operator bool() const { return queue != nullptr; }
};

// =========================================================
// SysV MQ helpers
// =========================================================

i64 SysvMqFindByKey(i32 key)
{
    if (key == 0)
        return -1;
    sync::SpinLockGuard guard(g_sysv_lock);
    for (u32 i = 0; i < kSysvMqPoolCap; ++i)
    {
        const SysvMq& q = g_sysv_pool[i];
        if (!q.in_use || q.marked_destroy || q.key != key)
            continue;
        if (q.initializing)
            return kSysvMqAllocBusy;
        return SysvIpcEncodeId(SysvIpcIdFamily::MessageQueue, i, q.incarnation);
    }
    return -1;
}

i64 SysvMqAlloc(i32 key)
{
    auto flags = sync::SpinLockAcquire(g_sysv_lock);
    if (key != 0)
    {
        // Close the lookup/reservation race in DoMsgget. Initializing rows are
        // deliberately visible here so two IPC_CREAT callers cannot publish
        // distinct queues for the same key.
        for (u32 i = 0; i < kSysvMqPoolCap; ++i)
        {
            const SysvMq& q = g_sysv_pool[i];
            if (q.in_use && !q.marked_destroy && q.key == key)
            {
                sync::SpinLockRelease(g_sysv_lock, flags);
                return kSysvMqAllocBusy;
            }
        }
    }
    for (u32 i = 0; i < kSysvMqPoolCap; ++i)
    {
        if (g_sysv_pool[i].in_use || g_sysv_pool[i].closing || g_sysv_pool[i].incarnation >= kSysvIpcIdGenerationMax)
            continue;
        SysvMq& q = g_sysv_pool[i];
        ++q.incarnation;
        q.in_use = true;
        q.initializing = true;
        q.marked_destroy = false;
        q.closing = false;
        q.pins = 0;
        q.key = key;
        q.head = 0;
        q.tail = 0;
        q.count = 0;
        // The embedded wait queues are static-slot state, just like the
        // nonwrapping sequence. Do not reset their intrusive links on reuse:
        // at sequence saturation, an old-incarnation waiter may still be in
        // its bounded one-tick enqueue window after RMID's wake-all.
        q.ring = nullptr;
        WaitSequencePublishLocked(&q.wait_sequence);
        sync::SpinLockRelease(g_sysv_lock, flags);
        q.ring = static_cast<SysvMsg*>(mm::KMalloc(sizeof(SysvMsg) * kMqMsgsPerQueue));
        if (q.ring == nullptr)
        {
            flags = sync::SpinLockAcquire(g_sysv_lock);
            q.in_use = false;
            q.initializing = false;
            WaitSequencePublishLocked(&q.wait_sequence);
            sync::SpinLockRelease(g_sysv_lock, flags);
            return -1;
        }
        flags = sync::SpinLockAcquire(g_sysv_lock);
        q.initializing = false;
        WaitSequencePublishLocked(&q.wait_sequence);
        const u32 id = SysvIpcEncodeId(SysvIpcIdFamily::MessageQueue, i, q.incarnation);
        KASSERT(id != 0, "linux/sysvmq", "published queue has unencodable id");
        sync::SpinLockRelease(g_sysv_lock, flags);
        return id;
    }
    sync::SpinLockRelease(g_sysv_lock, flags);
    return -1;
}

i32 SysvFindByMtype(SysvMq& q, i64 mtype_filter)
{
    // Linear scan for the FIRST message matching the filter.
    // mtype_filter == 0    : any message (head)
    // mtype_filter > 0     : exact match
    // mtype_filter < 0     : any message with mtype <= |mtype_filter|
    if (q.count == 0)
        return -1;
    if (mtype_filter == 0)
        return static_cast<i32>(q.tail);
    const u64 negative_limit = (mtype_filter < 0) ? (0ull - static_cast<u64>(mtype_filter)) : 0;
    for (u32 i = 0; i < q.count; ++i)
    {
        const u32 idx = (q.tail + i) % kMqMsgsPerQueue;
        const SysvMsg& m = q.ring[idx];
        if (mtype_filter > 0 && m.mtype == mtype_filter)
            return static_cast<i32>(idx);
        if (mtype_filter < 0 && static_cast<u64>(m.mtype) <= negative_limit)
            return static_cast<i32>(idx);
    }
    return -1;
}

void SysvDrainAt(SysvMq& q, u32 idx)
{
    // Compact: shift entries between [tail, idx) one slot forward,
    // then advance tail. Keeps the ring dense; preserves FIFO.
    u32 cur = idx;
    while (cur != q.tail)
    {
        const u32 prev = (cur + kMqMsgsPerQueue - 1) % kMqMsgsPerQueue;
        q.ring[cur] = q.ring[prev];
        cur = prev;
    }
    q.tail = (q.tail + 1) % kMqMsgsPerQueue;
    --q.count;
}

} // namespace

// =========================================================
// SysV msgget / msgsnd / msgrcv / msgctl
// =========================================================

i64 DoMsgget(u64 key, u64 msgflg)
{
    const i32 ikey = static_cast<i32>(key);
    const bool create = (msgflg & kIpcCreat) != 0;
    const bool excl = (msgflg & kIpcExcl) != 0;
    // A concurrent creator leaves a short-lived initializing row. Both lookup
    // and allocation report that reservation under g_sysv_lock; yield until
    // its synchronous allocator publishes or rolls back so callers never see
    // a non-Linux EAGAIN or create a duplicate queue for the same key.
    while (true)
    {
        if (ikey != 0)
        {
            const i64 existing = SysvMqFindByKey(ikey);
            if (existing == kSysvMqAllocBusy)
            {
                sched::SchedYield();
                continue;
            }
            if (existing >= 0)
            {
                if (create && excl)
                    return -17; // -EEXIST
                return existing;
            }
            if (!create)
                return -2; // -ENOENT
        }

        const i64 id = SysvMqAlloc(ikey);
        if (id == kSysvMqAllocBusy)
        {
            sched::SchedYield();
            continue;
        }
        if (id < 0)
            return -28; // -ENOSPC
        arch::SerialWrite("[linux/sysvmq] alloc id=");
        arch::SerialWriteHex(static_cast<u64>(id));
        arch::SerialWrite(" key=");
        arch::SerialWriteHex(static_cast<u64>(ikey));
        arch::SerialWrite("\n");
        return id;
    }
}

i64 DoMsgsnd(u64 msqid, u64 user_msg, u64 msgsz, u64 msgflg)
{
    SysvIpcDecodedId decoded{};
    if (!SysvIpcDecodeId(msqid, SysvIpcIdFamily::MessageQueue, &decoded))
        return -22; // -EINVAL
    if (msgsz > kMqMaxMsgBytes)
        return -22;
    const u32 idx = decoded.index;
    const bool nowait = (msgflg & kIpcNowait) != 0;

    // Bind this in-flight operation to the generation carried by the public id
    // before touching user memory. RMID + reuse during CopyFromUser must report
    // EIDRM rather than redirecting the send to the replacement queue.
    SysvMq& q = g_sysv_pool[idx];
    const u64 expected_incarnation = decoded.generation;
    {
        auto lock_flags = sync::SpinLockAcquire(g_sysv_lock);
        if (!q.in_use || q.initializing || q.marked_destroy || q.closing || q.incarnation != expected_incarnation)
        {
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return -22;
        }
        sync::SpinLockRelease(g_sysv_lock, lock_flags);
    }

    // First 8 bytes of user_msg are the mtype (long).
    i64 mtype = 0;
    if (!mm::CopyFromUser(&mtype, reinterpret_cast<const void*>(user_msg), sizeof(mtype)))
        return -14; // -EFAULT
    if (mtype <= 0)
        return -22;
    SysvMsg stage;
    stage.mtype = mtype;
    stage.len = static_cast<u32>(msgsz);
    if (msgsz > 0)
    {
        if (!mm::CopyFromUser(stage.body, reinterpret_cast<const void*>(user_msg + sizeof(i64)), msgsz))
            return -14;
    }

    while (true)
    {
        auto lock_flags = sync::SpinLockAcquire(g_sysv_lock);
        if (!q.in_use || q.marked_destroy || q.closing || q.incarnation != expected_incarnation)
        {
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return kEIDRM;
        }
        if (q.count != kMqMsgsPerQueue)
        {
            q.ring[q.head] = stage;
            q.head = (q.head + 1) % kMqMsgsPerQueue;
            ++q.count;
            WaitSequencePublishLocked(&q.wait_sequence);
            // Receivers have heterogeneous mtype predicates. Waking only the
            // FIFO head can strand the matching receiver indefinitely now
            // that the old periodic poll is gone.
            sched::WaitQueueWakeAll(&q.read_wq);
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return 0;
        }
        if (nowait)
        {
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return -11; // -EAGAIN
        }
        sched::WaitQueue* wq = &q.write_wq;
        const u64 observed_sequence = WaitSequenceSnapshotLocked(&q.wait_sequence);
        sync::SpinLockRelease(g_sysv_lock, lock_flags);
        if (!WaitForSequenceChangeCancellable(wq, &q.wait_sequence, observed_sequence))
        {
            // RMID wins over cancellation when both became visible while the
            // operation was blocked, matching Linux's EIDRM precedence.
            lock_flags = sync::SpinLockAcquire(g_sysv_lock);
            const bool removed = !q.in_use || q.marked_destroy || q.closing || q.incarnation != expected_incarnation;
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return removed ? kEIDRM : kEINTR;
        }
    }
}

i64 DoMsgrcv(u64 msqid, u64 user_msg, u64 msgsz, u64 mtype_filter, u64 msgflg)
{
    SysvIpcDecodedId decoded{};
    if (!SysvIpcDecodeId(msqid, SysvIpcIdFamily::MessageQueue, &decoded))
        return -22;
    if (msgsz > kMqMaxMsgBytes)
        return -22;
    const u32 idx = decoded.index;
    const bool nowait = (msgflg & kIpcNowait) != 0;
    const i64 filter = static_cast<i64>(mtype_filter);

    SysvMq& q = g_sysv_pool[idx];
    const u64 expected_incarnation = decoded.generation;
    {
        auto lock_flags = sync::SpinLockAcquire(g_sysv_lock);
        if (!q.in_use || q.initializing || q.marked_destroy || q.closing || q.incarnation != expected_incarnation)
        {
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return -22;
        }
        sync::SpinLockRelease(g_sysv_lock, lock_flags);
    }
    SysvMsg out;
    while (true)
    {
        auto lock_flags = sync::SpinLockAcquire(g_sysv_lock);
        if (!q.in_use || q.marked_destroy || q.closing || q.incarnation != expected_incarnation)
        {
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return kEIDRM;
        }
        const i32 hit = SysvFindByMtype(q, filter);
        if (hit >= 0)
        {
            out = q.ring[hit];
            SysvDrainAt(q, static_cast<u32>(hit));
            WaitSequencePublishLocked(&q.wait_sequence);
            sched::WaitQueueWakeOne(&q.write_wq);
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            break;
        }
        if (nowait)
        {
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return -42; // -ENOMSG
        }
        sched::WaitQueue* wq = &q.read_wq;
        const u64 observed_sequence = WaitSequenceSnapshotLocked(&q.wait_sequence);
        sync::SpinLockRelease(g_sysv_lock, lock_flags);
        if (!WaitForSequenceChangeCancellable(wq, &q.wait_sequence, observed_sequence))
        {
            lock_flags = sync::SpinLockAcquire(g_sysv_lock);
            const bool removed = !q.in_use || q.marked_destroy || q.closing || q.incarnation != expected_incarnation;
            sync::SpinLockRelease(g_sysv_lock, lock_flags);
            return removed ? kEIDRM : kEINTR;
        }
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_msg), &out.mtype, sizeof(out.mtype)))
        return -14;
    const u64 to_copy = (out.len < msgsz) ? out.len : msgsz;
    if (to_copy > 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_msg + sizeof(i64)), out.body, to_copy))
            return -14;
    }
    return static_cast<i64>(to_copy);
}

i64 DoMsgctl(u64 msqid, u64 cmd, u64 user_buf)
{
    (void)user_buf;
    SysvIpcDecodedId decoded{};
    if (!SysvIpcDecodeId(msqid, SysvIpcIdFamily::MessageQueue, &decoded))
        return -22;
    const u32 idx = decoded.index;
    auto lock_flags = sync::SpinLockAcquire(g_sysv_lock);
    SysvMq& q = g_sysv_pool[idx];
    if (!q.in_use || q.initializing || q.incarnation != decoded.generation)
    {
        sync::SpinLockRelease(g_sysv_lock, lock_flags);
        return -22;
    }
    if (cmd == kIpcRmid)
    {
        q.marked_destroy = true;
        SysvMsg* ring = q.ring;
        q.closing = true;
        q.in_use = false;
        q.count = 0;
        WaitSequencePublishLocked(&q.wait_sequence);
        sched::WaitQueueWakeAll(&q.read_wq);
        sched::WaitQueueWakeAll(&q.write_wq);
        if (q.pins == 0)
        {
            q.ring = nullptr;
            q.closing = false;
        }
        else
        {
            ring = nullptr;
        }
        sync::SpinLockRelease(g_sysv_lock, lock_flags);
        if (ring != nullptr)
            mm::KFree(ring);
        return 0;
    }
    if (cmd == kIpcStat)
    {
        sync::SpinLockRelease(g_sysv_lock, lock_flags);
        return 0; // msqid_ds copy-out deferred (sub-GAP)
    }
    sync::SpinLockRelease(g_sysv_lock, lock_flags);
    return -22;
}

// =========================================================
// POSIX MQ — mq_open / mq_unlink / mq_timedsend / mq_timedreceive
// =========================================================

namespace
{

// abs_timeout in mq_timedsend / mq_timedreceive is a struct timespec
// {tv_sec; tv_nsec} interpreted on CLOCK_REALTIME. v0's clock is
// boot-relative (no RTC integration yet — see syscall_time.cpp), so
// the absolute timestamp is treated as "ns-since-boot". A NULL
// pointer means "block forever" (the same shape mq_send / mq_receive
// expose to userland). A timestamp already in the past means
// non-blocking — return -ETIMEDOUT immediately if the queue can't
// service the request.
//
// Returns:
//   true  → out_deadline_ticks valid (or zero if user_timeout == 0,
//           meaning "no deadline; block forever").
//   false → invalid timespec (negative or out-of-range nsec).
constexpr i64 kETimedOut = -110;

// Convert a user-pointed `struct timespec` (or NULL) into an
// absolute scheduler-tick deadline. Caller treats deadline == 0 as
// "no deadline; block indefinitely".
bool LoadDeadline(u64 user_timeout, u64& out_deadline_ticks, bool& out_no_deadline)
{
    out_deadline_ticks = 0;
    out_no_deadline = (user_timeout == 0);
    if (out_no_deadline)
        return true;

    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } ts;
    if (!mm::CopyFromUser(&ts, reinterpret_cast<const void*>(user_timeout), sizeof(ts)))
        return false;
    if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1'000'000'000)
        return false;

    constexpr u64 kMax = static_cast<u64>(-1);
    const u64 sec = static_cast<u64>(ts.tv_sec);
    const u64 nsec = static_cast<u64>(ts.tv_nsec);
    if (sec > (kMax - nsec) / 1'000'000'000ull)
        return false;
    const u64 abs_ns = sec * 1'000'000'000ull + nsec;
    const u64 period_ns = ::duetos::time::TickPeriodNs();
    if (period_ns == 0)
        return false;
    // Round up so a sub-tick deadline doesn't immediately fire.
    out_deadline_ticks = abs_ns > kMax - (period_ns - 1) ? kMax / period_ns : (abs_ns + (period_ns - 1)) / period_ns;
    return true;
}

// Sequence-linearized block honoring an absolute deadline. The scheduler APIs
// own interrupt save/restore. Returns 0 to re-check, -EINTR only for explicit
// cancellation, or -ETIMEDOUT once the caller's deadline is actually reached.
// Saturation uses a one-tick retry without exposing that internal poll as a
// user-visible timeout.
i64 WaitWithDeadline(::duetos::sched::WaitQueue* wq, const u64* sequence, u64 observed_sequence, u64 deadline_ticks,
                     bool no_deadline)
{
    if (no_deadline)
        return WaitForSequenceChangeCancellable(wq, sequence, observed_sequence) ? 0 : kEINTR;

    const u64 now = ::duetos::sched::SchedNowTicks();
    // Even an already-expired deadline goes through the scheduler bridge with
    // zero ticks so cancellation and a concurrent sequence publication retain
    // their documented precedence over TimedOut.
    u64 wait_ticks = now >= deadline_ticks ? 0 : deadline_ticks - now;
    if (observed_sequence == ~u64{0} && wait_ticks > 1)
        wait_ticks = 1;
    const sched::WaitQueueBlockResult result =
        sched::WaitQueueBlockIfSequenceUnchangedTimeoutCancellable(wq, sequence, observed_sequence, wait_ticks);
    if (result == sched::WaitQueueBlockResult::Cancelled)
        return kEINTR;
    if (result == sched::WaitQueueBlockResult::TimedOut &&
        !(observed_sequence == ~u64{0} && ::duetos::sched::SchedNowTicks() < deadline_ticks))
        return kETimedOut;
    return 0;
}

} // namespace

namespace
{

bool PosixMqNameEqual(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

i32 PosixMqFindByName(const char* name)
{
    for (u32 i = 0; i < kPosixMqPoolCap; ++i)
        if (g_posix_pool[i].in_use && !g_posix_pool[i].initializing && PosixMqNameEqual(g_posix_pool[i].name, name))
            return static_cast<i32>(i);
    return -1;
}

i32 PosixMqAlloc(const char* name, u32 max_msgs, u32 max_bytes)
{
    if (max_msgs == 0 || max_msgs > kMqMsgsPerQueue)
        max_msgs = kMqMsgsPerQueue;
    if (max_bytes == 0 || max_bytes > kMqMaxMsgBytes)
        max_bytes = kMqMaxMsgBytes;
    auto flags = sync::SpinLockAcquire(g_posix_lock);
    for (u32 i = 0; i < kPosixMqPoolCap; ++i)
    {
        if (g_posix_pool[i].in_use || g_posix_pool[i].closing)
            continue;
        PosixMq& q = g_posix_pool[i];
        q.in_use = true;
        q.initializing = true;
        q.closing = false;
        q.refs = 1;
        q.pins = 0;
        q.max_msgs = max_msgs;
        q.max_msg_bytes = max_bytes;
        q.count = 0;
        for (u32 j = 0; j < kPosixMqNameCap; ++j)
            q.name[j] = 0;
        for (u32 j = 0; j < kPosixMqNameCap - 1 && name[j] != '\0'; ++j)
            q.name[j] = name[j];
        q.read_wq.head = nullptr;
        q.read_wq.tail = nullptr;
        q.write_wq.head = nullptr;
        q.write_wq.tail = nullptr;
        q.ring = nullptr;
        WaitSequencePublishLocked(&q.wait_sequence);
        sync::SpinLockRelease(g_posix_lock, flags);
        q.ring = static_cast<PosixMsg*>(mm::KMalloc(sizeof(PosixMsg) * max_msgs));
        if (q.ring == nullptr)
        {
            flags = sync::SpinLockAcquire(g_posix_lock);
            q.in_use = false;
            q.initializing = false;
            WaitSequencePublishLocked(&q.wait_sequence);
            sync::SpinLockRelease(g_posix_lock, flags);
            return -1;
        }
        flags = sync::SpinLockAcquire(g_posix_lock);
        q.initializing = false;
        WaitSequencePublishLocked(&q.wait_sequence);
        sync::SpinLockRelease(g_posix_lock, flags);
        return static_cast<i32>(i);
    }
    sync::SpinLockRelease(g_posix_lock, flags);
    return -1;
}

} // namespace

void PosixMqRetain(u32 idx)
{
    if (idx >= kPosixMqPoolCap)
        return;
    sync::SpinLockGuard guard(g_posix_lock);
    if (g_posix_pool[idx].in_use && !g_posix_pool[idx].closing)
        ++g_posix_pool[idx].refs;
}

void PosixMqRelease(u32 idx)
{
    if (idx >= kPosixMqPoolCap)
        return;
    auto flags = sync::SpinLockAcquire(g_posix_lock);
    PosixMq& q = g_posix_pool[idx];
    if (!q.in_use || q.refs == 0)
    {
        sync::SpinLockRelease(g_posix_lock, flags);
        return;
    }
    --q.refs;
    PosixMsg* ring = nullptr;
    // mq_unlink + last-handle-close together free the ring.
    if (q.refs == 0 && q.name[0] == '\0')
    {
        q.closing = true;
        q.in_use = false;
        WaitSequencePublishLocked(&q.wait_sequence);
        sched::WaitQueueWakeAll(&q.read_wq);
        sched::WaitQueueWakeAll(&q.write_wq);
        if (q.pins == 0)
        {
            ring = q.ring;
            q.ring = nullptr;
            q.closing = false;
            q.count = 0;
        }
    }
    sync::SpinLockRelease(g_posix_lock, flags);
    if (ring != nullptr)
        mm::KFree(ring);
}

i64 DoMqOpen(u64 user_name, u64 oflag, u64 mode, u64 user_attr)
{
    (void)mode;
    (void)user_attr;
    constexpr u64 kOCreat = 0x40;
    constexpr u64 kOExcl = 0x80;
    constexpr u64 kOCloexec = 0x80000;
    char name[kPosixMqNameCap];
    const auto copy = mm::CopyUserCString(name, sizeof(name), reinterpret_cast<const void*>(user_name));
    if (copy.status == mm::UserStringCopyStatus::Fault || copy.status == mm::UserStringCopyStatus::BadArgument)
        return kEFAULT;
    if (copy.status == mm::UserStringCopyStatus::NoTerminator)
        return kENAMETOOLONG;
    if (name[0] != '/')
        return -22;

    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return -1;

    i32 idx = -1;
    {
        sync::SpinLockGuard guard(g_posix_lock);
        const i32 existing = PosixMqFindByName(name);
        if (existing >= 0)
        {
            if ((oflag & (kOCreat | kOExcl)) == (kOCreat | kOExcl))
                return -17; // -EEXIST
            ++g_posix_pool[static_cast<u32>(existing)].refs;
            idx = existing;
        }
    }
    if (idx < 0)
    {
        if ((oflag & kOCreat) == 0)
            return -2; // -ENOENT
        // attr: { mq_flags, mq_maxmsg, mq_msgsize, mq_curmsgs }
        u64 attr_max_msgs = kMqMsgsPerQueue;
        u64 attr_max_bytes = kMqMaxMsgBytes;
        if (user_attr != 0)
        {
            u64 attr[4];
            if (mm::CopyFromUser(attr, reinterpret_cast<const void*>(user_attr), sizeof(attr)))
            {
                attr_max_msgs = attr[1];
                attr_max_bytes = attr[2];
            }
        }
        idx = PosixMqAlloc(name, static_cast<u32>(attr_max_msgs), static_cast<u32>(attr_max_bytes));
        if (idx < 0)
            return -28;
    }

    auto kfile_result = ipc::KFileCreate(ipc::KFileKind::PosixMq, static_cast<u32>(idx), &PosixMqRelease, nullptr, 0);
    if (!kfile_result.has_value())
    {
        PosixMqRelease(static_cast<u32>(idx));
        return -12; // -ENOMEM
    }

    core::Process::LinuxFd payload{};
    payload.state = 13;
    payload.first_cluster = static_cast<u32>(idx);
    core::LinuxFdPrepared prepared{};
    if (!core::LinuxFdPrepare(&prepared, payload, &kfile_result.value()->base, static_cast<u32>(oflag)))
    {
        ipc::KObjectRelease(&kfile_result.value()->base);
        return kENFILE;
    }
    const i32 fd = core::LinuxFdBindLowest(p, 3, &prepared, (oflag & kOCloexec) != 0);
    if (fd < 0)
    {
        core::LinuxFdPreparedRelease(&prepared);
        return kEMFILE;
    }
    arch::SerialWrite("[linux/posixmq] open fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite(" name=\"");
    arch::SerialWrite(name);
    arch::SerialWrite("\"\n");
    return static_cast<i64>(fd);
}

i64 DoMqUnlink(u64 user_name)
{
    char name[kPosixMqNameCap];
    const auto copy = mm::CopyUserCString(name, sizeof(name), reinterpret_cast<const void*>(user_name));
    if (copy.status == mm::UserStringCopyStatus::Fault || copy.status == mm::UserStringCopyStatus::BadArgument)
        return kEFAULT;
    if (copy.status == mm::UserStringCopyStatus::NoTerminator)
        return kENAMETOOLONG;
    auto lock_flags = sync::SpinLockAcquire(g_posix_lock);
    const i32 idx = PosixMqFindByName(name);
    if (idx < 0)
    {
        sync::SpinLockRelease(g_posix_lock, lock_flags);
        return -2;
    }
    PosixMq& q = g_posix_pool[idx];
    // Mark the slot as anonymous so future mq_open(name) gets ENOENT.
    // Holders of the fd see in_use stay true via refcount.
    q.name[0] = '\0';
    if (q.refs == 0)
    {
        // No live fd holders — free immediately.
        PosixMsg* ring = q.ring;
        q.closing = true;
        q.in_use = false;
        if (q.pins != 0)
        {
            sync::SpinLockRelease(g_posix_lock, lock_flags);
            return 0;
        }
        q.ring = nullptr;
        q.count = 0;
        WaitSequencePublishLocked(&q.wait_sequence);
        sched::WaitQueueWakeAll(&q.read_wq);
        sched::WaitQueueWakeAll(&q.write_wq);
        sync::SpinLockRelease(g_posix_lock, lock_flags);
        if (ring != nullptr)
            mm::KFree(ring);
        return 0;
    }
    sync::SpinLockRelease(g_posix_lock, lock_flags);
    return 0;
}

i64 DoMqTimedsend(u64 mqdes, u64 user_msg, u64 msg_len, u64 prio, u64 user_timeout)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || mqdes >= 16)
        return -9; // -EBADF
    // Spectre v1 nospec — mask before passing the numeric index into
    // the retained fd-table lookup.
    mqdes = ::duetos::util::MaskedIndex(mqdes, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(mqdes), 13, &acquired))
        return -9;
    // Keep the exact KFile receipt alive across every wait. It prevents the
    // POSIX queue slot from retiring without carrying a subsystem pin or lock
    // through the scheduler boundary.
    LinuxFdAcquiredGuard acquired_guard{&acquired};
    const u32 idx = acquired.snapshot.first_cluster;
    if (idx >= kPosixMqPoolCap)
        return -22;
    PosixMq& q = g_posix_pool[idx];
    {
        auto lock_flags = sync::SpinLockAcquire(g_posix_lock);
        if (!q.in_use || q.initializing || q.closing)
        {
            sync::SpinLockRelease(g_posix_lock, lock_flags);
            return -9;
        }
        const u32 max_msg_bytes = q.max_msg_bytes;
        sync::SpinLockRelease(g_posix_lock, lock_flags);
        if (msg_len > max_msg_bytes)
            return -90; // -EMSGSIZE
    }
    u64 deadline_ticks = 0;
    bool no_deadline = true;
    if (!LoadDeadline(user_timeout, deadline_ticks, no_deadline))
        return -22; // -EINVAL
    PosixMsg stage;
    stage.prio = static_cast<u32>(prio);
    stage.len = static_cast<u32>(msg_len);
    if (msg_len > 0)
    {
        if (!mm::CopyFromUser(stage.body, reinterpret_cast<const void*>(user_msg), msg_len))
            return -14;
    }
    while (true)
    {
        auto lock_flags = sync::SpinLockAcquire(g_posix_lock);
        if (!q.in_use || q.closing)
        {
            sync::SpinLockRelease(g_posix_lock, lock_flags);
            return -9;
        }
        if (q.count != q.max_msgs)
        {
            q.ring[q.count] = stage;
            ++q.count;
            WaitSequencePublishLocked(&q.wait_sequence);
            sched::WaitQueueWakeOne(&q.read_wq);
            sync::SpinLockRelease(g_posix_lock, lock_flags);
            return 0;
        }
        sched::WaitQueue* wq = &q.write_wq;
        const u64 observed_sequence = WaitSequenceSnapshotLocked(&q.wait_sequence);
        sync::SpinLockRelease(g_posix_lock, lock_flags);
        const i64 wait_rv = WaitWithDeadline(wq, &q.wait_sequence, observed_sequence, deadline_ticks, no_deadline);
        if (wait_rv != 0)
            return wait_rv;
    }
}

i64 DoMqTimedreceive(u64 mqdes, u64 user_msg, u64 msg_cap, u64 user_prio, u64 user_timeout)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || mqdes >= 16)
        return -9;
    // Spectre v1 nospec — mask before dereference (see DoMqTimedsend).
    mqdes = ::duetos::util::MaskedIndex(mqdes, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(mqdes), 13, &acquired))
        return -9;
    // Same exact-receipt lifetime contract as the send path.
    LinuxFdAcquiredGuard acquired_guard{&acquired};
    const u32 idx = acquired.snapshot.first_cluster;
    if (idx >= kPosixMqPoolCap)
        return -22;
    PosixMq& q = g_posix_pool[idx];
    {
        auto lock_flags = sync::SpinLockAcquire(g_posix_lock);
        if (!q.in_use || q.initializing || q.closing)
        {
            sync::SpinLockRelease(g_posix_lock, lock_flags);
            return -9;
        }
        sync::SpinLockRelease(g_posix_lock, lock_flags);
    }
    u64 deadline_ticks = 0;
    bool no_deadline = true;
    if (!LoadDeadline(user_timeout, deadline_ticks, no_deadline))
        return -22;
    PosixMsg out;
    while (true)
    {
        auto lock_flags = sync::SpinLockAcquire(g_posix_lock);
        if (!q.in_use || q.closing)
        {
            sync::SpinLockRelease(g_posix_lock, lock_flags);
            return -9;
        }
        if (q.count != 0)
        {
            // Find highest-priority message.
            u32 best = 0;
            for (u32 i = 1; i < q.count; ++i)
                if (q.ring[i].prio > q.ring[best].prio)
                    best = i;
            out = q.ring[best];
            // Remove by shifting tail down.
            for (u32 i = best; i + 1 < q.count; ++i)
                q.ring[i] = q.ring[i + 1];
            --q.count;
            WaitSequencePublishLocked(&q.wait_sequence);
            sched::WaitQueueWakeOne(&q.write_wq);
            sync::SpinLockRelease(g_posix_lock, lock_flags);
            break;
        }
        sched::WaitQueue* wq = &q.read_wq;
        const u64 observed_sequence = WaitSequenceSnapshotLocked(&q.wait_sequence);
        sync::SpinLockRelease(g_posix_lock, lock_flags);
        const i64 wait_rv = WaitWithDeadline(wq, &q.wait_sequence, observed_sequence, deadline_ticks, no_deadline);
        if (wait_rv != 0)
            return wait_rv;
    }
    if (msg_cap < out.len)
        return -90; // -EMSGSIZE
    if (out.len > 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_msg), out.body, out.len))
            return -14;
    }
    if (user_prio != 0)
    {
        const u32 prio = out.prio;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_prio), &prio, sizeof(prio)))
            return -14;
    }
    return static_cast<i64>(out.len);
}

// mq_notify(mqdes, sevp) — request asynchronous notification
// when the queue transitions empty -> non-empty. NULL sevp =
// deregister. v0 accepts the request (validates the fd
// references a real mqd) but does NOT actually fire the
// signal on the next mq_send; that delivery path is a sub-
// GAP because the per-mqd notification record isn't tracked
// across processes. Real Linux behaviour for "register" is
// success; deregister is also success. Bad fd is -EBADF.
i64 DoMqNotify(u64 mqdes, u64 user_notification)
{
    (void)user_notification;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || mqdes >= 16)
        return kEBADF;
    // Spectre v1 nospec — mask before dereference (see DoMqTimedsend).
    mqdes = ::duetos::util::MaskedIndex(mqdes, 16);
    // mqd_t is an fd-table index. Retain and validate state 13 so a
    // concurrent close/reuse cannot redirect the check.
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(mqdes), 13, &acquired))
        return kEBADF;
    core::LinuxFdAcquiredRelease(&acquired);
    return 0;
}

i64 DoMqGetsetattr(u64 mqdes, u64 user_new, u64 user_old)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || mqdes >= 16)
        return -9;
    // Spectre v1 nospec — mask before dereference (see DoMqTimedsend).
    mqdes = ::duetos::util::MaskedIndex(mqdes, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(mqdes), 13, &acquired))
        return -9;
    const u32 idx = acquired.snapshot.first_cluster;
    if (idx >= kPosixMqPoolCap)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return -22;
    }
    PosixMqPin pin(idx);
    core::LinuxFdAcquiredRelease(&acquired);
    if (!pin)
        return -9;
    auto lock_flags = sync::SpinLockAcquire(g_posix_lock);
    PosixMq& q = *pin.queue;
    if (!q.in_use || q.closing)
    {
        sync::SpinLockRelease(g_posix_lock, lock_flags);
        return -9;
    }
    if (user_old != 0)
    {
        // struct mq_attr: { mq_flags; mq_maxmsg; mq_msgsize; mq_curmsgs; }
        u64 attr[4];
        attr[0] = 0;
        attr[1] = q.max_msgs;
        attr[2] = q.max_msg_bytes;
        attr[3] = q.count;
        sync::SpinLockRelease(g_posix_lock, lock_flags);
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), attr, sizeof(attr)))
            return -14;
    }
    else
    {
        sync::SpinLockRelease(g_posix_lock, lock_flags);
    }
    (void)user_new; // mq_flags writes (O_NONBLOCK toggle) — sub-GAP
    return 0;
}

} // namespace duetos::subsystems::linux::internal
