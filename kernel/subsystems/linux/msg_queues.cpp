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
 *     queues use msqid (= pool_idx + 1) directly as the descriptor,
 *     not a per-process fd.
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
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
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

constexpr u64 kIpcCreat = 0x200;
constexpr u64 kIpcExcl = 0x400;
constexpr u64 kIpcNowait = 0x800;
constexpr u64 kIpcRmid = 0;
constexpr u64 kIpcStat = 2;

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
    u8 _pad[2];
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
    u8 _pad[3];
    u32 refs;
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

// =========================================================
// SysV MQ helpers
// =========================================================

i32 SysvMqFindByKey(i32 key)
{
    if (key == 0)
        return -1;
    for (u32 i = 0; i < kSysvMqPoolCap; ++i)
        if (g_sysv_pool[i].in_use && !g_sysv_pool[i].marked_destroy && g_sysv_pool[i].key == key)
            return static_cast<i32>(i);
    return -1;
}

i32 SysvMqAlloc(i32 key)
{
    arch::Cli();
    for (u32 i = 0; i < kSysvMqPoolCap; ++i)
    {
        if (g_sysv_pool[i].in_use)
            continue;
        SysvMq& q = g_sysv_pool[i];
        q.in_use = true;
        q.marked_destroy = false;
        q.key = key;
        q.head = 0;
        q.tail = 0;
        q.count = 0;
        q.read_wq.head = nullptr;
        q.read_wq.tail = nullptr;
        q.write_wq.head = nullptr;
        q.write_wq.tail = nullptr;
        arch::Sti();
        q.ring = static_cast<SysvMsg*>(mm::KMalloc(sizeof(SysvMsg) * kMqMsgsPerQueue));
        if (q.ring == nullptr)
        {
            arch::Cli();
            q.in_use = false;
            arch::Sti();
            return -1;
        }
        return static_cast<i32>(i);
    }
    arch::Sti();
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
    for (u32 i = 0; i < q.count; ++i)
    {
        const u32 idx = (q.tail + i) % kMqMsgsPerQueue;
        const SysvMsg& m = q.ring[idx];
        if (mtype_filter > 0 && m.mtype == mtype_filter)
            return static_cast<i32>(idx);
        if (mtype_filter < 0 && m.mtype <= -mtype_filter)
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
    if (ikey != 0)
    {
        const i32 existing = SysvMqFindByKey(ikey);
        if (existing >= 0)
        {
            if (create && excl)
                return -17; // -EEXIST
            return existing + 1;
        }
        if (!create)
            return -2; // -ENOENT
    }
    const i32 idx = SysvMqAlloc(ikey);
    if (idx < 0)
        return -28; // -ENOSPC
    arch::SerialWrite("[linux/sysvmq] alloc idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite(" key=");
    arch::SerialWriteHex(static_cast<u64>(ikey));
    arch::SerialWrite("\n");
    return idx + 1;
}

i64 DoMsgsnd(u64 msqid, u64 user_msg, u64 msgsz, u64 msgflg)
{
    if (msqid == 0 || msqid > kSysvMqPoolCap)
        return -22; // -EINVAL
    if (msgsz > kMqMaxMsgBytes)
        return -22;
    const u32 idx = static_cast<u32>(msqid - 1);
    const bool nowait = (msgflg & kIpcNowait) != 0;

    // First 8 bytes of user_msg are the mtype (long).
    i64 mtype = 0;
    if (!mm::CopyFromUser(&mtype, reinterpret_cast<const void*>(user_msg), sizeof(mtype)))
        return -14; // -EFAULT
    if (mtype <= 0)
        return -22;
    SysvMq& q = g_sysv_pool[idx];
    arch::Cli();
    while (q.in_use && !q.marked_destroy && q.count == kMqMsgsPerQueue)
    {
        if (nowait)
        {
            arch::Sti();
            return -11; // -EAGAIN
        }
        sched::WaitQueueBlock(&q.write_wq);
        arch::Cli();
    }
    if (!q.in_use || q.marked_destroy)
    {
        arch::Sti();
        return -22;
    }
    // Stage outside Cli/Sti.
    SysvMsg stage;
    stage.mtype = mtype;
    stage.len = static_cast<u32>(msgsz);
    arch::Sti();
    if (msgsz > 0)
    {
        if (!mm::CopyFromUser(stage.body, reinterpret_cast<const void*>(user_msg + sizeof(i64)), msgsz))
            return -14;
    }
    arch::Cli();
    if (!q.in_use || q.marked_destroy)
    {
        arch::Sti();
        return -22;
    }
    q.ring[q.head] = stage;
    q.head = (q.head + 1) % kMqMsgsPerQueue;
    ++q.count;
    sched::WaitQueueWakeOne(&q.read_wq);
    arch::Sti();
    return 0;
}

i64 DoMsgrcv(u64 msqid, u64 user_msg, u64 msgsz, u64 mtype_filter, u64 msgflg)
{
    if (msqid == 0 || msqid > kSysvMqPoolCap)
        return -22;
    if (msgsz > kMqMaxMsgBytes)
        return -22;
    const u32 idx = static_cast<u32>(msqid - 1);
    const bool nowait = (msgflg & kIpcNowait) != 0;
    const i64 filter = static_cast<i64>(mtype_filter);

    SysvMq& q = g_sysv_pool[idx];
    SysvMsg out;
    arch::Cli();
    i32 hit = -1;
    while (q.in_use && !q.marked_destroy && (hit = SysvFindByMtype(q, filter)) < 0)
    {
        if (nowait)
        {
            arch::Sti();
            return -42; // -ENOMSG
        }
        sched::WaitQueueBlock(&q.read_wq);
        arch::Cli();
    }
    if (!q.in_use || q.marked_destroy)
    {
        arch::Sti();
        return -22;
    }
    out = q.ring[hit];
    SysvDrainAt(q, static_cast<u32>(hit));
    sched::WaitQueueWakeOne(&q.write_wq);
    arch::Sti();
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
    if (msqid == 0 || msqid > kSysvMqPoolCap)
        return -22;
    const u32 idx = static_cast<u32>(msqid - 1);
    arch::Cli();
    SysvMq& q = g_sysv_pool[idx];
    if (!q.in_use)
    {
        arch::Sti();
        return -22;
    }
    if (cmd == kIpcRmid)
    {
        q.marked_destroy = true;
        SysvMsg* ring = q.ring;
        sched::WaitQueueWakeAll(&q.read_wq);
        sched::WaitQueueWakeAll(&q.write_wq);
        q.in_use = false;
        q.ring = nullptr;
        q.count = 0;
        arch::Sti();
        if (ring != nullptr)
            mm::KFree(ring);
        return 0;
    }
    if (cmd == kIpcStat)
    {
        arch::Sti();
        return 0; // msqid_ds copy-out deferred (sub-GAP)
    }
    arch::Sti();
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

    const u64 abs_ns = static_cast<u64>(ts.tv_sec) * 1'000'000'000ull + static_cast<u64>(ts.tv_nsec);
    const u64 period_ns = ::duetos::time::TickPeriodNs();
    if (period_ns == 0)
        return false;
    // Round up so a sub-tick deadline doesn't immediately fire.
    out_deadline_ticks = (abs_ns + (period_ns - 1)) / period_ns;
    return true;
}

// Block on `wq` honoring `deadline_ticks` (absolute). Returns:
//   0  → woken (the surrounding loop re-checks the condition),
//  -ETIMEDOUT → deadline reached.
// Caller MUST hold IRQs disabled (arch::Cli) on entry; this helper
// takes care of the wait. On return IRQs are also disabled — the
// caller's outer loop expects to re-test under Cli().
i64 WaitWithDeadline(::duetos::sched::WaitQueue* wq, u64 deadline_ticks, bool no_deadline)
{
    if (no_deadline)
    {
        ::duetos::sched::WaitQueueBlock(wq);
        ::duetos::arch::Cli();
        return 0;
    }
    const u64 now = ::duetos::sched::SchedNowTicks();
    if (now >= deadline_ticks)
    {
        ::duetos::arch::Sti();
        return kETimedOut;
    }
    const u64 wait = deadline_ticks - now;
    const bool woken = ::duetos::sched::WaitQueueBlockTimeout(wq, wait);
    ::duetos::arch::Cli();
    if (!woken)
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
        if (g_posix_pool[i].in_use && PosixMqNameEqual(g_posix_pool[i].name, name))
            return static_cast<i32>(i);
    return -1;
}

i32 PosixMqAlloc(const char* name, u32 max_msgs, u32 max_bytes)
{
    if (max_msgs == 0 || max_msgs > kMqMsgsPerQueue)
        max_msgs = kMqMsgsPerQueue;
    if (max_bytes == 0 || max_bytes > kMqMaxMsgBytes)
        max_bytes = kMqMaxMsgBytes;
    arch::Cli();
    for (u32 i = 0; i < kPosixMqPoolCap; ++i)
    {
        if (g_posix_pool[i].in_use)
            continue;
        PosixMq& q = g_posix_pool[i];
        q.in_use = true;
        q.refs = 1;
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
        arch::Sti();
        q.ring = static_cast<PosixMsg*>(mm::KMalloc(sizeof(PosixMsg) * max_msgs));
        if (q.ring == nullptr)
        {
            arch::Cli();
            q.in_use = false;
            arch::Sti();
            return -1;
        }
        return static_cast<i32>(i);
    }
    arch::Sti();
    return -1;
}

} // namespace

void PosixMqRetain(u32 idx)
{
    if (idx >= kPosixMqPoolCap)
        return;
    arch::Cli();
    if (g_posix_pool[idx].in_use)
        ++g_posix_pool[idx].refs;
    arch::Sti();
}

void PosixMqRelease(u32 idx)
{
    if (idx >= kPosixMqPoolCap)
        return;
    arch::Cli();
    PosixMq& q = g_posix_pool[idx];
    if (!q.in_use || q.refs == 0)
    {
        arch::Sti();
        return;
    }
    --q.refs;
    // mq_unlink + last-handle-close together free the ring.
    arch::Sti();
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
    const i32 fd = core::LinuxFdAllocLowest(p, 3);
    if (fd < 0)
        return -24; // -EMFILE

    const i32 existing = PosixMqFindByName(name);
    i32 idx = existing;
    if (existing >= 0)
    {
        if ((oflag & (kOCreat | kOExcl)) == (kOCreat | kOExcl))
            return -17; // -EEXIST
        PosixMqRetain(static_cast<u32>(existing));
    }
    else
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
    p->linux_fds[fd].state = 13;
    p->linux_fds[fd].flags = 0;
    p->linux_fds[fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    p->linux_fds[fd].path[0] = '\0';
    if (!core::LinuxFdAttachKFile(p, static_cast<u32>(fd), /*kind=*/13, static_cast<u32>(idx), &PosixMqRelease))
    {
        p->linux_fds[fd].state = 0;
        PosixMqRelease(static_cast<u32>(idx));
        return -12; // -ENOMEM
    }
    if ((oflag & kOCloexec) != 0)
        core::LinuxFdSetCloexec(p, static_cast<u32>(fd), true);
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
    arch::Cli();
    const i32 idx = PosixMqFindByName(name);
    if (idx < 0)
    {
        arch::Sti();
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
        q.in_use = false;
        q.ring = nullptr;
        q.count = 0;
        sched::WaitQueueWakeAll(&q.read_wq);
        sched::WaitQueueWakeAll(&q.write_wq);
        arch::Sti();
        if (ring != nullptr)
            mm::KFree(ring);
        return 0;
    }
    arch::Sti();
    return 0;
}

i64 DoMqTimedsend(u64 mqdes, u64 user_msg, u64 msg_len, u64 prio, u64 user_timeout)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || mqdes >= 16)
        return -9; // -EBADF
    // Spectre v1 nospec — mask the index BEFORE the linux_fds[]
    // dereference so a mispredicted bounds branch can't speculate
    // an OOB load. See syscall_io.cpp DoWrite for class N rationale.
    mqdes = ::duetos::util::MaskedIndex(mqdes, 16);
    if (p->linux_fds[mqdes].state != 13)
        return -9;
    const u32 idx = p->linux_fds[mqdes].first_cluster;
    if (idx >= kPosixMqPoolCap)
        return -22;
    PosixMq& q = g_posix_pool[idx];
    if (msg_len > q.max_msg_bytes)
        return -90; // -EMSGSIZE
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
    arch::Cli();
    while (q.in_use && q.count == q.max_msgs)
    {
        const i64 wait_rv = WaitWithDeadline(&q.write_wq, deadline_ticks, no_deadline);
        if (wait_rv != 0)
            return wait_rv; // -ETIMEDOUT (IRQs already re-enabled)
    }
    if (!q.in_use)
    {
        arch::Sti();
        return -9;
    }
    q.ring[q.count] = stage;
    ++q.count;
    sched::WaitQueueWakeOne(&q.read_wq);
    arch::Sti();
    return 0;
}

i64 DoMqTimedreceive(u64 mqdes, u64 user_msg, u64 msg_cap, u64 user_prio, u64 user_timeout)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || mqdes >= 16)
        return -9;
    // Spectre v1 nospec — mask before dereference (see DoMqTimedsend).
    mqdes = ::duetos::util::MaskedIndex(mqdes, 16);
    if (p->linux_fds[mqdes].state != 13)
        return -9;
    const u32 idx = p->linux_fds[mqdes].first_cluster;
    if (idx >= kPosixMqPoolCap)
        return -22;
    PosixMq& q = g_posix_pool[idx];
    u64 deadline_ticks = 0;
    bool no_deadline = true;
    if (!LoadDeadline(user_timeout, deadline_ticks, no_deadline))
        return -22;
    PosixMsg out;
    arch::Cli();
    while (q.in_use && q.count == 0)
    {
        const i64 wait_rv = WaitWithDeadline(&q.read_wq, deadline_ticks, no_deadline);
        if (wait_rv != 0)
            return wait_rv;
    }
    if (!q.in_use)
    {
        arch::Sti();
        return -9;
    }
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
    sched::WaitQueueWakeOne(&q.write_wq);
    arch::Sti();
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
    // mqd_t is just an fd in the linux_fds table; mq state ==
    // 13 (see DoMqOpen). Reject if the fd doesn't reference
    // a message queue.
    if (p->linux_fds[mqdes].state != 13)
        return kEBADF;
    return 0;
}

i64 DoMqGetsetattr(u64 mqdes, u64 user_new, u64 user_old)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || mqdes >= 16)
        return -9;
    // Spectre v1 nospec — mask before dereference (see DoMqTimedsend).
    mqdes = ::duetos::util::MaskedIndex(mqdes, 16);
    if (p->linux_fds[mqdes].state != 13)
        return -9;
    const u32 idx = p->linux_fds[mqdes].first_cluster;
    if (idx >= kPosixMqPoolCap)
        return -22;
    PosixMq& q = g_posix_pool[idx];
    if (!q.in_use)
        return -9;
    if (user_old != 0)
    {
        // struct mq_attr: { mq_flags; mq_maxmsg; mq_msgsize; mq_curmsgs; }
        u64 attr[4];
        attr[0] = 0;
        attr[1] = q.max_msgs;
        attr[2] = q.max_msg_bytes;
        attr[3] = q.count;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_old), attr, sizeof(attr)))
            return -14;
    }
    (void)user_new; // mq_flags writes (O_NONBLOCK toggle) — sub-GAP
    return 0;
}

} // namespace duetos::subsystems::linux::internal
