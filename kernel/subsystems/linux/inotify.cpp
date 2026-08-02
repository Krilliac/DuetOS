/*
 * Linux inotify(7) v0 engine. Sibling TU of syscall.cpp.
 *
 * Wired in:
 *   - syscall.cpp dispatch table flips the inotify_init / init1 /
 *     add_watch / rm_watch calls to InotifyInit / InotifyInit1 /
 *     DoInotifyAddWatch / DoInotifyRmWatch in this TU.
 *   - syscall_io.cpp's DoRead state==10 arm calls InotifyRead.
 *   - syscall_file.cpp's DoClose state==10 arm calls InotifyRelease.
 *   - syscall_clone.cpp's DoFork state==10 arm calls InotifyRetain.
 *   - file_route.cpp's CreateForProcess / UnlinkForProcess /
 *     RenameForProcess publish IN_CREATE / IN_DELETE / IN_MOVED_*
 *     events via InotifyPublish.
 */

#include "subsystems/linux/inotify.h"
#include "subsystems/linux/fanotify.h"
#include "subsystems/linux/syscall_internal.h"
#include "subsystems/win32/dir_syscall.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "ipc/kfile.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/nospec.h"

namespace duetos::subsystems::linux::internal
{

void LinuxPollEventWake();

namespace
{

constexpr u32 kInotifyPoolCap = 8;
constexpr u32 kInotifyWatchCap = 16;
constexpr u32 kInotifyRingCap = 32;
constexpr u32 kInotifyPathCap = 64;

// struct inotify_event — Linux-stable layout. Header is 16 bytes;
// name follows (NUL-terminated, padded to 4-byte multiple).
struct InotifyEvent
{
    i32 wd;
    u32 mask;
    u32 cookie;
    u32 name_len; // bytes including NUL + padding
    char name[kInotifyPathCap];
};

struct InotifyWatch
{
    bool in_use;
    u8 _pad[3];
    i32 wd;
    u32 mask;
    char path[kInotifyPathCap];
};

struct InotifyInstance
{
    bool in_use;
    bool closing;
    u8 _pad[2];
    u32 refs;
    u32 pins;
    i32 next_wd;
    u32 _pad2;
    InotifyWatch watches[kInotifyWatchCap];
    InotifyEvent ring[kInotifyRingCap];
    u32 head;
    u32 tail;
    u32 count;
    u32 _pad3;
    u64 generation;
    u64 read_sequence;
    sched::WaitQueue read_wq;
};

InotifyInstance g_inotify_pool[kInotifyPoolCap];
constinit sync::SpinLock g_inotify_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};

struct InotifyPin
{
    u32 idx;
    u64 generation;
    InotifyInstance* instance;

    explicit InotifyPin(u32 value, u64 expected_generation = 0) : idx(value), generation(0), instance(nullptr)
    {
        if (value >= kInotifyPoolCap)
            return;
        sync::SpinLockGuard guard(g_inotify_lock);
        InotifyInstance& inst = g_inotify_pool[value];
        if (inst.in_use && !inst.closing && inst.pins != ~0U &&
            (expected_generation == 0 || inst.generation == expected_generation))
        {
            ++inst.pins;
            generation = inst.generation;
            instance = &inst;
        }
    }

    ~InotifyPin()
    {
        if (instance == nullptr)
            return;
        sync::SpinLockGuard guard(g_inotify_lock);
        InotifyInstance& inst = g_inotify_pool[idx];
        if (inst.pins > 0)
            --inst.pins;
        if (inst.pins == 0 && inst.refs == 0)
        {
            inst.in_use = false;
            inst.closing = false;
            inst.count = 0;
            inst.head = 0;
            inst.tail = 0;
        }
    }

    explicit operator bool() const { return instance != nullptr; }
};

bool PathEqual(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

void AdvanceReadSequenceLocked(InotifyInstance& inst)
{
    const u64 previous = __atomic_load_n(&inst.read_sequence, __ATOMIC_RELAXED);
    if (previous != ~u64{0})
        __atomic_store_n(&inst.read_sequence, previous + 1, __ATOMIC_RELEASE);
}

sched::WaitQueueBlockResult WaitForReadSequence(InotifyInstance& inst, u64 observed_sequence)
{
    if (observed_sequence == ~u64{0})
        return sched::WaitQueueBlockTimeoutCancellable(&inst.read_wq, 1);
    return sched::WaitQueueBlockIfSequenceUnchangedCancellable(&inst.read_wq, &inst.read_sequence, observed_sequence);
}

void WakeReadWaiters(InotifyInstance& inst)
{
    constexpr u64 kRflagsInterruptEnable = 1ULL << 9;
    const bool interrupts_were_enabled = (arch::ReadRflags() & kRflagsInterruptEnable) != 0;
    arch::Cli();
    sched::WaitQueueWakeAll(&inst.read_wq);
    if (interrupts_were_enabled)
        arch::Sti();
}

void CopyPath(const char* src, char (&dst)[kInotifyPathCap])
{
    u32 i = 0;
    for (; i < kInotifyPathCap - 1 && src[i] != '\0'; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}

i32 InotifyAlloc()
{
    sync::SpinLockGuard guard(g_inotify_lock);
    for (u32 i = 0; i < kInotifyPoolCap; ++i)
    {
        if (!g_inotify_pool[i].in_use && g_inotify_pool[i].generation != ~u64{0})
        {
            InotifyInstance& inst = g_inotify_pool[i];
            ++inst.generation;
            AdvanceReadSequenceLocked(inst);
            inst.in_use = true;
            inst.closing = false;
            inst.refs = 1;
            inst.pins = 0;
            inst.next_wd = 1;
            for (u32 w = 0; w < kInotifyWatchCap; ++w)
                inst.watches[w].in_use = false;
            inst.head = 0;
            inst.tail = 0;
            inst.count = 0;
            return static_cast<i32>(i);
        }
    }
    // Inotify instance pool saturated. Subsequent inotify_init1
    // calls will keep failing until something closes; once-warn
    // surfaces the saturation to the operator.
    KLOG_ONCE_WARN("subsystems/linux/inotify", "instance pool exhausted");
    return -1;
}

// Caller holds g_inotify_lock.
void RingPushLocked(InotifyInstance& inst, i32 wd, u32 mask, const char* path)
{
    if (inst.count == kInotifyRingCap)
    {
        // Drop oldest — Linux's inotify queue overflow is reported
        // via a synthetic IN_Q_OVERFLOW event (= 0x4000) but v0 just
        // drops the oldest entry quietly; sub-GAP.
        inst.tail = (inst.tail + 1) % kInotifyRingCap;
        --inst.count;
    }
    InotifyEvent& e = inst.ring[inst.head];
    e.wd = wd;
    e.mask = mask;
    e.cookie = 0;
    // name = leaf component of `path` (everything after the last '/').
    const char* leaf = path;
    for (const char* p = path; *p != '\0'; ++p)
        if (*p == '/')
            leaf = p + 1;
    for (u32 j = 0; j < kInotifyPathCap; ++j)
        e.name[j] = '\0';
    u32 i = 0;
    for (; i < kInotifyPathCap - 1 && leaf[i] != '\0'; ++i)
        e.name[i] = leaf[i];
    e.name[i] = '\0';
    // Linux pads name_len up to a 4-byte multiple including NUL.
    u32 nlen = i + 1;
    nlen = (nlen + 3) & ~3u;
    if (nlen > kInotifyPathCap)
        nlen = kInotifyPathCap;
    e.name_len = nlen;
    inst.head = (inst.head + 1) % kInotifyRingCap;
    ++inst.count;
    AdvanceReadSequenceLocked(inst);
}

} // namespace

void InotifyPublish(const char* path, u32 mask)
{
    if (path == nullptr || path[0] == '\0' || mask == 0)
        return;
    u32 wake_mask = 0;
    auto lock_flags = sync::SpinLockAcquire(g_inotify_lock);
    for (u32 i = 0; i < kInotifyPoolCap; ++i)
    {
        InotifyInstance& inst = g_inotify_pool[i];
        if (!inst.in_use)
            continue;
        bool published = false;
        // Fan out: any watch whose path is EITHER the full event
        // path OR the parent directory of the event path matches.
        // The subtree case is approximated by the parent-dir check:
        // a watcher on "/foo" gets events for "/foo/bar" because
        // "/foo" is the parent of "/foo/bar". Sub-GAP: deeper
        // ancestors aren't visited.
        for (u32 w = 0; w < kInotifyWatchCap; ++w)
        {
            InotifyWatch& watch = inst.watches[w];
            if (!watch.in_use)
                continue;
            if ((watch.mask & mask) == 0)
                continue;
            if (PathEqual(watch.path, path))
            {
                RingPushLocked(inst, watch.wd, mask, path);
                published = true;
                continue;
            }
            // Parent-of check: does watch.path == parent(path)?
            // Find the last '/' in `path`; compare prefix.
            const char* last_slash = nullptr;
            for (const char* p = path; *p != '\0'; ++p)
                if (*p == '/')
                    last_slash = p;
            if (last_slash == nullptr)
                continue;
            const u32 parent_len = static_cast<u32>(last_slash - path);
            // Special case: parent is "" → represents "/" .
            if (parent_len == 0)
            {
                if (watch.path[0] == '/' && watch.path[1] == '\0')
                {
                    RingPushLocked(inst, watch.wd, mask, path);
                    published = true;
                }
                continue;
            }
            // Normal case: watch.path must equal path[0..parent_len]
            // exactly and have a NUL at parent_len.
            u32 ci = 0;
            bool match = true;
            while (ci < parent_len)
            {
                if (watch.path[ci] != path[ci])
                {
                    match = false;
                    break;
                }
                ++ci;
            }
            if (match && watch.path[parent_len] == '\0')
            {
                RingPushLocked(inst, watch.wd, mask, path);
                published = true;
            }
        }
        if (published)
            wake_mask |= (1U << i);
    }
    sync::SpinLockRelease(g_inotify_lock, lock_flags);
    for (u32 i = 0; i < kInotifyPoolCap; ++i)
    {
        if ((wake_mask & (1U << i)) != 0)
            WakeReadWaiters(g_inotify_pool[i]);
    }
    if (wake_mask != 0)
        LinuxPollEventWake();
    // Fan the same event out to fanotify subscribers. Lives outside
    // the inotify Cli/Sti window because fanotify owns its own.
    FanotifyPublishFromInotify(path, mask);
    // Same hand-off into the Win32 dir-notify pool that backs
    // NtNotifyChangeDirectoryFile.
    ::duetos::subsystems::win32::Win32DirNotifyPublish(path, mask);
}

void InotifyRetain(u32 idx)
{
    if (idx >= kInotifyPoolCap)
        return;
    sync::SpinLockGuard guard(g_inotify_lock);
    InotifyInstance& inst = g_inotify_pool[idx];
    if (inst.in_use && !inst.closing)
        ++inst.refs;
}

void InotifyRelease(u32 idx)
{
    if (idx >= kInotifyPoolCap)
        return;
    bool wake = false;
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_inotify_lock);
    InotifyInstance& inst = g_inotify_pool[idx];
    if (!inst.in_use || inst.refs == 0)
    {
        sync::SpinLockRelease(g_inotify_lock, flags);
        return;
    }
    --inst.refs;
    if (inst.refs == 0)
    {
        inst.closing = true;
        AdvanceReadSequenceLocked(inst);
        wake = true;
        for (u32 w = 0; w < kInotifyWatchCap; ++w)
            inst.watches[w].in_use = false;
        if (inst.pins == 0)
        {
            inst.in_use = false;
            inst.closing = false;
            inst.count = 0;
            inst.head = 0;
            inst.tail = 0;
        }
    }
    sync::SpinLockRelease(g_inotify_lock, flags);
    if (wake)
    {
        WakeReadWaiters(inst);
        LinuxPollEventWake();
    }
}

i64 InotifyRead(u32 idx, u64 user_dst, u64 len, bool nonblocking)
{
    if (idx >= kInotifyPoolCap)
        return kEINVAL;
    if (len < 16)
        return kEINVAL;
    u64 expected_generation = 0;
    while (true)
    {
        u64 observed_sequence = 0;
        bool should_wait = false;
        {
            InotifyPin pin(idx, expected_generation);
            if (!pin)
                return 0;
            if (expected_generation == 0)
                expected_generation = pin.generation;

            const sync::IrqFlags lock_flags = sync::SpinLockAcquire(g_inotify_lock);
            InotifyInstance& inst = *pin.instance;
            if (!inst.in_use || inst.closing || inst.generation != expected_generation)
            {
                sync::SpinLockRelease(g_inotify_lock, lock_flags);
                return 0;
            }
            observed_sequence = __atomic_load_n(&inst.read_sequence, __ATOMIC_ACQUIRE);
            if (inst.count == 0)
            {
                sync::SpinLockRelease(g_inotify_lock, lock_flags);
                if (nonblocking)
                    return kEAGAIN;
                should_wait = true;
            }
            else
            {
                // Copy as many events as fit in the user buffer.
                u8 stage[256];
                u64 emitted = 0;
                while (inst.count > 0)
                {
                    const InotifyEvent& e = inst.ring[inst.tail];
                    const u64 record = 16 + e.name_len;
                    if (emitted + record > sizeof(stage) || emitted + record > len)
                        break;
                    u8* p = stage + emitted;
                    const i32 wd = e.wd;
                    const u32 mask = e.mask;
                    const u32 cookie = e.cookie;
                    const u32 name_len = e.name_len;
                    for (u32 i = 0; i < 4; ++i)
                        p[i] = static_cast<u8>((wd >> (i * 8)) & 0xFF);
                    for (u32 i = 0; i < 4; ++i)
                        p[4 + i] = static_cast<u8>((mask >> (i * 8)) & 0xFF);
                    for (u32 i = 0; i < 4; ++i)
                        p[8 + i] = static_cast<u8>((cookie >> (i * 8)) & 0xFF);
                    for (u32 i = 0; i < 4; ++i)
                        p[12 + i] = static_cast<u8>((name_len >> (i * 8)) & 0xFF);
                    for (u32 i = 0; i < name_len; ++i)
                        p[16 + i] = (i < kInotifyPathCap && e.name[i] != '\0') ? static_cast<u8>(e.name[i]) : 0;
                    emitted += record;
                    inst.tail = (inst.tail + 1) % kInotifyRingCap;
                    --inst.count;
                }
                sync::SpinLockRelease(g_inotify_lock, lock_flags);
                if (emitted == 0)
                    return kEAGAIN;
                if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, emitted))
                    return kEFAULT;
                return static_cast<i64>(emitted);
            }
        }

        if (should_wait)
        {
            InotifyInstance& inst = g_inotify_pool[idx];
            if (WaitForReadSequence(inst, observed_sequence) == sched::WaitQueueBlockResult::Cancelled)
                return kEINTR;
        }
    }
}

// =========================================================
// Syscall handlers
// =========================================================

i64 InotifyInit()
{
    return InotifyInit1(/*flags=*/0);
}

i64 InotifyInit1(u64 flags)
{
    constexpr u64 kIN_CLOEXEC = 0x80000;
    constexpr u64 kIN_NONBLOCK = 0x800;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    const i32 idx = InotifyAlloc();
    if (idx < 0)
        return kENFILE;

    auto kfile_result = ipc::KFileCreate(ipc::KFileKind::Inotify, static_cast<u32>(idx), &InotifyRelease, nullptr, 0);
    if (!kfile_result.has_value())
    {
        InotifyRelease(static_cast<u32>(idx));
        return kENOMEM;
    }

    core::Process::LinuxFd payload{};
    payload.state = 10;
    payload.first_cluster = static_cast<u32>(idx);
    core::LinuxFdPrepared prepared{};
    const u32 status_flags = static_cast<u32>(flags & kIN_NONBLOCK);
    if (!core::LinuxFdPrepare(&prepared, payload, &kfile_result.value()->base, status_flags))
    {
        ipc::KObjectRelease(&kfile_result.value()->base);
        return kENFILE;
    }
    const i32 fd = core::LinuxFdBindLowest(p, 3, &prepared, (flags & kIN_CLOEXEC) != 0);
    if (fd < 0)
    {
        core::LinuxFdPreparedRelease(&prepared);
        return kEMFILE;
    }
    arch::SerialWrite("[linux/inotify] init fd=");
    arch::SerialWriteHex(static_cast<u64>(fd));
    arch::SerialWrite(" pool_idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite("\n");
    return static_cast<i64>(fd);
}

i64 DoInotifyAddWatch(u64 fd, u64 user_path, u64 mask)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 10, &acquired))
        return kEBADF;
    const u32 idx = acquired.snapshot.first_cluster;
    if (idx >= kInotifyPoolCap)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
    char path[kInotifyPathCap];
    const auto copy = mm::CopyUserCString(path, sizeof(path), reinterpret_cast<const void*>(user_path));
    if (copy.status == mm::UserStringCopyStatus::Fault || copy.status == mm::UserStringCopyStatus::BadArgument)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEFAULT;
    }
    if (copy.status == mm::UserStringCopyStatus::NoTerminator)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kENAMETOOLONG;
    }
    InotifyPin pin(idx);
    core::LinuxFdAcquiredRelease(&acquired);
    if (!pin)
        return kEBADF;
    sync::SpinLockGuard guard(g_inotify_lock);
    InotifyInstance& inst = *pin.instance;
    if (!inst.in_use)
    {
        return kEBADF;
    }
    // IN_MASK_ADD (= 0x20000000): if a watch already exists on
    // path, OR the new mask in.
    constexpr u32 kInMaskAdd = 0x20000000;
    for (u32 w = 0; w < kInotifyWatchCap; ++w)
    {
        if (inst.watches[w].in_use && PathEqual(inst.watches[w].path, path))
        {
            if ((mask & kInMaskAdd) != 0)
                inst.watches[w].mask |= static_cast<u32>(mask);
            else
                inst.watches[w].mask = static_cast<u32>(mask);
            const i32 wd = inst.watches[w].wd;
            return static_cast<i64>(wd);
        }
    }
    for (u32 w = 0; w < kInotifyWatchCap; ++w)
    {
        if (!inst.watches[w].in_use)
        {
            inst.watches[w].in_use = true;
            inst.watches[w].wd = inst.next_wd++;
            inst.watches[w].mask = static_cast<u32>(mask);
            CopyPath(path, inst.watches[w].path);
            const i32 wd = inst.watches[w].wd;
            return static_cast<i64>(wd);
        }
    }
    return kENOMEM;
}

i64 DoInotifyRmWatch(u64 fd, u64 wd_arg)
{
    const i32 wd = static_cast<i32>(static_cast<i64>(wd_arg));
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(p, static_cast<u32>(fd), 10, &acquired))
        return kEBADF;
    const u32 idx = acquired.snapshot.first_cluster;
    if (idx >= kInotifyPoolCap)
    {
        core::LinuxFdAcquiredRelease(&acquired);
        return kEINVAL;
    }
    InotifyPin pin(idx);
    core::LinuxFdAcquiredRelease(&acquired);
    if (!pin)
        return kEBADF;
    sync::SpinLockGuard guard(g_inotify_lock);
    InotifyInstance& inst = *pin.instance;
    if (!inst.in_use)
    {
        return kEBADF;
    }
    for (u32 w = 0; w < kInotifyWatchCap; ++w)
    {
        if (inst.watches[w].in_use && inst.watches[w].wd == wd)
        {
            inst.watches[w].in_use = false;
            return 0;
        }
    }
    return kEINVAL;
}

} // namespace duetos::subsystems::linux::internal
