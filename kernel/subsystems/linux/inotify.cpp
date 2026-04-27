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
#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

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
    u8 _pad[3];
    u32 refs;
    i32 next_wd;
    u32 _pad2;
    InotifyWatch watches[kInotifyWatchCap];
    InotifyEvent ring[kInotifyRingCap];
    u32 head;
    u32 tail;
    u32 count;
    u32 _pad3;
    sched::WaitQueue read_wq;
};

InotifyInstance g_inotify_pool[kInotifyPoolCap];

bool PathEqual(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
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
    arch::Cli();
    for (u32 i = 0; i < kInotifyPoolCap; ++i)
    {
        if (!g_inotify_pool[i].in_use)
        {
            InotifyInstance& inst = g_inotify_pool[i];
            inst.in_use = true;
            inst.refs = 1;
            inst.next_wd = 1;
            for (u32 w = 0; w < kInotifyWatchCap; ++w)
                inst.watches[w].in_use = false;
            inst.head = 0;
            inst.tail = 0;
            inst.count = 0;
            inst.read_wq.head = nullptr;
            inst.read_wq.tail = nullptr;
            arch::Sti();
            return static_cast<i32>(i);
        }
    }
    arch::Sti();
    return -1;
}

// Caller holds arch::Cli.
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
}

} // namespace

void InotifyPublish(const char* path, u32 mask)
{
    if (path == nullptr || path[0] == '\0' || mask == 0)
        return;
    arch::Cli();
    for (u32 i = 0; i < kInotifyPoolCap; ++i)
    {
        InotifyInstance& inst = g_inotify_pool[i];
        if (!inst.in_use)
            continue;
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
                    RingPushLocked(inst, watch.wd, mask, path);
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
                RingPushLocked(inst, watch.wd, mask, path);
        }
        if (inst.count > 0)
            sched::WaitQueueWakeAll(&inst.read_wq);
    }
    arch::Sti();
}

void InotifyRetain(u32 idx)
{
    if (idx >= kInotifyPoolCap)
        return;
    arch::Cli();
    InotifyInstance& inst = g_inotify_pool[idx];
    if (inst.in_use)
        ++inst.refs;
    arch::Sti();
}

void InotifyRelease(u32 idx)
{
    if (idx >= kInotifyPoolCap)
        return;
    arch::Cli();
    InotifyInstance& inst = g_inotify_pool[idx];
    if (!inst.in_use || inst.refs == 0)
    {
        arch::Sti();
        return;
    }
    --inst.refs;
    if (inst.refs == 0)
    {
        sched::WaitQueueWakeAll(&inst.read_wq);
        inst.in_use = false;
        for (u32 w = 0; w < kInotifyWatchCap; ++w)
            inst.watches[w].in_use = false;
        inst.count = 0;
        inst.head = 0;
        inst.tail = 0;
    }
    arch::Sti();
}

i64 InotifyRead(u32 idx, u64 user_dst, u64 len)
{
    if (idx >= kInotifyPoolCap)
        return kEINVAL;
    if (len < 16)
        return kEINVAL;
    InotifyInstance& inst = g_inotify_pool[idx];
    arch::Cli();
    while (inst.in_use && inst.count == 0)
    {
        sched::WaitQueueBlock(&inst.read_wq);
        arch::Cli();
    }
    if (!inst.in_use)
    {
        arch::Sti();
        return 0;
    }
    // Copy as many events as fit in the user buffer.
    u8 stage[256];
    u64 emitted = 0;
    while (inst.count > 0)
    {
        const InotifyEvent& e = inst.ring[inst.tail];
        const u64 record = 16 + e.name_len;
        if (emitted + record > sizeof(stage) || emitted + record > len)
            break;
        // Pack: 16-byte header + name padded to e.name_len.
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
    arch::Sti();
    if (emitted == 0)
        return kEAGAIN;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, emitted))
        return kEFAULT;
    return static_cast<i64>(emitted);
}

// =========================================================
// Syscall handlers
// =========================================================

i64 InotifyInit()
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
    const i32 idx = InotifyAlloc();
    if (idx < 0)
        return kENFILE;
    p->linux_fds[fd].state = 10;
    p->linux_fds[fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    p->linux_fds[fd].path[0] = '\0';
    arch::SerialWrite("[linux/inotify] init fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" pool_idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite("\n");
    return static_cast<i64>(fd);
}

i64 InotifyInit1(u64 flags)
{
    (void)flags; // IN_NONBLOCK / IN_CLOEXEC accepted but ignored
    return InotifyInit();
}

i64 DoInotifyAddWatch(u64 fd, u64 user_path, u64 mask)
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state != 10)
        return kEBADF;
    const u32 idx = p->linux_fds[fd].first_cluster;
    if (idx >= kInotifyPoolCap)
        return kEINVAL;
    char path[kInotifyPathCap];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return kEFAULT;
    path[sizeof(path) - 1] = '\0';
    arch::Cli();
    InotifyInstance& inst = g_inotify_pool[idx];
    if (!inst.in_use)
    {
        arch::Sti();
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
            arch::Sti();
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
            arch::Sti();
            return static_cast<i64>(wd);
        }
    }
    arch::Sti();
    return kENOMEM;
}

i64 DoInotifyRmWatch(u64 fd, u64 wd_arg)
{
    const i32 wd = static_cast<i32>(static_cast<i64>(wd_arg));
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state != 10)
        return kEBADF;
    const u32 idx = p->linux_fds[fd].first_cluster;
    if (idx >= kInotifyPoolCap)
        return kEINVAL;
    arch::Cli();
    InotifyInstance& inst = g_inotify_pool[idx];
    if (!inst.in_use)
    {
        arch::Sti();
        return kEBADF;
    }
    for (u32 w = 0; w < kInotifyWatchCap; ++w)
    {
        if (inst.watches[w].in_use && inst.watches[w].wd == wd)
        {
            inst.watches[w].in_use = false;
            arch::Sti();
            return 0;
        }
    }
    arch::Sti();
    return kEINVAL;
}

} // namespace duetos::subsystems::linux::internal
