/*
 * Linux fanotify(7) — v0.
 *
 * Sister to inotify(7) but with permission-event-style metadata.
 * v0 implementation reuses the same FS-mutation publish-subscribe
 * pipeline (`InotifyPublish` from `inotify.cpp`) — a fanotify mark
 * subscribes to the same publish path, but each event lands in the
 * fanotify pool's per-instance ring with the fanotify wire format.
 *
 *   fanotify_init(flags, event_f_flags) → LinuxFd state 15
 *   fanotify_mark(fd, flags, mask, dirfd, path) → record a mark
 *   read(fd) → drain `struct fanotify_event_metadata` records
 *
 * Wire format (32 bytes per event, no permission-event payload yet):
 *   u32 event_len
 *   u8  vers       (= 3, FANOTIFY_METADATA_VERSION)
 *   u8  reserved
 *   u16 metadata_len  (= 24)
 *   u64 mask
 *   i32 fd
 *   u32 pid
 *
 * Sub-GAPs:
 *   - No permission events (FAN_OPEN_PERM / FAN_ACCESS_PERM)
 *     — would require a blocking userland response loop.
 *   - The reported `fd` is always -1 (FAN_NOFD); a real fanotify
 *     opens a fresh fd on the affected file. v0 callers that want
 *     the path can derive it from the watch they registered.
 *   - FAN_REPORT_FID / FAN_REPORT_DIR_FID metadata variants not
 *     emitted (always the v3 base struct).
 */

#include "subsystems/linux/fanotify.h"
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

constexpr u32 kFanotifyPoolCap = 4;
constexpr u32 kFanotifyMarkCap = 16;
constexpr u32 kFanotifyRingCap = 32;
constexpr u32 kFanotifyPathCap = 64;

// Linux fanotify mask bits we honour (subset).
constexpr u64 kFanAccess = 0x00000001;
constexpr u64 kFanModify = 0x00000002;
constexpr u64 kFanCloseWrite = 0x00000008;
constexpr u64 kFanOpen = 0x00000020;
constexpr u64 kFanCreate = 0x00000100;
constexpr u64 kFanDelete = 0x00000200;
constexpr u64 kFanMovedFrom = 0x00000040;
constexpr u64 kFanMovedTo = 0x00000080;
constexpr u64 kFanOnDir = 0x40000000;

struct FanMark
{
    bool in_use;
    u8 _pad[3];
    u64 mask;
    char path[kFanotifyPathCap];
};

struct FanEvent
{
    u32 event_len; // FAN_EVENT_METADATA_LEN aligned
    u64 mask;
    u32 pid;
    char name[kFanotifyPathCap]; // for fan-out diagnostics, NOT in wire format
};

struct FanInstance
{
    bool in_use;
    u8 _pad[3];
    u32 refs;
    FanMark marks[kFanotifyMarkCap];
    FanEvent ring[kFanotifyRingCap];
    u32 head;
    u32 tail;
    u32 count;
    u32 _pad2;
    sched::WaitQueue read_wq;
};

FanInstance g_fan_pool[kFanotifyPoolCap];

bool FanPathEqual(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

void FanCopyPath(const char* src, char (&dst)[kFanotifyPathCap])
{
    u32 i = 0;
    for (; i < kFanotifyPathCap - 1 && src[i] != '\0'; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}

// Translate inotify mask → fanotify mask bits. Crude but enough
// for the v0 "Linux server probes fanotify, sees real events" path.
u64 MaskInotifyToFan(u32 in_mask)
{
    u64 out = 0;
    if (in_mask & 0x001)
        out |= kFanAccess;
    if (in_mask & 0x002)
        out |= kFanModify;
    if (in_mask & 0x008)
        out |= kFanCloseWrite;
    if (in_mask & 0x020)
        out |= kFanOpen;
    if (in_mask & 0x100)
        out |= kFanCreate;
    if (in_mask & 0x200)
        out |= kFanDelete;
    if (in_mask & 0x040)
        out |= kFanMovedFrom;
    if (in_mask & 0x080)
        out |= kFanMovedTo;
    if (in_mask & 0x40000000u)
        out |= kFanOnDir;
    return out;
}

i32 FanAlloc()
{
    arch::Cli();
    for (u32 i = 0; i < kFanotifyPoolCap; ++i)
    {
        if (!g_fan_pool[i].in_use)
        {
            FanInstance& inst = g_fan_pool[i];
            inst.in_use = true;
            inst.refs = 1;
            for (u32 m = 0; m < kFanotifyMarkCap; ++m)
                inst.marks[m].in_use = false;
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

} // namespace

// =====================================================
// Public surface — called from inotify.cpp's publish hook
// =====================================================

void FanotifyPublishFromInotify(const char* path, u32 in_mask)
{
    if (path == nullptr || path[0] == '\0' || in_mask == 0)
        return;
    const u64 fan_mask = MaskInotifyToFan(in_mask);
    arch::Cli();
    for (u32 i = 0; i < kFanotifyPoolCap; ++i)
    {
        FanInstance& inst = g_fan_pool[i];
        if (!inst.in_use)
            continue;
        for (u32 m = 0; m < kFanotifyMarkCap; ++m)
        {
            FanMark& mk = inst.marks[m];
            if (!mk.in_use)
                continue;
            if ((mk.mask & fan_mask) == 0)
                continue;
            // Match: exact path OR parent-of-path (one-level
            // subtree, same shape as inotify).
            bool match = FanPathEqual(mk.path, path);
            if (!match)
            {
                // Parent-of-path test.
                const char* last_slash = nullptr;
                for (const char* q = path; *q != '\0'; ++q)
                    if (*q == '/')
                        last_slash = q;
                if (last_slash != nullptr)
                {
                    const u32 parent_len = static_cast<u32>(last_slash - path);
                    if (parent_len == 0)
                    {
                        if (mk.path[0] == '/' && mk.path[1] == '\0')
                            match = true;
                    }
                    else
                    {
                        u32 ci = 0;
                        bool eq = true;
                        while (ci < parent_len)
                        {
                            if (mk.path[ci] != path[ci])
                            {
                                eq = false;
                                break;
                            }
                            ++ci;
                        }
                        if (eq && mk.path[parent_len] == '\0')
                            match = true;
                    }
                }
            }
            if (!match)
                continue;
            // Push event. Drop oldest on overflow.
            if (inst.count == kFanotifyRingCap)
            {
                inst.tail = (inst.tail + 1) % kFanotifyRingCap;
                --inst.count;
            }
            FanEvent& e = inst.ring[inst.head];
            e.event_len = 24; // FAN_EVENT_METADATA_LEN
            e.mask = fan_mask;
            e.pid = 0; // unknown publisher pid — sub-GAP
            FanCopyPath(path, e.name);
            inst.head = (inst.head + 1) % kFanotifyRingCap;
            ++inst.count;
        }
        if (inst.count > 0)
            sched::WaitQueueWakeAll(&inst.read_wq);
    }
    arch::Sti();
}

void FanotifyRetain(u32 idx)
{
    if (idx >= kFanotifyPoolCap)
        return;
    arch::Cli();
    if (g_fan_pool[idx].in_use)
        ++g_fan_pool[idx].refs;
    arch::Sti();
}

void FanotifyRelease(u32 idx)
{
    if (idx >= kFanotifyPoolCap)
        return;
    arch::Cli();
    FanInstance& inst = g_fan_pool[idx];
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
        for (u32 m = 0; m < kFanotifyMarkCap; ++m)
            inst.marks[m].in_use = false;
        inst.count = 0;
    }
    arch::Sti();
}

i64 FanotifyRead(u32 idx, u64 user_dst, u64 len)
{
    if (idx >= kFanotifyPoolCap)
        return kEINVAL;
    FanInstance& inst = g_fan_pool[idx];
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
    u8 stage[256];
    u64 emitted = 0;
    while (inst.count > 0)
    {
        const FanEvent& e = inst.ring[inst.tail];
        constexpr u32 kRecord = 24;
        if (emitted + kRecord > sizeof(stage) || emitted + kRecord > len)
            break;
        u8* p = stage + emitted;
        const u32 event_len = e.event_len;
        for (u32 i = 0; i < 4; ++i)
            p[i] = static_cast<u8>((event_len >> (i * 8)) & 0xFF);
        p[4] = 3; // FANOTIFY_METADATA_VERSION
        p[5] = 0; // reserved
        p[6] = 24;
        p[7] = 0; // metadata_len = 24
        for (u32 i = 0; i < 8; ++i)
            p[8 + i] = static_cast<u8>((e.mask >> (i * 8)) & 0xFF);
        // fd = -1 (FAN_NOFD) — sub-GAP
        for (u32 i = 0; i < 4; ++i)
            p[16 + i] = 0xFF;
        for (u32 i = 0; i < 4; ++i)
            p[20 + i] = static_cast<u8>((e.pid >> (i * 8)) & 0xFF);
        emitted += kRecord;
        inst.tail = (inst.tail + 1) % kFanotifyRingCap;
        --inst.count;
    }
    arch::Sti();
    if (emitted == 0)
        return kEAGAIN;
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, emitted))
        return kEFAULT;
    return static_cast<i64>(emitted);
}

// =====================================================
// Syscall handlers
// =====================================================

i64 DoFanotifyInit(u64 flags, u64 event_f_flags)
{
    (void)flags;
    (void)event_f_flags;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 fd = 16;
    for (u32 i = 3; i < LinuxFdEffectiveMax(p); ++i)
        if (p->linux_fds[i].state == 0)
        {
            fd = i;
            break;
        }
    if (fd == 16)
        return kEMFILE;
    const i32 idx = FanAlloc();
    if (idx < 0)
        return kENFILE;
    p->linux_fds[fd].state = 15;
    p->linux_fds[fd].first_cluster = static_cast<u32>(idx);
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    p->linux_fds[fd].path[0] = '\0';
    arch::SerialWrite("[linux/fanotify] init fd=");
    arch::SerialWriteHex(fd);
    arch::SerialWrite(" idx=");
    arch::SerialWriteHex(static_cast<u64>(idx));
    arch::SerialWrite("\n");
    return static_cast<i64>(fd);
}

i64 DoFanotifyMark(u64 fd, u64 flags, u64 mask, u64 dirfd, u64 user_path)
{
    (void)dirfd; // AT_FDCWD-equivalent only — no per-fd dir resolution
    constexpr u64 kFanMarkAdd = 0x01;
    constexpr u64 kFanMarkRemove = 0x02;
    constexpr u64 kFanMarkFlush = 0x80;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16 || p->linux_fds[fd].state != 15)
        return kEBADF;
    const u32 idx = p->linux_fds[fd].first_cluster;
    if (idx >= kFanotifyPoolCap)
        return kEINVAL;
    char path[kFanotifyPathCap];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (user_path != 0)
    {
        if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
            return kEFAULT;
        path[sizeof(path) - 1] = 0;
    }
    arch::Cli();
    FanInstance& inst = g_fan_pool[idx];
    if (!inst.in_use)
    {
        arch::Sti();
        return kEBADF;
    }
    if (flags & kFanMarkFlush)
    {
        for (u32 m = 0; m < kFanotifyMarkCap; ++m)
            inst.marks[m].in_use = false;
        arch::Sti();
        return 0;
    }
    if (flags & kFanMarkRemove)
    {
        for (u32 m = 0; m < kFanotifyMarkCap; ++m)
            if (inst.marks[m].in_use && FanPathEqual(inst.marks[m].path, path))
                inst.marks[m].in_use = false;
        arch::Sti();
        return 0;
    }
    if ((flags & kFanMarkAdd) == 0 && flags != 0)
    {
        arch::Sti();
        return kEINVAL;
    }
    // Add path (default behaviour when neither REMOVE nor FLUSH set).
    for (u32 m = 0; m < kFanotifyMarkCap; ++m)
    {
        if (inst.marks[m].in_use && FanPathEqual(inst.marks[m].path, path))
        {
            inst.marks[m].mask |= mask;
            arch::Sti();
            return 0;
        }
    }
    for (u32 m = 0; m < kFanotifyMarkCap; ++m)
    {
        if (!inst.marks[m].in_use)
        {
            inst.marks[m].in_use = true;
            inst.marks[m].mask = mask;
            FanCopyPath(path, inst.marks[m].path);
            arch::Sti();
            return 0;
        }
    }
    arch::Sti();
    return kENOMEM;
}

} // namespace duetos::subsystems::linux::internal
