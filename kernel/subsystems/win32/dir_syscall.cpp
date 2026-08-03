/*
 * Win32 directory enumeration — SYS_DIR_OPEN + SYS_DIR_NEXT +
 * SYS_DIR_NOTIFY.
 *
 * Backs Win32 FindFirstFileW / FindNextFileW / NtQueryDirectoryFile
 * (one ABI surface, two front-ends). The kernel-side responsibility
 * here is "translate path to a stable directory snapshot, expose a
 * cursor via SYS_DIR_NEXT". WIN32_FIND_DATA marshalling stays in
 * the user-mode kernel32 thunks — keeps the kernel ABI minimal.
 *
 * Routing:
 *   - "/disk/<idx>/<rest>" → FAT32 lookup on volume idx, snapshot
 *     entries via Fat32ListDirByCluster.
 *   - everything else → Ramfs lookup against Process::root, walk
 *     children into the snapshot.
 *
 * Snapshot semantics: entries are copied at OPEN time and stay
 * stable for the lifetime of the handle. Mutations after open
 * don't perturb the iterator (matches POSIX getdents).
 */

#include "subsystems/win32/dir_syscall.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "syscall/syscall.h"
#include "util/string.h"

namespace duetos::subsystems::win32
{

namespace
{

constinit sync::SpinLock g_dir_notify_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};

// Caller holds proc->win32_file_lock. The helper acquires the notify lock in
// that fixed order, marks exact subscriptions terminal, publishes their
// sequences, and wakes them before returning.
void CancelDirNotifyForHandleLocked(core::Process* proc, u32 dir_slot);

// Strip a leading "/disk/<idx>/" prefix; on hit, set *out_volume_idx
// and return a pointer past the prefix. On miss, *out_volume_idx is
// untouched and the original pointer is returned.
const char* StripDiskPrefix(const char* path, u32& out_volume_idx, bool& is_disk)
{
    is_disk = false;
    if (path == nullptr)
        return nullptr;
    const char* p = path;
    if (p[0] != '/' || p[1] != 'd' || p[2] != 'i' || p[3] != 's' || p[4] != 'k' || p[5] != '/')
        return path;
    p += 6;
    u32 idx = 0;
    bool any = false;
    while (*p >= '0' && *p <= '9')
    {
        idx = idx * 10 + static_cast<u32>(*p - '0');
        ++p;
        any = true;
    }
    if (!any)
        return path;
    if (*p != '/' && *p != '\0')
        return path;
    out_volume_idx = idx;
    is_disk = true;
    return *p == '\0' ? p : p + 1; // skip the trailing '/'
}

i32 AllocDirSlot(core::Process* proc)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_file_lock);
    for (u64 i = 0; i < core::Process::kWin32DirCap; ++i)
    {
        if (!proc->win32_dirs[i].in_use)
        {
            auto& row = proc->win32_dirs[i];
            row.in_use = true; // private reservation; no handle is published yet
            row.entry_count = 0;
            row.next_index = 0;
            row.entries = nullptr;
            row.path[0] = '\0';
            sync::SpinLockRelease(proc->win32_file_lock, flags);
            return static_cast<i32>(i);
        }
    }
    sync::SpinLockRelease(proc->win32_file_lock, flags);
    // Per-process Win32 directory-handle table saturated. The thunk
    // returns INVALID_HANDLE_VALUE; klog gets the first hit so the
    // operator sees the saturation before subsequent FindFirstFile
    // calls all start failing.
    KLOG_ONCE_WARN("subsystems/win32/dir", "per-process directory handle table full");
    return -1;
}

void AbortDirSlot(core::Process* proc, u32 slot)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_file_lock);
    auto& row = proc->win32_dirs[slot];
    if (row.in_use && row.entries == nullptr)
    {
        row.in_use = false;
        row.entry_count = 0;
        row.next_index = 0;
        row.path[0] = '\0';
    }
    sync::SpinLockRelease(proc->win32_file_lock, flags);
}

// Snapshot a FAT32 directory's entries into a fresh KMalloc'd array.
// Returns 0 on success, -1 on lookup miss / OOM. On success
// *out_entries / *out_count are filled.
i64 SnapshotFat32(const fs::fat32::Volume* v, const char* rel_path, fs::fat32::DirEntry*& out_entries, u32& out_count)
{
    using fs::fat32::DirEntry;
    fs::fat32::DirEntry probe;
    if (!fs::fat32::Fat32LookupPath(v, rel_path, &probe))
        return -1;
    constexpr u64 kCap = core::Process::kWin32DirEntryMax;
    auto* buf = static_cast<DirEntry*>(mm::KMalloc(sizeof(DirEntry) * kCap));
    if (buf == nullptr)
        return -1;
    const u32 n = fs::fat32::Fat32ListDirByCluster(v, probe.first_cluster, buf, static_cast<u32>(kCap));
    out_entries = buf;
    out_count = n;
    return 0;
}

// Walk one path component against `dir`'s children. Returns the
// matching child (case-sensitive — ramfs names are stable
// constexpr strings) or nullptr.
const fs::RamfsNode* RamfsLookupChild(const fs::RamfsNode* dir, const char* name, u32 name_len)
{
    if (dir == nullptr || dir->children == nullptr)
        return nullptr;
    for (u32 i = 0; dir->children[i] != nullptr; ++i)
    {
        const fs::RamfsNode* child = dir->children[i];
        u32 j = 0;
        while (j < name_len && child->name[j] == name[j] && child->name[j] != '\0')
            ++j;
        if (j == name_len && child->name[j] == '\0')
            return child;
    }
    return nullptr;
}

// Resolve a slash-delimited path against `root`. Returns nullptr on
// miss. Empty / "/" returns root itself.
const fs::RamfsNode* RamfsResolvePath(const fs::RamfsNode* root, const char* path)
{
    if (root == nullptr || path == nullptr)
        return nullptr;
    const fs::RamfsNode* cur = root;
    while (*path == '/')
        ++path;
    while (*path != '\0' && cur != nullptr)
    {
        const char* start = path;
        while (*path != '\0' && *path != '/')
            ++path;
        const u32 len = static_cast<u32>(path - start);
        if (len > 0)
            cur = RamfsLookupChild(cur, start, len);
        while (*path == '/')
            ++path;
    }
    return cur;
}

// Snapshot a Ramfs directory. Walks the children pointer-array and
// copies each child's name + attributes + size into FAT32-shaped
// DirEntries (the userland thunks don't care which backing
// populated them).
i64 SnapshotRamfs(const fs::RamfsNode* dir, fs::fat32::DirEntry*& out_entries, u32& out_count)
{
    using fs::fat32::DirEntry;
    if (dir == nullptr || dir->type != fs::RamfsNodeType::kDir)
        return -1;
    constexpr u64 kCap = core::Process::kWin32DirEntryMax;
    auto* buf = static_cast<DirEntry*>(mm::KMalloc(sizeof(DirEntry) * kCap));
    if (buf == nullptr)
        return -1;
    u32 n = 0;
    if (dir->children != nullptr)
    {
        for (u32 i = 0; dir->children[i] != nullptr && n < kCap; ++i)
        {
            const fs::RamfsNode* child = dir->children[i];
            DirEntry& slot = buf[n];
            for (u32 j = 0; j < sizeof(slot.name); ++j)
                slot.name[j] = 0;
            const char* src = child->name;
            u32 ci = 0;
            while (src[ci] != '\0' && ci < sizeof(slot.name) - 1)
            {
                slot.name[ci] = src[ci];
                ++ci;
            }
            slot.attributes = (child->type == fs::RamfsNodeType::kDir) ? 0x10 : 0x20;
            slot.first_cluster = 0;
            slot.size_bytes = static_cast<u32>(child->file_size);
            ++n;
        }
    }
    out_entries = buf;
    out_count = n;
    return 0;
}

} // namespace

i64 SysDirOpen(u64 user_path)
{
    // kCapFsRead is gated centrally by `SyscallGate`
    // (cap_table.def) — SYS_DIR_OPEN never reaches this handler
    // without it.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;
    char path[64];
    if (!mm::CopyUserCString(path, sizeof(path), reinterpret_cast<const void*>(user_path)).ok())
        return -1;
    return SysDirOpenKernel(path);
}

i64 SysDirOpenKernel(const char* path)
{
    if (path == nullptr)
        return -1;
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;

    const i32 slot = AllocDirSlot(proc);
    if (slot < 0)
        return -1;

    fs::fat32::DirEntry* entries = nullptr;
    u32 count = 0;

    bool is_disk = false;
    u32 volume_idx = 0;
    const char* rest = StripDiskPrefix(path, volume_idx, is_disk);
    if (is_disk)
    {
        const auto* v = fs::fat32::Fat32Volume(volume_idx);
        if (v == nullptr)
        {
            AbortDirSlot(proc, static_cast<u32>(slot));
            return -1;
        }
        if (rest == nullptr || *rest == '\0')
            rest = "/";
        if (SnapshotFat32(v, rest, entries, count) < 0)
        {
            AbortDirSlot(proc, static_cast<u32>(slot));
            return -1;
        }
    }
    else
    {
        const fs::RamfsNode* node = RamfsResolvePath(proc->root, path);
        if (SnapshotRamfs(node, entries, count) < 0)
        {
            AbortDirSlot(proc, static_cast<u32>(slot));
            return -1;
        }
    }

    const sync::IrqFlags publish_flags = sync::SpinLockAcquire(proc->win32_file_lock);
    auto& dh = proc->win32_dirs[slot];
    dh.entry_count = count;
    dh.next_index = 0;
    dh.entries = entries;
    // Cache the volume-relative path for NtNotifyChangeDirectoryFile.
    // For "/disk/<idx>/<rest>" we keep <rest>; for ramfs paths we
    // keep `path` verbatim. NUL-terminated, capped at 63 + NUL.
    const char* rel = is_disk ? (rest != nullptr ? rest : "/") : path;
    u32 pi = 0;
    for (; pi < sizeof(dh.path) - 1 && rel[pi] != '\0'; ++pi)
        dh.path[pi] = rel[pi];
    dh.path[pi] = '\0';
    sync::SpinLockRelease(proc->win32_file_lock, publish_flags);

    arch::SerialWrite("[win32/dir] open path=\"");
    arch::SerialWrite(path);
    arch::SerialWrite("\" handle=");
    arch::SerialWriteHex(static_cast<u64>(slot) + core::Process::kWin32DirBase);
    arch::SerialWrite(" entries=");
    arch::SerialWriteHex(count);
    arch::SerialWrite("\n");

    return static_cast<i64>(slot) + static_cast<i64>(core::Process::kWin32DirBase);
}

i64 SysDirNext(u64 handle, u64 user_report)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;
    if (handle < core::Process::kWin32DirBase || handle >= core::Process::kWin32DirBase + core::Process::kWin32DirCap)
        return -1;
    const u32 slot = static_cast<u32>(handle - core::Process::kWin32DirBase);
    const sync::IrqFlags snapshot_flags = sync::SpinLockAcquire(proc->win32_file_lock);
    auto& dh = proc->win32_dirs[slot];
    if (!dh.in_use || dh.entries == nullptr)
    {
        sync::SpinLockRelease(proc->win32_file_lock, snapshot_flags);
        return -1;
    }
    if (dh.next_index >= dh.entry_count)
    {
        sync::SpinLockRelease(proc->win32_file_lock, snapshot_flags);
        return 0; // end of iteration
    }

    auto* entries = static_cast<fs::fat32::DirEntry*>(dh.entries);
    const u32 expected_index = dh.next_index;
    void* const expected_entries = dh.entries;
    const auto& e = entries[expected_index];
    core::Win32DirEntryReport report;
    for (u32 i = 0; i < sizeof(report.name); ++i)
        report.name[i] = 0;
    // Copy name (cap to 63 chars to leave room for NUL).
    u32 ci = 0;
    while (e.name[ci] != '\0' && ci < sizeof(report.name) - 1)
    {
        report.name[ci] = e.name[ci];
        ++ci;
    }
    report.attributes = static_cast<u32>(e.attributes);
    report._pad = 0;
    report.size_bytes = static_cast<u64>(e.size_bytes);
    for (u32 i = 0; i < sizeof(report._reserved); ++i)
        report._reserved[i] = 0;
    sync::SpinLockRelease(proc->win32_file_lock, snapshot_flags);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_report), &report, sizeof(report)))
        return -1;

    const sync::IrqFlags commit_flags = sync::SpinLockAcquire(proc->win32_file_lock);
    auto& commit_row = proc->win32_dirs[slot];
    if (!commit_row.in_use || commit_row.entries != expected_entries || commit_row.next_index != expected_index)
    {
        sync::SpinLockRelease(proc->win32_file_lock, commit_flags);
        return -1;
    }
    ++commit_row.next_index;
    sync::SpinLockRelease(proc->win32_file_lock, commit_flags);
    return 1;
}

i64 SysDirRewind(u64 handle)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;
    if (handle < core::Process::kWin32DirBase || handle >= core::Process::kWin32DirBase + core::Process::kWin32DirCap)
        return -1;
    const u32 slot = static_cast<u32>(handle - core::Process::kWin32DirBase);
    const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_file_lock);
    auto& dh = proc->win32_dirs[slot];
    if (!dh.in_use)
    {
        sync::SpinLockRelease(proc->win32_file_lock, flags);
        return -1;
    }
    dh.next_index = 0;
    sync::SpinLockRelease(proc->win32_file_lock, flags);
    return 0;
}

void SysDirClose(core::Process* proc, u64 handle)
{
    if (proc == nullptr)
        return;
    if (handle < core::Process::kWin32DirBase || handle >= core::Process::kWin32DirBase + core::Process::kWin32DirCap)
        return;
    const u32 slot = static_cast<u32>(handle - core::Process::kWin32DirBase);
    const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_file_lock);
    auto& dh = proc->win32_dirs[slot];
    if (!dh.in_use)
    {
        sync::SpinLockRelease(proc->win32_file_lock, flags);
        return;
    }
    void* const detached_entries = dh.entries;
    dh.entries = nullptr;
    dh.in_use = false;
    dh.entry_count = 0;
    dh.next_index = 0;
    dh.path[0] = '\0';
    CancelDirNotifyForHandleLocked(proc, slot);
    sync::SpinLockRelease(proc->win32_file_lock, flags);
    if (detached_entries != nullptr)
        mm::KFree(detached_entries);
}

// =====================================================
// Win32 dir-notify engine — backs NtNotifyChangeDirectoryFile.
// =====================================================
//
// 8-slot global subscriber pool. Each subscription pins a path,
// the FILE_NOTIFY_CHANGE_* filter, and a WaitQueue the caller
// blocks on. Win32DirNotifyPublish is invoked from InotifyPublish
// (in inotify.cpp) for every FS-mutation event; it walks the
// subscription pool and wakes any matching subscriber, recording
// the event's leaf name + ACTION code into the slot.

namespace
{

constexpr u32 kDirNotifyPoolCap = 8;

struct DirNotifySub
{
    bool in_use;
    bool subtree;
    bool closed;
    u8 _pad;
    u32 filter;      // FILE_NOTIFY_CHANGE_* bits
    u32 last_action; // FILE_ACTION_*
    u32 dir_slot;
    u64 generation;
    u64 event_sequence;
    core::Process* owner;
    char path[64];
    char last_name[64]; // leaf of the published event
    sched::WaitQueue wq;
};

DirNotifySub g_dir_notify_pool[kDirNotifyPoolCap];

constexpr u64 kSaturatedNotifySequence = ~u64(0);

u64 DirNotifySequenceSnapshot(const DirNotifySub& sub)
{
    return __atomic_load_n(&sub.event_sequence, __ATOMIC_ACQUIRE);
}

void AdvanceDirNotifySequenceLocked(DirNotifySub& sub)
{
    u64 observed = __atomic_load_n(&sub.event_sequence, __ATOMIC_RELAXED);
    while (observed != kSaturatedNotifySequence)
    {
        if (__atomic_compare_exchange_n(&sub.event_sequence, &observed, observed + 1, false, __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED))
        {
            return;
        }
    }
}

bool DirPathEqual(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

// Linux IN_* → Win32 FILE_ACTION_*
constexpr u32 kFileActionAdded = 0x1;
constexpr u32 kFileActionRemoved = 0x2;
constexpr u32 kFileActionModified = 0x3;
constexpr u32 kFileActionRenamedOldName = 0x4;
constexpr u32 kFileActionRenamedNewName = 0x5;

// FILE_NOTIFY_CHANGE_* filter bits → which IN_* events match.
constexpr u32 kFncFileName = 0x1;
constexpr u32 kFncDirName = 0x2;
constexpr u32 kFncAttributes = 0x4;
constexpr u32 kFncSize = 0x8;
constexpr u32 kFncLastWrite = 0x10;

bool MaskMatchesFilter(u32 in_mask, u32 filter)
{
    constexpr u32 kInCreate = 0x100;
    constexpr u32 kInDelete = 0x200;
    constexpr u32 kInMovedFrom = 0x40;
    constexpr u32 kInMovedTo = 0x80;
    constexpr u32 kInModify = 0x2;
    constexpr u32 kInAttrib = 0x4;
    constexpr u32 kInIsDir = 0x40000000;
    const u32 base = in_mask & ~kInIsDir;
    if ((base & (kInCreate | kInDelete | kInMovedFrom | kInMovedTo)) != 0)
    {
        if (in_mask & kInIsDir)
            return (filter & kFncDirName) != 0;
        return (filter & kFncFileName) != 0;
    }
    if ((base & kInModify) != 0)
        return (filter & (kFncSize | kFncLastWrite)) != 0;
    if ((base & kInAttrib) != 0)
        return (filter & kFncAttributes) != 0;
    return false;
}

u32 InMaskToFileAction(u32 in_mask)
{
    constexpr u32 kInCreate = 0x100;
    constexpr u32 kInDelete = 0x200;
    constexpr u32 kInMovedFrom = 0x40;
    constexpr u32 kInMovedTo = 0x80;
    constexpr u32 kInModify = 0x2;
    if (in_mask & kInCreate)
        return kFileActionAdded;
    if (in_mask & kInDelete)
        return kFileActionRemoved;
    if (in_mask & kInMovedFrom)
        return kFileActionRenamedOldName;
    if (in_mask & kInMovedTo)
        return kFileActionRenamedNewName;
    if (in_mask & kInModify)
        return kFileActionModified;
    return kFileActionModified;
}

// Strip leading '/' chars, then return the leaf component.
const char* PathLeaf(const char* path)
{
    const char* leaf = path;
    for (const char* p = path; *p != '\0'; ++p)
        if (*p == '/')
            leaf = p + 1;
    return leaf;
}

bool PathParentMatches(const char* watch_path, const char* event_path)
{
    // True iff watch_path equals the parent directory of event_path.
    const char* last_slash = nullptr;
    for (const char* q = event_path; *q != '\0'; ++q)
        if (*q == '/')
            last_slash = q;
    if (last_slash == nullptr)
        return false;
    const u32 parent_len = static_cast<u32>(last_slash - event_path);
    if (parent_len == 0)
        return watch_path[0] == '/' && watch_path[1] == '\0';
    u32 ci = 0;
    while (ci < parent_len)
    {
        if (watch_path[ci] != event_path[ci])
            return false;
        ++ci;
    }
    return watch_path[parent_len] == '\0';
}

} // namespace

namespace
{

void CancelDirNotifyForHandleLocked(core::Process* proc, u32 dir_slot)
{
    const sync::IrqFlags notify_flags = sync::SpinLockAcquire(g_dir_notify_lock);
    for (u32 i = 0; i < kDirNotifyPoolCap; ++i)
    {
        DirNotifySub& sub = g_dir_notify_pool[i];
        if (!sub.in_use || sub.owner != proc || sub.dir_slot != dir_slot)
            continue;
        sub.closed = true;
        AdvanceDirNotifySequenceLocked(sub);
        sched::WaitQueueWakeAll(&sub.wq);
    }
    sync::SpinLockRelease(g_dir_notify_lock, notify_flags);
}

} // namespace

void Win32DirNotifyPublish(const char* path, u32 in_mask)
{
    if (path == nullptr || path[0] == '\0' || in_mask == 0)
        return;
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_dir_notify_lock);
    for (u32 i = 0; i < kDirNotifyPoolCap; ++i)
    {
        DirNotifySub& s = g_dir_notify_pool[i];
        if (!s.in_use || s.closed)
            continue;
        if (!MaskMatchesFilter(in_mask, s.filter))
            continue;
        bool match = DirPathEqual(s.path, path);
        if (!match && s.subtree)
            match = PathParentMatches(s.path, path);
        if (!match)
            continue;
        // Record event into the slot (single-event-per-call v0).
        const char* leaf = PathLeaf(path);
        u32 li = 0;
        for (; li < sizeof(s.last_name) - 1 && leaf[li] != '\0'; ++li)
            s.last_name[li] = leaf[li];
        s.last_name[li] = '\0';
        s.last_action = InMaskToFileAction(in_mask);
        AdvanceDirNotifySequenceLocked(s);
        sched::WaitQueueWakeOne(&s.wq);
    }
    sync::SpinLockRelease(g_dir_notify_lock, flags);
}

i64 SysDirNotify(u64 handle, u64 filter, u64 watch_subtree, u64 user_buf, u64 buf_len)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;
    if (handle < core::Process::kWin32DirBase || handle >= core::Process::kWin32DirBase + core::Process::kWin32DirCap)
        return -1;
    const u32 slot = static_cast<u32>(handle - core::Process::kWin32DirBase);
    if (buf_len < 24) // FILE_NOTIFY_INFORMATION header (12) + 1 wide-char (2) + min padding
        return -1;

    // File-row -> notify-pool is the sole lock order. Close marks the row
    // unavailable and terminates matching subscriptions under that same order,
    // so close/reopen cannot strand a waiter on an ABA-reused directory slot.
    const sync::IrqFlags file_flags = sync::SpinLockAcquire(proc->win32_file_lock);
    auto& dh = proc->win32_dirs[slot];
    if (!dh.in_use || dh.entries == nullptr)
    {
        sync::SpinLockRelease(proc->win32_file_lock, file_flags);
        return -1;
    }

    const sync::IrqFlags notify_flags = sync::SpinLockAcquire(g_dir_notify_lock);
    i32 sub_idx = -1;
    u64 sub_generation = 0;
    for (u32 i = 0; i < kDirNotifyPoolCap; ++i)
    {
        if (!g_dir_notify_pool[i].in_use && g_dir_notify_pool[i].generation != kSaturatedNotifySequence)
        {
            sub_idx = static_cast<i32>(i);
            DirNotifySub& s = g_dir_notify_pool[i];
            ++s.generation;
            sub_generation = s.generation;
            s.in_use = true;
            s.subtree = (watch_subtree != 0);
            s.closed = false;
            s._pad = 0;
            s.filter = static_cast<u32>(filter);
            s.last_action = 0;
            s.dir_slot = slot;
            s.owner = proc;
            for (u32 j = 0; j < sizeof(s.path); ++j)
                s.path[j] = 0;
            for (u32 j = 0; j < sizeof(s.last_name); ++j)
                s.last_name[j] = 0;
            for (u32 j = 0; j < sizeof(dh.path) && j < sizeof(s.path) - 1 && dh.path[j] != '\0'; ++j)
                s.path[j] = dh.path[j];
            break;
        }
    }
    sync::SpinLockRelease(g_dir_notify_lock, notify_flags);
    sync::SpinLockRelease(proc->win32_file_lock, file_flags);
    if (sub_idx < 0)
        return -1;

    // Block until any publisher records an event into this slot.
    u32 action = 0;
    char name[64] = {};
    while (true)
    {
        const sync::IrqFlags inspect_flags = sync::SpinLockAcquire(g_dir_notify_lock);
        DirNotifySub& s = g_dir_notify_pool[sub_idx];
        if (!s.in_use || s.generation != sub_generation)
        {
            sync::SpinLockRelease(g_dir_notify_lock, inspect_flags);
            return -1;
        }
        if (s.closed)
        {
            s.in_use = false;
            s.owner = nullptr;
            sync::SpinLockRelease(g_dir_notify_lock, inspect_flags);
            return -1;
        }
        if (s.last_action != 0)
        {
            action = s.last_action;
            for (u32 j = 0; j < sizeof(name); ++j)
                name[j] = s.last_name[j];
            s.in_use = false;
            s.owner = nullptr;
            sync::SpinLockRelease(g_dir_notify_lock, inspect_flags);
            break;
        }

        const u64 observed_sequence = DirNotifySequenceSnapshot(s);
        sched::WaitQueue* const waiters = &s.wq;
        sync::SpinLockRelease(g_dir_notify_lock, inspect_flags);

        const sched::WaitQueueBlockResult wait_result =
            observed_sequence == kSaturatedNotifySequence
                ? sched::WaitQueueBlockTimeoutCancellable(waiters, 1)
                : sched::WaitQueueBlockIfSequenceUnchangedCancellable(
                      waiters, &g_dir_notify_pool[sub_idx].event_sequence, observed_sequence);
        if (wait_result != sched::WaitQueueBlockResult::Cancelled)
            continue;

        const sync::IrqFlags cancel_flags = sync::SpinLockAcquire(g_dir_notify_lock);
        DirNotifySub& cancelled = g_dir_notify_pool[sub_idx];
        if (cancelled.in_use && cancelled.generation == sub_generation)
        {
            cancelled.in_use = false;
            cancelled.owner = nullptr;
        }
        sync::SpinLockRelease(g_dir_notify_lock, cancel_flags);
        return -1;
    }

    // Build a single FILE_NOTIFY_INFORMATION record:
    //   u32 NextEntryOffset  = 0
    //   u32 Action
    //   u32 FileNameLength   (bytes, NOT counting NUL)
    //   wchar_t FileName[]
    u32 name_chars = 0;
    while (name_chars < sizeof(name) && name[name_chars] != '\0')
        ++name_chars;
    const u32 name_bytes = name_chars * 2;
    const u32 needed = 12 + name_bytes;
    if (needed > buf_len)
        return -1;
    u8 stage[256];
    if (needed > sizeof(stage))
        return -1;
    for (u32 i = 0; i < needed; ++i)
        stage[i] = 0;
    auto put32 = [&](u32 off, u32 v)
    {
        for (u32 i = 0; i < 4; ++i)
            stage[off + i] = static_cast<u8>((v >> (i * 8)) & 0xFF);
    };
    put32(0, 0); // NextEntryOffset
    put32(4, action);
    put32(8, name_bytes);
    for (u32 i = 0; i < name_chars; ++i)
    {
        stage[12 + i * 2] = static_cast<u8>(name[i]);
        stage[12 + i * 2 + 1] = 0;
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, needed))
        return -1;
    return static_cast<i64>(needed);
}

} // namespace duetos::subsystems::win32
