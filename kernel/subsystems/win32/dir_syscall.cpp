/*
 * Win32 directory enumeration — SYS_DIR_OPEN + SYS_DIR_NEXT.
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

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "syscall/syscall.h"
#include "util/string.h"

namespace duetos::subsystems::win32
{

namespace
{

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
    for (u64 i = 0; i < core::Process::kWin32DirCap; ++i)
        if (!proc->win32_dirs[i].in_use)
            return static_cast<i32>(i);
    return -1;
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
    using ::duetos::core::CapSetHas;
    using ::duetos::core::kCapFsRead;
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return -1;
    if (!CapSetHas(proc->caps, kCapFsRead))
    {
        core::RecordSandboxDenial(kCapFsRead);
        return -1;
    }
    char path[64];
    for (u32 i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    if (!mm::CopyFromUser(path, reinterpret_cast<const void*>(user_path), sizeof(path) - 1))
        return -1;
    path[sizeof(path) - 1] = 0;
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
            return -1;
        if (rest == nullptr || *rest == '\0')
            rest = "/";
        if (SnapshotFat32(v, rest, entries, count) < 0)
            return -1;
    }
    else
    {
        const fs::RamfsNode* node = RamfsResolvePath(proc->root, path);
        if (SnapshotRamfs(node, entries, count) < 0)
            return -1;
    }

    auto& dh = proc->win32_dirs[slot];
    dh.in_use = true;
    dh.entry_count = count;
    dh.next_index = 0;
    dh.entries = entries;

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
    auto& dh = proc->win32_dirs[slot];
    if (!dh.in_use || dh.entries == nullptr)
        return -1;
    if (dh.next_index >= dh.entry_count)
        return 0; // end of iteration

    auto* entries = static_cast<fs::fat32::DirEntry*>(dh.entries);
    const auto& e = entries[dh.next_index];
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
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_report), &report, sizeof(report)))
        return -1;
    ++dh.next_index;
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
    auto& dh = proc->win32_dirs[slot];
    if (!dh.in_use)
        return -1;
    dh.next_index = 0;
    return 0;
}

void SysDirClose(core::Process* proc, u64 handle)
{
    if (proc == nullptr)
        return;
    if (handle < core::Process::kWin32DirBase || handle >= core::Process::kWin32DirBase + core::Process::kWin32DirCap)
        return;
    const u32 slot = static_cast<u32>(handle - core::Process::kWin32DirBase);
    auto& dh = proc->win32_dirs[slot];
    if (!dh.in_use)
        return;
    if (dh.entries != nullptr)
    {
        mm::KFree(dh.entries);
        dh.entries = nullptr;
    }
    dh.in_use = false;
    dh.entry_count = 0;
    dh.next_index = 0;
}

} // namespace duetos::subsystems::win32
