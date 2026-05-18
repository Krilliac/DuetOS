/*
 * DuetOS — file-syscall routing layer: implementation.
 *
 * Companion to file_route.h — see there for the public router
 * API used by the syscall dispatcher.
 *
 * WHAT
 *   Decides which FS backend a path resolves into:
 *     - paths under `/bin/` -> embedded ramfs (binaries baked
 *                              into the kernel image at build time)
 *     - everything     -> the active mount at the longest
 *                         matching prefix (FAT32 / ext4 /
 *                         tmpfs / ramfs)
 *
 *   Insulates the syscall layer from per-FS specifics so
 *   SYS_READ / SYS_STAT can stay generic.
 *
 * HOW
 *   Mount table is a flat array of {prefix, fs-vtable}; lookup
 *   is a longest-prefix scan. Path normalisation (no `..`
 *   escapes, leading `/` enforcement) happens here before any
 *   FS-specific code sees the path.
 */

#include "fs/file_route.h"

#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "fs/duetfs.h"
#include "fs/duetfs/include/duetfs.h"
#include "fs/fat32.h"
#include "fs/mount.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"
#include "ipc/named_pipes.h"
#include "subsystems/linux/syscall_pipe.h"
#include "log/klog.h"
#include "proc/process.h"
#include "security/canary.h"
#include "subsystems/linux/inotify.h"
#include "util/nospec.h"

namespace duetos::fs::routing
{

namespace
{

constexpr const char* kDiskPrefix = "/disk/";
constexpr u64 kDiskPrefixLen = 6; // strlen("/disk/")
constexpr u64 kPathMax = 256;     // mirror SyscallPathMax for the in-kernel callers

// Field-wise DirEntry copy. The struct is ~140 bytes; a default
// `=` assignment makes the freestanding compiler emit a memcpy
// call (no libc here). Open-coding the copy keeps the linker
// happy without introducing a project-wide memcpy thunk for one
// caller.
void CopyDirEntry(fat32::DirEntry& dst, const fat32::DirEntry& src)
{
    for (u32 i = 0; i < sizeof(dst.name); ++i)
        dst.name[i] = src.name[i];
    dst.attributes = src.attributes;
    dst.first_cluster = src.first_cluster;
    dst.size_bytes = src.size_bytes;
}

void ZeroDirEntry(fat32::DirEntry& e)
{
    for (u32 i = 0; i < sizeof(e.name); ++i)
        e.name[i] = '\0';
    e.attributes = 0;
    e.first_cluster = 0;
    e.size_bytes = 0;
}

// Copy a NUL-terminated path into the handle's bounded path buffer.
// Returns true if the source fit; false (with the destination zeroed)
// if it didn't — caller treats that as "no growing-write path,
// fall back to in-place writes." The cap is set in process.h to
// match the longest path we expect from current shell + Win32 CWD
// flows; longer paths still open + read just fine, they just lose
// the past-EOF growth privilege.
bool CopyPathInto(char (&dst)[::duetos::core::Process::Win32FileHandle::kFat32PathCap], const char* src)
{
    using ::duetos::core::Process;
    constexpr u64 kCap = Process::Win32FileHandle::kFat32PathCap;
    if (src == nullptr)
    {
        for (u64 i = 0; i < kCap; ++i)
            dst[i] = '\0';
        return false;
    }
    u64 n = 0;
    while (src[n] != '\0' && n < kCap)
        ++n;
    if (n == kCap)
    {
        // Source longer than buffer (no NUL within cap). Drop it
        // — partial path would mis-route writes.
        for (u64 i = 0; i < kCap; ++i)
            dst[i] = '\0';
        return false;
    }
    for (u64 i = 0; i < n; ++i)
        dst[i] = src[i];
    for (u64 i = n; i < kCap; ++i)
        dst[i] = '\0';
    return true;
}

// Parse "/disk/<idx>/<rest>" → (idx, pointer-into-path-at-rest).
// Returns false on any malformed prefix (no digits, no separator
// after the index) or when the caller's namespace root cannot see
// the matching /disk/<idx> mount point. On a non-disk prefix returns
// false silently — the caller treats that as "use ramfs."
//
// Resolution order:
//   1. Mount registry — longest-visible-prefix match against
//      `VfsMountResolveVisible`. Hits when fat32 volumes have been
//      auto-mounted at boot (kernel/core/main.cpp wires that next to
//      the FAT32 self-test). `MountEntry::block_handle` carries the
//      FAT32 volume index.
//   2. Hardcoded "/disk/<idx>/<rest>" parse — fallback for callers
//      that hit before auto-mount has run, or when mounts are
//      cleared between fault-domain restarts.
bool ParseDiskPath(const RamfsNode* root, const char* path, u32* out_idx, const char** out_rest)
{
    if (root == nullptr || path == nullptr)
        return false;

    // (1) Mount registry — longest visible-prefix match. Only routes
    // here when the resolved entry is a FAT32 mount (other FS types
    // fall through to the hardcoded compatibility parser below).
    const char* mount_sub = nullptr;
    if (const auto* me = duetos::fs::VfsMountResolveVisible(root, path, kPathMax, &mount_sub))
    {
        if (me->fs_type == duetos::fs::FsType::Fat32 && mount_sub != nullptr && mount_sub[0] == '/')
        {
            *out_idx = me->block_handle;
            *out_rest = mount_sub;
            return true;
        }
    }

    // (2) Hardcoded "/disk/<idx>/<rest>" fallback.
    for (u64 i = 0; i < kDiskPrefixLen; ++i)
    {
        if (path[i] == '\0')
            return false;
        if (path[i] != kDiskPrefix[i])
            return false;
    }
    u64 cursor = kDiskPrefixLen;
    u32 idx = 0;
    bool any_digit = false;
    while (path[cursor] >= '0' && path[cursor] <= '9')
    {
        idx = idx * 10 + u32(path[cursor] - '0');
        any_digit = true;
        ++cursor;
        if (cursor > kDiskPrefixLen + 4) // bound: at most 4 digits, FAT32 cap is 16
            return false;
    }
    if (!any_digit)
        return false;
    // After the index we expect a '/'. The remainder (which may be
    // empty meaning "the volume root") starts at cursor + 1.
    if (path[cursor] != '/')
        return false;
    if (idx >= fat32::kMaxVolumes)
        return false;
    char mount_point[16] = {};
    if (!VfsFormatDiskMountPoint(idx, mount_point, sizeof(mount_point)) || !VfsMountVisibleFromRoot(root, mount_point))
        return false;
    *out_idx = idx;
    *out_rest = path + cursor; // include the leading '/' so Fat32LookupPath sees an absolute path
    return true;
}

// Resolve `path` against the VFS mount registry and, if the matched
// mount is a DuetFS mount visible from `root`, write the block handle
// and in-mount subpath (`*out_subpath` always starts with '/'). The
// kernel's boot DuetFS volume is mounted at "/duetfs", so paths like
// "/duetfs/etc/version" land here with subpath = "/etc/version".
bool ParseDuetFsPath(const RamfsNode* root, const char* path, u32* out_block_handle, const char** out_subpath)
{
    if (root == nullptr || path == nullptr)
        return false;
    const char* sub = nullptr;
    const auto* me = duetos::fs::VfsMountResolveVisible(root, path, kPathMax, &sub);
    if (me == nullptr || me->fs_type != duetos::fs::FsType::DuetFs)
        return false;
    if (sub == nullptr || sub[0] != '/')
        return false;
    *out_block_handle = me->block_handle;
    *out_subpath = sub;
    return true;
}

// Build a duetfs::Device descriptor from a mount block-handle.
duetos::fs::duetfs::Device DuetFsDeviceFor(u32 block_handle)
{
    return duetos::fs::duetfs::DeviceForMountHandle(block_handle);
}

// Path length (NUL-terminated) bounded at kPathMax — used to size
// the path_max argument to duetfs FFI calls. Ramfs paths can
// theoretically be longer; the duetfs FFI walks until NUL or
// path_max so we hand it a generous bound.
u64 PathLen(const char* p)
{
    u64 n = 0;
    while (p[n] != '\0' && n < kPathMax)
        ++n;
    return n;
}

// Find a free Win32 handle slot on `proc`. Returns kWin32HandleCap
// when none are free.
u64 FindFreeSlot(::duetos::core::Process* proc)
{
    using ::duetos::core::Process;
    for (u64 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        if (proc->win32_handles[i].kind == Process::FsBackingKind::None)
            return i;
    }
    return Process::kWin32HandleCap;
}

// Validate handle id, return slot index or u64(-1).
//
// Spectre v1 nospec: every consumer of this function uses the
// returned slot as a direct array index into win32_handles[]. The
// runtime bounds check protects correctness; we additionally mask
// the slot so a misprediction can't speculate a load past the
// table.
u64 HandleToSlot(u64 handle)
{
    using ::duetos::core::Process;
    if (handle < Process::kWin32HandleBase || handle >= Process::kWin32HandleBase + Process::kWin32HandleCap)
        return u64(-1);
    return ::duetos::util::MaskedIndex(handle - Process::kWin32HandleBase, Process::kWin32HandleCap);
}

// Per-handle byte size accessor — every backing knows it.
u64 HandleSize(const ::duetos::core::Process::Win32FileHandle& h)
{
    using ::duetos::core::Process;
    if (h.kind == Process::FsBackingKind::Ramfs && h.ramfs_node != nullptr)
        return h.ramfs_node->file_size;
    if (h.kind == Process::FsBackingKind::Fat32)
        return h.fat32_entry.size_bytes;
    if (h.kind == Process::FsBackingKind::DuetFs)
        return h.duetfs_size_bytes;
    if (h.kind == Process::FsBackingKind::RamVol)
    {
        u64 sz = 0;
        return duetos::fs::RamVolStat(h.ramvol_path, &sz, nullptr, nullptr) ? sz : 0;
    }
    return 0;
}

} // namespace

u64 OpenForProcess(::duetos::core::Process* proc, const char* path)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using ::duetos::core::Process;
    if (proc == nullptr || path == nullptr)
        return u64(-1);

    u32 disk_idx = 0;
    const char* disk_rest = nullptr;
    const bool routed = ParseDiskPath(proc->root, path, &disk_idx, &disk_rest);
    u32 duet_handle = 0;
    const char* duet_sub = nullptr;
    const bool duet_routed = ParseDuetFsPath(proc->root, path, &duet_handle, &duet_sub);

    const u64 slot = FindFreeSlot(proc);
    if (slot == Process::kWin32HandleCap)
    {
        SerialWrite("[fs/route] open out-of-handles pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
        return u64(-1);
    }
    Process::Win32FileHandle& h = proc->win32_handles[slot];

    if (duet_routed)
    {
        const auto dev = DuetFsDeviceFor(duet_handle);
        duetos::fs::duetfs::LookupResult res{};
        const u64 sub_len = PathLen(duet_sub);
        const u32 st = duetfs_lookup(&dev, reinterpret_cast<const u8*>(duet_sub), sub_len + 1, &res);
        if (st != duetos::fs::duetfs::kStatusOk)
        {
            SerialWrite("[fs/route] open: duetfs miss path=\"");
            SerialWrite(path);
            SerialWrite("\"\n");
            return u64(-1);
        }
        // Refuse open of a directory — Win32 file handles are file-only.
        if (res.kind != duetos::fs::duetfs::kKindFile && res.kind != duetos::fs::duetfs::kKindSymlink)
        {
            SerialWrite("[fs/route] open: refusing duetfs non-file kind\n");
            return u64(-1);
        }
        h.kind = Process::FsBackingKind::DuetFs;
        h.ramfs_node = nullptr;
        h.fat32_volume_idx = 0;
        h.duetfs_block_handle = duet_handle;
        h.duetfs_node_id = res.node_id;
        h.duetfs_size_bytes = static_cast<u64>(res.size_bytes);
        h.cursor = 0;
        h.is_canary = false;
        (void)CopyPathInto(h.fat32_path, nullptr);
        const u64 handle = Process::kWin32HandleBase + slot;
        SerialWrite("[fs/route] open ok pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" path=\"");
        SerialWrite(path);
        SerialWrite("\" backing=duetfs node=");
        SerialWriteHex(res.node_id);
        SerialWrite(" size=");
        SerialWriteHex(res.size_bytes);
        SerialWrite("\n");
        return handle;
    }

    if (routed)
    {
        const fat32::Volume* vol = fat32::Fat32Volume(disk_idx);
        if (vol == nullptr)
        {
            SerialWrite("[fs/route] open: no fat32 volume idx=");
            SerialWriteHex(disk_idx);
            SerialWrite(" path=\"");
            SerialWrite(path);
            SerialWrite("\"\n");
            return u64(-1);
        }
        fat32::DirEntry entry;
        ZeroDirEntry(entry);
        if (!fat32::Fat32LookupPath(vol, disk_rest, &entry))
        {
            SerialWrite("[fs/route] open: fat32 miss vol=");
            SerialWriteHex(disk_idx);
            SerialWrite(" path=\"");
            SerialWrite(disk_rest);
            SerialWrite("\"\n");
            return u64(-1);
        }
        // Reject directories — Win32 file handles are file-only in
        // v0. The directory-list syscall is a separate path.
        if ((entry.attributes & 0x10) != 0)
        {
            SerialWrite("[fs/route] open: refusing to open directory \"");
            SerialWrite(disk_rest);
            SerialWrite("\"\n");
            return u64(-1);
        }
        h.kind = Process::FsBackingKind::Fat32;
        h.ramfs_node = nullptr;
        h.fat32_volume_idx = disk_idx;
        CopyDirEntry(h.fat32_entry, entry);
        h.cursor = 0;
        // Stamp the in-volume path for past-EOF growing writes.
        // `disk_rest` already starts with '/' and addresses the
        // path inside the volume — exactly what Fat32WriteAtPath
        // wants. Long paths return false; the handle still works
        // for read + bounded write.
        (void)CopyPathInto(h.fat32_path, disk_rest);
        // Stamp the canary flag at open time. We only consult
        // the path-match side (CanaryMatchesPath) — suspicious-
        // extension matching at open is a false-positive
        // generator (existing files with these extensions
        // already on disk shouldn't all be quarantined; only
        // CREATE-time matches that, and CreateForProcess
        // already runs the full CanaryCheck before plant).
        h.is_canary = ::duetos::security::CanaryMatchesPath(disk_rest);
        const u64 handle = Process::kWin32HandleBase + slot;
        SerialWrite("[fs/route] open ok pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" path=\"");
        SerialWrite(path);
        SerialWrite("\" backing=fat32 vol=");
        SerialWriteHex(disk_idx);
        SerialWrite(" handle=");
        SerialWriteHex(handle);
        SerialWrite(" size=");
        SerialWriteHex(entry.size_bytes);
        SerialWrite("\n");
        return handle;
    }

    // RamVol (/run) — frame-backed writable RAM volume. Absolute
    // paths under "/run" route here; the path itself is the stable
    // handle (RamVol nodes are module-private).
    if (path[0] == '/' && path[1] == 'r' && path[2] == 'u' && path[3] == 'n' && (path[4] == '\0' || path[4] == '/'))
    {
        bool rv_dir = false;
        if (!duetos::fs::RamVolStat(path, nullptr, &rv_dir, nullptr))
        {
            SerialWrite("[fs/route] open: ramvol miss path=\"");
            SerialWrite(path);
            SerialWrite("\"\n");
            return u64(-1);
        }
        if (rv_dir)
        {
            SerialWrite("[fs/route] open: refusing ramvol directory \"");
            SerialWrite(path);
            SerialWrite("\"\n");
            return u64(-1);
        }
        u64 pl = 0;
        while (path[pl] != '\0')
            ++pl;
        if (pl >= Process::Win32FileHandle::kRamVolPathCap)
        {
            SerialWrite("[fs/route] open: ramvol path too long\n");
            return u64(-1);
        }
        h.kind = Process::FsBackingKind::RamVol;
        h.ramfs_node = nullptr;
        h.fat32_volume_idx = 0;
        for (u64 i = 0; i <= pl; ++i)
            h.ramvol_path[i] = path[i];
        h.cursor = 0;
        h.is_canary = false;
        (void)CopyPathInto(h.fat32_path, nullptr);
        const u64 handle = Process::kWin32HandleBase + slot;
        SerialWrite("[fs/route] open ok pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" path=\"");
        SerialWrite(path);
        SerialWrite("\" backing=ramvol\n");
        return handle;
    }

    // Ramfs fall-through.
    const RamfsNode* n = VfsLookup(proc->root, path, kPathMax);
    if (n == nullptr || n->type != RamfsNodeType::kFile)
    {
        SerialWrite("[fs/route] open: ramfs miss path=\"");
        SerialWrite(path);
        SerialWrite("\"\n");
        return u64(-1);
    }
    h.kind = Process::FsBackingKind::Ramfs;
    h.ramfs_node = n;
    h.fat32_volume_idx = 0;
    h.cursor = 0;
    h.is_canary = ::duetos::security::CanaryMatchesPath(path);
    (void)CopyPathInto(h.fat32_path, nullptr); // ramfs handles never need it
    const u64 handle = Process::kWin32HandleBase + slot;
    SerialWrite("[fs/route] open ok pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" path=\"");
    SerialWrite(path);
    SerialWrite("\" backing=ramfs handle=");
    SerialWriteHex(handle);
    SerialWrite(" size=");
    SerialWriteHex(n->file_size);
    SerialWrite("\n");
    return handle;
}

u64 ReadForProcess(::duetos::core::Process* proc, u64 handle, void* dst, u64 len)
{
    using ::duetos::core::Process;
    if (proc == nullptr || dst == nullptr)
        return u64(-1);
    const u64 slot = HandleToSlot(handle);
    if (slot == u64(-1))
        return u64(-1);
    Process::Win32FileHandle& h = proc->win32_handles[slot];
    if (h.kind == Process::FsBackingKind::None)
        return u64(-1);
    if (len == 0)
        return 0;

    if (h.kind == Process::FsBackingKind::Pipe)
    {
        // Pipe ends bypass the cursor / size machinery entirely
        // — the underlying ring buffer owns its own consumer
        // pointer. ReadForProcess on the write end is invalid
        // (returns -1); read end blocks via PipeRead's existing
        // wait-queue when the ring is empty AND writers remain.
        if (h.pipe_is_write_end)
            return u64(-1);
        const i64 got =
            ::duetos::subsystems::linux::internal::PipeRead(h.pipe_pool_idx, reinterpret_cast<u64>(dst), len);
        if (got < 0)
            return u64(-1);
        return static_cast<u64>(got);
    }

    const u64 size = HandleSize(h);
    if (h.cursor >= size)
        return 0; // EOF

    if (h.kind == Process::FsBackingKind::Ramfs)
    {
        const u64 remaining = size - h.cursor;
        const u64 take = (len < remaining) ? len : remaining;
        const u8* src = h.ramfs_node->file_bytes + h.cursor;
        auto* d = static_cast<u8*>(dst);
        for (u64 i = 0; i < take; ++i)
            d[i] = src[i];
        h.cursor += take;
        return take;
    }

    if (h.kind == Process::FsBackingKind::RamVol)
    {
        const u64 remaining = size - h.cursor;
        const u64 take = (len < remaining) ? len : remaining;
        const duetos::i64 got = duetos::fs::RamVolRead(h.ramvol_path, h.cursor, dst, take);
        if (got < 0)
            return u64(-1);
        h.cursor += static_cast<u64>(got);
        return static_cast<u64>(got);
    }

    if (h.kind == Process::FsBackingKind::DuetFs)
    {
        const auto dev = DuetFsDeviceFor(h.duetfs_block_handle);
        const u64 remaining = size - h.cursor;
        const u64 take = (len < remaining) ? len : remaining;
        usize got = 0;
        const u32 st = duetfs_read_file(&dev, h.duetfs_node_id, static_cast<u32>(h.cursor), dst, take, &got);
        if (st != duetos::fs::duetfs::kStatusOk)
            return u64(-1);
        h.cursor += static_cast<u64>(got);
        return static_cast<u64>(got);
    }

    // Fat32 backing — stream through the offset-aware reader so
    // we can resume from any cursor without staging the whole file.
    const fat32::Volume* vol = fat32::Fat32Volume(h.fat32_volume_idx);
    if (vol == nullptr)
        return u64(-1);
    const i64 got = fat32::Fat32ReadAt(vol, &h.fat32_entry, h.cursor, dst, len);
    if (got < 0)
        return u64(-1);
    h.cursor += u64(got);
    return u64(got);
}

u64 WriteForProcess(::duetos::core::Process* proc, u64 handle, const void* src, u64 len)
{
    using ::duetos::core::Process;
    if (proc == nullptr || src == nullptr)
        return u64(-1);
    const u64 slot = HandleToSlot(handle);
    if (slot == u64(-1))
        return u64(-1);
    Process::Win32FileHandle& h = proc->win32_handles[slot];
    if (h.kind == Process::FsBackingKind::None)
        return u64(-1);
    if (len == 0)
        return 0;

    if (h.kind == Process::FsBackingKind::Pipe)
    {
        // Pipe ends — read end can't be written; write end appends
        // to the ring through the existing pipe pool. PipeWrite
        // blocks on the wait-queue if the ring is full AND readers
        // remain; returns 0 with EPIPE-equivalent semantics if
        // every reader has closed.
        if (!h.pipe_is_write_end)
            return u64(-1);
        const i64 wrote = ::duetos::subsystems::linux::internal::PipeWrite(
            h.pipe_pool_idx, reinterpret_cast<u64>(const_cast<void*>(src)), len);
        if (wrote < 0)
            return u64(-1);
        return static_cast<u64>(wrote);
    }
    // Canary wall — handle-stamped variant. Closes the
    // "write-to-existing-canary" gap the path-only check
    // couldn't cover (the write syscall doesn't carry a path
    // string; only the file handle). The flag was stamped at
    // open time by `OpenForProcess`. CanaryTrip flags the
    // calling task for kill; we report short-write of 0 so
    // the syscall surfaces the failure consistently.
    if (h.is_canary)
    {
        ::duetos::security::CanaryTrip("<by-handle>", "write-existing");
        return u64(-1);
    }

    if (h.kind == Process::FsBackingKind::Ramfs)
        return u64(-1); // ramfs is .rodata

    if (h.kind == Process::FsBackingKind::RamVol)
    {
        // Positioned write at the cursor; RamVolWrite grows the
        // file + charges the quota and rejects a sealed file
        // (-1 == EROFS/ENOSPC-equivalent, same shape as the other
        // backends' failure return).
        const duetos::i64 wrote = duetos::fs::RamVolWrite(h.ramvol_path, h.cursor, src, len);
        if (wrote < 0)
            return u64(-1);
        h.cursor += static_cast<u64>(wrote);
        return static_cast<u64>(wrote);
    }

    if (h.kind == Process::FsBackingKind::DuetFs)
    {
        const auto dev = DuetFsDeviceFor(h.duetfs_block_handle);
        usize wrote = 0;
        const u32 st = duetfs_write_at(&dev, h.duetfs_node_id, static_cast<u32>(h.cursor), src, len, &wrote);
        if (st != duetos::fs::duetfs::kStatusOk)
            return u64(-1);
        h.cursor += static_cast<u64>(wrote);
        // Refresh the cached size — write_at auto-grew the file if the
        // write extended past EOF, and SeekForProcess / FstatForProcess
        // need the new size to clamp to a valid range.
        if (h.cursor > h.duetfs_size_bytes)
            h.duetfs_size_bytes = h.cursor;
        return static_cast<u64>(wrote);
    }

    const fat32::Volume* vol = fat32::Fat32Volume(h.fat32_volume_idx);
    if (vol == nullptr)
        return u64(-1);

    const u64 size = h.fat32_entry.size_bytes;
    // Overflow-safe: if `h.cursor + len` wraps u64 we'd mis-classify
    // a humongous write as an in-place fast-path write. The cursor is
    // bounded by FAT32's 4 GiB file-size cap, but `len` is the
    // user-supplied count and can be u64-max. Use subtractive form.
    if (len > (u64(-1) - h.cursor))
        return u64(-1);
    const u64 end = h.cursor + len;

    // In-place fast path: write entirely within the existing file.
    // Avoids the per-call ResolveParentDir walk Fat32WriteAtPath
    // does. Writes that grow the file fall through to the
    // path-resolved growing write below.
    if (end <= size)
    {
        const i64 wrote = fat32::Fat32WriteInPlace(vol, &h.fat32_entry, h.cursor, src, len);
        if (wrote < 0)
            return u64(-1);
        h.cursor += u64(wrote);
        ::duetos::core::RecordFsWrite(proc, u64(wrote));
        return u64(wrote);
    }

    // Growing write — extends past EOF. Needs a path so the
    // FAT32 layer can patch the parent dir entry's size after
    // chaining a new cluster. The path was stamped at open /
    // create time; if it's empty we don't have one (path was
    // longer than the bounded buffer), so we cap the write at
    // the in-place region and return the short count.
    if (h.fat32_path[0] == '\0')
    {
        if (h.cursor >= size)
            return u64(-1);
        const u64 take = size - h.cursor;
        const i64 wrote = fat32::Fat32WriteInPlace(vol, &h.fat32_entry, h.cursor, src, take);
        if (wrote < 0)
            return u64(-1);
        h.cursor += u64(wrote);
        ::duetos::core::RecordFsWrite(proc, u64(wrote));
        return u64(wrote);
    }

    const i64 wrote = fat32::Fat32WriteAtPath(vol, h.fat32_path, h.cursor, src, len);
    if (wrote < 0)
        return u64(-1);
    h.cursor += u64(wrote);
    // Refresh the cached DirEntry size — the on-disk dir entry
    // got patched inside Fat32WriteAtPath, but our snapshot
    // still reads the pre-grow value. Without this, a follow-up
    // SeekForProcess(SEEK_END) on the same handle returns the
    // stale size and subsequent reads stop early.
    fat32::DirEntry refreshed;
    if (fat32::Fat32LookupPath(vol, h.fat32_path, &refreshed))
        CopyDirEntry(h.fat32_entry, refreshed);
    ::duetos::core::RecordFsWrite(proc, u64(wrote));
    return u64(wrote);
}

u64 CreateForProcess(::duetos::core::Process* proc, const char* path, const void* init_bytes, u64 init_len)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using ::duetos::core::Process;
    if (proc == nullptr || path == nullptr)
        return u64(-1);
    if (init_len > 0 && init_bytes == nullptr)
        return u64(-1);

    u32 disk_idx = 0;
    const char* disk_rest = nullptr;
    u32 duet_handle = 0;
    const char* duet_sub = nullptr;
    if (ParseDuetFsPath(proc->root, path, &duet_handle, &duet_sub))
    {
        const auto dev = DuetFsDeviceFor(duet_handle);
        u32 new_id = 0;
        const u64 sub_len = PathLen(duet_sub);
        const u32 st = duetfs_create_path(&dev, reinterpret_cast<const u8*>(duet_sub), sub_len + 1,
                                          duetos::fs::duetfs::kKindFile, &new_id);
        if (st != duetos::fs::duetfs::kStatusOk)
        {
            SerialWrite("[fs/route] create: duetfs_create_path failed st=");
            SerialWriteHex(st);
            SerialWrite("\n");
            return u64(-1);
        }
        if (init_len > 0 && init_bytes != nullptr)
        {
            usize wrote = 0;
            const u32 wst = duetfs_write_at(&dev, new_id, 0, init_bytes, init_len, &wrote);
            if (wst != duetos::fs::duetfs::kStatusOk || wrote != init_len)
            {
                // Roll back the create — leaves the FS in its pre-call state.
                (void)duetfs_unlink_path(&dev, reinterpret_cast<const u8*>(duet_sub), sub_len + 1);
                return u64(-1);
            }
        }
        const u64 slot = FindFreeSlot(proc);
        if (slot == Process::kWin32HandleCap)
            return u64(-1);
        Process::Win32FileHandle& dh = proc->win32_handles[slot];
        dh.kind = Process::FsBackingKind::DuetFs;
        dh.ramfs_node = nullptr;
        dh.fat32_volume_idx = 0;
        dh.duetfs_block_handle = duet_handle;
        dh.duetfs_node_id = new_id;
        dh.duetfs_size_bytes = init_len;
        dh.cursor = 0;
        dh.is_canary = false;
        (void)CopyPathInto(dh.fat32_path, nullptr);
        if (init_len > 0)
            ::duetos::core::RecordFsWrite(proc, init_len);
        return Process::kWin32HandleBase + slot;
    }
    if (!ParseDiskPath(proc->root, path, &disk_idx, &disk_rest))
    {
        SerialWrite("[fs/route] create: ramfs path rejected (read-only) \"");
        SerialWrite(path);
        SerialWrite("\"\n");
        return u64(-1);
    }

    // Canary wall: refuse the create if the path matches a
    // registered canary or a suspicious-extension pattern. Trip
    // happens BEFORE the on-disk plant — a ransomware that
    // tries to write its encrypted-output file dies before its
    // bytes ever land. CanaryCheck flags the calling task for
    // kill; we still return failure so the syscall reports
    // -1 to the caller (it'll be reaped before it sees the
    // return anyway, but the contract is consistent).
    if (::duetos::security::CanaryCheck(disk_rest, "create"))
        return u64(-1);
    // Persistence-drop detector. Default Advisory mode logs +
    // bumps the counter; Deny mode (escalated by the guard on
    // a security-critical event) kills the writer. Returns
    // true when we should short-circuit.
    if (::duetos::security::PersistenceCheck(disk_rest, "create"))
        return u64(-1);

    const fat32::Volume* vol = fat32::Fat32Volume(disk_idx);
    if (vol == nullptr)
    {
        SerialWrite("[fs/route] create: no fat32 volume idx=");
        SerialWriteHex(disk_idx);
        SerialWrite("\n");
        return u64(-1);
    }

    // Allocate the slot BEFORE the on-disk plant so a slot-table
    // failure doesn't leave a freshly-created file orphaned in
    // the directory. If the plant fails the slot returns to
    // FsBackingKind::None below.
    const u64 slot = FindFreeSlot(proc);
    if (slot == Process::kWin32HandleCap)
    {
        SerialWrite("[fs/route] create out-of-handles pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
        return u64(-1);
    }
    Process::Win32FileHandle& h = proc->win32_handles[slot];

    const i64 created = fat32::Fat32CreateAtPath(vol, disk_rest, init_bytes, init_len);
    if (created < 0)
    {
        SerialWrite("[fs/route] create: Fat32CreateAtPath failed path=\"");
        SerialWrite(disk_rest);
        SerialWrite("\"\n");
        return u64(-1);
    }

    // Re-look up the newly-planted entry to get the canonical
    // DirEntry (first_cluster + size populated by the FS) so the
    // handle's read/write paths can address it.
    fat32::DirEntry entry;
    ZeroDirEntry(entry);
    if (!fat32::Fat32LookupPath(vol, disk_rest, &entry))
    {
        SerialWrite("[fs/route] create: post-plant lookup miss \"");
        SerialWrite(disk_rest);
        SerialWrite("\"\n");
        return u64(-1);
    }

    h.kind = Process::FsBackingKind::Fat32;
    h.ramfs_node = nullptr;
    h.fat32_volume_idx = disk_idx;
    CopyDirEntry(h.fat32_entry, entry);
    h.cursor = 0;
    // The create-path canary check ran above, before the plant —
    // any create that landed here got a clean verdict, so the
    // handle's is_canary is false. Stash it explicitly so the
    // write path doesn't read uninitialized state.
    h.is_canary = false;
    (void)CopyPathInto(h.fat32_path, disk_rest);
    // Ransomware-rate guard. Counts the create's init_bytes
    // payload toward the calling process's window — a typical
    // encrypt-loop is "create new file with encrypted contents"
    // followed by unlink-of-original, so the create surface
    // matters as much as the in-place write surface.
    if (init_len > 0)
        ::duetos::core::RecordFsWrite(proc, init_len);
    ::duetos::subsystems::linux::internal::InotifyPublish(disk_rest, ::duetos::subsystems::linux::internal::kInCreate);
    const u64 handle = Process::kWin32HandleBase + slot;
    SerialWrite("[fs/route] create ok pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" path=\"");
    SerialWrite(path);
    SerialWrite("\" backing=fat32 vol=");
    SerialWriteHex(disk_idx);
    SerialWrite(" handle=");
    SerialWriteHex(handle);
    SerialWrite(" size=");
    SerialWriteHex(entry.size_bytes);
    SerialWrite("\n");
    return handle;
}

u64 SeekForProcess(::duetos::core::Process* proc, u64 handle, i64 offset, u32 whence)
{
    using ::duetos::core::Process;
    if (proc == nullptr)
        return u64(-1);
    const u64 slot = HandleToSlot(handle);
    if (slot == u64(-1))
        return u64(-1);
    Process::Win32FileHandle& h = proc->win32_handles[slot];
    if (h.kind == Process::FsBackingKind::None)
        return u64(-1);
    const u64 size = HandleSize(h);
    i64 base = 0;
    switch (whence)
    {
    case 0:
        base = 0;
        break;
    case 1:
        base = static_cast<i64>(h.cursor);
        break;
    case 2:
        base = static_cast<i64>(size);
        break;
    default:
        return u64(-1);
    }
    i64 newpos = base + offset;
    if (newpos < 0)
        newpos = 0;
    if (static_cast<u64>(newpos) > size)
        newpos = static_cast<i64>(size);
    h.cursor = static_cast<u64>(newpos);
    return h.cursor;
}

u64 FstatForProcess(::duetos::core::Process* proc, u64 handle, u64* out_size)
{
    using ::duetos::core::Process;
    if (proc == nullptr || out_size == nullptr)
        return u64(-1);
    const u64 slot = HandleToSlot(handle);
    if (slot == u64(-1))
        return u64(-1);
    const Process::Win32FileHandle& h = proc->win32_handles[slot];
    if (h.kind == Process::FsBackingKind::None)
        return u64(-1);
    *out_size = HandleSize(h);
    return 0;
}

u64 CloseForProcess(::duetos::core::Process* proc, u64 handle)
{
    using ::duetos::core::Process;
    if (proc == nullptr)
        return 0;
    const u64 slot = HandleToSlot(handle);
    if (slot == u64(-1))
        return 0;
    Process::Win32FileHandle& h = proc->win32_handles[slot];
    // Pipe ends: drop the per-end refcount BEFORE clearing the
    // slot. The pipe pool walks read_refs / write_refs to decide
    // when to free the buffer + wake the opposite end (EOF /
    // EPIPE semantics); skipping the release would leak the slot.
    if (h.kind == Process::FsBackingKind::Pipe)
    {
        if (h.pipe_is_write_end)
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(h.pipe_pool_idx);
        else
            ::duetos::subsystems::linux::internal::PipeReleaseRead(h.pipe_pool_idx);
        // Server end of a named pipe: drop the registry entry
        // and any orphan opposite-end reservation (no client
        // ever connected) before the slot is reused. Client
        // ends and anonymous pipes keep slot == -1 and skip.
        if (h.named_pipe_registry_slot >= 0)
            ::duetos::ipc::NamedPipeOnServerClose(h.named_pipe_registry_slot);
    }
    h.kind = Process::FsBackingKind::None;
    h.ramfs_node = nullptr;
    h.fat32_volume_idx = 0;
    h.cursor = 0;
    h.pipe_pool_idx = 0;
    h.pipe_is_write_end = false;
    h.named_pipe_registry_slot = -1;
    (void)CopyPathInto(h.fat32_path, nullptr);
    return 0;
}

// ---------------------------------------------------------------
// Mutation surface (unlink + rename). Cap-gated by the syscall
// layer; this facade performs the dispatch and the validation
// but no capability check.
//
// Routing rules:
//   - "/disk/<idx>/<rest>"      → fat32::Fat32{Delete,Rename}AtPath
//   - everything else           → false (ramfs is read-only;
//                                  tmpfs has its own shell-only
//                                  surface and isn't routed here
//                                  in v0)
// ---------------------------------------------------------------

bool UnlinkForProcess(::duetos::core::Process* proc, const char* path)
{
    if (proc == nullptr || path == nullptr || path[0] == '\0')
        return false;
    u32 duet_handle = 0;
    const char* duet_sub = nullptr;
    if (ParseDuetFsPath(proc->root, path, &duet_handle, &duet_sub))
    {
        if (::duetos::security::CanaryCheck(duet_sub, "unlink"))
            return false;
        if (::duetos::security::PersistenceCheck(duet_sub, "unlink"))
            return false;
        const auto dev = DuetFsDeviceFor(duet_handle);
        const u64 sub_len = PathLen(duet_sub);
        if (duetfs_unlink_path(&dev, reinterpret_cast<const u8*>(duet_sub), sub_len + 1) !=
            duetos::fs::duetfs::kStatusOk)
        {
            return false;
        }
        ::duetos::subsystems::linux::internal::InotifyPublish(duet_sub,
                                                              ::duetos::subsystems::linux::internal::kInDelete);
        return true;
    }
    u32 idx = 0;
    const char* rest = nullptr;
    if (!ParseDiskPath(proc->root, path, &idx, &rest))
        return false;
    // Canary wall: refuse unlink of a canary path. Ransomware
    // typically deletes the original after writing the encrypted
    // copy, so the unlink surface is as important as create.
    if (::duetos::security::CanaryCheck(rest, "unlink"))
        return false;
    // Persistence-drop: deleting an autostart entry is a tell
    // (malware sometimes wipes alternative startup hooks). Note
    // it; in Deny mode the writer is killed.
    if (::duetos::security::PersistenceCheck(rest, "unlink"))
        return false;
    const fat32::Volume* v = fat32::Fat32Volume(idx);
    if (v == nullptr)
        return false;
    if (!fat32::Fat32DeleteAtPath(v, rest))
        return false;
    ::duetos::subsystems::linux::internal::InotifyPublish(rest, ::duetos::subsystems::linux::internal::kInDelete);
    return true;
}

bool StatPathForProcess(::duetos::core::Process* proc, const char* path, u64* out_size, bool* out_is_dir)
{
    if (proc == nullptr || path == nullptr || path[0] == '\0')
        return false;
    u32 duet_handle = 0;
    const char* duet_sub = nullptr;
    if (ParseDuetFsPath(proc->root, path, &duet_handle, &duet_sub))
    {
        const auto dev = DuetFsDeviceFor(duet_handle);
        duetos::fs::duetfs::LookupResult res{};
        const u64 sub_len = PathLen(duet_sub);
        const u32 st = duetfs_lookup(&dev, reinterpret_cast<const u8*>(duet_sub), sub_len + 1, &res);
        if (st != duetos::fs::duetfs::kStatusOk)
            return false;
        if (out_size != nullptr)
            *out_size = static_cast<u64>(res.size_bytes);
        if (out_is_dir != nullptr)
            *out_is_dir = (res.kind == duetos::fs::duetfs::kKindDir);
        return true;
    }
    u32 idx = 0;
    const char* rest = nullptr;
    if (ParseDiskPath(proc->root, path, &idx, &rest))
    {
        const fat32::Volume* v = fat32::Fat32Volume(idx);
        if (v == nullptr)
            return false;
        fat32::DirEntry e;
        if (!fat32::Fat32LookupPath(v, rest, &e))
            return false;
        if (out_size != nullptr)
            *out_size = e.size_bytes;
        if (out_is_dir != nullptr)
            *out_is_dir = (e.attributes & 0x10) != 0; // ATTR_DIRECTORY
        return true;
    }
    // Ramfs fall-through — mirror OpenForProcess so a stat call
    // sees every path the open call would. Without this,
    // GetFileAttributesW on a ramfs path (e.g. "/etc/version")
    // returns INVALID_FILE_ATTRIBUTES even though CreateFileW on
    // the same path succeeds.
    const RamfsNode* n = VfsLookup(proc->root, path, kPathMax);
    if (n == nullptr)
        return false;
    if (out_size != nullptr)
        *out_size = (n->type == RamfsNodeType::kFile) ? n->file_size : 0;
    if (out_is_dir != nullptr)
        *out_is_dir = (n->type == RamfsNodeType::kDir);
    return true;
}

bool RenameForProcess(::duetos::core::Process* proc, const char* src, const char* dst)
{
    if (proc == nullptr || src == nullptr || dst == nullptr || src[0] == '\0' || dst[0] == '\0')
        return false;
    u32 src_idx = 0;
    u32 dst_idx = 0;
    const char* src_rest = nullptr;
    const char* dst_rest = nullptr;
    if (!ParseDiskPath(proc->root, src, &src_idx, &src_rest))
        return false;
    if (!ParseDiskPath(proc->root, dst, &dst_idx, &dst_rest))
        return false;
    // Canary wall: refuse rename if EITHER endpoint is a canary
    // / suspicious-extension target. Ransomware that does
    // "rename X to X.encrypted" trips the dst-side check; an
    // attacker masquerading "rename canary to something safe"
    // trips the src-side check.
    if (::duetos::security::CanaryCheck(src_rest, "rename-src"))
        return false;
    if (::duetos::security::CanaryCheck(dst_rest, "rename-dst"))
        return false;
    if (::duetos::security::PersistenceCheck(src_rest, "rename-src"))
        return false;
    if (::duetos::security::PersistenceCheck(dst_rest, "rename-dst"))
        return false;
    if (src_idx != dst_idx)
        return false; // cross-volume rename not supported in v0
    const fat32::Volume* v = fat32::Fat32Volume(src_idx);
    if (v == nullptr)
        return false;
    if (!fat32::Fat32RenameAtPath(v, src_rest, dst_rest))
        return false;
    ::duetos::subsystems::linux::internal::InotifyPublish(src_rest,
                                                          ::duetos::subsystems::linux::internal::kInMovedFrom);
    ::duetos::subsystems::linux::internal::InotifyPublish(dst_rest, ::duetos::subsystems::linux::internal::kInMovedTo);
    return true;
}

// ---------------------------------------------------------------
// DuetFS- and FAT32-backed metadata operations. DuetFS routes
// through the Rust FFI; FAT32 routes through Fat32MkdirAtPath /
// the matching delete path. Ramfs is read-only and returns false.
// ---------------------------------------------------------------

bool MkdirForProcess(::duetos::core::Process* proc, const char* path)
{
    if (proc == nullptr || path == nullptr || path[0] == '\0')
        return false;
    // DuetFS path: <duet-handle>:/sub/dir
    u32 duet_handle = 0;
    const char* duet_sub = nullptr;
    if (ParseDuetFsPath(proc->root, path, &duet_handle, &duet_sub))
    {
        const auto dev = DuetFsDeviceFor(duet_handle);
        u32 new_id = 0;
        const u64 sub_len = PathLen(duet_sub);
        const u32 st = duetfs_create_path(&dev, reinterpret_cast<const u8*>(duet_sub), sub_len + 1,
                                          duetos::fs::duetfs::kKindDir, &new_id);
        if (st != duetos::fs::duetfs::kStatusOk)
            return false;
        ::duetos::subsystems::linux::internal::InotifyPublish(duet_sub,
                                                              ::duetos::subsystems::linux::internal::kInCreate);
        return true;
    }
    // FAT32 path: a disk volume reachable via /disk/<n>/ or the
    // process's root namespace. ParseDiskPath returns the volume
    // index + the in-volume tail; Fat32MkdirAtPath walks the
    // parent chain (parent must already exist) and plants a fresh
    // directory entry with seeded "." / ".." records. This was the
    // gap blocking installer-style "mkdir -p /Program Files/<app>"
    // from a userland Win32 PE — the create path already routed
    // here, but mkdir was DuetFS-only.
    u32 disk_idx = 0;
    const char* disk_rest = nullptr;
    if (!ParseDiskPath(proc->root, path, &disk_idx, &disk_rest))
        return false;
    const fat32::Volume* vol = fat32::Fat32Volume(disk_idx);
    if (vol == nullptr)
        return false;
    if (!fat32::Fat32MkdirAtPath(vol, disk_rest))
        return false;
    ::duetos::subsystems::linux::internal::InotifyPublish(disk_rest, ::duetos::subsystems::linux::internal::kInCreate);
    return true;
}

bool SymlinkForProcess(::duetos::core::Process* proc, const char* path, const char* target)
{
    if (proc == nullptr || path == nullptr || target == nullptr || path[0] == '\0' || target[0] == '\0')
        return false;
    u32 duet_handle = 0;
    const char* duet_sub = nullptr;
    if (!ParseDuetFsPath(proc->root, path, &duet_handle, &duet_sub))
        return false;
    const auto dev = DuetFsDeviceFor(duet_handle);
    u32 new_id = 0;
    const u64 sub_len = PathLen(duet_sub);
    const u64 tgt_len = PathLen(target);
    const u32 st = duetfs_create_symlink(&dev, reinterpret_cast<const u8*>(duet_sub), sub_len + 1,
                                         reinterpret_cast<const u8*>(target), tgt_len + 1, &new_id);
    if (st != duetos::fs::duetfs::kStatusOk)
        return false;
    ::duetos::subsystems::linux::internal::InotifyPublish(duet_sub, ::duetos::subsystems::linux::internal::kInCreate);
    return true;
}

bool LinkForProcess(::duetos::core::Process* proc, const char* existing_path, const char* new_path)
{
    if (proc == nullptr || existing_path == nullptr || new_path == nullptr || existing_path[0] == '\0' ||
        new_path[0] == '\0')
        return false;
    u32 e_handle = 0;
    u32 n_handle = 0;
    const char* e_sub = nullptr;
    const char* n_sub = nullptr;
    if (!ParseDuetFsPath(proc->root, existing_path, &e_handle, &e_sub) ||
        !ParseDuetFsPath(proc->root, new_path, &n_handle, &n_sub))
        return false;
    if (e_handle != n_handle)
        return false; // cross-volume link unsupported
    const auto dev = DuetFsDeviceFor(e_handle);
    const u64 e_len = PathLen(e_sub);
    const u64 n_len = PathLen(n_sub);
    const u32 st =
        duetfs_link(&dev, reinterpret_cast<const u8*>(e_sub), e_len + 1, reinterpret_cast<const u8*>(n_sub), n_len + 1);
    return st == duetos::fs::duetfs::kStatusOk;
}

u64 ReadlinkForProcess(::duetos::core::Process* proc, const char* path, char* dst, u64 dst_max)
{
    if (proc == nullptr || path == nullptr || dst == nullptr || dst_max == 0 || path[0] == '\0')
        return u64(-1);
    u32 duet_handle = 0;
    const char* duet_sub = nullptr;
    if (!ParseDuetFsPath(proc->root, path, &duet_handle, &duet_sub))
        return u64(-1);
    const auto dev = DuetFsDeviceFor(duet_handle);
    duetos::fs::duetfs::LookupResult res{};
    const u64 sub_len = PathLen(duet_sub);
    if (duetfs_lookup(&dev, reinterpret_cast<const u8*>(duet_sub), sub_len + 1, &res) != duetos::fs::duetfs::kStatusOk)
    {
        return u64(-1);
    }
    if (res.kind != duetos::fs::duetfs::kKindSymlink)
        return u64(-1);
    // Reserve one byte for NUL — duetfs_readlink writes raw bytes,
    // so we cap the read to dst_max - 1.
    usize copied = 0;
    if (duetfs_readlink(&dev, res.node_id, dst, dst_max - 1, &copied) != duetos::fs::duetfs::kStatusOk)
        return u64(-1);
    if (copied >= dst_max)
        copied = dst_max - 1;
    dst[copied] = '\0';
    return static_cast<u64>(copied);
}

// ---------------------------------------------------------------
// SelfTest: open /disk/0/HELLO.TXT through the routing facade,
// verify the bytes match what the FAT32 image builder seeded.
// HELLO.TXT is the canonical test artifact — the existing
// `Fat32SelfTest` already proves it round-trips through
// `Fat32ReadFile`; this test asserts the routing layer surfaces
// the same content via the Win32-handle API.
// ---------------------------------------------------------------

void SelfTest()
{
    KLOG_TRACE_SCOPE("fs/route", "SelfTest");
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using ::duetos::core::Process;

    if (fat32::Fat32VolumeCount() == 0)
    {
        SerialWrite("[fs/route-selftest] SKIP (no fat32 volumes registered)\n");
        return;
    }

    // Under a hypervisor, the routing self-test's open / read /
    // seek / write / close cycles each round-trip through the
    // emulated NVMe / AHCI front-end and dominate the boot smoke
    // wall clock. The probe + open-handle path above already
    // proved the routing layer can resolve "/disk/0/HELLO.TXT" to
    // a backing volume and surface its size; the rest of the test
    // is FAT32 R/W coverage that's better served by Fat32SelfTest
    // (also gated under emulator) on bare metal.
    if (::duetos::arch::IsEmulator())
    {
        SerialWrite("[fs/route-selftest] emulator detected — skipping read/write phases (probe only)\n");
        return;
    }

    // Synthesise a thin Process so we can exercise the per-process
    // handle table without dragging the spawn pipeline in. Only the
    // fields the routing layer reads are populated — `pid` for log
    // breadcrumbs, the win32_handles array for slot allocation, and
    // `root` so the ramfs fallback path doesn't deref nullptr if
    // the test ever exercises it.
    static Process s_test_proc = {};
    s_test_proc.pid = 0xFEEDU;
    s_test_proc.root = RamfsTrustedRoot();
    for (u32 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        s_test_proc.win32_handles[i].kind = Process::FsBackingKind::None;
        s_test_proc.win32_handles[i].ramfs_node = nullptr;
        s_test_proc.win32_handles[i].fat32_volume_idx = 0;
        s_test_proc.win32_handles[i].cursor = 0;
    }

    const u64 handle = OpenForProcess(&s_test_proc, "/disk/0/HELLO.TXT");
    if (handle == u64(-1))
    {
        SerialWrite("[fs/route-selftest] FAIL: open /disk/0/HELLO.TXT\n");
        ::duetos::core::Panic("fs/route", "SelfTest open failed");
    }

    // Expected content: image builder seeds HELLO.TXT with
    // "hello from fat32\n" (17 bytes — see
    // tools/qemu/make-gpt-image.py FAT_FILE_BODY). The existing
    // `Fat32SelfTest` runs BEFORE us and mutates the file:
    //   1. in-place rewrite restores bytes [0..5) to "hello"
    //      (lowercase) — same as the original prefix.
    //   2. append grows the file to 17 + 5000 = 5017 bytes,
    //      filling the tail with the A..Z pattern.
    // We assert the post-Fat32-test state: size is 17 + N for
    // some N>=0, and the first 17 bytes match the restored
    // "hello from fat32\n".
    u64 size = 0;
    if (FstatForProcess(&s_test_proc, handle, &size) != 0)
    {
        SerialWrite("[fs/route-selftest] FAIL: fstat\n");
        ::duetos::core::Panic("fs/route", "SelfTest fstat failed");
    }
    if (size < 17)
    {
        SerialWrite("[fs/route-selftest] FAIL: HELLO.TXT size=");
        SerialWriteHex(size);
        SerialWrite(" expected >= 17\n");
        ::duetos::core::Panic("fs/route", "SelfTest size below seed");
    }

    constexpr const char kExpected[] = "hello from fat32\n"; // image-builder seed (FAT_FILE_BODY)
    constexpr u64 kExpLen = sizeof(kExpected) - 1;
    char buf[32];
    for (u64 i = 0; i < sizeof(buf); ++i)
        buf[i] = 0;
    const u64 got = ReadForProcess(&s_test_proc, handle, buf, kExpLen);
    if (got != kExpLen)
    {
        SerialWrite("[fs/route-selftest] FAIL: read returned ");
        SerialWriteHex(got);
        SerialWrite(" want=");
        SerialWriteHex(kExpLen);
        SerialWrite("\n");
        ::duetos::core::Panic("fs/route", "SelfTest read length mismatch");
    }
    for (u64 i = 0; i < kExpLen; ++i)
    {
        if (buf[i] != kExpected[i])
        {
            SerialWrite("[fs/route-selftest] FAIL: byte ");
            SerialWriteHex(i);
            SerialWrite(" got=");
            SerialWriteHex(static_cast<u64>(static_cast<u8>(buf[i])));
            SerialWrite(" want=");
            SerialWriteHex(static_cast<u64>(static_cast<u8>(kExpected[i])));
            SerialWrite("\n");
            ::duetos::core::Panic("fs/route", "SelfTest byte mismatch");
        }
    }

    // Seek to EOF and verify a subsequent read returns 0 (true
    // end-of-file rather than zero-length-read on a fresh handle).
    if (SeekForProcess(&s_test_proc, handle, 0, /*END=*/2) != size)
    {
        SerialWrite("[fs/route-selftest] FAIL: seek to end\n");
        ::duetos::core::Panic("fs/route", "SelfTest seek end mismatch");
    }
    const u64 eof = ReadForProcess(&s_test_proc, handle, buf, sizeof(buf));
    if (eof != 0)
    {
        SerialWrite("[fs/route-selftest] FAIL: post-EOF read returned ");
        SerialWriteHex(eof);
        SerialWrite("\n");
        ::duetos::core::Panic("fs/route", "SelfTest EOF mismatch");
    }

    // Seek-rewind then re-read the prefix to prove SeekForProcess
    // works for fat32-backed handles.
    if (SeekForProcess(&s_test_proc, handle, 0, /*SET=*/0) != 0)
    {
        SerialWrite("[fs/route-selftest] FAIL: seek to 0\n");
        ::duetos::core::Panic("fs/route", "SelfTest seek failed");
    }
    char prefix[6];
    for (u64 i = 0; i < sizeof(prefix); ++i)
        prefix[i] = 0;
    const u64 got2 = ReadForProcess(&s_test_proc, handle, prefix, 5);
    if (got2 != 5 || prefix[0] != 'h' || prefix[4] != 'o')
    {
        SerialWrite("[fs/route-selftest] FAIL: post-seek prefix mismatch\n");
        ::duetos::core::Panic("fs/route", "SelfTest post-seek mismatch");
    }

    CloseForProcess(&s_test_proc, handle);
    if (s_test_proc.win32_handles[handle - Process::kWin32HandleBase].kind != Process::FsBackingKind::None)
    {
        SerialWrite("[fs/route-selftest] FAIL: close did not free slot\n");
        ::duetos::core::Panic("fs/route", "SelfTest close did not free slot");
    }

    // Write + read-back round-trip on HELLO.TXT. Use uppercase
    // "HELLO" to mirror the existing Fat32SelfTest in-place pattern;
    // restore to lowercase at the end so the on-disk fixture matches
    // what the next boot would see (the image is rebuilt every run,
    // but a clean tail keeps the self-test deterministic on reruns
    // against a persistent disk).
    const u64 wh = OpenForProcess(&s_test_proc, "/disk/0/HELLO.TXT");
    if (wh == u64(-1))
        ::duetos::core::Panic("fs/route", "SelfTest reopen for write failed");
    const char kUpper[5] = {'H', 'E', 'L', 'L', 'O'};
    if (WriteForProcess(&s_test_proc, wh, kUpper, 5) != 5)
    {
        SerialWrite("[fs/route-selftest] FAIL: write returned wrong count\n");
        ::duetos::core::Panic("fs/route", "SelfTest write count mismatch");
    }
    if (SeekForProcess(&s_test_proc, wh, 0, /*SET=*/0) != 0)
        ::duetos::core::Panic("fs/route", "SelfTest post-write seek failed");
    char vbuf[6];
    for (u64 i = 0; i < sizeof(vbuf); ++i)
        vbuf[i] = 0;
    if (ReadForProcess(&s_test_proc, wh, vbuf, 5) != 5 || vbuf[0] != 'H' || vbuf[4] != 'O')
    {
        SerialWrite("[fs/route-selftest] FAIL: post-write readback mismatch\n");
        ::duetos::core::Panic("fs/route", "SelfTest post-write readback");
    }
    // Restore so the on-disk content matches the seed prefix.
    if (SeekForProcess(&s_test_proc, wh, 0, /*SET=*/0) != 0)
        ::duetos::core::Panic("fs/route", "SelfTest restore seek failed");
    const char kLower[5] = {'h', 'e', 'l', 'l', 'o'};
    if (WriteForProcess(&s_test_proc, wh, kLower, 5) != 5)
        ::duetos::core::Panic("fs/route", "SelfTest restore write failed");
    CloseForProcess(&s_test_proc, wh);

    // Past-EOF write GROWS the file via Fat32WriteAtPath. Open
    // HELLO.TXT, seek to its end, append one byte, verify the
    // file grew + the new byte reads back.
    const u64 eh = OpenForProcess(&s_test_proc, "/disk/0/HELLO.TXT");
    if (eh == u64(-1))
        ::duetos::core::Panic("fs/route", "SelfTest open-for-eof-write failed");
    u64 esize = 0;
    if (FstatForProcess(&s_test_proc, eh, &esize) != 0)
        ::duetos::core::Panic("fs/route", "SelfTest fstat-for-eof failed");
    if (SeekForProcess(&s_test_proc, eh, 0, /*END=*/2) != esize)
        ::duetos::core::Panic("fs/route", "SelfTest seek-end before eof-write failed");
    if (WriteForProcess(&s_test_proc, eh, "x", 1) != 1)
    {
        SerialWrite("[fs/route-selftest] FAIL: past-EOF growing write returned wrong count\n");
        ::duetos::core::Panic("fs/route", "SelfTest past-EOF growing write count");
    }
    u64 grown = 0;
    if (FstatForProcess(&s_test_proc, eh, &grown) != 0 || grown != esize + 1)
    {
        SerialWrite("[fs/route-selftest] FAIL: file did not grow after past-EOF write\n");
        ::duetos::core::Panic("fs/route", "SelfTest grown size mismatch");
    }
    if (SeekForProcess(&s_test_proc, eh, static_cast<i64>(esize), /*SET=*/0) != esize)
        ::duetos::core::Panic("fs/route", "SelfTest seek before grow-readback failed");
    char gbuf[2] = {0, 0};
    if (ReadForProcess(&s_test_proc, eh, gbuf, 1) != 1 || gbuf[0] != 'x')
    {
        SerialWrite("[fs/route-selftest] FAIL: grown byte didn't read back\n");
        ::duetos::core::Panic("fs/route", "SelfTest grown byte readback");
    }
    // Restore HELLO.TXT to its seed length so subsequent
    // self-tests on the same volume aren't perturbed.
    if (fat32::Fat32TruncateAtPath(fat32::Fat32Volume(0), "/HELLO.TXT", esize) != static_cast<i64>(esize))
    {
        SerialWrite("[fs/route-selftest] WARN: cleanup truncate of HELLO.TXT failed\n");
    }
    CloseForProcess(&s_test_proc, eh);

    // Create + write + readback + delete a brand-new file. The
    // path is unique per boot so a persistent disk doesn't collide
    // across runs — though the FAT32 image is rebuilt each boot in
    // the QEMU smoke today.
    const char* new_path = "/disk/0/RTNEW.TXT";
    const char kSeed[7] = {'r', 'o', 'u', 't', 'i', 'n', 'g'};
    const u64 ch = CreateForProcess(&s_test_proc, new_path, kSeed, 7);
    if (ch == u64(-1))
    {
        SerialWrite("[fs/route-selftest] FAIL: create RTNEW.TXT\n");
        ::duetos::core::Panic("fs/route", "SelfTest create failed");
    }
    u64 csz = 0;
    if (FstatForProcess(&s_test_proc, ch, &csz) != 0 || csz != 7)
    {
        SerialWrite("[fs/route-selftest] FAIL: created file size != 7\n");
        ::duetos::core::Panic("fs/route", "SelfTest created size mismatch");
    }
    char rbuf[8];
    for (u64 i = 0; i < sizeof(rbuf); ++i)
        rbuf[i] = 0;
    if (ReadForProcess(&s_test_proc, ch, rbuf, 7) != 7 || rbuf[0] != 'r' || rbuf[6] != 'g')
    {
        SerialWrite("[fs/route-selftest] FAIL: created file readback mismatch\n");
        ::duetos::core::Panic("fs/route", "SelfTest created readback mismatch");
    }
    CloseForProcess(&s_test_proc, ch);

    // Tidy up so reruns find a clean tree. Delete uses the
    // existing Fat32 path-CRUD API directly — the routing layer
    // doesn't expose Delete in this slice (it would just be a
    // syscall thunk — Fat32 already has the implementation).
    if (!fat32::Fat32DeleteAtPath(fat32::Fat32Volume(0), "/RTNEW.TXT"))
    {
        SerialWrite("[fs/route-selftest] WARN: cleanup delete of RTNEW.TXT failed\n");
        // not fatal — the disk is rebuilt each boot
    }

    SerialWrite("[fs/route-selftest] PASS (open + read + EOF + seek + close + write + create + readback "
                "on /disk/0/HELLO.TXT and /disk/0/RTNEW.TXT)\n");
}

void RamVolFdSelfTest()
{
    using arch::SerialWrite;
    using ::duetos::core::Process;

    auto fail = [&](const char* why)
    {
        SerialWrite("[fs/route-ramvol-selftest] FAIL (");
        SerialWrite(why);
        SerialWrite(")\n");
        (void)duetos::fs::RamVolUnlink("/run/fdtest");
    };

    if (!duetos::fs::RamVolCreate("/run/fdtest"))
    {
        return fail("create");
    }

    static Process p = {};
    p.pid = 0xFEEEU;
    p.root = RamfsTrustedRoot();
    for (u32 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        p.win32_handles[i].kind = Process::FsBackingKind::None;
        p.win32_handles[i].ramfs_node = nullptr;
        p.win32_handles[i].fat32_volume_idx = 0;
        p.win32_handles[i].cursor = 0;
    }

    const char msg[] = "ramvol-fd-roundtrip";
    const u64 mlen = sizeof(msg) - 1;

    u64 h = OpenForProcess(&p, "/run/fdtest");
    if (h == u64(-1))
    {
        return fail("open");
    }
    if (WriteForProcess(&p, h, msg, mlen) != mlen)
    {
        CloseForProcess(&p, h);
        return fail("write");
    }
    u64 sz = 0;
    if (FstatForProcess(&p, h, &sz) != 0 || sz != mlen)
    {
        CloseForProcess(&p, h);
        return fail("fstat size");
    }
    CloseForProcess(&p, h);

    // Reopen so the cursor restarts at 0 (avoids depending on a
    // particular SEEK_* whence constant — keeps the test minimal).
    h = OpenForProcess(&p, "/run/fdtest");
    if (h == u64(-1))
    {
        return fail("reopen");
    }
    char buf[32];
    const u64 got = ReadForProcess(&p, h, buf, sizeof(buf));
    CloseForProcess(&p, h);
    if (got != mlen)
    {
        return fail("read len");
    }
    for (u64 i = 0; i < mlen; ++i)
    {
        if (buf[i] != msg[i])
        {
            return fail("read mismatch");
        }
    }

    (void)duetos::fs::RamVolUnlink("/run/fdtest");
    SerialWrite("[fs/route-ramvol-selftest] PASS\n");
}

} // namespace duetos::fs::routing
