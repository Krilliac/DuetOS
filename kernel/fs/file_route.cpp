#include "file_route.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../core/process.h"
#include "fat32.h"
#include "ramfs.h"
#include "vfs.h"

namespace customos::fs::routing
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

// Parse "/disk/<idx>/<rest>" → (idx, pointer-into-path-at-rest).
// Returns false on any malformed prefix (no digits, no separator
// after the index). On a non-disk prefix returns false silently —
// the caller treats that as "use ramfs."
bool ParseDiskPath(const char* path, u32* out_idx, const char** out_rest)
{
    if (path == nullptr)
        return false;
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
    *out_idx = idx;
    *out_rest = path + cursor; // include the leading '/' so Fat32LookupPath sees an absolute path
    return true;
}

// Find a free Win32 handle slot on `proc`. Returns kWin32HandleCap
// when none are free.
u64 FindFreeSlot(::customos::core::Process* proc)
{
    using ::customos::core::Process;
    for (u64 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        if (proc->win32_handles[i].kind == Process::FsBackingKind::None)
            return i;
    }
    return Process::kWin32HandleCap;
}

// Validate handle id, return slot index or u64(-1).
u64 HandleToSlot(u64 handle)
{
    using ::customos::core::Process;
    if (handle < Process::kWin32HandleBase || handle >= Process::kWin32HandleBase + Process::kWin32HandleCap)
        return u64(-1);
    return handle - Process::kWin32HandleBase;
}

// Per-handle byte size accessor — both backings know it.
u64 HandleSize(const ::customos::core::Process::Win32FileHandle& h)
{
    using ::customos::core::Process;
    if (h.kind == Process::FsBackingKind::Ramfs && h.ramfs_node != nullptr)
        return h.ramfs_node->file_size;
    if (h.kind == Process::FsBackingKind::Fat32)
        return h.fat32_entry.size_bytes;
    return 0;
}

} // namespace

u64 OpenForProcess(::customos::core::Process* proc, const char* path)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using ::customos::core::Process;
    if (proc == nullptr || path == nullptr)
        return u64(-1);

    u32 disk_idx = 0;
    const char* disk_rest = nullptr;
    const bool routed = ParseDiskPath(path, &disk_idx, &disk_rest);

    const u64 slot = FindFreeSlot(proc);
    if (slot == Process::kWin32HandleCap)
    {
        SerialWrite("[fs/route] open out-of-handles pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
        return u64(-1);
    }
    Process::Win32FileHandle& h = proc->win32_handles[slot];

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

u64 ReadForProcess(::customos::core::Process* proc, u64 handle, void* dst, u64 len)
{
    using ::customos::core::Process;
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

u64 SeekForProcess(::customos::core::Process* proc, u64 handle, i64 offset, u32 whence)
{
    using ::customos::core::Process;
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

u64 FstatForProcess(::customos::core::Process* proc, u64 handle, u64* out_size)
{
    using ::customos::core::Process;
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

u64 CloseForProcess(::customos::core::Process* proc, u64 handle)
{
    using ::customos::core::Process;
    if (proc == nullptr)
        return 0;
    const u64 slot = HandleToSlot(handle);
    if (slot == u64(-1))
        return 0;
    Process::Win32FileHandle& h = proc->win32_handles[slot];
    h.kind = Process::FsBackingKind::None;
    h.ramfs_node = nullptr;
    h.fat32_volume_idx = 0;
    h.cursor = 0;
    return 0;
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
    using ::customos::core::Process;

    if (fat32::Fat32VolumeCount() == 0)
    {
        SerialWrite("[fs/route-selftest] SKIP (no fat32 volumes registered)\n");
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
        ::customos::core::Panic("fs/route", "SelfTest open failed");
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
        ::customos::core::Panic("fs/route", "SelfTest fstat failed");
    }
    if (size < 17)
    {
        SerialWrite("[fs/route-selftest] FAIL: HELLO.TXT size=");
        SerialWriteHex(size);
        SerialWrite(" expected >= 17\n");
        ::customos::core::Panic("fs/route", "SelfTest size below seed");
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
        ::customos::core::Panic("fs/route", "SelfTest read length mismatch");
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
            ::customos::core::Panic("fs/route", "SelfTest byte mismatch");
        }
    }

    // Seek to EOF and verify a subsequent read returns 0 (true
    // end-of-file rather than zero-length-read on a fresh handle).
    if (SeekForProcess(&s_test_proc, handle, 0, /*END=*/2) != size)
    {
        SerialWrite("[fs/route-selftest] FAIL: seek to end\n");
        ::customos::core::Panic("fs/route", "SelfTest seek end mismatch");
    }
    const u64 eof = ReadForProcess(&s_test_proc, handle, buf, sizeof(buf));
    if (eof != 0)
    {
        SerialWrite("[fs/route-selftest] FAIL: post-EOF read returned ");
        SerialWriteHex(eof);
        SerialWrite("\n");
        ::customos::core::Panic("fs/route", "SelfTest EOF mismatch");
    }

    // Seek-rewind then re-read the prefix to prove SeekForProcess
    // works for fat32-backed handles.
    if (SeekForProcess(&s_test_proc, handle, 0, /*SET=*/0) != 0)
    {
        SerialWrite("[fs/route-selftest] FAIL: seek to 0\n");
        ::customos::core::Panic("fs/route", "SelfTest seek failed");
    }
    char prefix[6];
    for (u64 i = 0; i < sizeof(prefix); ++i)
        prefix[i] = 0;
    const u64 got2 = ReadForProcess(&s_test_proc, handle, prefix, 5);
    if (got2 != 5 || prefix[0] != 'h' || prefix[4] != 'o')
    {
        SerialWrite("[fs/route-selftest] FAIL: post-seek prefix mismatch\n");
        ::customos::core::Panic("fs/route", "SelfTest post-seek mismatch");
    }

    CloseForProcess(&s_test_proc, handle);
    if (s_test_proc.win32_handles[handle - Process::kWin32HandleBase].kind != Process::FsBackingKind::None)
    {
        SerialWrite("[fs/route-selftest] FAIL: close did not free slot\n");
        ::customos::core::Panic("fs/route", "SelfTest close did not free slot");
    }

    SerialWrite("[fs/route-selftest] PASS (open + size + read + EOF + seek + close on /disk/0/HELLO.TXT)\n");
}

} // namespace customos::fs::routing
