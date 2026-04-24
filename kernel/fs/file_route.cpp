#include "file_route.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../core/process.h"
#include "fat32.h"
#include "ramfs.h"
#include "vfs.h"

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
u64 HandleToSlot(u64 handle)
{
    using ::duetos::core::Process;
    if (handle < Process::kWin32HandleBase || handle >= Process::kWin32HandleBase + Process::kWin32HandleCap)
        return u64(-1);
    return handle - Process::kWin32HandleBase;
}

// Per-handle byte size accessor — both backings know it.
u64 HandleSize(const ::duetos::core::Process::Win32FileHandle& h)
{
    using ::duetos::core::Process;
    if (h.kind == Process::FsBackingKind::Ramfs && h.ramfs_node != nullptr)
        return h.ramfs_node->file_size;
    if (h.kind == Process::FsBackingKind::Fat32)
        return h.fat32_entry.size_bytes;
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

    if (h.kind == Process::FsBackingKind::Ramfs)
        return u64(-1); // ramfs is .rodata

    // Fat32 backing. v0 is in-place only — past-EOF writes need
    // append + dir-entry-size update which Fat32WriteInPlace
    // refuses. Cap `len` at remaining bytes; signal short-write
    // by returning the actual count (matches POSIX ssize_t).
    const u64 size = h.fat32_entry.size_bytes;
    if (h.cursor >= size)
        return u64(-1); // EOF — no growth in this slice
    const u64 remaining = size - h.cursor;
    const u64 take = (len < remaining) ? len : remaining;

    const fat32::Volume* vol = fat32::Fat32Volume(h.fat32_volume_idx);
    if (vol == nullptr)
        return u64(-1);
    const i64 wrote = fat32::Fat32WriteInPlace(vol, &h.fat32_entry, h.cursor, src, take);
    if (wrote < 0)
        return u64(-1);
    h.cursor += u64(wrote);
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
    if (!ParseDiskPath(path, &disk_idx, &disk_rest))
    {
        SerialWrite("[fs/route] create: ramfs path rejected (read-only) \"");
        SerialWrite(path);
        SerialWrite("\"\n");
        return u64(-1);
    }

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
    using ::duetos::core::Process;

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

    // Past-EOF write must fail without growing the file. Open
    // HELLO.TXT, seek past end, attempt write — expect u64(-1).
    const u64 eh = OpenForProcess(&s_test_proc, "/disk/0/HELLO.TXT");
    if (eh == u64(-1))
        ::duetos::core::Panic("fs/route", "SelfTest open-for-eof-write failed");
    u64 esize = 0;
    if (FstatForProcess(&s_test_proc, eh, &esize) != 0)
        ::duetos::core::Panic("fs/route", "SelfTest fstat-for-eof failed");
    if (SeekForProcess(&s_test_proc, eh, 0, /*END=*/2) != esize)
        ::duetos::core::Panic("fs/route", "SelfTest seek-end before eof-write failed");
    if (WriteForProcess(&s_test_proc, eh, "x", 1) != u64(-1))
    {
        SerialWrite("[fs/route-selftest] FAIL: past-EOF write should fail\n");
        ::duetos::core::Panic("fs/route", "SelfTest past-EOF write should fail");
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

} // namespace duetos::fs::routing
