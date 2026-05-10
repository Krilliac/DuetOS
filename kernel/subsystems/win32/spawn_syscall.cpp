/*
 * Win32 / Linux subprocess spawn — SYS_PROCESS_SPAWN.
 *
 * Backs kernel32.CreateProcessA / CreateProcessW and (eventually)
 * NtCreateUserProcess once ProcessParameters parsing lands. v0
 * takes a single path argument and spawns a fresh Process running
 * the named PE or ELF.
 *
 * Routing:
 *   - "/disk/<idx>/<rest>" → FAT32 read, autodetect PE / ELF by
 *     magic bytes, dispatch to SpawnPeFile / SpawnElfFile / SpawnElfLinux.
 *   - Anything else → -1 (no ramfs spawn path; ramfs PEs are
 *     baked-in arrays).
 *
 * Cap-gated on kCapSpawnThread (same threat class as a fresh
 * thread + the AS + the file read). Caller-inheritance flag
 * picks between caller's caps (default — fresh process inherits)
 * and trusted (only when caller already had trusted profile).
 *
 * Returns the new process's PID, or -1 on failure. Caller wraps
 * the PID via NtOpenProcess(PID) → process handle.
 */

#include "subsystems/win32/spawn_syscall.h"

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "proc/ring3_smoke.h"
#include "sched/sched.h"
#include "subsystems/linux/syscall_pipe.h"
#include "syscall/syscall.h"

namespace duetos::subsystems::win32
{

namespace
{

// Strip a "/disk/<idx>/" prefix; returns the volume index + a
// pointer past the prefix on hit. Returns false on miss.
bool ParseDiskPath(const char* path, u32& out_idx, const char*& out_rest)
{
    if (path == nullptr)
        return false;
    if (path[0] != '/' || path[1] != 'd' || path[2] != 'i' || path[3] != 's' || path[4] != 'k' || path[5] != '/')
        return false;
    const char* p = path + 6;
    u32 idx = 0;
    bool any = false;
    while (*p >= '0' && *p <= '9')
    {
        idx = idx * 10 + static_cast<u32>(*p - '0');
        any = true;
        ++p;
    }
    if (!any)
        return false;
    if (*p != '/' && *p != '\0')
        return false;
    out_idx = idx;
    out_rest = p;
    return true;
}

// Read a file's entire contents into a KMalloc'd buffer. Caller
// owns the buffer and must KFree it. Returns nullptr on miss.
u8* ReadFileToHeap(const char* path, u64& out_len)
{
    u32 disk_idx = 0;
    const char* rest = nullptr;
    if (!ParseDiskPath(path, disk_idx, rest))
        return nullptr;
    const auto* v = fs::fat32::Fat32Volume(disk_idx);
    if (v == nullptr)
        return nullptr;
    fs::fat32::DirEntry e;
    if (!fs::fat32::Fat32LookupPath(v, rest, &e))
        return nullptr;
    if (e.attributes & 0x10) // directory
        return nullptr;
    if (e.size_bytes == 0 || e.size_bytes > 16ull * 1024 * 1024)
        return nullptr; // refuse zero / oversized
    auto* buf = static_cast<u8*>(mm::KMalloc(e.size_bytes));
    if (buf == nullptr)
        return nullptr;
    const i64 got = fs::fat32::Fat32ReadFile(v, &e, buf, e.size_bytes);
    if (got < 0 || static_cast<u64>(got) != e.size_bytes)
    {
        mm::KFree(buf);
        return nullptr;
    }
    out_len = e.size_bytes;
    return buf;
}

// Detect PE vs ELF by magic. Returns:
//   1 = PE (MZ at offset 0)
//   2 = ELF (0x7F E L F at offset 0)
//   0 = unknown
i32 DetectFormat(const u8* bytes, u64 len)
{
    if (len < 4)
        return 0;
    if (bytes[0] == 'M' && bytes[1] == 'Z')
        return 1;
    if (bytes[0] == 0x7F && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F')
        return 2;
    return 0;
}

// Extract a leaf name from a path for the spawned process's
// `name` field. Caller-owned static buffer.
const char* LeafName(const char* path, char (&buf)[32])
{
    const char* leaf = path;
    for (const char* p = path; *p != '\0'; ++p)
        if (*p == '/' || *p == '\\')
            leaf = p + 1;
    u32 i = 0;
    for (; i < sizeof(buf) - 1 && leaf[i] != '\0'; ++i)
        buf[i] = leaf[i];
    buf[i] = '\0';
    return buf;
}

} // namespace

i64 SysProcessSpawn(u64 user_path, u64 flags)
{
    (void)flags;
    using ::duetos::core::CapSetHas;
    using ::duetos::core::kCapSpawnThread;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;
    if (!CapSetHas(caller->caps, kCapSpawnThread))
    {
        core::RecordSandboxDenial(kCapSpawnThread);
        return -1;
    }
    char path[128];
    if (!mm::CopyUserCString(path, sizeof(path), reinterpret_cast<const void*>(user_path)).ok())
        return -1;

    u64 file_len = 0;
    u8* bytes = ReadFileToHeap(path, file_len);
    if (bytes == nullptr)
    {
        arch::SerialWrite("[win32/spawn] read failed path=\"");
        arch::SerialWrite(path);
        arch::SerialWrite("\"\n");
        return -1;
    }
    const i32 fmt = DetectFormat(bytes, file_len);
    if (fmt == 0)
    {
        mm::KFree(bytes);
        return -1;
    }
    char namebuf[32];
    const char* name = LeafName(path, namebuf);
    // Inherit caller's caps + root + tick budget. Fresh process
    // gets its own PID and AS via the existing spawn helpers.
    constexpr u64 kFrameBudget = 256;
    u64 pid = 0;
    if (fmt == 1)
        pid = core::SpawnPeFile(name, bytes, file_len, caller->caps, caller->root, kFrameBudget, caller->tick_budget);
    else
        pid = core::SpawnElfFile(name, bytes, file_len, caller->caps, caller->root, kFrameBudget, caller->tick_budget);

    // SpawnPeFile / SpawnElfFile copy the bytes (or load section by
    // section into the new AS); the caller's heap buffer is no
    // longer needed after spawn returns.
    mm::KFree(bytes);

    if (pid == 0 || pid == static_cast<u64>(-1))
        return -1;
    arch::SerialWrite("[win32/spawn] ok pid=");
    arch::SerialWriteHex(pid);
    arch::SerialWrite(" path=\"");
    arch::SerialWrite(path);
    arch::SerialWrite("\" fmt=");
    arch::SerialWriteHex(static_cast<u64>(fmt));
    arch::SerialWrite("\n");
    return static_cast<i64>(pid);
}

namespace
{

// Resolve a Win32-shaped handle in `parent` to its win32_handles
// slot index. Returns Process::kWin32HandleCap if the handle is
// not a valid file/pipe handle in this process. Used by the
// stdio-inheritance path to copy the parent's slot into the
// child's table.
u64 ResolveParentHandleSlot(::duetos::core::Process* parent, u64 raw_handle)
{
    using ::duetos::core::Process;
    if (raw_handle < Process::kWin32HandleBase)
        return Process::kWin32HandleCap;
    const u64 idx = raw_handle - Process::kWin32HandleBase;
    if (idx >= Process::kWin32HandleCap)
        return Process::kWin32HandleCap;
    if (parent->win32_handles[idx].kind == Process::FsBackingKind::None)
        return Process::kWin32HandleCap;
    return idx;
}

// Find a free Win32FileHandle slot in `child`. Returns the slot
// index or Process::kWin32HandleCap if the table is full.
u64 ChildFindFreeSlot(::duetos::core::Process* child)
{
    using ::duetos::core::Process;
    for (u64 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        if (child->win32_handles[i].kind == Process::FsBackingKind::None)
            return i;
    }
    return Process::kWin32HandleCap;
}

// Duplicate a single parent slot into the first free child slot.
// Returns the assigned child handle (kWin32HandleBase + slot)
// on success, 0 on any failure (table-full / unsupported kind).
// Pipe handles bump the per-end pool refcount so the child holds
// its own reference.
u64 InheritOneStdHandle(::duetos::core::Process* parent, ::duetos::core::Process* child, u64 parent_handle)
{
    using ::duetos::core::Process;
    if (parent_handle == 0)
        return 0;
    const u64 parent_slot = ResolveParentHandleSlot(parent, parent_handle);
    if (parent_slot == Process::kWin32HandleCap)
        return 0;
    const u64 child_slot = ChildFindFreeSlot(child);
    if (child_slot == Process::kWin32HandleCap)
        return 0;
    const auto& src = parent->win32_handles[parent_slot];
    auto& dst = child->win32_handles[child_slot];
    dst = src;      // copy-by-value — fat32_path / pipe_pool_idx / cursor follow
    dst.cursor = 0; // child reads from start (Win32 contract: inherited handles don't share cursor)
    dst.is_canary = false;

    if (src.kind == Process::FsBackingKind::Pipe)
    {
        if (src.pipe_is_write_end)
            ::duetos::subsystems::linux::internal::PipeRetainWrite(src.pipe_pool_idx);
        else
            ::duetos::subsystems::linux::internal::PipeRetainRead(src.pipe_pool_idx);
    }
    return Process::kWin32HandleBase + child_slot;
}

} // namespace

i64 SysProcessSpawnEx(u64 user_path, u64 flags, u64 user_stdio_bundle)
{
    (void)flags;
    using ::duetos::core::CapSetHas;
    using ::duetos::core::kCapSpawnThread;
    using ::duetos::core::Process;
    using ::duetos::core::ProcessSpawnStdio;

    Process* caller = ::duetos::core::CurrentProcess();
    if (caller == nullptr)
        return -1;
    if (!CapSetHas(caller->caps, kCapSpawnThread))
    {
        ::duetos::core::RecordSandboxDenial(kCapSpawnThread);
        return -1;
    }

    char path[128];
    if (!::duetos::mm::CopyUserCString(path, sizeof(path), reinterpret_cast<const void*>(user_path)).ok())
        return -1;

    // Optionally copy the bundle. Zero pointer = no inheritance.
    ProcessSpawnStdio bundle{};
    bool have_bundle = false;
    if (user_stdio_bundle != 0)
    {
        if (!::duetos::mm::CopyFromUser(&bundle, reinterpret_cast<const void*>(user_stdio_bundle), sizeof(bundle)))
            return -1;
        have_bundle = true;
    }

    // Pre-validate every supplied parent handle BEFORE spawning so
    // a bad handle aborts cleanly (no half-spawned child to tear
    // down). Pipe handles aren't refcounted yet — the retain only
    // happens after we know the child slot is reserved.
    if (have_bundle)
    {
        const u64 candidates[3] = {bundle.stdin_handle, bundle.stdout_handle, bundle.stderr_handle};
        for (u64 i = 0; i < 3; ++i)
        {
            if (candidates[i] == 0)
                continue;
            const u64 slot = ResolveParentHandleSlot(caller, candidates[i]);
            if (slot == Process::kWin32HandleCap)
                return -1;
            const auto kind = caller->win32_handles[slot].kind;
            // v0 supports inheriting Pipe / Fat32 / Ramfs / DuetFs
            // — same set the child can already operate on through
            // the file-route layer.
            if (kind != Process::FsBackingKind::Pipe && kind != Process::FsBackingKind::Fat32 &&
                kind != Process::FsBackingKind::Ramfs && kind != Process::FsBackingKind::DuetFs)
                return -1;
        }
    }

    u64 file_len = 0;
    u8* bytes = ReadFileToHeap(path, file_len);
    if (bytes == nullptr)
    {
        arch::SerialWrite("[win32/spawn-ex] read failed path=\"");
        arch::SerialWrite(path);
        arch::SerialWrite("\"\n");
        return -1;
    }
    const i32 fmt = DetectFormat(bytes, file_len);
    if (fmt == 0)
    {
        ::duetos::mm::KFree(bytes);
        return -1;
    }
    char namebuf[32];
    const char* name = LeafName(path, namebuf);
    constexpr u64 kFrameBudget = 256;
    u64 pid = 0;
    if (fmt == 1)
        pid = ::duetos::core::SpawnPeFile(name, bytes, file_len, caller->caps, caller->root, kFrameBudget,
                                          caller->tick_budget);
    else
        pid = ::duetos::core::SpawnElfFile(name, bytes, file_len, caller->caps, caller->root, kFrameBudget,
                                           caller->tick_budget);
    ::duetos::mm::KFree(bytes);

    if (pid == 0 || pid == static_cast<u64>(-1))
        return -1;

    // Stitch the inheritable handles into the freshly-created
    // child. SpawnPeFile / SpawnElfFile have already created the
    // child Process and registered it; we look it up by pid.
    if (have_bundle)
    {
        Process* child = ::duetos::sched::SchedFindProcessByPid(pid);
        if (child != nullptr)
        {
            const u64 inherited_in = InheritOneStdHandle(caller, child, bundle.stdin_handle);
            const u64 inherited_out = InheritOneStdHandle(caller, child, bundle.stdout_handle);
            const u64 inherited_err = InheritOneStdHandle(caller, child, bundle.stderr_handle);
            child->std_handles[0] = inherited_in;
            child->std_handles[1] = inherited_out;
            child->std_handles[2] = inherited_err;
        }
    }

    arch::SerialWrite("[win32/spawn-ex] ok pid=");
    arch::SerialWriteHex(pid);
    arch::SerialWrite(" path=\"");
    arch::SerialWrite(path);
    arch::SerialWrite("\" stdio=");
    arch::SerialWriteHex(have_bundle ? 1 : 0);
    arch::SerialWrite("\n");
    return static_cast<i64>(pid);
}

} // namespace duetos::subsystems::win32
