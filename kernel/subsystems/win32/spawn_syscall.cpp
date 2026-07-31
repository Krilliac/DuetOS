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
#include "fs/file_route.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "proc/spawn.h"
#include "syscall/cap_gate.h"
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
    using ::duetos::core::kCapFsRead;
    using ::duetos::core::kCapSpawnThread;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;
    core::CapSet child_caps = core::CapSetEmpty();
    core::CapSet child_ceiling = core::CapSetEmpty();
    core::CapSet spawn_authority = core::CapSetEmpty();
    const u64 required_caps = core::RequiredCapMask(core::SYS_PROCESS_SPAWN);
    if (!core::ProcessCaptureSpawnAuthority(caller, required_caps, &child_caps, &child_ceiling, &spawn_authority))
    {
        core::RecordSandboxDenial(core::CapSetHas(spawn_authority, kCapFsRead) ? kCapSpawnThread : kCapFsRead);
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
        pid = core::SpawnPeFile(name, bytes, file_len, child_caps, caller->root, kFrameBudget, caller->tick_budget,
                                child_ceiling);
    else
        pid = core::SpawnElfFile(name, bytes, file_len, child_caps, caller->root, kFrameBudget, caller->tick_budget,
                                 child_ceiling);

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
bool SnapshotParentHandleKind(::duetos::core::Process* parent, u64 raw_handle,
                              ::duetos::core::Process::FsBackingKind* kind_out)
{
    using ::duetos::core::Process;
    if (parent == nullptr || kind_out == nullptr || raw_handle < Process::kWin32HandleBase)
        return false;
    const u64 idx = raw_handle - Process::kWin32HandleBase;
    if (idx >= Process::kWin32HandleCap)
        return false;
    const sync::IrqFlags lock_flags = sync::SpinLockAcquire(parent->win32_file_lock);
    const Process::FsBackingKind kind = parent->win32_handles[idx].kind;
    sync::SpinLockRelease(parent->win32_file_lock, lock_flags);
    if (kind == Process::FsBackingKind::None || kind == Process::FsBackingKind::Reserved)
        return false;
    *kind_out = kind;
    return true;
}

// Duplicate a single parent slot into the first free child slot.
// Returns the assigned child handle (kWin32HandleBase + slot)
// on success, 0 on any failure (table-full / unsupported kind).
// Pipe handles bump the per-end pool refcount so the child holds
// its own reference.
u64 InheritOneStdHandle(::duetos::core::Process* parent, ::duetos::core::Process* child, u64 parent_handle)
{
    return ::duetos::fs::routing::DuplicateForChild(parent, parent_handle, child);
#if 0 // Replaced by the atomic routing-layer duplicate above.
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
    // Registry ownership does NOT ride along. Only the handle that
    // CreateNamedPipe stamped is the server-end owner; the child
    // holds an ordinary pipe end, exactly like a client opened via
    // DoNamedPipeOpen (named_pipe_syscall.cpp, registry_slot=-1).
    //
    // Copying the slot made the child a second, co-equal owner: its
    // FIRST CloseHandle ran the WHOLE server teardown while the
    // parent still held a live server handle — unregistering the
    // name so no client could ever connect, and (when no client had
    // connected yet) dropping the opposite-end reservation ref, so
    // the parent's own WriteFile on its own untouched handle
    // returned kEpipe forever. A recycled slot index made it worse
    // still: the teardown then landed on an UNRELATED process's
    // registration.
    //
    // Refcounting needs no other change — the retain below is
    // per-end, and the child's CloseForProcess does exactly one
    // matching per-end release. Only the registry housekeeping must
    // not be duplicated.
    dst.named_pipe_registry_slot = -1;
    dst.named_pipe_registry_gen = 0;
    // `is_canary` deliberately rides along with the copy above. The
    // by-handle canary wall (fs/file_route.cpp WriteForProcess) is
    // the only tripwire an in-place overwrite has, because the write
    // syscall carries no path string. Clearing it here let a parent
    // disarm the wall by opening a canary-stamped file and handing
    // the handle to a child as stdout.

    if (src.kind == Process::FsBackingKind::Pipe)
    {
        if (src.pipe_is_write_end)
            ::duetos::subsystems::linux::internal::PipeRetainWrite(src.pipe_pool_idx);
        else
            ::duetos::subsystems::linux::internal::PipeRetainRead(src.pipe_pool_idx);
    }
    return Process::kWin32HandleBase + child_slot;
#endif
}

struct SpawnStdioPrepareContext
{
    ::duetos::core::Process* parent;
    ::duetos::core::ProcessSpawnStdio bundle;
};

bool PrepareChildStdio(::duetos::core::Process* child, void* raw_context)
{
    using ::duetos::core::Process;
    auto* context = static_cast<SpawnStdioPrepareContext*>(raw_context);
    if (child == nullptr || context == nullptr || context->parent == nullptr)
        return false;

    const u64 parent_std[3] = {context->bundle.stdin_handle, context->bundle.stdout_handle,
                               context->bundle.stderr_handle};
    u64 inherited[3] = {0, 0, 0};
    for (u64 i = 0; i < 3; ++i)
    {
        bool aliased = false;
        for (u64 j = 0; j < i && !aliased; ++j)
        {
            if (parent_std[i] != 0 && parent_std[j] == parent_std[i])
            {
                inherited[i] = inherited[j];
                aliased = true;
            }
        }
        if (!aliased)
        {
            inherited[i] = InheritOneStdHandle(context->parent, child, parent_std[i]);
            if (parent_std[i] != 0 && inherited[i] == 0)
                return false;
        }
    }
    child->std_handles[0] = inherited[0];
    child->std_handles[1] = inherited[1];
    child->std_handles[2] = inherited[2];
    return true;
}

} // namespace

i64 SysProcessSpawnEx(u64 user_path, u64 flags, u64 user_stdio_bundle)
{
    (void)flags;
    using ::duetos::core::kCapFsRead;
    using ::duetos::core::kCapSpawnThread;
    using ::duetos::core::Process;
    using ::duetos::core::ProcessSpawnStdio;

    Process* caller = ::duetos::core::CurrentProcess();
    if (caller == nullptr)
        return -1;
    ::duetos::core::CapSet child_caps = ::duetos::core::CapSetEmpty();
    ::duetos::core::CapSet child_ceiling = ::duetos::core::CapSetEmpty();
    ::duetos::core::CapSet spawn_authority = ::duetos::core::CapSetEmpty();
    const u64 required_caps = ::duetos::core::RequiredCapMask(::duetos::core::SYS_PROCESS_SPAWN_EX);
    if (!::duetos::core::ProcessCaptureSpawnAuthority(caller, required_caps, &child_caps, &child_ceiling,
                                                      &spawn_authority))
    {
        ::duetos::core::RecordSandboxDenial(::duetos::core::CapSetHas(spawn_authority, kCapFsRead) ? kCapSpawnThread
                                                                                                   : kCapFsRead);
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
            Process::FsBackingKind kind = Process::FsBackingKind::None;
            if (!SnapshotParentHandleKind(caller, candidates[i], &kind))
                return -1;
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
    SpawnStdioPrepareContext prepare_context{caller, bundle};
    const ::duetos::core::SpawnPrepareCallback prepare = have_bundle ? &PrepareChildStdio : nullptr;
    void* const prepare_arg = have_bundle ? static_cast<void*>(&prepare_context) : nullptr;
    u64 pid = 0;
    if (fmt == 1)
        pid = ::duetos::core::SpawnPeFile(name, bytes, file_len, child_caps, caller->root, kFrameBudget,
                                          caller->tick_budget, child_ceiling, /*origin_volume=*/0,
                                          /*origin_path=*/nullptr, prepare, prepare_arg);
    else
        pid = ::duetos::core::SpawnElfFile(name, bytes, file_len, child_caps, caller->root, kFrameBudget,
                                           caller->tick_budget, child_ceiling, prepare, prepare_arg);
    ::duetos::mm::KFree(bytes);

    if (pid == 0 || pid == static_cast<u64>(-1))
        return -1;

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
