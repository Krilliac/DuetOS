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

} // namespace duetos::subsystems::win32
