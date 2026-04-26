/*
 * DuetOS — kernel-side Win32 registry: implementation.
 *
 * See registry.h for the public contract + the v0 scope statement
 * (read-only, well-known keys only). The static tree mirrors the
 * one in userland/libs/advapi32/advapi32.c on purpose — until the
 * advapi32 build can include kernel headers, sharing one C source
 * isn't possible without disturbing the freestanding userland
 * build invariant. Drift between the two trees is bounded by a
 * comment in each: changes here MUST be mirrored to advapi32.c
 * in the same commit (and vice versa).
 */

#include "subsystems/win32/registry.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"

namespace duetos::subsystems::win32::registry
{

namespace
{

// Mirrors advapi32.c::RegValue. Sized to the smallest natural
// kernel layout — `data` borrows the ROM constants below, never
// owns. `dword_imm` is the storage backing REG_DWORD/REG_QWORD
// payloads.
struct RegValue
{
    const char* name;
    u32 type;
    u32 size;
    const void* data;
    u32 dword_imm;
};

struct RegKey
{
    u64 root;         // predefined HKEY sentinel (kHkey*) the key hangs off
    const char* path; // backslash-separated subkey path (case-insensitive at lookup)
    const RegValue* values;
    u32 value_count;
};

// DWORD-immediate storage — values of REG_DWORD point at these.
constexpr u32 kProxyEnableDword = 0;
constexpr u32 kVersionMajorDword = 10;

// HKLM\Software\Microsoft\Windows NT\CurrentVersion mirror. The
// values here MUST match advapi32.c's k_hklm_winnt_values. Adding
// a value here without doing the same in advapi32.c means PEs
// going through Reg* see one answer and PEs going through Nt*
// see another — silent inconsistency.
constexpr RegValue kHklmWinNtValues[] = {
    {"ProductName", kRegSz, 7, "DuetOS\0", 0},
    {"CurrentVersion", kRegSz, 5, "10.0\0", 0},
    {"CurrentBuild", kRegSz, 6, "19041\0", 0},
    {"CurrentBuildNumber", kRegSz, 6, "19041\0", 0},
    {"BuildLab", kRegSz, 13, "19041.duetos\0", 0},
    {"InstallationType", kRegSz, 7, "Client\0", 0},
    {"ReleaseId", kRegSz, 5, "2004\0", 0},
    {"EditionID", kRegSz, 13, "Professional\0", 0},
    {"CurrentMajorVersionNumber", kRegDword, 4, &kVersionMajorDword, 10},
};

constexpr RegValue kHkcuInternetValues[] = {
    {"ProxyEnable", kRegDword, 4, &kProxyEnableDword, 0},
};

constexpr RegValue kHkcuVolatileEnvValues[] = {
    {"USERNAME", kRegSz, 5, "user\0", 0},
    {"USERDOMAIN", kRegSz, 7, "DUETOS\0", 0},
};

constexpr RegKey kRegKeys[] = {
    {kHkeyLocalMachine, "Software\\Microsoft\\Windows NT\\CurrentVersion", kHklmWinNtValues,
     static_cast<u32>(sizeof(kHklmWinNtValues) / sizeof(kHklmWinNtValues[0]))},
    {kHkeyLocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion", kHklmWinNtValues,
     static_cast<u32>(sizeof(kHklmWinNtValues) / sizeof(kHklmWinNtValues[0]))},
    {kHkeyCurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", kHkcuInternetValues,
     static_cast<u32>(sizeof(kHkcuInternetValues) / sizeof(kHkcuInternetValues[0]))},
    {kHkeyCurrentUser, "Volatile Environment", kHkcuVolatileEnvValues,
     static_cast<u32>(sizeof(kHkcuVolatileEnvValues) / sizeof(kHkcuVolatileEnvValues[0]))},
};

constexpr u64 kRegKeyCount = sizeof(kRegKeys) / sizeof(kRegKeys[0]);

// Win32 NTSTATUS values used by the registry surface. Spelled out
// here so registry.cpp stays decoupled from any "NTSTATUS table"
// elsewhere — the set the registry returns is small and stable.
constexpr i64 kNtStatusSuccess = 0x00000000;
constexpr i64 kNtStatusObjectNameNotFound = static_cast<i64>(static_cast<u32>(0xC0000034));
constexpr i64 kNtStatusInvalidHandle = static_cast<i64>(static_cast<u32>(0xC0000008));
constexpr i64 kNtStatusInvalidParameter = static_cast<i64>(static_cast<u32>(0xC000000D));
constexpr i64 kNtStatusBufferTooSmall = static_cast<i64>(static_cast<u32>(0xC0000023));

inline char AsciiToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return static_cast<char>(c + ('a' - 'A'));
    }
    return c;
}

bool PathEqualCi(const char* a, const char* b)
{
    while (*a != 0 && *b != 0)
    {
        if (AsciiToLower(*a) != AsciiToLower(*b))
        {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == 0 && *b == 0;
}

const RegKey* LookupKey(u64 root, const char* path)
{
    for (u64 i = 0; i < kRegKeyCount; ++i)
    {
        if (kRegKeys[i].root != root)
        {
            continue;
        }
        if (PathEqualCi(kRegKeys[i].path, path))
        {
            return &kRegKeys[i];
        }
    }
    return nullptr;
}

// Copy a NUL-terminated ASCII string out of user space into a
// fixed kernel buffer. Returns false on copy fault or if the
// caller's string exceeds the buffer (security: no truncation
// — a too-long path means the caller is doing something
// unexpected, return -EINVAL rather than silently look up a
// truncated prefix).
bool CopyUserAsciiPath(u64 user_va, char* out, u64 cap)
{
    if (user_va == 0 || cap == 0)
    {
        return false;
    }
    for (u64 i = 0; i < cap; ++i)
    {
        char c = 0;
        if (!duetos::mm::CopyFromUser(&c, reinterpret_cast<const void*>(user_va + i), 1))
        {
            return false;
        }
        out[i] = c;
        if (c == 0)
        {
            return true;
        }
    }
    return false; // ran out of buffer before NUL
}

i64 OpAllocateSlot(core::Process* proc, const RegKey* key)
{
    for (u64 i = 0; i < core::Process::kWin32RegistryCap; ++i)
    {
        if (!proc->win32_reg_handles[i].in_use)
        {
            proc->win32_reg_handles[i].in_use = true;
            proc->win32_reg_handles[i].reg_key = key;
            return static_cast<i64>(core::Process::kWin32RegistryBase + i);
        }
    }
    return -1; // table full
}

const RegKey* SlotForHandle(core::Process* proc, u64 handle)
{
    if (handle < core::Process::kWin32RegistryBase ||
        handle >= core::Process::kWin32RegistryBase + core::Process::kWin32RegistryCap)
    {
        return nullptr;
    }
    const u64 idx = handle - core::Process::kWin32RegistryBase;
    if (!proc->win32_reg_handles[idx].in_use)
    {
        return nullptr;
    }
    return static_cast<const RegKey*>(proc->win32_reg_handles[idx].reg_key);
}

// ---- Op handlers ----

i64 DoOpen(arch::TrapFrame* frame)
{
    // rsi = parent HKEY (predefined sentinel or kernel handle —
    // v0 only honours predefined sentinels; passing a previously-
    // opened subkey handle as parent returns INVALID_HANDLE).
    // rdx = user VA of NUL-terminated ASCII subkey path.
    // r10 = user VA of u64 slot to receive the kernel handle on
    //       success (left untouched on failure).
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return kNtStatusInvalidParameter;
    }
    const u64 parent = frame->rsi;
    const u64 path_va = frame->rdx;
    const u64 out_va = frame->r10;
    if (out_va == 0)
    {
        return kNtStatusInvalidParameter;
    }

    char path_buf[256];
    if (!CopyUserAsciiPath(path_va, path_buf, sizeof(path_buf)))
    {
        return kNtStatusInvalidParameter;
    }

    // STUB: parent must be a predefined HKEY sentinel — opening a
    // subkey relative to a previously-opened kernel handle isn't
    // walked through the static tree yet. Real Windows allows
    // arbitrary nesting; v0 callers go HKLM\full\path or
    // HKCU\full\path which matches what every MSVC CRT does.
    if (parent < kHkeyClassesRoot || parent > kHkeyCurrentConfig)
    {
        return kNtStatusInvalidHandle;
    }

    const RegKey* key = LookupKey(parent, path_buf);
    if (key == nullptr)
    {
        return kNtStatusObjectNameNotFound;
    }

    const i64 handle = OpAllocateSlot(proc, key);
    if (handle < 0)
    {
        return kNtStatusInvalidParameter; // table full — closest STATUS_*
    }
    if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(out_va), &handle, sizeof(handle)))
    {
        // Releasing a slot we just allocated keeps the table from
        // leaking on a copy-to-user fault.
        const u64 idx = static_cast<u64>(handle) - core::Process::kWin32RegistryBase;
        proc->win32_reg_handles[idx].in_use = false;
        proc->win32_reg_handles[idx].reg_key = nullptr;
        return kNtStatusInvalidParameter;
    }
    return kNtStatusSuccess;
}

i64 DoClose(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return kNtStatusInvalidParameter;
    }
    const u64 handle = frame->rsi;
    if (!ReleaseHandleForCurrentProcess(handle))
    {
        return kNtStatusInvalidHandle;
    }
    (void)proc;
    return kNtStatusSuccess;
}

i64 DoQueryValue(arch::TrapFrame* frame)
{
    // rsi = handle (kernel reg handle)
    // rdx = user VA of NUL-terminated ASCII value name
    // r10 = user VA of buffer to receive value bytes (may be 0
    //       for size-only query)
    // r8  = byte capacity of the buffer (ignored if r10 == 0)
    // r9  = user VA of u64 [type, size_needed] out slot — type
    //       in low 32, required size in high 32. Always written
    //       on STATUS_SUCCESS or STATUS_BUFFER_TOO_SMALL.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return kNtStatusInvalidParameter;
    }
    const u64 handle = frame->rsi;
    const u64 name_va = frame->rdx;
    const u64 buf_va = frame->r10;
    const u64 buf_cap = frame->r8;
    const u64 out_va = frame->r9;

    const RegKey* key = SlotForHandle(proc, handle);
    if (key == nullptr)
    {
        return kNtStatusInvalidHandle;
    }

    char name_buf[64];
    if (!CopyUserAsciiPath(name_va, name_buf, sizeof(name_buf)))
    {
        return kNtStatusInvalidParameter;
    }

    for (u32 i = 0; i < key->value_count; ++i)
    {
        const RegValue& v = key->values[i];
        if (!PathEqualCi(v.name, name_buf))
        {
            continue;
        }
        const u32 want = v.size;

        if (out_va != 0)
        {
            const u64 packed = (static_cast<u64>(want) << 32) | static_cast<u64>(v.type);
            if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(out_va), &packed, sizeof(packed)))
            {
                return kNtStatusInvalidParameter;
            }
        }

        if (buf_va == 0)
        {
            return kNtStatusSuccess; // size-only query
        }
        if (buf_cap < want)
        {
            return kNtStatusBufferTooSmall;
        }
        if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va), v.data, want))
        {
            return kNtStatusInvalidParameter;
        }
        return kNtStatusSuccess;
    }
    return kNtStatusObjectNameNotFound;
}

} // namespace

bool ReleaseHandleForCurrentProcess(u64 handle)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return false;
    }
    if (handle < core::Process::kWin32RegistryBase ||
        handle >= core::Process::kWin32RegistryBase + core::Process::kWin32RegistryCap)
    {
        return false;
    }
    const u64 idx = handle - core::Process::kWin32RegistryBase;
    if (!proc->win32_reg_handles[idx].in_use)
    {
        return false;
    }
    proc->win32_reg_handles[idx].in_use = false;
    proc->win32_reg_handles[idx].reg_key = nullptr;
    return true;
}

void DoRegistry(arch::TrapFrame* frame)
{
    const u64 op = frame->rdi;
    i64 status = kNtStatusInvalidParameter;
    switch (op)
    {
    case kOpOpenKey:
        status = DoOpen(frame);
        break;
    case kOpClose:
        status = DoClose(frame);
        break;
    case kOpQueryValue:
        status = DoQueryValue(frame);
        break;
    default:
        // STUB: unknown / unsupported op — Enumerate{Key,Value}Key
        // route through this fallback today (kSysNtNotImpl on the
        // NT-name-table side keeps real Nt callers from getting
        // here at all; this path catches malformed ntdll thunks).
        status = kNtStatusInvalidParameter;
        break;
    }
    frame->rax = static_cast<u64>(status);
}

void RegistrySelfTest()
{
    KLOG_TRACE_SCOPE("subsystems/win32/registry", "RegistrySelfTest");

    auto fail = [](const char* what) { core::Panic("subsystems/win32/registry", what); };

    // Lookup of a known key against its predefined-HKEY root.
    if (LookupKey(kHkeyLocalMachine, "Software\\Microsoft\\Windows NT\\CurrentVersion") == nullptr)
    {
        fail("HKLM\\Software\\...\\Windows NT\\CurrentVersion not found");
    }
    if (LookupKey(kHkeyCurrentUser, "Volatile Environment") == nullptr)
    {
        fail("HKCU\\Volatile Environment not found");
    }
    // Case-insensitive match works as Win32 expects.
    if (LookupKey(kHkeyLocalMachine, "SOFTWARE\\microsoft\\WINDOWS NT\\CURRENTVERSION") == nullptr)
    {
        fail("case-insensitive path lookup failed");
    }
    // Bogus paths return nullptr.
    if (LookupKey(kHkeyLocalMachine, "Nope\\Nope") != nullptr)
    {
        fail("non-existent key returned non-null");
    }
    // Wrong root.
    if (LookupKey(kHkeyCurrentUser, "Software\\Microsoft\\Windows NT\\CurrentVersion") != nullptr)
    {
        fail("HKCU returned an HKLM-only path");
    }
    // ProductName is a REG_SZ "DuetOS\\0" of size 7.
    const RegKey* hklm = LookupKey(kHkeyLocalMachine, "Software\\Microsoft\\Windows NT\\CurrentVersion");
    bool found_product = false;
    for (u32 i = 0; i < hklm->value_count; ++i)
    {
        if (PathEqualCi(hklm->values[i].name, "ProductName"))
        {
            if (hklm->values[i].type != kRegSz || hklm->values[i].size != 7)
            {
                fail("ProductName has unexpected type/size");
            }
            found_product = true;
            break;
        }
    }
    if (!found_product)
    {
        fail("ProductName value missing from HKLM\\...\\CurrentVersion");
    }

    arch::SerialWrite("[registry-selftest] PASS (4 keys, well-known values, ci-lookup)\n");
}

} // namespace duetos::subsystems::win32::registry
