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

// Static tree. Two tiers:
//
//   - Terminal keys carry `values` + `value_count` and back the
//     well-known well-formed paths v0 callers actually read.
//   - Prefix keys (`values=nullptr, value_count=0`) exist solely
//     so a caller can walk into the tree one component at a time
//     — `RegOpenKey(HKLM, "Software", &h)` then
//     `RegOpenKey(h, "Microsoft\\Windows NT\\CurrentVersion", &h2)`
//     resolves both steps. Without the prefix entries the second
//     call would have to be `RegOpenKey(h, "...full path...", ...)`
//     with parent = HKLM, which forced every caller to know the
//     full path up-front.
//
// Mirror constraint: advapi32.c's k_reg_keys[] tracks the same
// shape. Adding an entry here means adding the matching entry
// there in the same commit.
constexpr RegKey kRegKeys[] = {
    {kHkeyLocalMachine, "Software\\Microsoft\\Windows NT\\CurrentVersion", kHklmWinNtValues,
     static_cast<u32>(sizeof(kHklmWinNtValues) / sizeof(kHklmWinNtValues[0]))},
    {kHkeyLocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion", kHklmWinNtValues,
     static_cast<u32>(sizeof(kHklmWinNtValues) / sizeof(kHklmWinNtValues[0]))},
    {kHkeyCurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", kHkcuInternetValues,
     static_cast<u32>(sizeof(kHkcuInternetValues) / sizeof(kHkcuInternetValues[0]))},
    {kHkeyCurrentUser, "Volatile Environment", kHkcuVolatileEnvValues,
     static_cast<u32>(sizeof(kHkcuVolatileEnvValues) / sizeof(kHkcuVolatileEnvValues[0]))},
    // Prefix keys — all distinct proper prefixes of the terminal
    // paths above. Same root + path pair returns the same entry,
    // so HKLM and HKCU each get their own prefix chain.
    {kHkeyLocalMachine, "Software", nullptr, 0},
    {kHkeyLocalMachine, "Software\\Microsoft", nullptr, 0},
    {kHkeyLocalMachine, "Software\\Microsoft\\Windows", nullptr, 0},
    {kHkeyLocalMachine, "Software\\Microsoft\\Windows NT", nullptr, 0},
    {kHkeyCurrentUser, "Software", nullptr, 0},
    {kHkeyCurrentUser, "Software\\Microsoft", nullptr, 0},
    {kHkeyCurrentUser, "Software\\Microsoft\\Windows", nullptr, 0},
    {kHkeyCurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion", nullptr, 0},
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
constexpr i64 kNtStatusInsufficientResources = static_cast<i64>(static_cast<u32>(0xC000009A));

// Sidecar mutable-value pool. The static tree is constexpr;
// NtSetValueKey / NtDeleteValueKey land their writes into the
// sidecar instead of mutating the static blob (which is in
// .rodata and would fault on write).
//
// Lookup precedence: NtQueryValueKey checks the sidecar first
// for an entry tagged with `key == this`, then falls back to
// the static `key->values[]` table. This means a SetValue with
// the same name as a static value shadows it for as long as the
// sidecar entry lives.
//
// Cap: 32 sidecar entries shared across every key, every
// process. The pool is global because the registry is global —
// HKLM\Software\... is the same store from every caller's
// perspective. 32 covers the ~ten common shell-config writes
// we care about in v0; sub-GAP for any test that wants more.
constexpr u32 kSidecarValueCap = 32;
constexpr u32 kSidecarNameMax = 64;
constexpr u32 kSidecarDataMax = 256;

struct SidecarValue
{
    bool in_use;
    bool tombstone; // true → this name is "deleted" and shadows any same-named static value
    u8 _pad[2];
    const RegKey* key; // pointer into kRegKeys[]; unique per (root, path)
    u32 type;          // REG_*
    u32 size;          // bytes valid in data[]
    char name[kSidecarNameMax];
    u8 data[kSidecarDataMax];
};

SidecarValue g_sidecar[kSidecarValueCap];

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
    // Per-process registry handle table saturated (32 slots). The
    // Win32 thunk returns INVALID_HANDLE_VALUE upward; here we
    // surface the first occurrence so the operator can correlate
    // against the misbehaving process before subsequent opens
    // start failing silently.
    KLOG_ONCE_WARN("subsystems/win32/registry", "per-process registry handle table full");
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

// ---- Sidecar helpers ----

SidecarValue* SidecarFind(const RegKey* key, const char* name)
{
    for (u32 i = 0; i < kSidecarValueCap; ++i)
    {
        if (!g_sidecar[i].in_use)
            continue;
        if (g_sidecar[i].key != key)
            continue;
        if (PathEqualCi(g_sidecar[i].name, name))
            return &g_sidecar[i];
    }
    return nullptr;
}

SidecarValue* SidecarAlloc()
{
    for (u32 i = 0; i < kSidecarValueCap; ++i)
    {
        if (!g_sidecar[i].in_use)
            return &g_sidecar[i];
    }
    return nullptr;
}

// ---- Op handlers ----

// Concatenate a parent key's path with a subkey path into `out`.
// Real Windows is forgiving about leading / trailing backslashes;
// match that. Returns false on overflow (caller treats as
// ObjectNameNotFound — a path that overflows can't possibly
// resolve in our small static tree).
bool ConcatRegPath(const char* parent_path, const char* sub, char* out, u64 cap)
{
    u64 i = 0;
    if (parent_path != nullptr)
    {
        while (parent_path[i] != '\0')
        {
            if (i + 1 >= cap)
                return false;
            out[i] = parent_path[i];
            ++i;
        }
    }
    // Trim a single trailing backslash on the parent so we don't
    // produce "Software\\\\Microsoft" if the parent string happened
    // to carry one. None of our static paths do, but defence in
    // depth.
    if (i > 0 && out[i - 1] == '\\')
        --i;

    // Skip a single leading backslash on `sub` so callers passing
    // "\\Microsoft" don't end up with a doubled separator.
    if (sub != nullptr && sub[0] == '\\')
        ++sub;

    // Empty sub means "open the parent again" — leave the result
    // as just the parent path. Caller resolves it back to the same
    // key (or fails cleanly if the parent path isn't in the tree
    // anymore for some reason).
    if (sub == nullptr || sub[0] == '\0')
    {
        out[i] = '\0';
        return true;
    }

    // Insert separator iff the parent contributed any characters.
    if (i > 0)
    {
        if (i + 1 >= cap)
            return false;
        out[i++] = '\\';
    }
    while (*sub != '\0')
    {
        if (i + 1 >= cap)
            return false;
        out[i++] = *sub++;
    }
    out[i] = '\0';
    return true;
}

i64 DoOpen(arch::TrapFrame* frame)
{
    // rsi = parent HKEY — predefined sentinel (kHkey*) OR a
    //       previously-opened kernel handle in the
    //       Process::kWin32RegistryBase range. Both forms walk
    //       the static tree.
    // rdx = user VA of NUL-terminated ASCII subkey path. May be
    //       empty when the caller is reopening the parent.
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

    // Resolve `parent` to a (root, path) pair so the rest of the
    // function only deals with the static-tree lookup.
    u64 root_sentinel = 0;
    const char* parent_path = "";
    char concat_buf[256];
    if (parent >= kHkeyClassesRoot && parent <= kHkeyCurrentConfig)
    {
        // Predefined HKEY: the subkey path is the lookup path
        // verbatim, root is the sentinel.
        root_sentinel = parent;
    }
    else if (parent >= core::Process::kWin32RegistryBase &&
             parent < core::Process::kWin32RegistryBase + core::Process::kWin32RegistryCap)
    {
        // Previously-opened kernel handle: synthesise the lookup
        // path by concatenating the parent's static path with the
        // caller's subkey, and lookup against the parent's root
        // sentinel.
        const RegKey* parent_key = SlotForHandle(proc, parent);
        if (parent_key == nullptr)
            return kNtStatusInvalidHandle;
        if (!ConcatRegPath(parent_key->path, path_buf, concat_buf, sizeof(concat_buf)))
            return kNtStatusObjectNameNotFound;
        root_sentinel = parent_key->root;
        parent_path = concat_buf;
    }
    else
    {
        return kNtStatusInvalidHandle;
    }

    const char* lookup_path = (parent_path[0] != '\0') ? parent_path : path_buf;
    const RegKey* key = LookupKey(root_sentinel, lookup_path);
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

    // Sidecar first — a prior NtSetValueKey shadows any same-
    // named static value for as long as the sidecar entry lives.
    // A tombstoned entry shadows the static value the same way
    // but reports STATUS_OBJECT_NAME_NOT_FOUND so the caller sees
    // the deletion.
    if (const SidecarValue* sv = SidecarFind(key, name_buf); sv != nullptr)
    {
        if (sv->tombstone)
            return kNtStatusObjectNameNotFound;
        const u32 want = sv->size;
        if (out_va != 0)
        {
            const u64 packed = (static_cast<u64>(want) << 32) | static_cast<u64>(sv->type);
            if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(out_va), &packed, sizeof(packed)))
                return kNtStatusInvalidParameter;
        }
        if (buf_va == 0)
            return kNtStatusSuccess;
        if (buf_cap < want)
            return kNtStatusBufferTooSmall;
        if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va), sv->data, want))
            return kNtStatusInvalidParameter;
        return kNtStatusSuccess;
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

i64 DoSetValue(arch::TrapFrame* frame)
{
    // rsi = handle (must be a previously-opened key)
    // rdx = user VA of NUL-terminated value name
    // r10 = user VA of value data (may be 0 iff size == 0)
    // r8  = data size in bytes
    // r9  = REG_* type
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return kNtStatusInvalidParameter;
    // Subsystem isolation: registry mutation is a kernel-state
    // change. Cap-gate on kCapFsWrite — same gate that protects
    // FAT32 writes — so a sandboxed PE can't alter the shared
    // kernel-side hive without explicit clearance. See
    // wiki/kernel/Subsystem-Isolation.md.
    if (!core::CapSetHas(proc->caps, core::kCapFsWrite))
    {
        core::RecordSandboxDenial(core::kCapFsWrite);
        return static_cast<i64>(static_cast<u32>(0xC0000022)); // STATUS_ACCESS_DENIED
    }
    const u64 handle = frame->rsi;
    const u64 name_va = frame->rdx;
    const u64 data_va = frame->r10;
    const u64 size = frame->r8;
    const u32 type = static_cast<u32>(frame->r9);

    const RegKey* key = SlotForHandle(proc, handle);
    if (key == nullptr)
        return kNtStatusInvalidHandle;
    if (size > kSidecarDataMax)
        return kNtStatusInsufficientResources;

    char name_buf[kSidecarNameMax];
    if (!CopyUserAsciiPath(name_va, name_buf, sizeof(name_buf)))
        return kNtStatusInvalidParameter;

    SidecarValue* sv = SidecarFind(key, name_buf);
    if (sv == nullptr)
    {
        sv = SidecarAlloc();
        if (sv == nullptr)
            return kNtStatusInsufficientResources;
        // Stamp identity. Name is copied in here; data on the
        // line below.
        u32 i = 0;
        for (; i + 1 < kSidecarNameMax && name_buf[i] != '\0'; ++i)
            sv->name[i] = name_buf[i];
        sv->name[i] = '\0';
        sv->key = key;
        sv->in_use = true;
    }
    // A SetValue on a tombstoned name "resurrects" the value (now
    // pointing at sidecar bytes — the static value stays shadowed
    // until the sidecar slot is freed).
    sv->tombstone = false;
    sv->type = type;
    sv->size = static_cast<u32>(size);
    if (size > 0)
    {
        if (!duetos::mm::CopyFromUser(sv->data, reinterpret_cast<const void*>(data_va), size))
        {
            // Roll the slot back so a faulting set doesn't leave
            // a half-stamped sidecar entry shadowing the static
            // value (which would silently corrupt subsequent
            // queries).
            sv->in_use = false;
            sv->tombstone = false;
            sv->key = nullptr;
            sv->name[0] = '\0';
            sv->size = 0;
            return kNtStatusInvalidParameter;
        }
    }
    RegistryHiveSave();
    return kNtStatusSuccess;
}

i64 DoDeleteValue(arch::TrapFrame* frame)
{
    // rsi = handle, rdx = user VA of value name.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return kNtStatusInvalidParameter;
    // Subsystem isolation: same cap gate as DoSetValue (registry
    // mutation requires kCapFsWrite).
    if (!core::CapSetHas(proc->caps, core::kCapFsWrite))
    {
        core::RecordSandboxDenial(core::kCapFsWrite);
        return static_cast<i64>(static_cast<u32>(0xC0000022));
    }
    const u64 handle = frame->rsi;
    const u64 name_va = frame->rdx;
    const RegKey* key = SlotForHandle(proc, handle);
    if (key == nullptr)
        return kNtStatusInvalidHandle;
    char name_buf[kSidecarNameMax];
    if (!CopyUserAsciiPath(name_va, name_buf, sizeof(name_buf)))
        return kNtStatusInvalidParameter;
    SidecarValue* sv = SidecarFind(key, name_buf);
    if (sv != nullptr)
    {
        // Already a sidecar entry. If it shadows a static value
        // we have to leave it occupied as a tombstone so the
        // shadowing persists across the delete. Otherwise we can
        // free the slot outright.
        bool shadows_static = false;
        for (u32 i = 0; i < key->value_count; ++i)
        {
            if (PathEqualCi(key->values[i].name, name_buf))
            {
                shadows_static = true;
                break;
            }
        }
        if (shadows_static)
        {
            sv->tombstone = true;
            sv->type = 0;
            sv->size = 0;
        }
        else
        {
            sv->in_use = false;
            sv->tombstone = false;
            sv->key = nullptr;
            sv->name[0] = '\0';
            sv->size = 0;
        }
        RegistryHiveSave();
        return kNtStatusSuccess;
    }
    // No sidecar entry yet — see if the name resolves to a static
    // value. If so, plant a tombstone so subsequent Query / Enum
    // calls behave as if the value were genuinely deleted.
    bool is_static_value = false;
    for (u32 i = 0; i < key->value_count; ++i)
    {
        if (PathEqualCi(key->values[i].name, name_buf))
        {
            is_static_value = true;
            break;
        }
    }
    if (is_static_value)
    {
        SidecarValue* tomb = SidecarAlloc();
        if (tomb == nullptr)
            return kNtStatusInsufficientResources;
        u32 i = 0;
        for (; i + 1 < kSidecarNameMax && name_buf[i] != '\0'; ++i)
            tomb->name[i] = name_buf[i];
        tomb->name[i] = '\0';
        tomb->key = key;
        tomb->in_use = true;
        tomb->tombstone = true;
        tomb->type = 0;
        tomb->size = 0;
        RegistryHiveSave();
        return kNtStatusSuccess;
    }
    return kNtStatusObjectNameNotFound;
}

i64 DoFlushKey(arch::TrapFrame* frame)
{
    // No on-disk hive; flush is a no-op success. The sidecar
    // already lives in kernel-resident RAM; "flush" has nothing
    // to do until a real persistence tier lands.
    (void)frame;
    return kNtStatusSuccess;
}

// True iff `key` has a sidecar tombstone for `name`. Used to
// skip static values that have been deleted via DoDeleteValue.
bool StaticValueIsTombstoned(const RegKey* key, const char* name)
{
    for (u32 i = 0; i < kSidecarValueCap; ++i)
    {
        if (!g_sidecar[i].in_use || g_sidecar[i].key != key)
            continue;
        if (!g_sidecar[i].tombstone)
            continue;
        if (PathEqualCi(g_sidecar[i].name, name))
            return true;
    }
    return false;
}

// Walk the values of an opened key and return the one at
// `index`. Static values come first (skipping any whose name
// has been tombstoned), then live sidecar entries with matching
// RegKey (skipping tombstones themselves). Out shape (32-byte
// header + name body):
//   [0..4)   index (u32)
//   [4..8)   type  (u32, REG_*)
//   [8..12)  data_size (u32, bytes)
//   [12..16) name_chars (u32, ASCII char count, no NUL)
//   [16..32) reserved (zero)
//   [32..)   name body (ASCII, NUL-terminated, fits buf_cap)
i64 DoEnumerateValue(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return kNtStatusInvalidParameter;
    const u64 handle = frame->rsi;
    const u32 index = static_cast<u32>(frame->rdx);
    const u64 buf_va = frame->r10;
    const u64 buf_cap = frame->r8;
    const RegKey* key = SlotForHandle(proc, handle);
    if (key == nullptr)
        return kNtStatusInvalidHandle;
    if (buf_va == 0 || buf_cap < 32)
        return kNtStatusInvalidParameter;

    // Walk the unified (static-then-sidecar) list, skipping
    // tombstoned entries. Position the caller's `index` against
    // the surviving (exposed) sequence.
    u32 visible = 0;
    for (u32 i = 0; i < key->value_count; ++i)
    {
        const RegValue& v = key->values[i];
        if (StaticValueIsTombstoned(key, v.name))
            continue;
        if (visible == index)
        {
            u32 name_chars = 0;
            while (v.name[name_chars] != '\0')
                ++name_chars;
            const u64 hdr = 32;
            if (buf_cap < hdr + name_chars + 1)
                return kNtStatusBufferTooSmall;
            u64 packed[4] = {0, 0, 0, 0};
            packed[0] = (static_cast<u64>(v.type) << 32) | static_cast<u64>(index);
            packed[1] = (static_cast<u64>(name_chars) << 32) | static_cast<u64>(v.size);
            if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va), packed, sizeof(packed)))
                return kNtStatusInvalidParameter;
            if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va + hdr), v.name, name_chars + 1))
                return kNtStatusInvalidParameter;
            return kNtStatusSuccess;
        }
        ++visible;
    }
    for (u32 i = 0; i < kSidecarValueCap; ++i)
    {
        if (!g_sidecar[i].in_use || g_sidecar[i].key != key)
            continue;
        if (g_sidecar[i].tombstone)
            continue;
        if (visible == index)
        {
            const SidecarValue& sv = g_sidecar[i];
            u32 name_chars = 0;
            while (sv.name[name_chars] != '\0')
                ++name_chars;
            const u64 hdr = 32;
            if (buf_cap < hdr + name_chars + 1)
                return kNtStatusBufferTooSmall;
            u64 packed[4] = {0, 0, 0, 0};
            packed[0] = (static_cast<u64>(sv.type) << 32) | static_cast<u64>(index);
            packed[1] = (static_cast<u64>(name_chars) << 32) | static_cast<u64>(sv.size);
            if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va), packed, sizeof(packed)))
                return kNtStatusInvalidParameter;
            if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va + hdr), sv.name, name_chars + 1))
                return kNtStatusInvalidParameter;
            return kNtStatusSuccess;
        }
        ++visible;
    }
    // STATUS_NO_MORE_ENTRIES = 0x8000001A. Caller's loop ends.
    return static_cast<i64>(static_cast<u32>(0x8000001A));
}

// True iff `candidate` is a direct child path of `parent_path`
// (one path component below). Out parameter `child_offset`
// points at the start of the child component within `candidate`
// when the function returns true.
bool IsDirectChild(const char* parent_path, const char* candidate, const char** child_offset)
{
    // Compare parent_path against candidate's prefix, case-insensitive.
    u64 i = 0;
    while (parent_path[i] != '\0')
    {
        if (AsciiToLower(parent_path[i]) != AsciiToLower(candidate[i]))
            return false;
        ++i;
    }
    // Parent must be followed by '\\' on candidate, then a non-empty
    // single-component remainder (no further '\\').
    if (candidate[i] != '\\')
        return false;
    const char* rest = candidate + i + 1;
    if (rest[0] == '\0')
        return false;
    for (u64 j = 0; rest[j] != '\0'; ++j)
    {
        if (rest[j] == '\\')
            return false;
    }
    *child_offset = rest;
    return true;
}

// Count children of `key` in the static tree. A child is any
// kRegKeys[] entry whose path is `key->path + "\\" + single_name`.
u32 CountSubkeys(const RegKey* key)
{
    u32 n = 0;
    for (u64 i = 0; i < kRegKeyCount; ++i)
    {
        if (kRegKeys[i].root != key->root)
            continue;
        const char* unused = nullptr;
        if (IsDirectChild(key->path, kRegKeys[i].path, &unused))
            ++n;
    }
    return n;
}

u32 StrLenAscii(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

// Longest direct-child name (chars) under `key` in the static
// tree. Backs KEY_FULL_INFORMATION.MaxNameLen so callers can
// size their RegEnumKey buffers without iterating first.
u32 MaxSubkeyNameChars(const RegKey* key)
{
    u32 best = 0;
    for (u64 i = 0; i < kRegKeyCount; ++i)
    {
        if (kRegKeys[i].root != key->root)
            continue;
        const char* child = nullptr;
        if (!IsDirectChild(key->path, kRegKeys[i].path, &child))
            continue;
        const u32 len = StrLenAscii(child);
        if (len > best)
            best = len;
    }
    return best;
}

// Longest value-name + value-data lengths across both the static
// table and any matching sidecar entries. Backs
// KEY_FULL_INFORMATION.MaxValueNameLen / MaxValueDataLen. Skips
// tombstoned static values + tombstone sidecar entries so the
// reported maxima reflect what enum will actually surface.
void MaxValueLens(const RegKey* key, u32* max_name_chars, u32* max_data_bytes)
{
    u32 best_name = 0;
    u32 best_data = 0;
    for (u32 i = 0; i < key->value_count; ++i)
    {
        if (StaticValueIsTombstoned(key, key->values[i].name))
            continue;
        const u32 nl = StrLenAscii(key->values[i].name);
        if (nl > best_name)
            best_name = nl;
        if (key->values[i].size > best_data)
            best_data = key->values[i].size;
    }
    for (u32 i = 0; i < kSidecarValueCap; ++i)
    {
        if (!g_sidecar[i].in_use || g_sidecar[i].key != key)
            continue;
        if (g_sidecar[i].tombstone)
            continue;
        const u32 nl = StrLenAscii(g_sidecar[i].name);
        if (nl > best_name)
            best_name = nl;
        if (g_sidecar[i].size > best_data)
            best_data = g_sidecar[i].size;
    }
    *max_name_chars = best_name;
    *max_data_bytes = best_data;
}

// Report subkey_count + value_count + max-name / max-value
// lengths. Output layout (40 bytes when buf_cap permits, else
// truncated to 16 for backwards-compatibility):
//
//   [0..8)   subkey_count (u64) — direct children in static tree
//   [8..16)  value_count  (u64) — static + matching sidecar
//   [16..24) max_subkey_name_chars (u64)
//   [24..32) max_value_name_chars  (u64) — across static + sidecar
//   [32..40) max_value_data_bytes  (u64) — across static + sidecar
//
// User-side ntdll thunk maps these onto KEY_FULL_INFORMATION's
// SubKeys / Values / MaxNameLen / MaxValueNameLen / MaxValueDataLen.
i64 DoQueryKey(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return kNtStatusInvalidParameter;
    const u64 handle = frame->rsi;
    const u64 buf_va = frame->rdx;
    const u64 buf_cap = frame->r10;
    const RegKey* key = SlotForHandle(proc, handle);
    if (key == nullptr)
        return kNtStatusInvalidHandle;
    if (buf_va == 0 || buf_cap < 16)
        return kNtStatusInvalidParameter;
    // Visible sidecar entries (not tombstones) AND visible static
    // values (those without a matching tombstone). The exposed
    // total drives the caller's enumeration loop.
    u32 sidecar_count = 0;
    u32 tombstone_count = 0;
    for (u32 i = 0; i < kSidecarValueCap; ++i)
    {
        if (!g_sidecar[i].in_use || g_sidecar[i].key != key)
            continue;
        if (g_sidecar[i].tombstone)
            ++tombstone_count;
        else
            ++sidecar_count;
    }
    u32 max_value_name_chars = 0;
    u32 max_value_data_bytes = 0;
    MaxValueLens(key, &max_value_name_chars, &max_value_data_bytes);

    const u32 visible_static = (key->value_count >= tombstone_count) ? (key->value_count - tombstone_count) : 0;

    u64 packed[5];
    packed[0] = static_cast<u64>(CountSubkeys(key));
    packed[1] = static_cast<u64>(visible_static + sidecar_count);
    packed[2] = static_cast<u64>(MaxSubkeyNameChars(key));
    packed[3] = static_cast<u64>(max_value_name_chars);
    packed[4] = static_cast<u64>(max_value_data_bytes);

    const u64 to_copy = (buf_cap >= sizeof(packed)) ? sizeof(packed) : 16;
    if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va), packed, to_copy))
        return kNtStatusInvalidParameter;
    return kNtStatusSuccess;
}

// Walk direct children of an opened key. Out shape mirrors
// kOpEnumerateValue's 32-byte header + name body so the user-side
// thunk can use the same staging-buffer pattern:
//
//   [0..4)   index (u32)
//   [4..8)   reserved (u32, zero)
//   [8..16)  reserved (u64, zero — last_write_time placeholder)
//   [16..20) name_chars (u32, ASCII char count, no NUL)
//   [20..32) reserved (zero)
//   [32..)   ASCII name body, NUL-terminated, fits buf_cap
//
// Returns STATUS_NO_MORE_ENTRIES (0x8000001A) when `index` is past
// the children count so a caller's enumeration loop terminates
// cleanly.
i64 DoEnumerateKey(arch::TrapFrame* frame)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return kNtStatusInvalidParameter;
    const u64 handle = frame->rsi;
    const u32 index = static_cast<u32>(frame->rdx);
    const u64 buf_va = frame->r10;
    const u64 buf_cap = frame->r8;
    const RegKey* key = SlotForHandle(proc, handle);
    if (key == nullptr)
        return kNtStatusInvalidHandle;
    if (buf_va == 0 || buf_cap < 32)
        return kNtStatusInvalidParameter;

    u32 hits = 0;
    for (u64 i = 0; i < kRegKeyCount; ++i)
    {
        if (kRegKeys[i].root != key->root)
            continue;
        const char* child_name = nullptr;
        if (!IsDirectChild(key->path, kRegKeys[i].path, &child_name))
            continue;
        if (hits == index)
        {
            u32 name_chars = 0;
            while (child_name[name_chars] != '\0')
                ++name_chars;
            const u64 hdr = 32;
            if (buf_cap < hdr + name_chars + 1)
                return kNtStatusBufferTooSmall;
            u64 packed[4] = {0, 0, 0, 0};
            packed[0] = static_cast<u64>(index);
            packed[2] = static_cast<u64>(name_chars) << 32;
            if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va), packed, sizeof(packed)))
                return kNtStatusInvalidParameter;
            if (!duetos::mm::CopyToUser(reinterpret_cast<void*>(buf_va + hdr), child_name, name_chars + 1))
                return kNtStatusInvalidParameter;
            return kNtStatusSuccess;
        }
        ++hits;
    }
    return static_cast<i64>(static_cast<u32>(0x8000001A));
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
    case kOpSetValue:
        status = DoSetValue(frame);
        break;
    case kOpDeleteValue:
        status = DoDeleteValue(frame);
        break;
    case kOpFlushKey:
        status = DoFlushKey(frame);
        break;
    case kOpEnumerateValue:
        status = DoEnumerateValue(frame);
        break;
    case kOpQueryKey:
        status = DoQueryKey(frame);
        break;
    case kOpEnumerateKey:
        status = DoEnumerateKey(frame);
        break;
    default:
        // Unknown / unsupported op. Every op a userland DLL ships
        // with today is routed above; falling through here means a
        // malformed thunk or a future op the caller probed without
        // first checking the kernel's op table.
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

    // Prefix entries — the proper prefixes of every terminal path
    // resolve to value-less RegKey rows so RegOpenKey can walk
    // the tree one component at a time.
    if (LookupKey(kHkeyLocalMachine, "Software") == nullptr)
        fail("HKLM\\Software prefix entry missing");
    if (LookupKey(kHkeyLocalMachine, "Software\\Microsoft\\Windows NT") == nullptr)
        fail("HKLM\\Software\\Microsoft\\Windows NT prefix entry missing");
    if (LookupKey(kHkeyCurrentUser, "Software\\Microsoft\\Windows\\CurrentVersion") == nullptr)
        fail("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion prefix entry missing");
    const RegKey* prefix = LookupKey(kHkeyLocalMachine, "Software");
    if (prefix == nullptr || prefix->value_count != 0 || prefix->values != nullptr)
        fail("prefix entry malformed");

    // Path concatenation rules: trailing backslash on parent and
    // leading backslash on subkey are tolerated, empty subkey
    // returns the parent path verbatim.
    char buf[64];
    if (!ConcatRegPath("Software", "Microsoft", buf, sizeof(buf)) || !PathEqualCi(buf, "Software\\Microsoft"))
        fail("ConcatRegPath: simple join failed");
    if (!ConcatRegPath("Software\\", "\\Microsoft", buf, sizeof(buf)) || !PathEqualCi(buf, "Software\\Microsoft"))
        fail("ConcatRegPath: edge-backslash trim failed");
    if (!ConcatRegPath("Software", "", buf, sizeof(buf)) || !PathEqualCi(buf, "Software"))
        fail("ConcatRegPath: empty subkey didn't return parent");
    if (!ConcatRegPath("", "Software", buf, sizeof(buf)) || !PathEqualCi(buf, "Software"))
        fail("ConcatRegPath: empty parent didn't return subkey");

    // Children walker: counts + names match the static tree.
    const RegKey* sw_hklm = LookupKey(kHkeyLocalMachine, "Software");
    if (sw_hklm == nullptr || CountSubkeys(sw_hklm) != 1)
        fail("HKLM\\Software should have exactly 1 child (Microsoft)");
    const RegKey* ms_hklm = LookupKey(kHkeyLocalMachine, "Software\\Microsoft");
    if (ms_hklm == nullptr || CountSubkeys(ms_hklm) != 2)
        fail("HKLM\\Software\\Microsoft should have 2 children (Windows + Windows NT)");
    const RegKey* terminal = LookupKey(kHkeyLocalMachine, "Software\\Microsoft\\Windows\\CurrentVersion");
    if (terminal == nullptr || CountSubkeys(terminal) != 0)
        fail("terminal HKLM CurrentVersion key should have no children");

    // Direct-child predicate: positive + negative + grandchild rejection.
    const char* child = nullptr;
    if (!IsDirectChild("Software", "Software\\Microsoft", &child) || !PathEqualCi(child, "Microsoft"))
        fail("IsDirectChild: positive case failed");
    if (IsDirectChild("Software", "Software\\Microsoft\\Windows", &child))
        fail("IsDirectChild: grandchild incorrectly flagged as direct child");
    if (IsDirectChild("Software", "SoftwareElse\\Foo", &child))
        fail("IsDirectChild: prefix-without-separator incorrectly matched");
    if (IsDirectChild("Software", "Software", &child))
        fail("IsDirectChild: same path incorrectly flagged as direct child");

    // Max-name walkers — used by KEY_FULL_INFORMATION.MaxNameLen +
    // MaxValueNameLen + MaxValueDataLen so callers can size their
    // RegEnumKey / RegEnumValue buffers without a probe pass.
    if (MaxSubkeyNameChars(ms_hklm) != 10 /* "Windows NT" */)
        fail("MaxSubkeyNameChars under HKLM\\Software\\Microsoft should be 10");
    u32 mn = 0, md = 0;
    MaxValueLens(hklm, &mn, &md);
    if (mn != 25 /* "CurrentMajorVersionNumber" */)
        fail("MaxValueLens name should be 25 for HKLM CurrentVersion");
    if (md != 13 /* "19041.duetos\\0" / "Professional\\0" */)
        fail("MaxValueLens data should be 13 for HKLM CurrentVersion");

    arch::SerialWrite("[registry-selftest] PASS (4 terminal + 8 prefix keys, ci-lookup, concat-path, child walker, "
                      "max-lens)\n");
}

namespace detail
{

namespace
{

// Public-POD ↔ internal helper. Both sidecar storage caps are
// guaranteed to fit the HiveSnapshot's path/name/data fields
// (the public POD's cap is set to match registry.cpp's private
// constants — see kSidecarPoolSize / sizes in registry.h).
static_assert(kSidecarPoolSize == kSidecarValueCap, "registry.h kSidecarPoolSize must track kSidecarValueCap");

void CopyAscii(char* dst, u32 cap, const char* src)
{
    if (cap == 0)
    {
        return;
    }
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < cap && src[i] != '\0'; ++i)
        {
            dst[i] = src[i];
        }
    }
    dst[i] = '\0';
}

} // namespace

bool SidecarSnapshotAt(u32 idx, HiveSnapshot* out)
{
    if (out == nullptr || idx >= kSidecarValueCap)
    {
        return false;
    }
    const SidecarValue& sv = g_sidecar[idx];
    out->active = sv.in_use;
    out->tombstone = sv.tombstone;
    out->root = (sv.key != nullptr) ? sv.key->root : 0ULL;
    out->type = sv.type;
    out->size = sv.size;
    CopyAscii(out->path, sizeof(out->path), (sv.key != nullptr) ? sv.key->path : "");
    CopyAscii(out->name, sizeof(out->name), sv.name);
    const u32 dlen = (sv.size <= sizeof(out->data)) ? sv.size : static_cast<u32>(sizeof(out->data));
    for (u32 i = 0; i < dlen; ++i)
    {
        out->data[i] = sv.data[i];
    }
    for (u32 i = dlen; i < sizeof(out->data); ++i)
    {
        out->data[i] = 0;
    }
    return true;
}

bool SidecarRestoreOne(const HiveSnapshot* in)
{
    if (in == nullptr || !in->active)
    {
        return false;
    }
    const RegKey* key = LookupKey(in->root, in->path);
    if (key == nullptr)
    {
        // Hive references a key the current build doesn't ship.
        // Forward-compat: silently skip rather than failing the
        // whole load.
        return false;
    }
    SidecarValue* sv = SidecarFind(key, in->name);
    if (sv == nullptr)
    {
        sv = SidecarAlloc();
        if (sv == nullptr)
        {
            return false;
        }
    }
    sv->in_use = true;
    sv->tombstone = in->tombstone;
    sv->key = key;
    sv->type = in->type;
    sv->size = in->size;
    u32 i = 0;
    for (; i + 1 < kSidecarNameMax && in->name[i] != '\0'; ++i)
    {
        sv->name[i] = in->name[i];
    }
    sv->name[i] = '\0';
    const u32 dlen = (in->size <= kSidecarDataMax) ? in->size : kSidecarDataMax;
    for (u32 k = 0; k < dlen; ++k)
    {
        sv->data[k] = in->data[k];
    }
    return true;
}

void SidecarReset()
{
    for (u32 i = 0; i < kSidecarValueCap; ++i)
    {
        g_sidecar[i].in_use = false;
        g_sidecar[i].tombstone = false;
        g_sidecar[i].key = nullptr;
        g_sidecar[i].name[0] = '\0';
        g_sidecar[i].type = 0;
        g_sidecar[i].size = 0;
    }
}

} // namespace detail

} // namespace duetos::subsystems::win32::registry
