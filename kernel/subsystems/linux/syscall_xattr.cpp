/*
 * DuetOS — Linux ABI: extended attributes (xattr).
 *
 * Real implementation backed by an in-kernel table. The 12
 * spec syscalls (set/get/list/remove × {/, l, f}) all funnel
 * through SetEntry/GetEntry/ListPath/RemoveEntry below; the
 * /-suffix and l-suffix are identical at the kernel level
 * (we don't follow symlinks anywhere yet) and the f-suffix
 * resolves the fd to a path before doing the same work.
 *
 * Storage: a single fixed-size table of (path, name, value)
 * triples. v0 caps at kXattrCap entries to avoid heap reach
 * from a syscall. Persistence is in-RAM only — the FAT32
 * tier has no xattr storage natively, so a reboot wipes the
 * table; that matches the "FS-doesn't-store-xattrs"
 * documented Linux fallback. Real persistence is a follow-up.
 */

#include "subsystems/linux/syscall_internal.h"

#include "mm/paging.h"
#include "proc/process.h"
#include "sync/spinlock.h"
#include "util/nospec.h"

namespace duetos::subsystems::linux::internal
{

// Spec-correct errnos that aren't already in syscall_internal.h.
// ENODATA = 61 (xattr "no such name"), EDQUOT = 122 (table full).
inline constexpr i64 kENODATA = -61;
inline constexpr i64 kEDQUOT = -122;


namespace
{

constexpr u32 kXattrCap = 64;
constexpr u32 kPathMax = 64;
constexpr u32 kNameMax = 64;
constexpr u32 kValueMax = 256;

struct XattrEntry
{
    char path[kPathMax];
    char name[kNameMax];
    u8 value[kValueMax];
    u32 value_len;
    bool in_use;
};

XattrEntry g_table[kXattrCap];
::duetos::sync::SpinLock g_lock = {};

bool StrEqual(const char* a, const char* b, u32 max)
{
    for (u32 i = 0; i < max; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
    return true;
}

u32 StrLen(const char* s, u32 max)
{
    u32 i = 0;
    while (i < max && s[i] != '\0')
        ++i;
    return i;
}

// Copy a NUL-terminated user string into a kernel buffer.
// Returns true on success, false on -EFAULT or oversize.
bool CopyUserCstr(u64 user_ptr, char* dst, u32 dst_cap)
{
    if (user_ptr == 0 || dst_cap == 0)
        return false;
    // Read up to dst_cap bytes; require a NUL within.
    u8 stage[256];
    const u32 to_read = dst_cap < sizeof(stage) ? dst_cap : sizeof(stage);
    if (!mm::CopyFromUser(stage, reinterpret_cast<const void*>(user_ptr), to_read))
        return false;
    bool found_nul = false;
    for (u32 i = 0; i < to_read; ++i)
    {
        dst[i] = static_cast<char>(stage[i]);
        if (stage[i] == '\0')
        {
            found_nul = true;
            break;
        }
    }
    if (!found_nul)
        dst[dst_cap - 1] = '\0';
    return true;
}

// Look up an entry by (path, name). Returns index or -1.
i32 FindEntry(const char* path, const char* name)
{
    for (u32 i = 0; i < kXattrCap; ++i)
    {
        if (!g_table[i].in_use)
            continue;
        if (StrEqual(g_table[i].path, path, kPathMax) && StrEqual(g_table[i].name, name, kNameMax))
            return static_cast<i32>(i);
    }
    return -1;
}

i32 AllocEntry()
{
    for (u32 i = 0; i < kXattrCap; ++i)
    {
        if (!g_table[i].in_use)
            return static_cast<i32>(i);
    }
    return -1;
}

// Resolve an fd to its underlying volume-relative path. v0 only
// supports this for state==2 (regular FAT32 file) since the
// path field is only populated there.
bool ResolveFdToPath(u64 fd, char* path_out)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return false;
    if (fd >= 16)
        return false;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = ::duetos::util::MaskedIndex(fd, 16);
    const auto& slot = p->linux_fds[fd];
    if (slot.state != 2 /*regular file*/)
        return false;
    for (u32 i = 0; i < kPathMax && i < sizeof(slot.path); ++i)
    {
        path_out[i] = slot.path[i];
        if (slot.path[i] == '\0')
            return true;
    }
    path_out[kPathMax - 1] = '\0';
    return true;
}

// XATTR_CREATE = 0x1, XATTR_REPLACE = 0x2.
constexpr u64 kXattrCreate = 0x1;
constexpr u64 kXattrReplace = 0x2;

i64 SetEntry(const char* path, const char* name, u64 user_value, u64 size, u64 flags)
{
    if (size > kValueMax)
        return kEINVAL;
    if (StrLen(name, kNameMax) == 0)
        return kEINVAL;

    u8 staged[kValueMax] = {0};
    if (size > 0)
    {
        if (!mm::CopyFromUser(staged, reinterpret_cast<const void*>(user_value), size))
            return kEFAULT;
    }

    auto guard = ::duetos::sync::SpinLockGuard{g_lock};
    i32 idx = FindEntry(path, name);
    const bool exists = (idx >= 0);

    if ((flags & kXattrCreate) != 0 && exists)
        return kEEXIST;
    if ((flags & kXattrReplace) != 0 && !exists)
        return kENOENT;

    if (!exists)
    {
        idx = AllocEntry();
        if (idx < 0)
            return kEDQUOT;
        for (u32 i = 0; i < kPathMax; ++i)
        {
            g_table[idx].path[i] = path[i];
            if (path[i] == '\0')
                break;
        }
        for (u32 i = 0; i < kNameMax; ++i)
        {
            g_table[idx].name[i] = name[i];
            if (name[i] == '\0')
                break;
        }
        g_table[idx].in_use = true;
    }
    for (u32 i = 0; i < size; ++i)
        g_table[idx].value[i] = staged[i];
    g_table[idx].value_len = static_cast<u32>(size);
    return 0;
}

i64 GetEntry(const char* path, const char* name, u64 user_value, u64 size)
{
    auto guard = ::duetos::sync::SpinLockGuard{g_lock};
    const i32 idx = FindEntry(path, name);
    if (idx < 0)
        return kENODATA;
    const u32 want = g_table[idx].value_len;
    if (size == 0)
        return static_cast<i64>(want); // size-query mode
    if (size < want)
        return kERANGE;
    if (want > 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_value), g_table[idx].value, want))
            return kEFAULT;
    }
    return static_cast<i64>(want);
}

i64 ListPath(const char* path, u64 user_list, u64 size)
{
    auto guard = ::duetos::sync::SpinLockGuard{g_lock};
    // First pass — compute total length.
    u32 total = 0;
    for (u32 i = 0; i < kXattrCap; ++i)
    {
        if (!g_table[i].in_use)
            continue;
        if (!StrEqual(g_table[i].path, path, kPathMax))
            continue;
        total += StrLen(g_table[i].name, kNameMax) + 1; // include NUL separator
    }
    if (size == 0)
        return static_cast<i64>(total);
    if (size < total)
        return kERANGE;
    if (total == 0)
        return 0;

    u8 stage[kXattrCap * (kNameMax + 1)] = {0};
    u32 pos = 0;
    for (u32 i = 0; i < kXattrCap; ++i)
    {
        if (!g_table[i].in_use)
            continue;
        if (!StrEqual(g_table[i].path, path, kPathMax))
            continue;
        const u32 nlen = StrLen(g_table[i].name, kNameMax);
        for (u32 k = 0; k < nlen; ++k)
            stage[pos++] = static_cast<u8>(g_table[i].name[k]);
        stage[pos++] = 0;
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_list), stage, total))
        return kEFAULT;
    return static_cast<i64>(total);
}

i64 RemoveEntry(const char* path, const char* name)
{
    auto guard = ::duetos::sync::SpinLockGuard{g_lock};
    const i32 idx = FindEntry(path, name);
    if (idx < 0)
        return kENODATA;
    g_table[idx].in_use = false;
    g_table[idx].value_len = 0;
    return 0;
}

} // namespace

// Spec: setxattr(path, name, value, size, flags).
i64 DoSetxattr(u64 user_path, u64 user_name, u64 value, u64 size, u64 flags)
{
    char path[kPathMax] = {0};
    char name[kNameMax] = {0};
    if (!CopyUserCstr(user_path, path, kPathMax) || !CopyUserCstr(user_name, name, kNameMax))
        return kEFAULT;
    return SetEntry(path, name, value, size, flags);
}
// lsetxattr — same as setxattr; we don't follow symlinks anywhere.
i64 DoLsetxattr(u64 path, u64 name, u64 value, u64 size, u64 flags)
{
    return DoSetxattr(path, name, value, size, flags);
}
// fsetxattr — fd-keyed; resolve fd -> synthetic path key.
i64 DoFsetxattr(u64 fd, u64 user_name, u64 value, u64 size, u64 flags)
{
    char path[kPathMax] = {0};
    char name[kNameMax] = {0};
    if (!ResolveFdToPath(fd, path))
        return kEBADF;
    if (!CopyUserCstr(user_name, name, kNameMax))
        return kEFAULT;
    return SetEntry(path, name, value, size, flags);
}

i64 DoGetxattr(u64 user_path, u64 user_name, u64 value, u64 size)
{
    char path[kPathMax] = {0};
    char name[kNameMax] = {0};
    if (!CopyUserCstr(user_path, path, kPathMax) || !CopyUserCstr(user_name, name, kNameMax))
        return kEFAULT;
    return GetEntry(path, name, value, size);
}
i64 DoLgetxattr(u64 path, u64 name, u64 value, u64 size)
{
    return DoGetxattr(path, name, value, size);
}
i64 DoFgetxattr(u64 fd, u64 user_name, u64 value, u64 size)
{
    char path[kPathMax] = {0};
    char name[kNameMax] = {0};
    if (!ResolveFdToPath(fd, path))
        return kEBADF;
    if (!CopyUserCstr(user_name, name, kNameMax))
        return kEFAULT;
    return GetEntry(path, name, value, size);
}

i64 DoListxattr(u64 user_path, u64 list, u64 size)
{
    char path[kPathMax] = {0};
    if (!CopyUserCstr(user_path, path, kPathMax))
        return kEFAULT;
    return ListPath(path, list, size);
}
i64 DoLlistxattr(u64 path, u64 list, u64 size)
{
    return DoListxattr(path, list, size);
}
i64 DoFlistxattr(u64 fd, u64 list, u64 size)
{
    char path[kPathMax] = {0};
    if (!ResolveFdToPath(fd, path))
        return kEBADF;
    return ListPath(path, list, size);
}

i64 DoRemovexattr(u64 user_path, u64 user_name)
{
    char path[kPathMax] = {0};
    char name[kNameMax] = {0};
    if (!CopyUserCstr(user_path, path, kPathMax) || !CopyUserCstr(user_name, name, kNameMax))
        return kEFAULT;
    return RemoveEntry(path, name);
}
i64 DoLremovexattr(u64 path, u64 name)
{
    return DoRemovexattr(path, name);
}
i64 DoFremovexattr(u64 fd, u64 user_name)
{
    char path[kPathMax] = {0};
    char name[kNameMax] = {0};
    if (!ResolveFdToPath(fd, path))
        return kEBADF;
    if (!CopyUserCstr(user_name, name, kNameMax))
        return kEFAULT;
    return RemoveEntry(path, name);
}

} // namespace duetos::subsystems::linux::internal
