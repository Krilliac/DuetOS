/*
 * DuetOS — Linux ABI: credential handlers.
 *
 * Sibling TU of syscall.cpp. Houses the get/set uid/gid/euid/egid
 * /resuid/resgid/fsuid/fsgid + groups + POSIX capabilities entry
 * points. v0 has no Linux-style user account model; every handler
 * either returns 0 (the uid/gid we model is 0 across the board)
 * or accepts the call as a no-op so setuid-style daemons and
 * libcap-using programs initialise without bailing.
 *
 * The dispatcher in syscall.cpp calls these via the
 * `internal::Do*` declarations in syscall_internal.h.
 */

#include "subsystems/linux/syscall_internal.h"

#include "mm/address_space.h"
#include "mm/paging.h"

namespace duetos::subsystems::linux::internal
{

// getuid / getgid / geteuid / getegid: DuetOS doesn't have a user-
// account model yet. Returning 0 satisfies musl's libc.a startup
// without misleading it: programs that check for root will see
// "yes you're root," which is consistent with "there are no
// privilege boundaries here."
i64 DoGetUid()
{
    return 0;
}
i64 DoGetGid()
{
    return 0;
}
i64 DoGetEuid()
{
    return 0;
}
i64 DoGetEgid()
{
    return 0;
}

// setuid / setgid / setreuid / setregid / setresuid / setresgid:
// v0 is uid 0 / gid 0 across the board. Accept the call as a
// no-op so setuid-root daemons started under us don't fail.
i64 DoSetuid(u64 uid)
{
    (void)uid;
    return 0;
}
i64 DoSetgid(u64 gid)
{
    (void)gid;
    return 0;
}
i64 DoSetreuid(u64 ruid, u64 euid)
{
    (void)ruid;
    (void)euid;
    return 0;
}
i64 DoSetregid(u64 rgid, u64 egid)
{
    (void)rgid;
    (void)egid;
    return 0;
}
i64 DoSetresuid(u64 ruid, u64 euid, u64 suid)
{
    (void)ruid;
    (void)euid;
    (void)suid;
    return 0;
}
i64 DoSetresgid(u64 rgid, u64 egid, u64 sgid)
{
    (void)rgid;
    (void)egid;
    (void)sgid;
    return 0;
}

// getresuid / getresgid (id_t* ruid, id_t* euid, id_t* suid):
// write three u32 zeros so the caller sees a consistent uid/gid
// triple. Bad pointers surface as EFAULT.
i64 DoGetresuid(u64 user_r, u64 user_e, u64 user_s)
{
    const u32 zero = 0;
    if (user_r != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_r), &zero, sizeof(zero)))
        return kEFAULT;
    if (user_e != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_e), &zero, sizeof(zero)))
        return kEFAULT;
    if (user_s != 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_s), &zero, sizeof(zero)))
        return kEFAULT;
    return 0;
}
i64 DoGetresgid(u64 user_r, u64 user_e, u64 user_s)
{
    return DoGetresuid(user_r, user_e, user_s);
}

// setfsuid / setfsgid: returns the PREVIOUS fsuid/fsgid, which
// is always 0 in v0.
i64 DoSetfsuid(u64 uid)
{
    (void)uid;
    return 0;
}
i64 DoSetfsgid(u64 gid)
{
    (void)gid;
    return 0;
}

// getgroups(size, list): return the supplementary group list.
// v0 has none; return 0 (count of groups in the list). Linux
// allows size=0 as a "how many groups would there be" probe;
// our answer is still 0.
i64 DoGetgroups(u64 size, u64 user_list)
{
    (void)size;
    (void)user_list;
    return 0;
}
// setgroups(size, list): accept as no-op. Refusing would break
// setuid-style binaries that drop their groups before privsep.
i64 DoSetgroups(u64 size, u64 user_list)
{
    (void)size;
    (void)user_list;
    return 0;
}

// capget / capset: POSIX capabilities. v0 has no Linux-style
// capability model (we have our own CapSet, but it's not the
// same shape). Accept the call as a no-op so libcap-using
// programs initialise without complaining.
i64 DoCapget(u64 user_hdr, u64 user_data)
{
    // capget needs at least the header (8 bytes: u32 version +
    // u32 pid). NULL hdr is the canonical Linux -EFAULT case.
    if (user_hdr == 0)
        return kEFAULT;
    struct CapHdr
    {
        u32 version;
        i32 pid;
    } hdr = {};
    if (!mm::CopyFromUser(&hdr, reinterpret_cast<const void*>(user_hdr), sizeof(hdr)))
        return kEFAULT;
    constexpr u32 kCapV3 = 0x20080522;
    constexpr u32 kCapV2 = 0x20071026;
    constexpr u32 kCapV1 = 0x19980330;
    if (hdr.version != kCapV3 && hdr.version != kCapV2 && hdr.version != kCapV1)
    {
        // Linux convention: rewrite header.version to current
        // and return -EINVAL so libcap can probe + retry. The
        // writeback is informational (lets libcap learn which
        // version IS supported on its next call); if the user's
        // header pointer is bad the probe simply doesn't learn
        // the version, but -EINVAL still tells it the call was
        // refused. Returning -EFAULT here instead would break
        // the libcap probe contract.
        const u32 fixed = kCapV3;
        (void)mm::CopyToUser(reinterpret_cast<void*>(user_hdr), &fixed, sizeof(fixed));
        return kEINVAL;
    }
    if (user_data != 0)
    {
        // Three u32 cap masks (effective / permitted /
        // inheritable) per "set" — 24 bytes for v3 (two 32-bit
        // halves), 12 bytes for v1/v2. Report the empty cap
        // set; v0 doesn't model the Linux ABI capability mask.
        u32 zeros[6] = {0, 0, 0, 0, 0, 0};
        const u32 sz = (hdr.version == kCapV3) ? 24 : 12;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_data), zeros, sz))
            return kEFAULT;
    }
    return 0;
}
i64 DoCapset(u64 user_hdr, u64 user_data)
{
    if (user_hdr == 0 || user_data == 0)
        return kEFAULT;
    struct CapHdr
    {
        u32 version;
        i32 pid;
    } hdr = {};
    if (!mm::CopyFromUser(&hdr, reinterpret_cast<const void*>(user_hdr), sizeof(hdr)))
        return kEFAULT;
    constexpr u32 kCapV3 = 0x20080522;
    constexpr u32 kCapV2 = 0x20071026;
    constexpr u32 kCapV1 = 0x19980330;
    if (hdr.version != kCapV3 && hdr.version != kCapV2 && hdr.version != kCapV1)
    {
        const u32 fixed = kCapV3;
        (void)mm::CopyToUser(reinterpret_cast<void*>(user_hdr), &fixed, sizeof(fixed));
        return kEINVAL;
    }
    // v0 doesn't actually mutate the Linux-ABI capability mask
    // (we have our own kCap* model on Process::caps). Accept
    // silently — libcap-using daemons proceed, even if their
    // capability writes are no-ops.
    return 0;
}

} // namespace duetos::subsystems::linux::internal
