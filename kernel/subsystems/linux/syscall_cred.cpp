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

#include "syscall_internal.h"

#include "../../mm/address_space.h"

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
    (void)user_hdr;
    (void)user_data;
    return 0;
}
i64 DoCapset(u64 user_hdr, u64 user_data)
{
    (void)user_hdr;
    (void)user_data;
    return 0;
}

} // namespace duetos::subsystems::linux::internal
