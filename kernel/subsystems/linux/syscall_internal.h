#pragma once

// Private cross-TU surface for the Linux ABI subsystem. Splits
// the implementation across multiple translation units that share
// the constants + handler declarations below:
//
//   syscall.cpp      — dispatcher, public wrappers, handlers not
//                      yet extracted into per-domain TUs.
//   syscall_cred.cpp — uid/gid/groups/capabilities handlers.
//
// Anything in `namespace duetos::subsystems::linux::internal` is
// intended for the subsystem's own TUs only — never include this
// header from outside kernel/subsystems/linux/. The public API
// lives in syscall.h.

#include "../../core/types.h"

namespace duetos::subsystems::linux::internal
{

// Canonical Linux errno values used by handlers we implement.
// Linux returns errno via a negative rax — these constants are
// the negated values so handlers can `return kEXXX` directly.
inline constexpr i64 kEPERM = -1;
inline constexpr i64 kENOENT = -2;
inline constexpr i64 kESRCH = -3;
inline constexpr i64 kEIO = -5;
inline constexpr i64 kEBADF = -9;
inline constexpr i64 kENOMEM = -12;
inline constexpr i64 kEFAULT = -14;
inline constexpr i64 kEISDIR = -21;
inline constexpr i64 kEINVAL = -22;
inline constexpr i64 kEMFILE = -24;
inline constexpr i64 kENOTTY = -25;
inline constexpr i64 kESPIPE = -29;
inline constexpr i64 kERANGE = -34;
inline constexpr i64 kENAMETOOLONG = -36;
inline constexpr i64 kENOSYS = -38;

// Resource limit handlers (syscall_rlimit.cpp). v0 reports the
// real ceilings where it has them (NOFILE 16, NPROC 64, STACK
// 64 KiB, NICE 20) and RLIM_INFINITY for everything else.
i64 DoGetrlimit(u64 resource, u64 user_old);
i64 DoSetrlimit(u64 resource, u64 user_new);
i64 DoPrlimit64(u64 pid, u64 resource, u64 user_new, u64 user_old);

// Credential handlers (syscall_cred.cpp). All are uid-0/gid-0
// no-ops in v0 — DuetOS has no Linux-style user account model.
i64 DoGetUid();
i64 DoGetGid();
i64 DoGetEuid();
i64 DoGetEgid();
i64 DoSetuid(u64 uid);
i64 DoSetgid(u64 gid);
i64 DoSetreuid(u64 ruid, u64 euid);
i64 DoSetregid(u64 rgid, u64 egid);
i64 DoSetresuid(u64 ruid, u64 euid, u64 suid);
i64 DoSetresgid(u64 rgid, u64 egid, u64 sgid);
i64 DoGetresuid(u64 user_r, u64 user_e, u64 user_s);
i64 DoGetresgid(u64 user_r, u64 user_e, u64 user_s);
i64 DoSetfsuid(u64 uid);
i64 DoSetfsgid(u64 gid);
i64 DoGetgroups(u64 size, u64 user_list);
i64 DoSetgroups(u64 size, u64 user_list);
i64 DoCapget(u64 user_hdr, u64 user_data);
i64 DoCapset(u64 user_hdr, u64 user_data);

} // namespace duetos::subsystems::linux::internal
