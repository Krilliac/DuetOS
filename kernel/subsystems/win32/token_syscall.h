#pragma once

/*
 * Win32 token-privilege adjustment — SYS_TOKEN_ADJUST.
 *
 * Backs ntdll.NtAdjustPrivilegesToken and (via advapi32 forwarding)
 * AdjustTokenPrivileges. Translates Win32 SE*Privilege LUIDs to the
 * caller's CapSet (kernel/proc/process.h). The userland token
 * surface (NtOpenProcessToken / NtQueryInformationToken) stays a
 * facade — the kernel's CapSet is the actual gate.
 *
 * v0 mappings:
 *   - SeDebugPrivilege       (LUID 20) → kCapDebug
 *   - SeBackupPrivilege      (LUID 17) → kCapFsRead
 *   - SeRestorePrivilege     (LUID 18) → kCapFsWrite
 *   - SeIncBasePriorityPriv. (LUID 14) → kCapSpawnThread
 *
 * Privileges with no DuetOS mapping (SeShutdownPrivilege,
 * SeSecurityPrivilege, SeTcbPrivilege, ...) are accepted as a
 * silent no-op — Windows lets a process "enable" a privilege that
 * isn't gated on anything DuetOS observes, so we match that shape.
 *
 * Adding a cap from user space is intentionally impossible: the
 * handler can only DROP caps (CapSetRemove). A process that wants
 * a cap it doesn't have was never going to be granted one by
 * asking nicely — Windows AdjustTokenPrivileges has the same
 * property in practice (privileges have to be on the token first,
 * which is set at creation time, not via this API).
 */

#include "util/types.h"

namespace duetos::subsystems::win32
{

i64 SysTokenAdjust(u64 disable_all, u64 user_new, u64 user_new_len, u64 user_prev, u64 user_prev_cap);

} // namespace duetos::subsystems::win32
