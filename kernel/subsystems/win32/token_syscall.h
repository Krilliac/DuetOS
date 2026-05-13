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
 * Enabling a privilege whose cap isn't already on the token routes
 * through the elevation broker (kernel/security/broker.h) — the
 * UAC-equivalent. The broker prompts for the logged-in user's
 * password (via the deferred-prompt mechanism, since the syscall
 * runs in the PE's task rather than the kbd-reader's), checks the
 * role table, and on a "Yes + correct password" outcome adds the
 * cap and caches the grant for the role's configured window.
 * "No" / wrong password / cancelled / role table refused all map
 * to the legacy STATUS_NOT_ALL_ASSIGNED return shape.
 */

#include "util/types.h"

namespace duetos::subsystems::win32
{

i64 SysTokenAdjust(u64 disable_all, u64 user_new, u64 user_new_len, u64 user_prev, u64 user_prev_cap);

} // namespace duetos::subsystems::win32
