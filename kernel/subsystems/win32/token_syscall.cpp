/*
 * Win32 token-privilege adjustment — SYS_TOKEN_ADJUST.
 *
 * See token_syscall.h for the full design rationale and LUID→cap
 * mapping table. This TU is the kernel-side handler: it copies the
 * TOKEN_PRIVILEGES blob in, walks the LUID_AND_ATTRIBUTES array,
 * and either drops a mapped cap (disable / remove paths) or
 * refuses an enable that asks for a cap the caller doesn't hold.
 */

#include "subsystems/win32/token_syscall.h"

#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "security/broker.h"

namespace duetos::subsystems::win32
{

namespace
{

// LUID_AND_ATTRIBUTES is a 12-byte struct on x64:
//   [0..4)  LowPart    (u32)
//   [4..8)  HighPart   (i32)  — always 0 for the well-known privileges
//   [8..12) Attributes (u32)  — bitset of SE_PRIVILEGE_*.
constexpr u32 kLuidAndAttrBytes = 12;

// SE_PRIVILEGE_* attribute bits (winnt.h).
constexpr u32 kSePrivEnabledByDefault = 0x1;
constexpr u32 kSePrivEnabled = 0x2;
constexpr u32 kSePrivRemoved = 0x4;

// Hard cap on the privilege count we'll accept in one call. Real
// Windows tokens carry ~30 privileges max; 32 is plenty and bounds
// the on-stack scratch buffer.
constexpr u32 kMaxPrivilegeCount = 32;
constexpr u32 kMaxBlobBytes = 4 + kMaxPrivilegeCount * kLuidAndAttrBytes;

// Translate a Win32 privilege LUID-low to a DuetOS cap, or kCapNone
// if the privilege has no observable mapping.
core::Cap LuidLowToCap(u32 luid_low)
{
    using core::kCapDebug;
    using core::kCapFsRead;
    using core::kCapFsWrite;
    using core::kCapNone;
    using core::kCapSpawnThread;
    switch (luid_low)
    {
    case 14: // SeIncreaseBasePriorityPrivilege
        return kCapSpawnThread;
    case 17: // SeBackupPrivilege
        return kCapFsRead;
    case 18: // SeRestorePrivilege
        return kCapFsWrite;
    case 20: // SeDebugPrivilege
        return kCapDebug;
    default:
        return kCapNone;
    }
}

// Short, human-readable name for the prompt reason. We don't want to
// surface raw LUID numbers to the user — "SeDebugPrivilege" is what
// a Windows operator would expect to see in a UAC dialog.
const char* LuidLowToPrivilegeName(u32 luid_low)
{
    switch (luid_low)
    {
    case 14:
        return "SeIncreaseBasePriorityPrivilege";
    case 17:
        return "SeBackupPrivilege";
    case 18:
        return "SeRestorePrivilege";
    case 20:
        return "SeDebugPrivilege";
    default:
        return "Win32 privilege";
    }
}

bool LoadBlob(u64 user_blob, u32 byte_len, u8* dst, u32& out_count)
{
    if (byte_len < 4 || byte_len > kMaxBlobBytes)
        return false;
    if (!mm::CopyFromUser(dst, reinterpret_cast<const void*>(user_blob), byte_len))
        return false;
    const u32 count = *reinterpret_cast<const u32*>(dst);
    if (count > kMaxPrivilegeCount)
        return false;
    if (4u + count * kLuidAndAttrBytes > byte_len)
        return false;
    out_count = count;
    return true;
}

} // namespace

i64 SysTokenAdjust(u64 disable_all, u64 user_new, u64 user_new_len, u64 user_prev, u64 user_prev_cap)
{
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return -1;

    u8 prev_blob[kMaxBlobBytes];
    for (u32 i = 0; i < sizeof(prev_blob); ++i)
        prev_blob[i] = 0;

    if (disable_all != 0)
    {
        // Drop every cap that has a Win32-privilege mapping — the
        // canonical AdjustTokenPrivileges(disable_all=TRUE) path
        // a sandbox shim emits before launching untrusted code.
        // PreviousState is left zero — callers passing
        // disable_all rarely care about it.
        core::CapSetRemove(caller->caps, core::kCapDebug);
        core::CapSetRemove(caller->caps, core::kCapFsRead);
        core::CapSetRemove(caller->caps, core::kCapFsWrite);
        core::CapSetRemove(caller->caps, core::kCapSpawnThread);
        arch::SerialWrite("[win32/token] disable-all dropped Debug+FsRead+FsWrite+SpawnThread\n");
        return 0;
    }

    if (user_new == 0)
        return -1;

    u8 new_blob[kMaxBlobBytes];
    u32 count = 0;
    if (!LoadBlob(user_new, static_cast<u32>(user_new_len), new_blob, count))
        return -1;

    // PreviousState header mirrors the input shape.
    *reinterpret_cast<u32*>(prev_blob) = count;

    bool not_all_assigned = false;
    for (u32 i = 0; i < count; ++i)
    {
        u8* in_la = new_blob + 4 + i * kLuidAndAttrBytes;
        u8* prev_la = prev_blob + 4 + i * kLuidAndAttrBytes;
        const u32 luid_low = *reinterpret_cast<const u32*>(in_la);
        const u32 luid_high = *reinterpret_cast<const u32*>(in_la + 4);
        const u32 attrs = *reinterpret_cast<const u32*>(in_la + 8);

        // Mirror LUID into prev (Windows reports the privilege you
        // asked about in the writeback even on miss).
        *reinterpret_cast<u32*>(prev_la) = luid_low;
        *reinterpret_cast<u32*>(prev_la + 4) = luid_high;

        if (luid_high != 0)
        {
            // Real Win32 LUIDs all have HighPart = 0; non-zero
            // means the caller forged a LUID. Refuse with a
            // "not assigned" record but keep walking.
            *reinterpret_cast<u32*>(prev_la + 8) = 0;
            not_all_assigned = true;
            continue;
        }

        const core::Cap mapped = LuidLowToCap(luid_low);
        const u32 prev_attrs =
            (mapped != core::kCapNone && core::CapSetHas(caller->caps, mapped)) ? kSePrivEnabled : 0u;
        *reinterpret_cast<u32*>(prev_la + 8) = prev_attrs;

        if ((attrs & kSePrivRemoved) != 0)
        {
            // SE_PRIVILEGE_REMOVED — drop the mapped cap. Always
            // succeeds (CapSetRemove is idempotent); never blocks
            // the caller.
            if (mapped != core::kCapNone)
                core::CapSetRemove(caller->caps, mapped);
            continue;
        }

        if ((attrs & (kSePrivEnabled | kSePrivEnabledByDefault)) != 0)
        {
            if (mapped == core::kCapNone)
            {
                // Privilege we don't model — accept silently.
                continue;
            }
            if (!core::CapSetHas(caller->caps, mapped))
            {
                // Caller asked to enable a privilege whose cap
                // isn't on the token. Route through the elevation
                // broker (UAC-style): the broker prompts for the
                // logged-in user's password (deferred-prompt path,
                // since this syscall runs in the PE's task, not
                // the kbd-reader's), checks the role table, and
                // on success adds the cap to caller->caps and
                // caches the grant. Failure paths (no role grants
                // this cap, bad password, cancelled, no kbd reader
                // available) report STATUS_NOT_ALL_ASSIGNED — the
                // same shape an unprivileged Windows process sees
                // when the user clicks "No" on a UAC dialog.
                duetos::security::BrokerRequest req{};
                req.proc = caller;
                req.cap = mapped;
                req.reason = LuidLowToPrivilegeName(luid_low);
                const auto outcome = duetos::security::BrokerRequestElevation(req);
                if (outcome == duetos::security::BrokerOutcome::Granted)
                {
                    // Broker added the cap to caller->caps. Reflect
                    // the new state in PreviousState so a follow-up
                    // AdjustTokenPrivileges with the prev blob
                    // round-trips correctly.
                    *reinterpret_cast<u32*>(prev_la + 8) = kSePrivEnabled;
                    continue;
                }
                not_all_assigned = true;
                continue;
            }
            // Cap is already held; nothing to flip.
            continue;
        }

        // Attrs == 0 means "disable" in the AdjustTokenPrivileges
        // contract. Drop the cap.
        if (mapped != core::kCapNone)
            core::CapSetRemove(caller->caps, mapped);
    }

    if (user_prev != 0 && user_prev_cap >= 4u + count * kLuidAndAttrBytes)
    {
        const u32 want = 4u + count * kLuidAndAttrBytes;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_prev), prev_blob, want))
            return -1;
    }

    return not_all_assigned ? 1 : 0;
}

} // namespace duetos::subsystems::win32
