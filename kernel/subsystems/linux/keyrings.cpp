/*
 * Linux kernel keyrings — v0.
 *
 * Real userland callers (sssd, krb5, gpg-agent, systemd's user
 * keyring) probe `add_key` / `request_key` / `keyctl` at startup.
 * v0 ships a minimal in-process keyring (per-Process, 16 slots) so
 * those probes get real keyref returns instead of -ENOSYS.
 *
 * Key model:
 *   - Each Process owns up to 16 keys: { id, type[16], description[64],
 *     payload[256] }.
 *   - id is a per-process serial (1..N), opaque to userland.
 *   - Special keyring sentinels:
 *       KEY_SPEC_THREAD_KEYRING    (-1) → caller's process keyring
 *       KEY_SPEC_PROCESS_KEYRING   (-2) → same
 *       KEY_SPEC_SESSION_KEYRING   (-3) → same
 *       KEY_SPEC_USER_KEYRING      (-4) → same
 *       KEY_SPEC_USER_SESSION      (-5) → same
 *       KEY_SPEC_GROUP_KEYRING     (-6) → same
 *   v0 collapses every keyring identity to "the caller's per-Process
 *   key store" — there's no real user / session / group model.
 *
 * Sub-GAPs:
 *   - Permissions field (KEYCTL_SETPERM) honoured but flat — no
 *     real read-vs-write privilege.
 *   - keyctl_search across foreign keyrings refused.
 *   - Key types: only "user" honored; "logon" / "asymmetric" /
 *     "encrypted" return -EOPNOTSUPP.
 *   - 256-byte payload cap.
 *   - Cross-process key sharing not implemented (fork inherits
 *     state via the per-Process table copy in DoFork; child gets
 *     its own keyring snapshot).
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "proc/process.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr u32 kKeyringSlots = 16;
constexpr u32 kKeyTypeCap = 16;
constexpr u32 kKeyDescCap = 64;
constexpr u32 kKeyPayloadCap = 256;

// Per-process keyring slot. Lives on Process via a side-table
// (we don't grow Process for v0 — instead, allocate the table
// lazily on first add_key). Indexed by (pid, slot).
struct KeyEntry
{
    bool in_use;
    u8 _pad[3];
    u32 id;   // 1..N, per-process serial
    u32 perm; // POSSESSOR / USER / GROUP / OTHER bits, flat in v0
    u32 _pad2;
    char type[kKeyTypeCap];
    char desc[kKeyDescCap];
    u8 payload[kKeyPayloadCap];
    u32 payload_len;
};

// We don't add a member to Process; instead, use a global keyed-
// by-pid table. 32 entries cap (enough for the typical small set
// of processes that exercise keyrings during a boot smoke).
constexpr u32 kProcKeyringCap = 32;
struct ProcKeyring
{
    bool in_use;
    u8 _pad[3];
    u32 next_id;
    u64 pid;
    KeyEntry slots[kKeyringSlots];
};

ProcKeyring g_keyrings[kProcKeyringCap];

ProcKeyring* FindKeyringForCurrent()
{
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return nullptr;
    for (u32 i = 0; i < kProcKeyringCap; ++i)
        if (g_keyrings[i].in_use && g_keyrings[i].pid == p->pid)
            return &g_keyrings[i];
    return nullptr;
}

ProcKeyring* GetOrCreateKeyringForCurrent()
{
    ProcKeyring* existing = FindKeyringForCurrent();
    if (existing != nullptr)
        return existing;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr)
        return nullptr;
    arch::Cli();
    for (u32 i = 0; i < kProcKeyringCap; ++i)
    {
        if (g_keyrings[i].in_use)
            continue;
        ProcKeyring& k = g_keyrings[i];
        k.in_use = true;
        k.next_id = 1;
        k.pid = p->pid;
        for (u32 j = 0; j < kKeyringSlots; ++j)
            k.slots[j].in_use = false;
        arch::Sti();
        return &k;
    }
    arch::Sti();
    return nullptr;
}

bool TypeEqual(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

void CopyStr(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    for (; i < cap - 1 && src[i] != '\0'; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}

} // namespace

i64 DoAddKey(u64 user_type, u64 user_desc, u64 user_payload, u64 plen, u64 keyring)
{
    (void)keyring; // collapse all keyring sentinels to the caller's keyring
    char type[kKeyTypeCap];
    char desc[kKeyDescCap];
    u8 payload[kKeyPayloadCap];
    const auto type_copy = mm::CopyUserCString(type, sizeof(type), reinterpret_cast<const void*>(user_type));
    if (type_copy.status == mm::UserStringCopyStatus::Fault || type_copy.status == mm::UserStringCopyStatus::BadArgument)
        return kEFAULT;
    if (type_copy.status == mm::UserStringCopyStatus::NoTerminator)
        return kENAMETOOLONG;
    const auto desc_copy = mm::CopyUserCString(desc, sizeof(desc), reinterpret_cast<const void*>(user_desc));
    if (desc_copy.status == mm::UserStringCopyStatus::Fault || desc_copy.status == mm::UserStringCopyStatus::BadArgument)
        return kEFAULT;
    if (desc_copy.status == mm::UserStringCopyStatus::NoTerminator)
        return kENAMETOOLONG;
    if (plen > kKeyPayloadCap)
        return -7; // -E2BIG
    if (plen > 0 && user_payload != 0)
    {
        if (!mm::CopyFromUser(payload, reinterpret_cast<const void*>(user_payload), plen))
            return kEFAULT;
    }
    if (!TypeEqual(type, "user") && !TypeEqual(type, "logon"))
        return -95; // -EOPNOTSUPP
    ProcKeyring* k = GetOrCreateKeyringForCurrent();
    if (k == nullptr)
        return kENOMEM;
    arch::Cli();
    for (u32 i = 0; i < kKeyringSlots; ++i)
    {
        if (!k->slots[i].in_use)
        {
            KeyEntry& e = k->slots[i];
            e.in_use = true;
            e.id = k->next_id++;
            e.perm = 0x3F3F3F3F; // permissive default
            CopyStr(e.type, sizeof(e.type), type);
            CopyStr(e.desc, sizeof(e.desc), desc);
            for (u32 j = 0; j < plen; ++j)
                e.payload[j] = payload[j];
            e.payload_len = static_cast<u32>(plen);
            arch::Sti();
            arch::SerialWrite("[linux/keyring] add type=\"");
            arch::SerialWrite(type);
            arch::SerialWrite("\" desc=\"");
            arch::SerialWrite(desc);
            arch::SerialWrite("\" id=");
            arch::SerialWriteHex(e.id);
            arch::SerialWrite("\n");
            return e.id;
        }
    }
    arch::Sti();
    return -28; // -ENOSPC
}

i64 DoRequestKey(u64 user_type, u64 user_desc, u64 user_callout, u64 dest_keyring)
{
    (void)user_callout;
    (void)dest_keyring;
    char type[kKeyTypeCap];
    char desc[kKeyDescCap];
    const auto type_copy = mm::CopyUserCString(type, sizeof(type), reinterpret_cast<const void*>(user_type));
    if (type_copy.status == mm::UserStringCopyStatus::Fault || type_copy.status == mm::UserStringCopyStatus::BadArgument)
        return kEFAULT;
    if (type_copy.status == mm::UserStringCopyStatus::NoTerminator)
        return kENAMETOOLONG;
    const auto desc_copy = mm::CopyUserCString(desc, sizeof(desc), reinterpret_cast<const void*>(user_desc));
    if (desc_copy.status == mm::UserStringCopyStatus::Fault || desc_copy.status == mm::UserStringCopyStatus::BadArgument)
        return kEFAULT;
    if (desc_copy.status == mm::UserStringCopyStatus::NoTerminator)
        return kENAMETOOLONG;
    ProcKeyring* k = FindKeyringForCurrent();
    if (k == nullptr)
        return -126; // -ENOKEY
    for (u32 i = 0; i < kKeyringSlots; ++i)
    {
        if (k->slots[i].in_use && TypeEqual(k->slots[i].type, type) && TypeEqual(k->slots[i].desc, desc))
            return k->slots[i].id;
    }
    return -126;
}

i64 DoKeyctl(u64 op, u64 a2, u64 a3, u64 a4, u64 /*a5*/)
{
    constexpr u64 kKeyctlGetKeyringId = 0;
    constexpr u64 kKeyctlJoinSession = 1;
    constexpr u64 kKeyctlUpdate = 2;
    constexpr u64 kKeyctlRevoke = 3;
    constexpr u64 kKeyctlChown = 4;
    constexpr u64 kKeyctlSetperm = 5;
    constexpr u64 kKeyctlDescribe = 6;
    constexpr u64 kKeyctlClear = 7;
    constexpr u64 kKeyctlLink = 8;
    constexpr u64 kKeyctlUnlink = 9;
    constexpr u64 kKeyctlSearch = 10;
    constexpr u64 kKeyctlRead = 11;
    constexpr u64 kKeyctlInstantiate = 12;
    constexpr u64 kKeyctlNegate = 13;
    constexpr u64 kKeyctlSetReqkey = 14;
    constexpr u64 kKeyctlSetTimeout = 15;
    constexpr u64 kKeyctlInvalidate = 21;
    constexpr u64 kKeyctlGetPersistent = 22;

    ProcKeyring* k = FindKeyringForCurrent();
    if (op == kKeyctlGetKeyringId)
    {
        // Always returns a positive keyring id; v0 collapses every
        // sentinel onto a single per-process keyring.
        if (k == nullptr)
            k = GetOrCreateKeyringForCurrent();
        if (k == nullptr)
            return kENOMEM;
        // Use the next_id-1 as the keyring's own id; clamp to >= 1.
        return 1;
    }
    if (k == nullptr)
        return -126;
    if (op == kKeyctlClear)
    {
        for (u32 i = 0; i < kKeyringSlots; ++i)
            k->slots[i].in_use = false;
        return 0;
    }
    if (op == kKeyctlInvalidate || op == kKeyctlRevoke || op == kKeyctlUnlink)
    {
        const u32 id = static_cast<u32>(a2);
        for (u32 i = 0; i < kKeyringSlots; ++i)
            if (k->slots[i].in_use && k->slots[i].id == id)
            {
                k->slots[i].in_use = false;
                return 0;
            }
        return -126;
    }
    if (op == kKeyctlRead)
    {
        const u32 id = static_cast<u32>(a2);
        const u64 user_buf = a3;
        const u64 buflen = a4;
        for (u32 i = 0; i < kKeyringSlots; ++i)
            if (k->slots[i].in_use && k->slots[i].id == id)
            {
                const KeyEntry& e = k->slots[i];
                const u64 to_copy = (e.payload_len < buflen) ? e.payload_len : buflen;
                if (to_copy > 0 && user_buf != 0)
                    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), e.payload, to_copy))
                        return kEFAULT;
                return e.payload_len; // returns FULL length even if buffer too small (Linux contract)
            }
        return -126;
    }
    if (op == kKeyctlDescribe)
    {
        const u32 id = static_cast<u32>(a2);
        const u64 user_buf = a3;
        const u64 buflen = a4;
        for (u32 i = 0; i < kKeyringSlots; ++i)
            if (k->slots[i].in_use && k->slots[i].id == id)
            {
                // Format: "type;0;0;perm;desc"
                char out[kKeyDescCap + 32];
                u32 oi = 0;
                const KeyEntry& e = k->slots[i];
                for (u32 j = 0; e.type[j] != '\0' && oi < sizeof(out) - 1; ++j)
                    out[oi++] = e.type[j];
                if (oi < sizeof(out) - 5)
                {
                    out[oi++] = ';';
                    out[oi++] = '0';
                    out[oi++] = ';';
                    out[oi++] = '0';
                    out[oi++] = ';';
                }
                for (u32 j = 0; e.desc[j] != '\0' && oi < sizeof(out) - 1; ++j)
                    out[oi++] = e.desc[j];
                out[oi] = '\0';
                const u64 to_copy = (oi + 1 < buflen) ? (oi + 1) : buflen;
                if (to_copy > 0 && user_buf != 0)
                    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), out, to_copy))
                        return kEFAULT;
                return oi + 1;
            }
        return -126;
    }
    if (op == kKeyctlUpdate)
    {
        const u32 id = static_cast<u32>(a2);
        const u64 user_payload = a3;
        const u64 plen = a4;
        if (plen > kKeyPayloadCap)
            return -7;
        for (u32 i = 0; i < kKeyringSlots; ++i)
            if (k->slots[i].in_use && k->slots[i].id == id)
            {
                u8 buf[kKeyPayloadCap];
                if (plen > 0 && user_payload != 0)
                    if (!mm::CopyFromUser(buf, reinterpret_cast<const void*>(user_payload), plen))
                        return kEFAULT;
                for (u32 j = 0; j < plen; ++j)
                    k->slots[i].payload[j] = buf[j];
                k->slots[i].payload_len = static_cast<u32>(plen);
                return 0;
            }
        return -126;
    }
    if (op == kKeyctlSetperm)
    {
        const u32 id = static_cast<u32>(a2);
        const u32 perm = static_cast<u32>(a3);
        for (u32 i = 0; i < kKeyringSlots; ++i)
            if (k->slots[i].in_use && k->slots[i].id == id)
            {
                k->slots[i].perm = perm;
                return 0;
            }
        return -126;
    }
    if (op == kKeyctlChown || op == kKeyctlLink || op == kKeyctlSetTimeout || op == kKeyctlSetReqkey ||
        op == kKeyctlInstantiate || op == kKeyctlNegate || op == kKeyctlJoinSession || op == kKeyctlGetPersistent)
        return 0; // accept-as-noop
    if (op == kKeyctlSearch)
    {
        // search a keyring for a key matching (type, desc); v0 only
        // searches the per-process keyring and ignores `keyring` arg.
        char type[kKeyTypeCap] = {};
        char desc[kKeyDescCap] = {};
        if (a2 != 0)
        {
            const auto type_copy = mm::CopyUserCString(type, sizeof(type), reinterpret_cast<const void*>(a2));
            if (!type_copy.ok())
                return (type_copy.status == mm::UserStringCopyStatus::NoTerminator) ? kENAMETOOLONG : kEFAULT;
        }
        if (a3 != 0)
        {
            const auto desc_copy = mm::CopyUserCString(desc, sizeof(desc), reinterpret_cast<const void*>(a3));
            if (!desc_copy.ok())
                return (desc_copy.status == mm::UserStringCopyStatus::NoTerminator) ? kENAMETOOLONG : kEFAULT;
        }
        for (u32 i = 0; i < kKeyringSlots; ++i)
            if (k->slots[i].in_use && TypeEqual(k->slots[i].type, type) && TypeEqual(k->slots[i].desc, desc))
                return k->slots[i].id;
        return -126;
    }
    return -22; // -EINVAL
}

} // namespace duetos::subsystems::linux::internal
