/*
 * DuetOS — Role-Based Access Control, v0.
 *
 * See rbac.h for the public contract and the design rationale.
 */

#include "security/rbac.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "security/persistence.h"
#include "util/string.h"
#include "util/types.h"

namespace duetos::security
{

using duetos::core::Cap;
using duetos::core::kCapCount;
using duetos::core::kCapNone;
using duetos::core::Panic;
using duetos::core::StrEqual;
using duetos::core::StrLen;

namespace
{

constexpr u32 kRbacMaxMemberships = duetos::core::kAuthMaxAccounts;

// Two simple in-memory tables. The role table is small enough that
// every lookup is a linear scan; same for memberships. v0 is fixed
// size, never grows past these bounds.
Role g_roles[kRbacMaxRoles];
AccountMembership g_memberships[kRbacMaxMemberships];
bool g_initialized = false;

void StrCopy(char* dst, const char* src, u32 cap)
{
    u32 i = 0;
    for (; i + 1 < cap && src[i] != '\0'; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}

void PolicyInitDefaults(RolePolicy& p, u64 mask)
{
    p.cap_mask = mask;
    for (u32 c = 0; c < kCapCount; ++c)
        p.grace_seconds[c] = RolePolicy::kUseDefault;
}

RoleId AllocRoleSlot()
{
    for (u32 i = 0; i < kRbacMaxRoles; ++i)
    {
        if (!g_roles[i].in_use)
            return i;
    }
    return kRbacRoleInvalid;
}

u32 AllocMembershipSlot()
{
    for (u32 i = 0; i < kRbacMaxMemberships; ++i)
    {
        if (!g_memberships[i].in_use)
            return i;
    }
    return ~0u;
}

u32 FindMembership(const char* username)
{
    for (u32 i = 0; i < kRbacMaxMemberships; ++i)
    {
        if (g_memberships[i].in_use && StrEqual(g_memberships[i].username, username))
            return i;
    }
    return ~0u;
}

RoleId SeedRoot()
{
    RolePolicy p{};
    u64 mask = 0;
    for (u32 c = 1; c < kCapCount; ++c)
        mask |= (1ULL << c);
    PolicyInitDefaults(p, mask);
    // Network admin always reprompts even for root — destructive
    // firewall changes are exactly the surface where stale cache
    // hurts most.
    p.grace_seconds[duetos::core::kCapNetAdmin] = kRbacNoGrace;
    return RbacRegisterRole("root", p);
}

RoleId SeedDeveloper()
{
    RolePolicy p{};
    const u64 mask = (1ULL << duetos::core::kCapFsRead) | (1ULL << duetos::core::kCapFsWrite) |
                     (1ULL << duetos::core::kCapSpawnThread) | (1ULL << duetos::core::kCapDebug) |
                     (1ULL << duetos::core::kCapSerialConsole) | (1ULL << duetos::core::kCapInput);
    PolicyInitDefaults(p, mask);
    // Long-running builds: 30 min grace on file writes.
    p.grace_seconds[duetos::core::kCapFsWrite] = 1800;
    return RbacRegisterRole("developer", p);
}

RoleId SeedNetop()
{
    RolePolicy p{};
    const u64 mask =
        (1ULL << duetos::core::kCapNet) | (1ULL << duetos::core::kCapNetAdmin) | (1ULL << duetos::core::kCapFsRead);
    PolicyInitDefaults(p, mask);
    p.grace_seconds[duetos::core::kCapNetAdmin] = kRbacNoGrace;
    return RbacRegisterRole("netop", p);
}

RoleId SeedAuditor()
{
    RolePolicy p{};
    const u64 mask = (1ULL << duetos::core::kCapFsRead) | (1ULL << duetos::core::kCapSerialConsole) |
                     (1ULL << duetos::core::kCapInput);
    PolicyInitDefaults(p, mask);
    return RbacRegisterRole("auditor", p);
}

RoleId SeedSandbox()
{
    RolePolicy p{};
    PolicyInitDefaults(p, 0);
    return RbacRegisterRole("sandbox", p);
}

} // namespace

RoleId RbacFindRole(const char* name)
{
    for (u32 i = 0; i < kRbacMaxRoles; ++i)
    {
        if (g_roles[i].in_use && StrEqual(g_roles[i].name, name))
            return i;
    }
    return kRbacRoleInvalid;
}

bool RbacGetRole(RoleId id, Role* out)
{
    if (id >= kRbacMaxRoles || !g_roles[id].in_use || out == nullptr)
        return false;
    *out = g_roles[id];
    return true;
}

RoleId RbacRegisterRole(const char* name, const RolePolicy& policy)
{
    if (name == nullptr || name[0] == '\0')
        return kRbacRoleInvalid;
    if (StrLen(name) >= kRbacRoleNameMax)
        return kRbacRoleInvalid;
    if (RbacFindRole(name) != kRbacRoleInvalid)
        return kRbacRoleInvalid;
    const RoleId slot = AllocRoleSlot();
    if (slot == kRbacRoleInvalid)
        return kRbacRoleInvalid;
    Role& r = g_roles[slot];
    StrCopy(r.name, name, kRbacRoleNameMax);
    r.policy = policy;
    r.in_use = true;
    return slot;
}

bool RbacAddMembership(const char* username, RoleId role)
{
    if (username == nullptr || username[0] == '\0')
        return false;
    if (role >= kRbacMaxRoles || !g_roles[role].in_use)
        return false;
    u32 idx = FindMembership(username);
    if (idx == ~0u)
    {
        idx = AllocMembershipSlot();
        if (idx == ~0u)
            return false;
        AccountMembership& m = g_memberships[idx];
        StrCopy(m.username, username, duetos::core::kAuthNameMax);
        m.role_mask = 0;
        m.in_use = true;
    }
    g_memberships[idx].role_mask |= (1u << role);
    return true;
}

bool RbacRemoveMembership(const char* username, RoleId role)
{
    const u32 idx = FindMembership(username);
    if (idx == ~0u)
        return false;
    if (role >= kRbacMaxRoles)
        return false;
    const u32 before = g_memberships[idx].role_mask;
    g_memberships[idx].role_mask &= ~(1u << role);
    if (g_memberships[idx].role_mask == 0)
    {
        // No remaining roles — free the slot so the table doesn't
        // accumulate dead rows after lots of remove/re-add cycles.
        g_memberships[idx].in_use = false;
    }
    return before != g_memberships[idx].role_mask;
}

bool RbacIsMember(const char* username, RoleId role)
{
    if (role >= kRbacMaxRoles)
        return false;
    const u32 idx = FindMembership(username);
    if (idx == ~0u)
        return false;
    return (g_memberships[idx].role_mask & (1u << role)) != 0;
}

u32 RbacAccountRoleMask(const char* username)
{
    const u32 idx = FindMembership(username);
    return (idx == ~0u) ? 0u : g_memberships[idx].role_mask;
}

bool RbacResolveElevation(const char* username, Cap cap, RoleId* out_role, u32* out_grace_seconds)
{
    if (cap == kCapNone || cap >= kCapCount)
        return false;
    const u32 mask = RbacAccountRoleMask(username);
    if (mask == 0)
        return false;
    const u64 cap_bit = 1ULL << static_cast<u32>(cap);
    for (u32 i = 0; i < kRbacMaxRoles; ++i)
    {
        if ((mask & (1u << i)) == 0)
            continue;
        if (!g_roles[i].in_use)
            continue;
        if ((g_roles[i].policy.cap_mask & cap_bit) == 0)
            continue;
        if (out_role != nullptr)
            *out_role = i;
        if (out_grace_seconds != nullptr)
        {
            const u16 raw = g_roles[i].policy.grace_seconds[static_cast<u32>(cap)];
            u32 grace = (raw == RolePolicy::kUseDefault) ? kRbacDefaultGraceSeconds : raw;
            if (grace > kRbacMaxGraceSeconds)
                grace = kRbacMaxGraceSeconds;
            *out_grace_seconds = grace;
        }
        return true;
    }
    return false;
}

u32 RbacRoleCount()
{
    u32 n = 0;
    for (u32 i = 0; i < kRbacMaxRoles; ++i)
    {
        if (g_roles[i].in_use)
            ++n;
    }
    return n;
}

bool RbacRoleAt(u32 idx, Role* out)
{
    u32 seen = 0;
    for (u32 i = 0; i < kRbacMaxRoles; ++i)
    {
        if (!g_roles[i].in_use)
            continue;
        if (seen == idx)
        {
            if (out != nullptr)
                *out = g_roles[i];
            return true;
        }
        ++seen;
    }
    return false;
}

void RbacInit()
{
    // GAP: role + membership tables are in-memory only — re-seeds
    // on every boot. Persistence is blocked on a writable system
    // FS + the /system/secrets layout; tracked in
    // wiki/reference/Roadmap.md (RBAC v1 follow-ups).
    FIX_NOTE_GAP("security/rbac.cpp:RbacInit", "persist role + membership tables across boots");
    for (u32 i = 0; i < kRbacMaxRoles; ++i)
        g_roles[i].in_use = false;
    for (u32 i = 0; i < kRbacMaxMemberships; ++i)
        g_memberships[i].in_use = false;

    const RoleId root_id = SeedRoot();
    SeedDeveloper();
    SeedNetop();
    SeedAuditor();
    const RoleId sandbox_id = SeedSandbox();

    if (root_id == kRbacRoleInvalid || sandbox_id == kRbacRoleInvalid)
        Panic("rbac", "built-in role registration failed");

    // Default memberships. The built-in admin account joins root;
    // the guest account joins sandbox; if a non-admin "user" account
    // exists (it doesn't in the v0 seed but might in test fixtures),
    // bind it to developer.
    RbacAddMembership("admin", root_id);
    RbacAddMembership("guest", sandbox_id);
    const RoleId dev_id = RbacFindRole("developer");
    if (dev_id != kRbacRoleInvalid)
        RbacAddMembership("user", dev_id);

    g_initialized = true;
}

void RbacSelfTest()
{
    arch::SerialWrite("[rbac] self-test: seeded roles + membership round-trip\n");

    if (RbacFindRole("root") == kRbacRoleInvalid)
        Panic("rbac", "self-test: root role missing");
    if (RbacFindRole("sandbox") == kRbacRoleInvalid)
        Panic("rbac", "self-test: sandbox role missing");

    // admin → root means admin can elevate to kCapFsWrite.
    RoleId resolved = kRbacRoleInvalid;
    u32 grace = 0;
    if (!RbacResolveElevation("admin", duetos::core::kCapFsWrite, &resolved, &grace))
        Panic("rbac", "self-test: admin/root cannot elevate to kCapFsWrite");
    if (resolved != RbacFindRole("root"))
        Panic("rbac", "self-test: admin elevation didn't pick the root role");
    if (grace != kRbacDefaultGraceSeconds)
        Panic("rbac", "self-test: root default grace mismatch");

    // root's no_cache override on kCapNetAdmin.
    if (!RbacResolveElevation("admin", duetos::core::kCapNetAdmin, &resolved, &grace))
        Panic("rbac", "self-test: admin/root cannot elevate to kCapNetAdmin");
    if (grace != kRbacNoGrace)
        Panic("rbac", "self-test: root kCapNetAdmin override should be no_cache");

    // guest → sandbox means guest cannot elevate to anything.
    if (RbacResolveElevation("guest", duetos::core::kCapFsWrite, nullptr, nullptr))
        Panic("rbac", "self-test: sandbox role granted FsWrite");

    // Unknown user has no role mask.
    if (RbacAccountRoleMask("nobody") != 0)
        Panic("rbac", "self-test: unknown user reported non-zero role mask");

    arch::SerialWrite("[rbac] self-test: PASS\n");
}

// ---------------------------------------------------------------------
// Persistence bridge — see rbac.h header comments and
// wiki/security/Persistence.md.
//
// Layout (encoded as one record inside the persistence envelope so
// the cipher-text length carries the whole role + membership table
// atomically):
//
//   struct RbacSnapshotPayload {
//     u8  magic[4];                 // 'D','R','B','C'
//     u32 format_version;           // = 1
//     u32 role_count;
//     u32 role_record_size;         // = kRoleRecordBytes (56)
//     u32 membership_count;
//     u32 membership_record_size;   // = kMembershipRecordBytes (40)
//     u32 reserved[2];              // zero
//
//     RoleRecord roles[role_count];
//     MembershipRecord memberships[membership_count];
//   }
//
//   struct RoleRecord {            // 56 bytes
//     u8  name[kRbacRoleNameMax];  // 24
//     u64 cap_mask;                //  8
//     u16 grace_seconds[kCapCount];// kCapCount*2
//     u8  in_use;                  //  1
//     u8  pad[...];                // to 56
//   };
//
//   struct MembershipRecord {      // 40 bytes
//     u8  username[kAuthNameMax];  // 32
//     u32 role_mask;               //  4
//     u8  in_use;                  //  1
//     u8  pad[3];                  //  3
//   };
// ---------------------------------------------------------------------

namespace
{

constexpr u8 kRbacMagic[4] = {'D', 'R', 'B', 'C'};
constexpr u32 kRbacSnapshotFormatVersion = 1;
constexpr u32 kRoleRecordBytes = 56;
constexpr u32 kMembershipRecordBytes = 40;
constexpr u32 kSubHeaderBytes = 32; // magic(4)+ver(4)+rc(4)+rs(4)+mc(4)+ms(4)+resv(8)
static_assert(24 + 8 + duetos::core::kCapCount * 2 + 1 <= kRoleRecordBytes,
              "kRoleRecordBytes too small for current Role layout");
static_assert(32 + 4 + 1 <= kMembershipRecordBytes, "kMembershipRecordBytes too small for current Membership layout");
static_assert(duetos::core::kAuthNameMax == 32, "RBAC snapshot assumes account name=32");

void StoreU16LE(u8* p, u16 v)
{
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
}

void StoreU32LE(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

void StoreU64LE(u8* p, u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        p[i] = static_cast<u8>(v >> (8u * i));
}

u16 LoadU16LE(const u8* p)
{
    return static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8);
}

u32 LoadU32LE(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

u64 LoadU64LE(const u8* p)
{
    u64 v = 0;
    for (u32 i = 0; i < 8; ++i)
        v |= static_cast<u64>(p[i]) << (8u * i);
    return v;
}

u32 ActiveRoleCount()
{
    u32 n = 0;
    for (u32 i = 0; i < kRbacMaxRoles; ++i)
        if (g_roles[i].in_use)
            ++n;
    return n;
}

u32 ActiveMembershipCount()
{
    u32 n = 0;
    for (u32 i = 0; i < kRbacMaxMemberships; ++i)
        if (g_memberships[i].in_use)
            ++n;
    return n;
}

void EncodeRole(const Role& r, u8 out[kRoleRecordBytes])
{
    for (u32 i = 0; i < kRoleRecordBytes; ++i)
        out[i] = 0;
    for (u32 i = 0; i < kRbacRoleNameMax; ++i)
        out[i] = static_cast<u8>(r.name[i]);
    StoreU64LE(out + kRbacRoleNameMax, r.policy.cap_mask);
    for (u32 c = 0; c < duetos::core::kCapCount; ++c)
        StoreU16LE(out + kRbacRoleNameMax + 8 + c * 2, r.policy.grace_seconds[c]);
    out[kRbacRoleNameMax + 8 + duetos::core::kCapCount * 2] = r.in_use ? 1u : 0u;
}

void DecodeRole(const u8 in[kRoleRecordBytes], Role& r)
{
    r = Role{};
    for (u32 i = 0; i < kRbacRoleNameMax; ++i)
        r.name[i] = static_cast<char>(in[i]);
    r.policy.cap_mask = LoadU64LE(in + kRbacRoleNameMax);
    for (u32 c = 0; c < duetos::core::kCapCount; ++c)
        r.policy.grace_seconds[c] = LoadU16LE(in + kRbacRoleNameMax + 8 + c * 2);
    r.in_use = in[kRbacRoleNameMax + 8 + duetos::core::kCapCount * 2] != 0;
}

void EncodeMembership(const AccountMembership& m, u8 out[kMembershipRecordBytes])
{
    for (u32 i = 0; i < kMembershipRecordBytes; ++i)
        out[i] = 0;
    for (u32 i = 0; i < duetos::core::kAuthNameMax; ++i)
        out[i] = static_cast<u8>(m.username[i]);
    StoreU32LE(out + duetos::core::kAuthNameMax, m.role_mask);
    out[duetos::core::kAuthNameMax + 4] = m.in_use ? 1u : 0u;
}

void DecodeMembership(const u8 in[kMembershipRecordBytes], AccountMembership& m)
{
    m = AccountMembership{};
    for (u32 i = 0; i < duetos::core::kAuthNameMax; ++i)
        m.username[i] = static_cast<char>(in[i]);
    m.role_mask = LoadU32LE(in + duetos::core::kAuthNameMax);
    m.in_use = in[duetos::core::kAuthNameMax + 4] != 0;
}

u32 ComputePayloadBytes(u32 role_count, u32 membership_count)
{
    return kSubHeaderBytes + role_count * kRoleRecordBytes + membership_count * kMembershipRecordBytes;
}

} // namespace

u32 RbacSnapshotEncodedSize()
{
    const u32 rc = ActiveRoleCount();
    const u32 mc = ActiveMembershipCount();
    if (rc == 0 && mc == 0)
        return 0;
    const u32 payload = ComputePayloadBytes(rc, mc);
    return PersistenceEncodedSize(1, payload);
}

bool RbacExportSnapshot(const char* password, const RbacSnapshotParams& params, u8* out, u32 out_capacity, u32* out_len)
{
    if (password == nullptr || out == nullptr)
        return false;
    const u32 rc = ActiveRoleCount();
    const u32 mc = ActiveMembershipCount();
    if (rc == 0 && mc == 0)
        return false;

    const u32 payload_bytes = ComputePayloadBytes(rc, mc);
    if (payload_bytes > 0xFFFFu)
        return false; // persistence envelope record_size cap

    // Build the payload buffer.
    u8 payload[kSubHeaderBytes + kRbacMaxRoles * kRoleRecordBytes + kRbacMaxMemberships * kMembershipRecordBytes];
    u32 off = 0;
    for (u32 i = 0; i < 4; ++i)
        payload[off++] = kRbacMagic[i];
    StoreU32LE(payload + off, kRbacSnapshotFormatVersion);
    off += 4;
    StoreU32LE(payload + off, rc);
    off += 4;
    StoreU32LE(payload + off, kRoleRecordBytes);
    off += 4;
    StoreU32LE(payload + off, mc);
    off += 4;
    StoreU32LE(payload + off, kMembershipRecordBytes);
    off += 4;
    StoreU32LE(payload + off, 0); // reserved
    off += 4;
    StoreU32LE(payload + off, 0);
    off += 4;
    KASSERT(off == kSubHeaderBytes, "rbac/persist", "sub-header size drift");

    for (u32 i = 0; i < kRbacMaxRoles; ++i)
    {
        if (!g_roles[i].in_use)
            continue;
        EncodeRole(g_roles[i], payload + off);
        off += kRoleRecordBytes;
    }
    for (u32 i = 0; i < kRbacMaxMemberships; ++i)
    {
        if (!g_memberships[i].in_use)
            continue;
        EncodeMembership(g_memberships[i], payload + off);
        off += kMembershipRecordBytes;
    }
    KASSERT(off == payload_bytes, "rbac/persist", "payload size drift");

    PersistenceParams pp{};
    pp.memory_kib = params.memory_kib;
    pp.time_cost = params.time_cost;
    pp.parallelism = params.parallelism;
    u32 pw_len = 0;
    while (password[pw_len] != '\0')
        ++pw_len;
    return PersistenceEncode(payload, 1, payload_bytes, password, pw_len, pp, out, out_capacity, out_len);
}

bool RbacImportSnapshot(const char* password, const u8* in, u32 in_len)
{
    if (password == nullptr || in == nullptr)
        return false;
    u32 pw_len = 0;
    while (password[pw_len] != '\0')
        ++pw_len;
    if (pw_len == 0)
        return false;

    u8 payload[kSubHeaderBytes + kRbacMaxRoles * kRoleRecordBytes + kRbacMaxMemberships * kMembershipRecordBytes];
    u32 record_count = 0;
    u32 record_size = 0;
    if (!PersistenceDecode(in, in_len, password, pw_len, payload, sizeof(payload), &record_count, &record_size))
        return false;
    if (record_count != 1)
        return false;
    if (record_size < kSubHeaderBytes || record_size > sizeof(payload))
        return false;

    // Parse sub-header.
    for (u32 i = 0; i < 4; ++i)
        if (payload[i] != kRbacMagic[i])
            return false;
    const u32 ver = LoadU32LE(payload + 4);
    if (ver != kRbacSnapshotFormatVersion)
        return false;
    const u32 rc = LoadU32LE(payload + 8);
    const u32 rs = LoadU32LE(payload + 12);
    const u32 mc = LoadU32LE(payload + 16);
    const u32 ms = LoadU32LE(payload + 20);

    if (rc > kRbacMaxRoles || mc > kRbacMaxMemberships)
        return false;
    if (rs != kRoleRecordBytes || ms != kMembershipRecordBytes)
        return false;
    if (ComputePayloadBytes(rc, mc) != record_size)
        return false;

    // Decode into scratch tables; commit only after the entire
    // payload parses cleanly.
    Role scratch_roles[kRbacMaxRoles] = {};
    AccountMembership scratch_memberships[kRbacMaxMemberships] = {};
    u32 off = kSubHeaderBytes;
    for (u32 i = 0; i < rc; ++i)
    {
        DecodeRole(payload + off, scratch_roles[i]);
        off += kRoleRecordBytes;
    }
    for (u32 i = 0; i < mc; ++i)
    {
        DecodeMembership(payload + off, scratch_memberships[i]);
        off += kMembershipRecordBytes;
    }
    // Commit.
    for (u32 i = 0; i < kRbacMaxRoles; ++i)
        g_roles[i] = scratch_roles[i];
    for (u32 i = 0; i < kRbacMaxMemberships; ++i)
        g_memberships[i] = scratch_memberships[i];
    return true;
}

void RbacSnapshotSelfTest()
{
    arch::SerialWrite("[rbac-snapshot] self-test: role + membership round-trip\n");

    // Add a probe membership we can revert later. Pick a known
    // account ("guest") and the developer role (already seeded).
    const RoleId dev = RbacFindRole("developer");
    KASSERT(dev != kRbacRoleInvalid, "rbac/snapshot", "self-test: developer role missing pre-export");
    const bool was_member = RbacIsMember("guest", dev);
    if (!was_member)
        KASSERT(RbacAddMembership("guest", dev), "rbac/snapshot", "self-test: add probe membership failed");

    RbacSnapshotParams params{};
    params.memory_kib = 32;
    params.time_cost = 2;
    params.parallelism = 1;
    u8 envelope[4096];
    u32 written = 0;
    KASSERT(RbacExportSnapshot("rbac-snap-pw", params, envelope, sizeof(envelope), &written), "rbac/snapshot",
            "self-test: export failed");
    KASSERT(written > 0 && written <= sizeof(envelope), "rbac/snapshot", "self-test: export wrote bogus length");

    // Mutate live tables: remove the probe membership.
    KASSERT(RbacRemoveMembership("guest", dev), "rbac/snapshot", "self-test: remove probe membership failed");
    KASSERT(!RbacIsMember("guest", dev), "rbac/snapshot", "self-test: probe membership should be gone pre-import");

    // Import — restores the pre-mutation state.
    KASSERT(RbacImportSnapshot("rbac-snap-pw", envelope, written), "rbac/snapshot",
            "self-test: import rejected its own envelope");
    KASSERT(RbacIsMember("guest", dev), "rbac/snapshot", "self-test: probe membership missing post-import");

    // Roles round-trip too: the developer role's cap_mask is
    // preserved.
    Role got{};
    KASSERT(RbacGetRole(dev, &got), "rbac/snapshot", "self-test: developer role disappeared");
    KASSERT(got.policy.cap_mask != 0, "rbac/snapshot", "self-test: developer cap_mask zeroed post-import");

    // Wrong password rejects.
    KASSERT(!RbacImportSnapshot("wrong-password", envelope, written), "rbac/snapshot",
            "self-test: wrong password accepted on import");
    // Tampered envelope rejects.
    {
        u8 bad[sizeof(envelope)];
        for (u32 i = 0; i < written; ++i)
            bad[i] = envelope[i];
        bad[written - 1] ^= 0x01;
        KASSERT(!RbacImportSnapshot("rbac-snap-pw", bad, written), "rbac/snapshot",
                "self-test: tampered envelope accepted on import");
    }

    // Cleanup: if the probe membership wasn't there pre-export,
    // tear it down post-test so the canonical seeded state is
    // unchanged after the self-test runs.
    if (!was_member)
        KASSERT(RbacRemoveMembership("guest", dev), "rbac/snapshot", "self-test: cleanup remove failed");

    arch::SerialWrite("[rbac-snapshot] self-test: PASS\n");
}

} // namespace duetos::security
