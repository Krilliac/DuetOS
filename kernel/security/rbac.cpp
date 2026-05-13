/*
 * DuetOS — Role-Based Access Control, v0.
 *
 * See rbac.h for the public contract and the design rationale.
 */

#include "security/rbac.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "util/types.h"

namespace duetos::security
{

using duetos::core::Cap;
using duetos::core::kCapCount;
using duetos::core::kCapNone;
using duetos::core::Panic;

namespace
{

constexpr u32 kRbacMaxMemberships = duetos::core::kAuthMaxAccounts;

// Two simple in-memory tables. The role table is small enough that
// every lookup is a linear scan; same for memberships. v0 is fixed
// size, never grows past these bounds.
Role g_roles[kRbacMaxRoles];
AccountMembership g_memberships[kRbacMaxMemberships];
bool g_initialized = false;

bool StrEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != '\0' && *b != '\0')
    {
        if (*a != *b)
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s != nullptr && s[n] != '\0')
        ++n;
    return n;
}

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

} // namespace duetos::security
