/*
 * Fixed-pool immutable credential service.
 *
 * State machine under g_credential_lock:
 *
 *     Retired --authority-create/derive--> Live --last-release--> Retired
 *
 * A row at kCredentialGenerationMaximum may complete its final Live lifetime,
 * but allocation permanently skips it afterward.  No operation retains a
 * parent from a derived row, so credential ownership cannot form a cycle.
 */

#include "proc/credentials.h"

#include "sync/spinlock.h"

namespace duetos::core
{

namespace
{

struct CredentialRow
{
    CredentialState state;
    u8 _pad0[3];
    u64 generation;
    u32 owner_references;
    CredentialSecurityContext security;
};

constinit CredentialRow g_credentials[kCredentialCapacity]{};
constinit sync::SpinLock g_credential_lock{};

bool IdIsStored(u32 id)
{
    return id != kCredentialInvalidId;
}

bool IntegrityIsValid(Win32IntegrityLevel integrity)
{
    return integrity >= Win32IntegrityLevel::Untrusted && integrity <= Win32IntegrityLevel::System;
}

bool GroupsAreCanonical(u32 count, const u32* groups, bool reject_root)
{
    if (count > kCredentialSupplementalGroupCapacity)
    {
        return false;
    }
    for (u32 index = 0; index < count; ++index)
    {
        const u32 group = groups[index];
        if (!IdIsStored(group) || (reject_root && group == 0) || (index != 0 && groups[index - 1] >= group))
        {
            return false;
        }
    }
    for (u32 index = count; index < kCredentialSupplementalGroupCapacity; ++index)
    {
        if (groups[index] != 0)
        {
            return false;
        }
    }
    return true;
}

bool CapabilityMaskIsCanonical(u64 mask)
{
    return (mask & ~kCredentialCapabilityKnownMask) == 0;
}

CredentialRow* ResolveExactLocked(CredentialKey key)
{
    if (!CredentialKeyIsValid(key))
    {
        return nullptr;
    }
    CredentialRow& row = g_credentials[key.slot];
    return row.generation == key.generation ? &row : nullptr;
}

CredentialKey AllocateLocked(const CredentialSecurityContext& security)
{
    for (u32 slot = 0; slot < kCredentialCapacity; ++slot)
    {
        CredentialRow& row = g_credentials[slot];
        if (row.state != CredentialState::Retired || row.generation >= kCredentialGenerationMaximum)
        {
            continue;
        }

        ++row.generation;
        row.owner_references = 1;
        row.security = security;
        row.state = CredentialState::Live;
        return CredentialKey{slot, row.generation};
    }
    return kInvalidCredentialKey;
}

bool IdComesFromParent(u32 id, u32 first, u32 second, u32 third, u32 fourth)
{
    return id == first || id == second || id == third || id == fourth;
}

bool UidsAreRestricted(const CredentialSecurityContext& parent, const CredentialSecurityContext& child)
{
    return IdComesFromParent(child.real_uid, parent.real_uid, parent.effective_uid, parent.saved_uid, parent.fs_uid) &&
           IdComesFromParent(child.effective_uid, parent.real_uid, parent.effective_uid, parent.saved_uid,
                             parent.fs_uid) &&
           IdComesFromParent(child.saved_uid, parent.real_uid, parent.effective_uid, parent.saved_uid, parent.fs_uid) &&
           IdComesFromParent(child.fs_uid, parent.real_uid, parent.effective_uid, parent.saved_uid, parent.fs_uid);
}

bool GidsAreRestricted(const CredentialSecurityContext& parent, const CredentialSecurityContext& child)
{
    return IdComesFromParent(child.real_gid, parent.real_gid, parent.effective_gid, parent.saved_gid, parent.fs_gid) &&
           IdComesFromParent(child.effective_gid, parent.real_gid, parent.effective_gid, parent.saved_gid,
                             parent.fs_gid) &&
           IdComesFromParent(child.saved_gid, parent.real_gid, parent.effective_gid, parent.saved_gid, parent.fs_gid) &&
           IdComesFromParent(child.fs_gid, parent.real_gid, parent.effective_gid, parent.saved_gid, parent.fs_gid);
}

bool GroupsAreSubset(const CredentialSecurityContext& parent, const CredentialSecurityContext& child)
{
    u32 parent_index = 0;
    for (u32 child_index = 0; child_index < child.supplemental_group_count; ++child_index)
    {
        const u32 wanted = child.supplemental_groups[child_index];
        while (parent_index < parent.supplemental_group_count && parent.supplemental_groups[parent_index] < wanted)
        {
            ++parent_index;
        }
        if (parent_index == parent.supplemental_group_count || parent.supplemental_groups[parent_index] != wanted)
        {
            return false;
        }
        ++parent_index;
    }
    return true;
}

bool MaskIsSubset(u64 child, u64 parent)
{
    return (child & ~parent) == 0;
}

bool IsRestrictedFrom(const CredentialSecurityContext& parent, const CredentialSecurityContext& child)
{
    return UidsAreRestricted(parent, child) && GidsAreRestricted(parent, child) && GroupsAreSubset(parent, child) &&
           MaskIsSubset(child.capability_effective, parent.capability_effective) &&
           MaskIsSubset(child.capability_permitted, parent.capability_permitted) &&
           MaskIsSubset(child.capability_inheritable, parent.capability_inheritable) &&
           MaskIsSubset(child.capability_bounding, parent.capability_bounding) &&
           child.win32_integrity <= parent.win32_integrity;
}

CredentialSecurityContext TrustedRootContext()
{
    CredentialSecurityContext context{};
    context.capability_effective = kCredentialCapabilityKnownMask;
    context.capability_permitted = kCredentialCapabilityKnownMask;
    context.capability_inheritable = kCredentialCapabilityKnownMask;
    context.capability_bounding = kCredentialCapabilityKnownMask;
    context.win32_integrity = Win32IntegrityLevel::System;
    return context;
}

CredentialSecurityContext SandboxContext(const CredentialSandboxIdentity& identity)
{
    CredentialSecurityContext context{};
    context.real_uid = identity.uid;
    context.effective_uid = identity.uid;
    context.saved_uid = identity.uid;
    context.fs_uid = identity.uid;
    context.real_gid = identity.gid;
    context.effective_gid = identity.gid;
    context.saved_gid = identity.gid;
    context.fs_gid = identity.gid;
    context.supplemental_group_count = identity.supplemental_group_count;
    for (u32 index = 0; index < kCredentialSupplementalGroupCapacity; ++index)
    {
        context.supplemental_groups[index] = identity.supplemental_groups[index];
    }
    context.win32_integrity = Win32IntegrityLevel::Low;
    return context;
}

bool ContextsEqual(const CredentialSecurityContext& lhs, const CredentialSecurityContext& rhs)
{
    if (lhs.real_uid != rhs.real_uid || lhs.effective_uid != rhs.effective_uid || lhs.saved_uid != rhs.saved_uid ||
        lhs.fs_uid != rhs.fs_uid || lhs.real_gid != rhs.real_gid || lhs.effective_gid != rhs.effective_gid ||
        lhs.saved_gid != rhs.saved_gid || lhs.fs_gid != rhs.fs_gid ||
        lhs.supplemental_group_count != rhs.supplemental_group_count ||
        lhs.capability_effective != rhs.capability_effective || lhs.capability_permitted != rhs.capability_permitted ||
        lhs.capability_inheritable != rhs.capability_inheritable ||
        lhs.capability_bounding != rhs.capability_bounding || lhs.win32_integrity != rhs.win32_integrity)
    {
        return false;
    }
    for (u32 index = 0; index < kCredentialSupplementalGroupCapacity; ++index)
    {
        if (lhs.supplemental_groups[index] != rhs.supplemental_groups[index])
        {
            return false;
        }
    }
    return true;
}

} // namespace

bool CredentialSecurityContextIsCanonical(const CredentialSecurityContext& context)
{
    if (!IdIsStored(context.real_uid) || !IdIsStored(context.effective_uid) || !IdIsStored(context.saved_uid) ||
        !IdIsStored(context.fs_uid) || !IdIsStored(context.real_gid) || !IdIsStored(context.effective_gid) ||
        !IdIsStored(context.saved_gid) || !IdIsStored(context.fs_gid) ||
        !GroupsAreCanonical(context.supplemental_group_count, context.supplemental_groups, false) ||
        !CapabilityMaskIsCanonical(context.capability_effective) ||
        !CapabilityMaskIsCanonical(context.capability_permitted) ||
        !CapabilityMaskIsCanonical(context.capability_inheritable) ||
        !CapabilityMaskIsCanonical(context.capability_bounding) ||
        !MaskIsSubset(context.capability_effective, context.capability_permitted) ||
        !MaskIsSubset(context.capability_permitted, context.capability_bounding) ||
        !MaskIsSubset(context.capability_inheritable, context.capability_bounding) ||
        !IntegrityIsValid(context.win32_integrity))
    {
        return false;
    }
    return true;
}

bool CredentialAuthorityCreateTrusted(CredentialSecurityContext initial, CredentialKey* out_key)
{
    if (out_key == nullptr)
    {
        return false;
    }
    *out_key = kInvalidCredentialKey;
    if (!CredentialSecurityContextIsCanonical(initial))
    {
        return false;
    }

    CredentialKey created = kInvalidCredentialKey;
    {
        sync::SpinLockGuard guard(g_credential_lock);
        created = AllocateLocked(initial);
    }
    *out_key = created;
    return CredentialKeyIsValid(created);
}

bool CredentialAuthorityCreateTrustedRoot(CredentialKey* out_key)
{
    return CredentialAuthorityCreateTrusted(TrustedRootContext(), out_key);
}

bool CredentialAuthorityCreateSandbox(CredentialSandboxIdentity identity, CredentialKey* out_key)
{
    if (out_key == nullptr)
    {
        return false;
    }
    *out_key = kInvalidCredentialKey;
    if (identity.uid == 0 || identity.gid == 0 || !IdIsStored(identity.uid) || !IdIsStored(identity.gid) ||
        !GroupsAreCanonical(identity.supplemental_group_count, identity.supplemental_groups, true))
    {
        return false;
    }
    return CredentialAuthorityCreateTrusted(SandboxContext(identity), out_key);
}

bool CredentialAuthorityCreateNobodySandbox(CredentialKey* out_key)
{
    CredentialSandboxIdentity nobody{};
    nobody.uid = kCredentialNobodyId;
    nobody.gid = kCredentialNobodyId;
    return CredentialAuthorityCreateSandbox(nobody, out_key);
}

bool CredentialRetain(CredentialKey key)
{
    sync::SpinLockGuard guard(g_credential_lock);
    CredentialRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != CredentialState::Live || row->owner_references == 0 ||
        row->owner_references == static_cast<u32>(~0U))
    {
        return false;
    }
    ++row->owner_references;
    return true;
}

bool CredentialRelease(CredentialKey* key)
{
    if (key == nullptr || !CredentialKeyIsValid(*key))
    {
        return false;
    }

    {
        sync::SpinLockGuard guard(g_credential_lock);
        CredentialRow* row = ResolveExactLocked(*key);
        if (row == nullptr || row->state != CredentialState::Live || row->owner_references == 0)
        {
            return false;
        }
        --row->owner_references;
        if (row->owner_references == 0)
        {
            row->state = CredentialState::Retired;
        }
    }
    *key = kInvalidCredentialKey;
    return true;
}

bool CredentialDeriveRestricted(CredentialKey parent, CredentialSecurityContext restricted, CredentialKey* out_child)
{
    if (out_child == nullptr)
    {
        return false;
    }
    *out_child = kInvalidCredentialKey;
    if (!CredentialSecurityContextIsCanonical(restricted))
    {
        return false;
    }

    CredentialKey created = kInvalidCredentialKey;
    {
        sync::SpinLockGuard guard(g_credential_lock);
        const CredentialRow* parent_row = ResolveExactLocked(parent);
        if (parent_row == nullptr || parent_row->state != CredentialState::Live || parent_row->owner_references == 0 ||
            !IsRestrictedFrom(parent_row->security, restricted))
        {
            return false;
        }
        created = AllocateLocked(restricted);
    }
    *out_child = created;
    return CredentialKeyIsValid(created);
}

bool CredentialInspectExact(CredentialKey key, CredentialSnapshot* out_snapshot)
{
    if (out_snapshot == nullptr)
    {
        return false;
    }
    *out_snapshot = {};

    CredentialSnapshot snapshot{};
    {
        sync::SpinLockGuard guard(g_credential_lock);
        const CredentialRow* row = ResolveExactLocked(key);
        if (row == nullptr)
        {
            return false;
        }
        snapshot.state = row->state;
        snapshot.owner_references = row->owner_references;
        snapshot.security = row->security;
    }
    *out_snapshot = snapshot;
    return true;
}

bool CredentialSelfTest()
{
    bool ok = true;
    CredentialKey trusted = kInvalidCredentialKey;
    CredentialKey child = kInvalidCredentialKey;
    CredentialKey sandbox = kInvalidCredentialKey;

    const CredentialSecurityContext root = TrustedRootContext();
    ok = CredentialAuthorityCreateTrusted(root, &trusted) && ok;

    CredentialSnapshot parent_before{};
    if (CredentialKeyIsValid(trusted))
    {
        ok = CredentialInspectExact(trusted, &parent_before) && parent_before.state == CredentialState::Live &&
             parent_before.owner_references == 1 && ContextsEqual(parent_before.security, root) && ok;

        CredentialSecurityContext restricted{};
        restricted.win32_integrity = Win32IntegrityLevel::Low;
        ok = CredentialDeriveRestricted(trusted, restricted, &child) && ok;

        CredentialSnapshot parent_after{};
        ok = CredentialInspectExact(trusted, &parent_after) && parent_after.state == parent_before.state &&
             parent_after.owner_references == parent_before.owner_references &&
             ContextsEqual(parent_after.security, parent_before.security) && ok;

        if (CredentialKeyIsValid(child))
        {
            CredentialKey refused{0, 1};
            ok = !CredentialDeriveRestricted(child, root, &refused) && refused == kInvalidCredentialKey && ok;

            CredentialKey retained = child;
            const bool retained_ok = CredentialRetain(child);
            ok = retained_ok && ok;
            if (retained_ok)
            {
                ok = CredentialRelease(&retained) && retained == kInvalidCredentialKey && ok;
            }

            CredentialKey replay = child;
            ok = CredentialRelease(&child) && child == kInvalidCredentialKey && ok;
            ok = !CredentialRelease(&replay) && ok;
        }
    }

    CredentialSandboxIdentity sandbox_identity{};
    sandbox_identity.uid = kCredentialNobodyId;
    sandbox_identity.gid = kCredentialNobodyId;
    ok = CredentialAuthorityCreateSandbox(sandbox_identity, &sandbox) && ok;
    if (CredentialKeyIsValid(sandbox))
    {
        CredentialSnapshot snapshot{};
        ok = CredentialInspectExact(sandbox, &snapshot) && snapshot.security.real_uid == kCredentialNobodyId &&
             snapshot.security.capability_bounding == 0 &&
             snapshot.security.win32_integrity == Win32IntegrityLevel::Low && ok;
        ok = CredentialRelease(&sandbox) && ok;
    }

    if (CredentialKeyIsValid(child))
    {
        ok = CredentialRelease(&child) && ok;
    }
    if (CredentialKeyIsValid(trusted))
    {
        ok = CredentialRelease(&trusted) && ok;
    }
    return ok;
}

} // namespace duetos::core
