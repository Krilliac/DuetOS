/*
 * Fixed-pool ThreadGroup metadata service.
 *
 * State machine under g_thread_group_lock:
 *
 *     Retired --authority-create--> Open --begin-exit--> Exiting
 *         ^                                             |
 *         +-------- final-owner release when empty -----+
 *
 * A row at kThreadGroupGenerationMaximum may complete its final lifetime,
 * but allocation permanently skips it afterward. Member values are copied
 * opaque identities, never Task pointers or borrowed scheduler storage.
 */

#include "proc/thread_group.h"

#include "sync/spinlock.h"

namespace duetos::core
{

namespace
{

struct ThreadGroupRow
{
    ThreadGroupState state;
    u8 _pad0[3];
    u64 generation;
    u32 owner_references;
    ThreadGroupMemberIdentity leader;
    u32 member_count;
    ThreadGroupMemberIdentity members[kThreadGroupMemberCapacity];
};

constinit ThreadGroupRow g_thread_groups[kThreadGroupCapacity]{};
constinit sync::SpinLock g_thread_group_lock{};

ThreadGroupRow* ResolveExactLocked(ThreadGroupKey key)
{
    if (!ThreadGroupKeyIsValid(key))
    {
        return nullptr;
    }
    ThreadGroupRow& row = g_thread_groups[key.slot];
    return row.generation == key.generation ? &row : nullptr;
}

ThreadGroupKey AllocateLocked(ThreadGroupMemberIdentity leader)
{
    for (u32 slot = 0; slot < kThreadGroupCapacity; ++slot)
    {
        ThreadGroupRow& row = g_thread_groups[slot];
        if (row.state != ThreadGroupState::Retired || row.generation >= kThreadGroupGenerationMaximum)
        {
            continue;
        }

        ++row.generation;
        row.owner_references = 1;
        row.leader = leader;
        row.member_count = 1;
        row.members[0] = leader;
        for (u32 index = 1; index < kThreadGroupMemberCapacity; ++index)
        {
            row.members[index] = kInvalidThreadGroupMemberIdentity;
        }
        row.state = ThreadGroupState::Open;
        return ThreadGroupKey{slot, row.generation};
    }
    return kInvalidThreadGroupKey;
}

u32 MemberLowerBound(const ThreadGroupRow& row, ThreadGroupMemberIdentity member)
{
    u32 first = 0;
    u32 count = row.member_count;
    while (count != 0)
    {
        const u32 step = count / 2;
        const u32 probe = first + step;
        if (row.members[probe].opaque < member.opaque)
        {
            first = probe + 1;
            count -= step + 1;
        }
        else
        {
            count = step;
        }
    }
    return first;
}

bool IsActive(const ThreadGroupRow& row)
{
    return (row.state == ThreadGroupState::Open || row.state == ThreadGroupState::Exiting) && row.owner_references != 0;
}

} // namespace

bool ThreadGroupAuthorityCreate(ThreadGroupMemberIdentity leader, ThreadGroupKey* out_key)
{
    if (out_key == nullptr)
    {
        return false;
    }
    *out_key = kInvalidThreadGroupKey;
    if (!ThreadGroupMemberIdentityIsValid(leader))
    {
        return false;
    }

    ThreadGroupKey created = kInvalidThreadGroupKey;
    {
        sync::SpinLockGuard guard(g_thread_group_lock);
        created = AllocateLocked(leader);
    }
    *out_key = created;
    return ThreadGroupKeyIsValid(created);
}

bool ThreadGroupRetain(ThreadGroupKey key)
{
    sync::SpinLockGuard guard(g_thread_group_lock);
    ThreadGroupRow* row = ResolveExactLocked(key);
    if (row == nullptr || !IsActive(*row) || row->owner_references == static_cast<u32>(~0U))
    {
        return false;
    }
    ++row->owner_references;
    return true;
}

bool ThreadGroupRelease(ThreadGroupKey* key)
{
    if (key == nullptr || !ThreadGroupKeyIsValid(*key))
    {
        return false;
    }

    {
        sync::SpinLockGuard guard(g_thread_group_lock);
        ThreadGroupRow* row = ResolveExactLocked(*key);
        if (row == nullptr || !IsActive(*row))
        {
            return false;
        }
        if (row->owner_references == 1 && (row->state != ThreadGroupState::Exiting || row->member_count != 0))
        {
            return false;
        }

        --row->owner_references;
        if (row->owner_references == 0)
        {
            row->state = ThreadGroupState::Retired;
        }
    }
    *key = kInvalidThreadGroupKey;
    return true;
}

bool ThreadGroupAuthorityAttachMember(ThreadGroupKey key, ThreadGroupMemberIdentity member)
{
    if (!ThreadGroupMemberIdentityIsValid(member))
    {
        return false;
    }

    sync::SpinLockGuard guard(g_thread_group_lock);
    ThreadGroupRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != ThreadGroupState::Open || row->owner_references == 0 ||
        row->member_count >= kThreadGroupMemberCapacity)
    {
        return false;
    }

    const u32 insert_at = MemberLowerBound(*row, member);
    if (insert_at < row->member_count && row->members[insert_at] == member)
    {
        return false;
    }
    for (u32 index = row->member_count; index > insert_at; --index)
    {
        row->members[index] = row->members[index - 1];
    }
    row->members[insert_at] = member;
    ++row->member_count;
    return true;
}

ThreadGroupMutationResult ThreadGroupAuthorityDetachMember(ThreadGroupKey key, ThreadGroupMemberIdentity member)
{
    if (!ThreadGroupMemberIdentityIsValid(member))
    {
        return ThreadGroupMutationResult::Rejected;
    }

    sync::SpinLockGuard guard(g_thread_group_lock);
    ThreadGroupRow* row = ResolveExactLocked(key);
    if (row == nullptr || !IsActive(*row))
    {
        return ThreadGroupMutationResult::Rejected;
    }

    const u32 remove_at = MemberLowerBound(*row, member);
    if (remove_at == row->member_count || !(row->members[remove_at] == member))
    {
        return ThreadGroupMutationResult::AlreadySatisfied;
    }
    for (u32 index = remove_at + 1; index < row->member_count; ++index)
    {
        row->members[index - 1] = row->members[index];
    }
    --row->member_count;
    row->members[row->member_count] = kInvalidThreadGroupMemberIdentity;
    return ThreadGroupMutationResult::Applied;
}

ThreadGroupMutationResult ThreadGroupBeginExit(ThreadGroupKey key)
{
    sync::SpinLockGuard guard(g_thread_group_lock);
    ThreadGroupRow* row = ResolveExactLocked(key);
    if (row == nullptr || !IsActive(*row))
    {
        return ThreadGroupMutationResult::Rejected;
    }
    if (row->state == ThreadGroupState::Exiting)
    {
        return ThreadGroupMutationResult::AlreadySatisfied;
    }
    row->state = ThreadGroupState::Exiting;
    return ThreadGroupMutationResult::Applied;
}

bool ThreadGroupInspectExact(ThreadGroupKey key, ThreadGroupSnapshot* out_snapshot)
{
    if (out_snapshot == nullptr)
    {
        return false;
    }
    *out_snapshot = {};

    ThreadGroupSnapshot snapshot{};
    {
        sync::SpinLockGuard guard(g_thread_group_lock);
        const ThreadGroupRow* row = ResolveExactLocked(key);
        if (row == nullptr)
        {
            return false;
        }
        snapshot.state = row->state;
        snapshot.owner_references = row->owner_references;
        snapshot.leader = row->leader;
        snapshot.member_count = row->member_count;
        for (u32 index = 0; index < kThreadGroupMemberCapacity; ++index)
        {
            snapshot.members[index] = row->members[index];
        }
    }
    *out_snapshot = snapshot;
    return true;
}

} // namespace duetos::core
