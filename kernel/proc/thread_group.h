#pragma once

/*
 * Allocation-free process thread-group metadata.
 *
 * This service owns only immutable group identity, lifecycle, exact member
 * identities, and owner-reference accounting. It deliberately has no
 * Process, Task, scheduler, Job, PID, or TID dependency. A later scheduler
 * adapter must mint generation-safe ThreadGroupMemberIdentity values from
 * live Tasks and call the authority-named membership entry points. PID/TID
 * bytes, user input, pointers, and borrowed scheduler-slot addresses are
 * never authority to construct a member identity.
 *
 * Locking and ownership:
 *   - Sixty-four fixed rows, each with at most sixty-four exact members.
 *   - One IRQ-safe metadata spinlock protects generations, lifecycle,
 *     references, and membership.
 *   - No allocation, logging, scheduler operation, callback, or external
 *     subsystem call occurs while the lock is held.
 *   - Keys use nonzero, non-wrapping generations. A row released at the
 *     terminal generation is permanently retired instead of risking ABA.
 *   - The final owner can release only after BeginExit and after every member
 *     has detached. This prevents an unreachable Open or populated group.
 */

#include "util/types.h"

namespace duetos::core
{

constexpr u32 kThreadGroupCapacity = 64;
constexpr u32 kThreadGroupMemberCapacity = 64;
constexpr u64 kThreadGroupGenerationMaximum = (1ULL << 51) - 1;

struct ThreadGroupKey
{
    u32 slot;
    u64 generation;
};

constexpr ThreadGroupKey kInvalidThreadGroupKey{kThreadGroupCapacity, 0};

constexpr bool ThreadGroupKeyIsValid(ThreadGroupKey key)
{
    return key.slot < kThreadGroupCapacity && key.generation != 0 && key.generation <= kThreadGroupGenerationMaximum;
}

constexpr bool operator==(ThreadGroupKey lhs, ThreadGroupKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation;
}

// Opaque exact Task incarnation minted only by a trusted scheduler adapter.
// The service validates only the reserved zero value and exact equality; it
// cannot and must not infer liveness from a PID/TID-shaped number.
struct ThreadGroupMemberIdentity
{
    u64 opaque;
};

constexpr ThreadGroupMemberIdentity kInvalidThreadGroupMemberIdentity{0};

constexpr bool ThreadGroupMemberIdentityIsValid(ThreadGroupMemberIdentity identity)
{
    return identity.opaque != 0;
}

constexpr bool operator==(ThreadGroupMemberIdentity lhs, ThreadGroupMemberIdentity rhs)
{
    return lhs.opaque == rhs.opaque;
}

enum class ThreadGroupState : u8
{
    Retired = 0,
    Open,
    Exiting,
};

// Detach and BeginExit are deliberately idempotent while an exact group is
// live. Rejected means malformed/stale authority or an invalid transition;
// AlreadySatisfied means no state changed and is still a successful replay.
enum class ThreadGroupMutationResult : u8
{
    Rejected = 0,
    Applied,
    AlreadySatisfied,
};

struct ThreadGroupSnapshot
{
    ThreadGroupState state;
    u32 owner_references;
    ThreadGroupMemberIdentity leader;
    u32 member_count;
    ThreadGroupMemberIdentity members[kThreadGroupMemberCapacity];
};

/// Authority-bearing creation for a scheduler-minted, live leader identity.
/// The leader is inserted as the first exact member. Failure invalidates
/// out_key and consumes no row.
bool ThreadGroupAuthorityCreate(ThreadGroupMemberIdentity leader, ThreadGroupKey* out_key);

/// Retain one owner of an exact Open or Exiting group. Saturation, stale keys,
/// retired rows, and malformed keys fail without mutation.
bool ThreadGroupRetain(ThreadGroupKey key);

/// Release one owner and invalidate the caller's local key on success. The
/// final owner is accepted only for an empty Exiting group, which atomically
/// retires the row. Failure leaves the key unchanged.
bool ThreadGroupRelease(ThreadGroupKey* key);

/// Authority-bearing attach of one scheduler-minted Task incarnation. Attach
/// is accepted only while Open; malformed identities, exact duplicates,
/// stale keys, and a full member set are rejected without mutation.
bool ThreadGroupAuthorityAttachMember(ThreadGroupKey key, ThreadGroupMemberIdentity member);

/// Authority-bearing detach. An exact member is removed once; replay for an
/// already-absent valid identity returns AlreadySatisfied while the group is
/// Open or Exiting. Stale/malformed authority is Rejected.
ThreadGroupMutationResult ThreadGroupAuthorityDetachMember(ThreadGroupKey key, ThreadGroupMemberIdentity member);

/// Transition Open -> Exiting. Replays while Exiting return AlreadySatisfied.
/// Retired or stale keys are rejected. Exiting permanently closes attachment.
ThreadGroupMutationResult ThreadGroupBeginExit(ThreadGroupKey key);

/// Copy one exact generation into caller storage. A just-retired generation
/// remains inspectable until slot reuse; stale keys never resolve to a newer
/// generation. Failure clears out_snapshot. No internal pointer is exposed.
bool ThreadGroupInspectExact(ThreadGroupKey key, ThreadGroupSnapshot* out_snapshot);

} // namespace duetos::core
