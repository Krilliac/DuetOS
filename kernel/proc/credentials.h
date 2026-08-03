#pragma once

/*
 * Immutable process credentials and security context.
 *
 * This service is the lifetime seam for the Unix identity, POSIX ABI
 * capability metadata, and Win32 integrity state that will later move out of
 * Process.  These POSIX masks are deliberately separate from DuetOS kernel
 * authorization (Process::CapSet); no implicit mapping exists.  A Process
 * owns one exact CredentialKey; fork/spawn retain that key, while a successful
 * credential change derives a new immutable row and atomically swaps the
 * Process owner in a later adapter.
 *
 * Ownership and threading:
 *   - Sixty-four fixed rows; no allocation and no Process/PID dependency.
 *   - One IRQ-safe metadata spinlock protects row identity and owner counts.
 *   - No allocation, logging, scheduler operation, user copy, or external
 *     callback occurs while that lock is held.
 *   - Keys use nonzero, non-wrapping generations.  A row released at the
 *     terminal generation is permanently retired rather than risking ABA.
 *   - Security contexts are immutable after publication.  DeriveRestricted
 *     creates an independent child row and never mutates or pins its parent.
 */

#include "util/types.h"

namespace duetos::core
{

constexpr u32 kCredentialCapacity = 64;
constexpr u32 kCredentialSupplementalGroupCapacity = 16;
constexpr u64 kCredentialGenerationMaximum = (1ULL << 51) - 1;

// Stored identities never use Linux's `(uid_t)-1` / `(gid_t)-1` syscall
// sentinel.  65534 is the conventional sandbox "nobody" identity.
constexpr u32 kCredentialInvalidId = static_cast<u32>(~0U);
constexpr u32 kCredentialNobodyId = 65534;

// POSIX/Linux ABI capabilities 0..40 (through CAP_CHECKPOINT_RESTORE).
// These are identity metadata, not DuetOS kernel authorization bits and not
// Process::CapSet. Undefined high bits are rejected so one logical capability
// set has one canonical spelling.
constexpr u64 kCredentialCapabilityKnownMask = (1ULL << 41) - 1;

struct CredentialKey
{
    u32 slot;
    u64 generation;
};

constexpr CredentialKey kInvalidCredentialKey{kCredentialCapacity, 0};

constexpr bool CredentialKeyIsValid(CredentialKey key)
{
    return key.slot < kCredentialCapacity && key.generation != 0 && key.generation <= kCredentialGenerationMaximum;
}

constexpr bool operator==(CredentialKey lhs, CredentialKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation;
}

enum class CredentialState : u8
{
    Retired = 0,
    Live,
};

// Numeric order is an authority order: a restricted derivation may preserve
// or lower this value, never raise it.
enum class Win32IntegrityLevel : u8
{
    Invalid = 0,
    Untrusted,
    Low,
    Medium,
    High,
    System,
};

struct CredentialSecurityContext
{
    u32 real_uid;
    u32 effective_uid;
    u32 saved_uid;
    u32 fs_uid;

    u32 real_gid;
    u32 effective_gid;
    u32 saved_gid;
    u32 fs_gid;

    u32 supplemental_group_count;
    u32 supplemental_groups[kCredentialSupplementalGroupCapacity];

    u64 capability_effective;
    u64 capability_permitted;
    u64 capability_inheritable;
    u64 capability_bounding;

    Win32IntegrityLevel win32_integrity;
};

// Sandbox construction accepts identity only.  It always forces empty
// capability masks and Low integrity.  IDs and groups must be non-root,
// non-sentinel values, and the group array must be canonical.
struct CredentialSandboxIdentity
{
    u32 uid;
    u32 gid;
    u32 supplemental_group_count;
    u32 supplemental_groups[kCredentialSupplementalGroupCapacity];
};

struct CredentialSnapshot
{
    CredentialState state;
    u32 owner_references;
    CredentialSecurityContext security;
};

/// Pure canonicality check.  Supplemental groups are strictly increasing,
/// unused group slots are zero, IDs are not sentinel values, capability bits
/// are known, effective is a subset of permitted, permitted is a subset of
/// bounding, inheritable is a subset of bounding, and integrity is valid.
bool CredentialSecurityContextIsCanonical(const CredentialSecurityContext& context);

/// Authority-bearing constructor for authenticated kernel/service bootstrap.
/// The supplied value must already be a canonical kernel-resident context.
/// Never call this with identity, groups, masks, or integrity taken directly
/// from user bytes, a path/name, PID, manifest claim, or IPC payload.
bool CredentialAuthorityCreateTrusted(CredentialSecurityContext initial, CredentialKey* out_key);

/// Narrow kernel-policy constructor for the canonical trusted root identity.
/// No caller-provided identity or capability data participates in this mint.
bool CredentialAuthorityCreateTrustedRoot(CredentialKey* out_key);

/// Authority-bearing sandbox constructor.  The caller authenticates the
/// identity assignment; this function additionally rejects root/sentinel IDs
/// and groups and forces an empty capability set plus Low integrity.
bool CredentialAuthorityCreateSandbox(CredentialSandboxIdentity identity, CredentialKey* out_key);

/// Narrow kernel-policy constructor for the canonical unprivileged sandbox
/// identity (uid/gid 65534, no groups, no POSIX capabilities, Low integrity).
/// This is the only credential mint used by ordinary sandbox Process roots.
bool CredentialAuthorityCreateNobodySandbox(CredentialKey* out_key);

/// Add one owner reference to an exact live generation.  Saturation, stale
/// keys, retired rows, and malformed keys are rejected without mutation.
bool CredentialRetain(CredentialKey key);

/// Consume one owner reference.  Success invalidates the caller's local key;
/// the last release retires the row.  Failure leaves the key unchanged.
bool CredentialRelease(CredentialKey* key);

/// Create one independent immutable child context.  Every identity must come
/// from the parent's corresponding UID/GID authority set; reducing the number
/// of distinct held identities is a drop, while assigning a new identity must
/// go through an authority-bearing constructor. Groups and each POSIX ABI
/// capability mask are field-wise subsets, and integrity may only be lowered.
/// Failure leaves out_child invalid and the parent bit-for-bit and
/// reference-count unchanged.
bool CredentialDeriveRestricted(CredentialKey parent, CredentialSecurityContext restricted, CredentialKey* out_child);

/// Exact diagnostic snapshot.  A just-retired generation remains inspectable
/// until the slot is reused; stale keys never resolve to a newer generation.
/// Failure clears out_snapshot.
bool CredentialInspectExact(CredentialKey key, CredentialSnapshot* out_snapshot);

/// Allocation-free boot regression for authority construction, monotonic
/// derivation, exact ownership, stale replay rejection, and parent immutability.
bool CredentialSelfTest();

} // namespace duetos::core
