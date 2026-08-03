#pragma once

/*
 * Generation-safe DuetOS authorization and enforcement context.
 *
 * AuthorizationContext is kernel policy, not ABI identity.  It owns durable
 * DuetOS capability authority, its monotonic ceiling, short-lived broker
 * leases, and the enforcement counters currently embedded in Process.  A
 * Process will eventually own one exact AuthorizationContextKey; this first
 * slice deliberately has no Process, scheduler, clock, filesystem, or logging
 * dependency.
 *
 * Ownership and threading:
 *   - Sixty-four fixed rows; no allocation and no raw row pointers escape.
 *   - One IRQ-safe spinlock protects row identity, references, and contents.
 *   - No allocation, logging, clock read, scheduler operation, grace lookup,
 *     callback, or other external operation occurs while that lock is held.
 *   - Every public operation is [any thread, IRQ-safe, thread-safe].
 *   - Time-bearing APIs accept a caller-sampled monotonic value.  A zero or
 *     regressing lease clock clears leased authority fail-closed.
 *   - Keys and lease generations are nonzero and non-wrapping.  Rows released
 *     at the terminal generation are permanently retired.
 */

#include "util/types.h"

namespace duetos::core
{

// Opaque declarations keep this service header usable by process.h without a
// circular include.  Callers that construct CapSet values or name Cap members
// also include proc/process.h.
enum Cap : u32;
struct CapSet;

constexpr u32 kAuthorizationContextCapacity = 64;
constexpr u32 kAuthorizationCapabilityStorageCount = 64;
constexpr u64 kAuthorizationGenerationMaximum = (1ULL << 51) - 1;
constexpr u64 kAuthorizationLeaseGenerationMaximum = (1ULL << 51) - 1;
constexpr u64 kAuthorizationDenialThreshold = 100;
constexpr u32 kAuthorizationFsWriteWindowCount = 3;
constexpr u32 kAuthorizationNoFsWriteWindow = static_cast<u32>(~0U);

inline constexpr u64 kAuthorizationFsWriteWindowTicks[kAuthorizationFsWriteWindowCount] = {
    100ULL,
    100ULL * 60 * 5,
    100ULL * 60 * 60,
};

inline constexpr u64 kAuthorizationFsWriteWindowByteCaps[kAuthorizationFsWriteWindowCount] = {
    16ULL * 1024 * 1024,
    256ULL * 1024 * 1024,
    2ULL * 1024 * 1024 * 1024,
};

struct AuthorizationContextKey
{
    u32 slot;
    u64 generation;
};

constexpr AuthorizationContextKey kInvalidAuthorizationContextKey{kAuthorizationContextCapacity, 0};

constexpr bool AuthorizationContextKeyIsValid(AuthorizationContextKey key)
{
    return key.slot < kAuthorizationContextCapacity && key.generation != 0 &&
           key.generation <= kAuthorizationGenerationMaximum;
}

constexpr bool operator==(AuthorizationContextKey lhs, AuthorizationContextKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation;
}

enum class AuthorizationContextState : u8
{
    Retired = 0,
    Live,
};

// Provenance is monotonic across spawn: a sandbox context cannot derive a
// trusted child.  A trusted parent may deliberately derive a sandbox child.
enum class AuthorizationLaunchProfile : u8
{
    Invalid = 0,
    Trusted,
    Sandbox,
};

enum class AuthorizationAction : u8
{
    None = 0,
    TickBudgetExceeded,
    DenialThresholdExceeded,
    FsWriteRateExceeded,
};

struct AuthorizationActionResult
{
    // false means the exact key was malformed, stale, or no longer live.
    bool resolved;
    // These flags explain a fail-closed FsWriteRateExceeded action.
    bool arithmetic_overflow;
    bool time_regression;
    AuthorizationAction action;
    // Valid only for a normal FsWriteRateExceeded cap crossing.
    u32 fs_write_window;
    // Post-operation tick, denial, or lifetime-write count.
    u64 value;
};

struct AuthorizationContextSnapshot
{
    AuthorizationContextState state;
    AuthorizationLaunchProfile provenance;
    u32 owner_references;

    u64 durable_bits;
    u64 ceiling_bits;
    u64 lease_bits;
    u64 effective_bits;
    u64 lease_deadline_ns[kAuthorizationCapabilityStorageCount];
    u64 lease_generation[kAuthorizationCapabilityStorageCount];
    u64 last_lease_time_ns;
    bool lease_time_regressed;

    u64 tick_budget;
    u64 ticks_used;
    bool tick_threshold_latched;

    u64 denial_count;
    bool denial_threshold_latched;

    u64 fs_write_bytes_total;
    u64 fs_write_window_bytes[kAuthorizationFsWriteWindowCount];
    u64 fs_write_window_start_tick[kAuthorizationFsWriteWindowCount];
    bool fs_write_window_initialized[kAuthorizationFsWriteWindowCount];
    u64 last_fs_write_tick;
    bool fs_write_clock_initialized;
    bool fs_write_time_regressed;
    bool fs_write_threshold_latched;
};

/// Authority-bearing trusted constructor.  durable must be a subset of the
/// monotonic ceiling, both masks must contain only defined DuetOS caps, and
/// tick_budget must be nonzero.  Failure leaves out_key invalid.
bool AuthorizationCreateTrusted(CapSet durable, CapSet ceiling, u64 tick_budget, AuthorizationContextKey* out_key);

/// Authority-bearing sandbox constructor.  The supplied caps are still
/// authenticated kernel policy; launch provenance is recorded separately so
/// a sandbox context can never derive a trusted child.
bool AuthorizationCreateSandbox(CapSet durable, CapSet ceiling, u64 tick_budget, AuthorizationContextKey* out_key);

/// Derive an independent child row.  requested durable authority must come
/// only from the parent's durable set, never from a lease.  The requested
/// ceiling must be a subset of the parent's current ceiling.  required_mask
/// may be authorized by the parent's current effective set, so a broker lease
/// can permit spawning without becoming durable child authority.  now_ns must
/// be sampled before entry.
bool AuthorizationDeriveForSpawn(AuthorizationContextKey parent, u64 now_ns, u64 required_mask, CapSet child_durable,
                                 CapSet child_ceiling, u64 child_tick_budget, AuthorizationLaunchProfile child_profile,
                                 AuthorizationContextKey* out_child);

/// Add one owner reference to an exact live generation.  Saturation and stale
/// keys fail without mutation.
bool AuthorizationRetain(AuthorizationContextKey key);

/// Consume one owner reference.  Success invalidates the caller's local key;
/// the last release retires the row and clears active leases.
bool AuthorizationRelease(AuthorizationContextKey* key);

/// Exact value snapshot.  For a live row, now_ns expires leases before the
/// copy.  A zero or regressing time clears all active leases fail-closed.
/// Retired exact generations remain inspectable until their slot is reused.
bool AuthorizationSnapshot(AuthorizationContextKey key, u64 now_ns, AuthorizationContextSnapshot* out_snapshot);

/// Non-blocking, side-effect-free diagnostic snapshot.  This does not sample
/// time or expire leases and therefore must never authorize an operation.
/// It exists for stop-the-world diagnostics where another stopped CPU may own
/// the registry lock.  Failure clears out_snapshot.
bool AuthorizationTrySnapshotNoExpire(AuthorizationContextKey key, AuthorizationContextSnapshot* out_snapshot);

/// Test one capability against effective authority after fail-closed lease
/// expiry using caller-sampled now_ns.
bool AuthorizationHas(AuthorizationContextKey key, Cap cap, u64 now_ns);

/// Grant durable authority only while the monotonic ceiling permits it.
bool AuthorizationGrantDurable(AuthorizationContextKey key, Cap cap);

/// Reversibly clear durable and active leased bits without lowering the grant
/// ceiling or resetting lease replay watermarks.  now_ns is sampled before
/// entry; previous_effective_out receives the exact effective mask that
/// linearized before the clear.  A null output is allowed.
bool AuthorizationDisableMask(AuthorizationContextKey key, u64 now_ns, u64 disable_mask,
                              u64* previous_effective_out = nullptr);

/// Permanently lower the ceiling and clear matching durable and leased bits.
/// Lease generation watermarks remain so a revoked grant cannot be replayed.
bool AuthorizationDropIrreversibly(AuthorizationContextKey key, u64 drop_mask);

/// Same irreversible drop, while atomically returning the effective authority
/// that linearized before it.  This is the Process compatibility adapter's
/// value-returning form; there is no snapshot/drop split-brain window.
bool AuthorizationDropIrreversiblyWithPrevious(AuthorizationContextKey key, u64 now_ns, u64 drop_mask,
                                               u64* previous_effective_out);

/// Publish or replace a per-cap broker lease.  generation must be strictly
/// newer than every generation previously accepted for that cap in this
/// context, deadline_ns must be after caller-sampled now_ns, and both must be
/// nonzero and within their defined domains.
bool AuthorizationGrantLease(AuthorizationContextKey key, Cap cap, u64 now_ns, u64 deadline_ns, u64 generation);

/// Revoke only the active lease with this exact generation.  Durable authority
/// and the replay-rejection generation watermark are untouched.
bool AuthorizationRevokeLease(AuthorizationContextKey key, Cap cap, u64 expected_generation);

/// Charge one or more execution ticks with saturating, fail-closed arithmetic.
/// The threshold action is returned exactly once per context lifetime.
AuthorizationActionResult AuthorizationChargeTick(AuthorizationContextKey key, u64 ticks);

/// Record one sandbox denial.  The threshold action is returned exactly once;
/// subsequent calls continue saturating the diagnostic count.
AuthorizationActionResult AuthorizationRecordDenial(AuthorizationContextKey key);

/// Record a completed filesystem write.  now_tick must be sampled before
/// entry.  Counter overflow and time regression both trigger one fail-closed
/// FsWriteRateExceeded action; normal windows trip strictly above their cap.
AuthorizationActionResult AuthorizationRecordFsWrite(AuthorizationContextKey key, u64 now_tick, u64 bytes);

/// Allocation-free boot regression covering construction, spawn derivation,
/// lease replay rejection, irreversible drop, thresholds, and exact release.
bool AuthorizationSelfTest();

} // namespace duetos::core
