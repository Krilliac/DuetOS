/*
 * Fixed-pool AuthorizationContext service.
 *
 * State machine under g_authorization_lock:
 *
 *     Retired --create/derive--> Live --last-release--> Retired
 *
 * Exact owner references protect each live generation.  A row whose terminal
 * generation completes is never allocated again.  Lease generations are
 * independent per capability and retained as replay-rejection watermarks even
 * after revoke, expiry, irreversible drop, or final release.
 */

#include "proc/authorization_context.h"

#include "proc/process.h"
#include "sync/spinlock.h"

namespace duetos::core
{

static_assert(static_cast<u32>(kCapCount) <= kAuthorizationCapabilityStorageCount);

namespace
{

struct AuthorizationRow
{
    AuthorizationContextState state;
    AuthorizationLaunchProfile provenance;
    u64 generation;
    u32 owner_references;

    u64 durable_bits;
    u64 ceiling_bits;
    u64 lease_bits;
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

constinit AuthorizationRow g_authorizations[kAuthorizationContextCapacity]{};
constinit sync::SpinLock g_authorization_lock{};

constexpr u64 KnownCapabilityMask()
{
    return CapSetTrusted().bits;
}

bool CapabilityMaskIsCanonical(u64 bits)
{
    return (bits & ~KnownCapabilityMask()) == 0;
}

bool CapabilityIsDefined(Cap cap)
{
    return cap != kCapNone && cap < kCapCount;
}

u64 CapabilityBit(Cap cap)
{
    return 1ULL << static_cast<u32>(cap);
}

bool ProfileIsValid(AuthorizationLaunchProfile profile)
{
    return profile == AuthorizationLaunchProfile::Trusted || profile == AuthorizationLaunchProfile::Sandbox;
}

AuthorizationRow* ResolveExactLocked(AuthorizationContextKey key)
{
    if (!AuthorizationContextKeyIsValid(key))
    {
        return nullptr;
    }
    AuthorizationRow& row = g_authorizations[key.slot];
    return row.generation == key.generation ? &row : nullptr;
}

void ClearActiveLeasesLocked(AuthorizationRow& row)
{
    row.lease_bits = 0;
    for (u32 index = 0; index < kAuthorizationCapabilityStorageCount; ++index)
    {
        row.lease_deadline_ns[index] = 0;
    }
}

// now_ns is a value sampled before the caller acquired this service lock.
// Returning false means leased authority was cleared fail-closed.  Durable
// authority remains valid and may still authorize the operation.
bool ObserveLeaseTimeLocked(AuthorizationRow& row, u64 now_ns)
{
    if (now_ns == 0 || (row.last_lease_time_ns != 0 && now_ns < row.last_lease_time_ns))
    {
        ClearActiveLeasesLocked(row);
        row.lease_time_regressed = true;
        return false;
    }

    if (now_ns > row.last_lease_time_ns)
    {
        row.last_lease_time_ns = now_ns;
    }

    u64 active = row.lease_bits;
    for (u32 index = 1; index < static_cast<u32>(kCapCount); ++index)
    {
        const u64 bit = 1ULL << index;
        if ((active & bit) == 0)
        {
            continue;
        }
        const u64 deadline = row.lease_deadline_ns[index];
        if (deadline == 0 || now_ns >= deadline)
        {
            row.lease_bits &= ~bit;
            row.lease_deadline_ns[index] = 0;
            active &= ~bit;
        }
    }
    return true;
}

u64 EffectiveBitsLocked(const AuthorizationRow& row)
{
    return (row.durable_bits | row.lease_bits) & row.ceiling_bits;
}

AuthorizationContextKey AllocateLocked(AuthorizationLaunchProfile provenance, u64 durable_bits, u64 ceiling_bits,
                                       u64 tick_budget, u64 initial_lease_time_ns)
{
    for (u32 slot = 0; slot < kAuthorizationContextCapacity; ++slot)
    {
        AuthorizationRow& row = g_authorizations[slot];
        if (row.state != AuthorizationContextState::Retired || row.generation >= kAuthorizationGenerationMaximum)
        {
            continue;
        }

        const u64 next_generation = row.generation + 1;
        // Reset explicitly instead of assigning a zero aggregate.  Apart from
        // making the identity transition reviewable field by field, this
        // prevents a debug compiler from lowering the reset to an out-of-line
        // memset/memcpy call while the registry spinlock is held.
        row.state = AuthorizationContextState::Live;
        row.provenance = provenance;
        row.generation = next_generation;
        row.owner_references = 1;
        row.durable_bits = durable_bits;
        row.ceiling_bits = ceiling_bits;
        row.lease_bits = 0;
        for (u32 index = 0; index < kAuthorizationCapabilityStorageCount; ++index)
        {
            row.lease_deadline_ns[index] = 0;
            row.lease_generation[index] = 0;
        }
        row.lease_time_regressed = false;
        row.tick_budget = tick_budget;
        row.ticks_used = 0;
        row.tick_threshold_latched = false;
        row.denial_count = 0;
        row.denial_threshold_latched = false;
        row.fs_write_bytes_total = 0;
        for (u32 index = 0; index < kAuthorizationFsWriteWindowCount; ++index)
        {
            row.fs_write_window_bytes[index] = 0;
            row.fs_write_window_start_tick[index] = 0;
            row.fs_write_window_initialized[index] = false;
        }
        row.last_fs_write_tick = 0;
        row.fs_write_clock_initialized = false;
        row.fs_write_time_regressed = false;
        row.fs_write_threshold_latched = false;
        row.last_lease_time_ns = initial_lease_time_ns;
        return AuthorizationContextKey{slot, next_generation};
    }
    return kInvalidAuthorizationContextKey;
}

bool CreateContext(AuthorizationLaunchProfile provenance, CapSet durable, CapSet ceiling, u64 tick_budget,
                   AuthorizationContextKey* out_key)
{
    if (out_key == nullptr)
    {
        return false;
    }
    *out_key = kInvalidAuthorizationContextKey;
    if (!ProfileIsValid(provenance) || tick_budget == 0 || !CapabilityMaskIsCanonical(durable.bits) ||
        !CapabilityMaskIsCanonical(ceiling.bits) || (durable.bits & ~ceiling.bits) != 0)
    {
        return false;
    }

    AuthorizationContextKey created = kInvalidAuthorizationContextKey;
    {
        sync::SpinLockGuard guard(g_authorization_lock);
        created = AllocateLocked(provenance, durable.bits, ceiling.bits, tick_budget, 0);
    }
    *out_key = created;
    return AuthorizationContextKeyIsValid(created);
}

bool AddSaturating(u64 current, u64 increment, u64* out_value)
{
    const u64 maximum = static_cast<u64>(~0ULL);
    if (increment > maximum - current)
    {
        *out_value = maximum;
        return false;
    }
    *out_value = current + increment;
    return true;
}

AuthorizationActionResult UnresolvedActionResult()
{
    return AuthorizationActionResult{false, false, false, AuthorizationAction::None, kAuthorizationNoFsWriteWindow, 0};
}

AuthorizationActionResult ResolvedActionResult(u64 value)
{
    return AuthorizationActionResult{true, false, false, AuthorizationAction::None, kAuthorizationNoFsWriteWindow,
                                     value};
}

void CopySnapshotLocked(const AuthorizationRow& row, AuthorizationContextSnapshot& snapshot)
{
    snapshot.state = row.state;
    snapshot.provenance = row.provenance;
    snapshot.owner_references = row.owner_references;
    snapshot.durable_bits = row.durable_bits;
    snapshot.ceiling_bits = row.ceiling_bits;
    snapshot.lease_bits = row.lease_bits;
    snapshot.effective_bits = EffectiveBitsLocked(row);
    for (u32 index = 0; index < kAuthorizationCapabilityStorageCount; ++index)
    {
        snapshot.lease_deadline_ns[index] = row.lease_deadline_ns[index];
        snapshot.lease_generation[index] = row.lease_generation[index];
    }
    snapshot.last_lease_time_ns = row.last_lease_time_ns;
    snapshot.lease_time_regressed = row.lease_time_regressed;
    snapshot.tick_budget = row.tick_budget;
    snapshot.ticks_used = row.ticks_used;
    snapshot.tick_threshold_latched = row.tick_threshold_latched;
    snapshot.denial_count = row.denial_count;
    snapshot.denial_threshold_latched = row.denial_threshold_latched;
    snapshot.fs_write_bytes_total = row.fs_write_bytes_total;
    for (u32 index = 0; index < kAuthorizationFsWriteWindowCount; ++index)
    {
        snapshot.fs_write_window_bytes[index] = row.fs_write_window_bytes[index];
        snapshot.fs_write_window_start_tick[index] = row.fs_write_window_start_tick[index];
        snapshot.fs_write_window_initialized[index] = row.fs_write_window_initialized[index];
    }
    snapshot.last_fs_write_tick = row.last_fs_write_tick;
    snapshot.fs_write_clock_initialized = row.fs_write_clock_initialized;
    snapshot.fs_write_time_regressed = row.fs_write_time_regressed;
    snapshot.fs_write_threshold_latched = row.fs_write_threshold_latched;
}

} // namespace

bool AuthorizationCreateTrusted(CapSet durable, CapSet ceiling, u64 tick_budget, AuthorizationContextKey* out_key)
{
    return CreateContext(AuthorizationLaunchProfile::Trusted, durable, ceiling, tick_budget, out_key);
}

bool AuthorizationCreateSandbox(CapSet durable, CapSet ceiling, u64 tick_budget, AuthorizationContextKey* out_key)
{
    return CreateContext(AuthorizationLaunchProfile::Sandbox, durable, ceiling, tick_budget, out_key);
}

bool AuthorizationDeriveForSpawn(AuthorizationContextKey parent, u64 now_ns, u64 required_mask, CapSet child_durable,
                                 CapSet child_ceiling, u64 child_tick_budget, AuthorizationLaunchProfile child_profile,
                                 AuthorizationContextKey* out_child)
{
    if (out_child == nullptr)
    {
        return false;
    }
    *out_child = kInvalidAuthorizationContextKey;
    if (!ProfileIsValid(child_profile) || child_tick_budget == 0 || !CapabilityMaskIsCanonical(required_mask) ||
        !CapabilityMaskIsCanonical(child_durable.bits) || !CapabilityMaskIsCanonical(child_ceiling.bits) ||
        (child_durable.bits & ~child_ceiling.bits) != 0)
    {
        return false;
    }

    AuthorizationContextKey created = kInvalidAuthorizationContextKey;
    {
        sync::SpinLockGuard guard(g_authorization_lock);
        AuthorizationRow* parent_row = ResolveExactLocked(parent);
        if (parent_row == nullptr || parent_row->state != AuthorizationContextState::Live ||
            parent_row->owner_references == 0)
        {
            return false;
        }

        const bool lease_time_valid = ObserveLeaseTimeLocked(*parent_row, now_ns);
        const u64 effective = EffectiveBitsLocked(*parent_row);
        if ((required_mask & ~effective) != 0 || (child_durable.bits & ~parent_row->durable_bits) != 0 ||
            (child_ceiling.bits & ~parent_row->ceiling_bits) != 0 ||
            (parent_row->provenance == AuthorizationLaunchProfile::Sandbox &&
             child_profile != AuthorizationLaunchProfile::Sandbox))
        {
            return false;
        }

        created = AllocateLocked(child_profile, child_durable.bits, child_ceiling.bits, child_tick_budget,
                                 lease_time_valid ? now_ns : 0);
    }
    *out_child = created;
    return AuthorizationContextKeyIsValid(created);
}

bool AuthorizationRetain(AuthorizationContextKey key)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0 ||
        row->owner_references == static_cast<u32>(~0U))
    {
        return false;
    }
    ++row->owner_references;
    return true;
}

bool AuthorizationRelease(AuthorizationContextKey* key)
{
    if (key == nullptr || !AuthorizationContextKeyIsValid(*key))
    {
        return false;
    }

    {
        sync::SpinLockGuard guard(g_authorization_lock);
        AuthorizationRow* row = ResolveExactLocked(*key);
        if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
        {
            return false;
        }
        --row->owner_references;
        if (row->owner_references == 0)
        {
            ClearActiveLeasesLocked(*row);
            row->state = AuthorizationContextState::Retired;
        }
    }
    *key = kInvalidAuthorizationContextKey;
    return true;
}

bool AuthorizationSnapshot(AuthorizationContextKey key, u64 now_ns, AuthorizationContextSnapshot* out_snapshot)
{
    if (out_snapshot == nullptr)
    {
        return false;
    }
    *out_snapshot = {};

    AuthorizationContextSnapshot snapshot{};
    {
        sync::SpinLockGuard guard(g_authorization_lock);
        AuthorizationRow* row = ResolveExactLocked(key);
        if (row == nullptr)
        {
            return false;
        }
        if (row->state == AuthorizationContextState::Live)
        {
            (void)ObserveLeaseTimeLocked(*row, now_ns);
        }
        CopySnapshotLocked(*row, snapshot);
    }
    *out_snapshot = snapshot;
    return true;
}

bool AuthorizationTrySnapshotNoExpire(AuthorizationContextKey key, AuthorizationContextSnapshot* out_snapshot)
{
    if (out_snapshot == nullptr)
    {
        return false;
    }
    *out_snapshot = {};

    sync::SpinLockTryGuard guard(g_authorization_lock);
    if (!guard)
    {
        return false;
    }
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return false;
    }
    CopySnapshotLocked(*row, *out_snapshot);
    return true;
}

bool AuthorizationHas(AuthorizationContextKey key, Cap cap, u64 now_ns)
{
    if (!CapabilityIsDefined(cap))
    {
        return false;
    }
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return false;
    }
    (void)ObserveLeaseTimeLocked(*row, now_ns);
    return (EffectiveBitsLocked(*row) & CapabilityBit(cap)) != 0;
}

bool AuthorizationGrantDurable(AuthorizationContextKey key, Cap cap)
{
    if (!CapabilityIsDefined(cap))
    {
        return false;
    }
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    const u64 bit = CapabilityBit(cap);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0 ||
        (row->ceiling_bits & bit) == 0)
    {
        return false;
    }
    row->durable_bits |= bit;
    return true;
}

bool AuthorizationDisableMask(AuthorizationContextKey key, u64 now_ns, u64 disable_mask, u64* previous_effective_out)
{
    if (previous_effective_out != nullptr)
    {
        *previous_effective_out = 0;
    }
    if (!CapabilityMaskIsCanonical(disable_mask))
    {
        return false;
    }

    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return false;
    }
    (void)ObserveLeaseTimeLocked(*row, now_ns);
    if (previous_effective_out != nullptr)
    {
        *previous_effective_out = EffectiveBitsLocked(*row);
    }
    row->durable_bits &= ~disable_mask;
    row->lease_bits &= ~disable_mask;
    for (u32 index = 1; index < static_cast<u32>(kCapCount); ++index)
    {
        if ((disable_mask & (1ULL << index)) != 0)
        {
            row->lease_deadline_ns[index] = 0;
        }
    }
    return true;
}

bool AuthorizationDropIrreversibly(AuthorizationContextKey key, u64 drop_mask)
{
    if (!CapabilityMaskIsCanonical(drop_mask))
    {
        return false;
    }
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return false;
    }
    row->ceiling_bits &= ~drop_mask;
    row->durable_bits &= ~drop_mask;
    row->lease_bits &= ~drop_mask;
    for (u32 index = 1; index < static_cast<u32>(kCapCount); ++index)
    {
        if ((drop_mask & (1ULL << index)) != 0)
        {
            row->lease_deadline_ns[index] = 0;
        }
    }
    return true;
}

bool AuthorizationDropIrreversiblyWithPrevious(AuthorizationContextKey key, u64 now_ns, u64 drop_mask,
                                               u64* previous_effective_out)
{
    if (previous_effective_out == nullptr)
    {
        return false;
    }
    *previous_effective_out = 0;
    if (!CapabilityMaskIsCanonical(drop_mask))
    {
        return false;
    }

    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return false;
    }
    (void)ObserveLeaseTimeLocked(*row, now_ns);
    *previous_effective_out = EffectiveBitsLocked(*row);
    row->ceiling_bits &= ~drop_mask;
    row->durable_bits &= ~drop_mask;
    row->lease_bits &= ~drop_mask;
    for (u32 index = 1; index < static_cast<u32>(kCapCount); ++index)
    {
        if ((drop_mask & (1ULL << index)) != 0)
        {
            row->lease_deadline_ns[index] = 0;
        }
    }
    return true;
}

bool AuthorizationGrantLease(AuthorizationContextKey key, Cap cap, u64 now_ns, u64 deadline_ns, u64 generation)
{
    if (!CapabilityIsDefined(cap) || deadline_ns == 0 || generation == 0 ||
        generation > kAuthorizationLeaseGenerationMaximum)
    {
        return false;
    }

    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return false;
    }
    if (!ObserveLeaseTimeLocked(*row, now_ns) || deadline_ns <= now_ns)
    {
        return false;
    }

    const u32 index = static_cast<u32>(cap);
    const u64 bit = CapabilityBit(cap);
    if ((row->ceiling_bits & bit) == 0 || generation <= row->lease_generation[index])
    {
        return false;
    }
    row->lease_generation[index] = generation;
    row->lease_deadline_ns[index] = deadline_ns;
    row->lease_bits |= bit;
    return true;
}

bool AuthorizationRevokeLease(AuthorizationContextKey key, Cap cap, u64 expected_generation)
{
    if (!CapabilityIsDefined(cap) || expected_generation == 0 ||
        expected_generation > kAuthorizationLeaseGenerationMaximum)
    {
        return false;
    }

    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return false;
    }
    const u32 index = static_cast<u32>(cap);
    const u64 bit = CapabilityBit(cap);
    if ((row->lease_bits & bit) == 0 || row->lease_generation[index] != expected_generation)
    {
        return false;
    }
    row->lease_bits &= ~bit;
    row->lease_deadline_ns[index] = 0;
    return true;
}

AuthorizationActionResult AuthorizationChargeTick(AuthorizationContextKey key, u64 ticks)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return UnresolvedActionResult();
    }

    AuthorizationActionResult result = ResolvedActionResult(row->ticks_used);
    if (ticks == 0)
    {
        return result;
    }

    u64 charged = 0;
    result.arithmetic_overflow = !AddSaturating(row->ticks_used, ticks, &charged);
    row->ticks_used = charged;
    result.value = charged;
    if (!row->tick_threshold_latched && (result.arithmetic_overflow || charged >= row->tick_budget))
    {
        row->tick_threshold_latched = true;
        result.action = AuthorizationAction::TickBudgetExceeded;
    }
    return result;
}

AuthorizationActionResult AuthorizationRecordDenial(AuthorizationContextKey key)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return UnresolvedActionResult();
    }

    AuthorizationActionResult result = ResolvedActionResult(row->denial_count);
    u64 count = 0;
    result.arithmetic_overflow = !AddSaturating(row->denial_count, 1, &count);
    row->denial_count = count;
    result.value = count;
    if (!row->denial_threshold_latched && (result.arithmetic_overflow || count >= kAuthorizationDenialThreshold))
    {
        row->denial_threshold_latched = true;
        result.action = AuthorizationAction::DenialThresholdExceeded;
    }
    return result;
}

AuthorizationActionResult AuthorizationRecordFsWrite(AuthorizationContextKey key, u64 now_tick, u64 bytes)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || row->owner_references == 0)
    {
        return UnresolvedActionResult();
    }

    AuthorizationActionResult result = ResolvedActionResult(row->fs_write_bytes_total);
    if (bytes == 0)
    {
        return result;
    }

    u64 lifetime = 0;
    result.arithmetic_overflow = !AddSaturating(row->fs_write_bytes_total, bytes, &lifetime);
    row->fs_write_bytes_total = lifetime;
    result.value = lifetime;

    if (row->fs_write_clock_initialized && now_tick < row->last_fs_write_tick)
    {
        row->fs_write_time_regressed = true;
        result.time_regression = true;
    }
    else
    {
        row->last_fs_write_tick = now_tick;
        row->fs_write_clock_initialized = true;
        for (u32 level = 0; level < kAuthorizationFsWriteWindowCount; ++level)
        {
            u64 window_bytes = bytes;
            if (!row->fs_write_window_initialized[level] ||
                now_tick - row->fs_write_window_start_tick[level] >= kAuthorizationFsWriteWindowTicks[level])
            {
                row->fs_write_window_initialized[level] = true;
                row->fs_write_window_start_tick[level] = now_tick;
            }
            else
            {
                const bool added = AddSaturating(row->fs_write_window_bytes[level], bytes, &window_bytes);
                result.arithmetic_overflow = !added || result.arithmetic_overflow;
            }
            row->fs_write_window_bytes[level] = window_bytes;
            if (result.fs_write_window == kAuthorizationNoFsWriteWindow &&
                window_bytes > kAuthorizationFsWriteWindowByteCaps[level])
            {
                result.fs_write_window = level;
            }
        }
    }

    if (!row->fs_write_threshold_latched && (result.arithmetic_overflow || result.time_regression ||
                                             result.fs_write_window != kAuthorizationNoFsWriteWindow))
    {
        row->fs_write_threshold_latched = true;
        result.action = AuthorizationAction::FsWriteRateExceeded;
    }
    return result;
}

bool AuthorizationSelfTest()
{
    bool ok = true;
    AuthorizationContextKey parent = kInvalidAuthorizationContextKey;
    AuthorizationContextKey child = kInvalidAuthorizationContextKey;
    const CapSet durable{1ULL << static_cast<u32>(kCapFsRead)};
    const CapSet ceiling{durable.bits | (1ULL << static_cast<u32>(kCapNet))};

    ok = AuthorizationCreateTrusted(durable, ceiling, 2, &parent) && ok;
    if (AuthorizationContextKeyIsValid(parent))
    {
        ok = AuthorizationGrantLease(parent, kCapNet, 10, 20, 1) && ok;
        ok = AuthorizationHas(parent, kCapNet, 11) && ok;
        ok = AuthorizationDeriveForSpawn(parent, 12, 1ULL << static_cast<u32>(kCapNet), durable, ceiling, 8,
                                         AuthorizationLaunchProfile::Sandbox, &child) &&
             ok;
        if (AuthorizationContextKeyIsValid(child))
        {
            ok = AuthorizationHas(child, kCapFsRead, 12) && !AuthorizationHas(child, kCapNet, 12) && ok;
            ok = AuthorizationRelease(&child) && ok;
        }
        ok = AuthorizationRevokeLease(parent, kCapNet, 1) && !AuthorizationGrantLease(parent, kCapNet, 13, 30, 1) && ok;
        ok = AuthorizationDropIrreversibly(parent, 1ULL << static_cast<u32>(kCapNet)) &&
             !AuthorizationGrantDurable(parent, kCapNet) && ok;

        const AuthorizationActionResult tick = AuthorizationChargeTick(parent, 2);
        ok = tick.resolved && tick.action == AuthorizationAction::TickBudgetExceeded && ok;
        u32 denial_actions = 0;
        for (u64 denial = 0; denial < kAuthorizationDenialThreshold; ++denial)
        {
            if (AuthorizationRecordDenial(parent).action == AuthorizationAction::DenialThresholdExceeded)
            {
                ++denial_actions;
            }
        }
        ok = denial_actions == 1 && ok;
        const AuthorizationActionResult write =
            AuthorizationRecordFsWrite(parent, 1, kAuthorizationFsWriteWindowByteCaps[0] + 1);
        ok = write.resolved && write.action == AuthorizationAction::FsWriteRateExceeded && write.fs_write_window == 0 &&
             ok;
        ok = AuthorizationRelease(&parent) && ok;
    }
    return ok;
}

} // namespace duetos::core
