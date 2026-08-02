// Hosted lifetime, authority, lease, accounting, and concurrency properties
// for proc/authorization_context.
//
// The production TU is included so terminal-generation and arithmetic-edge
// fixtures can be established without adding a production test API.  Public
// operations drive all behavior after each bounded fixture setup.  A host
// mutex supplies the kernel SpinLock symbols so sanitizers exercise the real
// production critical sections.

#include "host_test_helper.h"
#include "proc/authorization_context.h"
#include "proc/process.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <limits>
#include <mutex>
#include <thread>
#include <vector>

#include "proc/authorization_context.cpp"

namespace
{

std::mutex g_host_spinlock;

} // namespace

namespace duetos::sync
{

IrqFlags SpinLockAcquire(SpinLock&)
{
    g_host_spinlock.lock();
    return IrqFlags{0};
}

core::Result<IrqFlags> SpinLockTryAcquire(SpinLock&)
{
    if (!g_host_spinlock.try_lock())
    {
        return core::Err{core::ErrorCode::Busy};
    }
    return IrqFlags{0};
}

void SpinLockRelease(SpinLock&, IrqFlags)
{
    g_host_spinlock.unlock();
}

} // namespace duetos::sync

namespace duetos::core
{

bool HostSetRetiredAuthorizationGeneration(u32 slot, u64 generation)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    if (slot >= kAuthorizationContextCapacity || generation > kAuthorizationGenerationMaximum)
    {
        return false;
    }
    AuthorizationRow& row = g_authorizations[slot];
    if (row.state != AuthorizationContextState::Retired || row.owner_references != 0 || generation < row.generation)
    {
        return false;
    }
    row.generation = generation;
    return true;
}

bool HostSetAuthorizationOwnerReferences(AuthorizationContextKey key, u32 references)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live || references == 0)
    {
        return false;
    }
    row->owner_references = references;
    return true;
}

bool HostSetAuthorizationTickCount(AuthorizationContextKey key, u64 ticks)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live)
    {
        return false;
    }
    row->ticks_used = ticks;
    row->tick_threshold_latched = false;
    return true;
}

bool HostSetAuthorizationDenialCount(AuthorizationContextKey key, u64 denials)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live)
    {
        return false;
    }
    row->denial_count = denials;
    row->denial_threshold_latched = false;
    return true;
}

bool HostSetAuthorizationFsCounters(AuthorizationContextKey key, u64 lifetime, u64 window_bytes)
{
    sync::SpinLockGuard guard(g_authorization_lock);
    AuthorizationRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->state != AuthorizationContextState::Live)
    {
        return false;
    }
    row->fs_write_bytes_total = lifetime;
    row->fs_write_window_bytes[0] = window_bytes;
    row->fs_write_window_start_tick[0] = 100;
    row->fs_write_window_initialized[0] = true;
    row->last_fs_write_tick = 100;
    row->fs_write_clock_initialized = true;
    row->fs_write_threshold_latched = false;
    return true;
}

} // namespace duetos::core

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::core;

constexpr u64 Bit(Cap cap)
{
    return 1ULL << static_cast<u32>(cap);
}

AuthorizationContextSnapshot Inspect(AuthorizationContextKey key, u64 now_ns = 1000)
{
    AuthorizationContextSnapshot snapshot{};
    EXPECT_TRUE(AuthorizationSnapshot(key, now_ns, &snapshot));
    return snapshot;
}

void ReleaseIfValid(AuthorizationContextKey& key)
{
    if (AuthorizationContextKeyIsValid(key))
    {
        EXPECT_TRUE(AuthorizationRelease(&key));
    }
}

bool SnapshotAuthorityIsCanonical(const AuthorizationContextSnapshot& snapshot)
{
    const u64 known = CapSetTrusted().bits;
    return (snapshot.durable_bits & ~snapshot.ceiling_bits) == 0 &&
           (snapshot.lease_bits & ~snapshot.ceiling_bits) == 0 &&
           snapshot.effective_bits == ((snapshot.durable_bits | snapshot.lease_bits) & snapshot.ceiling_bits) &&
           (snapshot.ceiling_bits & ~known) == 0;
}

} // namespace

int main()
{
    EXPECT_TRUE(AuthorizationSelfTest());
    EXPECT_FALSE(AuthorizationContextKeyIsValid(kInvalidAuthorizationContextKey));
    EXPECT_TRUE(AuthorizationContextKeyIsValid(AuthorizationContextKey{0, 1}));
    EXPECT_FALSE(AuthorizationContextKeyIsValid(AuthorizationContextKey{0, 0}));
    EXPECT_FALSE(AuthorizationContextKeyIsValid(AuthorizationContextKey{0, kAuthorizationGenerationMaximum + 1}));

    const CapSet fs_read{Bit(kCapFsRead)};
    const CapSet fs_read_net{fs_read.bits | Bit(kCapNet)};
    const CapSet fs_read_net_thread{fs_read_net.bits | Bit(kCapSpawnThread)};

    // Process compatibility adapters need one linearized reversible-disable
    // value and a stop-loop snapshot that neither waits nor expires leases.
    AuthorizationContextKey disable = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(fs_read, fs_read_net, 100, &disable));
    EXPECT_TRUE(AuthorizationGrantLease(disable, kCapNet, 10, 20, 7));
    AuthorizationContextSnapshot no_expire{};
    EXPECT_TRUE(AuthorizationTrySnapshotNoExpire(disable, &no_expire));
    EXPECT_EQ(no_expire.effective_bits, fs_read_net.bits);
    EXPECT_EQ(no_expire.lease_generation[static_cast<u32>(kCapNet)], 7ULL);
    u64 previous_effective = 0;
    EXPECT_TRUE(AuthorizationDisableMask(disable, 11, fs_read_net.bits, &previous_effective));
    EXPECT_EQ(previous_effective, fs_read_net.bits);
    const auto disabled = Inspect(disable, 11);
    EXPECT_EQ(disabled.durable_bits, 0ULL);
    EXPECT_EQ(disabled.lease_bits, 0ULL);
    EXPECT_EQ(disabled.ceiling_bits, fs_read_net.bits);
    EXPECT_EQ(disabled.lease_generation[static_cast<u32>(kCapNet)], 7ULL);
    EXPECT_FALSE(AuthorizationGrantLease(disable, kCapNet, 11, 30, 7));
    EXPECT_FALSE(AuthorizationDisableMask(disable, 11, 1ULL << 63, &previous_effective));
    EXPECT_TRUE(AuthorizationGrantDurable(disable, kCapFsRead));
    EXPECT_TRUE(AuthorizationDropIrreversiblyWithPrevious(disable, 11, Bit(kCapFsRead), &previous_effective));
    EXPECT_EQ(previous_effective, Bit(kCapFsRead));
    EXPECT_EQ(Inspect(disable, 11).ceiling_bits & Bit(kCapFsRead), 0ULL);
    ReleaseIfValid(disable);

    AuthorizationContextSnapshot invalid_try{};
    invalid_try.state = AuthorizationContextState::Live;
    EXPECT_FALSE(AuthorizationTrySnapshotNoExpire(kInvalidAuthorizationContextKey, &invalid_try));
    EXPECT_EQ(invalid_try.state, AuthorizationContextState::Retired);

    // Constructors reject noncanonical masks, authority above the ceiling,
    // zero tick budgets, and missing output storage without consuming a row.
    AuthorizationContextKey refused{0, 1};
    EXPECT_FALSE(AuthorizationCreateTrusted(CapSet{1ULL << 63}, CapSetTrusted(), 1, &refused));
    EXPECT_TRUE(refused == kInvalidAuthorizationContextKey);
    EXPECT_FALSE(AuthorizationCreateTrusted(fs_read_net, fs_read, 1, &refused));
    EXPECT_TRUE(refused == kInvalidAuthorizationContextKey);
    EXPECT_FALSE(AuthorizationCreateSandbox(fs_read, fs_read, 0, &refused));
    EXPECT_TRUE(refused == kInvalidAuthorizationContextKey);
    EXPECT_FALSE(AuthorizationCreateTrusted(fs_read, fs_read, 1, nullptr));
    EXPECT_FALSE(AuthorizationCreateSandbox(fs_read, fs_read, 1, nullptr));
    EXPECT_FALSE(AuthorizationRelease(nullptr));

    // Required output pointers fail before changing the exact live context.
    // AuthorizationDisableMask deliberately accepts a null optional result.
    AuthorizationContextKey null_probe = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(fs_read, fs_read, 10, &null_probe));
    const AuthorizationContextSnapshot null_probe_before = Inspect(null_probe, 1);
    EXPECT_FALSE(AuthorizationSnapshot(null_probe, 1, nullptr));
    EXPECT_FALSE(AuthorizationTrySnapshotNoExpire(null_probe, nullptr));
    EXPECT_FALSE(AuthorizationDeriveForSpawn(null_probe, 1, 0, fs_read, fs_read, 10,
                                             AuthorizationLaunchProfile::Trusted, nullptr));
    EXPECT_FALSE(AuthorizationDropIrreversiblyWithPrevious(null_probe, 1, Bit(kCapFsRead), nullptr));
    EXPECT_TRUE(AuthorizationDisableMask(null_probe, 1, 0, nullptr));
    const AuthorizationContextSnapshot null_probe_after = Inspect(null_probe, 1);
    EXPECT_EQ(null_probe_after.owner_references, null_probe_before.owner_references);
    EXPECT_EQ(null_probe_after.durable_bits, null_probe_before.durable_bits);
    EXPECT_EQ(null_probe_after.ceiling_bits, null_probe_before.ceiling_bits);
    EXPECT_EQ(null_probe_after.effective_bits, null_probe_before.effective_bits);
    ReleaseIfValid(null_probe);

    AuthorizationContextKey sandbox = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateSandbox(fs_read, fs_read_net, 50, &sandbox));
    auto sandbox_snapshot = Inspect(sandbox, 10);
    EXPECT_EQ(sandbox_snapshot.state, AuthorizationContextState::Live);
    EXPECT_EQ(sandbox_snapshot.provenance, AuthorizationLaunchProfile::Sandbox);
    EXPECT_EQ(sandbox_snapshot.owner_references, 1U);
    EXPECT_EQ(sandbox_snapshot.durable_bits, fs_read.bits);
    EXPECT_EQ(sandbox_snapshot.ceiling_bits, fs_read_net.bits);
    EXPECT_TRUE(SnapshotAuthorityIsCanonical(sandbox_snapshot));

    // A sandbox cannot promote provenance during derivation.
    AuthorizationContextKey promoted{0, 1};
    EXPECT_FALSE(AuthorizationDeriveForSpawn(sandbox, 10, 0, fs_read, fs_read, 10, AuthorizationLaunchProfile::Trusted,
                                             &promoted));
    EXPECT_TRUE(promoted == kInvalidAuthorizationContextKey);
    ReleaseIfValid(sandbox);

    // Leases authorize the parent temporarily, but derivation may copy only
    // durable authority.  A trusted parent may deliberately sandbox a child.
    AuthorizationContextKey parent = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(fs_read, fs_read_net_thread, 1000, &parent));
    EXPECT_FALSE(AuthorizationHas(parent, kCapNone, 100));
    EXPECT_FALSE(AuthorizationHas(parent, kCapCount, 100));
    EXPECT_FALSE(AuthorizationGrantDurable(parent, kCapNone));
    EXPECT_FALSE(AuthorizationGrantDurable(parent, kCapCount));
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 0, 200, 1));
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 100, 100, 1));
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 100, 200, 0));
    EXPECT_FALSE(AuthorizationRevokeLease(parent, kCapNet, 0));
    EXPECT_TRUE(AuthorizationGrantLease(parent, kCapNet, 100, 200, 10));
    EXPECT_TRUE(AuthorizationHas(parent, kCapNet, 150));

    AuthorizationContextKey child = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationDeriveForSpawn(parent, 150, Bit(kCapNet), fs_read, fs_read_net, 200,
                                            AuthorizationLaunchProfile::Sandbox, &child));
    const auto child_snapshot = Inspect(child, 150);
    EXPECT_EQ(child_snapshot.provenance, AuthorizationLaunchProfile::Sandbox);
    EXPECT_EQ(child_snapshot.durable_bits, fs_read.bits);
    EXPECT_EQ(child_snapshot.lease_bits, 0ULL);
    EXPECT_TRUE(AuthorizationHas(child, kCapFsRead, 150));
    EXPECT_FALSE(AuthorizationHas(child, kCapNet, 150));

    AuthorizationContextKey laundered{0, 1};
    EXPECT_FALSE(AuthorizationDeriveForSpawn(parent, 150, Bit(kCapNet), fs_read_net, fs_read_net, 200,
                                             AuthorizationLaunchProfile::Sandbox, &laundered));
    EXPECT_TRUE(laundered == kInvalidAuthorizationContextKey);
    EXPECT_FALSE(AuthorizationDeriveForSpawn(parent, 150, 1ULL << 63, fs_read, fs_read, 200,
                                             AuthorizationLaunchProfile::Sandbox, &laundered));
    ReleaseIfValid(child);

    // Per-cap lease generations are strict replay watermarks.  A newer grant
    // may replace an active one; stale revokes cannot tear down that grant.
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 150, 250, 10));
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 150, 250, 9));
    EXPECT_FALSE(AuthorizationRevokeLease(parent, kCapNet, 9));
    EXPECT_TRUE(AuthorizationGrantLease(parent, kCapNet, 150, 250, 11));
    EXPECT_FALSE(AuthorizationRevokeLease(parent, kCapNet, 10));
    EXPECT_TRUE(AuthorizationHas(parent, kCapNet, 249));
    auto expired = Inspect(parent, 250);
    EXPECT_EQ(expired.lease_bits & Bit(kCapNet), 0ULL);
    EXPECT_EQ(expired.lease_generation[static_cast<u32>(kCapNet)], 11ULL);
    EXPECT_FALSE(AuthorizationRevokeLease(parent, kCapNet, 11));
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 250, 300, 11));
    EXPECT_TRUE(AuthorizationGrantLease(parent, kCapNet, 251, 300, 12));

    // A regressing or unavailable monotonic clock clears active leases.  The
    // high-water time and generation remain, preventing clock or grant replay.
    auto regressed = Inspect(parent, 200);
    EXPECT_TRUE(regressed.lease_time_regressed);
    EXPECT_EQ(regressed.lease_bits & Bit(kCapNet), 0ULL);
    EXPECT_EQ(regressed.last_lease_time_ns, 251ULL);
    EXPECT_EQ(regressed.lease_generation[static_cast<u32>(kCapNet)], 12ULL);
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 200, 400, 13));
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 251, 400, 12));
    EXPECT_TRUE(AuthorizationGrantLease(parent, kCapNet, 251, 400, 13));
    EXPECT_TRUE(AuthorizationHas(parent, kCapNet, 251));
    EXPECT_FALSE(AuthorizationHas(parent, kCapNet, 0));
    EXPECT_FALSE(AuthorizationRevokeLease(parent, kCapNet, 13));
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 252, 500, kAuthorizationLeaseGenerationMaximum + 1));

    // Durable grants obey the ceiling.  Dropping a bit clears every authority
    // form and can never be undone, including through a newer lease.
    EXPECT_TRUE(AuthorizationGrantDurable(parent, kCapSpawnThread));
    EXPECT_TRUE(AuthorizationHas(parent, kCapSpawnThread, 252));
    EXPECT_TRUE(AuthorizationDropIrreversibly(parent, Bit(kCapSpawnThread) | Bit(kCapNet)));
    const auto dropped = Inspect(parent, 252);
    EXPECT_EQ(dropped.ceiling_bits & (Bit(kCapSpawnThread) | Bit(kCapNet)), 0ULL);
    EXPECT_EQ(dropped.durable_bits & (Bit(kCapSpawnThread) | Bit(kCapNet)), 0ULL);
    EXPECT_EQ(dropped.lease_generation[static_cast<u32>(kCapNet)], 13ULL);
    EXPECT_FALSE(AuthorizationGrantDurable(parent, kCapSpawnThread));
    EXPECT_FALSE(AuthorizationGrantLease(parent, kCapNet, 252, 500, 14));
    EXPECT_FALSE(AuthorizationDropIrreversibly(parent, 1ULL << 63));

    // The maximum lease generation serves one final grant and then becomes a
    // permanent per-cap watermark; it never wraps to a replayable low value.
    AuthorizationContextKey lease_terminal = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(CapSetEmpty(), CapSet{Bit(kCapNet)}, 10, &lease_terminal));
    EXPECT_TRUE(AuthorizationGrantLease(lease_terminal, kCapNet, 1, 10, kAuthorizationLeaseGenerationMaximum));
    EXPECT_TRUE(AuthorizationRevokeLease(lease_terminal, kCapNet, kAuthorizationLeaseGenerationMaximum));
    EXPECT_FALSE(AuthorizationGrantLease(lease_terminal, kCapNet, 2, 10, kAuthorizationLeaseGenerationMaximum));
    EXPECT_FALSE(AuthorizationGrantLease(lease_terminal, kCapNet, 2, 10, kAuthorizationLeaseGenerationMaximum + 1));
    ReleaseIfValid(lease_terminal);

    // Exact ownership balances, saturates safely, and invalidates consumed
    // local keys.  An exact retired generation remains inspectable.
    AuthorizationContextKey retained = parent;
    EXPECT_TRUE(AuthorizationRetain(parent));
    EXPECT_EQ(Inspect(parent, 252).owner_references, 2U);
    EXPECT_TRUE(AuthorizationRelease(&retained));
    EXPECT_TRUE(retained == kInvalidAuthorizationContextKey);
    EXPECT_TRUE(HostSetAuthorizationOwnerReferences(parent, std::numeric_limits<u32>::max()));
    EXPECT_FALSE(AuthorizationRetain(parent));
    EXPECT_TRUE(HostSetAuthorizationOwnerReferences(parent, 1));
    const AuthorizationContextKey retired_key = parent;
    EXPECT_TRUE(AuthorizationRelease(&parent));
    EXPECT_TRUE(parent == kInvalidAuthorizationContextKey);
    const auto retired_snapshot = Inspect(retired_key, 252);
    EXPECT_EQ(retired_snapshot.state, AuthorizationContextState::Retired);
    EXPECT_EQ(retired_snapshot.owner_references, 0U);
    EXPECT_EQ(retired_snapshot.lease_bits, 0ULL);
    EXPECT_EQ(retired_snapshot.lease_generation[static_cast<u32>(kCapNet)], 13ULL);
    EXPECT_FALSE(AuthorizationRetain(retired_key));
    AuthorizationContextKey retired_release = retired_key;
    EXPECT_FALSE(AuthorizationRelease(&retired_release));

    // Recycle one row 10,000 times.  Every old exact key fails after reuse,
    // generations strictly advance, and owner references return to zero.
    constexpr u32 kReuseCycles = 10000;
    u32 reuse_errors = 0;
    AuthorizationContextKey previous = kInvalidAuthorizationContextKey;
    u64 previous_generation = 0;
    u32 reuse_slot = kAuthorizationContextCapacity;
    for (u32 cycle = 0; cycle < kReuseCycles; ++cycle)
    {
        AuthorizationContextKey current = kInvalidAuthorizationContextKey;
        if (!AuthorizationCreateSandbox(CapSetEmpty(), CapSetEmpty(), 1, &current))
        {
            ++reuse_errors;
            break;
        }
        if (cycle == 0)
        {
            reuse_slot = current.slot;
        }
        if (current.slot != reuse_slot || current.generation <= previous_generation)
        {
            ++reuse_errors;
        }
        if (AuthorizationContextKeyIsValid(previous))
        {
            AuthorizationContextSnapshot stale_snapshot{};
            if (AuthorizationSnapshot(previous, 1, &stale_snapshot) || AuthorizationRetain(previous))
            {
                ++reuse_errors;
            }
        }
        previous = current;
        previous_generation = current.generation;
        if (!AuthorizationRelease(&current))
        {
            ++reuse_errors;
            break;
        }
    }
    EXPECT_EQ(reuse_errors, 0U);

    // Capacity exhaustion is exact.  Releasing one row makes that slot the
    // sole allocation candidate and immediately invalidates its stale key.
    std::array<AuthorizationContextKey, kAuthorizationContextCapacity> full{};
    for (AuthorizationContextKey& key : full)
    {
        EXPECT_TRUE(AuthorizationCreateTrusted(fs_read, fs_read, 10, &key));
    }
    AuthorizationContextKey overflow{0, 1};
    EXPECT_FALSE(AuthorizationCreateTrusted(fs_read, fs_read, 10, &overflow));
    EXPECT_TRUE(overflow == kInvalidAuthorizationContextKey);
    const AuthorizationContextKey stale = full[17];
    EXPECT_TRUE(AuthorizationRelease(&full[17]));
    AuthorizationContextKey replacement = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(fs_read, fs_read, 10, &replacement));
    EXPECT_EQ(replacement.slot, stale.slot);
    EXPECT_TRUE(replacement.generation > stale.generation);
    AuthorizationContextSnapshot cleared{};
    EXPECT_FALSE(AuthorizationSnapshot(stale, 1, &cleared));
    EXPECT_FALSE(AuthorizationRetain(stale));
    for (AuthorizationContextKey& key : full)
    {
        ReleaseIfValid(key);
    }
    ReleaseIfValid(replacement);

    // Tick, denial, and write thresholds each return exactly one action.
    AuthorizationContextKey thresholds = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateSandbox(CapSetEmpty(), CapSetEmpty(), 3, &thresholds));
    auto action = AuthorizationChargeTick(thresholds, 2);
    EXPECT_EQ(action.action, AuthorizationAction::None);
    EXPECT_EQ(action.value, 2ULL);
    action = AuthorizationChargeTick(thresholds, 1);
    EXPECT_EQ(action.action, AuthorizationAction::TickBudgetExceeded);
    action = AuthorizationChargeTick(thresholds, 1);
    EXPECT_EQ(action.action, AuthorizationAction::None);
    u32 denial_actions = 0;
    for (u64 denial = 0; denial < kAuthorizationDenialThreshold + 10; ++denial)
    {
        if (AuthorizationRecordDenial(thresholds).action == AuthorizationAction::DenialThresholdExceeded)
        {
            ++denial_actions;
        }
    }
    EXPECT_EQ(denial_actions, 1U);
    action = AuthorizationRecordFsWrite(thresholds, 10, kAuthorizationFsWriteWindowByteCaps[0]);
    EXPECT_EQ(action.action, AuthorizationAction::None);
    action = AuthorizationRecordFsWrite(thresholds, 10, 1);
    EXPECT_EQ(action.action, AuthorizationAction::FsWriteRateExceeded);
    EXPECT_EQ(action.fs_write_window, 0U);
    action = AuthorizationRecordFsWrite(thresholds, 10, 1);
    EXPECT_EQ(action.action, AuthorizationAction::None);
    ReleaseIfValid(thresholds);

    // Window rollover includes the current write in the fresh window, while a
    // regressing tick is a fail-closed action and never subtracts elapsed time.
    AuthorizationContextKey windowed = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateSandbox(CapSetEmpty(), CapSetEmpty(), 100, &windowed));
    action = AuthorizationRecordFsWrite(windowed, 0, kAuthorizationFsWriteWindowByteCaps[0]);
    EXPECT_EQ(action.action, AuthorizationAction::None);
    action = AuthorizationRecordFsWrite(windowed, kAuthorizationFsWriteWindowTicks[0],
                                        kAuthorizationFsWriteWindowByteCaps[0]);
    EXPECT_EQ(action.action, AuthorizationAction::None);
    auto rolled = Inspect(windowed, 1);
    EXPECT_EQ(rolled.fs_write_window_start_tick[0], kAuthorizationFsWriteWindowTicks[0]);
    EXPECT_EQ(rolled.fs_write_window_bytes[0], kAuthorizationFsWriteWindowByteCaps[0]);
    action = AuthorizationRecordFsWrite(windowed, kAuthorizationFsWriteWindowTicks[0] - 1, 1);
    EXPECT_EQ(action.action, AuthorizationAction::FsWriteRateExceeded);
    EXPECT_TRUE(action.time_regression);
    action = AuthorizationRecordFsWrite(windowed, kAuthorizationFsWriteWindowTicks[0] - 2, 1);
    EXPECT_EQ(action.action, AuthorizationAction::None);
    EXPECT_TRUE(action.time_regression);
    ReleaseIfValid(windowed);

    // All arithmetic additions saturate and fail closed instead of wrapping.
    const u64 maximum = std::numeric_limits<u64>::max();
    AuthorizationContextKey tick_overflow = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(CapSetEmpty(), CapSetEmpty(), maximum, &tick_overflow));
    EXPECT_TRUE(HostSetAuthorizationTickCount(tick_overflow, maximum - 1));
    action = AuthorizationChargeTick(tick_overflow, 2);
    EXPECT_TRUE(action.arithmetic_overflow);
    EXPECT_EQ(action.value, maximum);
    EXPECT_EQ(action.action, AuthorizationAction::TickBudgetExceeded);
    ReleaseIfValid(tick_overflow);

    AuthorizationContextKey denial_overflow = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(CapSetEmpty(), CapSetEmpty(), maximum, &denial_overflow));
    EXPECT_TRUE(HostSetAuthorizationDenialCount(denial_overflow, maximum));
    action = AuthorizationRecordDenial(denial_overflow);
    EXPECT_TRUE(action.arithmetic_overflow);
    EXPECT_EQ(action.value, maximum);
    EXPECT_EQ(action.action, AuthorizationAction::DenialThresholdExceeded);
    ReleaseIfValid(denial_overflow);

    AuthorizationContextKey fs_overflow = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(CapSetEmpty(), CapSetEmpty(), maximum, &fs_overflow));
    EXPECT_TRUE(HostSetAuthorizationFsCounters(fs_overflow, maximum, maximum));
    action = AuthorizationRecordFsWrite(fs_overflow, 100, 1);
    EXPECT_TRUE(action.arithmetic_overflow);
    EXPECT_EQ(action.value, maximum);
    EXPECT_EQ(action.action, AuthorizationAction::FsWriteRateExceeded);
    ReleaseIfValid(fs_overflow);

    // Concurrent reference churn, lease mutation, accounting, and snapshots
    // share one exact live key.  Every snapshot remains internally coherent.
    AuthorizationContextKey concurrent = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateSandbox(fs_read, fs_read_net, maximum, &concurrent));
    constexpr u32 kIterations = 2000;
    constexpr u32 kThreadCount = 6;
    std::barrier<> start(static_cast<std::ptrdiff_t>(kThreadCount + 1));
    std::atomic<u32> errors{0};
    std::atomic<u32> concurrent_denial_actions{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);

    for (u32 owner_thread = 0; owner_thread < 2; ++owner_thread)
    {
        threads.emplace_back(
            [&]()
            {
                start.arrive_and_wait();
                for (u32 iteration = 0; iteration < kIterations; ++iteration)
                {
                    if (!AuthorizationRetain(concurrent))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    AuthorizationContextKey local = concurrent;
                    if (!AuthorizationRelease(&local) || local != kInvalidAuthorizationContextKey)
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }

    threads.emplace_back(
        [&]()
        {
            start.arrive_and_wait();
            for (u64 generation = 1; generation <= kIterations; ++generation)
            {
                if (!AuthorizationGrantLease(concurrent, kCapNet, 1000, 2000, generation) ||
                    !AuthorizationRevokeLease(concurrent, kCapNet, generation))
                {
                    errors.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });

    for (u32 snapshot_thread = 0; snapshot_thread < 2; ++snapshot_thread)
    {
        threads.emplace_back(
            [&]()
            {
                start.arrive_and_wait();
                for (u32 iteration = 0; iteration < kIterations; ++iteration)
                {
                    AuthorizationContextSnapshot snapshot{};
                    if (!AuthorizationSnapshot(concurrent, 1000, &snapshot) ||
                        snapshot.state != AuthorizationContextState::Live || snapshot.owner_references == 0 ||
                        !SnapshotAuthorityIsCanonical(snapshot))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }

    threads.emplace_back(
        [&]()
        {
            start.arrive_and_wait();
            for (u32 iteration = 0; iteration < kIterations; ++iteration)
            {
                if (!AuthorizationChargeTick(concurrent, 1).resolved ||
                    !AuthorizationRecordFsWrite(concurrent, iteration, 1).resolved)
                {
                    errors.fetch_add(1, std::memory_order_relaxed);
                }
                if (AuthorizationRecordDenial(concurrent).action == AuthorizationAction::DenialThresholdExceeded)
                {
                    concurrent_denial_actions.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });

    start.arrive_and_wait();
    for (std::thread& thread : threads)
    {
        thread.join();
    }
    EXPECT_EQ(errors.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(concurrent_denial_actions.load(std::memory_order_relaxed), 1U);
    const auto concurrent_snapshot = Inspect(concurrent, 1000);
    EXPECT_EQ(concurrent_snapshot.owner_references, 1U);
    EXPECT_EQ(concurrent_snapshot.ticks_used, static_cast<u64>(kIterations));
    EXPECT_EQ(concurrent_snapshot.denial_count, static_cast<u64>(kIterations));
    EXPECT_EQ(concurrent_snapshot.fs_write_bytes_total, static_cast<u64>(kIterations));
    EXPECT_TRUE(SnapshotAuthorityIsCanonical(concurrent_snapshot));
    ReleaseIfValid(concurrent);

    // A terminal-generation row serves one last lifetime, then allocation
    // permanently skips it while other rows continue independently.
    EXPECT_TRUE(HostSetRetiredAuthorizationGeneration(0, kAuthorizationGenerationMaximum - 1));
    EXPECT_FALSE(HostSetRetiredAuthorizationGeneration(0, 1));
    AuthorizationContextKey terminal = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(fs_read, fs_read, 1, &terminal));
    EXPECT_EQ(terminal.slot, 0U);
    EXPECT_EQ(terminal.generation, kAuthorizationGenerationMaximum);
    const AuthorizationContextKey terminal_stale = terminal;
    EXPECT_TRUE(AuthorizationRelease(&terminal));
    EXPECT_EQ(Inspect(terminal_stale, 1).state, AuthorizationContextState::Retired);
    EXPECT_FALSE(AuthorizationRetain(terminal_stale));

    AuthorizationContextKey after_terminal = kInvalidAuthorizationContextKey;
    EXPECT_TRUE(AuthorizationCreateTrusted(fs_read, fs_read, 1, &after_terminal));
    EXPECT_NE(after_terminal.slot, terminal_stale.slot);
    ReleaseIfValid(after_terminal);

    return duetos_host_test::finish_main("test_authorization_context");
}
