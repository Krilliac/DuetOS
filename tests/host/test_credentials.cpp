// Hosted ownership, policy, and concurrency properties for proc/credentials.
//
// The production TU is included so terminal-generation retirement can be
// forced without adding a production test API.  Public operations otherwise
// drive every check.  A host mutex supplies the kernel SpinLock symbols, so
// ASan/UBSan and TSan exercise the real production critical sections.

#include "host_test_helper.h"
#include "proc/credentials.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <mutex>
#include <thread>
#include <vector>

#include "proc/credentials.cpp"

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

void SpinLockRelease(SpinLock&, IrqFlags)
{
    g_host_spinlock.unlock();
}

} // namespace duetos::sync

namespace duetos::core
{

// White-box terminal setup.  It can only advance an ownerless retired row.
bool HostSetRetiredCredentialGeneration(u32 slot, u64 generation)
{
    sync::SpinLockGuard guard(g_credential_lock);
    if (slot >= kCredentialCapacity || generation > kCredentialGenerationMaximum)
    {
        return false;
    }
    CredentialRow& row = g_credentials[slot];
    if (row.state != CredentialState::Retired || row.owner_references != 0 || generation < row.generation)
    {
        return false;
    }
    row.generation = generation;
    return true;
}

} // namespace duetos::core

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::core;

CredentialSecurityContext RichContext()
{
    CredentialSecurityContext context{};
    context.real_uid = 1000;
    context.effective_uid = 1001;
    context.saved_uid = 1002;
    context.fs_uid = 1003;
    context.real_gid = 100;
    context.effective_gid = 101;
    context.saved_gid = 102;
    context.fs_gid = 103;
    context.supplemental_group_count = 4;
    context.supplemental_groups[0] = 10;
    context.supplemental_groups[1] = 20;
    context.supplemental_groups[2] = 30;
    context.supplemental_groups[3] = 40;
    context.capability_effective = 0x07;
    context.capability_permitted = 0x3F;
    context.capability_inheritable = 0x18;
    context.capability_bounding = 0xFF;
    context.win32_integrity = Win32IntegrityLevel::High;
    return context;
}

CredentialSecurityContext RestrictedContext()
{
    CredentialSecurityContext context = RichContext();
    context.real_uid = 1001;
    context.effective_uid = 1002;
    context.saved_uid = 1003;
    context.fs_uid = 1000;
    context.real_gid = 101;
    context.effective_gid = 102;
    context.saved_gid = 103;
    context.fs_gid = 100;
    context.supplemental_group_count = 2;
    for (u32& group : context.supplemental_groups)
    {
        group = 0;
    }
    context.supplemental_groups[0] = 10;
    context.supplemental_groups[1] = 30;
    context.capability_effective = 0x03;
    context.capability_permitted = 0x0F;
    context.capability_inheritable = 0x08;
    context.capability_bounding = 0x3F;
    context.win32_integrity = Win32IntegrityLevel::Medium;
    return context;
}

bool ContextEqual(const CredentialSecurityContext& lhs, const CredentialSecurityContext& rhs)
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

CredentialSnapshot Inspect(CredentialKey key)
{
    CredentialSnapshot snapshot{};
    EXPECT_TRUE(CredentialInspectExact(key, &snapshot));
    return snapshot;
}

bool SnapshotEqual(const CredentialSnapshot& lhs, const CredentialSnapshot& rhs)
{
    return lhs.state == rhs.state && lhs.owner_references == rhs.owner_references &&
           ContextEqual(lhs.security, rhs.security);
}

void ExpectTrustedRejected(const CredentialSecurityContext& malformed)
{
    CredentialKey output{0, 1};
    EXPECT_FALSE(CredentialAuthorityCreateTrusted(malformed, &output));
    EXPECT_TRUE(output == kInvalidCredentialKey);
}

void ExpectDeriveRejectedUnchanged(CredentialKey parent, const CredentialSecurityContext& escalation)
{
    const CredentialSnapshot before = Inspect(parent);
    CredentialKey output{0, 1};
    EXPECT_FALSE(CredentialDeriveRestricted(parent, escalation, &output));
    EXPECT_TRUE(output == kInvalidCredentialKey);
    const CredentialSnapshot after = Inspect(parent);
    EXPECT_TRUE(SnapshotEqual(before, after));
}

void ReleaseIfValid(CredentialKey& key)
{
    if (CredentialKeyIsValid(key))
    {
        EXPECT_TRUE(CredentialRelease(&key));
    }
}

} // namespace

int main()
{
    EXPECT_TRUE(CredentialSelfTest());
    EXPECT_FALSE(CredentialKeyIsValid(kInvalidCredentialKey));
    EXPECT_TRUE(CredentialKeyIsValid(CredentialKey{0, 1}));

    // Process root constructors have no caller-controlled identity surface.
    CredentialKey trusted_root = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateTrustedRoot(&trusted_root));
    auto trusted_root_snapshot = Inspect(trusted_root);
    EXPECT_EQ(trusted_root_snapshot.security.real_uid, 0U);
    EXPECT_EQ(trusted_root_snapshot.security.effective_uid, 0U);
    EXPECT_EQ(trusted_root_snapshot.security.real_gid, 0U);
    EXPECT_EQ(trusted_root_snapshot.security.capability_effective, kCredentialCapabilityKnownMask);
    EXPECT_EQ(trusted_root_snapshot.security.capability_bounding, kCredentialCapabilityKnownMask);
    EXPECT_EQ(trusted_root_snapshot.security.win32_integrity, Win32IntegrityLevel::System);

    // Normal child inheritance is an exact owner retain, not a mutable copy.
    CredentialKey inherited = trusted_root;
    EXPECT_TRUE(CredentialRetain(inherited));
    EXPECT_EQ(Inspect(trusted_root).owner_references, 2U);
    EXPECT_TRUE(CredentialRelease(&inherited));
    EXPECT_TRUE(inherited == kInvalidCredentialKey);
    EXPECT_EQ(Inspect(trusted_root).owner_references, 1U);
    ReleaseIfValid(trusted_root);

    CredentialKey nobody = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateNobodySandbox(&nobody));
    const auto nobody_snapshot = Inspect(nobody);
    EXPECT_EQ(nobody_snapshot.security.real_uid, kCredentialNobodyId);
    EXPECT_EQ(nobody_snapshot.security.effective_uid, kCredentialNobodyId);
    EXPECT_EQ(nobody_snapshot.security.fs_uid, kCredentialNobodyId);
    EXPECT_EQ(nobody_snapshot.security.real_gid, kCredentialNobodyId);
    EXPECT_EQ(nobody_snapshot.security.supplemental_group_count, 0U);
    EXPECT_EQ(nobody_snapshot.security.capability_effective, 0ULL);
    EXPECT_EQ(nobody_snapshot.security.capability_permitted, 0ULL);
    EXPECT_EQ(nobody_snapshot.security.capability_bounding, 0ULL);
    EXPECT_EQ(nobody_snapshot.security.win32_integrity, Win32IntegrityLevel::Low);
    ReleaseIfValid(nobody);

    const CredentialSecurityContext rich = RichContext();
    EXPECT_TRUE(CredentialSecurityContextIsCanonical(rich));
    CredentialKey parent = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateTrusted(rich, &parent));
    EXPECT_TRUE(CredentialKeyIsValid(parent));
    CredentialSnapshot parent_snapshot = Inspect(parent);
    EXPECT_EQ(parent_snapshot.state, CredentialState::Live);
    EXPECT_EQ(parent_snapshot.owner_references, 1U);
    EXPECT_TRUE(ContextEqual(parent_snapshot.security, rich));

    // Every non-canonical spelling is refused before it can consume a row.
    CredentialSecurityContext malformed = rich;
    malformed.real_uid = kCredentialInvalidId;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.fs_gid = kCredentialInvalidId;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.supplemental_group_count = kCredentialSupplementalGroupCapacity + 1U;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.supplemental_groups[2] = malformed.supplemental_groups[1];
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.supplemental_groups[1] = 5;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.supplemental_groups[4] = 50;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.capability_bounding |= 1ULL << 63;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.capability_effective |= 1ULL << 8;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.capability_permitted |= 1ULL << 8;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.capability_inheritable |= 1ULL << 8;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.win32_integrity = Win32IntegrityLevel::Invalid;
    ExpectTrustedRejected(malformed);
    malformed = rich;
    malformed.win32_integrity = static_cast<Win32IntegrityLevel>(99);
    ExpectTrustedRejected(malformed);
    EXPECT_TRUE(SnapshotEqual(parent_snapshot, Inspect(parent)));

    // Sandbox construction accepts only canonical non-root identity and
    // supplies no capability or high-integrity authority.
    CredentialSandboxIdentity sandbox_identity{};
    sandbox_identity.uid = 2000;
    sandbox_identity.gid = 200;
    sandbox_identity.supplemental_group_count = 2;
    sandbox_identity.supplemental_groups[0] = 210;
    sandbox_identity.supplemental_groups[1] = 220;
    CredentialKey sandbox = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateSandbox(sandbox_identity, &sandbox));
    auto sandbox_snapshot = Inspect(sandbox);
    EXPECT_EQ(sandbox_snapshot.security.real_uid, sandbox_identity.uid);
    EXPECT_EQ(sandbox_snapshot.security.fs_uid, sandbox_identity.uid);
    EXPECT_EQ(sandbox_snapshot.security.real_gid, sandbox_identity.gid);
    EXPECT_EQ(sandbox_snapshot.security.fs_gid, sandbox_identity.gid);
    EXPECT_EQ(sandbox_snapshot.security.supplemental_group_count, 2U);
    EXPECT_EQ(sandbox_snapshot.security.capability_effective, 0ULL);
    EXPECT_EQ(sandbox_snapshot.security.capability_permitted, 0ULL);
    EXPECT_EQ(sandbox_snapshot.security.capability_inheritable, 0ULL);
    EXPECT_EQ(sandbox_snapshot.security.capability_bounding, 0ULL);
    EXPECT_EQ(sandbox_snapshot.security.win32_integrity, Win32IntegrityLevel::Low);
    ReleaseIfValid(sandbox);

    CredentialKey refused{0, 1};
    CredentialSandboxIdentity bad_sandbox = sandbox_identity;
    bad_sandbox.uid = 0;
    EXPECT_FALSE(CredentialAuthorityCreateSandbox(bad_sandbox, &refused));
    EXPECT_TRUE(refused == kInvalidCredentialKey);
    bad_sandbox = sandbox_identity;
    bad_sandbox.gid = 0;
    EXPECT_FALSE(CredentialAuthorityCreateSandbox(bad_sandbox, &refused));
    bad_sandbox = sandbox_identity;
    bad_sandbox.supplemental_groups[0] = 0;
    EXPECT_FALSE(CredentialAuthorityCreateSandbox(bad_sandbox, &refused));
    bad_sandbox = sandbox_identity;
    bad_sandbox.supplemental_groups[1] = bad_sandbox.supplemental_groups[0];
    EXPECT_FALSE(CredentialAuthorityCreateSandbox(bad_sandbox, &refused));

    // A valid derivation may rearrange already-held identity values, select a
    // strict group subset, drop each capability mask, and lower integrity.
    const CredentialSecurityContext restricted = RestrictedContext();
    CredentialKey child = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialDeriveRestricted(parent, restricted, &child));
    EXPECT_TRUE(ContextEqual(Inspect(child).security, restricted));
    EXPECT_TRUE(SnapshotEqual(parent_snapshot, Inspect(parent)));

    // Each escalation dimension is refused independently and leaves the
    // parent exact snapshot unchanged.
    CredentialSecurityContext escalation = restricted;
    escalation.real_uid = 5000;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.real_uid = kCredentialNobodyId;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.fs_gid = 500;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.supplemental_groups[1] = 25;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.capability_effective |= 1ULL << 4;
    escalation.capability_permitted |= 1ULL << 4;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.capability_permitted |= 1ULL << 6;
    escalation.capability_bounding |= 1ULL << 6;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.capability_inheritable |= 1ULL << 5;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.capability_bounding |= 1ULL << 8;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.capability_bounding |= 1ULL << 63;
    ExpectDeriveRejectedUnchanged(parent, escalation);
    escalation = restricted;
    escalation.win32_integrity = Win32IntegrityLevel::System;
    ExpectDeriveRejectedUnchanged(parent, escalation);

    // Reducing four held identities to one already-held identity is a drop;
    // assigning a new identity (including nobody) requires an authority path.
    CredentialSecurityContext collapsed = restricted;
    collapsed.real_uid = rich.real_uid;
    collapsed.effective_uid = rich.real_uid;
    collapsed.saved_uid = rich.real_uid;
    collapsed.fs_uid = rich.real_uid;
    collapsed.real_gid = rich.real_gid;
    collapsed.effective_gid = rich.real_gid;
    collapsed.saved_gid = rich.real_gid;
    collapsed.fs_gid = rich.real_gid;
    collapsed.supplemental_group_count = 0;
    for (u32& group : collapsed.supplemental_groups)
    {
        group = 0;
    }
    collapsed.capability_effective = 0;
    collapsed.capability_permitted = 0;
    collapsed.capability_inheritable = 0;
    collapsed.capability_bounding = 0;
    collapsed.win32_integrity = Win32IntegrityLevel::Low;
    CredentialKey collapsed_child = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialDeriveRestricted(parent, collapsed, &collapsed_child));

    ReleaseIfValid(child);
    ReleaseIfValid(collapsed_child);
    ReleaseIfValid(parent);

    // Retains balance exactly; last release retires the same generation and a
    // copied stale key cannot replay a release or become live again.
    CredentialKey owned = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateTrusted(rich, &owned));
    constexpr u32 kCopies = 4;
    std::array<CredentialKey, kCopies> owners{};
    for (CredentialKey& owner : owners)
    {
        owner = owned;
        EXPECT_TRUE(CredentialRetain(owned));
    }
    EXPECT_EQ(Inspect(owned).owner_references, kCopies + 1U);
    for (CredentialKey& owner : owners)
    {
        EXPECT_TRUE(CredentialRelease(&owner));
        EXPECT_TRUE(owner == kInvalidCredentialKey);
    }
    CredentialKey replay = owned;
    EXPECT_TRUE(CredentialRelease(&owned));
    EXPECT_TRUE(owned == kInvalidCredentialKey);
    auto retired = Inspect(replay);
    EXPECT_EQ(retired.state, CredentialState::Retired);
    EXPECT_EQ(retired.owner_references, 0U);
    EXPECT_FALSE(CredentialRetain(replay));
    EXPECT_FALSE(CredentialRelease(&replay));

    // Fill all 64 rows.  Releasing exactly one row makes that slot the sole
    // allocation candidate, proving generation reuse and stale rejection.
    std::array<CredentialKey, kCredentialCapacity> full{};
    for (CredentialKey& key : full)
    {
        EXPECT_TRUE(CredentialAuthorityCreateTrusted(rich, &key));
    }
    CredentialKey overflow{0, 1};
    EXPECT_FALSE(CredentialAuthorityCreateTrusted(rich, &overflow));
    EXPECT_TRUE(overflow == kInvalidCredentialKey);

    const CredentialKey stale = full[17];
    const u64 stale_generation = stale.generation;
    EXPECT_TRUE(CredentialRelease(&full[17]));
    CredentialKey replacement = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateTrusted(rich, &replacement));
    EXPECT_EQ(replacement.slot, stale.slot);
    EXPECT_TRUE(replacement.generation > stale_generation);
    CredentialSnapshot cleared{CredentialState::Live, 77, rich};
    EXPECT_FALSE(CredentialInspectExact(stale, &cleared));
    EXPECT_EQ(cleared.owner_references, 0U);
    EXPECT_FALSE(CredentialRetain(stale));
    CredentialKey stale_release = stale;
    EXPECT_FALSE(CredentialRelease(&stale_release));
    EXPECT_EQ(Inspect(replacement).owner_references, 1U);
    for (CredentialKey& key : full)
    {
        ReleaseIfValid(key);
    }
    ReleaseIfValid(replacement);

    // Concurrent inherited-owner churn returns to the one root owner.
    CredentialKey concurrent = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateTrusted(rich, &concurrent));
    constexpr u32 kThreadCount = 8;
    constexpr u32 kIterations = 2000;
    std::barrier<> retain_start(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::atomic<u32> errors{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);
    for (u32 thread = 0; thread < kThreadCount; ++thread)
    {
        threads.emplace_back(
            [&]()
            {
                retain_start.arrive_and_wait();
                for (u32 iteration = 0; iteration < kIterations; ++iteration)
                {
                    if (!CredentialRetain(concurrent))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    CredentialKey local = concurrent;
                    if (!CredentialRelease(&local) || local != kInvalidCredentialKey)
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }
    retain_start.arrive_and_wait();
    for (std::thread& thread : threads)
    {
        thread.join();
    }
    threads.clear();
    EXPECT_EQ(errors.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(Inspect(concurrent).owner_references, 1U);

    // Derivation is independent ownership: concurrent create/release cycles
    // never alter the parent, and stale replay never consumes a reused row.
    std::barrier<> derive_start(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::atomic<u32> derivations{0};
    for (u32 thread = 0; thread < kThreadCount; ++thread)
    {
        threads.emplace_back(
            [&]()
            {
                derive_start.arrive_and_wait();
                for (u32 iteration = 0; iteration < kIterations; ++iteration)
                {
                    CredentialKey derived = kInvalidCredentialKey;
                    if (!CredentialDeriveRestricted(concurrent, restricted, &derived))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    derivations.fetch_add(1, std::memory_order_relaxed);
                    CredentialKey stale_child = derived;
                    if (!CredentialRelease(&derived) || CredentialRelease(&stale_child))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }
    derive_start.arrive_and_wait();
    for (std::thread& thread : threads)
    {
        thread.join();
    }
    EXPECT_EQ(errors.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(derivations.load(std::memory_order_relaxed), kThreadCount * kIterations);
    parent_snapshot = Inspect(concurrent);
    EXPECT_EQ(parent_snapshot.owner_references, 1U);
    EXPECT_TRUE(ContextEqual(parent_snapshot.security, rich));
    ReleaseIfValid(concurrent);

    // Terminal generations are valid for one final lifetime, then that slot
    // is permanently skipped.  Another slot continues independently.
    EXPECT_FALSE(CredentialKeyIsValid(CredentialKey{0, 0}));
    EXPECT_TRUE(CredentialKeyIsValid(CredentialKey{0, kCredentialGenerationMaximum}));
    EXPECT_FALSE(CredentialKeyIsValid(CredentialKey{0, kCredentialGenerationMaximum + 1U}));
    EXPECT_TRUE(HostSetRetiredCredentialGeneration(0, kCredentialGenerationMaximum - 1U));
    EXPECT_FALSE(HostSetRetiredCredentialGeneration(0, 1));
    CredentialKey terminal = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateTrusted(rich, &terminal));
    EXPECT_EQ(terminal.slot, 0U);
    EXPECT_EQ(terminal.generation, kCredentialGenerationMaximum);
    const CredentialKey terminal_stale = terminal;
    EXPECT_TRUE(CredentialRelease(&terminal));
    EXPECT_EQ(Inspect(terminal_stale).state, CredentialState::Retired);
    EXPECT_FALSE(CredentialRetain(terminal_stale));

    CredentialKey after_terminal = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateTrusted(rich, &after_terminal));
    EXPECT_NE(after_terminal.slot, terminal_stale.slot);
    ReleaseIfValid(after_terminal);

    // Null output storage is refused before row allocation or parent
    // mutation.  A null release target is likewise a no-op failure.
    EXPECT_FALSE(CredentialAuthorityCreateTrusted(rich, nullptr));
    EXPECT_FALSE(CredentialAuthorityCreateTrustedRoot(nullptr));
    EXPECT_FALSE(CredentialAuthorityCreateSandbox(sandbox_identity, nullptr));
    EXPECT_FALSE(CredentialAuthorityCreateNobodySandbox(nullptr));
    EXPECT_FALSE(CredentialInspectExact(kInvalidCredentialKey, nullptr));
    EXPECT_FALSE(CredentialRelease(nullptr));

    CredentialKey null_probe = kInvalidCredentialKey;
    EXPECT_TRUE(CredentialAuthorityCreateTrusted(rich, &null_probe));
    const CredentialSnapshot null_probe_before = Inspect(null_probe);
    EXPECT_FALSE(CredentialDeriveRestricted(null_probe, restricted, nullptr));
    EXPECT_TRUE(SnapshotEqual(null_probe_before, Inspect(null_probe)));
    ReleaseIfValid(null_probe);

    return duetos_host_test::finish_main("test_credentials");
}
