// tests/host/test_resource_domain.cpp
//
// Hosted ownership and concurrency properties for proc/resource_domain.cpp.
// The production TU is included so terminal-generation retirement can be
// reached without a production-only test seam.  All ordinary assertions use
// the public API; white-box helpers only advance already-Retired rows to the
// final generation.  The declared kernel SpinLock calls are supplied by one
// host mutex so the production critical sections run unchanged under TSan.

#include "host_test_helper.h"
#include "proc/resource_domain.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <mutex>
#include <thread>
#include <vector>

#include "proc/resource_domain.cpp"

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

// Test-only terminal setup.  Never mutates a live/closing row.
bool HostSetRetiredDomainGeneration(u32 slot, u64 generation)
{
    sync::SpinLockGuard guard(g_resource_domain_lock);
    if (slot >= kResourceDomainCapacity || generation > kResourceDomainGenerationMaximum)
        return false;
    ResourceDomainRow& row = g_resource_domains[slot];
    if (row.state != ResourceDomainState::Retired || row.owner_references != 0 || row.section_objects != 0 ||
        row.section_pages != 0 || row.channel_objects != 0 || row.channel_bytes != 0)
    {
        return false;
    }
    row.generation = generation;
    return true;
}

bool HostSetRetiredChargeGeneration(u32 slot, u64 generation)
{
    sync::SpinLockGuard guard(g_resource_domain_lock);
    if (slot >= kResourceSectionChargeCapacity || generation > kResourceSectionChargeGenerationMaximum)
        return false;
    ResourceSectionChargeRow& row = g_section_charges[slot];
    if (row.state != ResourceSectionChargeState::Retired || row.pages != 0)
        return false;
    row.generation = generation;
    row.domain = kInvalidResourceDomainKey;
    return true;
}

} // namespace duetos::core

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::core;

ResourceDomainSnapshot Inspect(ResourceDomainKey key)
{
    ResourceDomainSnapshot snapshot{};
    EXPECT_TRUE(ResourceDomainInspectExact(key, &snapshot));
    return snapshot;
}

void ReleaseChargeIfValid(ResourceSectionChargeKey& charge)
{
    if (ResourceSectionChargeKeyIsValid(charge))
        EXPECT_TRUE(ResourceDomainReleaseSection(&charge));
}

} // namespace

int main()
{
    EXPECT_TRUE(ResourceDomainSelfTest());

    // A spawned child inherits the exact key.  Retain/release changes only the
    // owner count; every inherited identity charges the same aggregate row.
    ResourceDomainKey inherited = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateSandbox(3, &inherited));
    EXPECT_TRUE(ResourceDomainKeyIsValid(inherited));
    constexpr u32 kChildCount = 4;
    std::array<ResourceDomainKey, kChildCount> child_keys{};
    for (u32 index = 0; index < kChildCount; ++index)
    {
        child_keys[index] = inherited;
        EXPECT_TRUE(child_keys[index] == inherited);
        EXPECT_TRUE(ResourceDomainRetain(child_keys[index]));
    }
    auto snapshot = Inspect(inherited);
    EXPECT_EQ(snapshot.owner_references, kChildCount + 1U);

    ResourceSectionChargeKey inherited_charge = kInvalidResourceSectionChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeSection(child_keys[2], 3, &inherited_charge, nullptr));
    snapshot = Inspect(inherited);
    EXPECT_EQ(snapshot.section_objects, 1U);
    EXPECT_EQ(snapshot.section_pages, 3U);
    for (ResourceDomainKey child : child_keys)
        EXPECT_TRUE(ResourceDomainRelease(child));
    snapshot = Inspect(inherited);
    EXPECT_EQ(snapshot.owner_references, 1U);
    EXPECT_TRUE(ResourceDomainRelease(inherited));
    snapshot = Inspect(inherited);
    EXPECT_EQ(snapshot.state, ResourceDomainState::Closing);
    EXPECT_EQ(snapshot.owner_references, 0U);
    EXPECT_FALSE(ResourceDomainRetain(inherited));

    ResourceSectionChargeKey inherited_replay = inherited_charge;
    EXPECT_TRUE(ResourceDomainReleaseSection(&inherited_charge));
    EXPECT_TRUE(inherited_charge == kInvalidResourceSectionChargeKey);
    EXPECT_FALSE(ResourceDomainReleaseSection(&inherited_replay));
    snapshot = Inspect(inherited);
    EXPECT_EQ(snapshot.state, ResourceDomainState::Retired);
    EXPECT_EQ(snapshot.section_objects, 0U);
    EXPECT_EQ(snapshot.section_pages, 0U);

    // Every quota refusal is transactional: the output token is invalid and
    // both counters remain byte-for-byte equal to the prior snapshot.
    ResourceDomainKey quota_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateSandbox(3, &quota_domain));
    ResourceSectionChargeKey quota_a = kInvalidResourceSectionChargeKey;
    ResourceSectionChargeKey quota_b = kInvalidResourceSectionChargeKey;
    ResourceSectionChargeKey refused = ResourceSectionChargeKey{0, 1};
    EXPECT_TRUE(ResourceDomainTryChargeSection(quota_domain, 2, &quota_a, nullptr));
    const ResourceDomainSnapshot before_page_refusal = Inspect(quota_domain);
    EXPECT_FALSE(ResourceDomainTryChargeSection(quota_domain, 2, &refused, nullptr));
    EXPECT_TRUE(refused == kInvalidResourceSectionChargeKey);
    snapshot = Inspect(quota_domain);
    EXPECT_EQ(snapshot.section_objects, before_page_refusal.section_objects);
    EXPECT_EQ(snapshot.section_pages, before_page_refusal.section_pages);
    EXPECT_TRUE(ResourceDomainTryChargeSection(quota_domain, 1, &quota_b, nullptr));
    const ResourceDomainSnapshot before_object_refusal = Inspect(quota_domain);
    EXPECT_FALSE(ResourceDomainTryChargeSection(quota_domain, 1, &refused, nullptr));
    snapshot = Inspect(quota_domain);
    EXPECT_EQ(snapshot.section_objects, before_object_refusal.section_objects);
    EXPECT_EQ(snapshot.section_pages, before_object_refusal.section_pages);
    ReleaseChargeIfValid(quota_a);
    ReleaseChargeIfValid(quota_b);
    EXPECT_TRUE(ResourceDomainRelease(quota_domain));

    // Malformed and overflow-shaped requests fail before mutating accounting.
    // The subtraction-based page check must remain safe even for UINT32_MAX.
    ResourceDomainKey arithmetic_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateSandbox(1, &arithmetic_domain));
    const ResourceDomainSnapshot before_arithmetic_refusal = Inspect(arithmetic_domain);
    refused = ResourceSectionChargeKey{0, 1};
    EXPECT_FALSE(ResourceDomainTryChargeSection(arithmetic_domain, static_cast<u32>(~0U), &refused, nullptr));
    EXPECT_TRUE(refused == kInvalidResourceSectionChargeKey);
    snapshot = Inspect(arithmetic_domain);
    EXPECT_EQ(snapshot.section_objects, before_arithmetic_refusal.section_objects);
    EXPECT_EQ(snapshot.section_pages, before_arithmetic_refusal.section_pages);
    refused = ResourceSectionChargeKey{0, 1};
    EXPECT_FALSE(ResourceDomainTryChargeSection(kInvalidResourceDomainKey, 1, &refused, nullptr));
    EXPECT_TRUE(refused == kInvalidResourceSectionChargeKey);
    EXPECT_FALSE(ResourceDomainTryChargeSection(arithmetic_domain, 1, nullptr, nullptr));
    EXPECT_FALSE(ResourceDomainReleaseSection(nullptr));
    EXPECT_TRUE(ResourceDomainRelease(arithmetic_domain));

    // Exhaust all eight exact charge rows while leaving a separate domain with
    // quota.  Charge-row exhaustion must not pre-debit that domain.
    ResourceDomainKey service = kInvalidResourceDomainKey;
    ResourceDomainKey trusted_a = kInvalidResourceDomainKey;
    ResourceDomainKey trusted_b = kInvalidResourceDomainKey;
    ResourceDomainKey no_slot = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateAuthenticatedService(&service));
    EXPECT_TRUE(ResourceDomainCreateTrusted(&trusted_a));
    EXPECT_TRUE(ResourceDomainCreateTrusted(&trusted_b));
    EXPECT_TRUE(ResourceDomainCreateTrusted(&no_slot));
    std::array<ResourceSectionChargeKey, kResourceSectionChargeCapacity> all_charges{};
    ResourceSectionPoolClass pool_class = ResourceSectionPoolClass::Ordinary;
    for (u32 index = 0; index < 4; ++index)
    {
        EXPECT_TRUE(ResourceDomainTryChargeSection(service, 1, &all_charges[index], &pool_class));
        EXPECT_EQ(pool_class, ResourceSectionPoolClass::AuthenticatedService);
    }
    for (u32 index = 0; index < 2; ++index)
    {
        EXPECT_TRUE(ResourceDomainTryChargeSection(trusted_a, 1, &all_charges[4 + index], nullptr));
        EXPECT_TRUE(ResourceDomainTryChargeSection(trusted_b, 1, &all_charges[6 + index], nullptr));
    }
    const ResourceDomainSnapshot before_slot_refusal = Inspect(no_slot);
    EXPECT_FALSE(ResourceDomainTryChargeSection(no_slot, 1, &refused, nullptr));
    snapshot = Inspect(no_slot);
    EXPECT_EQ(snapshot.section_objects, before_slot_refusal.section_objects);
    EXPECT_EQ(snapshot.section_pages, before_slot_refusal.section_pages);
    for (auto& charge : all_charges)
        ReleaseChargeIfValid(charge);
    EXPECT_TRUE(ResourceDomainRelease(service));
    EXPECT_TRUE(ResourceDomainRelease(trusted_a));
    EXPECT_TRUE(ResourceDomainRelease(trusted_b));
    EXPECT_TRUE(ResourceDomainRelease(no_slot));

    // Authenticated manifests narrow the service profile rather than receiving
    // the profile maxima implicitly. Zero and above-maximum requests fail
    // before consuming a domain row and always invalidate the output token.
    ResourceDomainKey bounded = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateBoundedAuthenticatedService(1, 17, &bounded));
    snapshot = Inspect(bounded);
    EXPECT_EQ(snapshot.profile, ResourceDomainProfile::AuthenticatedService);
    EXPECT_EQ(snapshot.section_pool_class, ResourceSectionPoolClass::AuthenticatedService);
    EXPECT_EQ(snapshot.section_object_limit, 1U);
    EXPECT_EQ(snapshot.section_page_limit, 17U);
    EXPECT_EQ(snapshot.channel_object_limit, kAuthenticatedServiceChannelObjectLimit);
    EXPECT_EQ(snapshot.channel_byte_limit, kAuthenticatedServiceChannelByteLimit);
    EXPECT_TRUE(ResourceDomainRelease(bounded));

    bounded = ResourceDomainKey{0, 1};
    EXPECT_FALSE(ResourceDomainCreateBoundedAuthenticatedService(0, 1, &bounded));
    EXPECT_TRUE(bounded == kInvalidResourceDomainKey);
    bounded = ResourceDomainKey{0, 1};
    EXPECT_FALSE(ResourceDomainCreateBoundedAuthenticatedService(1, 0, &bounded));
    EXPECT_TRUE(bounded == kInvalidResourceDomainKey);
    bounded = ResourceDomainKey{0, 1};
    EXPECT_FALSE(
        ResourceDomainCreateBoundedAuthenticatedService(kAuthenticatedServiceSectionObjectLimit + 1U, 1, &bounded));
    EXPECT_TRUE(bounded == kInvalidResourceDomainKey);
    bounded = ResourceDomainKey{0, 1};
    EXPECT_FALSE(
        ResourceDomainCreateBoundedAuthenticatedService(1, kAuthenticatedServiceSectionPageLimit + 1U, &bounded));
    EXPECT_TRUE(bounded == kInvalidResourceDomainKey);
    EXPECT_FALSE(ResourceDomainCreateBoundedAuthenticatedService(1, 1, nullptr));

    // Concurrent inherited-owner churn must return to the one root owner.
    ResourceDomainKey concurrent = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateAuthenticatedService(&concurrent));
    constexpr u32 kThreadCount = 8;
    constexpr u32 kOwnerIterations = 2000;
    std::barrier<> owner_start(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::atomic<u32> owner_errors{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);
    for (u32 thread = 0; thread < kThreadCount; ++thread)
    {
        threads.emplace_back(
            [&]()
            {
                owner_start.arrive_and_wait();
                for (u32 iteration = 0; iteration < kOwnerIterations; ++iteration)
                {
                    if (!ResourceDomainRetain(concurrent))
                    {
                        owner_errors.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    if (!ResourceDomainRelease(concurrent))
                        owner_errors.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }
    owner_start.arrive_and_wait();
    for (auto& thread : threads)
        thread.join();
    threads.clear();
    EXPECT_EQ(owner_errors.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(Inspect(concurrent).owner_references, 1U);

    // Eight simultaneous attempts against a four-object domain deterministically
    // produce four exact charges and four unchanged refusals.  Hold every
    // winner until the main thread has inspected the fully charged row.
    std::barrier<> attempted(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::barrier<> release_gate(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::atomic<u32> winners{0};
    std::atomic<u32> quota_refusals{0};
    std::atomic<u32> charge_errors{0};
    for (u32 thread = 0; thread < kThreadCount; ++thread)
    {
        threads.emplace_back(
            [&]()
            {
                ResourceSectionChargeKey charge = kInvalidResourceSectionChargeKey;
                const bool charged = ResourceDomainTryChargeSection(concurrent, 1, &charge, nullptr);
                if (charged)
                    winners.fetch_add(1, std::memory_order_relaxed);
                else
                    quota_refusals.fetch_add(1, std::memory_order_relaxed);
                attempted.arrive_and_wait();
                release_gate.arrive_and_wait();
                if (charged)
                {
                    ResourceSectionChargeKey replay = charge;
                    if (!ResourceDomainReleaseSection(&charge) || ResourceSectionChargeKeyIsValid(charge) ||
                        ResourceDomainReleaseSection(&replay))
                    {
                        charge_errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }
    attempted.arrive_and_wait();
    snapshot = Inspect(concurrent);
    EXPECT_EQ(winners.load(std::memory_order_relaxed), kAuthenticatedServiceSectionObjectLimit);
    EXPECT_EQ(quota_refusals.load(std::memory_order_relaxed), kThreadCount - kAuthenticatedServiceSectionObjectLimit);
    EXPECT_EQ(snapshot.section_objects, kAuthenticatedServiceSectionObjectLimit);
    EXPECT_EQ(snapshot.section_pages, kAuthenticatedServiceSectionObjectLimit);
    release_gate.arrive_and_wait();
    for (auto& thread : threads)
        thread.join();
    threads.clear();
    EXPECT_EQ(charge_errors.load(std::memory_order_relaxed), 0U);
    snapshot = Inspect(concurrent);
    EXPECT_EQ(snapshot.section_objects, 0U);
    EXPECT_EQ(snapshot.section_pages, 0U);

    // Racing copied final-reference tokens is linearizable: exactly one copy
    // consumes the charge, and the loser cannot underflow either counter.
    ResourceSectionChargeKey raced_charge = kInvalidResourceSectionChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeSection(concurrent, 1, &raced_charge, nullptr));
    std::barrier<> release_race_start(3);
    std::atomic<u32> release_winners{0};
    for (u32 thread = 0; thread < 2; ++thread)
    {
        threads.emplace_back(
            [&]()
            {
                ResourceSectionChargeKey copy = raced_charge;
                release_race_start.arrive_and_wait();
                if (ResourceDomainReleaseSection(&copy))
                    release_winners.fetch_add(1, std::memory_order_relaxed);
            });
    }
    release_race_start.arrive_and_wait();
    for (auto& thread : threads)
        thread.join();
    threads.clear();
    EXPECT_EQ(release_winners.load(std::memory_order_relaxed), 1U);
    EXPECT_FALSE(ResourceDomainReleaseSection(&raced_charge));
    snapshot = Inspect(concurrent);
    EXPECT_EQ(snapshot.section_objects, 0U);
    EXPECT_EQ(snapshot.section_pages, 0U);

    // Sustained concurrent charge/release and stale-token replay preserves an
    // exact zero balance after all workers exit.
    constexpr u32 kChargeIterations = 2000;
    std::barrier<> charge_start(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::atomic<u32> churn_successes{0};
    std::atomic<u32> churn_refusals{0};
    for (u32 thread = 0; thread < kThreadCount; ++thread)
    {
        threads.emplace_back(
            [&]()
            {
                charge_start.arrive_and_wait();
                for (u32 iteration = 0; iteration < kChargeIterations; ++iteration)
                {
                    ResourceSectionChargeKey charge = kInvalidResourceSectionChargeKey;
                    if (!ResourceDomainTryChargeSection(concurrent, 1, &charge, nullptr))
                    {
                        churn_refusals.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    churn_successes.fetch_add(1, std::memory_order_relaxed);
                    ResourceSectionChargeKey replay = charge;
                    if (!ResourceDomainReleaseSection(&charge) || ResourceDomainReleaseSection(&replay))
                        charge_errors.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }
    charge_start.arrive_and_wait();
    for (auto& thread : threads)
        thread.join();
    EXPECT_NE(churn_successes.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(churn_successes.load(std::memory_order_relaxed) + churn_refusals.load(std::memory_order_relaxed),
              kThreadCount * kChargeIterations);
    EXPECT_EQ(charge_errors.load(std::memory_order_relaxed), 0U);
    snapshot = Inspect(concurrent);
    EXPECT_EQ(snapshot.section_objects, 0U);
    EXPECT_EQ(snapshot.section_pages, 0U);
    EXPECT_TRUE(ResourceDomainRelease(concurrent));

    // Reusing both the domain row and charge row must not let either old
    // generation debit the replacement domain.
    ResourceDomainKey old_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&old_domain));
    ResourceSectionChargeKey old_charge = kInvalidResourceSectionChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeSection(old_domain, 1, &old_charge, nullptr));
    const ResourceSectionChargeKey stale_charge = old_charge;
    EXPECT_TRUE(ResourceDomainReleaseSection(&old_charge));
    EXPECT_TRUE(ResourceDomainRelease(old_domain));

    ResourceDomainKey replacement_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&replacement_domain));
    EXPECT_EQ(replacement_domain.slot, old_domain.slot);
    EXPECT_NE(replacement_domain.generation, old_domain.generation);
    EXPECT_FALSE(ResourceDomainRetain(old_domain));
    EXPECT_FALSE(ResourceDomainRelease(old_domain));
    refused = ResourceSectionChargeKey{0, 1};
    EXPECT_FALSE(ResourceDomainTryChargeSection(old_domain, 1, &refused, nullptr));
    EXPECT_TRUE(refused == kInvalidResourceSectionChargeKey);
    ResourceDomainSnapshot stale_snapshot{};
    EXPECT_FALSE(ResourceDomainInspectExact(old_domain, &stale_snapshot));

    ResourceSectionChargeKey replacement_charge = kInvalidResourceSectionChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeSection(replacement_domain, 1, &replacement_charge, nullptr));
    EXPECT_EQ(replacement_charge.slot, stale_charge.slot);
    EXPECT_NE(replacement_charge.generation, stale_charge.generation);
    const ResourceDomainSnapshot before_stale_release = Inspect(replacement_domain);
    ResourceSectionChargeKey stale_copy = stale_charge;
    EXPECT_FALSE(ResourceDomainReleaseSection(&stale_copy));
    snapshot = Inspect(replacement_domain);
    EXPECT_EQ(snapshot.section_objects, before_stale_release.section_objects);
    EXPECT_EQ(snapshot.section_pages, before_stale_release.section_pages);
    EXPECT_TRUE(ResourceDomainReleaseSection(&replacement_charge));
    EXPECT_TRUE(ResourceDomainRelease(replacement_domain));

    // Domain-table capacity is exact and transactional. An extra create must
    // invalidate its output without perturbing any live owner row.
    std::array<ResourceDomainKey, kResourceDomainCapacity> full_domains{};
    for (ResourceDomainKey& domain : full_domains)
        EXPECT_TRUE(ResourceDomainCreateTrusted(&domain));
    ResourceDomainKey capacity_refused = ResourceDomainKey{0, 1};
    EXPECT_FALSE(ResourceDomainCreateTrusted(&capacity_refused));
    EXPECT_TRUE(capacity_refused == kInvalidResourceDomainKey);
    for (ResourceDomainKey domain : full_domains)
    {
        EXPECT_EQ(Inspect(domain).owner_references, 1U);
        EXPECT_TRUE(ResourceDomainRelease(domain));
    }

    // Terminal generations are accepted exactly once and never wrap.  A row
    // at generation max is permanently skipped, while the next eligible row
    // continues with its own exact generation.
    EXPECT_FALSE(ResourceDomainKeyIsValid(ResourceDomainKey{0, 0}));
    EXPECT_TRUE(ResourceDomainKeyIsValid(ResourceDomainKey{0, kResourceDomainGenerationMaximum}));
    EXPECT_FALSE(ResourceDomainKeyIsValid(ResourceDomainKey{0, kResourceDomainGenerationMaximum + 1U}));
    EXPECT_FALSE(ResourceSectionChargeKeyIsValid(ResourceSectionChargeKey{0, 0}));
    EXPECT_TRUE(ResourceSectionChargeKeyIsValid(ResourceSectionChargeKey{0, kResourceSectionChargeGenerationMaximum}));
    EXPECT_FALSE(
        ResourceSectionChargeKeyIsValid(ResourceSectionChargeKey{0, kResourceSectionChargeGenerationMaximum + 1U}));

    EXPECT_TRUE(HostSetRetiredDomainGeneration(0, kResourceDomainGenerationMaximum - 1U));
    ResourceDomainKey terminal_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&terminal_domain));
    EXPECT_EQ(terminal_domain.slot, 0U);
    EXPECT_EQ(terminal_domain.generation, kResourceDomainGenerationMaximum);
    EXPECT_TRUE(ResourceDomainRelease(terminal_domain));
    snapshot = Inspect(terminal_domain);
    EXPECT_EQ(snapshot.state, ResourceDomainState::Retired);
    EXPECT_FALSE(ResourceDomainRetain(terminal_domain));

    ResourceDomainKey after_terminal = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&after_terminal));
    EXPECT_NE(after_terminal.slot, terminal_domain.slot);
    EXPECT_TRUE(ResourceDomainRelease(after_terminal));

    EXPECT_TRUE(HostSetRetiredChargeGeneration(0, kResourceSectionChargeGenerationMaximum - 1U));
    ResourceDomainKey charge_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&charge_domain));
    ResourceSectionChargeKey terminal_charge = kInvalidResourceSectionChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeSection(charge_domain, 1, &terminal_charge, nullptr));
    EXPECT_EQ(terminal_charge.slot, 0U);
    EXPECT_EQ(terminal_charge.generation, kResourceSectionChargeGenerationMaximum);
    EXPECT_TRUE(ResourceDomainReleaseSection(&terminal_charge));
    ResourceSectionChargeKey after_terminal_charge = kInvalidResourceSectionChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeSection(charge_domain, 1, &after_terminal_charge, nullptr));
    EXPECT_NE(after_terminal_charge.slot, 0U);
    EXPECT_TRUE(ResourceDomainReleaseSection(&after_terminal_charge));
    EXPECT_TRUE(ResourceDomainRelease(charge_domain));

    return duetos_host_test::finish_main("test_resource_domain");
}
