// Hosted exact-generation, rollback, concurrency, and terminal-exhaustion
// coverage for ResourceDomain ChannelCore charges.

#include "host_test_helper.h"
#include "proc/resource_domain.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <mutex>
#include <thread>

// Include the production TU so the terminal-generation test can advance only
// already-retired test rows without adding a production test seam.
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

bool HostSetRetiredChannelChargeGeneration(u32 slot, u64 generation)
{
    sync::SpinLockGuard guard(g_resource_domain_lock);
    if (slot >= kResourceChannelChargeCapacity || generation > kResourceChannelChargeGenerationMaximum)
        return false;
    ResourceChannelChargeRow& row = g_channel_charges[slot];
    if (row.state != ResourceChannelChargeState::Retired || !(row.domain == kInvalidResourceDomainKey) ||
        row.queued_buffer_bytes != 0)
    {
        return false;
    }
    row.generation = generation;
    return true;
}

bool HostRetireChannelChargeAuthority()
{
    sync::SpinLockGuard guard(g_resource_domain_lock);
    for (u32 slot = 0; slot < kResourceChannelChargeCapacity; ++slot)
    {
        ResourceChannelChargeRow& row = g_channel_charges[slot];
        if (row.state != ResourceChannelChargeState::Retired || !(row.domain == kInvalidResourceDomainKey) ||
            row.queued_buffer_bytes != 0)
        {
            return false;
        }
    }
    for (u32 slot = 0; slot < kResourceChannelChargeCapacity; ++slot)
        g_channel_charges[slot].generation = kResourceChannelChargeGenerationMaximum;
    return true;
}

} // namespace duetos::core

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::core;

constexpr u64 kTestChannelBytes = 8ULL * 1024;

ResourceDomainSnapshot Inspect(ResourceDomainKey key)
{
    ResourceDomainSnapshot snapshot{};
    EXPECT_TRUE(ResourceDomainInspectExact(key, &snapshot));
    return snapshot;
}

void ReleaseIfValid(ResourceChannelChargeKey& charge)
{
    if (ResourceChannelChargeKeyIsValid(charge))
        EXPECT_TRUE(ResourceDomainReleaseChannel(&charge));
}

} // namespace

int main()
{
    EXPECT_FALSE(ResourceChannelChargeKeyIsValid(kInvalidResourceChannelChargeKey));
    EXPECT_FALSE(ResourceChannelChargeKeyIsValid(ResourceChannelChargeKey{0, 0}));
    EXPECT_TRUE(ResourceChannelChargeKeyIsValid(ResourceChannelChargeKey{0, kResourceChannelChargeGenerationMaximum}));
    EXPECT_FALSE(ResourceDomainReleaseChannel(nullptr));
    ResourceChannelChargeKey invalid_charge{};
    EXPECT_FALSE(ResourceDomainReleaseChannel(&invalid_charge));
    EXPECT_FALSE(ResourceDomainTryChargeChannel(kInvalidResourceDomainKey, kTestChannelBytes, nullptr));

    // A charge keeps a zero-owner domain Closing until the exact final token
    // is consumed. A copied token cannot release twice or manufacture quota.
    ResourceDomainKey pinned = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&pinned));
    ResourceChannelChargeKey pinned_charge = kInvalidResourceChannelChargeKey;
    EXPECT_FALSE(ResourceDomainTryChargeChannel(pinned, 0, &pinned_charge));
    EXPECT_TRUE(pinned_charge == kInvalidResourceChannelChargeKey);
    EXPECT_TRUE(ResourceDomainTryChargeChannel(pinned, kTestChannelBytes, &pinned_charge));
    EXPECT_TRUE(ResourceChannelChargeKeyIsValid(pinned_charge));
    ResourceChannelChargeKey replay = pinned_charge;
    auto snapshot = Inspect(pinned);
    EXPECT_EQ(snapshot.channel_objects, 1U);
    EXPECT_EQ(snapshot.channel_bytes, kTestChannelBytes);
    EXPECT_EQ(snapshot.channel_object_limit, kTrustedChannelObjectLimit);
    EXPECT_EQ(snapshot.channel_byte_limit, kTrustedChannelByteLimit);
    EXPECT_TRUE(ResourceDomainRelease(pinned));
    snapshot = Inspect(pinned);
    EXPECT_EQ(snapshot.state, ResourceDomainState::Closing);
    EXPECT_EQ(snapshot.owner_references, 0U);
    EXPECT_EQ(snapshot.channel_objects, 1U);
    EXPECT_EQ(snapshot.channel_bytes, kTestChannelBytes);
    ResourceChannelChargeKey refused{0, 1};
    EXPECT_FALSE(ResourceDomainTryChargeChannel(pinned, kTestChannelBytes, &refused));
    EXPECT_TRUE(refused == kInvalidResourceChannelChargeKey);
    EXPECT_TRUE(ResourceDomainReleaseChannel(&pinned_charge));
    EXPECT_TRUE(pinned_charge == kInvalidResourceChannelChargeKey);
    EXPECT_FALSE(ResourceDomainReleaseChannel(&replay));
    snapshot = Inspect(pinned);
    EXPECT_EQ(snapshot.state, ResourceDomainState::Retired);
    EXPECT_EQ(snapshot.channel_objects, 0U);
    EXPECT_EQ(snapshot.channel_bytes, 0ULL);

    // Reusing both the domain and charge slots advances their generations.
    // An old copied charge remains stale and cannot debit the replacement.
    ResourceDomainKey aba_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&aba_domain));
    EXPECT_EQ(aba_domain.slot, pinned.slot);
    EXPECT_TRUE(aba_domain.generation > pinned.generation);
    ResourceChannelChargeKey first = kInvalidResourceChannelChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeChannel(aba_domain, kTestChannelBytes, &first));
    const ResourceChannelChargeKey stale_first = first;
    EXPECT_TRUE(ResourceDomainReleaseChannel(&first));
    ResourceChannelChargeKey second = kInvalidResourceChannelChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeChannel(aba_domain, kTestChannelBytes, &second));
    EXPECT_EQ(second.slot, stale_first.slot);
    EXPECT_TRUE(second.generation > stale_first.generation);
    replay = stale_first;
    EXPECT_FALSE(ResourceDomainReleaseChannel(&replay));
    EXPECT_EQ(Inspect(aba_domain).channel_objects, 1U);
    EXPECT_TRUE(ResourceDomainReleaseChannel(&second));
    EXPECT_TRUE(ResourceDomainRelease(aba_domain));

    // Section and channel charges independently pin one Closing generation;
    // retirement occurs only after both resource classes reach final release.
    ResourceDomainKey mixed = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateSandbox(1, &mixed));
    ResourceSectionChargeKey section_charge = kInvalidResourceSectionChargeKey;
    ResourceChannelChargeKey channel_charge = kInvalidResourceChannelChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeSection(mixed, 1, &section_charge, nullptr));
    EXPECT_TRUE(ResourceDomainTryChargeChannel(mixed, kTestChannelBytes, &channel_charge));
    EXPECT_TRUE(ResourceDomainRelease(mixed));
    EXPECT_TRUE(ResourceDomainReleaseChannel(&channel_charge));
    snapshot = Inspect(mixed);
    EXPECT_EQ(snapshot.state, ResourceDomainState::Closing);
    EXPECT_EQ(snapshot.section_objects, 1U);
    EXPECT_EQ(snapshot.channel_objects, 0U);
    EXPECT_EQ(snapshot.channel_bytes, 0ULL);
    EXPECT_TRUE(ResourceDomainReleaseSection(&section_charge));
    EXPECT_EQ(Inspect(mixed).state, ResourceDomainState::Retired);

    // Two copied owners racing final release linearize to one success.
    ResourceDomainKey raced = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&raced));
    ResourceChannelChargeKey race_charge = kInvalidResourceChannelChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeChannel(raced, kTestChannelBytes, &race_charge));
    std::barrier race_start(3);
    std::atomic<u32> race_successes{0};
    std::thread releaser_a(
        [&]
        {
            ResourceChannelChargeKey copy = race_charge;
            race_start.arrive_and_wait();
            if (ResourceDomainReleaseChannel(&copy))
                race_successes.fetch_add(1, std::memory_order_relaxed);
        });
    std::thread releaser_b(
        [&]
        {
            ResourceChannelChargeKey copy = race_charge;
            race_start.arrive_and_wait();
            if (ResourceDomainReleaseChannel(&copy))
                race_successes.fetch_add(1, std::memory_order_relaxed);
        });
    race_start.arrive_and_wait();
    releaser_a.join();
    releaser_b.join();
    EXPECT_EQ(race_successes.load(std::memory_order_relaxed), 1U);
    EXPECT_EQ(Inspect(raced).channel_objects, 0U);
    EXPECT_EQ(Inspect(raced).channel_bytes, 0ULL);
    replay = race_charge;
    EXPECT_FALSE(ResourceDomainReleaseChannel(&replay));
    EXPECT_TRUE(ResourceDomainRelease(raced));

    // Object and byte quotas are independent immutable profile policy. Tiny
    // charges cannot bypass the object cap, and one large-but-bounded charge
    // can consume the byte cap without consuming every object slot. Failures
    // leave both counters unchanged.
    ResourceDomainKey object_limited = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateSandbox(1, &object_limited));
    std::array<ResourceChannelChargeKey, kSandboxChannelObjectLimit> tiny_charges{};
    for (auto& charge : tiny_charges)
        EXPECT_TRUE(ResourceDomainTryChargeChannel(object_limited, 1, &charge));
    const ResourceDomainSnapshot before_object_quota = Inspect(object_limited);
    EXPECT_EQ(before_object_quota.channel_objects, kSandboxChannelObjectLimit);
    EXPECT_EQ(before_object_quota.channel_bytes, static_cast<u64>(kSandboxChannelObjectLimit));
    refused = ResourceChannelChargeKey{0, 1};
    EXPECT_FALSE(ResourceDomainTryChargeChannel(object_limited, 1, &refused));
    EXPECT_TRUE(refused == kInvalidResourceChannelChargeKey);
    snapshot = Inspect(object_limited);
    EXPECT_EQ(snapshot.channel_objects, before_object_quota.channel_objects);
    EXPECT_EQ(snapshot.channel_bytes, before_object_quota.channel_bytes);
    for (auto& charge : tiny_charges)
        ReleaseIfValid(charge);
    EXPECT_TRUE(ResourceDomainRelease(object_limited));

    ResourceDomainKey byte_limited = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&byte_limited));
    ResourceChannelChargeKey byte_charge = kInvalidResourceChannelChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeChannel(byte_limited, kTrustedChannelByteLimit, &byte_charge));
    const ResourceDomainSnapshot before_byte_quota = Inspect(byte_limited);
    EXPECT_EQ(before_byte_quota.channel_objects, 1U);
    EXPECT_EQ(before_byte_quota.channel_bytes, kTrustedChannelByteLimit);
    refused = ResourceChannelChargeKey{0, 1};
    EXPECT_FALSE(ResourceDomainTryChargeChannel(byte_limited, 1, &refused));
    EXPECT_TRUE(refused == kInvalidResourceChannelChargeKey);
    snapshot = Inspect(byte_limited);
    EXPECT_EQ(snapshot.channel_objects, before_byte_quota.channel_objects);
    EXPECT_EQ(snapshot.channel_bytes, before_byte_quota.channel_bytes);
    EXPECT_TRUE(ResourceDomainReleaseChannel(&byte_charge));
    EXPECT_TRUE(ResourceDomainRelease(byte_limited));

    // Four logical CPUs race the sandbox's exact two-core/two-buffer budget.
    // Admission linearizes under the ResourceDomain lock: exactly two complete
    // charges win and no partial object/byte update escapes.
    ResourceDomainKey concurrently_limited = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateSandbox(1, &concurrently_limited));
    constexpr u32 kConcurrentApplicants = 4;
    std::array<ResourceChannelChargeKey, kConcurrentApplicants> concurrent_charges{};
    std::array<std::thread, kConcurrentApplicants> applicants;
    std::barrier admission_start(kConcurrentApplicants + 1);
    std::atomic<u32> admission_successes{0};
    for (u32 index = 0; index < kConcurrentApplicants; ++index)
    {
        applicants[index] = std::thread(
            [&, index]
            {
                admission_start.arrive_and_wait();
                if (ResourceDomainTryChargeChannel(concurrently_limited, kTestChannelBytes, &concurrent_charges[index]))
                {
                    admission_successes.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }
    admission_start.arrive_and_wait();
    for (auto& applicant : applicants)
        applicant.join();
    EXPECT_EQ(admission_successes.load(std::memory_order_relaxed), kSandboxChannelObjectLimit);
    snapshot = Inspect(concurrently_limited);
    EXPECT_EQ(snapshot.channel_objects, kSandboxChannelObjectLimit);
    EXPECT_EQ(snapshot.channel_bytes, kSandboxChannelByteLimit);
    for (auto& charge : concurrent_charges)
        ReleaseIfValid(charge);
    EXPECT_TRUE(ResourceDomainRelease(concurrently_limited));

    // Exhausting the fixed charge pool is transactional and leaves the exact
    // domain counters unchanged. Two service profiles fill the global 64-row
    // authority without bypassing either per-domain quota.
    std::array<ResourceDomainKey, 2> full_domains{};
    for (auto& domain : full_domains)
        EXPECT_TRUE(ResourceDomainCreateAuthenticatedService(&domain));
    std::array<ResourceChannelChargeKey, kResourceChannelChargeCapacity> charges{};
    for (u32 index = 0; index < kResourceChannelChargeCapacity; ++index)
    {
        const u32 domain_index = index / kAuthenticatedServiceChannelObjectLimit;
        EXPECT_TRUE(ResourceDomainTryChargeChannel(full_domains[domain_index], kTestChannelBytes, &charges[index]));
    }
    for (const auto domain : full_domains)
    {
        snapshot = Inspect(domain);
        EXPECT_EQ(snapshot.channel_objects, kAuthenticatedServiceChannelObjectLimit);
        EXPECT_EQ(snapshot.channel_bytes, kAuthenticatedServiceChannelByteLimit);
    }

    ResourceDomainKey global_probe = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&global_probe));
    const ResourceDomainSnapshot before_full = Inspect(global_probe);
    refused = ResourceChannelChargeKey{0, 1};
    EXPECT_FALSE(ResourceDomainTryChargeChannel(global_probe, kTestChannelBytes, &refused));
    EXPECT_TRUE(refused == kInvalidResourceChannelChargeKey);
    snapshot = Inspect(global_probe);
    EXPECT_EQ(snapshot.owner_references, before_full.owner_references);
    EXPECT_EQ(snapshot.section_objects, before_full.section_objects);
    EXPECT_EQ(snapshot.section_pages, before_full.section_pages);
    EXPECT_EQ(snapshot.channel_objects, before_full.channel_objects);
    EXPECT_EQ(snapshot.channel_bytes, before_full.channel_bytes);
    for (auto& charge : charges)
        ReleaseIfValid(charge);
    for (const auto domain : full_domains)
    {
        EXPECT_EQ(Inspect(domain).channel_objects, 0U);
        EXPECT_EQ(Inspect(domain).channel_bytes, 0ULL);
        EXPECT_TRUE(ResourceDomainRelease(domain));
    }
    EXPECT_TRUE(ResourceDomainRelease(global_probe));

    // Terminal charge generation is allocated once and then permanently
    // retired. With every other row terminal, the next charge fails closed.
    EXPECT_TRUE(HostRetireChannelChargeAuthority());
    EXPECT_TRUE(HostSetRetiredChannelChargeGeneration(0, kResourceChannelChargeGenerationMaximum - 1U));
    ResourceDomainKey terminal_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&terminal_domain));
    ResourceChannelChargeKey terminal_charge = kInvalidResourceChannelChargeKey;
    EXPECT_TRUE(ResourceDomainTryChargeChannel(terminal_domain, kTestChannelBytes, &terminal_charge));
    EXPECT_EQ(terminal_charge.slot, 0U);
    EXPECT_EQ(terminal_charge.generation, kResourceChannelChargeGenerationMaximum);
    EXPECT_TRUE(ResourceDomainReleaseChannel(&terminal_charge));
    refused = ResourceChannelChargeKey{0, 1};
    EXPECT_FALSE(ResourceDomainTryChargeChannel(terminal_domain, kTestChannelBytes, &refused));
    EXPECT_TRUE(refused == kInvalidResourceChannelChargeKey);
    EXPECT_EQ(Inspect(terminal_domain).channel_objects, 0U);
    EXPECT_EQ(Inspect(terminal_domain).channel_bytes, 0ULL);
    EXPECT_TRUE(ResourceDomainRelease(terminal_domain));

    return duetos_host_test::finish_main("test_resource_domain_channel");
}
