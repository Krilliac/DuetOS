// Hosted lifecycle, ownership, and concurrency properties for proc/thread_group.
//
// The production TU is included so terminal-generation retirement can be
// forced without a production test API. Public operations drive every other
// check. A host mutex supplies the kernel SpinLock symbols for sanitizer and
// TSan coverage of the production critical sections.

#include "host_test_helper.h"
#include "proc/thread_group.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <mutex>
#include <thread>
#include <vector>

#include "proc/thread_group.cpp"

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

// White-box terminal setup. It can only advance an ownerless retired row.
bool HostSetRetiredThreadGroupGeneration(u32 slot, u64 generation)
{
    sync::SpinLockGuard guard(g_thread_group_lock);
    if (slot >= kThreadGroupCapacity || generation > kThreadGroupGenerationMaximum)
    {
        return false;
    }
    ThreadGroupRow& row = g_thread_groups[slot];
    if (row.state != ThreadGroupState::Retired || row.owner_references != 0 || generation < row.generation)
    {
        return false;
    }
    row.generation = generation;
    return true;
}

// White-box reference saturation setup. It cannot revive or retarget a row.
bool HostSetActiveThreadGroupOwnerReferences(ThreadGroupKey key, u32 owner_references)
{
    sync::SpinLockGuard guard(g_thread_group_lock);
    ThreadGroupRow* row = ResolveExactLocked(key);
    if (row == nullptr || !IsActive(*row) || owner_references == 0)
    {
        return false;
    }
    row->owner_references = owner_references;
    return true;
}

} // namespace duetos::core

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::core;

constexpr ThreadGroupMemberIdentity Member(u64 opaque)
{
    return ThreadGroupMemberIdentity{opaque};
}

ThreadGroupSnapshot Inspect(ThreadGroupKey key)
{
    ThreadGroupSnapshot snapshot{};
    EXPECT_TRUE(ThreadGroupInspectExact(key, &snapshot));
    return snapshot;
}

bool SnapshotIsCanonical(const ThreadGroupSnapshot& snapshot)
{
    if (!ThreadGroupMemberIdentityIsValid(snapshot.leader) || snapshot.member_count > kThreadGroupMemberCapacity)
    {
        return false;
    }
    for (u32 index = 0; index < snapshot.member_count; ++index)
    {
        if (!ThreadGroupMemberIdentityIsValid(snapshot.members[index]) ||
            (index != 0 && snapshot.members[index - 1].opaque >= snapshot.members[index].opaque))
        {
            return false;
        }
    }
    for (u32 index = snapshot.member_count; index < kThreadGroupMemberCapacity; ++index)
    {
        if (ThreadGroupMemberIdentityIsValid(snapshot.members[index]))
        {
            return false;
        }
    }
    return true;
}

bool Contains(const ThreadGroupSnapshot& snapshot, ThreadGroupMemberIdentity member)
{
    for (u32 index = 0; index < snapshot.member_count; ++index)
    {
        if (snapshot.members[index] == member)
        {
            return true;
        }
    }
    return false;
}

void RetireGroup(ThreadGroupKey& key)
{
    const ThreadGroupMutationResult exit_result = ThreadGroupBeginExit(key);
    EXPECT_TRUE(exit_result == ThreadGroupMutationResult::Applied ||
                exit_result == ThreadGroupMutationResult::AlreadySatisfied);
    const ThreadGroupSnapshot snapshot = Inspect(key);
    for (u32 index = 0; index < snapshot.member_count; ++index)
    {
        EXPECT_EQ(ThreadGroupAuthorityDetachMember(key, snapshot.members[index]), ThreadGroupMutationResult::Applied);
    }
    EXPECT_TRUE(ThreadGroupRelease(&key));
    EXPECT_TRUE(key == kInvalidThreadGroupKey);
}

} // namespace

int main()
{
    EXPECT_FALSE(ThreadGroupKeyIsValid(kInvalidThreadGroupKey));
    EXPECT_FALSE(ThreadGroupKeyIsValid(ThreadGroupKey{0, 0}));
    EXPECT_TRUE(ThreadGroupKeyIsValid(ThreadGroupKey{0, 1}));
    EXPECT_FALSE(ThreadGroupMemberIdentityIsValid(kInvalidThreadGroupMemberIdentity));
    EXPECT_TRUE(ThreadGroupMemberIdentityIsValid(Member(1)));

    ThreadGroupKey refused{0, 1};
    EXPECT_FALSE(ThreadGroupAuthorityCreate(kInvalidThreadGroupMemberIdentity, &refused));
    EXPECT_TRUE(refused == kInvalidThreadGroupKey);
    EXPECT_FALSE(ThreadGroupAuthorityCreate(Member(1), nullptr));

    // Creation publishes one exact leader member and one owner. Snapshots are
    // copies: mutating one cannot mutate the service row.
    const ThreadGroupMemberIdentity leader = Member(300);
    ThreadGroupKey group = kInvalidThreadGroupKey;
    EXPECT_TRUE(ThreadGroupAuthorityCreate(leader, &group));
    ThreadGroupSnapshot snapshot = Inspect(group);
    EXPECT_EQ(snapshot.state, ThreadGroupState::Open);
    EXPECT_EQ(snapshot.owner_references, 1U);
    EXPECT_TRUE(snapshot.leader == leader);
    EXPECT_EQ(snapshot.member_count, 1U);
    EXPECT_TRUE(snapshot.members[0] == leader);
    EXPECT_TRUE(SnapshotIsCanonical(snapshot));
    snapshot.members[0] = Member(999999);
    EXPECT_TRUE(Inspect(group).members[0] == leader);

    // Storage remains canonical regardless of attach order. Exact duplicates,
    // malformed identities, and premature final release are rejected.
    EXPECT_TRUE(ThreadGroupAuthorityAttachMember(group, Member(500)));
    EXPECT_TRUE(ThreadGroupAuthorityAttachMember(group, Member(100)));
    EXPECT_TRUE(ThreadGroupAuthorityAttachMember(group, Member(400)));
    EXPECT_FALSE(ThreadGroupAuthorityAttachMember(group, Member(400)));
    EXPECT_FALSE(ThreadGroupAuthorityAttachMember(group, kInvalidThreadGroupMemberIdentity));
    snapshot = Inspect(group);
    EXPECT_TRUE(SnapshotIsCanonical(snapshot));
    EXPECT_EQ(snapshot.member_count, 4U);
    EXPECT_EQ(snapshot.members[0].opaque, 100ULL);
    EXPECT_EQ(snapshot.members[1].opaque, 300ULL);
    EXPECT_EQ(snapshot.members[2].opaque, 400ULL);
    EXPECT_EQ(snapshot.members[3].opaque, 500ULL);

    EXPECT_EQ(ThreadGroupAuthorityDetachMember(group, Member(250)), ThreadGroupMutationResult::AlreadySatisfied);
    EXPECT_EQ(ThreadGroupAuthorityDetachMember(group, Member(400)), ThreadGroupMutationResult::Applied);
    EXPECT_EQ(ThreadGroupAuthorityDetachMember(group, Member(400)), ThreadGroupMutationResult::AlreadySatisfied);
    EXPECT_EQ(ThreadGroupAuthorityDetachMember(group, kInvalidThreadGroupMemberIdentity),
              ThreadGroupMutationResult::Rejected);

    EXPECT_TRUE(ThreadGroupRetain(group));
    ThreadGroupKey second_owner = group;
    EXPECT_EQ(Inspect(group).owner_references, 2U);
    EXPECT_TRUE(ThreadGroupRelease(&second_owner));
    EXPECT_TRUE(second_owner == kInvalidThreadGroupKey);
    EXPECT_EQ(Inspect(group).owner_references, 1U);
    EXPECT_FALSE(ThreadGroupRelease(&group));
    EXPECT_TRUE(ThreadGroupKeyIsValid(group));

    EXPECT_EQ(ThreadGroupBeginExit(group), ThreadGroupMutationResult::Applied);
    EXPECT_EQ(ThreadGroupBeginExit(group), ThreadGroupMutationResult::AlreadySatisfied);
    EXPECT_FALSE(ThreadGroupAuthorityAttachMember(group, Member(700)));
    EXPECT_FALSE(ThreadGroupRelease(&group));
    snapshot = Inspect(group);
    for (u32 index = 0; index < snapshot.member_count; ++index)
    {
        EXPECT_EQ(ThreadGroupAuthorityDetachMember(group, snapshot.members[index]), ThreadGroupMutationResult::Applied);
        EXPECT_EQ(ThreadGroupAuthorityDetachMember(group, snapshot.members[index]),
                  ThreadGroupMutationResult::AlreadySatisfied);
    }
    const ThreadGroupKey retired_exact = group;
    EXPECT_TRUE(ThreadGroupRelease(&group));
    snapshot = Inspect(retired_exact);
    EXPECT_EQ(snapshot.state, ThreadGroupState::Retired);
    EXPECT_EQ(snapshot.owner_references, 0U);
    EXPECT_EQ(snapshot.member_count, 0U);
    EXPECT_TRUE(snapshot.leader == leader);
    EXPECT_FALSE(ThreadGroupRetain(retired_exact));
    EXPECT_EQ(ThreadGroupBeginExit(retired_exact), ThreadGroupMutationResult::Rejected);

    // Owner references saturate instead of wrapping an active row to zero.
    constexpr u32 kOwnerReferenceMaximum = static_cast<u32>(~0U);
    ThreadGroupKey saturated = kInvalidThreadGroupKey;
    EXPECT_TRUE(ThreadGroupAuthorityCreate(Member(800), &saturated));
    EXPECT_TRUE(HostSetActiveThreadGroupOwnerReferences(saturated, kOwnerReferenceMaximum - 1U));
    EXPECT_TRUE(ThreadGroupRetain(saturated));
    EXPECT_EQ(Inspect(saturated).owner_references, kOwnerReferenceMaximum);
    EXPECT_FALSE(ThreadGroupRetain(saturated));
    EXPECT_EQ(Inspect(saturated).owner_references, kOwnerReferenceMaximum);
    EXPECT_TRUE(HostSetActiveThreadGroupOwnerReferences(saturated, 1));
    RetireGroup(saturated);

    // A group can hold exactly 64 identities including its leader.
    ThreadGroupKey member_full = kInvalidThreadGroupKey;
    EXPECT_TRUE(ThreadGroupAuthorityCreate(Member(1000), &member_full));
    for (u64 identity = 1; identity < kThreadGroupMemberCapacity; ++identity)
    {
        EXPECT_TRUE(ThreadGroupAuthorityAttachMember(member_full, Member(identity)));
    }
    snapshot = Inspect(member_full);
    EXPECT_EQ(snapshot.member_count, kThreadGroupMemberCapacity);
    EXPECT_TRUE(SnapshotIsCanonical(snapshot));
    EXPECT_FALSE(ThreadGroupAuthorityAttachMember(member_full, Member(2000)));
    RetireGroup(member_full);

    // The fixed pool publishes exactly 64 simultaneous groups and fails
    // transactionally at capacity.
    std::array<ThreadGroupKey, kThreadGroupCapacity> full{};
    for (u32 index = 0; index < kThreadGroupCapacity; ++index)
    {
        EXPECT_TRUE(ThreadGroupAuthorityCreate(Member(10000U + index), &full[index]));
    }
    ThreadGroupKey overflow{0, 1};
    EXPECT_FALSE(ThreadGroupAuthorityCreate(Member(20000), &overflow));
    EXPECT_TRUE(overflow == kInvalidThreadGroupKey);
    for (ThreadGroupKey& key : full)
    {
        RetireGroup(key);
    }

    // Ten thousand complete cycles exercise create, attach, duplicate reject,
    // idempotent detach/exit, empty-before-final-release, and owner leak checks.
    constexpr u32 kLifecycleCycles = 10000;
    for (u32 cycle = 0; cycle < kLifecycleCycles; ++cycle)
    {
        const u64 identity_base = 0x100000ULL + static_cast<u64>(cycle) * 2ULL;
        ThreadGroupKey cycle_group = kInvalidThreadGroupKey;
        EXPECT_TRUE(ThreadGroupAuthorityCreate(Member(identity_base), &cycle_group));
        EXPECT_TRUE(ThreadGroupAuthorityAttachMember(cycle_group, Member(identity_base + 1U)));
        EXPECT_FALSE(ThreadGroupAuthorityAttachMember(cycle_group, Member(identity_base + 1U)));
        EXPECT_EQ(ThreadGroupAuthorityDetachMember(cycle_group, Member(identity_base + 1U)),
                  ThreadGroupMutationResult::Applied);
        EXPECT_EQ(ThreadGroupAuthorityDetachMember(cycle_group, Member(identity_base + 1U)),
                  ThreadGroupMutationResult::AlreadySatisfied);
        EXPECT_EQ(ThreadGroupBeginExit(cycle_group), ThreadGroupMutationResult::Applied);
        EXPECT_EQ(ThreadGroupBeginExit(cycle_group), ThreadGroupMutationResult::AlreadySatisfied);
        EXPECT_EQ(ThreadGroupAuthorityDetachMember(cycle_group, Member(identity_base)),
                  ThreadGroupMutationResult::Applied);
        const ThreadGroupKey exact = cycle_group;
        EXPECT_TRUE(ThreadGroupRelease(&cycle_group));
        const ThreadGroupSnapshot retired = Inspect(exact);
        EXPECT_EQ(retired.state, ThreadGroupState::Retired);
        EXPECT_EQ(retired.owner_references, 0U);
        EXPECT_EQ(retired.member_count, 0U);
    }

    // Reuse changes the generation. A copied key from the old incarnation is
    // rejected by every mutating and observing operation.
    ThreadGroupKey old_group = kInvalidThreadGroupKey;
    EXPECT_TRUE(ThreadGroupAuthorityCreate(Member(0x300000), &old_group));
    const ThreadGroupKey stale = old_group;
    RetireGroup(old_group);
    ThreadGroupKey replacement = kInvalidThreadGroupKey;
    EXPECT_TRUE(ThreadGroupAuthorityCreate(Member(0x300001), &replacement));
    EXPECT_EQ(replacement.slot, stale.slot);
    EXPECT_TRUE(replacement.generation > stale.generation);
    EXPECT_FALSE(ThreadGroupRetain(stale));
    EXPECT_FALSE(ThreadGroupAuthorityAttachMember(stale, Member(0x300002)));
    EXPECT_EQ(ThreadGroupAuthorityDetachMember(stale, Member(0x300000)), ThreadGroupMutationResult::Rejected);
    EXPECT_EQ(ThreadGroupBeginExit(stale), ThreadGroupMutationResult::Rejected);
    ThreadGroupSnapshot cleared{ThreadGroupState::Open, 77, Member(77), 1, {Member(77)}};
    EXPECT_FALSE(ThreadGroupInspectExact(stale, &cleared));
    EXPECT_EQ(cleared.owner_references, 0U);
    ThreadGroupKey stale_release = stale;
    EXPECT_FALSE(ThreadGroupRelease(&stale_release));
    EXPECT_TRUE(stale_release == stale);
    RetireGroup(replacement);

    // Concurrent owners take snapshots and attach/detach disjoint exact Task
    // incarnations. The root owner and leader remain exact after all churn.
    ThreadGroupKey concurrent = kInvalidThreadGroupKey;
    const ThreadGroupMemberIdentity concurrent_leader = Member(0x400000);
    EXPECT_TRUE(ThreadGroupAuthorityCreate(concurrent_leader, &concurrent));
    constexpr u32 kThreadCount = 8;
    constexpr u32 kConcurrentIterations = 2000;
    std::barrier<> concurrent_start(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::atomic<u32> errors{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);
    for (u32 thread_index = 0; thread_index < kThreadCount; ++thread_index)
    {
        threads.emplace_back(
            [&, thread_index]()
            {
                const ThreadGroupMemberIdentity member = Member(0x410000ULL + thread_index);
                concurrent_start.arrive_and_wait();
                for (u32 iteration = 0; iteration < kConcurrentIterations; ++iteration)
                {
                    if (!ThreadGroupRetain(concurrent))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    ThreadGroupKey owner = concurrent;
                    if (!ThreadGroupAuthorityAttachMember(concurrent, member))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                    ThreadGroupSnapshot local{};
                    if (!ThreadGroupInspectExact(concurrent, &local) || !SnapshotIsCanonical(local) ||
                        !Contains(local, concurrent_leader) || !Contains(local, member))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (ThreadGroupAuthorityDetachMember(concurrent, member) != ThreadGroupMutationResult::Applied)
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                    if (!ThreadGroupRelease(&owner) || !(owner == kInvalidThreadGroupKey))
                    {
                        errors.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            });
    }
    concurrent_start.arrive_and_wait();
    for (std::thread& thread : threads)
    {
        thread.join();
    }
    threads.clear();
    EXPECT_EQ(errors.load(std::memory_order_relaxed), 0U);
    snapshot = Inspect(concurrent);
    EXPECT_EQ(snapshot.owner_references, 1U);
    EXPECT_EQ(snapshot.member_count, 1U);
    EXPECT_TRUE(snapshot.members[0] == concurrent_leader);
    RetireGroup(concurrent);

    // Exit racing attach is linearizable: attach either publishes before the
    // Open -> Exiting transition or is rejected after it. No third state is
    // accepted and cleanup always retires with zero owners/members.
    constexpr u32 kExitRaceCycles = 256;
    for (u32 cycle = 0; cycle < kExitRaceCycles; ++cycle)
    {
        const u64 identity_base = 0x500000ULL + static_cast<u64>(cycle) * 2ULL;
        const ThreadGroupMemberIdentity race_leader = Member(identity_base);
        const ThreadGroupMemberIdentity race_member = Member(identity_base + 1U);
        ThreadGroupKey race_group = kInvalidThreadGroupKey;
        EXPECT_TRUE(ThreadGroupAuthorityCreate(race_leader, &race_group));

        std::barrier<> race_start(3);
        std::atomic<bool> attached{false};
        std::thread attacher(
            [&]()
            {
                race_start.arrive_and_wait();
                attached.store(ThreadGroupAuthorityAttachMember(race_group, race_member), std::memory_order_relaxed);
            });
        std::thread exiter(
            [&]()
            {
                race_start.arrive_and_wait();
                if (ThreadGroupBeginExit(race_group) != ThreadGroupMutationResult::Applied)
                {
                    errors.fetch_add(1, std::memory_order_relaxed);
                }
            });
        race_start.arrive_and_wait();
        attacher.join();
        exiter.join();

        snapshot = Inspect(race_group);
        EXPECT_EQ(snapshot.state, ThreadGroupState::Exiting);
        EXPECT_TRUE(Contains(snapshot, race_leader));
        EXPECT_EQ(Contains(snapshot, race_member), attached.load(std::memory_order_relaxed));
        const ThreadGroupMutationResult member_detach = ThreadGroupAuthorityDetachMember(race_group, race_member);
        EXPECT_EQ(member_detach, attached.load(std::memory_order_relaxed)
                                     ? ThreadGroupMutationResult::Applied
                                     : ThreadGroupMutationResult::AlreadySatisfied);
        EXPECT_EQ(ThreadGroupAuthorityDetachMember(race_group, race_leader), ThreadGroupMutationResult::Applied);
        const ThreadGroupKey exact = race_group;
        EXPECT_TRUE(ThreadGroupRelease(&race_group));
        snapshot = Inspect(exact);
        EXPECT_EQ(snapshot.state, ThreadGroupState::Retired);
        EXPECT_EQ(snapshot.owner_references, 0U);
        EXPECT_EQ(snapshot.member_count, 0U);
    }
    EXPECT_EQ(errors.load(std::memory_order_relaxed), 0U);

    // Retain racing the final release has exactly two legal linearizations:
    // either retain pins the Exiting row first and becomes its final owner, or
    // release retires the row first and retain rejects the exact old key. In
    // neither case can the row reach zero owners while remaining active.
    constexpr u32 kReleaseRetainRaceCycles = 512;
    for (u32 cycle = 0; cycle < kReleaseRetainRaceCycles; ++cycle)
    {
        const ThreadGroupMemberIdentity race_leader = Member(0x600000ULL + cycle);
        ThreadGroupKey race_group = kInvalidThreadGroupKey;
        EXPECT_TRUE(ThreadGroupAuthorityCreate(race_leader, &race_group));
        EXPECT_EQ(ThreadGroupBeginExit(race_group), ThreadGroupMutationResult::Applied);
        EXPECT_EQ(ThreadGroupAuthorityDetachMember(race_group, race_leader), ThreadGroupMutationResult::Applied);

        const ThreadGroupKey exact = race_group;
        ThreadGroupKey releasing_owner = race_group;
        std::barrier<> race_start(3);
        std::atomic<bool> released{false};
        std::atomic<bool> retained{false};
        std::thread releaser(
            [&]()
            {
                race_start.arrive_and_wait();
                released.store(ThreadGroupRelease(&releasing_owner), std::memory_order_relaxed);
            });
        std::thread retainer(
            [&]()
            {
                race_start.arrive_and_wait();
                retained.store(ThreadGroupRetain(exact), std::memory_order_relaxed);
            });
        race_start.arrive_and_wait();
        releaser.join();
        retainer.join();

        EXPECT_TRUE(released.load(std::memory_order_relaxed));
        EXPECT_TRUE(releasing_owner == kInvalidThreadGroupKey);
        if (retained.load(std::memory_order_relaxed))
        {
            snapshot = Inspect(exact);
            EXPECT_EQ(snapshot.state, ThreadGroupState::Exiting);
            EXPECT_EQ(snapshot.owner_references, 1U);
            EXPECT_EQ(snapshot.member_count, 0U);
            ThreadGroupKey retained_owner = exact;
            EXPECT_TRUE(ThreadGroupRelease(&retained_owner));
            EXPECT_TRUE(retained_owner == kInvalidThreadGroupKey);
        }
        snapshot = Inspect(exact);
        EXPECT_EQ(snapshot.state, ThreadGroupState::Retired);
        EXPECT_EQ(snapshot.owner_references, 0U);
        EXPECT_EQ(snapshot.member_count, 0U);
        EXPECT_FALSE(ThreadGroupRetain(exact));
    }

    // A terminal generation receives one final lifetime and can never be
    // allocated again; another row remains independently available.
    EXPECT_TRUE(ThreadGroupKeyIsValid(ThreadGroupKey{0, kThreadGroupGenerationMaximum}));
    EXPECT_FALSE(ThreadGroupKeyIsValid(ThreadGroupKey{0, kThreadGroupGenerationMaximum + 1U}));
    EXPECT_TRUE(HostSetRetiredThreadGroupGeneration(0, kThreadGroupGenerationMaximum - 1U));
    EXPECT_FALSE(HostSetRetiredThreadGroupGeneration(0, 1));
    ThreadGroupKey terminal = kInvalidThreadGroupKey;
    EXPECT_TRUE(ThreadGroupAuthorityCreate(Member(0x700000), &terminal));
    EXPECT_EQ(terminal.slot, 0U);
    EXPECT_EQ(terminal.generation, kThreadGroupGenerationMaximum);
    const ThreadGroupKey terminal_exact = terminal;
    RetireGroup(terminal);
    EXPECT_EQ(Inspect(terminal_exact).state, ThreadGroupState::Retired);
    EXPECT_FALSE(ThreadGroupRetain(terminal_exact));

    ThreadGroupKey after_terminal = kInvalidThreadGroupKey;
    EXPECT_TRUE(ThreadGroupAuthorityCreate(Member(0x700001), &after_terminal));
    EXPECT_NE(after_terminal.slot, terminal_exact.slot);
    RetireGroup(after_terminal);

    return duetos_host_test::finish_main("test_thread_group");
}
