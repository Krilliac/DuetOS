// Hosted state-machine and concurrency coverage for
// drivers/video/gui_message_queue.cpp.
//
// Include the production TU directly so this test exercises the exact fixed
// registry, mutation-epoch, claim, purge, and reap implementation. The host
// SpinLock shim below preserves distinct lock identities and real parallel
// exclusion, which makes the concurrent section useful under ThreadSanitizer.
// White-box helpers are limited to observing slot selection and positioning an
// already-inactive slot one step before terminal epoch saturation.

#include "host_test_helper.h"
#include "drivers/video/gui_message_queue.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <cstdlib>
#include <thread>
#include <vector>

#include "drivers/video/gui_message_queue.cpp"

namespace
{

constexpr duetos::u32 kHostHeldLockCapacity = 8;
thread_local std::array<const duetos::sync::SpinLock*, kHostHeldLockCapacity> g_host_held_locks{};
thread_local duetos::u32 g_host_held_lock_count = 0;

bool HostLockIsHeld(const duetos::sync::SpinLock& lock)
{
    for (duetos::u32 index = 0; index < g_host_held_lock_count; ++index)
    {
        if (g_host_held_locks[index] == &lock)
        {
            return true;
        }
    }
    return false;
}

} // namespace

namespace duetos::sync
{

IrqFlags SpinLockAcquire(SpinLock& lock)
{
    if (g_host_held_lock_count >= kHostHeldLockCapacity || HostLockIsHeld(lock))
    {
        std::abort();
    }

    u32& next_word = const_cast<u32&>(lock.next_ticket);
    u32& serving_word = const_cast<u32&>(lock.now_serving);
    std::atomic_ref<u32> next(next_word);
    std::atomic_ref<u32> serving(serving_word);
    const u32 ticket = next.fetch_add(1, std::memory_order_relaxed);
    while (serving.load(std::memory_order_acquire) != ticket)
    {
        std::this_thread::yield();
    }
    g_host_held_locks[g_host_held_lock_count++] = &lock;
    return IrqFlags{0};
}

void SpinLockRelease(SpinLock& lock, IrqFlags)
{
    if (g_host_held_lock_count == 0 || g_host_held_locks[g_host_held_lock_count - 1] != &lock)
    {
        std::abort();
    }
    g_host_held_locks[--g_host_held_lock_count] = nullptr;

    u32& serving_word = const_cast<u32&>(lock.now_serving);
    std::atomic_ref<u32> serving(serving_word);
    (void)serving.fetch_add(1, std::memory_order_release);
}

void SpinLockAssertHeld(const SpinLock& lock)
{
    if (!HostLockIsHeld(lock))
    {
        std::abort();
    }
}

} // namespace duetos::sync

namespace duetos::arch
{

void SerialWrite(const char*) {}

} // namespace duetos::arch

namespace duetos::debug
{

void ProbeFire(ProbeId, u64, u64) {}

} // namespace duetos::debug

namespace duetos::drivers::video
{

bool HostPrepareInactiveQueueForTerminalEpoch(u32 slot)
{
    if (slot >= kGuiTaskQueueCapacity)
    {
        return false;
    }
    sync::SpinLockGuard registry_guard(g_queue_registry_lock);
    TaskMessageQueue& queue = g_task_queues[slot];
    sync::SpinLockGuard queue_guard(queue.lock);
    if (queue.active || queue.retired || queue.count != 0)
    {
        return false;
    }
    queue.epoch = kMaxQueueEpoch - 1;
    return true;
}

u32 HostQueueSlotFor(u64 pid, u64 tid)
{
    sync::SpinLockGuard registry_guard(g_queue_registry_lock);
    return FindQueueLocked(pid, tid);
}

bool HostQueueSlotRetired(u32 slot)
{
    if (slot >= kGuiTaskQueueCapacity)
    {
        return false;
    }
    sync::SpinLockGuard registry_guard(g_queue_registry_lock);
    TaskMessageQueue& queue = g_task_queues[slot];
    sync::SpinLockGuard queue_guard(queue.lock);
    return !queue.active && queue.retired;
}

} // namespace duetos::drivers::video

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::drivers::video;

struct Probe
{
    GuiMessageClaim claim{};
    GuiMessageProbeToken token{};
    GuiMessageProbeResult result{GuiMessageProbeResult::Gone};
};

Probe ProbeQueue(u64 pid, u64 tid, u32 filter = 0)
{
    Probe probe{};
    probe.result = GuiMessageProbeQueue(pid, tid, filter, &probe.claim, &probe.token);
    return probe;
}

WindowMsg Message(u32 hwnd, u32 sequence, u64 lane = 0)
{
    return WindowMsg{hwnd, 0x400u + sequence, sequence, lane};
}

void ExpectMessage(const GuiMessageClaim& claim, u32 hwnd, u32 sequence, u64 lane = 0)
{
    EXPECT_TRUE(claim.valid);
    EXPECT_EQ(claim.message.hwnd, hwnd);
    EXPECT_EQ(claim.message.message, 0x400u + sequence);
    EXPECT_EQ(claim.message.wparam, static_cast<u64>(sequence));
    EXPECT_EQ(claim.message.lparam, lane);
}

void DrainExact(u64 pid, u64 tid, u32 first_sequence, u32 count, u32 hwnd)
{
    for (u32 offset = 0; offset < count; ++offset)
    {
        GuiMessageClaim claim{};
        EXPECT_TRUE(GuiMessageSnapshot(pid, tid, 0, &claim));
        ExpectMessage(claim, hwnd, first_sequence + offset);
        EXPECT_TRUE(GuiMessageCommit(claim, true));
    }
    EXPECT_EQ(ProbeQueue(pid, tid).result, GuiMessageProbeResult::Empty);
}

} // namespace

int main()
{
    constexpr u64 kPid = 0x71000001u;
    constexpr u32 kHwndA = 0x101u;
    constexpr u32 kHwndB = 0x102u;

    // Malformed probes fail closed and clear every output they can reach.
    // This prevents a caller from accidentally treating a retained claim or
    // wait token as authoritative after an invalid request.
    GuiMessageClaim poisoned_claim{};
    poisoned_claim.message = Message(kHwndA, 0xFFu);
    poisoned_claim.owner_pid = kPid;
    poisoned_claim.owner_tid = 0xFFFFFFFFu;
    poisoned_claim.head_ticket = 1;
    poisoned_claim.message_ticket = 2;
    poisoned_claim.queue_epoch = 3;
    poisoned_claim.queue_slot = 4;
    poisoned_claim.valid = true;
    GuiMessageProbeToken poisoned_token{{5, 6}};
    EXPECT_EQ(GuiMessageProbeQueue(0, 1, 0, &poisoned_claim, &poisoned_token), GuiMessageProbeResult::Gone);
    EXPECT_FALSE(poisoned_claim.valid);
    EXPECT_EQ(poisoned_claim.owner_pid, 0ULL);
    EXPECT_EQ(poisoned_claim.owner_tid, 0ULL);
    EXPECT_EQ(poisoned_claim.head_ticket, 0ULL);
    EXPECT_EQ(poisoned_claim.message_ticket, 0ULL);
    EXPECT_EQ(poisoned_claim.queue_epoch, 0ULL);
    EXPECT_EQ(poisoned_claim.queue_slot, 0u);
    EXPECT_EQ(poisoned_token.opaque[0], 0ULL);
    EXPECT_EQ(poisoned_token.opaque[1], 0ULL);

    GuiMessageProbeToken one_sided_token{{7, 8}};
    EXPECT_EQ(GuiMessageProbeQueue(kPid, 1, 0, nullptr, &one_sided_token), GuiMessageProbeResult::Gone);
    EXPECT_EQ(one_sided_token.opaque[0], 0ULL);
    EXPECT_EQ(one_sided_token.opaque[1], 0ULL);

    GuiMessageClaim one_sided_claim{};
    one_sided_claim.valid = true;
    one_sided_claim.queue_epoch = 9;
    EXPECT_EQ(GuiMessageProbeQueue(kPid, 1, 0, &one_sided_claim, nullptr), GuiMessageProbeResult::Gone);
    EXPECT_FALSE(one_sided_claim.valid);
    EXPECT_EQ(one_sided_claim.queue_epoch, 0ULL);

    // A missing identity is Gone. Establishing it produces Empty, and a post
    // produces Message while invalidating the prior empty-state token.
    constexpr u64 kStateTid = 0x71001001u;
    Probe probe = ProbeQueue(kPid, kStateTid);
    EXPECT_EQ(probe.result, GuiMessageProbeResult::Gone);
    EXPECT_FALSE(probe.claim.valid);
    EXPECT_EQ(probe.token.opaque[0], 0ULL);
    EXPECT_EQ(probe.token.opaque[1], 0ULL);
    EXPECT_TRUE(GuiMessageEnsureQueue(kPid, kStateTid));
    Probe empty = ProbeQueue(kPid, kStateTid);
    EXPECT_EQ(empty.result, GuiMessageProbeResult::Empty);
    EXPECT_TRUE(GuiMessageProbeTokenCurrent(kPid, kStateTid, empty.token));
    EXPECT_TRUE(GuiMessagePost(kPid, kStateTid, Message(kHwndA, 1)));
    EXPECT_FALSE(GuiMessageProbeTokenCurrent(kPid, kStateTid, empty.token));
    probe = ProbeQueue(kPid, kStateTid);
    EXPECT_EQ(probe.result, GuiMessageProbeResult::Message);
    ExpectMessage(probe.claim, kHwndA, 1);
    EXPECT_TRUE(GuiMessageCommit(probe.claim, true));
    EXPECT_EQ(ProbeQueue(kPid, kStateTid).result, GuiMessageProbeResult::Empty);
    EXPECT_EQ(GuiMessageReapTask(kPid, kStateTid), 0u);
    EXPECT_EQ(ProbeQueue(kPid, kStateTid).result, GuiMessageProbeResult::Gone);

    // Two task queues in one process retain independent FIFO state.
    constexpr u64 kIndependentTidA = 0x71002001u;
    constexpr u64 kIndependentTidB = 0x71002002u;
    EXPECT_TRUE(GuiMessageEnsureQueue(kPid, kIndependentTidA));
    EXPECT_TRUE(GuiMessageEnsureQueue(kPid, kIndependentTidB));
    EXPECT_TRUE(GuiMessagePost(kPid, kIndependentTidA, Message(kHwndA, 10, kIndependentTidA)));
    EXPECT_TRUE(GuiMessagePost(kPid, kIndependentTidB, Message(kHwndB, 20, kIndependentTidB)));
    Probe task_a = ProbeQueue(kPid, kIndependentTidA);
    Probe task_b = ProbeQueue(kPid, kIndependentTidB);
    EXPECT_EQ(task_a.result, GuiMessageProbeResult::Message);
    EXPECT_EQ(task_b.result, GuiMessageProbeResult::Message);
    ExpectMessage(task_a.claim, kHwndA, 10, kIndependentTidA);
    ExpectMessage(task_b.claim, kHwndB, 20, kIndependentTidB);
    EXPECT_TRUE(GuiMessageCommit(task_a.claim, true));
    EXPECT_EQ(ProbeQueue(kPid, kIndependentTidA).result, GuiMessageProbeResult::Empty);
    EXPECT_EQ(ProbeQueue(kPid, kIndependentTidB).result, GuiMessageProbeResult::Message);
    EXPECT_TRUE(GuiMessageCommit(task_b.claim, true));
    EXPECT_EQ(GuiMessageReapTask(kPid, kIndependentTidA), 0u);
    EXPECT_EQ(GuiMessageReapTask(kPid, kIndependentTidB), 0u);

    // A full queue refuses the extra post without mutation or eviction. The
    // original head token remains current and all 64 entries drain in order.
    constexpr u64 kFullTid = 0x71003001u;
    EXPECT_TRUE(GuiMessageEnsureQueue(kPid, kFullTid));
    for (u32 sequence = 0; sequence < kGuiTaskQueueDepth; ++sequence)
    {
        EXPECT_TRUE(GuiMessagePost(kPid, kFullTid, Message(kHwndA, 100 + sequence)));
    }
    Probe full_head = ProbeQueue(kPid, kFullTid);
    EXPECT_EQ(full_head.result, GuiMessageProbeResult::Message);
    EXPECT_FALSE(GuiMessagePost(kPid, kFullTid, Message(kHwndA, 999)));
    EXPECT_TRUE(GuiMessageProbeTokenCurrent(kPid, kFullTid, full_head.token));
    DrainExact(kPid, kFullTid, 100, kGuiTaskQueueDepth, kHwndA);
    EXPECT_EQ(GuiMessageReapTask(kPid, kFullTid), 0u);

    // Filtered claims remove only the selected ticket. Abandoning a claim
    // models failed CopyToUser; a peer commit then makes that claim stale.
    constexpr u64 kFilteredTid = 0x71004001u;
    EXPECT_TRUE(GuiMessageEnsureQueue(kPid, kFilteredTid));
    EXPECT_TRUE(GuiMessagePost(kPid, kFilteredTid, Message(kHwndA, 1)));
    EXPECT_TRUE(GuiMessagePost(kPid, kFilteredTid, Message(kHwndB, 2)));
    EXPECT_TRUE(GuiMessagePost(kPid, kFilteredTid, Message(kHwndA, 3)));
    EXPECT_TRUE(GuiMessagePost(kPid, kFilteredTid, Message(kHwndB, 4)));
    Probe abandoned = ProbeQueue(kPid, kFilteredTid, kHwndB);
    Probe peer = ProbeQueue(kPid, kFilteredTid, kHwndB);
    EXPECT_EQ(abandoned.result, GuiMessageProbeResult::Message);
    EXPECT_EQ(peer.result, GuiMessageProbeResult::Message);
    EXPECT_EQ(abandoned.claim.message_ticket, peer.claim.message_ticket);
    ExpectMessage(abandoned.claim, kHwndB, 2);
    EXPECT_TRUE(GuiMessageCommit(peer.claim, true));
    EXPECT_FALSE(GuiMessageCommit(abandoned.claim, true));
    Probe head = ProbeQueue(kPid, kFilteredTid);
    ExpectMessage(head.claim, kHwndA, 1);
    EXPECT_TRUE(GuiMessageCommit(head.claim, true));
    Probe later_b = ProbeQueue(kPid, kFilteredTid, kHwndB);
    ExpectMessage(later_b.claim, kHwndB, 4);
    EXPECT_TRUE(GuiMessageCommit(later_b.claim, true));
    Probe remaining = ProbeQueue(kPid, kFilteredTid);
    ExpectMessage(remaining.claim, kHwndA, 3);
    EXPECT_TRUE(GuiMessageCommit(remaining.claim, true));

    // Even a zero-match purge is an observable HWND-invalidated mutation.
    Probe before_zero_purge = ProbeQueue(kPid, kFilteredTid);
    EXPECT_EQ(before_zero_purge.result, GuiMessageProbeResult::Empty);
    EXPECT_TRUE(GuiMessageProbeTokenCurrent(kPid, kFilteredTid, before_zero_purge.token));
    EXPECT_EQ(GuiMessagePurgeWindow(kPid, kFilteredTid, 0x1FFu), 0u);
    EXPECT_FALSE(GuiMessageProbeTokenCurrent(kPid, kFilteredTid, before_zero_purge.token));
    EXPECT_EQ(ProbeQueue(kPid, kFilteredTid).result, GuiMessageProbeResult::Empty);
    EXPECT_EQ(GuiMessageReapTask(kPid, kFilteredTid), 0u);

    // Empty reap is still Empty -> Gone. Process reap drains every nonempty
    // sibling queue, and late posting cannot recreate either task identity.
    constexpr u64 kEmptyReapTid = 0x71005001u;
    EXPECT_TRUE(GuiMessageEnsureQueue(kPid, kEmptyReapTid));
    Probe before_empty_reap = ProbeQueue(kPid, kEmptyReapTid);
    EXPECT_EQ(before_empty_reap.result, GuiMessageProbeResult::Empty);
    EXPECT_EQ(GuiMessageReapTask(kPid, kEmptyReapTid), 0u);
    EXPECT_EQ(ProbeQueue(kPid, kEmptyReapTid).result, GuiMessageProbeResult::Gone);
    EXPECT_FALSE(GuiMessageProbeTokenCurrent(kPid, kEmptyReapTid, before_empty_reap.token));
    EXPECT_FALSE(GuiMessagePost(kPid, kEmptyReapTid, Message(kHwndA, 1)));

    constexpr u64 kProcessReapTidA = 0x71005002u;
    constexpr u64 kProcessReapTidB = 0x71005003u;
    EXPECT_TRUE(GuiMessageEnsureQueue(kPid, kProcessReapTidA));
    EXPECT_TRUE(GuiMessageEnsureQueue(kPid, kProcessReapTidB));
    EXPECT_TRUE(GuiMessagePost(kPid, kProcessReapTidA, Message(kHwndA, 1)));
    EXPECT_TRUE(GuiMessagePost(kPid, kProcessReapTidA, Message(kHwndA, 2)));
    EXPECT_TRUE(GuiMessagePost(kPid, kProcessReapTidB, Message(kHwndB, 3)));
    EXPECT_EQ(GuiMessageReapProcess(kPid), 3u);
    EXPECT_EQ(ProbeQueue(kPid, kProcessReapTidA).result, GuiMessageProbeResult::Gone);
    EXPECT_EQ(ProbeQueue(kPid, kProcessReapTidB).result, GuiMessageProbeResult::Gone);
    EXPECT_FALSE(GuiMessagePost(kPid, kProcessReapTidA, Message(kHwndA, 4)));
    EXPECT_FALSE(GuiMessagePost(kPid, kProcessReapTidB, Message(kHwndB, 5)));

    // Reuse the exact registry slot with a different identity. An old claim
    // cannot commit against the new queue even when slot and ring position
    // match, and the new message remains intact.
    constexpr u64 kAbaPidA = 0x72000001u;
    constexpr u64 kAbaTidA = 0x72001001u;
    constexpr u64 kAbaPidB = 0x72000002u;
    constexpr u64 kAbaTidB = 0x72001002u;
    EXPECT_TRUE(GuiMessageEnsureQueue(kAbaPidA, kAbaTidA));
    EXPECT_TRUE(GuiMessagePost(kAbaPidA, kAbaTidA, Message(kHwndA, 7)));
    Probe stale = ProbeQueue(kAbaPidA, kAbaTidA);
    EXPECT_EQ(stale.result, GuiMessageProbeResult::Message);
    const u32 reused_slot = stale.claim.queue_slot;
    EXPECT_EQ(GuiMessageReapTask(kAbaPidA, kAbaTidA), 1u);
    EXPECT_TRUE(GuiMessageEnsureQueue(kAbaPidB, kAbaTidB));
    EXPECT_TRUE(GuiMessagePost(kAbaPidB, kAbaTidB, Message(kHwndB, 8)));
    Probe replacement = ProbeQueue(kAbaPidB, kAbaTidB);
    EXPECT_EQ(replacement.result, GuiMessageProbeResult::Message);
    EXPECT_EQ(replacement.claim.queue_slot, reused_slot);
    EXPECT_FALSE(GuiMessageCommit(stale.claim, true));
    EXPECT_TRUE(GuiMessageCommit(replacement.claim, true));
    EXPECT_EQ(GuiMessageReapTask(kAbaPidB, kAbaTidB), 0u);

    // Put inactive slot zero one step before terminal epoch. Allocation may
    // issue UINT64_MAX once; the next mutation retires that slot rather than
    // wrapping. A later queue is allocated from a different slot.
    constexpr u64 kTerminalPid = 0x73000001u;
    constexpr u64 kTerminalTid = 0x73001001u;
    EXPECT_TRUE(HostPrepareInactiveQueueForTerminalEpoch(0));
    EXPECT_TRUE(GuiMessageEnsureQueue(kTerminalPid, kTerminalTid));
    EXPECT_EQ(HostQueueSlotFor(kTerminalPid, kTerminalTid), 0u);
    Probe terminal_empty = ProbeQueue(kTerminalPid, kTerminalTid);
    EXPECT_EQ(terminal_empty.result, GuiMessageProbeResult::Empty);
    EXPECT_FALSE(GuiMessagePost(kTerminalPid, kTerminalTid, Message(kHwndA, 1)));
    EXPECT_EQ(ProbeQueue(kTerminalPid, kTerminalTid).result, GuiMessageProbeResult::Gone);
    EXPECT_FALSE(GuiMessageProbeTokenCurrent(kTerminalPid, kTerminalTid, terminal_empty.token));
    EXPECT_TRUE(HostQueueSlotRetired(0));
    EXPECT_TRUE(GuiMessageEnsureQueue(kTerminalPid, kTerminalTid));
    EXPECT_NE(HostQueueSlotFor(kTerminalPid, kTerminalTid), 0u);
    EXPECT_EQ(GuiMessageReapTask(kTerminalPid, kTerminalTid), 0u);

    // Concurrent producer/consumer pairs run beside idempotent EnsureQueue
    // churn (the queue registry's retain-style lookup). Producers retry only
    // bounded-full refusal; consumers accept a message only after exact claim
    // commit, so every lane must finish with a deterministic 1..N sequence.
    constexpr u32 kConcurrentQueueCount = 4;
    constexpr u32 kConcurrentMessageCount = 1500;
    constexpr u32 kEnsureIterations = 6000;
    constexpr u64 kConcurrentPid = 0x74000001u;
    constexpr u64 kConcurrentTidBase = 0x74001000u;
    constexpr u32 kConcurrentHwndBase = 0x200u;
    constexpr u32 kWorkersPerQueue = 3;
    std::array<std::atomic<u32>, kConcurrentQueueCount> concurrent_errors{};
    std::array<std::atomic<u32>, kConcurrentQueueCount> consumed{};
    std::array<std::atomic<bool>, kConcurrentQueueCount> abort{};
    for (u32 lane = 0; lane < kConcurrentQueueCount; ++lane)
    {
        EXPECT_TRUE(GuiMessageEnsureQueue(kConcurrentPid, kConcurrentTidBase + lane));
    }

    std::barrier<> start(static_cast<std::ptrdiff_t>(kConcurrentQueueCount * kWorkersPerQueue + 1u));
    std::vector<std::thread> workers;
    workers.reserve(kConcurrentQueueCount * kWorkersPerQueue);
    for (u32 lane = 0; lane < kConcurrentQueueCount; ++lane)
    {
        const u64 tid = kConcurrentTidBase + lane;
        const u32 hwnd = kConcurrentHwndBase + lane;
        workers.emplace_back(
            [&, lane, tid, hwnd]()
            {
                start.arrive_and_wait();
                for (u32 sequence = 1; sequence <= kConcurrentMessageCount && !abort[lane].load(); ++sequence)
                {
                    u32 retries = 0;
                    while (!GuiMessagePost(kConcurrentPid, tid, Message(hwnd, sequence, lane)))
                    {
                        if (abort[lane].load() || ++retries == 10000000u)
                        {
                            concurrent_errors[lane].fetch_add(1);
                            abort[lane].store(true);
                            return;
                        }
                        std::this_thread::yield();
                    }
                }
            });
        workers.emplace_back(
            [&, lane, tid, hwnd]()
            {
                start.arrive_and_wait();
                u32 expected = 1;
                u32 empty_spins = 0;
                while (expected <= kConcurrentMessageCount && !abort[lane].load())
                {
                    Probe next = ProbeQueue(kConcurrentPid, tid);
                    if (next.result == GuiMessageProbeResult::Empty)
                    {
                        if (++empty_spins == 50000000u)
                        {
                            concurrent_errors[lane].fetch_add(1);
                            abort[lane].store(true);
                            break;
                        }
                        std::this_thread::yield();
                        continue;
                    }
                    empty_spins = 0;
                    if (next.result != GuiMessageProbeResult::Message)
                    {
                        concurrent_errors[lane].fetch_add(1);
                        abort[lane].store(true);
                        break;
                    }
                    if (next.claim.message.hwnd != hwnd || next.claim.message.message != 0x400u + expected ||
                        next.claim.message.wparam != expected || next.claim.message.lparam != lane)
                    {
                        concurrent_errors[lane].fetch_add(1);
                    }
                    if (GuiMessageCommit(next.claim, true))
                    {
                        consumed[lane].fetch_add(1);
                        ++expected;
                    }
                }
            });
        workers.emplace_back(
            [&, lane, tid]()
            {
                start.arrive_and_wait();
                for (u32 iteration = 0; iteration < kEnsureIterations && !abort[lane].load(); ++iteration)
                {
                    if (!GuiMessageEnsureQueue(kConcurrentPid, tid))
                    {
                        concurrent_errors[lane].fetch_add(1);
                        abort[lane].store(true);
                        break;
                    }
                }
            });
    }
    start.arrive_and_wait();
    for (std::thread& worker : workers)
    {
        worker.join();
    }

    for (u32 lane = 0; lane < kConcurrentQueueCount; ++lane)
    {
        const u64 tid = kConcurrentTidBase + lane;
        EXPECT_FALSE(abort[lane].load());
        EXPECT_EQ(concurrent_errors[lane].load(), 0u);
        EXPECT_EQ(consumed[lane].load(), kConcurrentMessageCount);
        EXPECT_EQ(ProbeQueue(kConcurrentPid, tid).result, GuiMessageProbeResult::Empty);
        EXPECT_EQ(GuiMessageReapTask(kConcurrentPid, tid), 0u);
    }

    return duetos_host_test::finish_main("test_gui_message_queue");
}
