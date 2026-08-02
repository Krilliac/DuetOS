// Hostile host tests for the restart-safe driver worker lease.

#include "drivers/net/wireless_watch.h"
#include "host_test_helper.h"

#include <atomic>
#include <thread>
#include <vector>

using namespace duetos;
using namespace duetos::drivers::net;

namespace
{

void TestReceiptDiscipline()
{
    DriverWorkerLease lease{};
    const u64 first = DriverWorkerLeasePrepare(&lease);
    EXPECT_EQ(first, 1u);
    EXPECT_TRUE(DriverWorkerLeaseShouldRun(&lease, first));
    EXPECT_FALSE(DriverWorkerLeasePrepare(&lease) != 0);
    EXPECT_FALSE(DriverWorkerLeaseAcknowledge(&lease, first));
    EXPECT_FALSE(DriverWorkerLeaseRelease(&lease, first));

    EXPECT_TRUE(DriverWorkerLeaseRequestRetire(&lease, first));
    EXPECT_FALSE(DriverWorkerLeaseShouldRun(&lease, first));
    EXPECT_TRUE(DriverWorkerLeaseAcknowledge(&lease, first));
    EXPECT_TRUE(DriverWorkerLeaseIsAcknowledged(&lease, first));
    EXPECT_TRUE(DriverWorkerLeaseRelease(&lease, first));

    const u64 second = DriverWorkerLeasePrepare(&lease);
    EXPECT_EQ(second, 2u);
    EXPECT_FALSE(DriverWorkerLeaseAcknowledge(&lease, first));
    EXPECT_FALSE(DriverWorkerLeaseRequestRetire(&lease, first));
    EXPECT_TRUE(DriverWorkerLeaseShouldRun(&lease, second));
    EXPECT_TRUE(DriverWorkerLeaseRequestRetire(&lease, second));
    EXPECT_TRUE(DriverWorkerLeaseAcknowledge(&lease, second));
    EXPECT_TRUE(DriverWorkerLeaseRelease(&lease, second));
}

void TestFirstScheduleAfterRetire()
{
    DriverWorkerLease lease{};
    const u64 generation = DriverWorkerLeasePrepare(&lease);
    EXPECT_TRUE(generation != 0);

    std::atomic<bool> allow_start{false};
    std::atomic<bool> acknowledged{false};
    std::atomic<u32> polls{0};
    std::thread worker(
        [&]
        {
            while (!allow_start.load(std::memory_order_acquire))
                std::this_thread::yield();
            if (DriverWorkerLeaseShouldRun(&lease, generation))
                polls.fetch_add(1, std::memory_order_relaxed);
            acknowledged.store(DriverWorkerLeaseAcknowledge(&lease, generation), std::memory_order_release);
        });

    EXPECT_TRUE(DriverWorkerLeaseRequestRetire(&lease, generation));
    allow_start.store(true, std::memory_order_release);
    worker.join();
    EXPECT_EQ(polls.load(std::memory_order_relaxed), 0u);
    EXPECT_TRUE(acknowledged.load(std::memory_order_acquire));
    EXPECT_TRUE(DriverWorkerLeaseIsAcknowledged(&lease, generation));
    EXPECT_TRUE(DriverWorkerLeaseRelease(&lease, generation));
}

void TestRunningWorkerJoins()
{
    DriverWorkerLease lease{};
    const u64 generation = DriverWorkerLeasePrepare(&lease);
    std::atomic<bool> started{false};
    std::atomic<bool> acknowledged{false};
    std::atomic<u32> polls{0};
    std::thread worker(
        [&]
        {
            started.store(true, std::memory_order_release);
            while (DriverWorkerLeaseShouldRun(&lease, generation))
            {
                polls.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::yield();
            }
            acknowledged.store(DriverWorkerLeaseAcknowledge(&lease, generation), std::memory_order_release);
        });
    while (!started.load(std::memory_order_acquire) || polls.load(std::memory_order_relaxed) == 0)
        std::this_thread::yield();
    EXPECT_TRUE(DriverWorkerLeaseRequestRetire(&lease, generation));
    worker.join();
    EXPECT_TRUE(polls.load(std::memory_order_relaxed) != 0);
    EXPECT_TRUE(acknowledged.load(std::memory_order_acquire));
    EXPECT_TRUE(DriverWorkerLeaseRelease(&lease, generation));
}

void TestSinglePublisherAndExhaustion()
{
    DriverWorkerLease lease{};
    std::atomic<u32> winners{0};
    std::vector<std::thread> contenders;
    for (u32 i = 0; i < 16; ++i)
    {
        contenders.emplace_back(
            [&]
            {
                if (DriverWorkerLeasePrepare(&lease) != 0)
                    winners.fetch_add(1, std::memory_order_relaxed);
            });
    }
    for (std::thread& contender : contenders)
        contender.join();
    EXPECT_EQ(winners.load(std::memory_order_relaxed), 1u);

    const u64 generation = DriverWorkerLeaseActiveGeneration(&lease);
    EXPECT_TRUE(DriverWorkerLeaseRequestRetire(&lease, generation));
    EXPECT_TRUE(DriverWorkerLeaseAcknowledge(&lease, generation));
    EXPECT_TRUE(DriverWorkerLeaseRelease(&lease, generation));

    DriverWorkerLease exhausted{};
    exhausted.issued_generation = kDriverWorkerLeasePreparing - 1;
    EXPECT_EQ(DriverWorkerLeasePrepare(&exhausted), 0u);
    EXPECT_EQ(DriverWorkerLeaseActiveGeneration(&exhausted), 0u);
}

void TestOperationGateReceipts()
{
    DriverOperationGate gate{};
    EXPECT_FALSE(DriverOperationGateIsOpen(&gate));
    EXPECT_TRUE(DriverOperationGateOpen(&gate));
    EXPECT_FALSE(DriverOperationGateOpen(&gate));
    EXPECT_TRUE(DriverOperationGateTryAcquire(&gate));
    EXPECT_TRUE(DriverOperationGateTryAcquire(&gate));
    EXPECT_EQ(DriverOperationGatePinCount(&gate), 2u);

    EXPECT_TRUE(DriverOperationGateClose(&gate));
    EXPECT_FALSE(DriverOperationGateIsOpen(&gate));
    EXPECT_FALSE(DriverOperationGateTryAcquire(&gate));
    EXPECT_FALSE(DriverOperationGateOpen(&gate));
    EXPECT_TRUE(DriverOperationGateRelease(&gate));
    EXPECT_TRUE(DriverOperationGateRelease(&gate));
    EXPECT_FALSE(DriverOperationGateRelease(&gate));
    EXPECT_EQ(DriverOperationGatePinCount(&gate), 0u);

    EXPECT_TRUE(DriverOperationGateOpen(&gate));
    EXPECT_TRUE(DriverOperationGateClose(&gate));
}

void TestOperationGateCloseRace()
{
    DriverOperationGate gate{};
    EXPECT_TRUE(DriverOperationGateOpen(&gate));
    std::atomic<bool> start{false};
    std::atomic<bool> stop{false};
    std::atomic<u64> acquired{0};
    std::atomic<u64> release_failures{0};
    std::vector<std::thread> contenders;
    for (u32 i = 0; i < 16; ++i)
    {
        contenders.emplace_back(
            [&]
            {
                while (!start.load(std::memory_order_acquire))
                    std::this_thread::yield();
                while (!stop.load(std::memory_order_acquire))
                {
                    if (!DriverOperationGateTryAcquire(&gate))
                        continue;
                    acquired.fetch_add(1, std::memory_order_relaxed);
                    std::this_thread::yield();
                    if (!DriverOperationGateRelease(&gate))
                        release_failures.fetch_add(1, std::memory_order_relaxed);
                }
            });
    }
    start.store(true, std::memory_order_release);
    while (acquired.load(std::memory_order_relaxed) < 32)
        std::this_thread::yield();
    EXPECT_TRUE(DriverOperationGateClose(&gate));
    stop.store(true, std::memory_order_release);
    for (std::thread& contender : contenders)
        contender.join();
    EXPECT_FALSE(DriverOperationGateTryAcquire(&gate));
    EXPECT_EQ(DriverOperationGatePinCount(&gate), 0u);
    EXPECT_EQ(release_failures.load(std::memory_order_relaxed), 0u);
    EXPECT_TRUE(DriverOperationGateOpen(&gate));
    EXPECT_TRUE(DriverOperationGateClose(&gate));
}

} // namespace

int main()
{
    TestReceiptDiscipline();
    TestFirstScheduleAfterRetire();
    TestRunningWorkerJoins();
    TestSinglePublisherAndExhaustion();
    TestOperationGateReceipts();
    TestOperationGateCloseRace();
    return ::duetos_host_test::finish_main("wireless_watch");
}
