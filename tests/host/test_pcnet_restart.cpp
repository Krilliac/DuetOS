#include "drivers/net/pcnet.h"
#include "drivers/net/wireless_watch.h"
#include "host_test_helper.h"
#include "net/stack.h"

#include <atomic>
#include <cstddef>
#include <thread>

using namespace duetos;
using namespace duetos::drivers::net;
using namespace duetos::drivers::net::pcnet_contract;

namespace
{

void TestWireContract()
{
    static_assert(sizeof(PcnetDescriptor) == 16);
    static_assert(offsetof(PcnetDescriptor, address) == 0);
    static_assert(offsetof(PcnetDescriptor, buffer_count) == 4);
    static_assert(offsetof(PcnetDescriptor, status) == 6);
    static_assert(offsetof(PcnetDescriptor, message) == 8);
    static_assert(sizeof(PcnetInitBlock) == 32);
    static_assert(offsetof(PcnetInitBlock, physical_address) == 4);
    static_assert(offsetof(PcnetInitBlock, rx_ring_address) == 20);
    static_assert(offsetof(PcnetInitBlock, tx_ring_address) == 24);
    static_assert(EncodeBufferCount(2048) == 0xF800u);
    static_assert(EncodeBufferCount(1514) == 0xFA16u);
    static_assert(Csr0RuntimeAckValue(0xFFFFu) == 0x7E00u);
    static_assert(Csr0RuntimeAckValue(kCsr0InitDone | kCsr0Start) == 0);
}

void TestTxRingFullAndReclaim()
{
    TxCursor cursor{};
    for (u32 slot = 0; slot < kTxRingSlots; ++slot)
    {
        EXPECT_FALSE(TxRingFull(cursor));
        EXPECT_EQ(TxProducerSlot(cursor), slot);
        EXPECT_TRUE(TxCommit(cursor));
    }
    EXPECT_TRUE(TxRingFull(cursor));
    EXPECT_FALSE(TxCommit(cursor));
    EXPECT_EQ(cursor.producer, 0u);
    EXPECT_EQ(cursor.in_flight, kTxRingSlots);

    EXPECT_TRUE(TxReclaimOne(cursor));
    EXPECT_EQ(cursor.clean, 1u);
    EXPECT_FALSE(TxRingFull(cursor));
    EXPECT_TRUE(TxCommit(cursor));
    EXPECT_TRUE(TxRingFull(cursor));
    for (u32 i = 0; i < kTxRingSlots; ++i)
        EXPECT_TRUE(TxReclaimOne(cursor));
    EXPECT_FALSE(TxReclaimOne(cursor));
}

void TestHostileRxDescriptors()
{
    const u16 complete = kDescriptorStart | kDescriptorEnd;
    RxInspection inspected = InspectRx(kDescriptorOwn, 64, false);
    EXPECT_EQ(inspected.disposition, RxDisposition::NotReady);

    inspected = InspectRx(complete, 64, false);
    EXPECT_EQ(inspected.disposition, RxDisposition::Deliver);
    EXPECT_EQ(inspected.frame_bytes, 60u);
    EXPECT_FALSE(inspected.discard_until_end);

    inspected = InspectRx(kDescriptorStart, 100, false);
    EXPECT_EQ(inspected.disposition, RxDisposition::Drop);
    EXPECT_TRUE(inspected.discard_until_end);
    inspected = InspectRx(0, 100, inspected.discard_until_end);
    EXPECT_TRUE(inspected.discard_until_end);
    inspected = InspectRx(kDescriptorEnd, 100, inspected.discard_until_end);
    EXPECT_FALSE(inspected.discard_until_end);

    inspected = InspectRx(complete | kDescriptorError, 100, false);
    EXPECT_EQ(inspected.disposition, RxDisposition::Drop);
    inspected = InspectRx(complete, kEthernetHeaderBytes + kEthernetFcsBytes - 1, false);
    EXPECT_EQ(inspected.disposition, RxDisposition::Drop);
    inspected = InspectRx(complete, kMaximumFrameBytes + kEthernetFcsBytes + 1, false);
    EXPECT_EQ(inspected.disposition, RxDisposition::Drop);
    inspected = InspectRx(kDescriptorEnd, 100, false);
    EXPECT_EQ(inspected.disposition, RxDisposition::Drop);
}

using ContextTx = bool (*)(void*, u32, const void*, u64);

struct FakeStack
{
    DriverOperationGate callbacks{};
    net::NetInterfaceBinding live = net::kInvalidNetInterfaceBinding;
    u64 issued = 0;
    ContextTx tx = nullptr;
    void* context = nullptr;

    bool Bind(u32 iface, ContextTx callback, void* callback_context, net::NetInterfaceBinding* receipt)
    {
        if (net::NetInterfaceBindingIsValid(live) || callback == nullptr || receipt == nullptr)
            return false;
        live = {iface, ++issued};
        tx = callback;
        context = callback_context;
        if (!DriverOperationGateOpen(&callbacks))
            return false;
        *receipt = live;
        return true;
    }

    bool Transmit(net::NetInterfaceBinding binding)
    {
        if (!net::NetInterfaceBindingEqual(binding, live) || !DriverOperationGateTryAcquire(&callbacks))
            return false;
        const bool result = tx(context, binding.iface_index, this, sizeof(*this));
        EXPECT_TRUE(DriverOperationGateRelease(&callbacks));
        return result;
    }

    net::NetInterfaceUnbindResult Unbind(net::NetInterfaceBinding binding)
    {
        if (!net::NetInterfaceBindingEqual(binding, live))
            return net::NetInterfaceUnbindResult::StaleBinding;
        (void)DriverOperationGateClose(&callbacks);
        if (DriverOperationGatePinCount(&callbacks) != 0)
            return net::NetInterfaceUnbindResult::DrainTimedOut;
        live = net::kInvalidNetInterfaceBinding;
        tx = nullptr;
        context = nullptr;
        return net::NetInterfaceUnbindResult::Unbound;
    }
};

struct FakeDriver
{
    DriverOperationGate operations{};
    DriverWorkerLease worker{};
    std::atomic<bool> block{false};
    std::atomic<bool> release{false};
    std::atomic<u32> entered{0};
    std::atomic<u32> calls{0};
    u32 iface = 0;

    static bool Transmit(void* raw, u32 iface_index, const void*, u64)
    {
        auto* driver = static_cast<FakeDriver*>(raw);
        if (driver == nullptr || iface_index != driver->iface || !DriverOperationGateTryAcquire(&driver->operations))
            return false;
        driver->calls.fetch_add(1, std::memory_order_relaxed);
        driver->entered.fetch_add(1, std::memory_order_release);
        while (driver->block.load(std::memory_order_acquire) && !driver->release.load(std::memory_order_acquire))
            std::this_thread::yield();
        EXPECT_TRUE(DriverOperationGateRelease(&driver->operations));
        return true;
    }
};

void TestTimeoutRetryRebindAndStaleCallback()
{
    FakeStack stack{};
    FakeDriver driver{};
    driver.iface = 2;
    const u64 first_worker = DriverWorkerLeasePrepare(&driver.worker);
    EXPECT_TRUE(first_worker != 0);
    EXPECT_TRUE(DriverOperationGateOpen(&driver.operations));

    net::NetInterfaceBinding first = net::kInvalidNetInterfaceBinding;
    EXPECT_TRUE(stack.Bind(driver.iface, &FakeDriver::Transmit, &driver, &first));
    driver.block.store(true, std::memory_order_release);
    std::thread pinned([&] { EXPECT_TRUE(stack.Transmit(first)); });
    for (u32 tries = 0; tries < 100000 && driver.entered.load(std::memory_order_acquire) == 0; ++tries)
        std::this_thread::yield();
    EXPECT_EQ(driver.entered.load(std::memory_order_acquire), 1u);
    EXPECT_EQ(DriverOperationGatePinCount(&driver.operations), 1u);

    EXPECT_TRUE(DriverOperationGateClose(&driver.operations));
    EXPECT_TRUE(DriverWorkerLeaseRequestRetire(&driver.worker, first_worker));
    EXPECT_TRUE(DriverWorkerLeaseAcknowledge(&driver.worker, first_worker));
    EXPECT_FALSE(DriverOperationGateTryAcquire(&driver.operations));
    EXPECT_EQ(stack.Unbind(first), net::NetInterfaceUnbindResult::DrainTimedOut);

    driver.release.store(true, std::memory_order_release);
    pinned.join();
    EXPECT_EQ(DriverOperationGatePinCount(&driver.operations), 0u);
    EXPECT_EQ(stack.Unbind(first), net::NetInterfaceUnbindResult::Unbound);
    EXPECT_TRUE(DriverWorkerLeaseRelease(&driver.worker, first_worker));

    const u64 second_worker = DriverWorkerLeasePrepare(&driver.worker);
    EXPECT_TRUE(second_worker > first_worker);
    EXPECT_TRUE(DriverOperationGateOpen(&driver.operations));
    driver.block.store(false, std::memory_order_release);
    driver.release.store(false, std::memory_order_release);
    net::NetInterfaceBinding second = net::kInvalidNetInterfaceBinding;
    EXPECT_TRUE(stack.Bind(driver.iface, &FakeDriver::Transmit, &driver, &second));
    EXPECT_NE(second.generation, first.generation);

    const u32 calls_before = driver.calls.load(std::memory_order_relaxed);
    EXPECT_FALSE(stack.Transmit(first));
    EXPECT_EQ(driver.calls.load(std::memory_order_relaxed), calls_before);
    EXPECT_EQ(stack.Unbind(first), net::NetInterfaceUnbindResult::StaleBinding);
    EXPECT_TRUE(stack.Transmit(second));
    EXPECT_EQ(driver.calls.load(std::memory_order_relaxed), calls_before + 1);

    EXPECT_TRUE(DriverOperationGateClose(&driver.operations));
    EXPECT_TRUE(DriverWorkerLeaseRequestRetire(&driver.worker, second_worker));
    EXPECT_TRUE(DriverWorkerLeaseAcknowledge(&driver.worker, second_worker));
    EXPECT_EQ(stack.Unbind(second), net::NetInterfaceUnbindResult::Unbound);
    EXPECT_TRUE(DriverWorkerLeaseRelease(&driver.worker, second_worker));
}

void TestFirstScheduleAfterRetire()
{
    DriverWorkerLease lease{};
    const u64 generation = DriverWorkerLeasePrepare(&lease);
    std::atomic<bool> may_start{false};
    std::atomic<u32> polls{0};
    std::atomic<bool> acknowledged{false};
    std::thread worker(
        [&]
        {
            while (!may_start.load(std::memory_order_acquire))
                std::this_thread::yield();
            if (DriverWorkerLeaseShouldRun(&lease, generation))
                polls.fetch_add(1, std::memory_order_relaxed);
            acknowledged.store(DriverWorkerLeaseAcknowledge(&lease, generation), std::memory_order_release);
        });

    EXPECT_TRUE(DriverWorkerLeaseRequestRetire(&lease, generation));
    may_start.store(true, std::memory_order_release);
    worker.join();
    EXPECT_EQ(polls.load(std::memory_order_relaxed), 0u);
    EXPECT_TRUE(acknowledged.load(std::memory_order_acquire));
    EXPECT_TRUE(DriverWorkerLeaseRelease(&lease, generation));
}

} // namespace

int main()
{
    TestWireContract();
    TestTxRingFullAndReclaim();
    TestHostileRxDescriptors();
    TestTimeoutRetryRebindAndStaleCallback();
    TestFirstScheduleAfterRetire();
    return ::duetos_host_test::finish_main("pcnet_restart");
}
