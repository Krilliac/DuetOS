#include "drivers/net/wireless_watch.h"
#include "drivers/virtio/virtio_net.h"
#include "host_test_helper.h"
#include "net/stack.h"

#include <atomic>
#include <cstddef>
#include <thread>

using namespace duetos;
using namespace duetos::drivers::net;
using namespace duetos::drivers::virtio::virtio_net_contract;

namespace
{

void TestWireAndRxPolicy()
{
    static_assert(sizeof(NetHeader) == 10);
    static_assert(offsetof(NetHeader, flags) == 0);
    static_assert(offsetof(NetHeader, header_length) == 2);
    static_assert(offsetof(NetHeader, checksum_offset) == 8);
    NetHeader header{};
    EXPECT_TRUE(HeaderIsSupported(header));
    header.flags = 1;
    EXPECT_FALSE(HeaderIsSupported(header));
    header = {};
    header.gso_type = 1;
    EXPECT_FALSE(HeaderIsSupported(header));
    header = {};
    header.checksum_start = 1;
    EXPECT_FALSE(HeaderIsSupported(header));

    const RxInspection short_frame = InspectRxCompletion(kRxSlots, 0, sizeof(NetHeader));
    EXPECT_EQ(short_frame.disposition, RxDisposition::Drop);
    EXPECT_FALSE(short_frame.close_admission);
    EXPECT_EQ(InspectRxCompletion(kRxSlots, 0, sizeof(NetHeader) + kMinimumFrameBytes - 1).disposition,
              RxDisposition::Drop);
    EXPECT_TRUE(InspectRxCompletion(kRxSlots, kRxSlots, sizeof(NetHeader) + 64).close_admission);
    EXPECT_EQ(InspectRxCompletion(kRxSlots, 0, sizeof(NetHeader) + kMaximumFrameBytes + 1).disposition,
              RxDisposition::Drop);
    EXPECT_EQ(InspectRxCompletion(kRxSlots, 0, kRxBufferBytes + 1).disposition, RxDisposition::Drop);
    EXPECT_TRUE(InspectRxCompletion(0, 0, sizeof(NetHeader) + 64).close_admission);
    EXPECT_TRUE(InspectRxCompletion(kRxSlots + 1, 0, sizeof(NetHeader) + 64).close_admission);
    const RxInspection reduced_queue_hostile = InspectRxCompletion(4, 4, sizeof(NetHeader) + 64);
    EXPECT_EQ(reduced_queue_hostile.disposition, RxDisposition::Drop);
    EXPECT_TRUE(reduced_queue_hostile.close_admission);
    DriverOperationGate rx_admission{};
    EXPECT_TRUE(DriverOperationGateOpen(&rx_admission));
    if (reduced_queue_hostile.close_admission)
        EXPECT_TRUE(DriverOperationGateClose(&rx_admission));
    EXPECT_FALSE(DriverOperationGateTryAcquire(&rx_admission));

    const RxInspection valid = InspectRxCompletion(4, 3, sizeof(NetHeader) + kMinimumFrameBytes);
    EXPECT_EQ(valid.disposition, RxDisposition::Deliver);
    EXPECT_EQ(valid.frame_bytes, kMinimumFrameBytes);
    EXPECT_FALSE(valid.close_admission);
}

void TestTransportFingerprintIsExact()
{
    TransportFingerprint first{};
    first.address = {0, 3, 1, 0};
    first.vendor_device = 0x10411AF4u;
    first.class_revision = 0x02000001u;
    first.subsystem = 0x00011AF4u;
    first.common = {.bar_address = 0xF0000000u,
                    .bar_size = 0x1000u,
                    .physical = 0xF0000100u,
                    .offset = 0x100u,
                    .length = 0x38u,
                    .bir = 0,
                    .capability_offset = 0x40,
                    .capability_length = 16,
                    .present = true,
                    .bar_is_64bit = false,
                    .bar_is_prefetchable = false};
    first.notify = {.bar_address = 0xF0001000u,
                    .bar_size = 0x1000u,
                    .physical = 0xF0001200u,
                    .offset = 0x200u,
                    .length = 0x100u,
                    .bir = 1,
                    .capability_offset = 0x50,
                    .capability_length = 20,
                    .present = true,
                    .bar_is_64bit = false,
                    .bar_is_prefetchable = false};
    first.isr = {.bar_address = 0xF0002000u,
                 .bar_size = 0x1000u,
                 .physical = 0xF0002000u,
                 .offset = 0,
                 .length = 1,
                 .bir = 2,
                 .capability_offset = 0x64,
                 .capability_length = 16,
                 .present = true,
                 .bar_is_64bit = false,
                 .bar_is_prefetchable = false};
    first.device = {.bar_address = 0xF0003000u,
                    .bar_size = 0x1000u,
                    .physical = 0xF0003000u,
                    .offset = 0,
                    .length = 8,
                    .bir = 3,
                    .capability_offset = 0x74,
                    .capability_length = 16,
                    .present = true,
                    .bar_is_64bit = false,
                    .bar_is_prefetchable = false};
    first.notify_off_multiplier = 4;

    TransportFingerprint second = first;
    EXPECT_TRUE(SameTransport(first, second));
    second.address.function = 2;
    EXPECT_FALSE(SameTransport(first, second));
    second = first;
    second.notify.length += 4;
    EXPECT_FALSE(SameTransport(first, second));
    second = first;
    second.common.bar_size *= 2;
    EXPECT_FALSE(SameTransport(first, second));
    second = first;
    second.common.capability_offset += 4;
    EXPECT_FALSE(SameTransport(first, second));
    second = first;
    second.notify_off_multiplier = 2;
    EXPECT_FALSE(SameTransport(first, second));
    second = first;
    second.device.present = false;
    EXPECT_FALSE(SameTransport(first, second));
}

void TestDmaReleaseRequiresEveryProof()
{
    TeardownProof proof{true, true, true, true, true};
    EXPECT_TRUE(MayReleaseDma(proof));
    proof.worker_joined = false;
    EXPECT_FALSE(MayReleaseDma(proof));
    proof = {true, false, true, true, true};
    EXPECT_FALSE(MayReleaseDma(proof));
    proof = {true, true, false, true, true};
    EXPECT_FALSE(MayReleaseDma(proof));
    proof = {true, true, true, false, true};
    EXPECT_FALSE(MayReleaseDma(proof));
    proof = {true, true, true, true, false};
    EXPECT_FALSE(MayReleaseDma(proof));
}

using ContextTx = bool (*)(void*, u32, const void*, u64);

struct FakeStack
{
    DriverOperationGate callbacks{};
    net::NetInterfaceBinding live = net::kInvalidNetInterfaceBinding;
    u64 issued_generation = 0;
    ContextTx transmit = nullptr;
    void* context = nullptr;
    u32 rx_deliveries = 0;

    bool Bind(u32 iface_index, ContextTx callback, void* callback_context, net::NetInterfaceBinding* receipt)
    {
        if (net::NetInterfaceBindingIsValid(live) || callback == nullptr || receipt == nullptr)
            return false;
        live = {iface_index, ++issued_generation};
        transmit = callback;
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
        const bool result = transmit(context, binding.iface_index, this, sizeof(*this));
        EXPECT_TRUE(DriverOperationGateRelease(&callbacks));
        return result;
    }

    bool Inject(net::NetInterfaceBinding binding)
    {
        if (!net::NetInterfaceBindingEqual(binding, live) || !DriverOperationGateTryAcquire(&callbacks))
            return false;
        ++rx_deliveries;
        EXPECT_TRUE(DriverOperationGateRelease(&callbacks));
        return true;
    }

    net::NetInterfaceUnbindResult Unbind(net::NetInterfaceBinding binding)
    {
        if (!net::NetInterfaceBindingEqual(binding, live))
            return net::NetInterfaceUnbindResult::StaleBinding;
        (void)DriverOperationGateClose(&callbacks);
        if (DriverOperationGatePinCount(&callbacks) != 0)
            return net::NetInterfaceUnbindResult::DrainTimedOut;
        live = net::kInvalidNetInterfaceBinding;
        transmit = nullptr;
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
    u32 iface_index = 2;

    static bool Transmit(void* context, u32 iface, const void*, u64)
    {
        auto* const driver = static_cast<FakeDriver*>(context);
        if (driver == nullptr || iface != driver->iface_index || !DriverOperationGateTryAcquire(&driver->operations))
            return false;
        driver->calls.fetch_add(1, std::memory_order_relaxed);
        driver->entered.fetch_add(1, std::memory_order_release);
        while (driver->block.load(std::memory_order_acquire) && !driver->release.load(std::memory_order_acquire))
            std::this_thread::yield();
        EXPECT_TRUE(DriverOperationGateRelease(&driver->operations));
        return true;
    }
};

void TestTimeoutRetryRebindAndStaleTraffic()
{
    FakeStack stack{};
    FakeDriver driver{};
    const u64 first_worker = DriverWorkerLeasePrepare(&driver.worker);
    EXPECT_TRUE(first_worker != 0);
    EXPECT_TRUE(DriverOperationGateOpen(&driver.operations));

    net::NetInterfaceBinding first = net::kInvalidNetInterfaceBinding;
    EXPECT_TRUE(stack.Bind(driver.iface_index, &FakeDriver::Transmit, &driver, &first));
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
    EXPECT_TRUE(stack.Bind(driver.iface_index, &FakeDriver::Transmit, &driver, &second));
    EXPECT_NE(second.generation, first.generation);

    const u32 calls_before = driver.calls.load(std::memory_order_relaxed);
    const u32 rx_before = stack.rx_deliveries;
    EXPECT_FALSE(stack.Transmit(first));
    EXPECT_FALSE(stack.Inject(first));
    EXPECT_EQ(driver.calls.load(std::memory_order_relaxed), calls_before);
    EXPECT_EQ(stack.rx_deliveries, rx_before);
    EXPECT_EQ(stack.Unbind(first), net::NetInterfaceUnbindResult::StaleBinding);
    EXPECT_TRUE(stack.Transmit(second));
    EXPECT_TRUE(stack.Inject(second));
    EXPECT_EQ(driver.calls.load(std::memory_order_relaxed), calls_before + 1);
    EXPECT_EQ(stack.rx_deliveries, rx_before + 1);

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
    TestWireAndRxPolicy();
    TestTransportFingerprintIsExact();
    TestDmaReleaseRequiresEveryProof();
    TestTimeoutRetryRebindAndStaleTraffic();
    TestFirstScheduleAfterRetire();
    return ::duetos_host_test::finish_main("virtio_net_restart");
}
