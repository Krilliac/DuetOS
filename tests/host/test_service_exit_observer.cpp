// Hosted exact-registration, fast-exit, retry, exhaustion, drain, and
// concurrency coverage for core/service_exit_observer.{h,cpp}.

#include "host_test_helper.h"
#include "core/service_exit_observer.h"

#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>
#include <type_traits>

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

namespace
{

using namespace duetos::core;
using duetos::u32;
using duetos::u64;

static_assert(kServiceExitObserverCapacity == kServiceLifecycleCapacity);
static_assert(!std::is_copy_constructible_v<ServiceExitObserver>);
static_assert(!std::is_copy_assignable_v<ServiceExitObserver>);
static_assert(!std::is_copy_constructible_v<ServiceExitObserverEpoch>);
static_assert(!std::is_move_constructible_v<ServiceExitObserverEpoch>);

ServiceLifecycleStartTicket Start(u64 broker_epoch, u64 service_identity, u64 generation)
{
    return ServiceLifecycleStartTicket{broker_epoch, ServiceStartTicket{service_identity, generation}};
}

ProcessKey Key(u64 identity)
{
    return ProcessKey{identity, identity + 1000};
}

void Initialize(ServiceExitObserver* observer)
{
    ServiceExitObserverEpoch epoch = ServiceExitObserverMintEpoch();
    EXPECT_TRUE(epoch.IsValid());
    EXPECT_EQ(ServiceExitObserverInitialize(observer, &epoch), ServiceExitObserverStatus::Ok);
    EXPECT_FALSE(epoch.IsValid());
}

} // namespace

int main()
{
    using namespace duetos::core;
    using duetos::u32;
    using duetos::u64;

    EXPECT_EQ(ServiceExitObserverInitialize(nullptr, nullptr), ServiceExitObserverStatus::NullArgument);
    ServiceExitObserver invalid_epoch_observer{};
    ServiceExitObserverEpoch invalid_epoch{};
    EXPECT_EQ(ServiceExitObserverInitialize(&invalid_epoch_observer, &invalid_epoch),
              ServiceExitObserverStatus::InvalidEpoch);

    ServiceExitObserver observer{};
    Initialize(&observer);
    ServiceExitObserverEpoch second_epoch = ServiceExitObserverMintEpoch();
    EXPECT_EQ(ServiceExitObserverInitialize(&observer, &second_epoch), ServiceExitObserverStatus::AlreadyInitialized);
    EXPECT_TRUE(second_epoch.IsValid());

    ServiceExitObserverSnapshot snapshot{};
    EXPECT_EQ(ServiceExitObserverInspect(&observer, &snapshot), ServiceExitObserverStatus::Ok);
    EXPECT_EQ(snapshot.state, ServiceExitObserverState::Open);
    EXPECT_EQ(snapshot.active_count, 0U);
    EXPECT_EQ(snapshot.pending_count, 0U);
    EXPECT_TRUE(snapshot.observer_epoch != 0);
    EXPECT_EQ(snapshot.event_sequence, 1ULL);

    EXPECT_EQ(ServiceExitObserverReserve(&observer, kInvalidServiceLifecycleStartTicket).status,
              ServiceExitObserverStatus::InvalidStartTicket);
    const ServiceLifecycleStartTicket first_start = Start(11, 101, 1);
    ServiceExitReservationResult first = ServiceExitObserverReserve(&observer, first_start);
    EXPECT_EQ(first.status, ServiceExitObserverStatus::Ok);
    EXPECT_TRUE(ServiceExitRegistrationIsValid(first.registration));
    EXPECT_EQ(ServiceExitObserverReserve(&observer, first_start).status,
              ServiceExitObserverStatus::DuplicateRegistration);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, first.registration, kInvalidProcessKey),
              ServiceExitObserverStatus::InvalidProcessKey);

    const ProcessKey first_process = Key(501);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, first.registration, first_process),
              ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, first.registration, first_process),
              ServiceExitObserverStatus::InvalidRegistration);
    ServiceExitRegistration bound_copy = first.registration;
    EXPECT_EQ(ServiceExitObserverAbort(&observer, &bound_copy), ServiceExitObserverStatus::InvalidRegistration);

    // A Process may exit immediately after the publication gate. Its exact
    // registration already exists, so the event cannot race ahead of setup.
    const u64 before_exit_sequence = ServiceExitObserverEventSequenceSnapshot(&observer);
    EXPECT_EQ(ServiceExitObserverPublishExit(&observer, first_process, 73), ServiceExitObserverStatus::Ok);
    EXPECT_TRUE(ServiceExitObserverEventSequenceSnapshot(&observer) > before_exit_sequence);
    EXPECT_EQ(ServiceExitObserverPublishExit(&observer, first_process, 73),
              ServiceExitObserverStatus::ExitAlreadyPublished);
    EXPECT_EQ(ServiceExitObserverPublishExit(&observer, Key(9999), 1), ServiceExitObserverStatus::NotFound);

    ServiceExitDequeueResult event = ServiceExitObserverDequeue(&observer);
    EXPECT_EQ(event.status, ServiceExitObserverStatus::Ok);
    EXPECT_TRUE(ServiceExitEventReceiptIsValid(event.event.receipt));
    EXPECT_EQ(event.event.instance.start, first.registration.start);
    EXPECT_EQ(event.event.instance.process, (ServiceInstanceKey{first_process.identity, first_process.pid}));
    EXPECT_EQ(event.event.exit_code, 73U);
    EXPECT_EQ(event.event.failed, 1U);
    EXPECT_EQ(ServiceExitObserverDequeue(&observer).status, ServiceExitObserverStatus::NoEvent);

    // External lifecycle/directory work may report Busy. Requeue consumes the
    // delivered receipt and reproduces the same exact event, never a new one.
    ServiceExitEventReceipt first_receipt = event.event.receipt;
    EXPECT_EQ(ServiceExitObserverRequeue(&observer, &first_receipt), ServiceExitObserverStatus::Ok);
    EXPECT_FALSE(ServiceExitEventReceiptIsValid(first_receipt));
    event = ServiceExitObserverDequeue(&observer);
    EXPECT_EQ(event.status, ServiceExitObserverStatus::Ok);
    EXPECT_EQ(event.event.receipt.process, first_process);
    ServiceExitEventReceipt stale_receipt = event.event.receipt;
    EXPECT_EQ(ServiceExitObserverAcknowledge(&observer, &event.event.receipt), ServiceExitObserverStatus::Ok);
    EXPECT_FALSE(ServiceExitEventReceiptIsValid(event.event.receipt));
    EXPECT_EQ(ServiceExitObserverAcknowledge(&observer, &stale_receipt),
              ServiceExitObserverStatus::InvalidEventReceipt);

    // Abort is exact and only legal before publication binding.
    ServiceExitReservationResult aborted = ServiceExitObserverReserve(&observer, Start(11, 102, 1));
    EXPECT_EQ(aborted.status, ServiceExitObserverStatus::Ok);
    const ServiceExitRegistration aborted_stale = aborted.registration;
    EXPECT_EQ(ServiceExitObserverAbort(&observer, &aborted.registration), ServiceExitObserverStatus::Ok);
    EXPECT_FALSE(ServiceExitRegistrationIsValid(aborted.registration));
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, aborted_stale, Key(502)),
              ServiceExitObserverStatus::InvalidRegistration);

    // Cross-observer and duplicate-Process authority fail closed.
    ServiceExitObserver other{};
    Initialize(&other);
    ServiceExitReservationResult cross = ServiceExitObserverReserve(&observer, Start(11, 103, 1));
    EXPECT_EQ(cross.status, ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&other, cross.registration, Key(503)),
              ServiceExitObserverStatus::InvalidRegistration);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, cross.registration, Key(503)),
              ServiceExitObserverStatus::Ok);
    ServiceExitReservationResult duplicate_process = ServiceExitObserverReserve(&observer, Start(11, 104, 1));
    EXPECT_EQ(duplicate_process.status, ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, duplicate_process.registration, Key(503)),
              ServiceExitObserverStatus::DuplicateProcess);
    EXPECT_EQ(ServiceExitObserverAbort(&observer, &duplicate_process.registration), ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverPublishExit(&observer, Key(503), 0), ServiceExitObserverStatus::Ok);
    event = ServiceExitObserverDequeue(&observer);
    EXPECT_EQ(event.event.failed, 0U);
    EXPECT_EQ(ServiceExitObserverAcknowledge(&observer, &event.event.receipt), ServiceExitObserverStatus::Ok);

    // If the lifecycle commit rejects after observer binding, the scheduler
    // gate must roll back the exact Bound identity without fabricating an exit
    // for a Process that was never published.
    ServiceExitReservationResult gate_rejected = ServiceExitObserverReserve(&observer, Start(11, 105, 1));
    EXPECT_EQ(gate_rejected.status, ServiceExitObserverStatus::Ok);
    const ProcessKey rejected_process = Key(504);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, gate_rejected.registration, rejected_process),
              ServiceExitObserverStatus::Ok);
    ServiceExitRegistration wrong_process_receipt = gate_rejected.registration;
    EXPECT_EQ(ServiceExitObserverRollbackBound(&observer, &wrong_process_receipt, Key(505)),
              ServiceExitObserverStatus::InvalidRegistration);
    const ServiceExitRegistration rejected_stale = gate_rejected.registration;
    EXPECT_EQ(ServiceExitObserverRollbackBound(&observer, &gate_rejected.registration, rejected_process),
              ServiceExitObserverStatus::Ok);
    EXPECT_FALSE(ServiceExitRegistrationIsValid(gate_rejected.registration));
    EXPECT_EQ(ServiceExitObserverPublishExit(&observer, rejected_process, 1), ServiceExitObserverStatus::NotFound);
    EXPECT_EQ(ServiceExitObserverDequeue(&observer).status, ServiceExitObserverStatus::NoEvent);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, rejected_stale, rejected_process),
              ServiceExitObserverStatus::InvalidRegistration);

    // Rollback is never an alternate acknowledgement path once a real exit is
    // pending or delivered.
    ServiceExitReservationResult cannot_rollback = ServiceExitObserverReserve(&observer, Start(11, 106, 1));
    const ProcessKey exiting_process = Key(506);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&observer, cannot_rollback.registration, exiting_process),
              ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverPublishExit(&observer, exiting_process, 2), ServiceExitObserverStatus::Ok);
    ServiceExitRegistration pending_registration = cannot_rollback.registration;
    EXPECT_EQ(ServiceExitObserverRollbackBound(&observer, &pending_registration, exiting_process),
              ServiceExitObserverStatus::InvalidRegistration);
    event = ServiceExitObserverDequeue(&observer);
    EXPECT_EQ(event.status, ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverRollbackBound(&observer, &pending_registration, exiting_process),
              ServiceExitObserverStatus::InvalidRegistration);
    EXPECT_EQ(ServiceExitObserverAcknowledge(&observer, &event.event.receipt), ServiceExitObserverStatus::Ok);

    // Terminal slot generation retires instead of wrapping. The stale maximum
    // generation receipt cannot target the next free slot.
    ServiceExitObserver exhaustion{};
    Initialize(&exhaustion);
    EXPECT_TRUE(
        ServiceExitObserverHostSetSlotGenerationForTest(&exhaustion, 0, kServiceExitObserverGenerationMaximum - 1));
    ServiceExitReservationResult terminal = ServiceExitObserverReserve(&exhaustion, Start(12, 200, 1));
    EXPECT_EQ(terminal.registration.slot, 0U);
    EXPECT_EQ(terminal.registration.generation, kServiceExitObserverGenerationMaximum);
    const ServiceExitRegistration terminal_stale = terminal.registration;
    EXPECT_EQ(ServiceExitObserverAbort(&exhaustion, &terminal.registration), ServiceExitObserverStatus::Ok);
    ServiceExitReservationResult after_terminal = ServiceExitObserverReserve(&exhaustion, Start(12, 201, 1));
    EXPECT_EQ(after_terminal.status, ServiceExitObserverStatus::Ok);
    EXPECT_EQ(after_terminal.registration.slot, 1U);
    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&exhaustion, terminal_stale, Key(600)),
              ServiceExitObserverStatus::InvalidRegistration);
    EXPECT_EQ(ServiceExitObserverAbort(&exhaustion, &after_terminal.registration), ServiceExitObserverStatus::Ok);

    // Capacity and contention: every worker independently reserves, binds, and
    // publishes; the fixed set is then drained without loss or duplication.
    ServiceExitObserver concurrent{};
    Initialize(&concurrent);
    constexpr u32 kWorkers = 32;
    std::array<ServiceExitObserverStatus, kWorkers> reserve_status{};
    std::array<ServiceExitObserverStatus, kWorkers> bind_status{};
    std::array<ServiceExitObserverStatus, kWorkers> publish_status{};
    std::array<std::thread, kWorkers> workers{};
    for (u32 index = 0; index < kWorkers; ++index)
    {
        workers[index] = std::thread(
            [&, index]()
            {
                const ServiceLifecycleStartTicket start = Start(13, 1000 + index, 1);
                ServiceExitReservationResult reserved = ServiceExitObserverReserve(&concurrent, start);
                reserve_status[index] = reserved.status;
                if (reserved.status != ServiceExitObserverStatus::Ok)
                    return;
                const ProcessKey process = Key(2000 + index);
                bind_status[index] =
                    ServiceExitObserverBindAtSchedulerPublication(&concurrent, reserved.registration, process);
                if (bind_status[index] == ServiceExitObserverStatus::Ok)
                    publish_status[index] = ServiceExitObserverPublishExit(&concurrent, process, index);
            });
    }
    for (std::thread& worker : workers)
        worker.join();
    for (u32 index = 0; index < kWorkers; ++index)
    {
        EXPECT_EQ(reserve_status[index], ServiceExitObserverStatus::Ok);
        EXPECT_EQ(bind_status[index], ServiceExitObserverStatus::Ok);
        EXPECT_EQ(publish_status[index], ServiceExitObserverStatus::Ok);
    }
    std::array<bool, kWorkers> seen{};
    for (u32 count = 0; count < kWorkers; ++count)
    {
        ServiceExitDequeueResult next = ServiceExitObserverDequeue(&concurrent);
        EXPECT_EQ(next.status, ServiceExitObserverStatus::Ok);
        const u64 service_identity = next.event.instance.start.transition.service_identity;
        EXPECT_TRUE(service_identity >= 1000 && service_identity < 1000 + kWorkers);
        if (service_identity >= 1000 && service_identity < 1000 + kWorkers)
        {
            const u32 index = static_cast<u32>(service_identity - 1000);
            EXPECT_FALSE(seen[index]);
            seen[index] = true;
            EXPECT_EQ(next.event.exit_code, index);
        }
        EXPECT_EQ(ServiceExitObserverAcknowledge(&concurrent, &next.event.receipt), ServiceExitObserverStatus::Ok);
    }
    EXPECT_EQ(ServiceExitObserverDequeue(&concurrent).status, ServiceExitObserverStatus::NoEvent);
    EXPECT_EQ(ServiceExitObserverInspect(&concurrent, &snapshot), ServiceExitObserverStatus::Ok);
    EXPECT_EQ(snapshot.active_count, 0U);
    EXPECT_EQ(snapshot.pending_count, 0U);

    // A full observer refuses the 65th start. Drain is a one-way admission
    // close and cannot finish while any reserved/bound/delivered row survives.
    ServiceExitObserver full{};
    Initialize(&full);
    std::array<ServiceExitRegistration, kServiceExitObserverCapacity> registrations{};
    for (u32 index = 0; index < kServiceExitObserverCapacity; ++index)
    {
        const ServiceExitReservationResult reserved = ServiceExitObserverReserve(&full, Start(14, 3000 + index, 1));
        EXPECT_EQ(reserved.status, ServiceExitObserverStatus::Ok);
        registrations[index] = reserved.registration;
    }
    EXPECT_EQ(ServiceExitObserverReserve(&full, Start(14, 9999, 1)).status,
              ServiceExitObserverStatus::CapacityExhausted);
    EXPECT_EQ(ServiceExitObserverBeginDrain(&full), ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverReserve(&full, Start(14, 9999, 1)).status, ServiceExitObserverStatus::Draining);
    EXPECT_EQ(ServiceExitObserverFinishDrain(&full), ServiceExitObserverStatus::Busy);
    for (ServiceExitRegistration& registration : registrations)
        EXPECT_EQ(ServiceExitObserverAbort(&full, &registration), ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverFinishDrain(&full), ServiceExitObserverStatus::Ok);
    EXPECT_EQ(ServiceExitObserverFinishDrain(&full), ServiceExitObserverStatus::Closed);

    EXPECT_TRUE(std::strcmp(ServiceExitObserverStatusName(ServiceExitObserverStatus::ExitAlreadyPublished),
                            "exit-already-published") == 0);
    EXPECT_TRUE(std::strcmp(ServiceExitObserverStatusName(ServiceExitObserverStatus::InvalidEventReceipt),
                            "invalid-event-receipt") == 0);

    return duetos_host_test::finish_main("service_exit_observer");
}
