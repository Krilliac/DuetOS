#pragma once

/*
 * Exact managed-service Process-exit observation.
 *
 * A service start reserves one fixed slot before its private Process can be
 * scheduler-published.  The scheduler publication gate binds the exact,
 * non-recycled ProcessKey to that reservation.  Process teardown later
 * publishes one scalar exit event only after the Process has reached Exited.
 * A supervisor dequeues the event, commits lifecycle/directory teardown, and
 * acknowledges the exact receipt before the slot can be reused.
 *
 * This module deliberately does not call the scheduler, lifecycle broker,
 * ServiceDirectory, allocator, logger, or arbitrary callbacks.  Its lock is
 * never held across any external operation.  Registration and event receipts
 * carry observer epoch plus non-wrapping slot generation, so stale authority
 * cannot alias a later service incarnation even when a PID is recycled.
 */

#include "core/service_directory.h"
#include "core/service_lifecycle_broker.h"
#include "proc/process.h"
#include "sync/spinlock.h"
#include "util/types.h"

namespace duetos::core
{

inline constexpr u32 kServiceExitObserverCapacity = kServiceLifecycleCapacity;
inline constexpr u32 kServiceExitObserverInvalidSlot = kServiceExitObserverCapacity;
inline constexpr u32 kServiceExitObserverGenerationMaximum = ~0U;
inline constexpr u64 kServiceExitObserverInvalidEpoch = 0;

enum class ServiceExitObserverStatus : u8;
struct ServiceExitObserver;

class ServiceExitObserverEpoch
{
  public:
    constexpr ServiceExitObserverEpoch() = default;
    ~ServiceExitObserverEpoch() = default;
    ServiceExitObserverEpoch(const ServiceExitObserverEpoch&) = delete;
    ServiceExitObserverEpoch& operator=(const ServiceExitObserverEpoch&) = delete;
    ServiceExitObserverEpoch(ServiceExitObserverEpoch&&) = delete;
    ServiceExitObserverEpoch& operator=(ServiceExitObserverEpoch&&) = delete;

    [[nodiscard]] constexpr bool IsValid() const { return m_value != kServiceExitObserverInvalidEpoch; }

  private:
    explicit constexpr ServiceExitObserverEpoch(u64 value) : m_value(value) {}

    u64 m_value = kServiceExitObserverInvalidEpoch;

    friend ServiceExitObserverEpoch ServiceExitObserverMintEpoch();
    friend ServiceExitObserverStatus ServiceExitObserverInitialize(ServiceExitObserver*, ServiceExitObserverEpoch*);
};

ServiceExitObserverEpoch ServiceExitObserverMintEpoch();

enum class ServiceExitObserverState : u8
{
    Uninitialized = 0,
    Open,
    Draining,
    Closed,
};

enum class ServiceExitObserverSlotState : u8
{
    Free = 0,
    Reserved,
    Bound,
    ExitPending,
    Delivered,
    Retired,
};

enum class ServiceExitObserverStatus : u8
{
    Ok = 0,
    NullArgument,
    InvalidEpoch,
    AlreadyInitialized,
    NotInitialized,
    Draining,
    Closed,
    CapacityExhausted,
    InvalidStartTicket,
    DuplicateRegistration,
    InvalidRegistration,
    InvalidProcessKey,
    InvalidDirectoryRegistration,
    DuplicateProcess,
    ExitAlreadyPublished,
    NotFound,
    NoEvent,
    InvalidEventReceipt,
    Busy,
};

struct ServiceExitRegistration
{
    u64 observer_epoch;
    u32 slot;
    u32 generation;
    ServiceLifecycleStartTicket start;
};

inline constexpr ServiceExitRegistration kInvalidServiceExitRegistration{
    kServiceExitObserverInvalidEpoch,
    kServiceExitObserverInvalidSlot,
    0,
    kInvalidServiceLifecycleStartTicket,
};

inline constexpr bool ServiceExitRegistrationIsValid(ServiceExitRegistration registration)
{
    return registration.observer_epoch != kServiceExitObserverInvalidEpoch &&
           registration.slot < kServiceExitObserverCapacity && registration.generation != 0 &&
           ServiceLifecycleStartTicketIsValid(registration.start);
}

inline constexpr bool operator==(ServiceExitRegistration left, ServiceExitRegistration right)
{
    return left.observer_epoch == right.observer_epoch && left.slot == right.slot &&
           left.generation == right.generation && left.start == right.start;
}

struct ServiceExitReservationResult
{
    ServiceExitObserverStatus status;
    ServiceExitRegistration registration;
};

struct ServiceExitEventReceipt
{
    ServiceExitRegistration registration;
    ProcessKey process;
};

inline constexpr ServiceExitEventReceipt kInvalidServiceExitEventReceipt{
    kInvalidServiceExitRegistration,
    kInvalidProcessKey,
};

inline constexpr bool ServiceExitEventReceiptIsValid(const ServiceExitEventReceipt& receipt)
{
    return ServiceExitRegistrationIsValid(receipt.registration) && ProcessKeyIsValid(receipt.process);
}

struct ServiceExitEvent
{
    ServiceExitEventReceipt receipt;
    ServiceLifecycleInstanceToken instance;
    // Exact scalar teardown identity captured from the same private
    // registration reservation consumed by joint lifecycle/directory
    // publication. It is metadata, not observer acknowledgement authority.
    ServiceKey directory_service;
    u32 exit_code;
    u8 failed;
    u8 reserved8[3];
};

struct ServiceExitDequeueResult
{
    ServiceExitObserverStatus status;
    ServiceExitEvent event;
};

struct ServiceExitObserverSlot
{
    ServiceExitObserverSlotState state;
    u8 reserved8[3];
    u32 generation;
    ServiceLifecycleStartTicket start;
    ProcessKey process;
    ServiceKey directory_service;
    u32 exit_code;
    u32 reserved32;
};

// Public only so the boot owner can provide fixed, allocation-free storage.
// Treat all fields as opaque after Initialize succeeds.
struct ServiceExitObserver
{
    sync::SpinLock lock;
    ServiceExitObserverState state;
    u8 initialized;
    u16 reserved16;
    u32 active_count;
    u32 pending_count;
    u64 observer_epoch;
    u64 event_sequence;
    ServiceExitObserverSlot slots[kServiceExitObserverCapacity];

    ServiceExitObserver();
    ServiceExitObserver(const ServiceExitObserver&) = delete;
    ServiceExitObserver& operator=(const ServiceExitObserver&) = delete;
    ServiceExitObserver(ServiceExitObserver&&) = delete;
    ServiceExitObserver& operator=(ServiceExitObserver&&) = delete;
};

struct ServiceExitObserverSnapshot
{
    ServiceExitObserverState state;
    u32 active_count;
    u32 pending_count;
    u64 observer_epoch;
    u64 event_sequence;
};

ServiceExitObserverStatus ServiceExitObserverInitialize(ServiceExitObserver* observer, ServiceExitObserverEpoch* epoch);

// Reserve before private Process construction can reach scheduler publication.
ServiceExitReservationResult ServiceExitObserverReserve(ServiceExitObserver* observer,
                                                        ServiceLifecycleStartTicket start);

// Called by the Process publication gate. It performs no callback, allocation,
// wait, logging, or scheduler operation and never retains a Process pointer.
ServiceExitObserverStatus ServiceExitObserverBindAtSchedulerPublication(
    ServiceExitObserver* observer, ServiceExitRegistration registration, ProcessKey process,
    const ServiceRegistrationReservation& directory_registration);

// Only an unbound reservation may be aborted.
ServiceExitObserverStatus ServiceExitObserverAbort(ServiceExitObserver* observer,
                                                   ServiceExitRegistration* registration);

// Publication-gate rollback after Bind succeeded but the lower-ranked
// lifecycle commit rejected. The Process was never scheduler-visible, so this
// consumes only an exact matching Bound row and emits no exit event. Pending
// or delivered exits can never be rolled back through this path.
ServiceExitObserverStatus ServiceExitObserverRollbackBound(ServiceExitObserver* observer,
                                                           ServiceExitRegistration* registration, ProcessKey process);

// Called after Process runtime teardown and release-publication of Exited.
// Publishing is idempotence-refusing: an exact ProcessKey emits at most once.
ServiceExitObserverStatus ServiceExitObserverPublishExit(ServiceExitObserver* observer, ProcessKey process,
                                                         u32 exit_code);

// Dequeue marks the row Delivered. Acknowledge frees/retire it only after the
// caller commits all external lifecycle/directory effects. Requeue is the
// replay-safe retry path when an external consumer reports Busy.
ServiceExitDequeueResult ServiceExitObserverDequeue(ServiceExitObserver* observer);
ServiceExitObserverStatus ServiceExitObserverAcknowledge(ServiceExitObserver* observer,
                                                         ServiceExitEventReceipt* receipt);
ServiceExitObserverStatus ServiceExitObserverRequeue(ServiceExitObserver* observer, ServiceExitEventReceipt* receipt);

ServiceExitObserverStatus ServiceExitObserverBeginDrain(ServiceExitObserver* observer);
ServiceExitObserverStatus ServiceExitObserverFinishDrain(ServiceExitObserver* observer);
ServiceExitObserverStatus ServiceExitObserverInspect(ServiceExitObserver* observer,
                                                     ServiceExitObserverSnapshot* snapshot_out);
u64 ServiceExitObserverEventSequenceSnapshot(const ServiceExitObserver* observer);

#if !defined(DUETOS_HOST_TEST)
// Install exactly one static-lifetime boot observer. Ordinary non-service
// Process exits return NotInitialized/NotFound and require no special case in
// the Process reaper.
ServiceExitObserverStatus ServiceExitObserverInstallKernelObserver(ServiceExitObserver* observer);
ServiceExitObserverStatus ServiceExitObserverPublishKernelProcessExit(ProcessKey process, u32 exit_code);
#else
// Host-only exhaustion seam; requires an otherwise-free slot.
bool ServiceExitObserverHostSetSlotGenerationForTest(ServiceExitObserver* observer, u32 slot, u32 generation);
#endif

const char* ServiceExitObserverStatusName(ServiceExitObserverStatus status);

} // namespace duetos::core
