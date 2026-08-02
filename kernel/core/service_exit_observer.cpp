#include "core/service_exit_observer.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#endif

namespace duetos::core
{

namespace
{

u64 g_next_observer_epoch = 1;

#if !defined(DUETOS_HOST_TEST)
ServiceExitObserver* g_kernel_observer = nullptr;
#endif

u64 AtomicLoadRelaxed(u64* value)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u64>(*value).load(std::memory_order_relaxed);
#else
    return __atomic_load_n(value, __ATOMIC_RELAXED);
#endif
}

bool AtomicCompareExchangeRelaxed(u64* value, u64* expected, u64 desired)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u64>(*value).compare_exchange_weak(*expected, desired, std::memory_order_relaxed,
                                                              std::memory_order_relaxed);
#else
    return __atomic_compare_exchange_n(value, expected, desired, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
#endif
}

u64 AtomicLoadAcquire(const u64* value)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<const u64>(*value).load(std::memory_order_acquire);
#else
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
#endif
}

void AtomicStoreRelease(u64* value, u64 desired)
{
#if defined(DUETOS_HOST_TEST)
    std::atomic_ref<u64>(*value).store(desired, std::memory_order_release);
#else
    __atomic_store_n(value, desired, __ATOMIC_RELEASE);
#endif
}

void ClearSlotIdentity(ServiceExitObserverSlot* slot)
{
    slot->start = kInvalidServiceLifecycleStartTicket;
    slot->process = kInvalidProcessKey;
    slot->exit_code = 0;
    slot->reserved32 = 0;
}

void ReleaseSlot(ServiceExitObserverSlot* slot)
{
    ClearSlotIdentity(slot);
    slot->state = slot->generation == kServiceExitObserverGenerationMaximum ? ServiceExitObserverSlotState::Retired
                                                                            : ServiceExitObserverSlotState::Free;
}

void ClearObserver(ServiceExitObserver* observer)
{
    observer->lock = sync::SpinLock{0, 0, 0xFFFFFFFFu, sync::kLockClassServiceLifecycle};
    observer->state = ServiceExitObserverState::Uninitialized;
    observer->initialized = 0;
    observer->reserved16 = 0;
    observer->active_count = 0;
    observer->pending_count = 0;
    observer->observer_epoch = kServiceExitObserverInvalidEpoch;
    observer->event_sequence = 0;
    for (u32 index = 0; index < kServiceExitObserverCapacity; ++index)
        observer->slots[index] = ServiceExitObserverSlot{};
}

void PublishSequenceLocked(ServiceExitObserver* observer)
{
    const u64 current = AtomicLoadAcquire(&observer->event_sequence);
    if (current != ~static_cast<u64>(0))
        AtomicStoreRelease(&observer->event_sequence, current + 1);
}

bool RegistrationMatches(const ServiceExitObserver* observer, const ServiceExitObserverSlot& slot,
                         ServiceExitRegistration registration)
{
    return ServiceExitRegistrationIsValid(registration) && registration.observer_epoch == observer->observer_epoch &&
           slot.generation == registration.generation && slot.start == registration.start;
}

bool SlotIsActive(ServiceExitObserverSlotState state)
{
    return state == ServiceExitObserverSlotState::Reserved || state == ServiceExitObserverSlotState::Bound ||
           state == ServiceExitObserverSlotState::ExitPending || state == ServiceExitObserverSlotState::Delivered;
}

} // namespace

ServiceExitObserverEpoch ServiceExitObserverMintEpoch()
{
    u64 current = AtomicLoadRelaxed(&g_next_observer_epoch);
    while (current != ~static_cast<u64>(0))
    {
        u64 expected = current;
        if (AtomicCompareExchangeRelaxed(&g_next_observer_epoch, &expected, current + 1))
            return ServiceExitObserverEpoch(current);
        current = expected;
    }
    return ServiceExitObserverEpoch{};
}

ServiceExitObserver::ServiceExitObserver()
{
    ClearObserver(this);
}

ServiceExitObserverStatus ServiceExitObserverInitialize(ServiceExitObserver* observer, ServiceExitObserverEpoch* epoch)
{
    if (observer == nullptr || epoch == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    if (!epoch->IsValid())
        return ServiceExitObserverStatus::InvalidEpoch;
    if (observer->initialized != 0 || observer->state != ServiceExitObserverState::Uninitialized)
        return ServiceExitObserverStatus::AlreadyInitialized;

    observer->state = ServiceExitObserverState::Open;
    observer->initialized = 1;
    observer->observer_epoch = epoch->m_value;
    epoch->m_value = kServiceExitObserverInvalidEpoch;
    AtomicStoreRelease(&observer->event_sequence, 1);
    return ServiceExitObserverStatus::Ok;
}

ServiceExitReservationResult ServiceExitObserverReserve(ServiceExitObserver* observer,
                                                        ServiceLifecycleStartTicket start)
{
    ServiceExitReservationResult result{ServiceExitObserverStatus::NullArgument, kInvalidServiceExitRegistration};
    if (observer == nullptr)
        return result;
    if (!ServiceLifecycleStartTicketIsValid(start))
    {
        result.status = ServiceExitObserverStatus::InvalidStartTicket;
        return result;
    }

    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0 || observer->state == ServiceExitObserverState::Uninitialized)
    {
        result.status = ServiceExitObserverStatus::NotInitialized;
        return result;
    }
    if (observer->state == ServiceExitObserverState::Draining)
    {
        result.status = ServiceExitObserverStatus::Draining;
        return result;
    }
    if (observer->state == ServiceExitObserverState::Closed)
    {
        result.status = ServiceExitObserverStatus::Closed;
        return result;
    }

    u32 free_slot = kServiceExitObserverInvalidSlot;
    for (u32 index = 0; index < kServiceExitObserverCapacity; ++index)
    {
        const ServiceExitObserverSlot& candidate = observer->slots[index];
        if (SlotIsActive(candidate.state) && candidate.start == start)
        {
            result.status = ServiceExitObserverStatus::DuplicateRegistration;
            return result;
        }
        if (free_slot == kServiceExitObserverInvalidSlot && candidate.state == ServiceExitObserverSlotState::Free &&
            candidate.generation < kServiceExitObserverGenerationMaximum)
        {
            free_slot = index;
        }
    }
    if (free_slot == kServiceExitObserverInvalidSlot)
    {
        result.status = ServiceExitObserverStatus::CapacityExhausted;
        return result;
    }

    ServiceExitObserverSlot& slot = observer->slots[free_slot];
    ++slot.generation;
    slot.state = ServiceExitObserverSlotState::Reserved;
    slot.start = start;
    slot.process = kInvalidProcessKey;
    slot.exit_code = 0;
    ++observer->active_count;
    result.status = ServiceExitObserverStatus::Ok;
    result.registration = ServiceExitRegistration{observer->observer_epoch, free_slot, slot.generation, start};
    return result;
}

ServiceExitObserverStatus ServiceExitObserverBindAtSchedulerPublication(ServiceExitObserver* observer,
                                                                        ServiceExitRegistration registration,
                                                                        ProcessKey process)
{
    if (observer == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    if (!ProcessKeyIsValid(process))
        return ServiceExitObserverStatus::InvalidProcessKey;
    if (!ServiceExitRegistrationIsValid(registration) || registration.slot >= kServiceExitObserverCapacity)
        return ServiceExitObserverStatus::InvalidRegistration;

    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    if (observer->state == ServiceExitObserverState::Closed)
        return ServiceExitObserverStatus::Closed;

    ServiceExitObserverSlot& slot = observer->slots[registration.slot];
    if (!RegistrationMatches(observer, slot, registration) || slot.state != ServiceExitObserverSlotState::Reserved)
        return ServiceExitObserverStatus::InvalidRegistration;
    for (u32 index = 0; index < kServiceExitObserverCapacity; ++index)
    {
        if (index == registration.slot)
            continue;
        const ServiceExitObserverSlot& candidate = observer->slots[index];
        if ((candidate.state == ServiceExitObserverSlotState::Bound ||
             candidate.state == ServiceExitObserverSlotState::ExitPending ||
             candidate.state == ServiceExitObserverSlotState::Delivered) &&
            candidate.process == process)
        {
            return ServiceExitObserverStatus::DuplicateProcess;
        }
    }

    slot.process = process;
    slot.state = ServiceExitObserverSlotState::Bound;
    return ServiceExitObserverStatus::Ok;
}

ServiceExitObserverStatus ServiceExitObserverAbort(ServiceExitObserver* observer, ServiceExitRegistration* registration)
{
    if (observer == nullptr || registration == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    if (!ServiceExitRegistrationIsValid(*registration) || registration->slot >= kServiceExitObserverCapacity)
        return ServiceExitObserverStatus::InvalidRegistration;

    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    ServiceExitObserverSlot& slot = observer->slots[registration->slot];
    if (!RegistrationMatches(observer, slot, *registration) || slot.state != ServiceExitObserverSlotState::Reserved)
        return ServiceExitObserverStatus::InvalidRegistration;
    ReleaseSlot(&slot);
    --observer->active_count;
    *registration = kInvalidServiceExitRegistration;
    return ServiceExitObserverStatus::Ok;
}

ServiceExitObserverStatus ServiceExitObserverRollbackBound(ServiceExitObserver* observer,
                                                           ServiceExitRegistration* registration, ProcessKey process)
{
    if (observer == nullptr || registration == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    if (!ProcessKeyIsValid(process))
        return ServiceExitObserverStatus::InvalidProcessKey;
    if (!ServiceExitRegistrationIsValid(*registration) || registration->slot >= kServiceExitObserverCapacity)
        return ServiceExitObserverStatus::InvalidRegistration;

    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    ServiceExitObserverSlot& slot = observer->slots[registration->slot];
    if (!RegistrationMatches(observer, slot, *registration) || slot.state != ServiceExitObserverSlotState::Bound ||
        slot.process != process)
    {
        return ServiceExitObserverStatus::InvalidRegistration;
    }
    ReleaseSlot(&slot);
    --observer->active_count;
    *registration = kInvalidServiceExitRegistration;
    return ServiceExitObserverStatus::Ok;
}

ServiceExitObserverStatus ServiceExitObserverPublishExit(ServiceExitObserver* observer, ProcessKey process,
                                                         u32 exit_code)
{
    if (observer == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    if (!ProcessKeyIsValid(process))
        return ServiceExitObserverStatus::InvalidProcessKey;

    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    if (observer->state == ServiceExitObserverState::Closed)
        return ServiceExitObserverStatus::Closed;
    for (u32 index = 0; index < kServiceExitObserverCapacity; ++index)
    {
        ServiceExitObserverSlot& slot = observer->slots[index];
        if (slot.process != process)
            continue;
        if (slot.state == ServiceExitObserverSlotState::ExitPending ||
            slot.state == ServiceExitObserverSlotState::Delivered)
        {
            return ServiceExitObserverStatus::ExitAlreadyPublished;
        }
        if (slot.state != ServiceExitObserverSlotState::Bound)
            continue;
        slot.exit_code = exit_code;
        slot.state = ServiceExitObserverSlotState::ExitPending;
        ++observer->pending_count;
        PublishSequenceLocked(observer);
        return ServiceExitObserverStatus::Ok;
    }
    return ServiceExitObserverStatus::NotFound;
}

ServiceExitDequeueResult ServiceExitObserverDequeue(ServiceExitObserver* observer)
{
    ServiceExitDequeueResult result{ServiceExitObserverStatus::NullArgument, {}};
    if (observer == nullptr)
        return result;

    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
    {
        result.status = ServiceExitObserverStatus::NotInitialized;
        return result;
    }
    if (observer->state == ServiceExitObserverState::Closed)
    {
        result.status = ServiceExitObserverStatus::Closed;
        return result;
    }
    for (u32 index = 0; index < kServiceExitObserverCapacity; ++index)
    {
        ServiceExitObserverSlot& slot = observer->slots[index];
        if (slot.state != ServiceExitObserverSlotState::ExitPending)
            continue;
        slot.state = ServiceExitObserverSlotState::Delivered;
        --observer->pending_count;
        const ServiceExitRegistration registration{observer->observer_epoch, index, slot.generation, slot.start};
        const ServiceExitEventReceipt receipt{registration, slot.process};
        result.status = ServiceExitObserverStatus::Ok;
        result.event = ServiceExitEvent{
            receipt,
            ServiceLifecycleInstanceToken{slot.start, ServiceInstanceKey{slot.process.identity, slot.process.pid}},
            slot.exit_code,
            static_cast<u8>(slot.exit_code != 0 ? 1 : 0),
            {},
        };
        return result;
    }
    result.status = ServiceExitObserverStatus::NoEvent;
    return result;
}

ServiceExitObserverStatus ServiceExitObserverAcknowledge(ServiceExitObserver* observer,
                                                         ServiceExitEventReceipt* receipt)
{
    if (observer == nullptr || receipt == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    if (!ServiceExitEventReceiptIsValid(*receipt) || receipt->registration.slot >= kServiceExitObserverCapacity)
        return ServiceExitObserverStatus::InvalidEventReceipt;

    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    ServiceExitObserverSlot& slot = observer->slots[receipt->registration.slot];
    if (!RegistrationMatches(observer, slot, receipt->registration) || slot.process != receipt->process ||
        slot.state != ServiceExitObserverSlotState::Delivered)
    {
        return ServiceExitObserverStatus::InvalidEventReceipt;
    }
    ReleaseSlot(&slot);
    --observer->active_count;
    *receipt = kInvalidServiceExitEventReceipt;
    return ServiceExitObserverStatus::Ok;
}

ServiceExitObserverStatus ServiceExitObserverRequeue(ServiceExitObserver* observer, ServiceExitEventReceipt* receipt)
{
    if (observer == nullptr || receipt == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    if (!ServiceExitEventReceiptIsValid(*receipt) || receipt->registration.slot >= kServiceExitObserverCapacity)
        return ServiceExitObserverStatus::InvalidEventReceipt;

    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    ServiceExitObserverSlot& slot = observer->slots[receipt->registration.slot];
    if (!RegistrationMatches(observer, slot, receipt->registration) || slot.process != receipt->process ||
        slot.state != ServiceExitObserverSlotState::Delivered)
    {
        return ServiceExitObserverStatus::InvalidEventReceipt;
    }
    slot.state = ServiceExitObserverSlotState::ExitPending;
    ++observer->pending_count;
    PublishSequenceLocked(observer);
    *receipt = kInvalidServiceExitEventReceipt;
    return ServiceExitObserverStatus::Ok;
}

ServiceExitObserverStatus ServiceExitObserverBeginDrain(ServiceExitObserver* observer)
{
    if (observer == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    if (observer->state == ServiceExitObserverState::Closed)
        return ServiceExitObserverStatus::Closed;
    observer->state = ServiceExitObserverState::Draining;
    return ServiceExitObserverStatus::Ok;
}

ServiceExitObserverStatus ServiceExitObserverFinishDrain(ServiceExitObserver* observer)
{
    if (observer == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    if (observer->state == ServiceExitObserverState::Closed)
        return ServiceExitObserverStatus::Closed;
    if (observer->state != ServiceExitObserverState::Draining || observer->active_count != 0 ||
        observer->pending_count != 0)
    {
        return ServiceExitObserverStatus::Busy;
    }
    observer->state = ServiceExitObserverState::Closed;
    return ServiceExitObserverStatus::Ok;
}

ServiceExitObserverStatus ServiceExitObserverInspect(ServiceExitObserver* observer,
                                                     ServiceExitObserverSnapshot* snapshot_out)
{
    if (observer == nullptr || snapshot_out == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    *snapshot_out = ServiceExitObserverSnapshot{observer->state, observer->active_count, observer->pending_count,
                                                observer->observer_epoch, AtomicLoadAcquire(&observer->event_sequence)};
    return ServiceExitObserverStatus::Ok;
}

u64 ServiceExitObserverEventSequenceSnapshot(const ServiceExitObserver* observer)
{
    return observer == nullptr ? 0 : AtomicLoadAcquire(&observer->event_sequence);
}

#if !defined(DUETOS_HOST_TEST)
ServiceExitObserverStatus ServiceExitObserverInstallKernelObserver(ServiceExitObserver* observer)
{
    if (observer == nullptr)
        return ServiceExitObserverStatus::NullArgument;
    sync::SpinLockGuard guard(observer->lock);
    if (observer->initialized == 0)
        return ServiceExitObserverStatus::NotInitialized;
    if (observer->state != ServiceExitObserverState::Open)
        return observer->state == ServiceExitObserverState::Draining ? ServiceExitObserverStatus::Draining
                                                                     : ServiceExitObserverStatus::Closed;
    ServiceExitObserver* expected = nullptr;
    if (!__atomic_compare_exchange_n(&g_kernel_observer, &expected, observer, false, __ATOMIC_RELEASE,
                                     __ATOMIC_ACQUIRE))
    {
        return expected == observer ? ServiceExitObserverStatus::Ok : ServiceExitObserverStatus::AlreadyInitialized;
    }
    return ServiceExitObserverStatus::Ok;
}

ServiceExitObserverStatus ServiceExitObserverPublishKernelProcessExit(ProcessKey process, u32 exit_code)
{
    ServiceExitObserver* observer = __atomic_load_n(&g_kernel_observer, __ATOMIC_ACQUIRE);
    return observer == nullptr ? ServiceExitObserverStatus::NotInitialized
                               : ServiceExitObserverPublishExit(observer, process, exit_code);
}
#else
bool ServiceExitObserverHostSetSlotGenerationForTest(ServiceExitObserver* observer, u32 slot, u32 generation)
{
    if (observer == nullptr || slot >= kServiceExitObserverCapacity)
        return false;
    sync::SpinLockGuard guard(observer->lock);
    ServiceExitObserverSlot& target = observer->slots[slot];
    if (observer->initialized == 0 || target.state != ServiceExitObserverSlotState::Free)
        return false;
    target.generation = generation;
    if (generation == kServiceExitObserverGenerationMaximum)
        target.state = ServiceExitObserverSlotState::Retired;
    return true;
}
#endif

const char* ServiceExitObserverStatusName(ServiceExitObserverStatus status)
{
    switch (status)
    {
    case ServiceExitObserverStatus::Ok:
        return "ok";
    case ServiceExitObserverStatus::NullArgument:
        return "null-argument";
    case ServiceExitObserverStatus::InvalidEpoch:
        return "invalid-epoch";
    case ServiceExitObserverStatus::AlreadyInitialized:
        return "already-initialized";
    case ServiceExitObserverStatus::NotInitialized:
        return "not-initialized";
    case ServiceExitObserverStatus::Draining:
        return "draining";
    case ServiceExitObserverStatus::Closed:
        return "closed";
    case ServiceExitObserverStatus::CapacityExhausted:
        return "capacity-exhausted";
    case ServiceExitObserverStatus::InvalidStartTicket:
        return "invalid-start-ticket";
    case ServiceExitObserverStatus::DuplicateRegistration:
        return "duplicate-registration";
    case ServiceExitObserverStatus::InvalidRegistration:
        return "invalid-registration";
    case ServiceExitObserverStatus::InvalidProcessKey:
        return "invalid-process-key";
    case ServiceExitObserverStatus::DuplicateProcess:
        return "duplicate-process";
    case ServiceExitObserverStatus::ExitAlreadyPublished:
        return "exit-already-published";
    case ServiceExitObserverStatus::NotFound:
        return "not-found";
    case ServiceExitObserverStatus::NoEvent:
        return "no-event";
    case ServiceExitObserverStatus::InvalidEventReceipt:
        return "invalid-event-receipt";
    case ServiceExitObserverStatus::Busy:
        return "busy";
    }
    return "unknown";
}

} // namespace duetos::core
