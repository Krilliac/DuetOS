#include "core/service_exit_reap_ledger.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#endif

namespace duetos::core
{

namespace
{

// Global non-wrapping mint spaces.  Both survive ledger close/reinitialize on
// purpose: an admission ticket or public delivery token minted by an earlier
// ledger incarnation can never alias a row of a later one.  Exhaustion is
// fail-closed (mint returns 0) exactly like the broker/observer epoch mints.
u64 g_next_reap_admission = 1;
u64 g_next_reap_delivery_token = 1;

#if defined(DUETOS_HOST_TEST)
std::atomic<ServiceExitReapLedgerHostHook> g_host_hook{nullptr};
std::atomic<void*> g_host_hook_context{nullptr};

void RunHostHook(ServiceExitReapLedgerHostHookPoint point, u32 row, u64 admission, ServiceExitReapRowStage stage)
{
    const ServiceExitReapLedgerHostHook hook = g_host_hook.load(std::memory_order_acquire);
    if (hook != nullptr)
    {
        const ServiceExitReapLedgerHostHookEvent event{point, row, admission, stage};
        hook(event, g_host_hook_context.load(std::memory_order_acquire));
    }
}
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

// Lock-free CAS mint, callable with or without the ledger lock held (it
// never takes any lock itself).  Returns 0 once the space is exhausted.
u64 MintNonWrapping(u64* counter)
{
    u64 current = AtomicLoadRelaxed(counter);
    while (current != ~static_cast<u64>(0))
    {
        u64 expected = current;
        if (AtomicCompareExchangeRelaxed(counter, &expected, current + 1))
            return current;
        current = expected;
    }
    return 0;
}

void IncrementSaturating(u32* value)
{
    if (*value != ~0U)
        ++(*value);
}

void AddSaturating(u32* value, u32 amount)
{
    const u32 headroom = ~0U - *value;
    *value = amount > headroom ? ~0U : *value + amount;
}

void ClearRow(ServiceExitReapRow* row)
{
    *row = ServiceExitReapRow{};
    row->directory_service = kInvalidServiceKey;
    row->directory_owner = kInvalidServiceInstanceToken;
    row->delivery_owner = kInvalidProcessKey;
}

void ClearLedger(ServiceExitReapLedger* ledger)
{
    ledger->lock = sync::SpinLock{0, 0, 0xFFFFFFFFu, sync::kLockClassServiceLifecycle};
    ledger->state = ServiceExitReapLedgerState::Uninitialized;
    ledger->initialized = 0;
    ledger->reserved16 = 0;
    ledger->live_rows = 0;
    ledger->pump_cursor = 0;
    ledger->acquisitions_inflight = 0;
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
        ClearRow(&ledger->rows[index]);
}

bool RowIsLive(const ServiceExitReapRow& row)
{
    return row.stage != ServiceExitReapRowStage::Free;
}

// Acknowledge can return NotInitialized without consuming the exact receipt;
// retain it for recovery.  InvalidEventReceipt is permanent under the ledger's
// sole-consumer contract.  The broader observer enum contains values this API
// never returns, and canonical rows reject them below.
bool ObserverAckStatusIsRetryable(ServiceExitObserverStatus status)
{
    return status == ServiceExitObserverStatus::NotInitialized;
}

bool RowNeedsPump(const ServiceExitReapRow& row)
{
    if (row.stage == ServiceExitReapRowStage::DirectoryCommitted &&
        row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::Refused &&
        !ObserverAckStatusIsRetryable(row.observer_ack_status))
    {
        return false;
    }
    return row.stage == ServiceExitReapRowStage::Acquired || row.stage == ServiceExitReapRowStage::LifecycleCommitted ||
           row.stage == ServiceExitReapRowStage::DirectoryDraining ||
           row.stage == ServiceExitReapRowStage::DirectoryCommitted;
}

ProcessKey RowProcessKey(const ServiceExitReapRow& row)
{
    return row.event.receipt.process;
}

ServiceExitReapEventKey RowEventKey(const ServiceExitReapRow& row)
{
    return ServiceExitReapEventKey{
        row.event.instance.start.broker_epoch,
        row.event.instance.start.transition.service_identity,
        row.event.instance.start.transition.generation,
        RowProcessKey(row),
        row.event_sequence,
    };
}

bool EventIsZero(const ServiceExitEvent& event)
{
    return event.receipt.registration.observer_epoch == 0 && event.receipt.registration.slot == 0 &&
           event.receipt.registration.generation == 0 && event.receipt.registration.start.broker_epoch == 0 &&
           event.receipt.registration.start.transition.service_identity == 0 &&
           event.receipt.registration.start.transition.generation == 0 && event.receipt.process.identity == 0 &&
           event.receipt.process.pid == 0 && event.instance.start.broker_epoch == 0 &&
           event.instance.start.transition.service_identity == 0 && event.instance.start.transition.generation == 0 &&
           event.instance.process.process_identity == 0 && event.instance.process.pid == 0 && event.exit_code == 0 &&
           event.failed == 0 && event.reserved8[0] == 0 && event.reserved8[1] == 0 && event.reserved8[2] == 0;
}

bool EventIsCanonical(const ServiceExitEvent& event)
{
    return ServiceExitEventReceiptIsValid(event.receipt) && ServiceLifecycleInstanceTokenIsValid(event.instance) &&
           event.receipt.registration.start == event.instance.start &&
           event.receipt.process.identity == event.instance.process.process_identity &&
           event.receipt.process.pid == event.instance.process.pid && event.failed <= 1 && event.reserved8[0] == 0 &&
           event.reserved8[1] == 0 && event.reserved8[2] == 0;
}

// Reversible lifecycle refusals keep the row Acquired for a later retry (and
// keep the pre-commit rollback path open).  Everything else that is not Ok is
// an exact terminal refusal: the broker can never commit this instance token,
// so the settled outcome is recorded verbatim and the event proceeds toward
// delivery instead of being dropped or retried forever.
bool LifecycleStatusIsRetryable(ServiceLifecycleStatus status)
{
    return status == ServiceLifecycleStatus::InvalidTimestamp || status == ServiceLifecycleStatus::NotInitialized;
}

bool LifecycleStatusIsTerminal(ServiceLifecycleStatus status)
{
    return status == ServiceLifecycleStatus::CorruptState || status == ServiceLifecycleStatus::TransitionRejected ||
           status == ServiceLifecycleStatus::StaleBrokerEpoch || status == ServiceLifecycleStatus::Closed ||
           status == ServiceLifecycleStatus::NotFound || status == ServiceLifecycleStatus::StaleGeneration;
}

bool EndpointReleaseStatusIsRetryable(ServiceEndpointStatus status)
{
    return status == ServiceEndpointStatus::Busy || status == ServiceEndpointStatus::ResourceReleaseFailed;
}

bool DirectoryOutcomeIsRetryable(ServiceDirectoryStatus status, ServiceEndpointStatus endpoint_status)
{
    if (status == ServiceDirectoryStatus::Busy || status == ServiceDirectoryStatus::NotInitialized)
        return endpoint_status == ServiceEndpointStatus::Ok;
    return status == ServiceDirectoryStatus::EndpointReleaseFailed && EndpointReleaseStatusIsRetryable(endpoint_status);
}

bool DirectoryOutcomeIsTerminal(ServiceDirectoryStatus status, ServiceEndpointStatus endpoint_status)
{
    return status == ServiceDirectoryStatus::CorruptState || status == ServiceDirectoryStatus::OwnerMismatch ||
           (status == ServiceDirectoryStatus::EndpointReleaseFailed && endpoint_status != ServiceEndpointStatus::Ok &&
            !EndpointReleaseStatusIsRetryable(endpoint_status));
}

bool LifecycleSettlementIsCanonical(const ServiceExitReapRow& row)
{
    switch (row.lifecycle_disposition)
    {
    case ServiceExitReapLifecycleDisposition::None:
        return row.lifecycle_status == ServiceLifecycleStatus::Ok || LifecycleStatusIsRetryable(row.lifecycle_status);
    case ServiceExitReapLifecycleDisposition::Committed:
        return row.lifecycle_status == ServiceLifecycleStatus::Ok;
    case ServiceExitReapLifecycleDisposition::RefusedTerminal:
        return LifecycleStatusIsTerminal(row.lifecycle_status);
    }
    return false;
}

bool DirectorySettlementIsCanonical(const ServiceExitReapRow& row)
{
    switch (row.directory_disposition)
    {
    case ServiceExitReapDirectoryDisposition::None:
        return (row.directory_status == ServiceDirectoryStatus::Ok &&
                row.directory_endpoint_status == ServiceEndpointStatus::Ok) ||
               DirectoryOutcomeIsRetryable(row.directory_status, row.directory_endpoint_status);
    case ServiceExitReapDirectoryDisposition::Committed:
        return row.directory_bound == 1 && row.directory_status == ServiceDirectoryStatus::Ok &&
               row.directory_endpoint_status == ServiceEndpointStatus::Ok;
    case ServiceExitReapDirectoryDisposition::SettledAbsent:
        return row.directory_bound == 1 && row.directory_status == ServiceDirectoryStatus::StaleKey &&
               row.directory_endpoint_status == ServiceEndpointStatus::Ok;
    case ServiceExitReapDirectoryDisposition::RefusedTerminal:
        return row.directory_bound == 1 &&
               DirectoryOutcomeIsTerminal(row.directory_status, row.directory_endpoint_status);
    case ServiceExitReapDirectoryDisposition::Unbound:
        return row.directory_bound == 0 && row.directory_status == ServiceDirectoryStatus::Ok &&
               row.directory_endpoint_status == ServiceEndpointStatus::Ok && row.directory_drained_channels == 0;
    }
    return false;
}

bool ObserverAckSettlementIsCanonical(const ServiceExitReapRow& row)
{
    switch (row.observer_ack_disposition)
    {
    case ServiceExitReapObserverAckDisposition::None:
    case ServiceExitReapObserverAckDisposition::Acknowledged:
        return row.observer_ack_status == ServiceExitObserverStatus::Ok;
    case ServiceExitReapObserverAckDisposition::Refused:
        return row.observer_ack_status == ServiceExitObserverStatus::NotInitialized ||
               row.observer_ack_status == ServiceExitObserverStatus::InvalidEventReceipt;
    }
    return false;
}

bool RowIsCanonical(const ServiceExitReapRow& row)
{
    if (row.stage > ServiceExitReapRowStage::Delivered || row.pump_inflight > 1 || row.directory_bound > 1 ||
        row.reserved8[0] != 0 || row.reserved8[1] != 0 || row.reserved32 != 0 ||
        row.lifecycle_disposition > ServiceExitReapLifecycleDisposition::RefusedTerminal ||
        row.directory_disposition > ServiceExitReapDirectoryDisposition::Unbound ||
        row.observer_ack_disposition > ServiceExitReapObserverAckDisposition::Refused ||
        row.lifecycle_status > ServiceLifecycleStatus::Busy ||
        row.directory_status > ServiceDirectoryStatus::HandleRollbackFailed ||
        row.directory_endpoint_status > ServiceEndpointStatus::RequestRejected ||
        row.observer_ack_status > ServiceExitObserverStatus::Busy)
    {
        return false;
    }

    if (!LifecycleSettlementIsCanonical(row) || !DirectorySettlementIsCanonical(row) ||
        !ObserverAckSettlementIsCanonical(row))
    {
        return false;
    }

    if (!RowIsLive(row))
    {
        return row.admission == kServiceExitReapInvalidAdmission &&
               row.event_sequence == kServiceExitReapInvalidEventSequence && EventIsZero(row.event) &&
               row.directory_bound == 0 && row.directory_service == kInvalidServiceKey &&
               row.directory_owner == kInvalidServiceInstanceToken &&
               row.lifecycle_disposition == ServiceExitReapLifecycleDisposition::None &&
               row.directory_disposition == ServiceExitReapDirectoryDisposition::None &&
               row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::None &&
               row.lifecycle_status == ServiceLifecycleStatus::Ok &&
               row.directory_status == ServiceDirectoryStatus::Ok &&
               row.directory_endpoint_status == ServiceEndpointStatus::Ok &&
               row.observer_ack_status == ServiceExitObserverStatus::Ok && row.directory_drained_channels == 0 &&
               row.delivery_token == kServiceExitReapInvalidDeliveryToken && row.delivery_owner == kInvalidProcessKey &&
               row.delivery_count == 0;
    }

    if (row.admission == kServiceExitReapInvalidAdmission ||
        row.event_sequence == kServiceExitReapInvalidEventSequence || row.event_sequence != row.admission ||
        !EventIsCanonical(row.event) ||
        !(row.directory_owner ==
          ServiceInstanceToken{row.event.instance.start.transition, row.event.instance.process}) ||
        (row.directory_bound != 0 ? !ServiceKeyIsValid(row.directory_service)
                                  : !(row.directory_service == kInvalidServiceKey)))
    {
        return false;
    }

    if (row.directory_disposition == ServiceExitReapDirectoryDisposition::Unbound && row.directory_bound != 0)
        return false;
    if ((row.directory_disposition == ServiceExitReapDirectoryDisposition::Committed ||
         row.directory_disposition == ServiceExitReapDirectoryDisposition::SettledAbsent) &&
        row.directory_bound == 0)
    {
        return false;
    }

    switch (row.stage)
    {
    case ServiceExitReapRowStage::Acquired:
        return row.lifecycle_disposition == ServiceExitReapLifecycleDisposition::None &&
               row.directory_disposition == ServiceExitReapDirectoryDisposition::None &&
               row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::None &&
               row.delivery_token == kServiceExitReapInvalidDeliveryToken && row.delivery_owner == kInvalidProcessKey &&
               row.delivery_count == 0 && row.directory_drained_channels == 0;
    case ServiceExitReapRowStage::LifecycleCommitted:
        return row.lifecycle_disposition != ServiceExitReapLifecycleDisposition::None &&
               row.directory_disposition == ServiceExitReapDirectoryDisposition::None &&
               row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::None &&
               row.delivery_token == kServiceExitReapInvalidDeliveryToken && row.delivery_owner == kInvalidProcessKey &&
               row.delivery_count == 0 && row.directory_drained_channels == 0;
    case ServiceExitReapRowStage::DirectoryDraining:
        return row.lifecycle_disposition != ServiceExitReapLifecycleDisposition::None &&
               row.directory_disposition == ServiceExitReapDirectoryDisposition::None &&
               row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::None &&
               row.delivery_token == kServiceExitReapInvalidDeliveryToken && row.delivery_owner == kInvalidProcessKey &&
               row.delivery_count == 0;
    case ServiceExitReapRowStage::DirectoryCommitted:
        if (row.lifecycle_disposition == ServiceExitReapLifecycleDisposition::None ||
            row.directory_disposition == ServiceExitReapDirectoryDisposition::None ||
            row.delivery_owner != kInvalidProcessKey || row.delivery_count != 0 ||
            row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::Acknowledged)
        {
            return false;
        }
        if (row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::Refused)
        {
            return row.delivery_token != kServiceExitReapInvalidDeliveryToken &&
                   row.observer_ack_status != ServiceExitObserverStatus::Ok;
        }
        return row.delivery_token == kServiceExitReapInvalidDeliveryToken || row.pump_inflight == 1;
    case ServiceExitReapRowStage::ReadyForDelivery:
        return row.lifecycle_disposition != ServiceExitReapLifecycleDisposition::None &&
               row.directory_disposition != ServiceExitReapDirectoryDisposition::None &&
               row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::Acknowledged &&
               row.observer_ack_status == ServiceExitObserverStatus::Ok &&
               row.delivery_token != kServiceExitReapInvalidDeliveryToken && row.delivery_owner == kInvalidProcessKey;
    case ServiceExitReapRowStage::Delivered:
        return row.lifecycle_disposition != ServiceExitReapLifecycleDisposition::None &&
               row.directory_disposition != ServiceExitReapDirectoryDisposition::None &&
               row.observer_ack_disposition == ServiceExitReapObserverAckDisposition::Acknowledged &&
               row.observer_ack_status == ServiceExitObserverStatus::Ok &&
               row.delivery_token != kServiceExitReapInvalidDeliveryToken && ProcessKeyIsValid(row.delivery_owner) &&
               row.delivery_count != 0;
    case ServiceExitReapRowStage::Free:
        break;
    }
    return false;
}

bool LedgerIsCanonicalLocked(const ServiceExitReapLedger& ledger)
{
    if (ledger.initialized != 1 || ledger.reserved16 != 0 ||
        (ledger.state != ServiceExitReapLedgerState::Open && ledger.state != ServiceExitReapLedgerState::Closed) ||
        ledger.pump_cursor >= kServiceExitReapLedgerCapacity ||
        ledger.acquisitions_inflight > kServiceExitReapLedgerCapacity)
        return false;
    u32 live = 0;
    u32 acquiring = 0;
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        const ServiceExitReapRow& row = ledger.rows[index];
        if (!RowIsCanonical(row))
            return false;
        if (RowIsLive(row))
            ++live;
        else if (row.pump_inflight != 0)
            ++acquiring;
        for (u32 previous = 0; previous < index; ++previous)
        {
            const ServiceExitReapRow& other = ledger.rows[previous];
            if (!RowIsLive(row) || !RowIsLive(other))
                continue;
            if (row.admission == other.admission || row.event_sequence == other.event_sequence)
                return false;
            if (row.delivery_token != kServiceExitReapInvalidDeliveryToken &&
                row.delivery_token == other.delivery_token)
                return false;
        }
    }
    if (ledger.state == ServiceExitReapLedgerState::Closed && (live != 0 || acquiring != 0))
        return false;
    return live == ledger.live_rows && acquiring == ledger.acquisitions_inflight;
}

bool LedgerIsPristineLocked(const ServiceExitReapLedger& ledger)
{
    if (ledger.initialized != 0 || ledger.state != ServiceExitReapLedgerState::Uninitialized ||
        ledger.reserved16 != 0 || ledger.live_rows != 0 || ledger.pump_cursor != 0 || ledger.acquisitions_inflight != 0)
    {
        return false;
    }
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        if (!RowIsCanonical(ledger.rows[index]) || ledger.rows[index].pump_inflight != 0)
            return false;
    }
    return true;
}

ServiceExitReapStatus ReadyLedgerLocked(const ServiceExitReapLedger& ledger)
{
    if (ledger.initialized != 1 || ledger.state == ServiceExitReapLedgerState::Uninitialized)
        return ServiceExitReapStatus::NotInitialized;
    if (ledger.state == ServiceExitReapLedgerState::Closed)
        return ServiceExitReapStatus::Closed;
    if (ledger.state != ServiceExitReapLedgerState::Open)
        return ServiceExitReapStatus::CorruptState;
    return ServiceExitReapStatus::Ok;
}

bool RowMatchesEventKey(const ServiceExitReapRow& row, ServiceExitReapEventKey event)
{
    return RowIsLive(row) && RowEventKey(row) == event;
}

bool RowHasAuthoritativeRestageSettlement(const ServiceExitReapRow& row)
{
    const bool lifecycle_committed = row.lifecycle_disposition == ServiceExitReapLifecycleDisposition::Committed;
    const bool directory_settled = row.directory_disposition == ServiceExitReapDirectoryDisposition::Committed ||
                                   row.directory_disposition == ServiceExitReapDirectoryDisposition::SettledAbsent;
    const bool teardown_stage = row.stage == ServiceExitReapRowStage::DirectoryCommitted ||
                                row.stage == ServiceExitReapRowStage::ReadyForDelivery ||
                                row.stage == ServiceExitReapRowStage::Delivered;
    return lifecycle_committed && directory_settled && teardown_stage;
}

} // namespace

ServiceExitReapLedger::ServiceExitReapLedger()
{
    ClearLedger(this);
}

ServiceExitReapStatus ServiceExitReapLedgerInitialize(ServiceExitReapLedger* ledger)
{
    if (ledger == nullptr)
        return ServiceExitReapStatus::NullArgument;
    sync::SpinLockGuard guard(ledger->lock);
    if (ledger->initialized == 1)
    {
        if (ledger->state == ServiceExitReapLedgerState::Open)
            return ServiceExitReapStatus::AlreadyInitialized;
        if (ledger->state != ServiceExitReapLedgerState::Closed || !LedgerIsCanonicalLocked(*ledger) ||
            ledger->live_rows != 0 || ledger->acquisitions_inflight != 0)
        {
            return ServiceExitReapStatus::CorruptState;
        }
    }
    else if (!LedgerIsPristineLocked(*ledger))
    {
        return ServiceExitReapStatus::CorruptState;
    }
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
        ClearRow(&ledger->rows[index]);
    ledger->reserved16 = 0;
    ledger->live_rows = 0;
    ledger->pump_cursor = 0;
    ledger->acquisitions_inflight = 0;
    ledger->initialized = 1;
    ledger->state = ServiceExitReapLedgerState::Open;
    return ServiceExitReapStatus::Ok;
}

ServiceExitReapStatus ServiceExitReapLedgerClose(ServiceExitReapLedger* ledger)
{
    if (ledger == nullptr)
        return ServiceExitReapStatus::NullArgument;
    sync::SpinLockGuard guard(ledger->lock);
    const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
    if (ready != ServiceExitReapStatus::Ok)
        return ready;
    if (!LedgerIsCanonicalLocked(*ledger))
        return ServiceExitReapStatus::CorruptState;
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        const ServiceExitReapRow& row = ledger->rows[index];
        if (RowIsLive(row) || row.pump_inflight != 0)
            return ServiceExitReapStatus::RowsLive;
    }
    ledger->state = ServiceExitReapLedgerState::Closed;
    return ServiceExitReapStatus::Ok;
}

ServiceExitReapAcquireResult ServiceExitReapLedgerAcquireFromObserver(ServiceExitReapLedger* ledger,
                                                                      ServiceExitObserver* observer,
                                                                      ServiceExitReapDirectoryBinding binding)
{
    ServiceExitReapAcquireResult result{ServiceExitReapStatus::NullArgument, ServiceExitObserverStatus::Ok,
                                        kInvalidServiceExitReapRowTicket};
    if (ledger == nullptr || observer == nullptr)
        return result;
    if (binding.bound > 1 || (binding.bound == 0 && !(binding.service == kInvalidServiceKey)) ||
        (binding.bound == 1 && !ServiceKeyIsValid(binding.service)))
    {
        result.status = ServiceExitReapStatus::InvalidBinding;
        return result;
    }

    u32 reserved_row = kServiceExitReapInvalidRow;
    u64 admission = kServiceExitReapInvalidAdmission;
    {
        sync::SpinLockGuard guard(ledger->lock);
        const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
        if (ready != ServiceExitReapStatus::Ok)
        {
            result.status = ready;
            return result;
        }
        if (!LedgerIsCanonicalLocked(*ledger))
        {
            result.status = ServiceExitReapStatus::CorruptState;
            return result;
        }
        for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
        {
            ServiceExitReapRow& row = ledger->rows[index];
            if (!RowIsLive(row) && row.pump_inflight == 0)
            {
                reserved_row = index;
                break;
            }
        }
        // A full ledger refuses BEFORE the observer dequeue, so the event
        // stays queued in the observer and nothing is consumed or dropped.
        if (reserved_row == kServiceExitReapInvalidRow)
        {
            result.status = ServiceExitReapStatus::CapacityExhausted;
            return result;
        }
        admission = MintNonWrapping(&g_next_reap_admission);
        if (admission == kServiceExitReapInvalidAdmission)
        {
            result.status = ServiceExitReapStatus::SequenceExhausted;
            return result;
        }
        ledger->rows[reserved_row].pump_inflight = 1;
        ++ledger->acquisitions_inflight;
    }

#if defined(DUETOS_HOST_TEST)
    RunHostHook(ServiceExitReapLedgerHostHookPoint::AcquireReservedBeforeObserverDequeue, reserved_row, admission,
                ServiceExitReapRowStage::Free);
#endif
    const ServiceExitDequeueResult dequeued = ServiceExitObserverDequeue(observer);
#if defined(DUETOS_HOST_TEST)
    RunHostHook(ServiceExitReapLedgerHostHookPoint::ObserverDequeueReturnedBeforeLedgerApply, reserved_row, admission,
                ServiceExitReapRowStage::Free);
#endif

    sync::SpinLockGuard guard(ledger->lock);
    ServiceExitReapRow& row = ledger->rows[reserved_row];
    if (dequeued.status != ServiceExitObserverStatus::Ok)
    {
        row.pump_inflight = 0;
        --ledger->acquisitions_inflight;
        result.status = dequeued.status == ServiceExitObserverStatus::NoEvent ? ServiceExitReapStatus::NoEvent
                                                                              : ServiceExitReapStatus::ObserverRefused;
        result.observer_status = dequeued.status;
        return result;
    }

    ClearRow(&row);
    row.stage = ServiceExitReapRowStage::Acquired;
    row.admission = admission;
    row.event_sequence = admission;
    row.event = dequeued.event;
    row.directory_bound = binding.bound;
    row.directory_service = binding.service;
    // The exact directory owner token is derived from the event's instance
    // token, exactly as ServiceLifecycleBrokerObserveExit derives its
    // transition token; joint publication guarantees the directory row owner
    // equals this pair for the crashed incarnation.
    row.directory_owner =
        ServiceInstanceToken{dequeued.event.instance.start.transition, dequeued.event.instance.process};
    --ledger->acquisitions_inflight;
    ++ledger->live_rows;
    result.status = ServiceExitReapStatus::Ok;
    result.observer_status = dequeued.status;
    result.ticket = ServiceExitReapRowTicket{reserved_row, admission};
    return result;
}

ServiceExitReapRollbackResult ServiceExitReapLedgerRollbackAcquired(ServiceExitReapLedger* ledger,
                                                                    ServiceExitObserver* observer,
                                                                    ServiceExitReapRowTicket ticket)
{
    ServiceExitReapRollbackResult result{ServiceExitReapStatus::NullArgument, ServiceExitObserverStatus::Ok};
    if (ledger == nullptr || observer == nullptr)
        return result;
    if (!ServiceExitReapRowTicketIsValid(ticket))
    {
        result.status = ServiceExitReapStatus::StaleTicket;
        return result;
    }

    ServiceExitEventReceipt receipt = kInvalidServiceExitEventReceipt;
    {
        sync::SpinLockGuard guard(ledger->lock);
        const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
        if (ready != ServiceExitReapStatus::Ok)
        {
            result.status = ready;
            return result;
        }
        if (!LedgerIsCanonicalLocked(*ledger))
        {
            result.status = ServiceExitReapStatus::CorruptState;
            return result;
        }
        ServiceExitReapRow& row = ledger->rows[ticket.row];
        if (!RowIsLive(row) || row.admission != ticket.admission)
        {
            result.status = ServiceExitReapStatus::StaleTicket;
            return result;
        }
        // Rollback is legal only before the lifecycle commit settles.  After
        // that the receipt must never be requeued, so this refusal is the
        // structural guarantee, not a transient state.
        if (row.stage != ServiceExitReapRowStage::Acquired)
        {
            result.status = ServiceExitReapStatus::WrongStage;
            return result;
        }
        if (row.pump_inflight != 0)
        {
            result.status = ServiceExitReapStatus::Busy;
            return result;
        }
        row.pump_inflight = 1;
        receipt = row.event.receipt;
    }

#if defined(DUETOS_HOST_TEST)
    RunHostHook(ServiceExitReapLedgerHostHookPoint::RollbackReservedBeforeObserverRequeue, ticket.row, ticket.admission,
                ServiceExitReapRowStage::Acquired);
#endif
    const ServiceExitObserverStatus requeued = ServiceExitObserverRequeue(observer, &receipt);

    sync::SpinLockGuard guard(ledger->lock);
    ServiceExitReapRow& row = ledger->rows[ticket.row];
    result.observer_status = requeued;
    if (!RowIsCanonical(row) || row.stage != ServiceExitReapRowStage::Acquired || row.pump_inflight != 1 ||
        row.admission != ticket.admission)
    {
        result.status = ServiceExitReapStatus::CorruptState;
        return result;
    }
    if (requeued == ServiceExitObserverStatus::Ok)
    {
        ClearRow(&row);
        --ledger->live_rows;
        result.status = ServiceExitReapStatus::Ok;
        return result;
    }
    // A refused requeue keeps the row Acquired with its exact receipt; the
    // event is neither dropped nor duplicated.
    row.pump_inflight = 0;
    result.status = ServiceExitReapStatus::RollbackRefused;
    return result;
}

namespace
{

struct ReapPumpWorkItem
{
    u32 row;
    u64 admission;
    ServiceExitReapRowStage stage;
    u8 directory_bound;
    ServiceExitEvent event;
    ServiceKey directory_service;
    ServiceInstanceToken directory_owner;
    u64 delivery_token;
};

// Select the next row needing progress, rotating from the stored cursor so a
// perpetually-Busy low row cannot starve later rows.  Marks the row in-flight.
bool PumpSelectLocked(ServiceExitReapLedger* ledger, ReapPumpWorkItem* item)
{
    for (u32 offset = 0; offset < kServiceExitReapLedgerCapacity; ++offset)
    {
        const u32 index = (ledger->pump_cursor + offset) % kServiceExitReapLedgerCapacity;
        ServiceExitReapRow& row = ledger->rows[index];
        if (!RowNeedsPump(row) || row.pump_inflight != 0)
            continue;
        row.pump_inflight = 1;
        ledger->pump_cursor = (index + 1) % kServiceExitReapLedgerCapacity;
        item->row = index;
        item->admission = row.admission;
        item->stage = row.stage;
        item->directory_bound = row.directory_bound;
        item->event = row.event;
        item->directory_service = row.directory_service;
        item->directory_owner = row.directory_owner;
        item->delivery_token = row.delivery_token;
        return true;
    }
    return false;
}

} // namespace

namespace
{

bool PumpWorkItemStillMatches(const ServiceExitReapRow& row, const ReapPumpWorkItem& item)
{
    return row.stage == item.stage && row.pump_inflight == 1 && row.admission == item.admission;
}

} // namespace

ServiceExitReapPumpResult ServiceExitReapLedgerPump(ServiceExitReapLedger* ledger, ServiceLifecycleBroker* broker,
                                                    ServiceDirectory* directory, ServiceExitObserver* observer,
                                                    u64 now_ns, u32 max_steps)
{
    ServiceExitReapPumpResult result{};
    result.status = ServiceExitReapStatus::NullArgument;
    if (ledger == nullptr || broker == nullptr || directory == nullptr || observer == nullptr)
        return result;
    result.status = ServiceExitReapStatus::Ok;

    // A zero-step pump is still an API/state probe, not a validation bypass.
    // Preflight once before the bounded loop so uninitialized, closed, or
    // hostile storage fails exactly as it does for a positive work budget.
    {
        sync::SpinLockGuard guard(ledger->lock);
        const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
        if (ready != ServiceExitReapStatus::Ok)
        {
            result.status = ready;
            return result;
        }
        if (!LedgerIsCanonicalLocked(*ledger))
        {
            result.status = ServiceExitReapStatus::CorruptState;
            return result;
        }
    }

    for (u32 step = 0; step < max_steps; ++step)
    {
        ReapPumpWorkItem item{};
        {
            sync::SpinLockGuard guard(ledger->lock);
            const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
            if (ready != ServiceExitReapStatus::Ok)
            {
                result.status = ready;
                return result;
            }
            if (!LedgerIsCanonicalLocked(*ledger))
            {
                result.status = ServiceExitReapStatus::CorruptState;
                return result;
            }
            if (!PumpSelectLocked(ledger, &item))
                break;
        }
        ++result.steps_attempted;
#if defined(DUETOS_HOST_TEST)
        RunHostHook(ServiceExitReapLedgerHostHookPoint::PumpSelectedBeforeExternalCall, item.row, item.admission,
                    item.stage);
#endif

        if (item.stage == ServiceExitReapRowStage::Acquired)
        {
            const ServiceLifecycleStatus observed =
                ServiceLifecycleBrokerObserveExit(broker, item.event.instance, now_ns, item.event.failed != 0);
            sync::SpinLockGuard guard(ledger->lock);
            ServiceExitReapRow& row = ledger->rows[item.row];
            if (!PumpWorkItemStillMatches(row, item))
            {
                result.status = ServiceExitReapStatus::CorruptState;
                continue;
            }
            row.lifecycle_status = observed;
            if (observed == ServiceLifecycleStatus::Ok)
            {
                row.stage = ServiceExitReapRowStage::LifecycleCommitted;
                row.lifecycle_disposition = ServiceExitReapLifecycleDisposition::Committed;
                ++result.lifecycle_committed;
            }
            else if (!LifecycleStatusIsRetryable(observed))
            {
                row.stage = ServiceExitReapRowStage::LifecycleCommitted;
                row.lifecycle_disposition = ServiceExitReapLifecycleDisposition::RefusedTerminal;
                ++result.lifecycle_refused;
            }
            row.pump_inflight = 0;
            continue;
        }

        if (item.stage == ServiceExitReapRowStage::LifecycleCommitted && item.directory_bound == 0)
        {
            sync::SpinLockGuard guard(ledger->lock);
            ServiceExitReapRow& row = ledger->rows[item.row];
            if (!PumpWorkItemStillMatches(row, item))
            {
                result.status = ServiceExitReapStatus::CorruptState;
                continue;
            }
            row.stage = ServiceExitReapRowStage::DirectoryCommitted;
            row.directory_disposition = ServiceExitReapDirectoryDisposition::Unbound;
            ++result.directory_committed;
            row.pump_inflight = 0;
            continue;
        }

        if (item.stage == ServiceExitReapRowStage::LifecycleCommitted ||
            item.stage == ServiceExitReapRowStage::DirectoryDraining)
        {
            const ServiceDirectoryCloseResult closed =
                ServiceDirectoryOwnerCrashed(directory, item.directory_service, item.directory_owner);
            sync::SpinLockGuard guard(ledger->lock);
            ServiceExitReapRow& row = ledger->rows[item.row];
            if (!PumpWorkItemStillMatches(row, item))
            {
                result.status = ServiceExitReapStatus::CorruptState;
                continue;
            }
            row.directory_status = closed.status;
            row.directory_endpoint_status = closed.endpoint_status;
            AddSaturating(&row.directory_drained_channels, closed.drained_channels);
            if (closed.status == ServiceDirectoryStatus::Ok)
            {
                row.stage = ServiceExitReapRowStage::DirectoryCommitted;
                row.directory_disposition = ServiceExitReapDirectoryDisposition::Committed;
                ++result.directory_committed;
            }
            else if (closed.status == ServiceDirectoryStatus::StaleKey)
            {
                // ResolveExactLocked proved that this exact generation no
                // longer owns a row.  This is authoritative settled-absent
                // evidence, not a generic refusal.
                row.stage = ServiceExitReapRowStage::DirectoryCommitted;
                row.directory_disposition = ServiceExitReapDirectoryDisposition::SettledAbsent;
                ++result.directory_committed;
            }
            else if (DirectoryOutcomeIsRetryable(closed.status, closed.endpoint_status))
            {
                // Busy, a retryable nested endpoint release failure, or a
                // not-yet-initialized directory retains the exact row,
                // ServiceKey, and owner token for a later bounded pass.
                // CloseEntry keeps failed endpoint receipts in its closing
                // array; permanent nested failures are parked below instead
                // of consuming every future pump rotation.
                row.stage = ServiceExitReapRowStage::DirectoryDraining;
                ++result.directory_busy;
            }
            else
            {
                row.stage = ServiceExitReapRowStage::DirectoryCommitted;
                row.directory_disposition = ServiceExitReapDirectoryDisposition::RefusedTerminal;
                ++result.directory_refused;
            }
            row.pump_inflight = 0;
            continue;
        }

        // DirectoryCommitted: reserve and durably store the public token before
        // the irreversible observer ACK.  Two concurrent rows at the final
        // token can therefore never both release their observer slots while
        // only one obtains acknowledgement authority.
        u64 token = item.delivery_token;
        if (token == kServiceExitReapInvalidDeliveryToken)
        {
            token = MintNonWrapping(&g_next_reap_delivery_token);
            if (token == kServiceExitReapInvalidDeliveryToken)
            {
                sync::SpinLockGuard guard(ledger->lock);
                ledger->rows[item.row].pump_inflight = 0;
                result.status = ServiceExitReapStatus::TokenSpaceExhausted;
                continue;
            }
            sync::SpinLockGuard guard(ledger->lock);
            ServiceExitReapRow& row = ledger->rows[item.row];
            if (row.stage != ServiceExitReapRowStage::DirectoryCommitted || row.pump_inflight != 1 ||
                row.admission != item.admission || row.delivery_token != kServiceExitReapInvalidDeliveryToken)
            {
                result.status = ServiceExitReapStatus::CorruptState;
                continue;
            }
            row.delivery_token = token;
        }

        ServiceExitEventReceipt receipt = item.event.receipt;
        const ServiceExitObserverStatus acked = ServiceExitObserverAcknowledge(observer, &receipt);
#if defined(DUETOS_HOST_TEST)
        RunHostHook(ServiceExitReapLedgerHostHookPoint::ObserverAckReturnedBeforeLedgerApply, item.row, item.admission,
                    item.stage);
#endif
        sync::SpinLockGuard guard(ledger->lock);
        ServiceExitReapRow& row = ledger->rows[item.row];
        if (row.stage != ServiceExitReapRowStage::DirectoryCommitted || row.pump_inflight != 1 ||
            row.admission != item.admission || row.delivery_token != token)
        {
            result.status = ServiceExitReapStatus::CorruptState;
            continue;
        }
        row.observer_ack_status = acked;
        if (acked != ServiceExitObserverStatus::Ok)
        {
            // No failed ACK may fabricate a deliverable row.  Retain both the
            // exact receipt and the reserved token for a later retry or
            // fail-closed diagnosis.
            row.observer_ack_disposition = ServiceExitReapObserverAckDisposition::Refused;
            row.pump_inflight = 0;
            result.status = ServiceExitReapStatus::ObserverRefused;
            continue;
        }
        row.observer_ack_disposition = ServiceExitReapObserverAckDisposition::Acknowledged;
        row.stage = ServiceExitReapRowStage::ReadyForDelivery;
        ++result.ready_transitions;
        row.pump_inflight = 0;
    }

    sync::SpinLockGuard guard(ledger->lock);
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        if (RowNeedsPump(ledger->rows[index]))
            ++result.rows_pending;
    }
    return result;
}

namespace
{

ServiceExitReapDeliveryRecord BuildDeliveryRecordLocked(const ServiceExitReapRow& row)
{
    ServiceExitReapDeliveryRecord record{};
    record.delivery_token = row.delivery_token;
    record.service_identity = row.event.instance.start.transition.service_identity;
    record.generation = row.event.instance.start.transition.generation;
    record.broker_epoch = row.event.instance.start.broker_epoch;
    record.event_sequence = row.event_sequence;
    record.instance = row.event.instance.process;
    record.process = row.event.receipt.process;
    record.exit_code = row.event.exit_code;
    record.failed = row.event.failed;
    record.lifecycle_disposition = row.lifecycle_disposition;
    record.directory_disposition = row.directory_disposition;
    record.observer_ack_disposition = row.observer_ack_disposition;
    record.lifecycle_status = row.lifecycle_status;
    record.directory_status = row.directory_status;
    record.observer_ack_status = row.observer_ack_status;
    record.directory_drained_channels = row.directory_drained_channels;
    record.delivery_count = row.delivery_count;
    return record;
}

} // namespace

ServiceExitReapDeliveryResult ServiceExitReapLedgerDequeueForDelivery(ServiceExitReapLedger* ledger,
                                                                      ProcessKey delivery_owner)
{
    ServiceExitReapDeliveryResult result{ServiceExitReapStatus::NullArgument, {}};
    if (ledger == nullptr)
        return result;
    if (!ProcessKeyIsValid(delivery_owner))
    {
        result.status = ServiceExitReapStatus::InvalidProcessKey;
        return result;
    }
    sync::SpinLockGuard guard(ledger->lock);
    const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
    if (ready != ServiceExitReapStatus::Ok)
    {
        result.status = ready;
        return result;
    }
    if (!LedgerIsCanonicalLocked(*ledger))
    {
        result.status = ServiceExitReapStatus::CorruptState;
        return result;
    }
    u32 oldest = kServiceExitReapInvalidRow;
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        const ServiceExitReapRow& row = ledger->rows[index];
        if (row.stage != ServiceExitReapRowStage::ReadyForDelivery)
            continue;
        if (oldest == kServiceExitReapInvalidRow || row.admission < ledger->rows[oldest].admission)
            oldest = index;
    }
    if (oldest == kServiceExitReapInvalidRow)
    {
        result.status = ServiceExitReapStatus::NoEvent;
        return result;
    }
    ServiceExitReapRow& row = ledger->rows[oldest];
    row.stage = ServiceExitReapRowStage::Delivered;
    row.delivery_owner = delivery_owner;
    IncrementSaturating(&row.delivery_count);
    result.status = ServiceExitReapStatus::Ok;
    result.record = BuildDeliveryRecordLocked(row);
    return result;
}

ServiceExitReapStatus ServiceExitReapLedgerAcknowledgeDelivery(ServiceExitReapLedger* ledger,
                                                               ServiceExitReapEventKey event, u64 delivery_token,
                                                               ProcessKey delivery_owner)
{
    if (ledger == nullptr)
        return ServiceExitReapStatus::NullArgument;
    if (!ServiceExitReapEventKeyIsValid(event))
        return ServiceExitReapStatus::InvalidEventKey;
    if (delivery_token == kServiceExitReapInvalidDeliveryToken)
        return ServiceExitReapStatus::StaleToken;
    if (!ProcessKeyIsValid(delivery_owner))
        return ServiceExitReapStatus::InvalidProcessKey;
    sync::SpinLockGuard guard(ledger->lock);
    const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
    if (ready != ServiceExitReapStatus::Ok)
        return ready;
    if (!LedgerIsCanonicalLocked(*ledger))
        return ServiceExitReapStatus::CorruptState;
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        ServiceExitReapRow& row = ledger->rows[index];
        if (!RowIsLive(row) || row.delivery_token != delivery_token)
            continue;
        // Exactly one live row can carry a token (global monotonic mint), so
        // every refusal below returns without touching any other row.
        if (!RowMatchesEventKey(row, event))
            return ServiceExitReapStatus::StaleEvent;
        if (row.stage != ServiceExitReapRowStage::Delivered)
            return ServiceExitReapStatus::WrongStage;
        if (!(row.delivery_owner == delivery_owner))
            return ServiceExitReapStatus::ForeignAcknowledger;
        ClearRow(&row);
        --ledger->live_rows;
        return ServiceExitReapStatus::Ok;
    }
    return ServiceExitReapStatus::StaleToken;
}

ServiceExitReapOwnerExitResult ServiceExitReapLedgerNotifyDeliveryOwnerExit(ServiceExitReapLedger* ledger,
                                                                            ProcessKey delivery_owner)
{
    ServiceExitReapOwnerExitResult result{ServiceExitReapStatus::NullArgument, 0};
    if (ledger == nullptr)
        return result;
    if (!ProcessKeyIsValid(delivery_owner))
    {
        result.status = ServiceExitReapStatus::InvalidProcessKey;
        return result;
    }
    sync::SpinLockGuard guard(ledger->lock);
    const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
    if (ready != ServiceExitReapStatus::Ok)
    {
        result.status = ready;
        return result;
    }
    if (!LedgerIsCanonicalLocked(*ledger))
    {
        result.status = ServiceExitReapStatus::CorruptState;
        return result;
    }
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        ServiceExitReapRow& row = ledger->rows[index];
        if (row.stage != ServiceExitReapRowStage::Delivered || !(row.delivery_owner == delivery_owner))
            continue;
        // The sole sanctioned stage reversal: the exact lease owner died
        // before acknowledging.  The public token and the recorded settlement
        // facts stay; only the lease clears, so the next exact serviced
        // incarnation redelivers the same token.
        row.stage = ServiceExitReapRowStage::ReadyForDelivery;
        row.delivery_owner = kInvalidProcessKey;
        ++result.reverted_rows;
    }
    result.status = ServiceExitReapStatus::Ok;
    return result;
}

ServiceExitReapRestageResult ServiceExitReapLedgerQueryRestageExact(ServiceExitReapLedger* ledger,
                                                                    ServiceExitReapEventKey event)
{
    ServiceExitReapRestageResult result{ServiceExitReapStatus::NullArgument, 0, 0, 0};
    if (ledger == nullptr)
        return result;
    if (!ServiceExitReapEventKeyIsValid(event))
    {
        result.status = ServiceExitReapStatus::InvalidEventKey;
        return result;
    }
    sync::SpinLockGuard guard(ledger->lock);
    const ServiceExitReapStatus ready = ReadyLedgerLocked(*ledger);
    if (ready != ServiceExitReapStatus::Ok)
    {
        result.status = ready;
        return result;
    }
    if (!LedgerIsCanonicalLocked(*ledger))
    {
        result.status = ServiceExitReapStatus::CorruptState;
        return result;
    }
    // A concurrent observer dequeue has not yet revealed its service identity.
    // Refuse to attest restage until that event is durably visible.
    if (ledger->acquisitions_inflight != 0)
    {
        result.status = ServiceExitReapStatus::Busy;
        return result;
    }
    bool exact_found = false;
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        const ServiceExitReapRow& row = ledger->rows[index];
        if (!RowIsLive(row) || row.event.instance.start.transition.service_identity != event.service_identity)
            continue;
        ++result.live_rows;
        if (!RowHasAuthoritativeRestageSettlement(row))
            ++result.blocking_rows;
        if (RowMatchesEventKey(row, event))
            exact_found = true;
    }
    if (!exact_found)
    {
        // A row for another generation or process is never proof for this
        // exact target.
        result.status = ServiceExitReapStatus::NotFound;
        return result;
    }
    if (result.live_rows >= kServiceExitReapRowsPerObserverSlot)
        ++result.blocking_rows;
    result.status = ServiceExitReapStatus::Ok;
    // Delivery-token allocation, observer ACK, and userland ACK are not
    // teardown authority.  The exact lifecycle+directory facts are.
    result.eligible = static_cast<u8>(result.blocking_rows == 0 ? 1 : 0);
    return result;
}

ServiceExitReapStatus ServiceExitReapLedgerInspect(ServiceExitReapLedger* ledger,
                                                   ServiceExitReapLedgerSnapshot* snapshot_out)
{
    if (ledger == nullptr || snapshot_out == nullptr)
        return ServiceExitReapStatus::NullArgument;
    *snapshot_out = ServiceExitReapLedgerSnapshot{};
    sync::SpinLockGuard guard(ledger->lock);
    if (ledger->initialized != 1)
        return ServiceExitReapStatus::NotInitialized;
    if (!LedgerIsCanonicalLocked(*ledger))
        return ServiceExitReapStatus::CorruptState;
    snapshot_out->state = ledger->state;
    snapshot_out->live_rows = ledger->live_rows;
    for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
    {
        const u32 stage = static_cast<u32>(ledger->rows[index].stage);
        if (stage < 7U)
            ++snapshot_out->stage_counts[stage];
    }
    return ServiceExitReapStatus::Ok;
}

ServiceExitReapRowInspectResult ServiceExitReapLedgerInspectRow(ServiceExitReapLedger* ledger, u32 row)
{
    ServiceExitReapRowInspectResult result{ServiceExitReapStatus::NullArgument, {}};
    if (ledger == nullptr)
        return result;
    if (row >= kServiceExitReapLedgerCapacity)
    {
        result.status = ServiceExitReapStatus::NotFound;
        return result;
    }
    sync::SpinLockGuard guard(ledger->lock);
    if (ledger->initialized != 1)
    {
        result.status = ServiceExitReapStatus::NotInitialized;
        return result;
    }
    if (!LedgerIsCanonicalLocked(*ledger))
    {
        result.status = ServiceExitReapStatus::CorruptState;
        return result;
    }
    const ServiceExitReapRow& source = ledger->rows[row];
    result.snapshot.stage = source.stage;
    result.snapshot.lifecycle_disposition = source.lifecycle_disposition;
    result.snapshot.directory_disposition = source.directory_disposition;
    result.snapshot.observer_ack_disposition = source.observer_ack_disposition;
    result.snapshot.admission = source.admission;
    result.snapshot.event_sequence = source.event_sequence;
    result.snapshot.broker_epoch = source.event.instance.start.broker_epoch;
    result.snapshot.service_identity = source.event.instance.start.transition.service_identity;
    result.snapshot.generation = source.event.instance.start.transition.generation;
    result.snapshot.process = source.event.receipt.process;
    result.snapshot.delivery_token = source.delivery_token;
    result.snapshot.delivery_owner = source.delivery_owner;
    result.snapshot.delivery_count = source.delivery_count;
    result.snapshot.directory_drained_channels = source.directory_drained_channels;
    result.status = ServiceExitReapStatus::Ok;
    return result;
}

const char* ServiceExitReapStatusName(ServiceExitReapStatus status)
{
    switch (status)
    {
    case ServiceExitReapStatus::Ok:
        return "ok";
    case ServiceExitReapStatus::NullArgument:
        return "null-argument";
    case ServiceExitReapStatus::InvalidBinding:
        return "invalid-binding";
    case ServiceExitReapStatus::InvalidProcessKey:
        return "invalid-process-key";
    case ServiceExitReapStatus::InvalidEventKey:
        return "invalid-event-key";
    case ServiceExitReapStatus::AlreadyInitialized:
        return "already-initialized";
    case ServiceExitReapStatus::NotInitialized:
        return "not-initialized";
    case ServiceExitReapStatus::Closed:
        return "closed";
    case ServiceExitReapStatus::CorruptState:
        return "corrupt-state";
    case ServiceExitReapStatus::CapacityExhausted:
        return "capacity-exhausted";
    case ServiceExitReapStatus::SequenceExhausted:
        return "sequence-exhausted";
    case ServiceExitReapStatus::TokenSpaceExhausted:
        return "token-space-exhausted";
    case ServiceExitReapStatus::NoEvent:
        return "no-event";
    case ServiceExitReapStatus::ObserverRefused:
        return "observer-refused";
    case ServiceExitReapStatus::NotFound:
        return "not-found";
    case ServiceExitReapStatus::Busy:
        return "busy";
    case ServiceExitReapStatus::RowsLive:
        return "rows-live";
    case ServiceExitReapStatus::WrongStage:
        return "wrong-stage";
    case ServiceExitReapStatus::StaleTicket:
        return "stale-ticket";
    case ServiceExitReapStatus::StaleToken:
        return "stale-token";
    case ServiceExitReapStatus::StaleEvent:
        return "stale-event";
    case ServiceExitReapStatus::ForeignAcknowledger:
        return "foreign-acknowledger";
    case ServiceExitReapStatus::RollbackRefused:
        return "rollback-refused";
    }
    return "unknown";
}

#if defined(DUETOS_HOST_TEST)
void ServiceExitReapLedgerHostSetHook(ServiceExitReapLedgerHostHook hook, void* context)
{
    if (hook == nullptr)
    {
        g_host_hook.store(nullptr, std::memory_order_release);
        g_host_hook_context.store(nullptr, std::memory_order_release);
        return;
    }
    g_host_hook_context.store(context, std::memory_order_release);
    g_host_hook.store(hook, std::memory_order_release);
}

u64 ServiceExitReapLedgerHostSetNextDeliveryTokenForTest(u64 next_token)
{
    u64 previous = AtomicLoadRelaxed(&g_next_reap_delivery_token);
    for (;;)
    {
        u64 expected = previous;
        if (AtomicCompareExchangeRelaxed(&g_next_reap_delivery_token, &expected, next_token))
            return previous;
        previous = expected;
    }
}
#endif

} // namespace duetos::core
