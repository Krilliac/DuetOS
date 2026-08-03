#pragma once

#include "util/types.h"

#if defined(_MSC_VER)
#include <atomic>
#endif

/*
 * Restart-safe driver worker lease.
 *
 * A worker context is stable storage, but stable storage alone does not make
 * reuse safe.  The owner publishes a generation before SchedCreate, requests
 * retirement by that exact generation, and may reuse the context only after
 * the worker acknowledges the same generation.  This closes both sides of
 * the first-schedule race: a worker that starts before retirement runs, while
 * one first scheduled after retirement observes the request and exits.
 *
 * The helper is freestanding and host-testable.  `net.cpp` supplies the
 * scheduler wake/wait policy and uses it for the e1000 RX worker; future
 * backend-specific wireless watchers must use the same contract rather than
 * raw NicInfo pointers plus immortal loops.
 */

namespace duetos::drivers::net
{

struct alignas(8) DriverWorkerLease
{
    u64 issued_generation;
    u64 active_generation;
    u64 retire_generation;
    u64 acknowledged_generation;
};

namespace worker_lease_detail
{

inline u64 LoadAcquire(const u64* value)
{
#if defined(_MSC_VER)
    return std::atomic_ref<u64>(*const_cast<u64*>(value)).load(std::memory_order_acquire);
#else
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
#endif
}

inline u64 LoadRelaxed(const u64* value)
{
#if defined(_MSC_VER)
    return std::atomic_ref<u64>(*const_cast<u64*>(value)).load(std::memory_order_relaxed);
#else
    return __atomic_load_n(value, __ATOMIC_RELAXED);
#endif
}

inline void StoreRelease(u64* value, u64 desired)
{
#if defined(_MSC_VER)
    std::atomic_ref<u64>(*value).store(desired, std::memory_order_release);
#else
    __atomic_store_n(value, desired, __ATOMIC_RELEASE);
#endif
}

inline void StoreRelaxed(u64* value, u64 desired)
{
#if defined(_MSC_VER)
    std::atomic_ref<u64>(*value).store(desired, std::memory_order_relaxed);
#else
    __atomic_store_n(value, desired, __ATOMIC_RELAXED);
#endif
}

inline bool CompareExchange(u64* value, u64* expected, u64 desired)
{
#if defined(_MSC_VER)
    return std::atomic_ref<u64>(*value).compare_exchange_strong(*expected, desired, std::memory_order_acq_rel,
                                                                std::memory_order_acquire);
#else
    return __atomic_compare_exchange_n(value, expected, desired, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#endif
}

} // namespace worker_lease_detail

// One-word operation admission gate. The open bit and pin count share the
// same compare/exchange domain, so shutdown cannot observe zero pins between
// an entrant's admission check and its pin publication. A zero-initialized
// gate is closed; reopening is legal only after every old pin is released.
struct alignas(8) DriverOperationGate
{
    u64 state;
};

inline constexpr u64 kDriverOperationGateOpen = u64(1) << 63;
inline constexpr u64 kDriverOperationGatePinsMask = ~kDriverOperationGateOpen;

inline bool DriverOperationGateOpen(DriverOperationGate* gate)
{
    if (gate == nullptr)
        return false;
    u64 expected = 0;
    return worker_lease_detail::CompareExchange(&gate->state, &expected, kDriverOperationGateOpen);
}

inline bool DriverOperationGateTryAcquire(DriverOperationGate* gate)
{
    if (gate == nullptr)
        return false;
    u64 observed = worker_lease_detail::LoadAcquire(&gate->state);
    while ((observed & kDriverOperationGateOpen) != 0)
    {
        if ((observed & kDriverOperationGatePinsMask) == kDriverOperationGatePinsMask)
            return false;
        u64 expected = observed;
        if (worker_lease_detail::CompareExchange(&gate->state, &expected, observed + 1))
            return true;
        observed = expected;
    }
    return false;
}

inline bool DriverOperationGateClose(DriverOperationGate* gate)
{
    if (gate == nullptr)
        return false;
    u64 observed = worker_lease_detail::LoadAcquire(&gate->state);
    while ((observed & kDriverOperationGateOpen) != 0)
    {
        u64 expected = observed;
        const u64 closed = observed & kDriverOperationGatePinsMask;
        if (worker_lease_detail::CompareExchange(&gate->state, &expected, closed))
            return true;
        observed = expected;
    }
    return false;
}

inline bool DriverOperationGateRelease(DriverOperationGate* gate)
{
    if (gate == nullptr)
        return false;
    u64 observed = worker_lease_detail::LoadAcquire(&gate->state);
    while ((observed & kDriverOperationGatePinsMask) != 0)
    {
        u64 expected = observed;
        if (worker_lease_detail::CompareExchange(&gate->state, &expected, observed - 1))
            return true;
        observed = expected;
    }
    return false;
}

inline bool DriverOperationGateIsOpen(const DriverOperationGate* gate)
{
    return gate != nullptr && (worker_lease_detail::LoadAcquire(&gate->state) & kDriverOperationGateOpen) != 0;
}

inline u64 DriverOperationGatePinCount(const DriverOperationGate* gate)
{
    return gate == nullptr ? 0 : worker_lease_detail::LoadAcquire(&gate->state) & kDriverOperationGatePinsMask;
}

inline constexpr u64 kDriverWorkerLeasePreparing = ~u64(0);

/// Reserve and publish a new generation. Returns zero when the context is
/// already active or generation space is exhausted. Call before SchedCreate.
inline u64 DriverWorkerLeasePrepare(DriverWorkerLease* lease)
{
    if (lease == nullptr)
        return 0;

    u64 expected = 0;
    if (!worker_lease_detail::CompareExchange(&lease->active_generation, &expected, kDriverWorkerLeasePreparing))
        return 0;

    const u64 issued = worker_lease_detail::LoadRelaxed(&lease->issued_generation);
    if (issued >= kDriverWorkerLeasePreparing - 1)
    {
        worker_lease_detail::StoreRelease(&lease->active_generation, 0);
        return 0;
    }

    const u64 generation = issued + 1;
    worker_lease_detail::StoreRelaxed(&lease->issued_generation, generation);
    worker_lease_detail::StoreRelease(&lease->active_generation, generation);
    return generation;
}

inline u64 DriverWorkerLeaseActiveGeneration(const DriverWorkerLease* lease)
{
    if (lease == nullptr)
        return 0;
    const u64 generation = worker_lease_detail::LoadAcquire(&lease->active_generation);
    return generation == kDriverWorkerLeasePreparing ? 0 : generation;
}

inline bool DriverWorkerLeaseShouldRun(const DriverWorkerLease* lease, u64 generation)
{
    return lease != nullptr && generation != 0 &&
           worker_lease_detail::LoadAcquire(&lease->active_generation) == generation &&
           worker_lease_detail::LoadAcquire(&lease->retire_generation) != generation;
}

inline bool DriverWorkerLeaseRequestRetire(DriverWorkerLease* lease, u64 generation)
{
    if (lease == nullptr || generation == 0 ||
        worker_lease_detail::LoadAcquire(&lease->active_generation) != generation)
        return false;
    worker_lease_detail::StoreRelease(&lease->retire_generation, generation);
    return true;
}

inline bool DriverWorkerLeaseAcknowledge(DriverWorkerLease* lease, u64 generation)
{
    if (lease == nullptr || generation == 0 ||
        worker_lease_detail::LoadAcquire(&lease->active_generation) != generation ||
        worker_lease_detail::LoadAcquire(&lease->retire_generation) != generation)
        return false;
    worker_lease_detail::StoreRelease(&lease->acknowledged_generation, generation);
    return true;
}

inline bool DriverWorkerLeaseIsAcknowledged(const DriverWorkerLease* lease, u64 generation)
{
    return lease != nullptr && generation != 0 &&
           worker_lease_detail::LoadAcquire(&lease->acknowledged_generation) == generation;
}

/// Release a retired generation for reuse. Refuses early release and stale
/// generation receipts; successful release is the owner's join point.
inline bool DriverWorkerLeaseRelease(DriverWorkerLease* lease, u64 generation)
{
    if (!DriverWorkerLeaseIsAcknowledged(lease, generation))
        return false;
    u64 expected = generation;
    return worker_lease_detail::CompareExchange(&lease->active_generation, &expected, 0);
}

} // namespace duetos::drivers::net
