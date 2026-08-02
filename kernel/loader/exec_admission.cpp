#include "loader/exec_admission.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

namespace duetos::loader
{

namespace
{

constexpr u64 kU64Max = ~static_cast<u64>(0);

bool LockIsCanonicalZero(const ExecAdmission& admission)
{
#if defined(DUETOS_HOST_TEST)
    return admission.lock.next_ticket == 0 && admission.lock.now_serving == 0;
#else
    return admission.lock.next_ticket == 0 && admission.lock.now_serving == 0 && admission.lock.owner_cpu == 0 &&
           admission.lock.class_id == sync::kLockClassUnclassified;
#endif
}

bool LockIsQuiescent(const ExecAdmission& admission)
{
#if defined(DUETOS_HOST_TEST)
    return admission.lock.next_ticket == admission.lock.now_serving;
#else
    return admission.lock.next_ticket == admission.lock.now_serving && admission.lock.owner_cpu == 0xFFFFFFFFU;
#endif
}

void ResetLockCanonicalZero(ExecAdmission* admission)
{
    admission->lock.next_ticket = 0;
    admission->lock.now_serving = 0;
#if !defined(DUETOS_HOST_TEST)
    admission->lock.owner_cpu = 0;
    admission->lock.class_id = sync::kLockClassUnclassified;
#endif
}

bool AdmissionIsCanonicalZero(const ExecAdmission& admission)
{
    return LockIsCanonicalZero(admission) && admission.storage == nullptr && admission.storage_capacity == 0 &&
           admission.frozen_bytes == 0 && admission.initialized == 0 &&
           admission.state == ExecAdmissionState::Uninitialized && admission.cancel_requested == 0 &&
           admission.identity_exhausted == 0 && admission.reserved == 0 && admission.next_identity == 0 &&
           admission.active_identity == 0 && admission.retired_identity == 0;
}

#if defined(DUETOS_HOST_TEST)
u32 AtomicFetchAdd(u32* value, u32 increment)
{
    return std::atomic_ref<u32>(*value).fetch_add(increment, std::memory_order_acquire);
}

u32 AtomicLoadAcquire(u32* value)
{
    return std::atomic_ref<u32>(*value).load(std::memory_order_acquire);
}

void AtomicStoreRelease(u32* value, u32 next)
{
    std::atomic_ref<u32>(*value).store(next, std::memory_order_release);
}

void CpuRelax()
{
#if defined(_MSC_VER)
    _mm_pause();
#else
    __builtin_ia32_pause();
#endif
}
#endif

class AdmissionGuard
{
  public:
#if defined(DUETOS_HOST_TEST)
    explicit AdmissionGuard(ExecAdmission& admission)
        : m_admission(admission), m_ticket(AtomicFetchAdd(&admission.lock.next_ticket, 1))
    {
        while (AtomicLoadAcquire(&admission.lock.now_serving) != m_ticket)
            CpuRelax();
    }

    ~AdmissionGuard() { AtomicStoreRelease(&m_admission.lock.now_serving, m_ticket + 1U); }
#else
    explicit AdmissionGuard(ExecAdmission& admission) : m_guard(admission.lock) {}
    ~AdmissionGuard() = default;
#endif

    AdmissionGuard(const AdmissionGuard&) = delete;
    AdmissionGuard& operator=(const AdmissionGuard&) = delete;
    AdmissionGuard(AdmissionGuard&&) = delete;
    AdmissionGuard& operator=(AdmissionGuard&&) = delete;

  private:
#if defined(DUETOS_HOST_TEST)
    ExecAdmission& m_admission;
    u32 m_ticket;
#else
    sync::SpinLockGuard m_guard;
#endif
};

bool PointerRangeIsValid(const void* pointer, u64 bytes)
{
    if (pointer == nullptr || bytes == 0)
        return false;
    const uptr begin = reinterpret_cast<uptr>(pointer);
    return static_cast<uptr>(bytes) <= ~static_cast<uptr>(0) - begin;
}

bool PointerRangesOverlap(const void* left, u64 left_bytes, const void* right, u64 right_bytes)
{
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    const uptr left_end = left_begin + static_cast<uptr>(left_bytes);
    const uptr right_end = right_begin + static_cast<uptr>(right_bytes);
    return left_begin < right_end && right_begin < left_end;
}

void CopyBytes(u8* destination, const u8* source, u32 bytes)
{
    for (u32 index = 0; index < bytes; ++index)
        destination[index] = source[index];
}

void CopyHash(Hash256* destination, const Hash256& source)
{
    for (u32 index = 0; index < 32; ++index)
        destination->bytes[index] = source.bytes[index];
}

bool StateIsValid(const ExecAdmission& admission)
{
    if (admission.initialized != 1 || admission.storage == nullptr ||
        admission.storage_capacity != kExecAdmissionMaxPlanBytes || admission.next_identity == 0 ||
        admission.cancel_requested > 1 || admission.identity_exhausted > 1)
    {
        return false;
    }

    switch (admission.state)
    {
    case ExecAdmissionState::Idle:
        return admission.active_identity == 0 && admission.frozen_bytes == 0 && admission.cancel_requested == 0;
    case ExecAdmissionState::Copying:
    case ExecAdmissionState::Prepared:
        return admission.active_identity != 0 && admission.frozen_bytes != 0 &&
               admission.frozen_bytes <= admission.storage_capacity && admission.cancel_requested <= 1;
    case ExecAdmissionState::Validating:
        return admission.active_identity != 0 && admission.frozen_bytes != 0 &&
               admission.frozen_bytes <= admission.storage_capacity;
    case ExecAdmissionState::Consumed:
        return admission.active_identity == 0 && admission.retired_identity != 0 && admission.frozen_bytes != 0 &&
               admission.frozen_bytes <= admission.storage_capacity && admission.cancel_requested == 0;
    case ExecAdmissionState::Poisoned:
        return admission.active_identity == 0 && admission.frozen_bytes == 0 && admission.cancel_requested == 0 &&
               admission.identity_exhausted == 1;
    case ExecAdmissionState::Uninitialized:
        return false;
    }
    return false;
}

ExecAdmissionStatus TokenFailure(const ExecAdmission& admission, u64 token)
{
    if (token != 0 && token == admission.retired_identity)
        return ExecAdmissionStatus::TokenReplayed;
    return ExecAdmissionStatus::StaleToken;
}

void RetireAttempt(ExecAdmission& admission)
{
    admission.retired_identity = admission.active_identity;
    admission.active_identity = 0;
    admission.frozen_bytes = 0;
    admission.cancel_requested = 0;
    admission.state = admission.identity_exhausted != 0 ? ExecAdmissionState::Poisoned : ExecAdmissionState::Idle;
}

ExecAdmissionPrepareResult PrepareFailure(ExecAdmissionStatus status)
{
    return ExecAdmissionPrepareResult{status, 0};
}

ExecAdmissionConsumeResult ConsumeFailure(ExecAdmissionStatus status,
                                          LoadPlanValidationError validation_error = LoadPlanValidationError::Ok)
{
    return ExecAdmissionConsumeResult{status, validation_error};
}

} // namespace

ExecAdmissionStatus ExecAdmissionInitialize(ExecAdmission* admission, void* storage, u32 storage_bytes,
                                            u64 first_identity)
{
    if (admission == nullptr || first_identity == 0)
        return ExecAdmissionStatus::InvalidArgument;
    if (storage_bytes < kExecAdmissionMaxPlanBytes)
        return ExecAdmissionStatus::StorageTooSmall;
    if (!PointerRangeIsValid(storage, kExecAdmissionMaxPlanBytes) ||
        PointerRangesOverlap(admission, sizeof(ExecAdmission), storage, kExecAdmissionMaxPlanBytes))
    {
        return ExecAdmissionStatus::InvalidArgument;
    }
    if (!AdmissionIsCanonicalZero(*admission))
        return ExecAdmissionStatus::CorruptState;

#if defined(DUETOS_HOST_TEST)
    admission->lock.next_ticket = 0;
    admission->lock.now_serving = 0;
#else
    admission->lock.next_ticket = 0;
    admission->lock.now_serving = 0;
    admission->lock.owner_cpu = 0xFFFFFFFFU;
    admission->lock.class_id = sync::kLockClassUnclassified;
#endif
    admission->storage = static_cast<u8*>(storage);
    admission->storage_capacity = kExecAdmissionMaxPlanBytes;
    admission->frozen_bytes = 0;
    admission->initialized = 1;
    admission->state = ExecAdmissionState::Idle;
    admission->cancel_requested = 0;
    admission->identity_exhausted = 0;
    admission->reserved = 0;
    admission->next_identity = first_identity;
    admission->active_identity = 0;
    admission->retired_identity = 0;
    return ExecAdmissionStatus::Ok;
}

ExecAdmissionStatus ExecAdmissionQuiescentSuccessorIdentity(const ExecAdmission* admission, u64* first_identity_out)
{
    if (admission == nullptr || first_identity_out == nullptr ||
        !PointerRangeIsValid(first_identity_out, sizeof(*first_identity_out)) ||
        PointerRangesOverlap(first_identity_out, sizeof(*first_identity_out), admission, sizeof(*admission)))
    {
        return ExecAdmissionStatus::InvalidArgument;
    }
    if (admission->initialized == 0)
        return ExecAdmissionStatus::NotInitialized;
    if (!PointerRangeIsValid(admission->storage, admission->storage_capacity))
        return ExecAdmissionStatus::CorruptState;
    if (PointerRangesOverlap(first_identity_out, sizeof(*first_identity_out), admission->storage,
                             admission->storage_capacity))
    {
        return ExecAdmissionStatus::AliasedBuffer;
    }
    if (!LockIsQuiescent(*admission) || admission->active_identity != 0 || admission->cancel_requested != 0)
        return ExecAdmissionStatus::NotQuiescent;
    if (!StateIsValid(*admission))
        return ExecAdmissionStatus::CorruptState;
    if (admission->state == ExecAdmissionState::Poisoned || admission->identity_exhausted != 0)
        return ExecAdmissionStatus::IdentityExhausted;
    if (admission->state != ExecAdmissionState::Idle && admission->state != ExecAdmissionState::Consumed)
        return ExecAdmissionStatus::NotQuiescent;

    *first_identity_out = admission->next_identity;
    return ExecAdmissionStatus::Ok;
}

ExecAdmissionStatus ExecAdmissionCanResetQuiescent(const ExecAdmission* admission)
{
    if (admission == nullptr)
        return ExecAdmissionStatus::InvalidArgument;
    if (AdmissionIsCanonicalZero(*admission))
        return ExecAdmissionStatus::Ok;
    if (admission->initialized == 0)
        return ExecAdmissionStatus::CorruptState;
    if (!LockIsQuiescent(*admission) || admission->active_identity != 0 || admission->cancel_requested != 0)
        return ExecAdmissionStatus::NotQuiescent;
    if (!StateIsValid(*admission))
        return ExecAdmissionStatus::CorruptState;
    if (admission->state != ExecAdmissionState::Idle && admission->state != ExecAdmissionState::Consumed &&
        admission->state != ExecAdmissionState::Poisoned)
    {
        return ExecAdmissionStatus::NotQuiescent;
    }
    if (!PointerRangeIsValid(admission->storage, admission->storage_capacity) ||
        PointerRangesOverlap(admission, sizeof(*admission), admission->storage, admission->storage_capacity))
    {
        return ExecAdmissionStatus::CorruptState;
    }

    return ExecAdmissionStatus::Ok;
}

ExecAdmissionStatus ExecAdmissionResetQuiescent(ExecAdmission* admission)
{
    const ExecAdmissionStatus validation = ExecAdmissionCanResetQuiescent(admission);
    if (validation != ExecAdmissionStatus::Ok)
        return validation;
    if (AdmissionIsCanonicalZero(*admission))
        return ExecAdmissionStatus::Ok;

    u8* const storage = admission->storage;
    const u32 storage_capacity = admission->storage_capacity;
    for (u32 index = 0; index < storage_capacity; ++index)
        storage[index] = 0;

    admission->storage = nullptr;
    admission->storage_capacity = 0;
    admission->frozen_bytes = 0;
    admission->initialized = 0;
    admission->state = ExecAdmissionState::Uninitialized;
    admission->cancel_requested = 0;
    admission->identity_exhausted = 0;
    admission->reserved = 0;
    admission->next_identity = 0;
    admission->active_identity = 0;
    admission->retired_identity = 0;
    ResetLockCanonicalZero(admission);
    return ExecAdmissionStatus::Ok;
}

ExecAdmissionPrepareResult ExecAdmissionPrepare(ExecAdmission* admission, const void* plan_bytes, u64 byte_count)
{
    if (admission == nullptr || plan_bytes == nullptr || byte_count == 0)
        return PrepareFailure(ExecAdmissionStatus::InvalidArgument);
    if (admission->initialized == 0)
        return PrepareFailure(ExecAdmissionStatus::NotInitialized);
    if (byte_count > kExecAdmissionMaxPlanBytes)
        return PrepareFailure(ExecAdmissionStatus::PlanTooLarge);
    if (!PointerRangeIsValid(plan_bytes, byte_count) ||
        PointerRangesOverlap(plan_bytes, byte_count, admission, sizeof(ExecAdmission)) ||
        PointerRangesOverlap(plan_bytes, byte_count, admission->storage, admission->storage_capacity))
    {
        return PrepareFailure(ExecAdmissionStatus::AliasedBuffer);
    }

    u64 token = 0;
    {
        AdmissionGuard guard(*admission);
        if (!StateIsValid(*admission))
            return PrepareFailure(ExecAdmissionStatus::CorruptState);
        if (admission->state == ExecAdmissionState::Consumed)
            return PrepareFailure(ExecAdmissionStatus::Terminal);
        if (admission->state == ExecAdmissionState::Poisoned || admission->identity_exhausted != 0)
            return PrepareFailure(ExecAdmissionStatus::IdentityExhausted);
        if (admission->state != ExecAdmissionState::Idle)
            return PrepareFailure(ExecAdmissionStatus::Busy);

        token = admission->next_identity;
        if (token == kU64Max)
            admission->identity_exhausted = 1;
        else
            admission->next_identity = token + 1;

        admission->active_identity = token;
        admission->frozen_bytes = static_cast<u32>(byte_count);
        admission->cancel_requested = 0;
        admission->state = ExecAdmissionState::Copying;
    }

    // The source may change immediately after this loop. Only the frozen
    // destination is decoded later; no header pre-read can create a TOCTOU gap.
    CopyBytes(admission->storage, static_cast<const u8*>(plan_bytes), static_cast<u32>(byte_count));

    {
        AdmissionGuard guard(*admission);
        if (!StateIsValid(*admission) || admission->state != ExecAdmissionState::Copying ||
            admission->active_identity != token)
        {
            return PrepareFailure(ExecAdmissionStatus::CorruptState);
        }
        if (admission->cancel_requested != 0)
        {
            RetireAttempt(*admission);
            return PrepareFailure(ExecAdmissionStatus::Cancelled);
        }
        admission->state = ExecAdmissionState::Prepared;
    }
    return ExecAdmissionPrepareResult{ExecAdmissionStatus::Ok, token};
}

ExecAdmissionConsumeResult ExecAdmissionConsume(ExecAdmission* admission, u64 token,
                                                const Hash256* expected_source_hash, LoadBackingQueryV1 query_backing,
                                                void* query_context, LoadPlanViewV1* view_out)
{
    if (view_out == nullptr)
        return ConsumeFailure(ExecAdmissionStatus::InvalidArgument);
    if (!PointerRangeIsValid(view_out, sizeof(LoadPlanViewV1)))
        return ConsumeFailure(ExecAdmissionStatus::InvalidArgument);
    if (admission == nullptr)
    {
        *view_out = LoadPlanViewV1{};
        return ConsumeFailure(ExecAdmissionStatus::InvalidArgument);
    }
    if (PointerRangesOverlap(view_out, sizeof(LoadPlanViewV1), admission, sizeof(ExecAdmission)))
    {
        return ConsumeFailure(ExecAdmissionStatus::AliasedBuffer);
    }
    if (admission->initialized == 0)
    {
        *view_out = LoadPlanViewV1{};
        return ConsumeFailure(ExecAdmissionStatus::NotInitialized);
    }
    if (!PointerRangeIsValid(admission->storage, admission->storage_capacity))
    {
        *view_out = LoadPlanViewV1{};
        return ConsumeFailure(ExecAdmissionStatus::CorruptState);
    }
    if (PointerRangesOverlap(view_out, sizeof(LoadPlanViewV1), admission->storage, admission->storage_capacity))
        return ConsumeFailure(ExecAdmissionStatus::AliasedBuffer);

    if (token == 0)
    {
        *view_out = LoadPlanViewV1{};
        return ConsumeFailure(ExecAdmissionStatus::InvalidArgument);
    }

    Hash256 expected_hash_snapshot{};
    const Hash256* expected_hash = nullptr;
    if (expected_source_hash != nullptr)
    {
        if (!PointerRangeIsValid(expected_source_hash, sizeof(Hash256)))
        {
            *view_out = LoadPlanViewV1{};
            return ConsumeFailure(ExecAdmissionStatus::InvalidArgument);
        }
        if (PointerRangesOverlap(expected_source_hash, sizeof(Hash256), admission, sizeof(ExecAdmission)) ||
            PointerRangesOverlap(expected_source_hash, sizeof(Hash256), admission->storage,
                                 admission->storage_capacity))
        {
            *view_out = LoadPlanViewV1{};
            return ConsumeFailure(ExecAdmissionStatus::AliasedBuffer);
        }
        // Snapshot before clearing the output so even a caller that reuses
        // one buffer for trusted input and result cannot change the decision.
        CopyHash(&expected_hash_snapshot, *expected_source_hash);
        expected_hash = &expected_hash_snapshot;
    }
    *view_out = LoadPlanViewV1{};

    const u8* frozen_plan = nullptr;
    u32 frozen_bytes = 0;
    {
        AdmissionGuard guard(*admission);
        if (!StateIsValid(*admission))
            return ConsumeFailure(ExecAdmissionStatus::CorruptState);
        if (admission->active_identity != token)
            return ConsumeFailure(TokenFailure(*admission, token));
        if (admission->state != ExecAdmissionState::Prepared)
            return ConsumeFailure(ExecAdmissionStatus::Busy);

        admission->state = ExecAdmissionState::Validating;
        frozen_plan = admission->storage;
        frozen_bytes = admission->frozen_bytes;
    }

    // Both trusted metadata and the hostile plan now have one stable snapshot
    // for the complete validation pass. The authority callback deliberately
    // runs after releasing the admission lock and may request cancellation.
    LoadPlanViewV1 validated_view{};
    const LoadPlanValidationError validation_error =
        LoadPlanValidateV1(frozen_plan, frozen_bytes, expected_hash, query_backing, query_context, &validated_view);

    {
        AdmissionGuard guard(*admission);
        if (!StateIsValid(*admission) || admission->state != ExecAdmissionState::Validating ||
            admission->active_identity != token || admission->storage != frozen_plan ||
            admission->frozen_bytes != frozen_bytes)
        {
            return ConsumeFailure(ExecAdmissionStatus::CorruptState);
        }
        if (admission->cancel_requested != 0)
        {
            RetireAttempt(*admission);
            return ConsumeFailure(ExecAdmissionStatus::Cancelled);
        }
        if (validation_error != LoadPlanValidationError::Ok)
        {
            RetireAttempt(*admission);
            return ConsumeFailure(ExecAdmissionStatus::PlanRejected, validation_error);
        }
        if (validated_view.bytes != frozen_plan || validated_view.size != frozen_bytes)
        {
            RetireAttempt(*admission);
            return ConsumeFailure(ExecAdmissionStatus::CorruptState);
        }

        admission->retired_identity = token;
        admission->active_identity = 0;
        admission->cancel_requested = 0;
        admission->state = ExecAdmissionState::Consumed;
        *view_out = validated_view;
    }
    return ExecAdmissionConsumeResult{ExecAdmissionStatus::Ok, LoadPlanValidationError::Ok};
}

ExecAdmissionStatus ExecAdmissionCancel(ExecAdmission* admission, u64 token)
{
    if (admission == nullptr || token == 0)
        return ExecAdmissionStatus::InvalidArgument;
    if (admission->initialized == 0)
        return ExecAdmissionStatus::NotInitialized;

    AdmissionGuard guard(*admission);
    if (!StateIsValid(*admission))
        return ExecAdmissionStatus::CorruptState;
    if (admission->active_identity != token)
        return TokenFailure(*admission, token);

    switch (admission->state)
    {
    case ExecAdmissionState::Prepared:
        RetireAttempt(*admission);
        return ExecAdmissionStatus::Ok;
    case ExecAdmissionState::Copying:
    case ExecAdmissionState::Validating:
        admission->cancel_requested = 1;
        return ExecAdmissionStatus::CancelPending;
    case ExecAdmissionState::Idle:
    case ExecAdmissionState::Consumed:
    case ExecAdmissionState::Poisoned:
        return TokenFailure(*admission, token);
    case ExecAdmissionState::Uninitialized:
        return ExecAdmissionStatus::NotInitialized;
    }
    return ExecAdmissionStatus::CorruptState;
}

const char* ExecAdmissionStatusName(ExecAdmissionStatus status)
{
    switch (status)
    {
    case ExecAdmissionStatus::Ok:
        return "ok";
    case ExecAdmissionStatus::InvalidArgument:
        return "invalid-argument";
    case ExecAdmissionStatus::NotInitialized:
        return "not-initialized";
    case ExecAdmissionStatus::StorageTooSmall:
        return "storage-too-small";
    case ExecAdmissionStatus::AliasedBuffer:
        return "aliased-buffer";
    case ExecAdmissionStatus::Busy:
        return "busy";
    case ExecAdmissionStatus::Terminal:
        return "terminal";
    case ExecAdmissionStatus::PlanTooLarge:
        return "plan-too-large";
    case ExecAdmissionStatus::StaleToken:
        return "stale-token";
    case ExecAdmissionStatus::TokenReplayed:
        return "token-replayed";
    case ExecAdmissionStatus::IdentityExhausted:
        return "identity-exhausted";
    case ExecAdmissionStatus::CancelPending:
        return "cancel-pending";
    case ExecAdmissionStatus::Cancelled:
        return "cancelled";
    case ExecAdmissionStatus::PlanRejected:
        return "plan-rejected";
    case ExecAdmissionStatus::CorruptState:
        return "corrupt-state";
    case ExecAdmissionStatus::NotQuiescent:
        return "not-quiescent";
    }
    return "unknown";
}

} // namespace duetos::loader
