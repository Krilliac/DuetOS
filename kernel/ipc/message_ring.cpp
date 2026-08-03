#include "ipc/message_ring.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

namespace duetos::ipc
{

namespace
{

constexpr u32 kRecordSequenceOffset = 0;
constexpr u32 kRecordFrameSizeOffset = 8;
constexpr u32 kRecordReservedOffset = 12;
constexpr u64 kU64Max = ~static_cast<u64>(0);
constexpr u32 kRingStateUninitialized = 0;
constexpr u32 kRingStateInitializing = 1;
constexpr u32 kRingStateReady = 2;

u32 AtomicLoadAcquire(u32* value)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u32>(*value).load(std::memory_order_acquire);
#else
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
#endif
}

void AtomicStoreRelease(u32* value, u32 next)
{
#if defined(DUETOS_HOST_TEST)
    std::atomic_ref<u32>(*value).store(next, std::memory_order_release);
#else
    __atomic_store_n(value, next, __ATOMIC_RELEASE);
#endif
}

bool AtomicCompareExchangeState(u32* value, u32* expected, u32 desired)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u32>(*value).compare_exchange_strong(*expected, desired, std::memory_order_acq_rel,
                                                                std::memory_order_acquire);
#else
    return __atomic_compare_exchange_n(value, expected, desired, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#endif
}

#if defined(DUETOS_HOST_TEST)
u32 AtomicFetchAdd(u32* value, u32 increment)
{
    return std::atomic_ref<u32>(*value).fetch_add(increment, std::memory_order_acquire);
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

class RingGuard
{
  public:
#if defined(DUETOS_HOST_TEST)
    explicit RingGuard(MessageRing& ring) : m_ring(ring), m_ticket(AtomicFetchAdd(&ring.lock.next_ticket, 1))
    {
        while (AtomicLoadAcquire(&ring.lock.now_serving) != m_ticket)
            CpuRelax();
    }

    ~RingGuard() { AtomicStoreRelease(&m_ring.lock.now_serving, m_ticket + 1U); }
#else
    explicit RingGuard(MessageRing& ring) : m_guard(ring.lock) {}
    ~RingGuard() = default;
#endif

    RingGuard(const RingGuard&) = delete;
    RingGuard& operator=(const RingGuard&) = delete;
    RingGuard(RingGuard&&) = delete;
    RingGuard& operator=(RingGuard&&) = delete;

  private:
#if defined(DUETOS_HOST_TEST)
    MessageRing& m_ring;
    u32 m_ticket;
#else
    sync::SpinLockGuard m_guard;
#endif
};

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | (static_cast<u32>(bytes[1]) << 8U) | (static_cast<u32>(bytes[2]) << 16U) |
           (static_cast<u32>(bytes[3]) << 24U);
}

u64 ReadLe64(const u8* bytes)
{
    return static_cast<u64>(ReadLe32(bytes)) | (static_cast<u64>(ReadLe32(bytes + 4)) << 32U);
}

void WriteLe32(u8* bytes, u32 value)
{
    bytes[0] = static_cast<u8>(value & 0xFFU);
    bytes[1] = static_cast<u8>((value >> 8U) & 0xFFU);
    bytes[2] = static_cast<u8>((value >> 16U) & 0xFFU);
    bytes[3] = static_cast<u8>((value >> 24U) & 0xFFU);
}

void WriteLe64(u8* bytes, u64 value)
{
    WriteLe32(bytes, static_cast<u32>(value & 0xFFFFFFFFULL));
    WriteLe32(bytes + 4, static_cast<u32>(value >> 32U));
}

bool PointerRangeIsValid(const void* pointer, u32 bytes)
{
    if (pointer == nullptr)
        return false;
    const uptr begin = reinterpret_cast<uptr>(pointer);
    return static_cast<uptr>(bytes) <= kU64Max - begin;
}

bool PointerRangesOverlap(const void* left, u32 left_bytes, const void* right, u32 right_bytes)
{
    if (left == nullptr || right == nullptr || left_bytes == 0 || right_bytes == 0)
        return false;
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    return left_begin <= right_begin ? right_begin - left_begin < left_bytes : left_begin - right_begin < right_bytes;
}

bool RingIsReady(MessageRing* ring)
{
    return ring != nullptr && AtomicLoadAcquire(&ring->initialized) == kRingStateReady;
}

u32 AdvanceOffset(u32 offset, u32 bytes, u32 capacity)
{
    const u32 remaining = capacity - offset;
    if (bytes < remaining)
        return offset + bytes;
    if (bytes == remaining)
        return 0;
    return bytes - remaining;
}

void CopyIntoStorage(MessageRing& ring, u32 offset, const u8* source, u32 bytes)
{
    u32 remaining = bytes;
    u32 source_offset = 0;
    u32 target_offset = offset;
    while (remaining != 0)
    {
        const u32 contiguous = ring.capacity_bytes - target_offset;
        const u32 chunk = remaining < contiguous ? remaining : contiguous;
        for (u32 index = 0; index < chunk; ++index)
            ring.storage[target_offset + index] = source[source_offset + index];
        remaining -= chunk;
        source_offset += chunk;
        target_offset = remaining == 0 ? target_offset : 0;
    }
}

void CopyFromStorage(const MessageRing& ring, u32 offset, u8* destination, u32 bytes)
{
    u32 remaining = bytes;
    u32 destination_offset = 0;
    u32 source_offset = offset;
    while (remaining != 0)
    {
        const u32 contiguous = ring.capacity_bytes - source_offset;
        const u32 chunk = remaining < contiguous ? remaining : contiguous;
        for (u32 index = 0; index < chunk; ++index)
            destination[destination_offset + index] = ring.storage[source_offset + index];
        remaining -= chunk;
        destination_offset += chunk;
        source_offset = remaining == 0 ? source_offset : 0;
    }
}

void CopyBytes(u8* destination, const u8* source, u32 bytes)
{
    for (u32 index = 0; index < bytes; ++index)
        destination[index] = source[index];
}

bool StateIsValid(const MessageRing& ring)
{
    if (ring.storage == nullptr || ring.capacity_bytes < kMessageRingMinimumStorageBytes)
        return false;
    if (ring.head_offset >= ring.capacity_bytes || ring.tail_offset >= ring.capacity_bytes ||
        ring.used_bytes > ring.capacity_bytes)
    {
        return false;
    }
    if ((ring.queued_frames == 0) != (ring.used_bytes == 0))
        return false;
    if (ring.queued_frames != 0 && ring.used_bytes < kMessageRingMinimumStorageBytes)
        return false;
    if (ring.receive_sequence == 0)
    {
        if (ring.receive_lease_id != 0 || ring.receive_frame_size != 0 || ring.receive_copy_id != 0 ||
            ring.receive_copy_succeeded_id != 0)
            return false;
    }
    else if (ring.queued_frames == 0 || ring.receive_lease_id == 0 ||
             ring.receive_frame_size < kMessageAbiHeaderV1Bytes)
    {
        return false;
    }
    if (ring.receive_copy_id != 0 && ring.receive_copy_succeeded_id != 0)
        return false;
    if (ring.next_receive_lease_id == 0 || ring.next_copy_id == 0 || ring.receive_lease_exhausted > 1 ||
        ring.copy_id_exhausted > 1)
        return false;

    if (ring.producer_reservation_id == 0)
    {
        if (ring.producer_record_bytes != 0 || ring.producer_frame_size != 0 || ring.producer_copy_active != 0 ||
            ring.producer_abort_requested != 0)
        {
            return false;
        }
    }
    else
    {
        if (ring.producer_tail_offset != ring.tail_offset ||
            ring.producer_record_bytes != kMessageRingRecordHeaderBytes + ring.producer_frame_size ||
            ring.producer_frame_size < kMessageAbiHeaderV1Bytes ||
            ring.producer_record_bytes > ring.capacity_bytes - ring.used_bytes)
        {
            return false;
        }
    }
    return true;
}

void ClearProducer(MessageRing& ring)
{
    ring.producer_reservation_id = 0;
    ring.producer_tail_offset = 0;
    ring.producer_record_bytes = 0;
    ring.producer_frame_size = 0;
    ring.producer_copy_active = 0;
    ring.producer_abort_requested = 0;
}

void ClearReceiver(MessageRing& ring)
{
    ring.receive_sequence = 0;
    ring.receive_lease_id = 0;
    ring.receive_frame_size = 0;
    ring.receive_copy_id = 0;
    ring.receive_copy_succeeded_id = 0;
}

struct HeadRecord
{
    u64 sequence;
    u32 frame_size;
    u32 record_size;
};

bool ReadHeadRecord(const MessageRing& ring, HeadRecord* record_out)
{
    if (record_out == nullptr || ring.queued_frames == 0 || ring.used_bytes < kMessageRingRecordHeaderBytes)
        return false;

    u8 header[kMessageRingRecordHeaderBytes]{};
    CopyFromStorage(ring, ring.head_offset, header, kMessageRingRecordHeaderBytes);
    const u64 sequence = ReadLe64(header + kRecordSequenceOffset);
    const u32 frame_size = ReadLe32(header + kRecordFrameSizeOffset);
    const u32 reserved = ReadLe32(header + kRecordReservedOffset);
    if (sequence == 0 || reserved != 0 || frame_size < kMessageAbiHeaderV1Bytes || frame_size > kMessageAbiMaxBytes)
        return false;

    const u32 record_size = kMessageRingRecordHeaderBytes + frame_size;
    if (record_size > ring.used_bytes || record_size > ring.capacity_bytes)
        return false;
    *record_out = HeadRecord{sequence, frame_size, record_size};
    return true;
}

MessageRingEnqueueResult EnqueueFailure(MessageRingStatus status, MessageValidationError message_error,
                                        PayloadValidationError payload_error)
{
    return MessageRingEnqueueResult{status, 0, 0, message_error, payload_error};
}

} // namespace

MessageRingStatus MessageRingInitialize(MessageRing* ring, void* storage, u32 storage_bytes, u64 first_sequence)
{
    if (ring == nullptr || first_sequence == 0 || storage_bytes < kMessageRingMinimumStorageBytes ||
        !PointerRangeIsValid(storage, storage_bytes) ||
        PointerRangesOverlap(ring, static_cast<u32>(sizeof(MessageRing)), storage, storage_bytes))
    {
        return MessageRingStatus::InvalidArgument;
    }

    u32 expected_state = kRingStateUninitialized;
    if (!AtomicCompareExchangeState(&ring->initialized, &expected_state, kRingStateInitializing))
        return MessageRingStatus::AlreadyInitialized;

#if defined(DUETOS_HOST_TEST)
    ring->lock.next_ticket = 0;
    ring->lock.now_serving = 0;
#else
    ring->lock.next_ticket = 0;
    ring->lock.now_serving = 0;
    ring->lock.owner_cpu = 0;
    ring->lock.class_id = sync::kLockClassUnclassified;
#endif
    ring->storage = static_cast<u8*>(storage);
    ring->capacity_bytes = storage_bytes;
    ring->head_offset = 0;
    ring->tail_offset = 0;
    ring->used_bytes = 0;
    ring->queued_frames = 0;
    ring->next_sequence = first_sequence;
    ring->sequence_exhausted = 0;
    ring->next_reservation_id = 1;
    ring->reservation_exhausted = 0;
    ring->next_receive_lease_id = 1;
    ring->receive_lease_exhausted = 0;
    ring->next_copy_id = 1;
    ring->copy_id_exhausted = 0;
    ClearProducer(*ring);
    ClearReceiver(*ring);
    AtomicStoreRelease(&ring->initialized, kRingStateReady);
    return MessageRingStatus::Ok;
}

MessageRingEnqueueResult MessageRingPrepareEnqueue(MessageRing* ring, const void* frame, u32 frame_bytes,
                                                   const PayloadVersionRule* payload_rules, u32 payload_rule_count)
{
    if (ring == nullptr || frame == nullptr || frame_bytes == 0)
        return EnqueueFailure(MessageRingStatus::InvalidArgument, MessageValidationError::Ok,
                              PayloadValidationError::Ok);
    if (!RingIsReady(ring))
        return EnqueueFailure(MessageRingStatus::NotInitialized, MessageValidationError::Ok,
                              PayloadValidationError::Ok);
    if (!PointerRangeIsValid(frame, frame_bytes) ||
        PointerRangesOverlap(frame, frame_bytes, ring->storage, ring->capacity_bytes) ||
        PointerRangesOverlap(frame, frame_bytes, ring, static_cast<u32>(sizeof(MessageRing))))
    {
        return EnqueueFailure(MessageRingStatus::AliasedBuffer, MessageValidationError::Ok, PayloadValidationError::Ok);
    }

    const bool has_rules = payload_rules != nullptr;
    const bool has_rule_count = payload_rule_count != 0;
    if (has_rules != has_rule_count || payload_rule_count > kVersionedPayloadMaxRules)
    {
        return EnqueueFailure(MessageRingStatus::InvalidPayloadContract, MessageValidationError::Ok,
                              PayloadValidationError::InvalidRuleTable);
    }
    if (has_rules)
    {
        const u32 rule_bytes = payload_rule_count * static_cast<u32>(sizeof(PayloadVersionRule));
        if (!PointerRangeIsValid(payload_rules, rule_bytes))
        {
            return EnqueueFailure(MessageRingStatus::InvalidPayloadContract, MessageValidationError::Ok,
                                  PayloadValidationError::InvalidRuleTable);
        }
        if (PointerRangesOverlap(payload_rules, rule_bytes, frame, frame_bytes) ||
            PointerRangesOverlap(payload_rules, rule_bytes, ring->storage, ring->capacity_bytes) ||
            PointerRangesOverlap(payload_rules, rule_bytes, ring, static_cast<u32>(sizeof(MessageRing))))
        {
            return EnqueueFailure(MessageRingStatus::AliasedBuffer, MessageValidationError::Ok,
                                  PayloadValidationError::Ok);
        }
    }

    MessageView message_view{};
    const MessageValidationError message_error = MessageValidate(frame, frame_bytes, &message_view);
    if (message_error != MessageValidationError::Ok)
        return EnqueueFailure(MessageRingStatus::MalformedMessage, message_error, PayloadValidationError::Ok);

    if (message_view.payload_size == 0)
    {
        if (has_rules)
        {
            const auto* payload_end = static_cast<const u8*>(frame) + message_view.header_size;
            const PayloadValidationError payload_error =
                PayloadValidate(payload_end, 0, payload_rules, payload_rule_count, nullptr);
            return EnqueueFailure(MessageRingStatus::MalformedPayload, MessageValidationError::Ok, payload_error);
        }
    }
    else
    {
        if (!has_rules)
            return EnqueueFailure(MessageRingStatus::MissingPayloadContract, MessageValidationError::Ok,
                                  PayloadValidationError::InvalidRuleTable);
        const auto* payload = static_cast<const u8*>(frame) + message_view.payload_offset;
        const PayloadValidationError payload_error =
            PayloadValidate(payload, message_view.payload_size, payload_rules, payload_rule_count, nullptr);
        if (payload_error != PayloadValidationError::Ok)
            return EnqueueFailure(MessageRingStatus::MalformedPayload, MessageValidationError::Ok, payload_error);
    }

    const u32 record_bytes = kMessageRingRecordHeaderBytes + frame_bytes;
    u64 reservation_id = 0;
    u32 frame_offset = 0;
    {
        RingGuard guard(*ring);
        if (!StateIsValid(*ring))
            return EnqueueFailure(MessageRingStatus::CorruptState, MessageValidationError::Ok,
                                  PayloadValidationError::Ok);
        if (ring->producer_reservation_id != 0)
            return EnqueueFailure(MessageRingStatus::Busy, MessageValidationError::Ok, PayloadValidationError::Ok);
        if (ring->reservation_exhausted != 0)
            return EnqueueFailure(MessageRingStatus::ReservationExhausted, MessageValidationError::Ok,
                                  PayloadValidationError::Ok);
        if (ring->sequence_exhausted != 0)
            return EnqueueFailure(MessageRingStatus::SequenceExhausted, MessageValidationError::Ok,
                                  PayloadValidationError::Ok);
        if (record_bytes > ring->capacity_bytes - ring->used_bytes)
            return EnqueueFailure(MessageRingStatus::Full, MessageValidationError::Ok, PayloadValidationError::Ok);

        reservation_id = ring->next_reservation_id;
        if (reservation_id == kU64Max)
            ring->reservation_exhausted = 1;
        else
            ring->next_reservation_id = reservation_id + 1;

        ring->producer_reservation_id = reservation_id;
        ring->producer_tail_offset = ring->tail_offset;
        ring->producer_record_bytes = record_bytes;
        ring->producer_frame_size = frame_bytes;
        ring->producer_copy_active = 1;
        ring->producer_abort_requested = 0;
        frame_offset = AdvanceOffset(ring->tail_offset, kMessageRingRecordHeaderBytes, ring->capacity_bytes);
    }

    // The source is a stable kernel buffer, never a faulting user pointer.  The
    // reservation is outside `used_bytes`, so consumers cannot observe it.
    CopyIntoStorage(*ring, frame_offset, static_cast<const u8*>(frame), frame_bytes);

    {
        RingGuard guard(*ring);
        if (!StateIsValid(*ring) || ring->producer_reservation_id != reservation_id || ring->producer_copy_active == 0)
        {
            if (ring->producer_reservation_id == reservation_id)
                ClearProducer(*ring);
            return EnqueueFailure(MessageRingStatus::CorruptState, MessageValidationError::Ok,
                                  PayloadValidationError::Ok);
        }
        ring->producer_copy_active = 0;
        if (ring->producer_abort_requested != 0)
        {
            ClearProducer(*ring);
            return EnqueueFailure(MessageRingStatus::ProducerAborted, MessageValidationError::Ok,
                                  PayloadValidationError::Ok);
        }
    }

    return MessageRingEnqueueResult{MessageRingStatus::Ok, reservation_id, 0, MessageValidationError::Ok,
                                    PayloadValidationError::Ok};
}

MessageRingStatus MessageRingPublishEnqueue(MessageRing* ring, u64 reservation_id, u64* sequence_out)
{
    if (sequence_out != nullptr && !PointerRangeIsValid(sequence_out, static_cast<u32>(sizeof(*sequence_out))))
        return MessageRingStatus::InvalidArgument;
    if (ring != nullptr && sequence_out != nullptr &&
        PointerRangesOverlap(sequence_out, static_cast<u32>(sizeof(*sequence_out)), ring,
                             static_cast<u32>(sizeof(MessageRing))))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    if (ring == nullptr)
    {
        if (sequence_out != nullptr)
            *sequence_out = 0;
        return MessageRingStatus::InvalidArgument;
    }
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;
    if (sequence_out != nullptr && PointerRangesOverlap(sequence_out, static_cast<u32>(sizeof(*sequence_out)),
                                                        ring->storage, ring->capacity_bytes))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    if (reservation_id == 0)
    {
        if (sequence_out != nullptr)
            *sequence_out = 0;
        return MessageRingStatus::InvalidArgument;
    }
    if (sequence_out != nullptr)
        *sequence_out = 0;

    RingGuard guard(*ring);
    if (!StateIsValid(*ring))
        return MessageRingStatus::CorruptState;
    if (ring->producer_reservation_id != reservation_id)
        return MessageRingStatus::StaleReservation;
    if (ring->producer_copy_active != 0)
        return MessageRingStatus::Busy;
    if (ring->producer_abort_requested != 0)
    {
        ClearProducer(*ring);
        return MessageRingStatus::ProducerAborted;
    }
    if (ring->sequence_exhausted != 0)
    {
        ClearProducer(*ring);
        return MessageRingStatus::SequenceExhausted;
    }

    const u64 sequence = ring->next_sequence;
    u8 header[kMessageRingRecordHeaderBytes]{};
    WriteLe64(header + kRecordSequenceOffset, sequence);
    WriteLe32(header + kRecordFrameSizeOffset, ring->producer_frame_size);
    WriteLe32(header + kRecordReservedOffset, 0);
    CopyIntoStorage(*ring, ring->producer_tail_offset, header, kMessageRingRecordHeaderBytes);

    ring->tail_offset = AdvanceOffset(ring->tail_offset, ring->producer_record_bytes, ring->capacity_bytes);
    ring->used_bytes += ring->producer_record_bytes;
    ++ring->queued_frames;
    if (sequence == kU64Max)
        ring->sequence_exhausted = 1;
    else
        ring->next_sequence = sequence + 1;
    ClearProducer(*ring);
    if (sequence_out != nullptr)
        *sequence_out = sequence;
    return MessageRingStatus::Ok;
}

MessageRingStatus MessageRingAbortEnqueue(MessageRing* ring, u64 reservation_id)
{
    if (ring == nullptr || reservation_id == 0)
        return MessageRingStatus::InvalidArgument;
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;

    RingGuard guard(*ring);
    if (!StateIsValid(*ring))
        return MessageRingStatus::CorruptState;
    if (ring->producer_reservation_id != reservation_id)
        return MessageRingStatus::StaleReservation;
    if (ring->producer_copy_active != 0)
    {
        ring->producer_abort_requested = 1;
        return MessageRingStatus::Ok;
    }
    ClearProducer(*ring);
    return MessageRingStatus::Ok;
}

MessageRingEnqueueResult MessageRingEnqueue(MessageRing* ring, const void* frame, u32 frame_bytes,
                                            const PayloadVersionRule* payload_rules, u32 payload_rule_count)
{
    MessageRingEnqueueResult result =
        MessageRingPrepareEnqueue(ring, frame, frame_bytes, payload_rules, payload_rule_count);
    if (result.status != MessageRingStatus::Ok)
        return result;

    u64 sequence = 0;
    result.status = MessageRingPublishEnqueue(ring, result.reservation_id, &sequence);
    if (result.status == MessageRingStatus::Ok)
        result.sequence = sequence;
    else
        (void)MessageRingAbortEnqueue(ring, result.reservation_id);
    return result;
}

MessageRingStatus MessageRingPeek(MessageRing* ring, MessageRingPeekView* view_out)
{
    if (view_out != nullptr && !PointerRangeIsValid(view_out, static_cast<u32>(sizeof(*view_out))))
        return MessageRingStatus::InvalidArgument;
    if (ring != nullptr && view_out != nullptr &&
        PointerRangesOverlap(view_out, static_cast<u32>(sizeof(*view_out)), ring,
                             static_cast<u32>(sizeof(MessageRing))))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    if (ring == nullptr || view_out == nullptr)
        return MessageRingStatus::InvalidArgument;
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;
    if (PointerRangesOverlap(view_out, static_cast<u32>(sizeof(*view_out)), ring->storage, ring->capacity_bytes))
        return MessageRingStatus::AliasedBuffer;
    *view_out = {};

    RingGuard guard(*ring);
    if (!StateIsValid(*ring))
        return MessageRingStatus::CorruptState;
    if (ring->receive_sequence != 0)
        return MessageRingStatus::Busy;
    if (ring->queued_frames == 0)
        return MessageRingStatus::Empty;
    if (ring->receive_lease_exhausted != 0)
        return MessageRingStatus::ReceiveLeaseExhausted;

    HeadRecord record{};
    if (!ReadHeadRecord(*ring, &record))
        return MessageRingStatus::CorruptState;
    const u64 receive_lease_id = ring->next_receive_lease_id;
    if (receive_lease_id == kU64Max)
        ring->receive_lease_exhausted = 1;
    else
        ring->next_receive_lease_id = receive_lease_id + 1;
    ring->receive_sequence = record.sequence;
    ring->receive_lease_id = receive_lease_id;
    ring->receive_frame_size = record.frame_size;
    ring->receive_copy_id = 0;
    ring->receive_copy_succeeded_id = 0;
    *view_out = MessageRingPeekView{record.sequence, receive_lease_id, record.frame_size};
    return MessageRingStatus::Ok;
}

MessageRingStatus MessageRingBeginCopyOut(MessageRing* ring, u64 sequence, u64 receive_lease_id,
                                          MessageRingCopySpans* spans_out)
{
    if (spans_out != nullptr && !PointerRangeIsValid(spans_out, static_cast<u32>(sizeof(*spans_out))))
        return MessageRingStatus::InvalidArgument;
    if (ring != nullptr && spans_out != nullptr &&
        PointerRangesOverlap(spans_out, static_cast<u32>(sizeof(*spans_out)), ring,
                             static_cast<u32>(sizeof(MessageRing))))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    if (ring == nullptr || sequence == 0 || receive_lease_id == 0 || spans_out == nullptr)
        return MessageRingStatus::InvalidArgument;
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;
    if (PointerRangesOverlap(spans_out, static_cast<u32>(sizeof(*spans_out)), ring->storage, ring->capacity_bytes))
        return MessageRingStatus::AliasedBuffer;
    *spans_out = {};

    RingGuard guard(*ring);
    if (!StateIsValid(*ring))
        return MessageRingStatus::CorruptState;
    if (ring->receive_sequence != sequence)
        return MessageRingStatus::StaleSequence;
    if (ring->receive_lease_id != receive_lease_id)
        return MessageRingStatus::StaleReceiveLease;
    if (ring->receive_copy_id != 0)
        return MessageRingStatus::Busy;
    if (ring->copy_id_exhausted != 0)
        return MessageRingStatus::CopyIdExhausted;

    HeadRecord record{};
    if (!ReadHeadRecord(*ring, &record) || record.sequence != sequence || record.frame_size != ring->receive_frame_size)
        return MessageRingStatus::CorruptState;

    const u32 frame_offset = AdvanceOffset(ring->head_offset, kMessageRingRecordHeaderBytes, ring->capacity_bytes);
    const u32 contiguous = ring->capacity_bytes - frame_offset;
    const u32 first_size = record.frame_size < contiguous ? record.frame_size : contiguous;
    const u32 second_size = record.frame_size - first_size;
    const u64 copy_id = ring->next_copy_id;
    if (copy_id == kU64Max)
        ring->copy_id_exhausted = 1;
    else
        ring->next_copy_id = copy_id + 1;
    ring->receive_copy_id = copy_id;
    ring->receive_copy_succeeded_id = 0;
    *spans_out = MessageRingCopySpans{ring->storage + frame_offset, first_size,
                                      second_size == 0 ? nullptr : ring->storage, second_size, copy_id};
    return MessageRingStatus::Ok;
}

MessageRingStatus MessageRingEndCopyOut(MessageRing* ring, u64 sequence, u64 receive_lease_id, u64 copy_id,
                                        bool succeeded)
{
    if (ring == nullptr || sequence == 0 || receive_lease_id == 0 || copy_id == 0)
        return MessageRingStatus::InvalidArgument;
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;

    RingGuard guard(*ring);
    if (!StateIsValid(*ring))
        return MessageRingStatus::CorruptState;
    if (ring->receive_sequence != sequence)
        return MessageRingStatus::StaleSequence;
    if (ring->receive_lease_id != receive_lease_id)
        return MessageRingStatus::StaleReceiveLease;
    if (ring->receive_copy_id == 0)
        return MessageRingStatus::CopyNotActive;
    if (ring->receive_copy_id != copy_id)
        return MessageRingStatus::StaleCopyAttempt;
    ring->receive_copy_id = 0;
    ring->receive_copy_succeeded_id = succeeded ? copy_id : 0;
    return MessageRingStatus::Ok;
}

MessageRingStatus MessageRingCopyOut(MessageRing* ring, u64 sequence, u64 receive_lease_id, void* destination,
                                     u32 destination_bytes, u32* copied_bytes_out)
{
    if (copied_bytes_out != nullptr &&
        !PointerRangeIsValid(copied_bytes_out, static_cast<u32>(sizeof(*copied_bytes_out))))
    {
        return MessageRingStatus::InvalidArgument;
    }
    if (ring != nullptr && copied_bytes_out != nullptr &&
        PointerRangesOverlap(copied_bytes_out, static_cast<u32>(sizeof(*copied_bytes_out)), ring,
                             static_cast<u32>(sizeof(MessageRing))))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    if (ring == nullptr)
    {
        if (copied_bytes_out != nullptr)
            *copied_bytes_out = 0;
        return MessageRingStatus::InvalidArgument;
    }
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;
    if (PointerRangesOverlap(destination, destination_bytes, ring->storage, ring->capacity_bytes) ||
        PointerRangesOverlap(destination, destination_bytes, ring, static_cast<u32>(sizeof(MessageRing))))
        return MessageRingStatus::AliasedBuffer;
    if (copied_bytes_out != nullptr &&
        PointerRangesOverlap(copied_bytes_out, static_cast<u32>(sizeof(*copied_bytes_out)), ring->storage,
                             ring->capacity_bytes))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    if (sequence == 0 || receive_lease_id == 0 || destination == nullptr ||
        !PointerRangeIsValid(destination, destination_bytes))
    {
        if (copied_bytes_out != nullptr)
            *copied_bytes_out = 0;
        return MessageRingStatus::InvalidArgument;
    }
    if (copied_bytes_out != nullptr &&
        PointerRangesOverlap(copied_bytes_out, static_cast<u32>(sizeof(*copied_bytes_out)), destination,
                             destination_bytes))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    if (copied_bytes_out != nullptr)
        *copied_bytes_out = 0;

    MessageRingCopySpans spans{};
    MessageRingStatus status = MessageRingBeginCopyOut(ring, sequence, receive_lease_id, &spans);
    if (status != MessageRingStatus::Ok)
        return status;
    const u32 required = spans.first_size + spans.second_size;
    if (destination_bytes < required)
    {
        (void)MessageRingEndCopyOut(ring, sequence, receive_lease_id, spans.copy_id, false);
        return MessageRingStatus::BufferTooSmall;
    }

    auto* bytes = static_cast<u8*>(destination);
    CopyBytes(bytes, spans.first, spans.first_size);
    if (spans.second_size != 0)
        CopyBytes(bytes + spans.first_size, spans.second, spans.second_size);

    status = MessageRingEndCopyOut(ring, sequence, receive_lease_id, spans.copy_id, true);
    if (status == MessageRingStatus::Ok && copied_bytes_out != nullptr)
        *copied_bytes_out = required;
    return status;
}

MessageRingStatus MessageRingCommit(MessageRing* ring, u64 sequence, u64 receive_lease_id)
{
    if (ring == nullptr || sequence == 0 || receive_lease_id == 0)
        return MessageRingStatus::InvalidArgument;
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;

    RingGuard guard(*ring);
    if (!StateIsValid(*ring))
        return MessageRingStatus::CorruptState;
    if (ring->receive_sequence != sequence)
        return MessageRingStatus::StaleSequence;
    if (ring->receive_lease_id != receive_lease_id)
        return MessageRingStatus::StaleReceiveLease;
    if (ring->receive_copy_id != 0)
        return MessageRingStatus::Busy;
    if (ring->receive_copy_succeeded_id == 0)
        return MessageRingStatus::CopyRequired;

    HeadRecord record{};
    if (!ReadHeadRecord(*ring, &record) || record.sequence != sequence || record.frame_size != ring->receive_frame_size)
        return MessageRingStatus::CorruptState;
    ring->head_offset = AdvanceOffset(ring->head_offset, record.record_size, ring->capacity_bytes);
    ring->used_bytes -= record.record_size;
    --ring->queued_frames;
    if (ring->queued_frames == 0)
        ring->head_offset = ring->tail_offset;
    ClearReceiver(*ring);
    return MessageRingStatus::Ok;
}

MessageRingStatus MessageRingCancelReceive(MessageRing* ring, u64 sequence, u64 receive_lease_id)
{
    if (ring == nullptr || sequence == 0 || receive_lease_id == 0)
        return MessageRingStatus::InvalidArgument;
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;

    RingGuard guard(*ring);
    if (!StateIsValid(*ring))
        return MessageRingStatus::CorruptState;
    if (ring->receive_sequence != sequence)
        return MessageRingStatus::StaleSequence;
    if (ring->receive_lease_id != receive_lease_id)
        return MessageRingStatus::StaleReceiveLease;
    if (ring->receive_copy_id != 0)
        return MessageRingStatus::Busy;
    ClearReceiver(*ring);
    return MessageRingStatus::Ok;
}

MessageRingStatus MessageRingInspect(MessageRing* ring, MessageRingSnapshot* snapshot_out)
{
    if (snapshot_out != nullptr && !PointerRangeIsValid(snapshot_out, static_cast<u32>(sizeof(*snapshot_out))))
        return MessageRingStatus::InvalidArgument;
    if (ring != nullptr && snapshot_out != nullptr &&
        PointerRangesOverlap(snapshot_out, static_cast<u32>(sizeof(*snapshot_out)), ring,
                             static_cast<u32>(sizeof(MessageRing))))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    if (ring == nullptr || snapshot_out == nullptr)
        return MessageRingStatus::InvalidArgument;
    if (!RingIsReady(ring))
        return MessageRingStatus::NotInitialized;
    if (PointerRangesOverlap(snapshot_out, static_cast<u32>(sizeof(*snapshot_out)), ring->storage,
                             ring->capacity_bytes))
    {
        return MessageRingStatus::AliasedBuffer;
    }
    *snapshot_out = {};

    RingGuard guard(*ring);
    if (!StateIsValid(*ring))
        return MessageRingStatus::CorruptState;
    *snapshot_out = MessageRingSnapshot{
        ring->capacity_bytes,
        ring->used_bytes,
        ring->capacity_bytes - ring->used_bytes,
        ring->queued_frames,
        ring->next_sequence,
        ring->producer_reservation_id,
        ring->receive_sequence,
        ring->producer_copy_active != 0,
        ring->producer_abort_requested != 0,
        ring->receive_copy_id != 0,
        ring->receive_copy_succeeded_id != 0,
        ring->sequence_exhausted != 0,
        ring->reservation_exhausted != 0,
        ring->receive_lease_exhausted != 0,
        ring->copy_id_exhausted != 0,
    };
    return MessageRingStatus::Ok;
}

const char* MessageRingStatusName(MessageRingStatus status)
{
    switch (status)
    {
    case MessageRingStatus::Ok:
        return "ok";
    case MessageRingStatus::InvalidArgument:
        return "invalid-argument";
    case MessageRingStatus::NotInitialized:
        return "not-initialized";
    case MessageRingStatus::AliasedBuffer:
        return "aliased-buffer";
    case MessageRingStatus::MalformedMessage:
        return "malformed-message";
    case MessageRingStatus::InvalidPayloadContract:
        return "invalid-payload-contract";
    case MessageRingStatus::MissingPayloadContract:
        return "missing-payload-contract";
    case MessageRingStatus::MalformedPayload:
        return "malformed-payload";
    case MessageRingStatus::Full:
        return "full";
    case MessageRingStatus::Busy:
        return "busy";
    case MessageRingStatus::Empty:
        return "empty";
    case MessageRingStatus::BufferTooSmall:
        return "buffer-too-small";
    case MessageRingStatus::CopyRequired:
        return "copy-required";
    case MessageRingStatus::CopyNotActive:
        return "copy-not-active";
    case MessageRingStatus::StaleSequence:
        return "stale-sequence";
    case MessageRingStatus::StaleReservation:
        return "stale-reservation";
    case MessageRingStatus::ProducerAborted:
        return "producer-aborted";
    case MessageRingStatus::SequenceExhausted:
        return "sequence-exhausted";
    case MessageRingStatus::ReservationExhausted:
        return "reservation-exhausted";
    case MessageRingStatus::CorruptState:
        return "corrupt-state";
    case MessageRingStatus::AlreadyInitialized:
        return "already-initialized";
    case MessageRingStatus::StaleReceiveLease:
        return "stale-receive-lease";
    case MessageRingStatus::StaleCopyAttempt:
        return "stale-copy-attempt";
    case MessageRingStatus::ReceiveLeaseExhausted:
        return "receive-lease-exhausted";
    case MessageRingStatus::CopyIdExhausted:
        return "copy-id-exhausted";
    }
    return "unknown";
}

} // namespace duetos::ipc
