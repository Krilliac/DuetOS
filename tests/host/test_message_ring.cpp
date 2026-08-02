// tests/host/test_message_ring.cpp
//
// Hosted contract and concurrent-model coverage for message_ring.  Exercises
// exact producer reservation abort, explicit saturation, wrapped records,
// receive copy failure/cancel/retry, stale commits, hostile frames/payloads,
// terminal sequence exhaustion, and MPSC enqueue with one transactional reader.

#include "host_test_helper.h"
#include "ipc/message_ring.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <thread>
#include <vector>

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using duetos::ipc::kMessageAbiHeaderV1Bytes;
using duetos::ipc::kVersionedPayloadHeaderBytes;
using duetos::ipc::kVersionedPayloadMaxRules;
using duetos::ipc::MessageEncodeHeaderV1;
using duetos::ipc::MessageHeaderV1;
using duetos::ipc::MessageKind;
using duetos::ipc::MessageRing;
using duetos::ipc::MessageRingAbortEnqueue;
using duetos::ipc::MessageRingBeginCopyOut;
using duetos::ipc::MessageRingCancelReceive;
using duetos::ipc::MessageRingCommit;
using duetos::ipc::MessageRingCopyOut;
using duetos::ipc::MessageRingCopySpans;
using duetos::ipc::MessageRingEndCopyOut;
using duetos::ipc::MessageRingEnqueue;
using duetos::ipc::MessageRingInitialize;
using duetos::ipc::MessageRingInspect;
using duetos::ipc::MessageRingPeek;
using duetos::ipc::MessageRingPeekView;
using duetos::ipc::MessageRingPrepareEnqueue;
using duetos::ipc::MessageRingPublishEnqueue;
using duetos::ipc::MessageRingSnapshot;
using duetos::ipc::MessageRingStatus;
using duetos::ipc::MessageRingStatusName;
using duetos::ipc::MessageValidationError;
using duetos::ipc::PayloadEncodeHeader;
using duetos::ipc::PayloadValidationError;
using duetos::ipc::PayloadVersionRule;

constexpr u32 kFrameBytes = kMessageAbiHeaderV1Bytes + kVersionedPayloadHeaderBytes + 8;
constexpr std::array<PayloadVersionRule, 1> kPayloadRules{{
    {1, 0, kVersionedPayloadHeaderBytes, 64},
}};

void WriteLe16(u8* bytes, u16 value)
{
    bytes[0] = static_cast<u8>(value & 0xFFU);
    bytes[1] = static_cast<u8>((value >> 8U) & 0xFFU);
}

void WriteLe32(u8* bytes, u32 value)
{
    bytes[0] = static_cast<u8>(value & 0xFFU);
    bytes[1] = static_cast<u8>((value >> 8U) & 0xFFU);
    bytes[2] = static_cast<u8>((value >> 16U) & 0xFFU);
    bytes[3] = static_cast<u8>((value >> 24U) & 0xFFU);
}

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | (static_cast<u32>(bytes[1]) << 8U) | (static_cast<u32>(bytes[2]) << 16U) |
           (static_cast<u32>(bytes[3]) << 24U);
}

std::array<u8, kFrameBytes> MakeFrame(u32 item, u64 request_id)
{
    std::array<u8, kFrameBytes> frame{};
    const MessageHeaderV1 message{MessageKind::Request, 0, 7, 11, request_id};
    EXPECT_EQ(MessageEncodeHeaderV1(frame.data(), static_cast<u32>(frame.size()), message), MessageValidationError::Ok);
    u8* payload = frame.data() + kMessageAbiHeaderV1Bytes;
    EXPECT_EQ(PayloadEncodeHeader(payload, static_cast<u32>(frame.size()) - kMessageAbiHeaderV1Bytes, 1, 0,
                                  kPayloadRules.data(), static_cast<u32>(kPayloadRules.size())),
              PayloadValidationError::Ok);
    WriteLe32(payload + kVersionedPayloadHeaderBytes, item);
    WriteLe32(payload + kVersionedPayloadHeaderBytes + 4, ~item);
    return frame;
}

std::array<u8, kMessageAbiHeaderV1Bytes> MakeEmptyFrame(u64 request_id)
{
    std::array<u8, kMessageAbiHeaderV1Bytes> frame{};
    const MessageHeaderV1 message{MessageKind::Request, 0, 7, 12, request_id};
    EXPECT_EQ(MessageEncodeHeaderV1(frame.data(), static_cast<u32>(frame.size()), message), MessageValidationError::Ok);
    return frame;
}

MessageRingSnapshot Inspect(MessageRing& ring)
{
    MessageRingSnapshot snapshot{};
    EXPECT_EQ(MessageRingInspect(&ring, &snapshot), MessageRingStatus::Ok);
    return snapshot;
}

void ExpectSnapshotEquals(const MessageRingSnapshot& actual, const MessageRingSnapshot& expected)
{
    EXPECT_EQ(actual.capacity_bytes, expected.capacity_bytes);
    EXPECT_EQ(actual.used_bytes, expected.used_bytes);
    EXPECT_EQ(actual.free_bytes, expected.free_bytes);
    EXPECT_EQ(actual.queued_frames, expected.queued_frames);
    EXPECT_EQ(actual.next_sequence, expected.next_sequence);
    EXPECT_EQ(actual.producer_reservation_id, expected.producer_reservation_id);
    EXPECT_EQ(actual.receive_sequence, expected.receive_sequence);
    EXPECT_EQ(actual.producer_copy_active, expected.producer_copy_active);
    EXPECT_EQ(actual.producer_abort_requested, expected.producer_abort_requested);
    EXPECT_EQ(actual.receive_copy_active, expected.receive_copy_active);
    EXPECT_EQ(actual.receive_copy_succeeded, expected.receive_copy_succeeded);
    EXPECT_EQ(actual.sequence_exhausted, expected.sequence_exhausted);
    EXPECT_EQ(actual.reservation_exhausted, expected.reservation_exhausted);
    EXPECT_EQ(actual.receive_lease_exhausted, expected.receive_lease_exhausted);
    EXPECT_EQ(actual.copy_id_exhausted, expected.copy_id_exhausted);
}

template <std::size_t N>
void CopyAndCommit(MessageRing& ring, const MessageRingPeekView& view, std::array<u8, N>& destination)
{
    u32 copied = 0;
    EXPECT_EQ(MessageRingCopyOut(&ring, view.sequence, view.receive_lease_id, destination.data(),
                                 static_cast<u32>(destination.size()), &copied),
              MessageRingStatus::Ok);
    EXPECT_EQ(copied, static_cast<u32>(destination.size()));
    EXPECT_EQ(MessageRingCommit(&ring, view.sequence, view.receive_lease_id), MessageRingStatus::Ok);
}

} // namespace

int main()
{
    MessageRing uninitialized{};
    MessageRingPeekView peek{17, 19, 23};
    EXPECT_EQ(MessageRingPeek(&uninitialized, &peek), MessageRingStatus::NotInitialized);
    EXPECT_EQ(peek.sequence, 17ULL);
    EXPECT_EQ(peek.receive_lease_id, 19ULL);
    EXPECT_EQ(peek.frame_size, 23U);

    // An operation that observes the one-shot Initializing state cannot safely
    // read the backing-storage fields yet.  It therefore leaves every output
    // untouched, including one that will become part of that storage.
    MessageRing initializing_ring{};
    alignas(u64) std::array<u8, 128> initializing_storage{};
    initializing_storage.fill(0xA5);
    initializing_ring.storage = initializing_storage.data();
    initializing_ring.capacity_bytes = static_cast<u32>(initializing_storage.size());
    initializing_ring.initialized = 1;
    const auto initializing_storage_before = initializing_storage;
    EXPECT_EQ(MessageRingPublishEnqueue(&initializing_ring, 1, reinterpret_cast<u64*>(initializing_storage.data())),
              MessageRingStatus::NotInitialized);
    EXPECT_EQ(MessageRingPeek(&initializing_ring, reinterpret_cast<MessageRingPeekView*>(initializing_storage.data())),
              MessageRingStatus::NotInitialized);
    EXPECT_EQ(MessageRingBeginCopyOut(&initializing_ring, 1, 1,
                                      reinterpret_cast<MessageRingCopySpans*>(initializing_storage.data())),
              MessageRingStatus::NotInitialized);
    std::array<u8, kFrameBytes> initializing_destination{};
    EXPECT_EQ(MessageRingCopyOut(&initializing_ring, 1, 1, initializing_destination.data(),
                                 static_cast<u32>(initializing_destination.size()),
                                 reinterpret_cast<u32*>(initializing_storage.data())),
              MessageRingStatus::NotInitialized);
    EXPECT_EQ(
        MessageRingInspect(&initializing_ring, reinterpret_cast<MessageRingSnapshot*>(initializing_storage.data())),
        MessageRingStatus::NotInitialized);
    EXPECT_TRUE(initializing_storage == initializing_storage_before);
    EXPECT_EQ(MessageRingInitialize(nullptr, nullptr, 0), MessageRingStatus::InvalidArgument);
    std::array<u8, 47> too_small{};
    EXPECT_EQ(MessageRingInitialize(&uninitialized, too_small.data(), static_cast<u32>(too_small.size())),
              MessageRingStatus::InvalidArgument);
    alignas(u64) std::array<u8, 128> retry_storage{};
    EXPECT_EQ(MessageRingInitialize(&uninitialized, retry_storage.data(), static_cast<u32>(retry_storage.size()), 3),
              MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingInitialize(&uninitialized, retry_storage.data(), static_cast<u32>(retry_storage.size()), 4),
              MessageRingStatus::AlreadyInitialized);

    // Concurrent initialization has one winner.  The losing storage is never
    // installed, and the resulting ring remains fully usable.
    MessageRing initialization_race{};
    alignas(u64) std::array<u8, 128> initialization_storage_a{};
    alignas(u64) std::array<u8, 128> initialization_storage_b{};
    std::atomic<bool> initialize_now{false};
    MessageRingStatus initialization_status_a = MessageRingStatus::CorruptState;
    MessageRingStatus initialization_status_b = MessageRingStatus::CorruptState;
    std::thread initializer_a(
        [&]()
        {
            while (!initialize_now.load(std::memory_order_acquire))
                std::this_thread::yield();
            initialization_status_a = MessageRingInitialize(&initialization_race, initialization_storage_a.data(),
                                                            static_cast<u32>(initialization_storage_a.size()), 7);
        });
    std::thread initializer_b(
        [&]()
        {
            while (!initialize_now.load(std::memory_order_acquire))
                std::this_thread::yield();
            initialization_status_b = MessageRingInitialize(&initialization_race, initialization_storage_b.data(),
                                                            static_cast<u32>(initialization_storage_b.size()), 7);
        });
    initialize_now.store(true, std::memory_order_release);
    initializer_a.join();
    initializer_b.join();
    const u32 initialize_ok_count = static_cast<u32>(initialization_status_a == MessageRingStatus::Ok) +
                                    static_cast<u32>(initialization_status_b == MessageRingStatus::Ok);
    const u32 initialize_loser_count =
        static_cast<u32>(initialization_status_a == MessageRingStatus::AlreadyInitialized) +
        static_cast<u32>(initialization_status_b == MessageRingStatus::AlreadyInitialized);
    EXPECT_EQ(initialize_ok_count, 1U);
    EXPECT_EQ(initialize_loser_count, 1U);
    const auto initialization_frame = MakeEmptyFrame(99);
    auto initialization_enqueue = MessageRingEnqueue(&initialization_race, initialization_frame.data(),
                                                     static_cast<u32>(initialization_frame.size()));
    EXPECT_EQ(initialization_enqueue.status, MessageRingStatus::Ok);
    MessageRingPeekView initialization_peek{};
    EXPECT_EQ(MessageRingPeek(&initialization_race, &initialization_peek), MessageRingStatus::Ok);
    std::array<u8, kMessageAbiHeaderV1Bytes> initialization_copy{};
    CopyAndCommit(initialization_race, initialization_peek, initialization_copy);
    EXPECT_TRUE(initialization_copy == initialization_frame);

    // Prepared bytes remain unpublished until an exact publish, and an exact
    // abort frees that reservation without consuming a message sequence.
    alignas(u64) std::array<u8, 256> storage{};
    MessageRing ring{};
    EXPECT_EQ(MessageRingInitialize(&ring, storage.data(), static_cast<u32>(storage.size()), 10),
              MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingInspect(&ring, reinterpret_cast<MessageRingSnapshot*>(&ring)),
              MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(MessageRingInspect(&ring, reinterpret_cast<MessageRingSnapshot*>(storage.data())),
              MessageRingStatus::AliasedBuffer);
    alignas(PayloadVersionRule) const auto first_frame = MakeFrame(1, 101);
    auto prepared = MessageRingPrepareEnqueue(&ring, first_frame.data(), static_cast<u32>(first_frame.size()),
                                              kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(prepared.status, MessageRingStatus::Ok);
    EXPECT_NE(prepared.reservation_id, 0ULL);
    EXPECT_EQ(prepared.sequence, 0ULL);
    auto snapshot = Inspect(ring);
    EXPECT_EQ(snapshot.queued_frames, 0U);
    EXPECT_EQ(snapshot.used_bytes, 0U);
    EXPECT_EQ(snapshot.next_sequence, 10ULL);
    EXPECT_EQ(snapshot.producer_reservation_id, prepared.reservation_id);
    alignas(u64) std::array<u8, 256> replacement_storage{};
    EXPECT_EQ(MessageRingInitialize(&ring, replacement_storage.data(), static_cast<u32>(replacement_storage.size()), 1),
              MessageRingStatus::AlreadyInitialized);
    EXPECT_EQ(Inspect(ring).producer_reservation_id, prepared.reservation_id);
    EXPECT_EQ(MessageRingPublishEnqueue(&ring, prepared.reservation_id, reinterpret_cast<u64*>(&ring)),
              MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(MessageRingPublishEnqueue(&ring, prepared.reservation_id, reinterpret_cast<u64*>(storage.data())),
              MessageRingStatus::AliasedBuffer);
    const auto storage_before_invalid_publish = storage;
    EXPECT_EQ(MessageRingPublishEnqueue(&ring, 0, reinterpret_cast<u64*>(storage.data())),
              MessageRingStatus::AliasedBuffer);
    EXPECT_TRUE(storage == storage_before_invalid_publish);
    EXPECT_EQ(Inspect(ring).producer_reservation_id, prepared.reservation_id);
    const auto second_frame = MakeFrame(2, 102);
    EXPECT_EQ(MessageRingPrepareEnqueue(&ring, second_frame.data(), static_cast<u32>(second_frame.size()),
                                        kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()))
                  .status,
              MessageRingStatus::Busy);
    EXPECT_EQ(MessageRingAbortEnqueue(&ring, prepared.reservation_id + 1), MessageRingStatus::StaleReservation);
    EXPECT_EQ(MessageRingAbortEnqueue(&ring, prepared.reservation_id), MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingPublishEnqueue(&ring, prepared.reservation_id, nullptr), MessageRingStatus::StaleReservation);
    snapshot = Inspect(ring);
    EXPECT_EQ(snapshot.producer_reservation_id, 0ULL);
    EXPECT_EQ(snapshot.next_sequence, 10ULL);

    auto enqueued = MessageRingEnqueue(&ring, first_frame.data(), static_cast<u32>(first_frame.size()),
                                       kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(enqueued.status, MessageRingStatus::Ok);
    EXPECT_EQ(enqueued.sequence, 10ULL);
    EXPECT_EQ(Inspect(ring).queued_frames, 1U);

    // Receive failure paths leave the exact head reserved and retryable.
    EXPECT_EQ(MessageRingPeek(&ring, reinterpret_cast<MessageRingPeekView*>(&ring)), MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(MessageRingPeek(&ring, reinterpret_cast<MessageRingPeekView*>(storage.data())),
              MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(Inspect(ring).receive_sequence, 0ULL);
    EXPECT_EQ(MessageRingPeek(&ring, &peek), MessageRingStatus::Ok);
    EXPECT_EQ(peek.sequence, 10ULL);
    EXPECT_NE(peek.receive_lease_id, 0ULL);
    EXPECT_EQ(peek.frame_size, kFrameBytes);
    const u64 first_receive_lease = peek.receive_lease_id;
    EXPECT_EQ(MessageRingPeek(&ring, &peek), MessageRingStatus::Busy);
    EXPECT_EQ(MessageRingCommit(&ring, 10, first_receive_lease), MessageRingStatus::CopyRequired);

    MessageRingCopySpans spans{};
    EXPECT_EQ(MessageRingBeginCopyOut(&ring, 10, first_receive_lease, reinterpret_cast<MessageRingCopySpans*>(&ring)),
              MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(MessageRingBeginCopyOut(&ring, 10, first_receive_lease,
                                      reinterpret_cast<MessageRingCopySpans*>(storage.data())),
              MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(MessageRingBeginCopyOut(&ring, 10, first_receive_lease, &spans), MessageRingStatus::Ok);
    EXPECT_NE(spans.copy_id, 0ULL);
    EXPECT_EQ(spans.first_size + spans.second_size, kFrameBytes);
    EXPECT_EQ(MessageRingCommit(&ring, 10, first_receive_lease), MessageRingStatus::Busy);
    EXPECT_EQ(MessageRingCancelReceive(&ring, 10, first_receive_lease), MessageRingStatus::Busy);
    EXPECT_EQ(MessageRingEndCopyOut(&ring, 10, first_receive_lease, spans.copy_id, false), MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingCommit(&ring, 10, first_receive_lease), MessageRingStatus::CopyRequired);
    EXPECT_EQ(MessageRingEndCopyOut(&ring, 10, first_receive_lease, spans.copy_id, true),
              MessageRingStatus::CopyNotActive);

    alignas(u32) std::array<u8, kFrameBytes> aliased_count_destination{};
    EXPECT_EQ(MessageRingCopyOut(&ring, 10, first_receive_lease, aliased_count_destination.data(),
                                 static_cast<u32>(aliased_count_destination.size()),
                                 reinterpret_cast<u32*>(aliased_count_destination.data())),
              MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(MessageRingCopyOut(&ring, 10, first_receive_lease, aliased_count_destination.data(),
                                 static_cast<u32>(aliased_count_destination.size()), reinterpret_cast<u32*>(&ring)),
              MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(MessageRingCopyOut(&ring, 10, first_receive_lease, aliased_count_destination.data(),
                                 static_cast<u32>(aliased_count_destination.size()),
                                 reinterpret_cast<u32*>(storage.data())),
              MessageRingStatus::AliasedBuffer);
    const auto storage_before_invalid_copy = storage;
    EXPECT_EQ(MessageRingCopyOut(&ring, 0, first_receive_lease, nullptr, 0, reinterpret_cast<u32*>(storage.data())),
              MessageRingStatus::AliasedBuffer);
    EXPECT_TRUE(storage == storage_before_invalid_copy);
    EXPECT_EQ(Inspect(ring).receive_sequence, 10ULL);
    std::array<u8, kFrameBytes - 1> short_copy{};
    EXPECT_EQ(
        MessageRingCopyOut(&ring, 10, first_receive_lease, short_copy.data(), static_cast<u32>(short_copy.size())),
        MessageRingStatus::BufferTooSmall);
    EXPECT_EQ(MessageRingCopyOut(&ring, 10, first_receive_lease, storage.data(), kFrameBytes),
              MessageRingStatus::AliasedBuffer);
    EXPECT_EQ(Inspect(ring).queued_frames, 1U);

    std::array<u8, kFrameBytes> copied{};
    EXPECT_EQ(MessageRingCopyOut(&ring, 10, first_receive_lease, copied.data(), static_cast<u32>(copied.size())),
              MessageRingStatus::Ok);
    EXPECT_TRUE(copied == first_frame);
    // Cancellation after a successful copy still preserves the frame for
    // delivery retry; a fresh Peek returns the same message sequence.
    EXPECT_EQ(MessageRingCancelReceive(&ring, 10, first_receive_lease), MessageRingStatus::Ok);
    EXPECT_EQ(Inspect(ring).queued_frames, 1U);
    EXPECT_EQ(MessageRingPeek(&ring, &peek), MessageRingStatus::Ok);
    EXPECT_EQ(peek.sequence, 10ULL);
    EXPECT_NE(peek.receive_lease_id, first_receive_lease);
    const u64 retry_receive_lease = peek.receive_lease_id;
    EXPECT_EQ(MessageRingCancelReceive(&ring, 10, first_receive_lease), MessageRingStatus::StaleReceiveLease);

    // A delayed completion from copy attempt A cannot terminate copy attempt B
    // for the same message and receive lease.
    MessageRingCopySpans stale_attempt{};
    EXPECT_EQ(MessageRingBeginCopyOut(&ring, 10, retry_receive_lease, &stale_attempt), MessageRingStatus::Ok);
    const u64 stale_copy_id = stale_attempt.copy_id;
    EXPECT_EQ(MessageRingEndCopyOut(&ring, 10, retry_receive_lease, stale_copy_id, false), MessageRingStatus::Ok);
    MessageRingCopySpans current_attempt{};
    EXPECT_EQ(MessageRingBeginCopyOut(&ring, 10, retry_receive_lease, &current_attempt), MessageRingStatus::Ok);
    EXPECT_NE(current_attempt.copy_id, stale_copy_id);
    EXPECT_EQ(MessageRingEndCopyOut(&ring, 10, retry_receive_lease, stale_copy_id, true),
              MessageRingStatus::StaleCopyAttempt);
    EXPECT_EQ(MessageRingCommit(&ring, 10, retry_receive_lease), MessageRingStatus::Busy);
    EXPECT_EQ(MessageRingEndCopyOut(&ring, 10, retry_receive_lease, current_attempt.copy_id, false),
              MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingCommit(&ring, 10, retry_receive_lease), MessageRingStatus::CopyRequired);
    CopyAndCommit(ring, peek, copied);
    EXPECT_EQ(Inspect(ring).queued_frames, 0U);
    EXPECT_EQ(MessageRingCommit(&ring, 10, retry_receive_lease), MessageRingStatus::StaleSequence);

    // Hostile envelope and payload failures occur before reservation and leave
    // all queue and sequence counters unchanged.
    const auto baseline = Inspect(ring);
    auto malformed_message = first_frame;
    malformed_message[0] ^= 1U;
    auto failure = MessageRingEnqueue(&ring, malformed_message.data(), static_cast<u32>(malformed_message.size()),
                                      kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(failure.status, MessageRingStatus::MalformedMessage);
    EXPECT_EQ(failure.message_error, MessageValidationError::BadMagic);
    failure = MessageRingEnqueue(&ring, first_frame.data(), static_cast<u32>(first_frame.size()));
    EXPECT_EQ(failure.status, MessageRingStatus::MissingPayloadContract);
    failure =
        MessageRingEnqueue(&ring, first_frame.data(), static_cast<u32>(first_frame.size()), kPayloadRules.data(), 0);
    EXPECT_EQ(failure.status, MessageRingStatus::InvalidPayloadContract);
    failure = MessageRingEnqueue(&ring, first_frame.data(), static_cast<u32>(first_frame.size()), kPayloadRules.data(),
                                 kVersionedPayloadMaxRules + 1U);
    EXPECT_EQ(failure.status, MessageRingStatus::InvalidPayloadContract);
    failure = MessageRingEnqueue(&ring, first_frame.data(), static_cast<u32>(first_frame.size()),
                                 reinterpret_cast<const PayloadVersionRule*>(first_frame.data()),
                                 static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(failure.status, MessageRingStatus::AliasedBuffer);
    failure =
        MessageRingEnqueue(&ring, first_frame.data(), static_cast<u32>(first_frame.size()),
                           reinterpret_cast<const PayloadVersionRule*>(&ring), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(failure.status, MessageRingStatus::AliasedBuffer);
    failure = MessageRingEnqueue(&ring, first_frame.data(), static_cast<u32>(first_frame.size()),
                                 reinterpret_cast<const PayloadVersionRule*>(storage.data()),
                                 static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(failure.status, MessageRingStatus::AliasedBuffer);
    auto malformed_payload = first_frame;
    WriteLe16(malformed_payload.data() + kMessageAbiHeaderV1Bytes + 4, 99);
    failure = MessageRingEnqueue(&ring, malformed_payload.data(), static_cast<u32>(malformed_payload.size()),
                                 kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(failure.status, MessageRingStatus::MalformedPayload);
    EXPECT_EQ(failure.payload_error, PayloadValidationError::UnsupportedVersion);
    const auto empty_frame = MakeEmptyFrame(103);
    failure = MessageRingEnqueue(&ring, empty_frame.data(), static_cast<u32>(empty_frame.size()), kPayloadRules.data(),
                                 static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(failure.status, MessageRingStatus::MalformedPayload);
    EXPECT_EQ(failure.payload_error, PayloadValidationError::TruncatedHeader);
    snapshot = Inspect(ring);
    EXPECT_EQ(snapshot.queued_frames, baseline.queued_frames);
    EXPECT_EQ(snapshot.used_bytes, baseline.used_bytes);
    EXPECT_EQ(snapshot.next_sequence, baseline.next_sequence);

    // Saturation is explicit.  After one consume, the third record wraps both
    // its internal record header and frame across the caller storage boundary.
    std::array<u8, 150> wrap_storage{};
    MessageRing wrap_ring{};
    EXPECT_EQ(MessageRingInitialize(&wrap_ring, wrap_storage.data(), static_cast<u32>(wrap_storage.size())),
              MessageRingStatus::Ok);
    const auto frame_a = MakeFrame(10, 201);
    const auto frame_b = MakeFrame(11, 202);
    const auto frame_c = MakeFrame(12, 203);
    EXPECT_EQ(MessageRingEnqueue(&wrap_ring, frame_a.data(), static_cast<u32>(frame_a.size()), kPayloadRules.data(),
                                 static_cast<u32>(kPayloadRules.size()))
                  .status,
              MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingEnqueue(&wrap_ring, frame_b.data(), static_cast<u32>(frame_b.size()), kPayloadRules.data(),
                                 static_cast<u32>(kPayloadRules.size()))
                  .status,
              MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingEnqueue(&wrap_ring, frame_c.data(), static_cast<u32>(frame_c.size()), kPayloadRules.data(),
                                 static_cast<u32>(kPayloadRules.size()))
                  .status,
              MessageRingStatus::Full);
    EXPECT_EQ(MessageRingPeek(&wrap_ring, &peek), MessageRingStatus::Ok);
    EXPECT_EQ(peek.sequence, 1ULL);
    CopyAndCommit(wrap_ring, peek, copied);
    EXPECT_TRUE(copied == frame_a);
    enqueued = MessageRingEnqueue(&wrap_ring, frame_c.data(), static_cast<u32>(frame_c.size()), kPayloadRules.data(),
                                  static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(enqueued.status, MessageRingStatus::Ok);
    EXPECT_EQ(enqueued.sequence, 3ULL);
    EXPECT_EQ(MessageRingPeek(&wrap_ring, &peek), MessageRingStatus::Ok);
    EXPECT_EQ(peek.sequence, 2ULL);
    CopyAndCommit(wrap_ring, peek, copied);
    EXPECT_TRUE(copied == frame_b);
    EXPECT_EQ(MessageRingPeek(&wrap_ring, &peek), MessageRingStatus::Ok);
    EXPECT_EQ(peek.sequence, 3ULL);
    EXPECT_EQ(MessageRingBeginCopyOut(&wrap_ring, peek.sequence, peek.receive_lease_id, &spans), MessageRingStatus::Ok);
    EXPECT_NE(spans.second, nullptr);
    EXPECT_NE(spans.second_size, 0U);
    EXPECT_EQ(MessageRingEndCopyOut(&wrap_ring, peek.sequence, peek.receive_lease_id, spans.copy_id, false),
              MessageRingStatus::Ok);
    CopyAndCommit(wrap_ring, peek, copied);
    EXPECT_TRUE(copied == frame_c);

    // Sequence UINT64_MAX publishes exactly once and is never wrapped to zero.
    std::array<u8, 128> terminal_storage{};
    MessageRing terminal_ring{};
    constexpr u64 kTerminalSequence = ~static_cast<u64>(0);
    EXPECT_EQ(MessageRingInitialize(&terminal_ring, terminal_storage.data(), static_cast<u32>(terminal_storage.size()),
                                    kTerminalSequence),
              MessageRingStatus::Ok);
    enqueued = MessageRingEnqueue(&terminal_ring, empty_frame.data(), static_cast<u32>(empty_frame.size()));
    EXPECT_EQ(enqueued.status, MessageRingStatus::Ok);
    EXPECT_EQ(enqueued.sequence, kTerminalSequence);
    EXPECT_TRUE(Inspect(terminal_ring).sequence_exhausted);
    EXPECT_EQ(MessageRingEnqueue(&terminal_ring, empty_frame.data(), static_cast<u32>(empty_frame.size())).status,
              MessageRingStatus::SequenceExhausted);

    // Producer reservation UINT64_MAX is issued exactly once. Aborting that
    // terminal reservation does not make it reusable, and every later failure
    // leaves queue/storage state unchanged with sanitized result fields.
    alignas(u64) std::array<u8, 128> reservation_exhaustion_storage{};
    MessageRing reservation_exhaustion_ring{};
    EXPECT_EQ(MessageRingInitialize(&reservation_exhaustion_ring, reservation_exhaustion_storage.data(),
                                    static_cast<u32>(reservation_exhaustion_storage.size())),
              MessageRingStatus::Ok);
    reservation_exhaustion_ring.next_reservation_id = kTerminalSequence;
    auto terminal_reservation = MessageRingPrepareEnqueue(&reservation_exhaustion_ring, empty_frame.data(),
                                                          static_cast<u32>(empty_frame.size()));
    EXPECT_EQ(terminal_reservation.status, MessageRingStatus::Ok);
    EXPECT_EQ(terminal_reservation.reservation_id, kTerminalSequence);
    EXPECT_EQ(terminal_reservation.sequence, 0ULL);
    EXPECT_EQ(reservation_exhaustion_ring.next_reservation_id, kTerminalSequence);
    EXPECT_TRUE(Inspect(reservation_exhaustion_ring).reservation_exhausted);
    EXPECT_EQ(MessageRingAbortEnqueue(&reservation_exhaustion_ring, terminal_reservation.reservation_id),
              MessageRingStatus::Ok);
    const auto before_reservation_failure = Inspect(reservation_exhaustion_ring);
    const auto storage_before_reservation_failure = reservation_exhaustion_storage;
    const auto exhausted_reservation = MessageRingPrepareEnqueue(&reservation_exhaustion_ring, empty_frame.data(),
                                                                 static_cast<u32>(empty_frame.size()));
    EXPECT_EQ(exhausted_reservation.status, MessageRingStatus::ReservationExhausted);
    EXPECT_EQ(exhausted_reservation.reservation_id, 0ULL);
    EXPECT_EQ(exhausted_reservation.sequence, 0ULL);
    EXPECT_EQ(exhausted_reservation.message_error, MessageValidationError::Ok);
    EXPECT_EQ(exhausted_reservation.payload_error, PayloadValidationError::Ok);
    EXPECT_EQ(reservation_exhaustion_ring.next_reservation_id, kTerminalSequence);
    EXPECT_TRUE(reservation_exhaustion_storage == storage_before_reservation_failure);
    ExpectSnapshotEquals(Inspect(reservation_exhaustion_ring), before_reservation_failure);

    // Receive and copy authority IDs publish UINT64_MAX once, then fail closed
    // instead of wrapping and making a stale token current again. These direct
    // counter assignments are isolated host-only exhaustion injections.
    alignas(u64) std::array<u8, 128> receive_exhaustion_storage{};
    MessageRing receive_exhaustion_ring{};
    EXPECT_EQ(MessageRingInitialize(&receive_exhaustion_ring, receive_exhaustion_storage.data(),
                                    static_cast<u32>(receive_exhaustion_storage.size())),
              MessageRingStatus::Ok);
    EXPECT_EQ(
        MessageRingEnqueue(&receive_exhaustion_ring, empty_frame.data(), static_cast<u32>(empty_frame.size())).status,
        MessageRingStatus::Ok);
    receive_exhaustion_ring.next_receive_lease_id = kTerminalSequence;
    MessageRingPeekView terminal_lease{};
    EXPECT_EQ(MessageRingPeek(&receive_exhaustion_ring, &terminal_lease), MessageRingStatus::Ok);
    EXPECT_EQ(terminal_lease.receive_lease_id, kTerminalSequence);
    EXPECT_EQ(
        MessageRingCancelReceive(&receive_exhaustion_ring, terminal_lease.sequence, terminal_lease.receive_lease_id),
        MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingPeek(&receive_exhaustion_ring, &terminal_lease), MessageRingStatus::ReceiveLeaseExhausted);

    alignas(u64) std::array<u8, 128> copy_exhaustion_storage{};
    MessageRing copy_exhaustion_ring{};
    EXPECT_EQ(MessageRingInitialize(&copy_exhaustion_ring, copy_exhaustion_storage.data(),
                                    static_cast<u32>(copy_exhaustion_storage.size())),
              MessageRingStatus::Ok);
    EXPECT_EQ(
        MessageRingEnqueue(&copy_exhaustion_ring, empty_frame.data(), static_cast<u32>(empty_frame.size())).status,
        MessageRingStatus::Ok);
    MessageRingPeekView copy_exhaustion_view{};
    EXPECT_EQ(MessageRingPeek(&copy_exhaustion_ring, &copy_exhaustion_view), MessageRingStatus::Ok);
    copy_exhaustion_ring.next_copy_id = kTerminalSequence;
    MessageRingCopySpans terminal_copy{};
    EXPECT_EQ(MessageRingBeginCopyOut(&copy_exhaustion_ring, copy_exhaustion_view.sequence,
                                      copy_exhaustion_view.receive_lease_id, &terminal_copy),
              MessageRingStatus::Ok);
    EXPECT_EQ(terminal_copy.copy_id, kTerminalSequence);
    EXPECT_EQ(MessageRingEndCopyOut(&copy_exhaustion_ring, copy_exhaustion_view.sequence,
                                    copy_exhaustion_view.receive_lease_id, terminal_copy.copy_id, false),
              MessageRingStatus::Ok);
    EXPECT_EQ(MessageRingBeginCopyOut(&copy_exhaustion_ring, copy_exhaustion_view.sequence,
                                      copy_exhaustion_view.receive_lease_id, &terminal_copy),
              MessageRingStatus::CopyIdExhausted);
    EXPECT_EQ(MessageRingCancelReceive(&copy_exhaustion_ring, copy_exhaustion_view.sequence,
                                       copy_exhaustion_view.receive_lease_id),
              MessageRingStatus::Ok);

    // Concurrent model: four producers contend through Busy/Full while one
    // consumer verifies every exact published sequence and payload once.
    constexpr u32 kProducerCount = 4;
    constexpr u32 kItemsPerProducer = 250;
    constexpr u32 kItemCount = kProducerCount * kItemsPerProducer;
    std::array<u8, 4096> concurrent_storage{};
    MessageRing concurrent_ring{};
    EXPECT_EQ(
        MessageRingInitialize(&concurrent_ring, concurrent_storage.data(), static_cast<u32>(concurrent_storage.size())),
        MessageRingStatus::Ok);
    std::array<std::array<u8, kFrameBytes>, kItemCount> concurrent_frames{};
    for (u32 item = 0; item < kItemCount; ++item)
        concurrent_frames[item] = MakeFrame(item, static_cast<u64>(item) + 1ULL);
    std::atomic<bool> start{false};
    std::atomic<bool> stop{false};
    std::atomic<u32> producer_failures{0};
    std::atomic<u32> producers_done{0};
    std::vector<std::thread> producers;
    producers.reserve(kProducerCount);
    for (u32 producer = 0; producer < kProducerCount; ++producer)
    {
        producers.emplace_back(
            [&, producer]()
            {
                while (!start.load(std::memory_order_acquire) && !stop.load(std::memory_order_relaxed))
                    std::this_thread::yield();
                for (u32 local = 0; local < kItemsPerProducer && !stop.load(std::memory_order_relaxed); ++local)
                {
                    const u32 item = producer * kItemsPerProducer + local;
                    const auto& frame = concurrent_frames[item];
                    while (!stop.load(std::memory_order_relaxed))
                    {
                        const auto result =
                            MessageRingEnqueue(&concurrent_ring, frame.data(), static_cast<u32>(frame.size()),
                                               kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
                        if (result.status == MessageRingStatus::Ok)
                            break;
                        if (result.status != MessageRingStatus::Busy && result.status != MessageRingStatus::Full)
                        {
                            producer_failures.fetch_add(1, std::memory_order_relaxed);
                            stop.store(true, std::memory_order_release);
                            break;
                        }
                        std::this_thread::yield();
                    }
                }
                producers_done.fetch_add(1, std::memory_order_release);
            });
    }

    std::array<u8, kItemCount> seen{};
    u32 received = 0;
    u64 expected_sequence = 1;
    start.store(true, std::memory_order_release);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (received < kItemCount && std::chrono::steady_clock::now() < deadline &&
           !stop.load(std::memory_order_acquire))
    {
        const MessageRingStatus peek_status = MessageRingPeek(&concurrent_ring, &peek);
        if (peek_status == MessageRingStatus::Empty || peek_status == MessageRingStatus::Busy)
        {
            std::this_thread::yield();
            continue;
        }
        if (peek_status != MessageRingStatus::Ok)
        {
            producer_failures.fetch_add(1, std::memory_order_relaxed);
            stop.store(true, std::memory_order_release);
            break;
        }
        EXPECT_EQ(peek.sequence, expected_sequence);
        std::array<u8, kFrameBytes> frame{};
        u32 copied_bytes = 0;
        if (MessageRingCopyOut(&concurrent_ring, peek.sequence, peek.receive_lease_id, frame.data(),
                               static_cast<u32>(frame.size()), &copied_bytes) != MessageRingStatus::Ok ||
            copied_bytes != kFrameBytes ||
            MessageRingCommit(&concurrent_ring, peek.sequence, peek.receive_lease_id) != MessageRingStatus::Ok)
        {
            producer_failures.fetch_add(1, std::memory_order_relaxed);
            stop.store(true, std::memory_order_release);
            break;
        }
        const u8* application = frame.data() + kMessageAbiHeaderV1Bytes + kVersionedPayloadHeaderBytes;
        const u32 item = ReadLe32(application);
        const u32 complement = ReadLe32(application + 4);
        if (item >= kItemCount || complement != ~item || seen[item] != 0)
        {
            producer_failures.fetch_add(1, std::memory_order_relaxed);
            stop.store(true, std::memory_order_release);
            break;
        }
        seen[item] = 1;
        ++received;
        ++expected_sequence;
    }
    if (received != kItemCount)
        stop.store(true, std::memory_order_release);
    for (auto& producer : producers)
        producer.join();
    EXPECT_EQ(producer_failures.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(producers_done.load(std::memory_order_acquire), kProducerCount);
    EXPECT_EQ(received, kItemCount);
    for (u8 value : seen)
        EXPECT_EQ(value, 1U);
    EXPECT_EQ(Inspect(concurrent_ring).queued_frames, 0U);

    EXPECT_STREQ(MessageRingStatusName(MessageRingStatus::Full), "full");
    EXPECT_STREQ(MessageRingStatusName(MessageRingStatus::AlreadyInitialized), "already-initialized");
    EXPECT_STREQ(MessageRingStatusName(MessageRingStatus::StaleReceiveLease), "stale-receive-lease");
    EXPECT_STREQ(MessageRingStatusName(MessageRingStatus::StaleCopyAttempt), "stale-copy-attempt");
    EXPECT_STREQ(MessageRingStatusName(static_cast<MessageRingStatus>(0xFF)), "unknown");

    return duetos_host_test::finish_main("test_message_ring");
}
