// Hosted ownership, wait, close, and concurrent-delivery properties for
// ipc/kmessage_port.cpp.  Minimal host KObject/HandleTable definitions keep
// this target focused on the MessagePort contract; the real generation-safe
// table has its own production selftests and is still compiled against these
// exact wrapper calls in the freestanding kernel target.

#include "host_test_helper.h"
#include "ipc/kmessage_port.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <thread>
#include <vector>

namespace
{

std::mutex g_object_lock;
std::mutex g_table_lock;
std::atomic<duetos::u32> g_destroyed{0};

} // namespace

namespace duetos::ipc
{

void KObjectInit(KObject* object, KObjectType type, KObjectDestroyFn destroy)
{
    object->type = type;
    object->refcount = 1;
    object->destroy = destroy;
}

bool KObjectAcquire(KObject* object)
{
    if (object == nullptr)
        return false;
    std::lock_guard<std::mutex> guard(g_object_lock);
    if (object->refcount == 0 || object->refcount == static_cast<u32>(-1))
        return false;
    ++object->refcount;
    return true;
}

void KObjectRelease(KObject* object)
{
    if (object == nullptr)
        return;
    KObjectDestroyFn destroy = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_object_lock);
        if (object->refcount == 0)
            return;
        --object->refcount;
        if (object->refcount == 0)
            destroy = object->destroy;
    }
    if (destroy != nullptr)
    {
        g_destroyed.fetch_add(1, std::memory_order_relaxed);
        destroy(object);
    }
}

u32 KObjectRefcount(const KObject* object)
{
    if (object == nullptr)
        return 0;
    std::lock_guard<std::mutex> guard(g_object_lock);
    return object->refcount;
}

KObject* HandleTableLookupRef(HandleTable& table, Handle handle, KObjectType expected_type, u64 required_rights)
{
    std::lock_guard<std::mutex> guard(g_table_lock);
    u32 slot_index = 0;
    u32 generation = 0;
    if (table.state != HandleTableState::Open || !HandleDecode(handle, &slot_index, &generation))
        return nullptr;
    HandleSlot& slot = table.slots[slot_index];
    if (slot.state != HandleSlotState::Live || slot.generation != generation || slot.obj == nullptr ||
        slot.obj->type != expected_type || (slot.rights & required_rights) != required_rights)
    {
        return nullptr;
    }
    return KObjectAcquire(slot.obj) ? slot.obj : nullptr;
}

::duetos::core::Result<KObject*> HandleTableDetach(HandleTable& table, Handle handle, KObjectType expected_type,
                                                   u64 required_rights)
{
    std::lock_guard<std::mutex> guard(g_table_lock);
    u32 slot_index = 0;
    u32 generation = 0;
    if (table.state != HandleTableState::Open || !HandleDecode(handle, &slot_index, &generation))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    HandleSlot& slot = table.slots[slot_index];
    if (slot.state != HandleSlotState::Live || slot.generation != generation || slot.obj == nullptr ||
        (expected_type != KObjectType::Invalid && slot.obj->type != expected_type))
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    if ((slot.rights & required_rights) != required_rights)
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};

    KObject* object = slot.obj;
    slot.obj = nullptr;
    slot.rights = 0;
    slot.state = slot.generation == kHandleGenerationMax ? HandleSlotState::Retired : HandleSlotState::Free;
    return object;
}

} // namespace duetos::ipc

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::ipc;

constexpr u32 kFrameBytes = kMessageAbiHeaderV1Bytes + kVersionedPayloadHeaderBytes + 8;
constexpr std::array<PayloadVersionRule, 1> kPayloadRules{{
    {1, 0, kVersionedPayloadHeaderBytes, 64},
}};

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

std::array<u8, kFrameBytes> MakeFrame(u32 value)
{
    std::array<u8, kFrameBytes> frame{};
    const MessageHeaderV1 message{MessageKind::Request, 0, 31, 9, static_cast<u64>(value) + 1ULL};
    EXPECT_EQ(MessageEncodeHeaderV1(frame.data(), static_cast<u32>(frame.size()), message), MessageValidationError::Ok);
    u8* payload = frame.data() + kMessageAbiHeaderV1Bytes;
    EXPECT_EQ(PayloadEncodeHeader(payload, static_cast<u32>(frame.size()) - kMessageAbiHeaderV1Bytes, 1, 0,
                                  kPayloadRules.data(), static_cast<u32>(kPayloadRules.size())),
              PayloadValidationError::Ok);
    WriteLe32(payload + kVersionedPayloadHeaderBytes, value);
    WriteLe32(payload + kVersionedPayloadHeaderBytes + 4, ~value);
    return frame;
}

Handle InstallHandle(HandleTable& table, KObject* object, u32 slot_index, u64 rights, bool acquire, u32 generation = 1)
{
    if (generation == 0 || generation > kHandleGenerationMax)
        return kHandleInvalid;
    if (acquire && !KObjectAcquire(object))
        return kHandleInvalid;
    std::lock_guard<std::mutex> guard(g_table_lock);
    HandleSlot& slot = table.slots[slot_index];
    slot.obj = object;
    slot.rights = rights;
    slot.generation = generation;
    slot.acquisition_pins = 0;
    slot.state = HandleSlotState::Live;
    return HandleEncode(slot_index, slot.generation);
}

void RemoveHandle(HandleTable& table, Handle handle)
{
    auto detached = HandleTableDetach(table, handle, KObjectType::Invalid, 0);
    EXPECT_TRUE(detached.has_value());
    if (detached.has_value())
        KObjectRelease(detached.value());
}

KMessagePortSnapshot Inspect(KMessagePort* port)
{
    KMessagePortSnapshot snapshot{};
    EXPECT_EQ(KMessagePortInspect(port, &snapshot), KMessagePortStatus::Ok);
    return snapshot;
}

struct CopyWindowBarrier
{
    std::mutex inner;
    std::condition_variable changed;
    bool reached = false;
    bool resume = false;
};

void PauseInCopyWindow(void* context)
{
    auto& barrier = *static_cast<CopyWindowBarrier*>(context);
    std::unique_lock<std::mutex> lock(barrier.inner);
    barrier.reached = true;
    barrier.changed.notify_all();
    barrier.changed.wait(lock, [&barrier]() { return barrier.resume; });
}

} // namespace

int main()
{
    constexpr u64 kFullRights = kHandleRightRead | kHandleRightWrite | kHandleRightWait | kHandleRightDestroy |
                                kHandleRightDuplicate | kHandleRightTransfer | kHandleRightInspect;

    auto created = KMessagePortCreate();
    EXPECT_TRUE(created.has_value());
    if (!created.has_value())
        return duetos_host_test::finish_main("test_kmessage_port");
    KMessagePort* port = created.value();
    EXPECT_EQ(port->base.type, KObjectType::MessagePort);
    EXPECT_EQ(Inspect(port).ring.capacity_bytes, kMessagePortStorageBytes);
    const auto before_alias = Inspect(port);
    EXPECT_EQ(KMessagePortInspect(port, reinterpret_cast<KMessagePortSnapshot*>(port)),
              KMessagePortStatus::InvalidArgument);
    EXPECT_EQ(KMessagePortInspect(port, reinterpret_cast<KMessagePortSnapshot*>(port->storage)),
              KMessagePortStatus::InvalidArgument);
    const auto alias_frame = MakeFrame(6);
    const auto alias_send =
        KMessagePortSend(port, alias_frame.data(), static_cast<u32>(alias_frame.size()),
                         reinterpret_cast<const PayloadVersionRule*>(port), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(alias_send.status, KMessagePortStatus::InvalidArgument);
    EXPECT_EQ(alias_send.ring.status, MessageRingStatus::AliasedBuffer);
    const auto after_alias = Inspect(port);
    EXPECT_EQ(after_alias.ring.queued_frames, before_alias.ring.queued_frames);
    EXPECT_EQ(after_alias.ring.used_bytes, before_alias.ring.used_bytes);

    HandleTable table{};
    const Handle full = InstallHandle(table, &port->base, 1, kFullRights, false);
    const Handle write_only = InstallHandle(table, &port->base, 2, kHandleRightWrite, true);
    const Handle read_only = InstallHandle(table, &port->base, 3, kHandleRightRead, true);
    const Handle wait_only = InstallHandle(table, &port->base, 4, kHandleRightWait, true);
    EXPECT_EQ(KObjectRefcount(&port->base), 4U);

    const auto first = MakeFrame(7);
    EXPECT_EQ(KMessagePortSendHandle(table, read_only, first.data(), static_cast<u32>(first.size()),
                                     kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()))
                  .status,
              KMessagePortStatus::InvalidHandleOrRights);
    std::array<u8, kFrameBytes> copied{};
    EXPECT_EQ(KMessagePortTryReceiveHandle(table, write_only, copied.data(), static_cast<u32>(copied.size())).status,
              KMessagePortStatus::InvalidHandleOrRights);
    EXPECT_EQ(KMessagePortWaitReadableHandle(table, read_only), KMessagePortStatus::InvalidHandleOrRights);
    EXPECT_EQ(KMessagePortCloseHandle(table, wait_only), KMessagePortStatus::InvalidHandleOrRights);

    // A prepared reservation is not readiness. The waiter remains parked until
    // a port Send publishes and signals under the same predicate mutex.
    auto prepared = MessageRingPrepareEnqueue(&port->ring, first.data(), static_cast<u32>(first.size()),
                                              kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(prepared.status, MessageRingStatus::Ok);
    std::atomic<bool> waiter_started{false};
    std::atomic<bool> waiter_done{false};
    std::atomic<KMessagePortStatus> waiter_status{KMessagePortStatus::RingFailure};
    std::thread waiter(
        [&]()
        {
            waiter_started.store(true, std::memory_order_release);
            waiter_status.store(KMessagePortWaitReadableHandle(table, wait_only), std::memory_order_release);
            waiter_done.store(true, std::memory_order_release);
        });
    while (!waiter_started.load(std::memory_order_acquire))
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(waiter_done.load(std::memory_order_acquire));
    EXPECT_EQ(MessageRingAbortEnqueue(&port->ring, prepared.reservation_id), MessageRingStatus::Ok);
    auto sent = KMessagePortSendHandle(table, write_only, first.data(), static_cast<u32>(first.size()),
                                       kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(sent.status, KMessagePortStatus::Ok);
    const auto wake_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!waiter_done.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < wake_deadline)
        std::this_thread::yield();
    if (!waiter_done.load(std::memory_order_acquire))
        KMessagePortClose(port);
    waiter.join();
    EXPECT_TRUE(waiter_done.load(std::memory_order_acquire));
    EXPECT_EQ(waiter_status.load(std::memory_order_acquire), KMessagePortStatus::Ok);
    EXPECT_EQ(Inspect(port).ring.queued_frames, 1U);

    // A too-small destination cancels the exact receive claim; retry sees and
    // commits the same sequence once, with the bytes copied outside locks.
    std::array<u8, kFrameBytes - 1> too_small{};
    auto received =
        KMessagePortTryReceiveHandle(table, read_only, too_small.data(), static_cast<u32>(too_small.size()));
    EXPECT_EQ(received.status, KMessagePortStatus::RingFailure);
    EXPECT_EQ(received.ring_status, MessageRingStatus::BufferTooSmall);
    EXPECT_EQ(Inspect(port).ring.queued_frames, 1U);
    received = KMessagePortTryReceiveHandle(table, read_only, copied.data(), static_cast<u32>(copied.size()));
    EXPECT_EQ(received.status, KMessagePortStatus::Ok);
    EXPECT_TRUE(copied == first);
    EXPECT_EQ(Inspect(port).ring.queued_frames, 0U);

    // Hostile validation never reserves visible capacity.
    auto malformed = first;
    malformed[0] ^= 1U;
    const auto before_malformed = Inspect(port);
    sent = KMessagePortSendHandle(table, write_only, malformed.data(), static_cast<u32>(malformed.size()),
                                  kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
    EXPECT_EQ(sent.status, KMessagePortStatus::RingFailure);
    EXPECT_EQ(sent.ring.status, MessageRingStatus::MalformedMessage);
    const auto after_malformed = Inspect(port);
    EXPECT_EQ(after_malformed.ring.queued_frames, before_malformed.ring.queued_frames);
    EXPECT_EQ(after_malformed.ring.used_bytes, before_malformed.ring.used_bytes);

    // Teardown is terminal: a parked waiter wakes Closed, and retained sibling
    // handles keep storage alive long enough to observe rejected new ops.
    waiter_done.store(false, std::memory_order_release);
    std::thread closing_waiter(
        [&]()
        {
            waiter_status.store(KMessagePortWaitReadableHandle(table, wait_only), std::memory_order_release);
            waiter_done.store(true, std::memory_order_release);
        });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(KMessagePortCloseHandle(table, full), KMessagePortStatus::Ok);
    closing_waiter.join();
    EXPECT_TRUE(waiter_done.load(std::memory_order_acquire));
    EXPECT_EQ(waiter_status.load(std::memory_order_acquire), KMessagePortStatus::Closed);
    EXPECT_EQ(KMessagePortSend(port, first.data(), static_cast<u32>(first.size()), kPayloadRules.data(),
                               static_cast<u32>(kPayloadRules.size()))
                  .status,
              KMessagePortStatus::Closed);
    EXPECT_EQ(KMessagePortCloseHandle(table, full), KMessagePortStatus::InvalidHandleOrRights);
    EXPECT_TRUE(Inspect(port).closed);
    RemoveHandle(table, write_only);
    RemoveHandle(table, read_only);
    RemoveHandle(table, wait_only);

    // Deterministically close after the unlocked byte copy but before the
    // receiver reacquires the port mutex. Close cancels the exact lease without
    // consuming the frame; a fresh ring lease can retry the same sequence.
    auto copy_close_created = KMessagePortCreate();
    EXPECT_TRUE(copy_close_created.has_value());
    if (copy_close_created.has_value())
    {
        KMessagePort* copy_close_port = copy_close_created.value();
        const auto copy_close_frame = MakeFrame(8);
        const auto copy_close_sent =
            KMessagePortSend(copy_close_port, copy_close_frame.data(), static_cast<u32>(copy_close_frame.size()),
                             kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
        EXPECT_EQ(copy_close_sent.status, KMessagePortStatus::Ok);

        CopyWindowBarrier copy_window{};
        KMessagePortHostArmCopyWindowHook(copy_close_port, &PauseInCopyWindow, &copy_window);
        std::array<u8, kFrameBytes> interrupted_copy{};
        KMessagePortReceiveResult interrupted_result{KMessagePortStatus::RingFailure, MessageRingStatus::CorruptState,
                                                     0, 0, 0};
        std::thread interrupted_receiver(
            [&]()
            {
                interrupted_result = KMessagePortTryReceive(copy_close_port, interrupted_copy.data(),
                                                            static_cast<u32>(interrupted_copy.size()));
            });

        bool copy_window_reached = false;
        {
            std::unique_lock<std::mutex> lock(copy_window.inner);
            copy_window_reached = copy_window.changed.wait_for(lock, std::chrono::seconds(2),
                                                               [&copy_window]() { return copy_window.reached; });
        }
        EXPECT_TRUE(copy_window_reached);
        KMessagePortClose(copy_close_port);
        {
            std::lock_guard<std::mutex> lock(copy_window.inner);
            copy_window.resume = true;
        }
        copy_window.changed.notify_all();
        interrupted_receiver.join();

        EXPECT_EQ(interrupted_result.status, KMessagePortStatus::Closed);
        EXPECT_EQ(interrupted_result.ring_status, MessageRingStatus::ProducerAborted);
        EXPECT_EQ(interrupted_result.sequence, copy_close_sent.ring.sequence);
        EXPECT_EQ(interrupted_result.frame_size, static_cast<u32>(copy_close_frame.size()));
        EXPECT_EQ(interrupted_result.copied_bytes, 0U);
        EXPECT_TRUE(interrupted_copy == copy_close_frame);
        const auto after_copy_close = Inspect(copy_close_port);
        EXPECT_TRUE(after_copy_close.closed);
        EXPECT_EQ(after_copy_close.ring.queued_frames, 1U);
        EXPECT_EQ(after_copy_close.ring.receive_sequence, 0ULL);

        std::array<u8, kFrameBytes> closed_destination{};
        EXPECT_EQ(KMessagePortTryReceive(copy_close_port, closed_destination.data(),
                                         static_cast<u32>(closed_destination.size()))
                      .status,
                  KMessagePortStatus::Closed);
        EXPECT_EQ(Inspect(copy_close_port).ring.queued_frames, 1U);

        MessageRingPeekView retry_view{};
        EXPECT_EQ(MessageRingPeek(&copy_close_port->ring, &retry_view), MessageRingStatus::Ok);
        EXPECT_EQ(retry_view.sequence, copy_close_sent.ring.sequence);
        std::array<u8, kFrameBytes> retried_copy{};
        u32 retried_bytes = 0;
        EXPECT_EQ(MessageRingCopyOut(&copy_close_port->ring, retry_view.sequence, retry_view.receive_lease_id,
                                     retried_copy.data(), static_cast<u32>(retried_copy.size()), &retried_bytes),
                  MessageRingStatus::Ok);
        EXPECT_EQ(retried_bytes, static_cast<u32>(retried_copy.size()));
        EXPECT_TRUE(retried_copy == copy_close_frame);
        EXPECT_EQ(MessageRingCommit(&copy_close_port->ring, retry_view.sequence, retry_view.receive_lease_id),
                  MessageRingStatus::Ok);
        EXPECT_EQ(Inspect(copy_close_port).ring.queued_frames, 0U);
        KObjectRelease(&copy_close_port->base);
    }

    // A close of the same handle while receive copy-out is unlocked detaches
    // the handle reference, but the lookup reference keeps the object alive
    // until the receiver reacquires the mutex, cancels its exact lease, and
    // unwinds. Destruction occurs only after the wrapper releases that pin.
    const u32 destroyed_before_inflight_close = g_destroyed.load(std::memory_order_relaxed);
    auto inflight_created = KMessagePortCreate();
    EXPECT_TRUE(inflight_created.has_value());
    if (inflight_created.has_value())
    {
        KMessagePort* inflight_port = inflight_created.value();
        HandleTable inflight_table{};
        const Handle inflight_handle = InstallHandle(inflight_table, &inflight_port->base, 1, kFullRights, false);
        const auto inflight_frame = MakeFrame(9);
        const auto inflight_sent = KMessagePortSendHandle(inflight_table, inflight_handle, inflight_frame.data(),
                                                          static_cast<u32>(inflight_frame.size()), kPayloadRules.data(),
                                                          static_cast<u32>(kPayloadRules.size()));
        EXPECT_EQ(inflight_sent.status, KMessagePortStatus::Ok);

        CopyWindowBarrier inflight_window{};
        KMessagePortHostArmCopyWindowHook(inflight_port, &PauseInCopyWindow, &inflight_window);
        std::array<u8, kFrameBytes> inflight_copy{};
        KMessagePortReceiveResult inflight_result{KMessagePortStatus::RingFailure, MessageRingStatus::CorruptState, 0,
                                                  0, 0};
        std::thread inflight_receiver(
            [&]()
            {
                inflight_result = KMessagePortTryReceiveHandle(inflight_table, inflight_handle, inflight_copy.data(),
                                                               static_cast<u32>(inflight_copy.size()));
            });

        bool inflight_window_reached = false;
        {
            std::unique_lock<std::mutex> lock(inflight_window.inner);
            inflight_window_reached = inflight_window.changed.wait_for(
                lock, std::chrono::seconds(2), [&inflight_window]() { return inflight_window.reached; });
        }
        EXPECT_TRUE(inflight_window_reached);
        EXPECT_EQ(KMessagePortCloseHandle(inflight_table, inflight_handle), KMessagePortStatus::Ok);
        EXPECT_EQ(g_destroyed.load(std::memory_order_relaxed), destroyed_before_inflight_close);
        EXPECT_EQ(KMessagePortWaitReadableHandle(inflight_table, inflight_handle),
                  KMessagePortStatus::InvalidHandleOrRights);
        {
            std::lock_guard<std::mutex> lock(inflight_window.inner);
            inflight_window.resume = true;
        }
        inflight_window.changed.notify_all();
        inflight_receiver.join();

        EXPECT_EQ(inflight_result.status, KMessagePortStatus::Closed);
        EXPECT_EQ(inflight_result.ring_status, MessageRingStatus::ProducerAborted);
        EXPECT_EQ(inflight_result.sequence, inflight_sent.ring.sequence);
        EXPECT_EQ(inflight_result.copied_bytes, 0U);
        EXPECT_TRUE(inflight_copy == inflight_frame);
        EXPECT_EQ(g_destroyed.load(std::memory_order_relaxed), destroyed_before_inflight_close + 1U);
    }

    // Reusing a table slot with a new generation cannot revive authority from
    // the detached handle. Every stale wrapper rejects before touching the
    // replacement, while the exact new handle retains full functionality.
    const u32 destroyed_before_aba = g_destroyed.load(std::memory_order_relaxed);
    HandleTable aba_table{};
    auto aba_first_created = KMessagePortCreate();
    EXPECT_TRUE(aba_first_created.has_value());
    Handle stale_handle = kHandleInvalid;
    if (aba_first_created.has_value())
    {
        KMessagePort* aba_first = aba_first_created.value();
        stale_handle = InstallHandle(aba_table, &aba_first->base, 1, kFullRights, false, 1);
        EXPECT_EQ(KMessagePortCloseHandle(aba_table, stale_handle), KMessagePortStatus::Ok);
        EXPECT_EQ(g_destroyed.load(std::memory_order_relaxed), destroyed_before_aba + 1U);
    }

    auto aba_replacement_created = KMessagePortCreate();
    EXPECT_TRUE(aba_replacement_created.has_value());
    if (aba_replacement_created.has_value())
    {
        KMessagePort* aba_replacement = aba_replacement_created.value();
        const Handle replacement_handle = InstallHandle(aba_table, &aba_replacement->base, 1, kFullRights, false, 2);
        EXPECT_NE(replacement_handle, stale_handle);
        const auto aba_frame = MakeFrame(10);
        std::array<u8, kFrameBytes> aba_copy{};
        EXPECT_EQ(KMessagePortSendHandle(aba_table, stale_handle, aba_frame.data(), static_cast<u32>(aba_frame.size()),
                                         kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()))
                      .status,
                  KMessagePortStatus::InvalidHandleOrRights);
        EXPECT_EQ(
            KMessagePortTryReceiveHandle(aba_table, stale_handle, aba_copy.data(), static_cast<u32>(aba_copy.size()))
                .status,
            KMessagePortStatus::InvalidHandleOrRights);
        EXPECT_EQ(KMessagePortWaitReadableHandle(aba_table, stale_handle), KMessagePortStatus::InvalidHandleOrRights);
        EXPECT_EQ(KMessagePortCloseHandle(aba_table, stale_handle), KMessagePortStatus::InvalidHandleOrRights);
        EXPECT_FALSE(Inspect(aba_replacement).closed);
        EXPECT_EQ(Inspect(aba_replacement).ring.queued_frames, 0U);

        EXPECT_EQ(KMessagePortSendHandle(aba_table, replacement_handle, aba_frame.data(),
                                         static_cast<u32>(aba_frame.size()), kPayloadRules.data(),
                                         static_cast<u32>(kPayloadRules.size()))
                      .status,
                  KMessagePortStatus::Ok);
        EXPECT_EQ(KMessagePortTryReceiveHandle(aba_table, replacement_handle, aba_copy.data(),
                                               static_cast<u32>(aba_copy.size()))
                      .status,
                  KMessagePortStatus::Ok);
        EXPECT_TRUE(aba_copy == aba_frame);
        EXPECT_EQ(KMessagePortCloseHandle(aba_table, replacement_handle), KMessagePortStatus::Ok);
        EXPECT_EQ(g_destroyed.load(std::memory_order_relaxed), destroyed_before_aba + 2U);
    }

    // MPSC stress through one generation-tagged handle: producers retry only
    // explicit Busy/Full backpressure; one waiter/receiver consumes every
    // exact payload once.
    auto stress_created = KMessagePortCreate();
    EXPECT_TRUE(stress_created.has_value());
    if (stress_created.has_value())
    {
        KMessagePort* stress_port = stress_created.value();
        HandleTable stress_table{};
        const Handle stress_handle = InstallHandle(stress_table, &stress_port->base, 1, kFullRights, false);
        constexpr u32 kProducerCount = 4;
        constexpr u32 kPerProducer = 200;
        constexpr u32 kTotal = kProducerCount * kPerProducer;
        std::array<std::array<u8, kFrameBytes>, kTotal> frames{};
        for (u32 item = 0; item < kTotal; ++item)
            frames[item] = MakeFrame(item);

        std::atomic<bool> start{false};
        std::atomic<bool> stop{false};
        std::atomic<u32> failures{0};
        std::vector<std::thread> producers;
        for (u32 producer = 0; producer < kProducerCount; ++producer)
        {
            producers.emplace_back(
                [&, producer]()
                {
                    while (!start.load(std::memory_order_acquire))
                        std::this_thread::yield();
                    for (u32 local = 0; local < kPerProducer && !stop.load(std::memory_order_relaxed); ++local)
                    {
                        const u32 item = producer * kPerProducer + local;
                        for (;;)
                        {
                            const auto result = KMessagePortSendHandle(
                                stress_table, stress_handle, frames[item].data(), static_cast<u32>(frames[item].size()),
                                kPayloadRules.data(), static_cast<u32>(kPayloadRules.size()));
                            if (result.status == KMessagePortStatus::Ok)
                                break;
                            if (result.status != KMessagePortStatus::RingFailure ||
                                (result.ring.status != MessageRingStatus::Busy &&
                                 result.ring.status != MessageRingStatus::Full))
                            {
                                failures.fetch_add(1, std::memory_order_relaxed);
                                stop.store(true, std::memory_order_release);
                                break;
                            }
                            std::this_thread::yield();
                        }
                    }
                });
        }

        std::array<u8, kTotal> seen{};
        u32 consumed = 0;
        start.store(true, std::memory_order_release);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (consumed < kTotal && !stop.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline)
        {
            if (KMessagePortWaitReadableHandle(stress_table, stress_handle) != KMessagePortStatus::Ok)
            {
                failures.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            std::array<u8, kFrameBytes> frame{};
            const auto result =
                KMessagePortTryReceiveHandle(stress_table, stress_handle, frame.data(), static_cast<u32>(frame.size()));
            if (result.status != KMessagePortStatus::Ok)
            {
                failures.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            const u8* payload = frame.data() + kMessageAbiHeaderV1Bytes + kVersionedPayloadHeaderBytes;
            const u32 item = ReadLe32(payload);
            if (item >= kTotal || ReadLe32(payload + 4) != ~item || seen[item] != 0)
            {
                failures.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            seen[item] = 1;
            ++consumed;
        }
        if (consumed != kTotal)
            stop.store(true, std::memory_order_release);
        for (auto& producer : producers)
            producer.join();
        EXPECT_EQ(failures.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(consumed, kTotal);
        for (u8 value : seen)
            EXPECT_EQ(value, 1U);
        EXPECT_EQ(KMessagePortCloseHandle(stress_table, stress_handle), KMessagePortStatus::Ok);
    }

    EXPECT_EQ(g_destroyed.load(std::memory_order_relaxed), 6U);
    EXPECT_STREQ(KMessagePortStatusName(KMessagePortStatus::Closed), "closed");
    EXPECT_STREQ(KMessagePortStatusName(static_cast<KMessagePortStatus>(0xFF)), "unknown");
    return duetos_host_test::finish_main("test_kmessage_port");
}
