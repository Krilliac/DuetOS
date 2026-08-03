// Hosted hostile-input, lifetime, replay, rights, and concurrency coverage for
// ipc/object_transfer.{h,cpp}.  Minimal public HandleTable/KObject definitions
// keep this target focused on the transfer contract.  The production source is
// compiled against the same exact lookup/retain/insert API.

#include "host_test_helper.h"
#include "ipc/object_transfer.h"

#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <type_traits>
#include <vector>

namespace
{

std::mutex g_object_lock;
std::mutex g_handle_lock;
std::atomic<duetos::u32> g_destroyed{0};
std::atomic<duetos::u64> g_next_reservation_nonce{1};
std::atomic<duetos::u32> g_reserve_calls{0};
std::atomic<duetos::u32> g_publish_calls{0};
std::atomic<duetos::u32> g_abort_calls{0};

struct AcquireGate
{
    std::atomic<duetos::ipc::KObject*> target{nullptr};
    std::atomic<bool> armed{false};
    std::atomic<bool> entered{false};
    std::atomic<bool> released{false};
};

AcquireGate g_acquire_gate;

void MaybeBlockAcquire(duetos::ipc::KObject* object)
{
    if (g_acquire_gate.target.load(std::memory_order_acquire) != object ||
        !g_acquire_gate.armed.exchange(false, std::memory_order_acq_rel))
    {
        return;
    }
    g_acquire_gate.entered.store(true, std::memory_order_release);
    g_acquire_gate.entered.notify_all();
    g_acquire_gate.released.wait(false, std::memory_order_acquire);
}

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
    MaybeBlockAcquire(object);
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
        destroy(object);
}

u32 KObjectRefcount(const KObject* object)
{
    if (object == nullptr)
        return 0;
    std::lock_guard<std::mutex> guard(g_object_lock);
    return object->refcount;
}

u64 TypeAllowedRights(KObjectType type)
{
    if (type == KObjectType::Test)
        return kHandleRightAll;
    if (type == KObjectType::Event)
    {
        return kHandleRightDuplicate | kHandleRightTransfer | kHandleRightDestroy | kHandleRightInspect |
               kHandleRightWait | kHandleRightSignal;
    }
    return 0;
}

KObject* HandleTableLookupRef(HandleTable& table, Handle handle, KObjectType expected_type, u64 required_rights)
{
    KObject* object = nullptr;
    u32 pinned_slot = 0;
    u32 pinned_generation = 0;
    {
        std::lock_guard<std::mutex> guard(g_handle_lock);
        if (table.state != HandleTableState::Open || !HandleDecode(handle, &pinned_slot, &pinned_generation))
            return nullptr;
        HandleSlot& slot = table.slots[pinned_slot];
        if (slot.state != HandleSlotState::Live || slot.generation != pinned_generation || slot.obj == nullptr ||
            slot.obj->type != expected_type || (slot.rights & required_rights) != required_rights)
        {
            return nullptr;
        }
        if (slot.acquisition_pins == static_cast<u32>(-1) || table.active_operations == static_cast<u32>(-1))
            return nullptr;
        object = slot.obj;
        ++slot.acquisition_pins;
        ++table.active_operations;
    }

    const bool retained = KObjectAcquire(object);
    bool identity_intact = false;
    {
        std::lock_guard<std::mutex> guard(g_handle_lock);
        HandleSlot& slot = table.slots[pinned_slot];
        identity_intact = slot.generation == pinned_generation && slot.obj == object &&
                          (slot.state == HandleSlotState::Live || slot.state == HandleSlotState::Closing) &&
                          slot.acquisition_pins > 0 && table.active_operations > 0;
        if (slot.acquisition_pins > 0)
            --slot.acquisition_pins;
        if (table.active_operations > 0)
            --table.active_operations;
    }
    if (!identity_intact || !retained)
    {
        if (retained)
            KObjectRelease(object);
        return nullptr;
    }
    return object;
}

core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* object, u64 requested_rights)
{
    if (object == nullptr || object->type == KObjectType::Invalid || requested_rights == 0 ||
        (requested_rights & ~TypeAllowedRights(object->type)) != 0)
    {
        return core::Err{core::ErrorCode::InvalidArgument};
    }

    std::lock_guard<std::mutex> guard(g_handle_lock);
    if (table.state != HandleTableState::Open)
        return core::Err{core::ErrorCode::BadState};
    for (u32 index = 1; index < kHandleTableCapacity; ++index)
    {
        HandleSlot& slot = table.slots[index];
        if (slot.state != HandleSlotState::Free || slot.generation == kHandleGenerationMax)
            continue;
        ++slot.generation;
        slot.obj = object;
        slot.rights = requested_rights;
        slot.reservation_nonce = 0;
        slot.acquisition_pins = 0;
        slot.reserved_type = KObjectType::Invalid;
        slot.state = HandleSlotState::Live;
        table.next_free_hint = index;
        return HandleEncode(index, slot.generation);
    }
    return core::Err{core::ErrorCode::OutOfMemory};
}

core::Result<HandleTableReservation> HandleTableReserve(HandleTable& table, KObjectType object_type,
                                                        u64 requested_rights)
{
    g_reserve_calls.fetch_add(1, std::memory_order_relaxed);
    if (object_type == KObjectType::Invalid || requested_rights == 0 || (requested_rights & ~kHandleRightAll) != 0)
    {
        return core::Err{core::ErrorCode::InvalidArgument};
    }
    if ((requested_rights & ~TypeAllowedRights(object_type)) != 0)
        return core::Err{core::ErrorCode::PermissionDenied};

    std::lock_guard<std::mutex> guard(g_handle_lock);
    if (table.state != HandleTableState::Open)
        return core::Err{core::ErrorCode::BadState};
    const u32 start = (table.next_free_hint + 1u) % kHandleTableCapacity;
    for (u32 step = 0; step < kHandleTableCapacity; ++step)
    {
        u32 index = start + step;
        if (index >= kHandleTableCapacity)
            index -= kHandleTableCapacity;
        if (index == 0)
            continue;
        HandleSlot& slot = table.slots[index];
        if (slot.state != HandleSlotState::Free)
            continue;
        if (slot.generation == kHandleGenerationMax)
        {
            slot.state = HandleSlotState::Retired;
            continue;
        }

        const u64 nonce = g_next_reservation_nonce.fetch_add(1, std::memory_order_relaxed);
        if (nonce == 0)
            return core::Err{core::ErrorCode::Overflow};
        ++slot.generation;
        slot.obj = nullptr;
        slot.rights = requested_rights;
        slot.reservation_nonce = nonce;
        slot.acquisition_pins = 0;
        slot.reserved_type = object_type;
        slot.state = HandleSlotState::Reserved;
        table.next_free_hint = index;
        return HandleTableReservation{HandleEncode(index, slot.generation), nonce};
    }
    return core::Err{core::ErrorCode::OutOfMemory};
}

core::Result<Handle> HandleTablePublish(HandleTable& table, HandleTableReservation reservation, KObject* object)
{
    g_publish_calls.fetch_add(1, std::memory_order_relaxed);
    u32 slot_index = 0;
    u32 generation = 0;
    if (!HandleTableReservationIsValid(reservation) || !HandleDecode(reservation.handle, &slot_index, &generation) ||
        object == nullptr || object->type == KObjectType::Invalid || KObjectRefcount(object) == 0)
    {
        return core::Err{core::ErrorCode::InvalidArgument};
    }

    std::lock_guard<std::mutex> guard(g_handle_lock);
    if (table.state != HandleTableState::Open)
        return core::Err{core::ErrorCode::BadState};
    HandleSlot& slot = table.slots[slot_index];
    if (slot.state != HandleSlotState::Reserved || slot.generation != generation ||
        slot.reservation_nonce != reservation.nonce || slot.obj != nullptr || slot.acquisition_pins != 0 ||
        slot.reserved_type != object->type)
    {
        return core::Err{core::ErrorCode::InvalidArgument};
    }
    if ((slot.rights & ~TypeAllowedRights(object->type)) != 0)
        return core::Err{core::ErrorCode::PermissionDenied};

    slot.obj = object;
    slot.reservation_nonce = 0;
    slot.reserved_type = KObjectType::Invalid;
    slot.state = HandleSlotState::Live;
    return reservation.handle;
}

core::Result<void> HandleTableAbort(HandleTable& table, HandleTableReservation reservation)
{
    g_abort_calls.fetch_add(1, std::memory_order_relaxed);
    u32 slot_index = 0;
    u32 generation = 0;
    if (!HandleTableReservationIsValid(reservation) || !HandleDecode(reservation.handle, &slot_index, &generation))
        return core::Err{core::ErrorCode::InvalidArgument};

    std::lock_guard<std::mutex> guard(g_handle_lock);
    if (table.state != HandleTableState::Open)
        return core::Err{core::ErrorCode::BadState};
    HandleSlot& slot = table.slots[slot_index];
    if (slot.state != HandleSlotState::Reserved || slot.generation != generation ||
        slot.reservation_nonce != reservation.nonce || slot.obj != nullptr || slot.acquisition_pins != 0 ||
        slot.reserved_type == KObjectType::Invalid)
    {
        return core::Err{core::ErrorCode::InvalidArgument};
    }

    slot.rights = 0;
    slot.reservation_nonce = 0;
    slot.reserved_type = KObjectType::Invalid;
    slot.state = slot.generation == kHandleGenerationMax ? HandleSlotState::Retired : HandleSlotState::Free;
    return {};
}

} // namespace duetos::ipc

namespace
{

using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::ipc;

struct TestObject
{
    KObject base;
    ObjectTransferTable* close_on_destroy = nullptr;
    ObjectTransferStatus reentrant_close_status = ObjectTransferStatus::CorruptState;
};

void DestroyTestObject(KObject* object)
{
    auto* test_object = reinterpret_cast<TestObject*>(object);
    if (test_object->close_on_destroy != nullptr)
        test_object->reentrant_close_status = ObjectTransferTableClose(test_object->close_on_destroy);
    g_destroyed.fetch_add(1, std::memory_order_relaxed);
}

void InitializeHandleTable(HandleTable* table)
{
    *table = HandleTable{};
    table->state = HandleTableState::Open;
    for (u32 index = 0; index < kHandleTableCapacity; ++index)
    {
        table->slots[index].obj = nullptr;
        table->slots[index].rights = 0;
        table->slots[index].reservation_nonce = 0;
        table->slots[index].generation = 0;
        table->slots[index].acquisition_pins = 0;
        table->slots[index].reserved_type = KObjectType::Invalid;
        table->slots[index].state = index == 0 ? HandleSlotState::Retired : HandleSlotState::Free;
    }
}

Handle InstallInitial(HandleTable* table, KObject* object, u64 rights)
{
    auto inserted = HandleTableInsert(*table, object, rights);
    EXPECT_TRUE(inserted.has_value());
    return inserted.has_value() ? inserted.value() : kHandleInvalid;
}

u64 HostHandleRights(HandleTable* table, Handle handle)
{
    std::lock_guard<std::mutex> guard(g_handle_lock);
    u32 slot_index = 0;
    u32 generation = 0;
    if (!HandleDecode(handle, &slot_index, &generation))
        return 0;
    const HandleSlot& slot = table->slots[slot_index];
    return slot.state == HandleSlotState::Live && slot.generation == generation ? slot.rights : 0;
}

void HostRemoveHandle(HandleTable* table, Handle handle)
{
    KObject* object = nullptr;
    u32 slot_index = 0;
    u32 generation = 0;
    if (!HandleDecode(handle, &slot_index, &generation))
        return;

    for (;;)
    {
        {
            std::lock_guard<std::mutex> guard(g_handle_lock);
            HandleSlot& slot = table->slots[slot_index];
            if (slot.generation != generation ||
                (slot.state != HandleSlotState::Live && slot.state != HandleSlotState::Closing))
            {
                return;
            }
            slot.state = HandleSlotState::Closing;
            if (slot.acquisition_pins == 0)
            {
                object = slot.obj;
                slot.obj = nullptr;
                slot.rights = 0;
                slot.reservation_nonce = 0;
                slot.reserved_type = KObjectType::Invalid;
                slot.state = slot.generation == kHandleGenerationMax ? HandleSlotState::Retired : HandleSlotState::Free;
            }
        }
        if (object != nullptr)
            break;
        std::this_thread::yield();
    }
    KObjectRelease(object);
}

void HostDrainHandleTable(HandleTable* table)
{
    std::array<KObject*, kHandleTableCapacity> detached{};
    u32 count = 0;
    {
        std::lock_guard<std::mutex> guard(g_handle_lock);
        table->state = HandleTableState::Closed;
        for (u32 index = 1; index < kHandleTableCapacity; ++index)
        {
            HandleSlot& slot = table->slots[index];
            if (slot.obj != nullptr)
                detached[count++] = slot.obj;
            slot.obj = nullptr;
            slot.rights = 0;
            slot.reservation_nonce = 0;
            slot.acquisition_pins = 0;
            slot.reserved_type = KObjectType::Invalid;
            slot.state = slot.generation == kHandleGenerationMax ? HandleSlotState::Retired : HandleSlotState::Free;
        }
        table->active_operations = 0;
    }
    for (u32 index = 0; index < count; ++index)
        KObjectRelease(detached[index]);
}

ObjectTransferImmutableMetadata MakeMetadata(u64 identity, u8 seed)
{
    ObjectTransferImmutableMetadata metadata{};
    metadata.identity = identity;
    metadata.object_size = 0x4000 + identity;
    for (u32 index = 0; index < 32; ++index)
        metadata.content_hash[index] = static_cast<u8>(seed + index);
    metadata.flags = kObjectTransferMetadataSealed;
    return metadata;
}

ObjectTransferAuthority MakeAuthority(u64 rights, u64 identity = 1, u8 seed = 0x20)
{
    return ObjectTransferAuthority{KObjectType::Test, rights, MakeMetadata(identity, seed)};
}

struct TransferFixture
{
    TestObject object{};
    HandleTable source{};
    ObjectTransferTable transfer{};
    Handle source_handle = kHandleInvalid;

    explicit TransferFixture(u64 source_rights = kHandleRightAll, u32 first_generation = 1)
    {
        KObjectInit(&object.base, KObjectType::Test, &DestroyTestObject);
        InitializeHandleTable(&source);
        source_handle = InstallInitial(&source, &object.base, source_rights);
        EXPECT_EQ(ObjectTransferTableInitialize(&transfer, first_generation), ObjectTransferStatus::Ok);
    }

    ~TransferFixture()
    {
        ObjectTransferTableClose(&transfer);
        HostDrainHandleTable(&source);
    }
};

bool WaitForTrue(const std::atomic<bool>& value)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!value.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    return value.load(std::memory_order_acquire);
}

bool WaitForClosing(ObjectTransferTable* table)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (ObjectTransferLiveCount(table) != 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    return ObjectTransferLiveCount(table) == 0;
}

bool WaitForHandleClosing(HandleTable* table, Handle handle)
{
    u32 slot_index = 0;
    u32 generation = 0;
    if (!HandleDecode(handle, &slot_index, &generation))
        return false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    for (;;)
    {
        {
            std::lock_guard<std::mutex> guard(g_handle_lock);
            const HandleSlot& slot = table->slots[slot_index];
            if (slot.generation == generation && slot.state == HandleSlotState::Closing)
                return true;
        }
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::yield();
    }
}

HandleTableReservation HostFindReservation(HandleTable* table)
{
    std::lock_guard<std::mutex> guard(g_handle_lock);
    for (u32 index = 1; index < kHandleTableCapacity; ++index)
    {
        const HandleSlot& slot = table->slots[index];
        if (slot.state == HandleSlotState::Reserved && slot.reservation_nonce != 0)
            return HandleTableReservation{HandleEncode(index, slot.generation), slot.reservation_nonce};
    }
    return kInvalidHandleTableReservation;
}

u32 HostReservedCount(HandleTable* table)
{
    std::lock_guard<std::mutex> guard(g_handle_lock);
    u32 count = 0;
    for (u32 index = 1; index < kHandleTableCapacity; ++index)
    {
        if (table->slots[index].state == HandleSlotState::Reserved)
            ++count;
    }
    return count;
}

} // namespace

int main()
{
    // Decoding publishes one value, so callers cannot alias slot/generation
    // output pointers. Opaque references remain positive and exact.
    {
        static_assert(
            std::is_same_v<decltype(ObjectTransferRefDecode(kObjectTransferRefInvalid)), ObjectTransferDecodedRef>);
        const ObjectTransferRef reference = ObjectTransferRefEncode(1, 7);
        const ObjectTransferDecodedRef decoded = ObjectTransferRefDecode(reference);
        EXPECT_TRUE(ObjectTransferDecodedRefIsValid(decoded));
        EXPECT_EQ(decoded.slot, 1U);
        EXPECT_EQ(decoded.generation, 7U);
        EXPECT_TRUE(reference <= kObjectTransferPositiveMax);
        EXPECT_FALSE(ObjectTransferDecodedRefIsValid(ObjectTransferRefDecode(0)));
        EXPECT_FALSE(ObjectTransferDecodedRefIsValid(ObjectTransferRefDecode(0x80000001U)));
        EXPECT_FALSE(ObjectTransferDecodedRefIsValid(ObjectTransferRefDecode(1U << kObjectTransferSlotBits)));
        EXPECT_FALSE(ObjectTransferDecodedRefIsValid(
            ObjectTransferRefDecode((1U << kObjectTransferSlotBits) | kObjectTransferTableCapacity)));
    }

    // Initialize is one-shot from canonical zero storage. Invalid construction
    // never repairs corrupt storage, and Closed cannot be reset to generation 1.
    {
        ObjectTransferTable table{};
        EXPECT_EQ(ObjectTransferTableInitialize(nullptr), ObjectTransferStatus::InvalidArgument);
        EXPECT_EQ(ObjectTransferTableInitialize(&table, 0), ObjectTransferStatus::InvalidArgument);
        EXPECT_EQ(table.initialized, 0U);
        table.next_free_hint = 1;
        EXPECT_EQ(ObjectTransferTableInitialize(&table), ObjectTransferStatus::CorruptState);
        EXPECT_EQ(table.initialized, 0U);
        table.next_free_hint = 0;
        EXPECT_EQ(ObjectTransferTableInitialize(&table), ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferTableInitialize(&table), ObjectTransferStatus::AlreadyInitialized);
        EXPECT_EQ(ObjectTransferTableClose(&table), ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferTableInitialize(&table, 1), ObjectTransferStatus::AlreadyInitialized);
        EXPECT_EQ(table.state, ObjectTransferTableState::Closed);
    }

    // The hosted HandleTable seam preserves the production unpublished-ticket
    // contract used by imports: tickets are table/generation/nonce exact,
    // publication adopts once, and abort/publish replays fail closed.
    {
        TestObject object{};
        KObjectInit(&object.base, KObjectType::Test, &DestroyTestObject);
        HandleTable destination{};
        HandleTable other{};
        InitializeHandleTable(&destination);
        InitializeHandleTable(&other);

        const auto reserved = HandleTableReserve(destination, KObjectType::Test, kHandleRightRead);
        ASSERT_TRUE(reserved.has_value());
        const HandleTableReservation ticket = reserved.value();
        EXPECT_EQ(HostHandleRights(&destination, ticket.handle), 0U);
        EXPECT_FALSE(HandleTablePublish(other, ticket, &object.base).has_value());
        EXPECT_FALSE(HandleTableAbort(other, ticket).has_value());
        HandleTableReservation wrong_nonce = ticket;
        ++wrong_nonce.nonce;
        EXPECT_FALSE(HandleTableAbort(destination, wrong_nonce).has_value());

        const auto published = HandleTablePublish(destination, ticket, &object.base);
        ASSERT_TRUE(published.has_value());
        EXPECT_EQ(published.value(), ticket.handle);
        EXPECT_EQ(HostHandleRights(&destination, ticket.handle), kHandleRightRead);
        EXPECT_FALSE(HandleTablePublish(destination, ticket, &object.base).has_value());
        EXPECT_FALSE(HandleTableAbort(destination, ticket).has_value());
        HostDrainHandleTable(&destination);
        HostDrainHandleTable(&other);
    }

    // The trusted export authority must be concrete, sealed, canonical, and
    // backed atomically by Transfer + Duplicate + every granted right.
    {
        TransferFixture fixture(kHandleRightTransfer | kHandleRightDuplicate | kHandleRightRead);
        const u32 before = KObjectRefcount(&fixture.object.base);

        ObjectTransferAuthority invalid = MakeAuthority(kHandleRightRead);
        invalid.type = KObjectType::Invalid;
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle, invalid).status,
                  ObjectTransferStatus::InvalidArgument);
        invalid = MakeAuthority(kHandleRightRead);
        invalid.metadata.identity = 0;
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle, invalid).status,
                  ObjectTransferStatus::InvalidArgument);
        invalid = MakeAuthority(kHandleRightRead);
        invalid.metadata.flags = 0;
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle, invalid).status,
                  ObjectTransferStatus::InvalidArgument);
        invalid = MakeAuthority(kHandleRightRead);
        invalid.metadata.reserved = 1;
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle, invalid).status,
                  ObjectTransferStatus::InvalidArgument);
        invalid = MakeAuthority(kHandleRightAll | (1ULL << 40));
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle, invalid).status,
                  ObjectTransferStatus::InvalidArgument);
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                       MakeAuthority(kHandleRightWrite))
                      .status,
                  ObjectTransferStatus::SourceRejected);
        invalid = MakeAuthority(kHandleRightInspect);
        invalid.type = KObjectType::Event;
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle, invalid).status,
                  ObjectTransferStatus::SourceRejected);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), before);
        EXPECT_EQ(ObjectTransferLiveCount(&fixture.transfer), 0U);
    }
    {
        TransferFixture missing_duplicate(kHandleRightTransfer | kHandleRightRead);
        EXPECT_EQ(ObjectTransferExport(&missing_duplicate.transfer, &missing_duplicate.source,
                                       missing_duplicate.source_handle, MakeAuthority(kHandleRightRead))
                      .status,
                  ObjectTransferStatus::SourceRejected);
    }
    {
        TransferFixture missing_transfer(kHandleRightDuplicate | kHandleRightRead);
        EXPECT_EQ(ObjectTransferExport(&missing_transfer.transfer, &missing_transfer.source,
                                       missing_transfer.source_handle, MakeAuthority(kHandleRightRead))
                      .status,
                  ObjectTransferStatus::SourceRejected);
    }

    // Source close cannot invalidate the exact retained lookup already pinned
    // by Export. Close waits only in the hosted HandleTable model; Export then
    // transfers its retained reference into the row without resurrection.
    {
        TransferFixture fixture;
        g_acquire_gate.target.store(&fixture.object.base, std::memory_order_release);
        g_acquire_gate.entered.store(false, std::memory_order_release);
        g_acquire_gate.released.store(false, std::memory_order_release);
        g_acquire_gate.armed.store(true, std::memory_order_release);

        ObjectTransferExportResult export_result{};
        std::atomic<bool> source_close_done{false};
        std::thread exporter(
            [&]()
            {
                export_result = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                     MakeAuthority(kHandleRightRead, 31));
            });
        EXPECT_TRUE(WaitForTrue(g_acquire_gate.entered));
        std::thread source_closer(
            [&]()
            {
                HostRemoveHandle(&fixture.source, fixture.source_handle);
                source_close_done.store(true, std::memory_order_release);
            });
        EXPECT_TRUE(WaitForHandleClosing(&fixture.source, fixture.source_handle));
        EXPECT_FALSE(source_close_done.load(std::memory_order_acquire));

        g_acquire_gate.released.store(true, std::memory_order_release);
        g_acquire_gate.released.notify_all();
        exporter.join();
        source_closer.join();
        g_acquire_gate.target.store(nullptr, std::memory_order_release);
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                       MakeAuthority(kHandleRightRead, 32))
                      .status,
                  ObjectTransferStatus::SourceRejected);
        fixture.source_handle = kHandleInvalid;

        EXPECT_EQ(export_result.status, ObjectTransferStatus::Ok);
        EXPECT_TRUE(source_close_done.load(std::memory_order_acquire));
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
        HandleTable destination{};
        InitializeHandleTable(&destination);
        const ObjectTransferImportResult imported = ObjectTransferImport(
            &fixture.transfer, export_result.reference, &destination, KObjectType::Test, kHandleRightRead);
        EXPECT_EQ(imported.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, export_result.reference), ObjectTransferStatus::Ok);
        HostDrainHandleTable(&destination);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 0U);
    }

    // Hostile fields can only select and narrow table-owned authority.  The
    // imported metadata is the frozen trusted copy, and persistent import was
    // authorized by source Duplicate even though the stored ceiling omits it.
    {
        TransferFixture fixture;
        ObjectTransferAuthority authority = MakeAuthority(kHandleRightRead | kHandleRightWait, 41, 0x51);
        const ObjectTransferImmutableMetadata frozen = authority.metadata;
        const ObjectTransferExportResult exported =
            ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle, authority);
        EXPECT_EQ(exported.status, ObjectTransferStatus::Ok);
        EXPECT_NE(exported.reference, kObjectTransferRefInvalid);
        authority.metadata.identity = 999;
        authority.metadata.content_hash[0] ^= 0xFF;

        HandleTable destination{};
        InitializeHandleTable(&destination);
        const u32 reserves_before_invalid_refs = g_reserve_calls.load(std::memory_order_relaxed);
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, 0, &destination, KObjectType::Test, kHandleRightRead).status,
                  ObjectTransferStatus::InvalidReference);
        EXPECT_EQ(
            ObjectTransferImport(&fixture.transfer, 0x80000001U, &destination, KObjectType::Test, kHandleRightRead)
                .status,
            ObjectTransferStatus::InvalidReference);
        EXPECT_EQ(g_reserve_calls.load(std::memory_order_relaxed), reserves_before_invalid_refs);
        const ObjectTransferDecodedRef exported_decoded = ObjectTransferRefDecode(exported.reference);
        EXPECT_TRUE(ObjectTransferDecodedRefIsValid(exported_decoded));
        const ObjectTransferRef future_reference =
            ObjectTransferRefEncode(exported_decoded.slot, exported_decoded.generation + 1u);
        const u32 aborts_before_rejections = g_abort_calls.load(std::memory_order_relaxed);
        EXPECT_EQ(
            ObjectTransferImport(&fixture.transfer, future_reference, &destination, KObjectType::Test, kHandleRightRead)
                .status,
            ObjectTransferStatus::StaleReference);
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Event,
                                       kHandleRightWait)
                      .status,
                  ObjectTransferStatus::TypeMismatch);
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Test,
                                       kHandleRightWrite)
                      .status,
                  ObjectTransferStatus::RightsDenied);
        EXPECT_EQ(g_abort_calls.load(std::memory_order_relaxed), aborts_before_rejections + 3U);
        EXPECT_EQ(HostReservedCount(&destination), 0U);

        const u32 aborts_before_success = g_abort_calls.load(std::memory_order_relaxed);
        const ObjectTransferImportResult first = ObjectTransferImport(
            &fixture.transfer, exported.reference, &destination, KObjectType::Test, kHandleRightRead);
        EXPECT_EQ(first.status, ObjectTransferStatus::Ok);
        EXPECT_NE(first.handle, kHandleInvalid);
        EXPECT_EQ(first.authority.type, KObjectType::Test);
        EXPECT_EQ(first.authority.rights, kHandleRightRead);
        EXPECT_EQ(first.authority.metadata.identity, frozen.identity);
        EXPECT_EQ(first.authority.metadata.content_hash[0], frozen.content_hash[0]);
        EXPECT_EQ(HostHandleRights(&destination, first.handle), kHandleRightRead);
        EXPECT_EQ(g_abort_calls.load(std::memory_order_relaxed), aborts_before_success);

        const ObjectTransferImportResult second = ObjectTransferImport(
            &fixture.transfer, exported.reference, &destination, KObjectType::Test, kHandleRightWait);
        EXPECT_EQ(second.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(HostHandleRights(&destination, second.handle), kHandleRightWait);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Test,
                                       kHandleRightRead)
                      .status,
                  ObjectTransferStatus::ReferenceReplayed);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::ReferenceReplayed);
        HostDrainHandleTable(&destination);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // A failed destination publication drops only the import retain; the row
    // remains live and continues to own exactly one reference.
    {
        TransferFixture fixture;
        const auto exported = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                   MakeAuthority(kHandleRightRead));
        ASSERT_TRUE(exported.status == ObjectTransferStatus::Ok);
        HandleTable closed_destination{};
        InitializeHandleTable(&closed_destination);
        closed_destination.state = HandleTableState::Closed;
        const u32 before = KObjectRefcount(&fixture.object.base);
        const auto imported = ObjectTransferImport(&fixture.transfer, exported.reference, &closed_destination,
                                                   KObjectType::Test, kHandleRightRead);
        EXPECT_EQ(imported.status, ObjectTransferStatus::DestinationRejected);
        EXPECT_EQ(imported.destination_error, duetos::core::ErrorCode::BadState);
        EXPECT_EQ(imported.handle, kHandleInvalid);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), before);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Ok);
    }

    // Destination exhaustion is decided by the unpublished reservation before
    // the transfer row is pinned or the object retained. The persistent export
    // remains usable after capacity becomes available elsewhere.
    {
        TransferFixture fixture;
        const auto exported = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                   MakeAuthority(kHandleRightRead, 61));
        ASSERT_TRUE(exported.status == ObjectTransferStatus::Ok);
        HandleTable full_destination{};
        InitializeHandleTable(&full_destination);
        for (u32 index = 1; index < kHandleTableCapacity; ++index)
        {
            ASSERT_TRUE(KObjectAcquire(&fixture.object.base));
            const auto inserted = HandleTableInsert(full_destination, &fixture.object.base, kHandleRightRead);
            ASSERT_TRUE(inserted.has_value());
        }

        const u32 refs_before = KObjectRefcount(&fixture.object.base);
        const u32 publishes_before = g_publish_calls.load(std::memory_order_relaxed);
        const u32 aborts_before = g_abort_calls.load(std::memory_order_relaxed);
        const auto rejected = ObjectTransferImport(&fixture.transfer, exported.reference, &full_destination,
                                                   KObjectType::Test, kHandleRightRead);
        EXPECT_EQ(rejected.status, ObjectTransferStatus::DestinationRejected);
        EXPECT_EQ(rejected.destination_error, duetos::core::ErrorCode::OutOfMemory);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), refs_before);
        EXPECT_EQ(ObjectTransferLiveCount(&fixture.transfer), 1U);
        EXPECT_EQ(g_publish_calls.load(std::memory_order_relaxed), publishes_before);
        EXPECT_EQ(g_abort_calls.load(std::memory_order_relaxed), aborts_before);

        HostDrainHandleTable(&full_destination);
        HandleTable destination{};
        InitializeHandleTable(&destination);
        const auto imported = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                   KObjectType::Test, kHandleRightRead);
        EXPECT_EQ(imported.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Ok);
        HostDrainHandleTable(&destination);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // Reservation tickets are never user-visible. If trusted code corruptly
    // consumes the exact ticket while Import owns it, cross-table and stale
    // aliases remain rejected and Import fails closed without leaking its
    // checked retain or disturbing the persistent transfer row.
    {
        TransferFixture fixture;
        const auto exported = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                   MakeAuthority(kHandleRightRead, 62));
        ASSERT_TRUE(exported.status == ObjectTransferStatus::Ok);
        HandleTable destination{};
        HandleTable other{};
        InitializeHandleTable(&destination);
        InitializeHandleTable(&other);

        g_acquire_gate.target.store(&fixture.object.base, std::memory_order_release);
        g_acquire_gate.entered.store(false, std::memory_order_release);
        g_acquire_gate.released.store(false, std::memory_order_release);
        g_acquire_gate.armed.store(true, std::memory_order_release);
        ObjectTransferImportResult import_result{};
        std::thread importer(
            [&]()
            {
                import_result = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                     KObjectType::Test, kHandleRightRead);
            });
        EXPECT_TRUE(WaitForTrue(g_acquire_gate.entered));
        const HandleTableReservation ticket = HostFindReservation(&destination);
        ASSERT_TRUE(HandleTableReservationIsValid(ticket));
        EXPECT_FALSE(HandleTableAbort(other, ticket).has_value());
        EXPECT_FALSE(HandleTablePublish(other, ticket, &fixture.object.base).has_value());
        HandleTableReservation stale_ticket = ticket;
        ++stale_ticket.nonce;
        EXPECT_FALSE(HandleTableAbort(destination, stale_ticket).has_value());
        EXPECT_TRUE(HandleTableAbort(destination, ticket).has_value());
        EXPECT_FALSE(HandleTableAbort(destination, ticket).has_value());

        g_acquire_gate.released.store(true, std::memory_order_release);
        g_acquire_gate.released.notify_all();
        importer.join();
        g_acquire_gate.target.store(nullptr, std::memory_order_release);
        EXPECT_EQ(import_result.status, ObjectTransferStatus::CorruptState);
        EXPECT_EQ(import_result.destination_error, duetos::core::ErrorCode::InvalidArgument);
        EXPECT_EQ(HostReservedCount(&destination), 0U);
        EXPECT_EQ(ObjectTransferLiveCount(&fixture.transfer), 1U);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 2U);

        const auto recovered = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                    KObjectType::Test, kHandleRightRead);
        EXPECT_EQ(recovered.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Ok);
        HostDrainHandleTable(&destination);
        HostDrainHandleTable(&other);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // Destination teardown may clear an unpublished reservation while Import
    // owns a transfer-row pin. Publish and Abort then both report BadState;
    // that is a safe rejection, not a leaked ticket or a consumed export.
    {
        TransferFixture fixture;
        const auto exported = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                   MakeAuthority(kHandleRightRead, 63));
        ASSERT_TRUE(exported.status == ObjectTransferStatus::Ok);
        HandleTable destination{};
        InitializeHandleTable(&destination);

        g_acquire_gate.target.store(&fixture.object.base, std::memory_order_release);
        g_acquire_gate.entered.store(false, std::memory_order_release);
        g_acquire_gate.released.store(false, std::memory_order_release);
        g_acquire_gate.armed.store(true, std::memory_order_release);
        ObjectTransferImportResult import_result{};
        std::thread importer(
            [&]()
            {
                import_result = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                     KObjectType::Test, kHandleRightRead);
            });
        EXPECT_TRUE(WaitForTrue(g_acquire_gate.entered));
        ASSERT_TRUE(HandleTableReservationIsValid(HostFindReservation(&destination)));
        HostDrainHandleTable(&destination);

        g_acquire_gate.released.store(true, std::memory_order_release);
        g_acquire_gate.released.notify_all();
        importer.join();
        g_acquire_gate.target.store(nullptr, std::memory_order_release);
        EXPECT_EQ(import_result.status, ObjectTransferStatus::DestinationRejected);
        EXPECT_EQ(import_result.destination_error, duetos::core::ErrorCode::BadState);
        EXPECT_EQ(HostReservedCount(&destination), 0U);
        EXPECT_EQ(ObjectTransferLiveCount(&fixture.transfer), 1U);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 2U);

        HandleTable fresh_destination{};
        InitializeHandleTable(&fresh_destination);
        const auto recovered = ObjectTransferImport(&fixture.transfer, exported.reference, &fresh_destination,
                                                    KObjectType::Test, kHandleRightRead);
        EXPECT_EQ(recovered.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Ok);
        HostDrainHandleTable(&fresh_destination);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // Import linearizes at the pin. Revoke marks Closing and returns Busy
    // without waiting; a retry after the pin leaves performs the detach.
    {
        TransferFixture fixture;
        const auto exported = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                   MakeAuthority(kHandleRightRead));
        ASSERT_TRUE(exported.status == ObjectTransferStatus::Ok);
        HandleTable destination{};
        InitializeHandleTable(&destination);

        g_acquire_gate.target.store(&fixture.object.base, std::memory_order_release);
        g_acquire_gate.entered.store(false, std::memory_order_release);
        g_acquire_gate.released.store(false, std::memory_order_release);
        g_acquire_gate.armed.store(true, std::memory_order_release);

        ObjectTransferImportResult import_result{};
        std::thread importer(
            [&]()
            {
                import_result = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                     KObjectType::Test, kHandleRightRead);
            });
        EXPECT_TRUE(WaitForTrue(g_acquire_gate.entered));
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Busy);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Busy);
        EXPECT_TRUE(WaitForClosing(&fixture.transfer));
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Test,
                                       kHandleRightRead)
                      .status,
                  ObjectTransferStatus::Busy);

        g_acquire_gate.released.store(true, std::memory_order_release);
        g_acquire_gate.released.notify_all();
        importer.join();
        g_acquire_gate.target.store(nullptr, std::memory_order_release);
        EXPECT_EQ(import_result.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Test,
                                       kHandleRightRead)
                      .status,
                  ObjectTransferStatus::ReferenceReplayed);
        HostDrainHandleTable(&destination);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // Persistent import is safe under ordinary concurrency; every temporary
    // destination handle owns one checked ref and returns it on exact close.
    {
        TransferFixture fixture;
        const auto exported = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                   MakeAuthority(kHandleRightRead));
        ASSERT_TRUE(exported.status == ObjectTransferStatus::Ok);
        constexpr u32 kThreads = 4;
        constexpr u32 kIterations = 100;
        std::atomic<u32> failures{0};
        std::vector<std::thread> workers;
        for (u32 worker = 0; worker < kThreads; ++worker)
        {
            workers.emplace_back(
                [&]()
                {
                    HandleTable destination{};
                    InitializeHandleTable(&destination);
                    for (u32 iteration = 0; iteration < kIterations; ++iteration)
                    {
                        const auto imported = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                                   KObjectType::Test, kHandleRightRead);
                        if (imported.status != ObjectTransferStatus::Ok)
                        {
                            failures.fetch_add(1, std::memory_order_relaxed);
                            break;
                        }
                        HostRemoveHandle(&destination, imported.handle);
                    }
                    HostDrainHandleTable(&destination);
                });
        }
        for (auto& worker : workers)
            worker.join();
        EXPECT_EQ(failures.load(std::memory_order_relaxed), 0U);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 2U);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Ok);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // Full endpoint close has the same retryable pin barrier. The first call
    // publishes Draining and returns Busy; a later call completes teardown.
    {
        TransferFixture fixture;
        const auto exported = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                   MakeAuthority(kHandleRightRead));
        ASSERT_TRUE(exported.status == ObjectTransferStatus::Ok);
        HandleTable destination{};
        InitializeHandleTable(&destination);

        g_acquire_gate.target.store(&fixture.object.base, std::memory_order_release);
        g_acquire_gate.entered.store(false, std::memory_order_release);
        g_acquire_gate.released.store(false, std::memory_order_release);
        g_acquire_gate.armed.store(true, std::memory_order_release);

        ObjectTransferImportResult import_result{};
        std::thread importer(
            [&]()
            {
                import_result = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                     KObjectType::Test, kHandleRightRead);
            });
        EXPECT_TRUE(WaitForTrue(g_acquire_gate.entered));
        EXPECT_EQ(ObjectTransferTableClose(&fixture.transfer), ObjectTransferStatus::Busy);
        EXPECT_EQ(ObjectTransferTableClose(&fixture.transfer), ObjectTransferStatus::Busy);
        EXPECT_TRUE(WaitForClosing(&fixture.transfer));
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Test,
                                       kHandleRightRead)
                      .status,
                  ObjectTransferStatus::Closed);

        g_acquire_gate.released.store(true, std::memory_order_release);
        g_acquire_gate.released.notify_all();
        importer.join();
        g_acquire_gate.target.store(nullptr, std::memory_order_release);
        EXPECT_EQ(import_result.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferTableClose(&fixture.transfer), ObjectTransferStatus::Ok);
        HostDrainHandleTable(&destination);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // Failed reinitialization cannot reset a live generation domain. When the
    // allocator eventually revisits the same slot, it advances generation and
    // the old reference remains replay-rejected.
    {
        TransferFixture fixture;
        const ObjectTransferExportResult first = ObjectTransferExport(
            &fixture.transfer, &fixture.source, fixture.source_handle, MakeAuthority(kHandleRightRead, 300));
        ASSERT_TRUE(first.status == ObjectTransferStatus::Ok);
        const ObjectTransferDecodedRef first_decoded = ObjectTransferRefDecode(first.reference);
        ASSERT_TRUE(ObjectTransferDecodedRefIsValid(first_decoded));
        const u32 live_refcount = KObjectRefcount(&fixture.object.base);
        EXPECT_EQ(ObjectTransferTableInitialize(&fixture.transfer, 1), ObjectTransferStatus::AlreadyInitialized);
        EXPECT_EQ(ObjectTransferLiveCount(&fixture.transfer), 1U);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), live_refcount);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, first.reference), ObjectTransferStatus::Ok);

        ObjectTransferRef reused_reference = kObjectTransferRefInvalid;
        ObjectTransferDecodedRef reused_decoded = kInvalidObjectTransferDecodedRef;
        for (u32 attempt = 0; attempt < kObjectTransferTableCapacity; ++attempt)
        {
            const ObjectTransferExportResult candidate =
                ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                     MakeAuthority(kHandleRightRead, 301 + attempt, static_cast<u8>(attempt)));
            ASSERT_TRUE(candidate.status == ObjectTransferStatus::Ok);
            const ObjectTransferDecodedRef decoded = ObjectTransferRefDecode(candidate.reference);
            ASSERT_TRUE(ObjectTransferDecodedRefIsValid(decoded));
            if (decoded.slot == first_decoded.slot)
            {
                reused_reference = candidate.reference;
                reused_decoded = decoded;
                break;
            }
            EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, candidate.reference), ObjectTransferStatus::Ok);
        }
        ASSERT_TRUE(reused_reference != kObjectTransferRefInvalid);
        EXPECT_EQ(reused_decoded.generation, first_decoded.generation + 1U);
        EXPECT_NE(reused_reference, first.reference);
        EXPECT_EQ(ObjectTransferTableInitialize(&fixture.transfer, first_decoded.generation),
                  ObjectTransferStatus::AlreadyInitialized);

        HandleTable destination{};
        InitializeHandleTable(&destination);
        EXPECT_EQ(
            ObjectTransferImport(&fixture.transfer, first.reference, &destination, KObjectType::Test, kHandleRightRead)
                .status,
            ObjectTransferStatus::ReferenceReplayed);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, reused_reference), ObjectTransferStatus::Ok);
        HostDrainHandleTable(&destination);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // Issuing the terminal generation retires each row permanently.  A full
    // table reports transient Full; after all terminal refs are revoked it
    // reports permanent IdentityExhausted and never wraps to a stale identity.
    {
        TransferFixture fixture(kHandleRightAll, kObjectTransferGenerationMax);
        std::array<ObjectTransferRef, kObjectTransferTableCapacity - 1> references{};
        for (u32 index = 0; index < references.size(); ++index)
        {
            const auto exported =
                ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                     MakeAuthority(kHandleRightRead, index + 1, static_cast<u8>(index)));
            EXPECT_EQ(exported.status, ObjectTransferStatus::Ok);
            references[index] = exported.reference;
            const ObjectTransferDecodedRef decoded = ObjectTransferRefDecode(exported.reference);
            EXPECT_TRUE(ObjectTransferDecodedRefIsValid(decoded));
            EXPECT_EQ(decoded.generation, kObjectTransferGenerationMax);
        }
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                       MakeAuthority(kHandleRightRead, 100))
                      .status,
                  ObjectTransferStatus::Full);
        for (ObjectTransferRef reference : references)
            EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, reference), ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                       MakeAuthority(kHandleRightRead, 101))
                      .status,
                  ObjectTransferStatus::IdentityExhausted);
        for (ObjectTransferRef reference : references)
            EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, reference), ObjectTransferStatus::ReferenceReplayed);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
    }

    // Endpoint close is terminal, releases every row ref outside the lock, and
    // is idempotent across concurrent callers.
    {
        TransferFixture fixture;
        std::array<ObjectTransferRef, 3> references{};
        for (u32 index = 0; index < references.size(); ++index)
        {
            references[index] = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                     MakeAuthority(kHandleRightRead, index + 20))
                                    .reference;
        }
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 4U);
        std::array<ObjectTransferStatus, 2> statuses{};
        std::thread first([&]() { statuses[0] = ObjectTransferTableClose(&fixture.transfer); });
        std::thread second([&]() { statuses[1] = ObjectTransferTableClose(&fixture.transfer); });
        first.join();
        second.join();
        EXPECT_EQ(statuses[0], ObjectTransferStatus::Ok);
        EXPECT_EQ(statuses[1], ObjectTransferStatus::Ok);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
        HandleTable destination{};
        InitializeHandleTable(&destination);
        EXPECT_EQ(
            ObjectTransferImport(&fixture.transfer, references[0], &destination, KObjectType::Test, kHandleRightRead)
                .status,
            ObjectTransferStatus::Closed);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, references[0]), ObjectTransferStatus::Closed);
        EXPECT_EQ(ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                       MakeAuthority(kHandleRightRead, 99))
                      .status,
                  ObjectTransferStatus::Closed);
        HostDrainHandleTable(&destination);
    }

    // Closed is published after authority detaches but before any last-ref
    // destructor runs.  A destructor that re-enters close therefore observes
    // the terminal state instead of waiting forever on the owning call.
    {
        TransferFixture fixture;
        const auto exported = ObjectTransferExport(&fixture.transfer, &fixture.source, fixture.source_handle,
                                                   MakeAuthority(kHandleRightRead, 200));
        ASSERT_TRUE(exported.status == ObjectTransferStatus::Ok);
        fixture.object.close_on_destroy = &fixture.transfer;
        HostRemoveHandle(&fixture.source, fixture.source_handle);
        fixture.source_handle = kHandleInvalid;
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 1U);
        EXPECT_EQ(ObjectTransferTableClose(&fixture.transfer), ObjectTransferStatus::Ok);
        EXPECT_EQ(fixture.object.reentrant_close_status, ObjectTransferStatus::Ok);
        EXPECT_EQ(KObjectRefcount(&fixture.object.base), 0U);
    }

    EXPECT_STREQ(ObjectTransferStatusName(ObjectTransferStatus::ReferenceReplayed), "reference-replayed");
    EXPECT_STREQ(ObjectTransferStatusName(ObjectTransferStatus::AlreadyInitialized), "already-initialized");
    EXPECT_STREQ(ObjectTransferStatusName(static_cast<ObjectTransferStatus>(0xFF)), "?");
    EXPECT_EQ(g_destroyed.load(std::memory_order_relaxed), 17U);
    return duetos_host_test::finish_main("test_object_transfer");
}
