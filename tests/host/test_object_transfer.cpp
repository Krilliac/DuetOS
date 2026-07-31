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
#include <vector>

namespace
{

std::mutex g_object_lock;
std::mutex g_handle_lock;
std::atomic<duetos::u32> g_destroyed{0};

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
    {
        std::lock_guard<std::mutex> guard(g_handle_lock);
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
        object = slot.obj;
    }
    return KObjectAcquire(object) ? object : nullptr;
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
        slot.acquisition_pins = 0;
        slot.state = HandleSlotState::Live;
        return HandleEncode(index, slot.generation);
    }
    return core::Err{core::ErrorCode::OutOfMemory};
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
        table->slots[index].generation = 0;
        table->slots[index].acquisition_pins = 0;
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
    {
        std::lock_guard<std::mutex> guard(g_handle_lock);
        u32 slot_index = 0;
        u32 generation = 0;
        if (!HandleDecode(handle, &slot_index, &generation))
            return;
        HandleSlot& slot = table->slots[slot_index];
        if (slot.state != HandleSlotState::Live || slot.generation != generation)
            return;
        object = slot.obj;
        slot.obj = nullptr;
        slot.rights = 0;
        slot.state = slot.generation == kHandleGenerationMax ? HandleSlotState::Retired : HandleSlotState::Free;
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
            slot.state = slot.generation == kHandleGenerationMax ? HandleSlotState::Retired : HandleSlotState::Free;
        }
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

} // namespace

int main()
{
    // Opaque references remain positive, syntactically bounded, and exact.
    {
        const ObjectTransferRef reference = ObjectTransferRefEncode(1, 7);
        u32 slot = 0;
        u32 generation = 0;
        EXPECT_TRUE(ObjectTransferRefDecode(reference, &slot, &generation));
        EXPECT_EQ(slot, 1U);
        EXPECT_EQ(generation, 7U);
        EXPECT_TRUE(reference <= kObjectTransferPositiveMax);
        EXPECT_FALSE(ObjectTransferRefDecode(0, nullptr, nullptr));
        EXPECT_FALSE(ObjectTransferRefDecode(0x80000001U, nullptr, nullptr));
        EXPECT_FALSE(ObjectTransferRefDecode(1U << kObjectTransferSlotBits, nullptr, nullptr));
        EXPECT_FALSE(ObjectTransferRefDecode((1U << kObjectTransferSlotBits) | kObjectTransferTableCapacity,
                                             nullptr, nullptr));
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
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, 0, &destination, KObjectType::Test, kHandleRightRead).status,
                  ObjectTransferStatus::InvalidReference);
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, 0x80000001U, &destination, KObjectType::Test,
                                       kHandleRightRead)
                      .status,
                  ObjectTransferStatus::InvalidReference);
        u32 exported_slot = 0;
        u32 exported_generation = 0;
        EXPECT_TRUE(ObjectTransferRefDecode(exported.reference, &exported_slot, &exported_generation));
        const ObjectTransferRef future_reference =
            ObjectTransferRefEncode(exported_slot, exported_generation + 1u);
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, future_reference, &destination, KObjectType::Test,
                                       kHandleRightRead)
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

        const ObjectTransferImportResult first = ObjectTransferImport(
            &fixture.transfer, exported.reference, &destination, KObjectType::Test, kHandleRightRead);
        EXPECT_EQ(first.status, ObjectTransferStatus::Ok);
        EXPECT_NE(first.handle, kHandleInvalid);
        EXPECT_EQ(first.authority.type, KObjectType::Test);
        EXPECT_EQ(first.authority.rights, kHandleRightRead);
        EXPECT_EQ(first.authority.metadata.identity, frozen.identity);
        EXPECT_EQ(first.authority.metadata.content_hash[0], frozen.content_hash[0]);
        EXPECT_EQ(HostHandleRights(&destination, first.handle), kHandleRightRead);

        const ObjectTransferImportResult second = ObjectTransferImport(
            &fixture.transfer, exported.reference, &destination, KObjectType::Test, kHandleRightWait);
        EXPECT_EQ(second.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(HostHandleRights(&destination, second.handle), kHandleRightWait);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference), ObjectTransferStatus::Ok);
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Test,
                                       kHandleRightRead)
                      .status,
                  ObjectTransferStatus::ReferenceReplayed);
        EXPECT_EQ(ObjectTransferRevoke(&fixture.transfer, exported.reference),
                  ObjectTransferStatus::ReferenceReplayed);
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

    // Import linearizes at the pin.  Revoke can mark Closing while the checked
    // retain is deliberately stalled, but cannot release the row-owned ref;
    // the pinned import succeeds and later imports are refused.
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
        ObjectTransferStatus revoke_status = ObjectTransferStatus::CorruptState;
        std::atomic<bool> revoke_done{false};
        std::thread importer(
            [&]()
            {
                import_result = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                     KObjectType::Test, kHandleRightRead);
            });
        EXPECT_TRUE(WaitForTrue(g_acquire_gate.entered));
        std::thread revoker(
            [&]()
            {
                revoke_status = ObjectTransferRevoke(&fixture.transfer, exported.reference);
                revoke_done.store(true, std::memory_order_release);
            });
        EXPECT_TRUE(WaitForClosing(&fixture.transfer));
        EXPECT_FALSE(revoke_done.load(std::memory_order_acquire));
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Test,
                                       kHandleRightRead)
                      .status,
                  ObjectTransferStatus::Busy);

        g_acquire_gate.released.store(true, std::memory_order_release);
        g_acquire_gate.released.notify_all();
        importer.join();
        revoker.join();
        g_acquire_gate.target.store(nullptr, std::memory_order_release);
        EXPECT_EQ(import_result.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(revoke_status, ObjectTransferStatus::Ok);
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

    // Full endpoint close has the same pin barrier as exact revoke.  A closer
    // does not publish Closed or release the row-owned ref until the already-
    // linearized import has completed its checked retain and removed its pin.
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
        ObjectTransferStatus close_status = ObjectTransferStatus::CorruptState;
        std::atomic<bool> close_done{false};
        std::thread importer(
            [&]()
            {
                import_result = ObjectTransferImport(&fixture.transfer, exported.reference, &destination,
                                                     KObjectType::Test, kHandleRightRead);
            });
        EXPECT_TRUE(WaitForTrue(g_acquire_gate.entered));
        std::thread closer(
            [&]()
            {
                close_status = ObjectTransferTableClose(&fixture.transfer);
                close_done.store(true, std::memory_order_release);
            });
        EXPECT_TRUE(WaitForClosing(&fixture.transfer));
        EXPECT_FALSE(close_done.load(std::memory_order_acquire));
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, exported.reference, &destination, KObjectType::Test,
                                       kHandleRightRead)
                      .status,
                  ObjectTransferStatus::Closed);

        g_acquire_gate.released.store(true, std::memory_order_release);
        g_acquire_gate.released.notify_all();
        importer.join();
        closer.join();
        g_acquire_gate.target.store(nullptr, std::memory_order_release);
        EXPECT_EQ(import_result.status, ObjectTransferStatus::Ok);
        EXPECT_EQ(close_status, ObjectTransferStatus::Ok);
        EXPECT_TRUE(close_done.load(std::memory_order_acquire));
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
            u32 generation = 0;
            EXPECT_TRUE(ObjectTransferRefDecode(exported.reference, nullptr, &generation));
            EXPECT_EQ(generation, kObjectTransferGenerationMax);
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
        EXPECT_EQ(ObjectTransferImport(&fixture.transfer, references[0], &destination, KObjectType::Test,
                                       kHandleRightRead)
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
    EXPECT_STREQ(ObjectTransferStatusName(static_cast<ObjectTransferStatus>(0xFF)), "?");
    EXPECT_EQ(g_destroyed.load(std::memory_order_relaxed), 11U);
    return duetos_host_test::finish_main("test_object_transfer");
}
