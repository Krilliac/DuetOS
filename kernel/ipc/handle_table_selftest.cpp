/* Boot-time and scheduler-phase verification for opaque Handle v2. */

#include "ipc/handle_table.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/kevent.h"
#include "log/klog.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "util/types.h"

namespace duetos::ipc
{

namespace
{

struct SelfTestObject
{
    KObject base;
    u32 destroyed;
};

u32 g_destroy_count = 0;

void DestroySelfTestObject(KObject* obj)
{
    auto* self = reinterpret_cast<SelfTestObject*>(obj);
    ++self->destroyed;
    ++g_destroy_count;
}

[[noreturn]] void Fail(const char* message)
{
    ::duetos::core::Panic("ipc/handle_table", message);
}

void Expect(bool condition, const char* message)
{
    if (!condition)
        Fail(message);
}

void Init(SelfTestObject* object, KObjectType type = KObjectType::Test)
{
    *object = SelfTestObject{};
    KObjectInit(&object->base, type, &DestroySelfTestObject);
}

Handle InsertFull(HandleTable& table, SelfTestObject* object)
{
    auto inserted = HandleTableInsert(table, &object->base, TypeAllowedRights(object->base.type));
    if (!inserted.has_value())
        Fail("test insert failed");
    return inserted.value();
}

constexpr u32 kContentionReaders = 3;
constexpr u32 kContentionIterations = 1000;

struct HandleContentionState
{
    HandleTable source;
    HandleTable duplicates;
    u32 current;
    u32 stale;
    u32 churn_done;
    u32 readers_done;
    u32 failures;
};

HandleContentionState g_contention{};

struct DrainContentionObject
{
    KObject base;
};

struct DrainContentionState
{
    HandleTable table;
    DrainContentionObject object;
    u32 destroy_entered;
    u32 allow_destroy;
    u32 destroy_done;
    u32 owner_done;
    u32 follower_started;
    u32 follower_done;
};

DrainContentionState g_drain_contention{};

void RecordContentionFailure()
{
    __atomic_add_fetch(&g_contention.failures, 1u, __ATOMIC_SEQ_CST);
}

void HandleChurnTask(void*)
{
    for (u32 iteration = 0; iteration < kContentionIterations; ++iteration)
    {
        auto created = KEventCreate(/*manual_reset=*/true, /*initial=*/false);
        if (!created.has_value())
        {
            RecordContentionFailure();
            break;
        }
        KEvent* event = created.value();
        auto inserted = HandleTableInsert(g_contention.source, &event->base, TypeAllowedRights(KObjectType::Event));
        if (!inserted.has_value())
        {
            KObjectRelease(&event->base);
            RecordContentionFailure();
            break;
        }

        const Handle handle = inserted.value();
        __atomic_store_n(&g_contention.current, handle, __ATOMIC_SEQ_CST);
        sched::SchedYield();
        sched::SchedYield();

        if (!HandleTableRemove(g_contention.source, handle).has_value())
            RecordContentionFailure();
        __atomic_store_n(&g_contention.stale, handle, __ATOMIC_SEQ_CST);
        __atomic_store_n(&g_contention.current, 0u, __ATOMIC_SEQ_CST);
        sched::SchedYield();
    }
    __atomic_store_n(&g_contention.churn_done, 1u, __ATOMIC_SEQ_CST);
}

void HandleReaderTask(void*)
{
    while (__atomic_load_n(&g_contention.churn_done, __ATOMIC_SEQ_CST) == 0)
    {
        const Handle current = __atomic_load_n(&g_contention.current, __ATOMIC_SEQ_CST);
        if (current != kHandleInvalid)
        {
            KObject* object = HandleTableLookupRef(g_contention.source, current, KObjectType::Event, kHandleRightWait);
            if (object != nullptr)
            {
                if (object->type != KObjectType::Event)
                    RecordContentionFailure();
                KObjectRelease(object);
            }

            // Duplicate is allowed to linearize before a racing close.
            // If it succeeds, its independently retained destination
            // identity must be removable exactly once.
            auto duplicate = HandleTableDuplicate(g_contention.source, g_contention.duplicates, current);
            if (duplicate.has_value() && !HandleTableRemove(g_contention.duplicates, duplicate.value()).has_value())
                RecordContentionFailure();
        }

        const Handle stale = __atomic_load_n(&g_contention.stale, __ATOMIC_SEQ_CST);
        if (stale != kHandleInvalid)
        {
            KObject* stale_object = HandleTableLookupRef(g_contention.source, stale, KObjectType::Event);
            if (stale_object != nullptr)
            {
                KObjectRelease(stale_object);
                RecordContentionFailure();
            }
            if (HandleTableRemove(g_contention.source, stale).has_value())
                RecordContentionFailure();
        }
        sched::SchedYield();
    }
    __atomic_add_fetch(&g_contention.readers_done, 1u, __ATOMIC_SEQ_CST);
}

void DrainContentionDestroy(KObject*)
{
    __atomic_store_n(&g_drain_contention.destroy_entered, 1u, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&g_drain_contention.allow_destroy, __ATOMIC_SEQ_CST) == 0)
        sched::SchedYield();
    __atomic_store_n(&g_drain_contention.destroy_done, 1u, __ATOMIC_SEQ_CST);
}

void DrainOwnerTask(void*)
{
    HandleTableDrain(g_drain_contention.table);
    __atomic_store_n(&g_drain_contention.owner_done, 1u, __ATOMIC_SEQ_CST);
}

void DrainFollowerTask(void*)
{
    __atomic_store_n(&g_drain_contention.follower_started, 1u, __ATOMIC_SEQ_CST);
    HandleTableDrain(g_drain_contention.table);
    __atomic_store_n(&g_drain_contention.follower_done, 1u, __ATOMIC_SEQ_CST);
}

} // namespace

void HandleTableSelfTest()
{
    KLOG_INFO_A(::duetos::core::LogArea::IPC, "ipc/handle_table",
                "self-test: opaque generation, ABA, ownership, saturation, drain");

    HandleTable table_a{};
    HandleTable table_b{};
    SelfTestObject original{};
    Init(&original);

    const Handle old_handle = InsertFull(table_a, &original);
    Expect(old_handle == HandleEncode(1, 1), "first handle is not slot1/generation1");
    Expect(old_handle <= kHandlePositiveMax, "internal handle is not PE32-positive");

    u64 public_mutex = 0;
    Expect(HandleEncodeTagged(old_handle, 0x200, &public_mutex) && public_mutex == 0x1201,
           "tagged mutex encoding mismatch");
    Handle round_trip = kHandleInvalid;
    Expect(HandleDecodeTagged(public_mutex, 0x200, &round_trip) && round_trip == old_handle,
           "tagged handle round-trip failed");
    Expect(!HandleDecodeTagged(0x201, 0x200, &round_trip), "generation-zero public handle accepted");
    Expect(!HandleDecodeTagged(public_mutex, 0x300, &round_trip), "cross-type public handle accepted");
    Expect(!HandleDecodeTagged(0x80001201ULL, 0x200, &round_trip), "negative PE32 handle accepted");
    Expect(!HandleDecodeTagged(0x100001201ULL, 0x200, &round_trip), "upper-32-bit handle accepted");

    KObject* retained = HandleTableLookupRef(table_a, old_handle, KObjectType::Test);
    Expect(retained == &original.base, "retained lookup failed");
    Expect(KObjectRefcount(&original.base) == 2, "retained lookup did not add one ref");
    KObjectRelease(retained);
    Expect(HandleTableLookupRef(table_a, old_handle, KObjectType::Mutex) == nullptr,
           "wrong-type retained lookup succeeded");

    auto duplicate = HandleTableDuplicate(table_a, table_b, old_handle);
    Expect(duplicate.has_value() && KObjectRefcount(&original.base) == 2, "duplicate ownership mismatch");
    const Handle sibling = duplicate.value();

    Expect(HandleTableRemove(table_a, old_handle).has_value(), "remove original failed");
    Expect(HandleTableLookupRef(table_a, old_handle, KObjectType::Test) == nullptr, "closed token still resolved");

    // Force immediate reuse of row 1. The new token must differ only by
    // its generation, and every stale operation must fail closed.
    table_a.next_free_hint = 0;
    SelfTestObject replacement{};
    Init(&replacement);
    const Handle new_handle = InsertFull(table_a, &replacement);
    Expect(HandleSlotIndex(new_handle) == HandleSlotIndex(old_handle) && new_handle != old_handle,
           "forced row reuse did not advance generation");
    Expect(HandleTableLookupRef(table_a, old_handle, KObjectType::Test) == nullptr, "stale lookup aliased replacement");
    Expect(!HandleTableRemove(table_a, old_handle).has_value(), "stale remove closed replacement");
    Expect(!HandleTableDuplicate(table_a, table_b, old_handle).has_value(), "stale duplicate succeeded");
    Expect(!HandleReplace(table_a, old_handle, kHandleRightInspect).has_value(), "stale replace succeeded");
    retained = HandleTableLookupRef(table_a, new_handle, KObjectType::Test);
    Expect(retained == &replacement.base, "replacement stopped resolving after stale operations");
    KObjectRelease(retained);

    Expect(HandleTableRemove(table_b, sibling).has_value(), "remove duplicate failed");
    Expect(original.destroyed == 1, "duplicate lifecycle did not destroy exactly once");
    Expect(HandleTableRemove(table_a, new_handle).has_value(), "remove replacement failed");
    Expect(replacement.destroyed == 1, "replacement did not destroy exactly once");

    // Multi-object publication can reserve a destination identity without
    // exposing it. Only the exact nonce, generation, table, type, and rights
    // may publish; abort and drain consume the invisible row without touching
    // caller-owned KObject references.
    HandleTable publication_table{};
    auto reserved = HandleTableReserve(publication_table, KObjectType::Test, kHandleRightRead | kHandleRightDestroy);
    Expect(reserved.has_value() && HandleTableReservationIsValid(reserved.value()), "publication reservation failed");
    const HandleTableReservation publication_ticket = reserved.value();
    Expect(HandleTableLiveCount(publication_table) == 0 &&
               HandleTableRights(publication_table, publication_ticket.handle) == 0 &&
               HandleTableLookupRef(publication_table, publication_ticket.handle, KObjectType::Test) == nullptr &&
               HandleTableSnapshot(publication_table, nullptr, 0) == 0,
           "unpublished reservation became observable");

    SelfTestObject publication_object{};
    SelfTestObject wrong_type{};
    Init(&publication_object);
    Init(&wrong_type, KObjectType::Event);
    HandleTableReservation wrong_nonce = publication_ticket;
    ++wrong_nonce.nonce;
    Expect(!HandleTablePublish(publication_table, wrong_nonce, &publication_object.base).has_value(),
           "wrong reservation nonce published");
    HandleTable other_table{};
    Expect(!HandleTablePublish(other_table, publication_ticket, &publication_object.base).has_value(),
           "cross-table reservation published");
    Expect(!HandleTablePublish(publication_table, publication_ticket, &wrong_type.base).has_value() &&
               KObjectRefcount(&wrong_type.base) == 1,
           "wrong-type publication consumed caller ownership");

    auto published = HandleTablePublish(publication_table, publication_ticket, &publication_object.base);
    Expect(published.has_value() && published.value() == publication_ticket.handle &&
               HandleTableLiveCount(publication_table) == 1 &&
               HandleTableRights(publication_table, publication_ticket.handle) ==
                   (kHandleRightRead | kHandleRightDestroy),
           "exact reservation did not publish atomically");
    Expect(!HandleTablePublish(publication_table, publication_ticket, &wrong_type.base).has_value() &&
               !HandleTableAbort(publication_table, publication_ticket).has_value(),
           "consumed publication ticket replayed");
    Expect(HandleTableRemove(publication_table, publication_ticket.handle).has_value() &&
               publication_object.destroyed == 1,
           "published reservation ownership did not close exactly once");
    KObjectRelease(&wrong_type.base);

    publication_table.next_free_hint = 0;
    auto aborted = HandleTableReserve(publication_table, KObjectType::Test, kHandleRightDestroy);
    Expect(aborted.has_value() && aborted.value().handle != publication_ticket.handle &&
               aborted.value().nonce != publication_ticket.nonce,
           "row reuse recreated a reservation identity");
    const HandleTableReservation aborted_ticket = aborted.value();
    Expect(HandleTableAbort(publication_table, aborted_ticket).has_value() &&
               !HandleTableAbort(publication_table, aborted_ticket).has_value(),
           "reservation abort was not exact and single-use");

    HandleTable terminal_reservation{};
    terminal_reservation.slots[1].generation = kHandleGenerationMax - 1;
    terminal_reservation.next_free_hint = 0;
    auto terminal_reserved = HandleTableReserve(terminal_reservation, KObjectType::Test, kHandleRightDestroy);
    Expect(terminal_reserved.has_value() &&
               (terminal_reserved.value().handle >> kHandleSlotBits) == kHandleGenerationMax &&
               HandleTableAbort(terminal_reservation, terminal_reserved.value()).has_value() &&
               terminal_reservation.slots[1].state == HandleSlotState::Retired,
           "terminal reservation generation did not retire");

    HandleTable drain_reservation{};
    auto drain_ticket = HandleTableReserve(drain_reservation, KObjectType::Test, kHandleRightDestroy);
    SelfTestObject drain_object{};
    Init(&drain_object);
    Expect(drain_ticket.has_value(), "drain reservation failed");
    HandleTableDrain(drain_reservation);
    auto publish_after_drain = HandleTablePublish(drain_reservation, drain_ticket.value(), &drain_object.base);
    Expect(!publish_after_drain.has_value() && publish_after_drain.error() == ::duetos::core::ErrorCode::BadState &&
               KObjectRefcount(&drain_object.base) == 1,
           "drain consumed unpublished caller ownership");
    KObjectRelease(&drain_object.base);

    // Retain saturation must not publish an unbacked destination slot.
    HandleTable saturated_src{};
    HandleTable saturated_dst{};
    SelfTestObject saturated{};
    Init(&saturated);
    const Handle saturated_handle = InsertFull(saturated_src, &saturated);
    saturated.base.refcount = static_cast<u32>(-1);
    Expect(!HandleTableDuplicate(saturated_src, saturated_dst, saturated_handle).has_value(),
           "duplicate published after saturated retain");
    Expect(HandleTableLiveCount(saturated_dst) == 0 && saturated.base.refcount == static_cast<u32>(-1),
           "failed saturated duplicate changed ownership");
    saturated.base.refcount = 1;
    Expect(HandleTableRemove(saturated_src, saturated_handle).has_value(), "saturated test cleanup failed");

    // Terminal generations retire rather than wrap.
    HandleTable terminal{};
    terminal.slots[1].generation = kHandleGenerationMax - 1;
    terminal.next_free_hint = 0;
    SelfTestObject terminal_obj{};
    Init(&terminal_obj);
    const Handle terminal_handle = InsertFull(terminal, &terminal_obj);
    Expect((terminal_handle >> kHandleSlotBits) == kHandleGenerationMax, "terminal generation not allocated");
    Expect(HandleTableRemove(terminal, terminal_handle).has_value(), "terminal remove failed");
    Expect(terminal.slots[1].state == HandleSlotState::Retired, "terminal slot was not retired");

    // Fixed-capacity and terminal drain behavior.
    HandleTable full{};
    SelfTestObject objects[kHandleTableCapacity]{};
    for (u32 i = 1; i < kHandleTableCapacity; ++i)
    {
        Init(&objects[i]);
        (void)InsertFull(full, &objects[i]);
    }
    SelfTestObject overflow{};
    Init(&overflow);
    auto rightsless_insert = HandleTableInsert(full, &overflow.base, 0);
    Expect(!rightsless_insert.has_value() && rightsless_insert.error() == ::duetos::core::ErrorCode::InvalidArgument,
           "rightsless handle was published");
    auto overflow_insert = HandleTableInsert(full, &overflow.base, kHandleRightAll);
    Expect(!overflow_insert.has_value() && overflow_insert.error() == ::duetos::core::ErrorCode::OutOfMemory,
           "full table did not report OutOfMemory");
    Expect(KObjectRefcount(&overflow.base) == 1, "failed insert consumed caller reference");
    KObjectRelease(&overflow.base);
    HandleTableDrain(full);
    Expect(HandleTableLiveCount(full) == 0, "drain left live handles");
    SelfTestObject after_drain{};
    Init(&after_drain);
    auto late_insert = HandleTableInsert(full, &after_drain.base, kHandleRightAll);
    Expect(!late_insert.has_value() && late_insert.error() == ::duetos::core::ErrorCode::BadState,
           "post-drain insert succeeded");
    KObjectRelease(&after_drain.base);
    HandleTableDrain(full); // idempotent

    arch::SerialWrite("[ipc] handle-table v2 self-test OK\n");
}

void HandleRightsSelfTest()
{
    static_assert(static_cast<u16>(KObjectType::MessagePort) == 8, "MessagePort type tag changed");
    static_assert(static_cast<u16>(KObjectType::ServiceEndpoint) == 9, "ServiceEndpoint type tag changed");
    const u64 user_file = HandleRightsForProcess(KObjectType::File, ::duetos::core::CapSetUserLaunch());
    const u64 trusted_file = HandleRightsForProcess(KObjectType::File, ::duetos::core::CapSetTrusted());
    const u64 empty_file = HandleRightsForProcess(KObjectType::File, ::duetos::core::CapSetEmpty());
    Expect((user_file & kHandleRightRead) != 0 && (user_file & kHandleRightWrite) == 0,
           "sandbox File rights did not deny Write");
    Expect((trusted_file & (kHandleRightRead | kHandleRightWrite)) == (kHandleRightRead | kHandleRightWrite),
           "trusted File rights missing Read/Write");
    Expect((empty_file & (kHandleRightRead | kHandleRightWrite)) == 0, "empty caps minted File Read/Write");

    constexpr u64 kMessagePortOperations = kHandleRightRead | kHandleRightWrite | kHandleRightWait;
    constexpr u64 kMessagePortCommon =
        kHandleRightDuplicate | kHandleRightTransfer | kHandleRightDestroy | kHandleRightInspect;
    const u64 port_allowed = TypeAllowedRights(KObjectType::MessagePort);
    const u64 port_empty = HandleRightsForProcess(KObjectType::MessagePort, ::duetos::core::CapSetEmpty());
    const u64 port_trusted = HandleRightsForProcess(KObjectType::MessagePort, ::duetos::core::CapSetTrusted());
    Expect(port_allowed == (kMessagePortCommon | kMessagePortOperations),
           "MessagePort allowed-rights contract drifted");
    Expect((port_allowed & kHandleRightSignal) == 0, "MessagePort acquired Event Signal semantics");
    Expect(port_empty == ((kMessagePortCommon & ~kHandleRightInspect) | kMessagePortOperations),
           "empty caps changed the MessagePort rights contract");
    Expect(port_trusted == (kMessagePortCommon | kMessagePortOperations),
           "trusted caps changed the MessagePort rights contract");
    Expect(KObjectTypeName(KObjectType::MessagePort)[0] == 'm', "MessagePort type name missing");

    const u64 endpoint_allowed = TypeAllowedRights(KObjectType::ServiceEndpoint);
    const u64 endpoint_empty = HandleRightsForProcess(KObjectType::ServiceEndpoint, ::duetos::core::CapSetEmpty());
    const u64 endpoint_trusted = HandleRightsForProcess(KObjectType::ServiceEndpoint, ::duetos::core::CapSetTrusted());
    constexpr u64 kEndpointOperations = kHandleRightRead | kHandleRightWrite | kHandleRightWait | kHandleRightDestroy;
    constexpr u64 kEndpointForbidden = kHandleRightDuplicate | kHandleRightTransfer;
    Expect(endpoint_allowed == (kEndpointOperations | kHandleRightInspect),
           "ServiceEndpoint allowed-rights contract drifted");
    Expect(endpoint_empty == kEndpointOperations, "ServiceEndpoint object-local rights were widened or removed");
    Expect(endpoint_trusted == (kEndpointOperations | kHandleRightInspect),
           "trusted ServiceEndpoint rights lost Debug Inspect or gained generic movement authority");
    Expect((endpoint_allowed & kEndpointForbidden) == 0 && (endpoint_empty & kEndpointForbidden) == 0 &&
               (endpoint_trusted & kEndpointForbidden) == 0,
           "ServiceEndpoint Duplicate/Transfer authority was minted");
    Expect((endpoint_empty & (kHandleRightSignal | kHandleRightInspect)) == 0,
           "ServiceEndpoint object-local rights were widened or removed");
    Expect(KObjectTypeName(KObjectType::ServiceEndpoint)[0] == 's', "ServiceEndpoint type name missing");

    HandleTable port_table{};
    SelfTestObject port{};
    Init(&port, KObjectType::MessagePort);
    auto port_insert = HandleTableInsert(port_table, &port.base, port_empty);
    Expect(port_insert.has_value(), "MessagePort insert failed");
    const Handle port_handle = port_insert.value();
    KObject* port_ref = HandleTableLookupRef(port_table, port_handle, KObjectType::MessagePort, kMessagePortOperations);
    Expect(port_ref == &port.base, "MessagePort Send/Receive/Wait lookup failed");
    KObjectRelease(port_ref);
    Expect(HandleTableLookupRef(port_table, port_handle, KObjectType::Mailbox) == nullptr,
           "MessagePort aliased Mailbox type identity");
    auto port_detached = HandleTableDetach(port_table, port_handle, KObjectType::MessagePort, kHandleRightDestroy);
    Expect(port_detached.has_value() && port_detached.value() == &port.base, "MessagePort Destroy detach failed");
    KObjectRelease(port_detached.value());
    Expect(port.destroyed == 1, "MessagePort close did not destroy exactly once");

    SelfTestObject signal_port{};
    Init(&signal_port, KObjectType::MessagePort);
    auto signal_insert = HandleTableInsert(port_table, &signal_port.base, port_empty | kHandleRightSignal);
    Expect(!signal_insert.has_value() && signal_insert.error() == ::duetos::core::ErrorCode::PermissionDenied,
           "MessagePort insert accepted Signal right");
    KObjectRelease(&signal_port.base);

    // A ServiceEndpoint may be operated and destroyed through its exact
    // accepted handle, but generic handle-table minting must not create another
    // endpoint identity. This remains fail closed even for trusted caps: direct
    // insert/reservation cannot add Duplicate/Transfer, and a live endpoint
    // without Duplicate cannot be duplicated or generation-replaced.
    HandleTable endpoint_table{};
    HandleTable endpoint_destination{};
    SelfTestObject endpoint{};
    Init(&endpoint, KObjectType::ServiceEndpoint);
    auto endpoint_forbidden_insert =
        HandleTableInsert(endpoint_table, &endpoint.base, endpoint_trusted | kEndpointForbidden);
    Expect(!endpoint_forbidden_insert.has_value() &&
               endpoint_forbidden_insert.error() == ::duetos::core::ErrorCode::PermissionDenied &&
               KObjectRefcount(&endpoint.base) == 1 && HandleTableLiveCount(endpoint_table) == 0,
           "trusted ServiceEndpoint insert minted Duplicate/Transfer");
    auto endpoint_forbidden_reservation =
        HandleTableReserve(endpoint_table, KObjectType::ServiceEndpoint, endpoint_trusted | kEndpointForbidden);
    Expect(!endpoint_forbidden_reservation.has_value() &&
               endpoint_forbidden_reservation.error() == ::duetos::core::ErrorCode::PermissionDenied &&
               HandleTableLiveCount(endpoint_table) == 0,
           "ServiceEndpoint reservation minted Duplicate/Transfer");

    auto endpoint_insert = HandleTableInsert(endpoint_table, &endpoint.base, endpoint_trusted);
    Expect(endpoint_insert.has_value(), "trusted ServiceEndpoint insert failed");
    const Handle endpoint_handle = endpoint_insert.value();
    Expect(HandleTableRights(endpoint_table, endpoint_handle) == endpoint_trusted &&
               HandleCheckRight(endpoint_table, endpoint_handle, kEndpointOperations) &&
               !HandleCheckRight(endpoint_table, endpoint_handle, kEndpointForbidden),
           "ServiceEndpoint stored rights violated the non-transferable ceiling");
    auto endpoint_duplicate = HandleTableDuplicate(endpoint_table, endpoint_destination, endpoint_handle);
    Expect(!endpoint_duplicate.has_value() &&
               endpoint_duplicate.error() == ::duetos::core::ErrorCode::PermissionDenied &&
               HandleTableLiveCount(endpoint_destination) == 0 && KObjectRefcount(&endpoint.base) == 1,
           "generic ServiceEndpoint duplicate succeeded");
    auto endpoint_narrow_duplicate =
        HandleTableDuplicateRights(endpoint_table, endpoint_destination, endpoint_handle, endpoint_empty);
    Expect(!endpoint_narrow_duplicate.has_value() &&
               endpoint_narrow_duplicate.error() == ::duetos::core::ErrorCode::PermissionDenied &&
               HandleTableLiveCount(endpoint_destination) == 0,
           "rights-narrow ServiceEndpoint duplicate succeeded");
    auto endpoint_replace = HandleReplace(endpoint_table, endpoint_handle, endpoint_empty);
    Expect(!endpoint_replace.has_value() && endpoint_replace.error() == ::duetos::core::ErrorCode::PermissionDenied &&
               HandleTableRights(endpoint_table, endpoint_handle) == endpoint_trusted,
           "generic ServiceEndpoint replace succeeded");

    SelfTestObject endpoint_adopt_replacement{};
    Init(&endpoint_adopt_replacement, KObjectType::ServiceEndpoint);
    auto endpoint_forbidden_adopt =
        HandleTableAdoptReplace(endpoint_table, endpoint_handle, &endpoint_adopt_replacement.base,
                                endpoint_trusted | kHandleRightTransfer, KObjectType::ServiceEndpoint);
    Expect(!endpoint_forbidden_adopt.has_value() &&
               endpoint_forbidden_adopt.error() == ::duetos::core::ErrorCode::PermissionDenied &&
               KObjectRefcount(&endpoint_adopt_replacement.base) == 1 &&
               HandleTableRights(endpoint_table, endpoint_handle) == endpoint_trusted,
           "adopt-replace minted ServiceEndpoint Transfer authority");
    KObjectRelease(&endpoint_adopt_replacement.base);
    auto endpoint_detached =
        HandleTableDetach(endpoint_table, endpoint_handle, KObjectType::ServiceEndpoint, kHandleRightDestroy);
    Expect(endpoint_detached.has_value() && endpoint_detached.value() == &endpoint.base,
           "ServiceEndpoint Destroy detach failed");
    KObjectRelease(endpoint_detached.value());
    Expect(endpoint.destroyed == 1, "ServiceEndpoint rights test did not destroy exactly once");

    HandleTable file_table{};
    SelfTestObject file{};
    Init(&file, KObjectType::File);
    auto file_insert = HandleTableInsert(file_table, &file.base, user_file);
    Expect(file_insert.has_value(), "sandbox File insert failed");
    const Handle file_handle = file_insert.value();
    KObject* read_ref = HandleTableLookupRef(file_table, file_handle, KObjectType::File, kHandleRightRead);
    Expect(read_ref == &file.base, "sandbox File Read lookup failed");
    KObjectRelease(read_ref);
    Expect(HandleTableLookupRef(file_table, file_handle, KObjectType::File, kHandleRightWrite) == nullptr,
           "sandbox File Write lookup succeeded");
    Expect(HandleTableRemove(file_table, file_handle).has_value(), "File rights cleanup failed");

    HandleTable table{};
    SelfTestObject event{};
    Init(&event, KObjectType::Event);
    const u64 initial = kHandleRightDuplicate | kHandleRightDestroy | kHandleRightWait | kHandleRightSignal;
    auto inserted = HandleTableInsert(table, &event.base, initial);
    Expect(inserted.has_value(), "rights insert failed");
    const Handle source = inserted.value();

    const u64 narrowed = kHandleRightDuplicate | kHandleRightDestroy | kHandleRightWait;
    auto duplicate = HandleTableDuplicateRights(table, table, source, narrowed);
    Expect(duplicate.has_value(), "rights-narrow duplicate failed");
    const Handle narrow_handle = duplicate.value();
    Expect(HandleTableRights(table, narrow_handle) == narrowed &&
               !HandleCheckRight(table, narrow_handle, kHandleRightSignal),
           "duplicate rights were not narrowed");
    Expect(!HandleTableDuplicateRights(table, table, narrow_handle, initial).has_value(),
           "duplicate rights escalation succeeded");

    const u32 count_before = HandleTableLiveCount(table);
    const u32 refs_before = KObjectRefcount(&event.base);
    const u64 even_narrower = kHandleRightDuplicate | kHandleRightDestroy;
    auto replaced = HandleReplace(table, narrow_handle, even_narrower);
    Expect(replaced.has_value(), "atomic replace failed");
    Expect(HandleSlotIndex(replaced.value()) == HandleSlotIndex(narrow_handle) && replaced.value() != narrow_handle,
           "replace did not rotate same-slot generation");
    Expect(HandleTableLiveCount(table) == count_before && KObjectRefcount(&event.base) == refs_before,
           "replace changed live/ref counts");
    Expect(HandleTableLookupRef(table, narrow_handle, KObjectType::Event) == nullptr, "replace left old identity live");
    Expect(HandleTableRights(table, replaced.value()) == even_narrower, "replace stored wrong rights");
    Expect(!HandleReplace(table, replaced.value(), 0).has_value() &&
               HandleTableRights(table, replaced.value()) == even_narrower,
           "rightsless replace mutated a live handle");

    auto no_dup = HandleReplace(table, replaced.value(), kHandleRightDestroy);
    Expect(no_dup.has_value(), "final duplicate-right removal failed");
    Expect(!HandleTableDuplicate(table, table, no_dup.value()).has_value(),
           "duplicate succeeded without Duplicate right");

    HandleTableDrain(table);
    Expect(event.destroyed == 1, "rights test object destroy count mismatch");
    arch::SerialWrite("[handle-rights] self-test OK (type-aware ceilings + narrowing)\n");
}

void HandleTableContentionSelfTest()
{
    arch::SerialWrite("[ipc] handle-table contention self-test: close/reuse/lookup/duplicate\n");
    g_contention = HandleContentionState{};

    // Force every allocation through row 1 so each of the 1000 closes
    // immediately reuses the same physical row with a new generation.
    // This turns an occasional ABA race into the dominant path.
    for (u32 slot = 2; slot < kHandleTableCapacity; ++slot)
    {
        g_contention.source.slots[slot].generation = kHandleGenerationMax;
        g_contention.source.slots[slot].state = HandleSlotState::Retired;
    }

    Expect(sched::SchedCreate(&HandleChurnTask, nullptr, "handle-churn") != nullptr,
           "contention churn task creation failed");
    for (u32 i = 0; i < kContentionReaders; ++i)
        Expect(sched::SchedCreate(&HandleReaderTask, nullptr, "handle-reader") != nullptr,
               "contention reader task creation failed");

    constexpr u32 kMaxTicks = 3000;
    for (u32 tick = 0; tick < kMaxTicks; ++tick)
    {
        if (__atomic_load_n(&g_contention.churn_done, __ATOMIC_SEQ_CST) != 0 &&
            __atomic_load_n(&g_contention.readers_done, __ATOMIC_SEQ_CST) == kContentionReaders)
            break;
        sched::SchedSleepTicks(1);
    }

    Expect(__atomic_load_n(&g_contention.churn_done, __ATOMIC_SEQ_CST) != 0, "contention churn task timed out");
    Expect(__atomic_load_n(&g_contention.readers_done, __ATOMIC_SEQ_CST) == kContentionReaders,
           "contention reader tasks timed out");
    Expect(__atomic_load_n(&g_contention.failures, __ATOMIC_SEQ_CST) == 0,
           "contention test observed ABA/refcount failure");
    Expect(HandleTableLiveCount(g_contention.source) == 0 && HandleTableLiveCount(g_contention.duplicates) == 0,
           "contention test leaked a handle");
    const Handle final_stale = __atomic_load_n(&g_contention.stale, __ATOMIC_SEQ_CST);
    Expect(final_stale != kHandleInvalid &&
               HandleTableLookupRef(g_contention.source, final_stale, KObjectType::Event) == nullptr &&
               !HandleTableRemove(g_contention.source, final_stale).has_value(),
           "contention final stale token did not fail closed");

    HandleTableDrain(g_contention.source);
    HandleTableDrain(g_contention.duplicates);

    // A non-owner Drain is a completion waiter. Hold the final destroy
    // callback open and prove a follower cannot return merely because the
    // owner detached all rows; Closed is published only after callbacks end.
    g_drain_contention = DrainContentionState{};
    KObjectInit(&g_drain_contention.object.base, KObjectType::Test, &DrainContentionDestroy);
    Expect(HandleTableInsert(g_drain_contention.table, &g_drain_contention.object.base,
                             TypeAllowedRights(KObjectType::Test))
               .has_value(),
           "drain contention insert failed");
    Expect(sched::SchedCreate(&DrainOwnerTask, nullptr, "handle-drain-owner") != nullptr,
           "drain owner task creation failed");
    for (u32 tick = 0; tick < kMaxTicks && __atomic_load_n(&g_drain_contention.destroy_entered, __ATOMIC_SEQ_CST) == 0;
         ++tick)
        sched::SchedSleepTicks(1);
    Expect(__atomic_load_n(&g_drain_contention.destroy_entered, __ATOMIC_SEQ_CST) != 0,
           "drain destroy callback did not start");

    Expect(sched::SchedCreate(&DrainFollowerTask, nullptr, "handle-drain-follower") != nullptr,
           "drain follower task creation failed");
    for (u32 tick = 0; tick < kMaxTicks && __atomic_load_n(&g_drain_contention.follower_started, __ATOMIC_SEQ_CST) == 0;
         ++tick)
        sched::SchedSleepTicks(1);
    Expect(__atomic_load_n(&g_drain_contention.follower_started, __ATOMIC_SEQ_CST) != 0,
           "drain follower task did not start");
    sched::SchedSleepTicks(2);
    Expect(__atomic_load_n(&g_drain_contention.follower_done, __ATOMIC_SEQ_CST) == 0,
           "concurrent drain returned before destroy callback completed");

    __atomic_store_n(&g_drain_contention.allow_destroy, 1u, __ATOMIC_SEQ_CST);
    for (u32 tick = 0; tick < kMaxTicks; ++tick)
    {
        if (__atomic_load_n(&g_drain_contention.owner_done, __ATOMIC_SEQ_CST) != 0 &&
            __atomic_load_n(&g_drain_contention.follower_done, __ATOMIC_SEQ_CST) != 0)
            break;
        sched::SchedSleepTicks(1);
    }
    Expect(__atomic_load_n(&g_drain_contention.destroy_done, __ATOMIC_SEQ_CST) != 0 &&
               __atomic_load_n(&g_drain_contention.owner_done, __ATOMIC_SEQ_CST) != 0 &&
               __atomic_load_n(&g_drain_contention.follower_done, __ATOMIC_SEQ_CST) != 0,
           "concurrent drain completion timed out");

    // Drain is terminal and must reject publication after the teardown
    // linearization point while preserving the caller's reference.
    auto late = KEventCreate(false, false);
    Expect(late.has_value(), "contention late-create failed");
    auto late_insert =
        HandleTableInsert(g_contention.source, &late.value()->base, TypeAllowedRights(KObjectType::Event));
    Expect(!late_insert.has_value() && late_insert.error() == ::duetos::core::ErrorCode::BadState,
           "contention post-drain insert succeeded");
    KObjectRelease(&late.value()->base);

    arch::SerialWrite("[ipc] handle-table contention self-test OK\n");
}

} // namespace duetos::ipc
