/*
 * DuetOS — per-process handle table implementation, v0 (plan A3).
 *
 * See `handle_table.h` for the public contract. This TU owns slot
 * allocation, lookup, refcount-aware removal, cross-table
 * duplication, and the boot self-test.
 *
 * Slot 0 is reserved (kHandleInvalid). The first usable slot is
 * index 1 — Insert returns Handle == 1, 2, 3, ….
 */

#include "ipc/handle_table.h"

#include "core/panic.h"
#include "ipc/kobject.h"
#include "log/klog.h"
#include "sync/spinlock.h"
#include "util/nospec.h"
#include "util/result.h"
#include "util/types.h"

namespace duetos::ipc
{

namespace
{

[[noreturn]] void PanicHt(const char* what)
{
    core::Panic("ipc/handle_table", what);
}

bool HandleInRange(Handle h)
{
    return h != kHandleInvalid && h < kHandleTableCapacity;
}

} // namespace

::duetos::core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* obj)
{
    if (obj == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::IPC, "ipc/handle_table", "Insert called with null KObject");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    sync::SpinLockGuard guard(table.lock);
    // Two-pass scan starting at the post-hint index. Skips the
    // typically-busy prefix on a sparse table; degrades to a
    // full scan when the table is dense. Slot 0 stays reserved
    // for kHandleInvalid.
    const u32 start = (table.next_free_hint + 1u) % kHandleTableCapacity;
    for (u32 step = 0; step < kHandleTableCapacity; ++step)
    {
        u32 i = start + step;
        if (i >= kHandleTableCapacity)
            i -= kHandleTableCapacity;
        if (i == 0)
            continue; // reserved sentinel slot
        if (table.slots[i].obj == nullptr)
        {
            table.slots[i].obj = obj;
            table.next_free_hint = i;
            KLOG_TRACE_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "insert ok handle", static_cast<u64>(i));
            return static_cast<Handle>(i);
        }
    }
    KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "Insert: table full (OOM)",
                 static_cast<u64>(kHandleTableCapacity));
    return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
}

KObject* HandleTableLookup(HandleTable& table, Handle h, KObjectType expected_type)
{
    if (!HandleInRange(h))
    {
        return nullptr;
    }
    // Spectre v1 nospec: a misprediction of HandleInRange could
    // speculate `table.slots[h]` for an h past the cap. Mask the
    // index so the speculative load is bounded to [0, capacity).
    const Handle masked_h = static_cast<Handle>(util::MaskedIndex32(static_cast<u32>(h), kHandleTableCapacity));
    sync::SpinLockGuard guard(table.lock);
    KObject* obj = table.slots[masked_h].obj;
    if (obj == nullptr)
    {
        return nullptr;
    }
    if (expected_type != KObjectType::Invalid && obj->type != expected_type)
    {
        return nullptr;
    }
    return obj;
}

KObject* HandleTableLookupRef(HandleTable& table, Handle h, KObjectType expected_type)
{
    if (!HandleInRange(h))
    {
        return nullptr;
    }
    // Spectre v1 nospec — see HandleTableLookup for the rationale.
    const Handle masked_h = static_cast<Handle>(util::MaskedIndex32(static_cast<u32>(h), kHandleTableCapacity));
    KObject* obj = nullptr;
    {
        sync::SpinLockGuard guard(table.lock);
        obj = table.slots[masked_h].obj;
        if (obj == nullptr)
        {
            return nullptr;
        }
        if (expected_type != KObjectType::Invalid && obj->type != expected_type)
        {
            return nullptr;
        }
        // Take the reference under the table's lock so a racing
        // HandleTableRemove can't drop the slot's reference between
        // our peek and our acquire. Once the ref is taken, releasing
        // the table lock is safe — the object cannot be freed before
        // the caller's matching `KObjectRelease`.
        KObjectAcquire(obj);
    }
    return obj;
}

::duetos::core::Result<void> HandleTableRemove(HandleTable& table, Handle h)
{
    if (!HandleInRange(h))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "Remove: handle out of range",
                     static_cast<u64>(h));
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    // Spectre v1 nospec — see HandleTableLookup for the rationale.
    const Handle masked_h = static_cast<Handle>(util::MaskedIndex32(static_cast<u32>(h), kHandleTableCapacity));
    KObject* dropped = nullptr;
    {
        sync::SpinLockGuard guard(table.lock);
        if (table.slots[masked_h].obj == nullptr)
        {
            KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "Remove: empty slot", static_cast<u64>(h));
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        }
        dropped = table.slots[masked_h].obj;
        table.slots[masked_h].obj = nullptr;
    }
    KLOG_TRACE_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "remove ok handle", static_cast<u64>(h));
    // Release outside the table lock — destroy callbacks may
    // touch other handle tables / IPC objects.
    KObjectRelease(dropped);
    return {};
}

::duetos::core::Result<Handle> HandleTableDuplicate(HandleTable& src, HandleTable& dst, Handle h)
{
    if (!HandleInRange(h))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "Duplicate: src handle out of range",
                     static_cast<u64>(h));
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    // Use the Ref variant so the table-owned reference is bumped under
    // src.lock — without that, a concurrent HandleTableRemove between
    // the unlocked Lookup return and our KObjectAcquire could drop the
    // last reference and free `obj`, leaving us calling Acquire on
    // freed memory. The matching Release on the error path below balances
    // the Ref-acquired reference; on success the destination table
    // inherits ownership of that ref via Insert.
    KObject* obj = HandleTableLookupRef(src, h, KObjectType::Invalid);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "Duplicate: src handle empty",
                     static_cast<u64>(h));
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    auto inserted = HandleTableInsert(dst, obj);
    if (!inserted.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table",
                     "Duplicate: dst Insert failed, backing out refcount", static_cast<u64>(h));
        KObjectRelease(obj);
        return ::duetos::core::Err{inserted.error()};
    }
    KLOG_TRACE_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "duplicate ok new dst handle",
                  static_cast<u64>(inserted.value()));
    return inserted;
}

u32 HandleTableLiveCount(HandleTable& table)
{
    sync::SpinLockGuard guard(table.lock);
    u32 count = 0;
    for (u32 i = 1; i < kHandleTableCapacity; ++i)
    {
        if (table.slots[i].obj != nullptr)
        {
            ++count;
        }
    }
    return count;
}

void HandleTableDrain(HandleTable& table)
{
    // Pull pointers out under the lock, release outside the lock.
    KObject* victims[kHandleTableCapacity];
    u32 victim_count = 0;
    {
        sync::SpinLockGuard guard(table.lock);
        for (u32 i = 1; i < kHandleTableCapacity; ++i)
        {
            if (table.slots[i].obj != nullptr)
            {
                victims[victim_count++] = table.slots[i].obj;
                table.slots[i].obj = nullptr;
            }
        }
    }
    KLOG_INFO_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "drain releasing handles",
                 static_cast<u64>(victim_count));
    for (u32 i = 0; i < victim_count; ++i)
    {
        KObjectRelease(victims[i]);
    }
}

namespace
{

// Self-test scratch type (mirrors the one in kobject.cpp; kept
// local to this TU so the test is self-contained).
struct StTestObject
{
    KObject base;
    u32 destroyed;
};

u32 g_st_destroy_count = 0;

void StDestroy(KObject* obj)
{
    auto* self = reinterpret_cast<StTestObject*>(obj);
    self->destroyed = 1;
    ++g_st_destroy_count;
}

} // namespace

void HandleTableSelfTest()
{
    KLOG_TRACE_SCOPE("ipc/handle_table", "HandleTableSelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::IPC, "ipc/handle_table", "self-test: insert/lookup/duplicate/remove/drain");

    HandleTable table_a{};
    HandleTable table_b{};

    StTestObject obj{};
    KObjectInit(&obj.base, KObjectType::Test, &StDestroy);

    // (1) Insert: returns a non-zero handle.
    auto r_insert = HandleTableInsert(table_a, &obj.base);
    if (!r_insert.has_value())
    {
        PanicHt("Insert into empty table failed");
    }
    const Handle h_a = r_insert.value();
    if (h_a == kHandleInvalid)
    {
        PanicHt("Insert returned kHandleInvalid");
    }

    // (2) Lookup: succeeds with matching type-tag.
    if (HandleTableLookup(table_a, h_a, KObjectType::Test) != &obj.base)
    {
        PanicHt("Lookup with right type failed");
    }
    // (2a) LookupRef: also bumps the refcount so the caller can
    // safely use the pointer across a blocking primitive without
    // racing a concurrent Remove. Drop the extra ref before
    // continuing so subsequent assertions stay accurate.
    {
        const u32 ref_before = KObjectRefcount(&obj.base);
        KObject* pinned = HandleTableLookupRef(table_a, h_a, KObjectType::Test);
        if (pinned != &obj.base)
        {
            PanicHt("LookupRef returned wrong KObject");
        }
        if (KObjectRefcount(&obj.base) != ref_before + 1)
        {
            PanicHt("LookupRef did not bump refcount by 1");
        }
        if (HandleTableLookupRef(table_a, h_a, KObjectType::Mutex) != nullptr)
        {
            PanicHt("LookupRef with wrong type-tag returned non-null");
        }
        if (KObjectRefcount(&obj.base) != ref_before + 1)
        {
            PanicHt("LookupRef type-mismatch leaked a ref");
        }
        KObjectRelease(pinned);
        if (KObjectRefcount(&obj.base) != ref_before)
        {
            PanicHt("LookupRef Release did not restore refcount");
        }
    }
    // Type-tag mismatch returns nullptr.
    if (HandleTableLookup(table_a, h_a, KObjectType::Mutex) != nullptr)
    {
        PanicHt("Lookup with wrong type returned non-null");
    }
    // KObjectType::Invalid disables the type check (used by Duplicate).
    if (HandleTableLookup(table_a, h_a, KObjectType::Invalid) != &obj.base)
    {
        PanicHt("Lookup with Invalid type-check failed");
    }
    // Out-of-range / zero handle returns nullptr.
    if (HandleTableLookup(table_a, kHandleInvalid, KObjectType::Test) != nullptr)
    {
        PanicHt("Lookup on kHandleInvalid did not return nullptr");
    }
    if (HandleTableLookup(table_a, kHandleTableCapacity, KObjectType::Test) != nullptr)
    {
        PanicHt("Lookup on out-of-range handle did not return nullptr");
    }

    // (3) Duplicate into a sibling table; refcount goes to 2.
    if (KObjectRefcount(&obj.base) != 1)
    {
        PanicHt("Refcount drifted before Duplicate");
    }
    auto r_dup = HandleTableDuplicate(table_a, table_b, h_a);
    if (!r_dup.has_value())
    {
        PanicHt("Duplicate to empty sibling table failed");
    }
    const Handle h_b = r_dup.value();
    if (KObjectRefcount(&obj.base) != 2)
    {
        PanicHt("Refcount != 2 after Duplicate");
    }
    if (HandleTableLookup(table_b, h_b, KObjectType::Test) != &obj.base)
    {
        PanicHt("Duplicate-target lookup failed");
    }

    // (4) Remove from table_a; refcount drops to 1, destroy must NOT fire.
    const u32 destroy_baseline = g_st_destroy_count;
    if (!HandleTableRemove(table_a, h_a).has_value())
    {
        PanicHt("Remove on valid handle failed");
    }
    if (KObjectRefcount(&obj.base) != 1)
    {
        PanicHt("Refcount != 1 after first Remove");
    }
    if (g_st_destroy_count != destroy_baseline)
    {
        PanicHt("Destroy fired prematurely");
    }
    if (HandleTableLookup(table_a, h_a, KObjectType::Test) != nullptr)
    {
        PanicHt("Removed handle still resolves");
    }
    // Sibling handle still works.
    if (HandleTableLookup(table_b, h_b, KObjectType::Test) != &obj.base)
    {
        PanicHt("Sibling handle stopped working after first Remove");
    }

    // (5) Remove from table_b; refcount = 0, destroy fires once.
    if (!HandleTableRemove(table_b, h_b).has_value())
    {
        PanicHt("Remove on second handle failed");
    }
    if (g_st_destroy_count != destroy_baseline + 1)
    {
        PanicHt("Destroy did not fire on last Remove");
    }
    if (obj.destroyed != 1)
    {
        PanicHt("Destroy fired but per-object counter wrong");
    }

    // (6) Bad-handle removal returns InvalidArgument, doesn't fire destroy.
    if (HandleTableRemove(table_a, h_a).has_value())
    {
        PanicHt("Remove on already-removed handle returned Ok");
    }
    if (HandleTableRemove(table_a, kHandleInvalid).has_value())
    {
        PanicHt("Remove on kHandleInvalid returned Ok");
    }

    // (7) Fill-to-capacity stress: kHandleTableCapacity-1 inserts succeed
    // (slot 0 reserved); next insert returns OutOfMemory; Drain frees all.
    HandleTable big{};
    static StTestObject stress_objs[kHandleTableCapacity - 1];
    for (u32 i = 0; i < kHandleTableCapacity - 1; ++i)
    {
        stress_objs[i].destroyed = 0;
        KObjectInit(&stress_objs[i].base, KObjectType::Test, &StDestroy);
        auto r = HandleTableInsert(big, &stress_objs[i].base);
        if (!r.has_value())
        {
            PanicHt("Bulk insert hit OOM before capacity");
        }
    }
    if (HandleTableLiveCount(big) != kHandleTableCapacity - 1)
    {
        PanicHt("Live count wrong after bulk insert");
    }
    StTestObject overflow{};
    KObjectInit(&overflow.base, KObjectType::Test, &StDestroy);
    auto r_overflow = HandleTableInsert(big, &overflow.base);
    if (r_overflow.has_value())
    {
        PanicHt("Insert past capacity did not return Err");
    }
    if (r_overflow.error() != ::duetos::core::ErrorCode::OutOfMemory)
    {
        PanicHt("Capacity-overflow Err code != OutOfMemory");
    }
    // Drop the overflow object's standalone reference (it never made
    // it into a table, so refcount is still 1 — Release frees it).
    KObjectRelease(&overflow.base);

    const u32 pre_drain_destroyed = g_st_destroy_count;
    HandleTableDrain(big);
    if (HandleTableLiveCount(big) != 0)
    {
        PanicHt("Drain did not empty the table");
    }
    if (g_st_destroy_count != pre_drain_destroyed + (kHandleTableCapacity - 1))
    {
        PanicHt("Drain destroy count wrong");
    }

    KLOG_INFO_A(::duetos::core::LogArea::IPC, "ipc/handle_table",
                "self-test OK (capacity, dup, drain, type-tag verified)");
}

} // namespace duetos::ipc
