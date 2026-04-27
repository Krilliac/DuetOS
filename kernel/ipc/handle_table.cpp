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

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/kobject.h"
#include "sync/spinlock.h"
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
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    sync::SpinLockGuard guard(table.lock);
    // Skip slot 0 — kHandleInvalid is the "no handle" sentinel.
    for (u32 i = 1; i < kHandleTableCapacity; ++i)
    {
        if (table.slots[i].obj == nullptr)
        {
            table.slots[i].obj = obj;
            return static_cast<Handle>(i);
        }
    }
    return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
}

KObject* HandleTableLookup(HandleTable& table, Handle h, KObjectType expected_type)
{
    if (!HandleInRange(h))
    {
        return nullptr;
    }
    sync::SpinLockGuard guard(table.lock);
    KObject* obj = table.slots[h].obj;
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

::duetos::core::Result<void> HandleTableRemove(HandleTable& table, Handle h)
{
    if (!HandleInRange(h))
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    KObject* dropped = nullptr;
    {
        sync::SpinLockGuard guard(table.lock);
        if (table.slots[h].obj == nullptr)
        {
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        }
        dropped = table.slots[h].obj;
        table.slots[h].obj = nullptr;
    }
    // Release outside the table lock — destroy callbacks may
    // touch other handle tables / IPC objects.
    KObjectRelease(dropped);
    return {};
}

::duetos::core::Result<Handle> HandleTableDuplicate(HandleTable& src, HandleTable& dst, Handle h)
{
    if (!HandleInRange(h))
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    KObject* obj = HandleTableLookup(src, h, KObjectType::Invalid);
    if (obj == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    // Add the destination's reference first. If Insert fails, we
    // back it out so the refcount is unchanged on Err.
    KObjectAcquire(obj);

    auto inserted = HandleTableInsert(dst, obj);
    if (!inserted.has_value())
    {
        KObjectRelease(obj);
        return ::duetos::core::Err{inserted.error()};
    }
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
    arch::SerialWrite("[ipc] handle-table self-test: insert/lookup/duplicate/remove/drain\n");

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

    arch::SerialWrite("[ipc] handle-table self-test OK (capacity, dup, drain, type-tag verified).\n");
}

} // namespace duetos::ipc
