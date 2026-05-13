/*
 * DuetOS — cross-process named-kobject namespace, implementation.
 *
 * See named_kobjects.h for the API contract + lifetime model.
 */

#include "ipc/named_kobjects.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/kevent.h"
#include "ipc/kmutex.h"
#include "ipc/ksemaphore.h"
#include "log/klog.h"
#include "sync/spinlock.h"

namespace duetos::ipc
{

namespace
{

struct NamedKObjectEntry
{
    KObjectType type;
    char name[kNamedKObjectMaxNameLen];
    KObject* obj;
    bool valid;
    u64 last_used_tick;
};

constinit NamedKObjectEntry g_table[kNamedKObjectSlots] = {};
constinit ::duetos::sync::SpinLock g_table_lock = {};
constinit u64 g_next_tick = 1;

bool NameMatches(const NamedKObjectEntry& e, KObjectType type, const char* name)
{
    if (!e.valid || e.type != type)
        return false;
    for (u32 i = 0; i < kNamedKObjectMaxNameLen; ++i)
    {
        if (e.name[i] != name[i])
            return false;
        if (e.name[i] == '\0')
            return true;
    }
    // Reaching the end without a NUL terminator means the stored
    // name didn't fit in the slot — treat as no-match defensively.
    return false;
}

u32 NameLen(const char* name)
{
    u32 i = 0;
    for (; i < kNamedKObjectMaxNameLen && name[i] != '\0'; ++i)
    { /* count to NUL */
    }
    return i;
}

void StoreName(NamedKObjectEntry& e, const char* name)
{
    u32 i = 0;
    for (; i + 1 < kNamedKObjectMaxNameLen && name[i] != '\0'; ++i)
        e.name[i] = name[i];
    e.name[i] = '\0';
}

// Pick a slot for a new registration. Prefer an empty slot;
// otherwise evict the least-recently-used valid entry. Caller
// holds g_table_lock.
u32 PickVictimSlot()
{
    u32 victim = 0;
    u64 oldest = (u64)-1;
    for (u32 i = 0; i < kNamedKObjectSlots; ++i)
    {
        if (!g_table[i].valid)
            return i;
        if (g_table[i].last_used_tick < oldest)
        {
            oldest = g_table[i].last_used_tick;
            victim = i;
        }
    }
    return victim;
}

} // namespace

KObject* NamedKObjectFind(KObjectType type, const char* name)
{
    if (name == nullptr || name[0] == '\0')
        return nullptr;
    if (NameLen(name) >= kNamedKObjectMaxNameLen)
        return nullptr;

    auto flags = ::duetos::sync::SpinLockAcquire(g_table_lock);
    KObject* hit = nullptr;
    for (u32 i = 0; i < kNamedKObjectSlots; ++i)
    {
        if (NameMatches(g_table[i], type, name))
        {
            hit = g_table[i].obj;
            g_table[i].last_used_tick = ++g_next_tick;
            break;
        }
    }
    if (hit != nullptr)
    {
        // Bump refcount under the table lock so the entry can't be
        // evicted by a concurrent Register before we add our ref.
        KObjectAcquire(hit);
    }
    ::duetos::sync::SpinLockRelease(g_table_lock, flags);
    return hit;
}

bool NamedKObjectRegister(KObjectType type, const char* name, KObject* obj)
{
    if (name == nullptr || name[0] == '\0' || obj == nullptr)
        return false;
    if (NameLen(name) >= kNamedKObjectMaxNameLen)
        return false;

    auto flags = ::duetos::sync::SpinLockAcquire(g_table_lock);
    // Check for an existing entry first — Register is idempotent
    // for the "Create returns existing" path. The caller is
    // responsible for releasing the ref on its caller-allocated
    // `obj` when this branch fires (it observed an existing
    // registration and didn't need its newly-allocated kobj).
    for (u32 i = 0; i < kNamedKObjectSlots; ++i)
    {
        if (NameMatches(g_table[i], type, name))
        {
            g_table[i].last_used_tick = ++g_next_tick;
            ::duetos::sync::SpinLockRelease(g_table_lock, flags);
            return true;
        }
    }
    // No existing entry — pick a victim slot. If the victim was
    // valid we drop its refcount AFTER the spinlock release (so
    // the kobj's destroy callback can call back into the table
    // without recursive-lock issues).
    KObject* evicted = nullptr;
    const u32 slot = PickVictimSlot();
    if (g_table[slot].valid)
        evicted = g_table[slot].obj;
    StoreName(g_table[slot], name);
    g_table[slot].type = type;
    g_table[slot].obj = obj;
    g_table[slot].valid = true;
    g_table[slot].last_used_tick = ++g_next_tick;
    KObjectAcquire(obj); // table-owned reference
    ::duetos::sync::SpinLockRelease(g_table_lock, flags);

    if (evicted != nullptr)
        KObjectRelease(evicted);
    return true;
}

void NamedKObjectSelfTest()
{
    // Smoke-test the (Find on empty → null), (Register → Find →
    // refcount-bump observed) shape. A dedicated kobject would
    // be cleanest; we use a KEvent because it's the lightest
    // concrete kobject the IPC layer ships.
    auto create_r = KEventCreate(/*manual_reset=*/false, /*initial=*/false);
    if (!create_r.has_value())
    {
        ::duetos::arch::SerialWrite("[selftest:named-kobj] FAIL KEventCreate\n");
        return;
    }
    KEvent* ev = create_r.value();
    KObject* obj = &ev->base;
    const u32 ref_before = KObjectRefcount(obj);

    // 1. Empty-table Find returns nullptr.
    if (NamedKObjectFind(KObjectType::Event, "selftest-named-kobj") != nullptr)
    {
        ::duetos::arch::SerialWrite("[selftest:named-kobj] FAIL pre-register Find\n");
        KObjectRelease(obj);
        return;
    }

    // 2. Register + Find returns the same object with refcount
    //    incremented by 2 (one for the table, one for the Find).
    if (!NamedKObjectRegister(KObjectType::Event, "selftest-named-kobj", obj))
    {
        ::duetos::arch::SerialWrite("[selftest:named-kobj] FAIL Register\n");
        KObjectRelease(obj);
        return;
    }
    KObject* found = NamedKObjectFind(KObjectType::Event, "selftest-named-kobj");
    if (found != obj)
    {
        ::duetos::arch::SerialWrite("[selftest:named-kobj] FAIL Find returned wrong obj\n");
        if (found != nullptr)
            KObjectRelease(found);
        KObjectRelease(obj);
        return;
    }
    const u32 ref_after = KObjectRefcount(obj);
    if (ref_after != ref_before + 2)
    {
        ::duetos::arch::SerialWrite("[selftest:named-kobj] FAIL refcount drift\n");
        KObjectRelease(found);
        KObjectRelease(obj);
        return;
    }

    // 3. Type mismatch returns null.
    if (NamedKObjectFind(KObjectType::Mutex, "selftest-named-kobj") != nullptr)
    {
        ::duetos::arch::SerialWrite("[selftest:named-kobj] FAIL type-mismatch Find\n");
        KObjectRelease(found);
        KObjectRelease(obj);
        return;
    }

    KObjectRelease(found);
    KObjectRelease(obj);
    KLOG_INFO_AV(::duetos::core::LogArea::Memory, "selftest:named-kobj", "ok; ref drift", ref_after - ref_before);
}

} // namespace duetos::ipc
