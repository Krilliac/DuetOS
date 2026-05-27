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
#include "log/klog.h"
#include "proc/process.h"
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

u64 TypeAllowedRights(KObjectType type)
{
    // Per-type rights menus. The bits NOT set here represent
    // operations that aren't meaningful for the type (e.g. you
    // can't Signal a File, you can't Read a Mutex). Inspect /
    // Duplicate / Transfer / Destroy are universal — every kernel
    // object can be queried, duplicated, passed, and closed.
    constexpr u64 kCommon = kHandleRightDuplicate | kHandleRightTransfer | kHandleRightDestroy | kHandleRightInspect;

    switch (type)
    {
    case KObjectType::Mutex:
        // Mutex: acquire = Wait, release = Signal. No Read/Write.
        return kCommon | kHandleRightWait | kHandleRightSignal;
    case KObjectType::Event:
        // Event: WaitForSingleObject = Wait, SetEvent/ResetEvent = Signal.
        // No Read/Write (Pulse is a v0 GAP, still Signal-shaped).
        return kCommon | kHandleRightWait | kHandleRightSignal;
    case KObjectType::Semaphore:
        // Semaphore: acquire = Wait, release = Signal. No Read/Write.
        return kCommon | kHandleRightWait | kHandleRightSignal;
    case KObjectType::Mailbox:
        // Mailbox: send = Write, recv = Read, wait-for-empty = Wait.
        return kCommon | kHandleRightRead | kHandleRightWrite | kHandleRightWait;
    case KObjectType::Waitable:
        // Generic waitable — wait only, no I/O surface.
        return kCommon | kHandleRightWait;
    case KObjectType::File:
        // File: bytes flow through Read/Write; Inspect covers
        // stat/fstat. Files are not signalable today (epoll-on-
        // file is a follow-up; will surface Wait+Signal then).
        return kCommon | kHandleRightRead | kHandleRightWrite;
    case KObjectType::Iocp:
        // I/O completion port: dequeue = Read, post = Write,
        // wait-for-completion = Wait.
        return kCommon | kHandleRightRead | kHandleRightWrite | kHandleRightWait;
    case KObjectType::Test:
        // Self-test surface — accept everything so the test can
        // exercise the full enumeration without picking a real type.
        return kHandleRightAll;
    case KObjectType::Invalid:
        return 0;
    }
    return 0;
}

u64 ProcessCapsToHandleRights(const ::duetos::core::CapSet& caps)
{
    // Map ambient process caps to per-handle rights the process is
    // permitted to grant on new handles. Caps the process LACKS
    // narrow the default-rights ceiling.
    //
    // Read / Wait / Duplicate / Transfer / Destroy / Inspect are
    // unconditionally grantable — a process that holds a handle
    // can always read its own state, wait on it, dup it within its
    // own table, pass it through IPC, close it, and inspect it.
    // These rights are GATED at the syscall level by the kernel's
    // process-cap ceiling separately (e.g. SYS_FILE_READ on a file
    // still requires kCapFsRead; this layer only ensures the
    // process can MINT a handle carrying the right).
    //
    // Write and Signal are the rights the cap mapping actually
    // narrows: a sandboxed process without kCapFsWrite cannot mint
    // a file handle bearing Write authority even if the underlying
    // type supports it.
    u64 rights = kHandleRightRead | kHandleRightDuplicate | kHandleRightTransfer | kHandleRightWait |
                 kHandleRightDestroy | kHandleRightInspect;

    if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapFsWrite))
    {
        rights |= kHandleRightWrite;
    }
    // Signal authority — every trusted profile carries this; the
    // sandbox profile does not. The kernel's SpawnThread cap is the
    // closest existing proxy for "may affect kernel-object state":
    // an attacker without SpawnThread cannot create the second task
    // that would need signal-coordination in the first place. A
    // dedicated kCapIpcSignal cap is a future-clean follow-up if a
    // workload demonstrates the asymmetric profile is needed.
    if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapSpawnThread))
    {
        rights |= kHandleRightSignal;
    }
    // Without SpawnThread we also grant Write — the sandbox profile
    // includes Write so it can still send to its own mailboxes /
    // signal-via-write-shaped surfaces. The fence above already
    // dropped Write for sandboxed FS handles via the kCapFsWrite
    // gate; for non-FS types (Mailbox, etc.) Write means "send,"
    // which is unprivileged.
    rights |= kHandleRightWrite;
    return rights;
}

namespace
{

// Core insert path. Walks the slot table under the table lock and
// installs (obj, rights) at the first free slot. Both public
// `HandleTableInsert` overloads route through here; the rights-
// less overload passes the full type-allowed mask.
::duetos::core::Result<Handle> InsertWithRights(HandleTable& table, KObject* obj, u64 rights)
{
    KASSERT_WITH_VALUE(table.next_free_hint < kHandleTableCapacity, "ipc/handle_table",
                       "next_free_hint corrupted (oob)", static_cast<u64>(table.next_free_hint));
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
            KASSERT(table.slots[i].obj == nullptr, "ipc/handle_table", "slot raced between check and install");
            table.slots[i].obj = obj;
            table.slots[i].rights = rights;
            table.next_free_hint = i;
            KLOG_TRACE_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "insert ok handle", static_cast<u64>(i));
            return static_cast<Handle>(i);
        }
    }
    KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "Insert: table full (OOM)",
                 static_cast<u64>(kHandleTableCapacity));
    return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
}

} // namespace

::duetos::core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* obj)
{
    if (obj == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::IPC, "ipc/handle_table", "Insert called with null KObject");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    // Default rights: the full type-allowed set. Callers that know
    // the holding process's caps should use the rights-aware
    // overload to narrow further; this default keeps the existing
    // single-arg call sites working without per-site changes.
    const u64 default_rights = TypeAllowedRights(obj->type);
    sync::SpinLockGuard guard(table.lock);
    return InsertWithRights(table, obj, default_rights);
}

::duetos::core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* obj, u64 requested_rights)
{
    if (obj == nullptr)
    {
        KLOG_WARN_A(::duetos::core::LogArea::IPC, "ipc/handle_table", "Insert called with null KObject");
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    // Narrow to the type-allowed ceiling. A caller can never
    // mint a handle carrying a right the underlying type doesn't
    // recognise (e.g. Signal on a File).
    const u64 final_rights = requested_rights & TypeAllowedRights(obj->type);
    sync::SpinLockGuard guard(table.lock);
    return InsertWithRights(table, obj, final_rights);
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
    // Architectural-bounds invariant on the masked index. Catches
    // a MaskedIndex32 regression where the mask formula stops
    // clamping (a one-character bug would turn a Spectre-defence
    // into a real OOB on every IPC syscall).
    KASSERT_WITH_VALUE(masked_h < kHandleTableCapacity, "ipc/handle_table", "masked handle oob",
                       static_cast<u64>(masked_h));
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
    KASSERT_WITH_VALUE(masked_h < kHandleTableCapacity, "ipc/handle_table", "masked handle oob",
                       static_cast<u64>(masked_h));
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
    KASSERT_WITH_VALUE(masked_h < kHandleTableCapacity, "ipc/handle_table", "masked handle oob",
                       static_cast<u64>(masked_h));
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
        table.slots[masked_h].rights = 0;
    }
    KLOG_TRACE_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "remove ok handle", static_cast<u64>(h));
    // Release outside the table lock — destroy callbacks may
    // touch other handle tables / IPC objects.
    KObjectRelease(dropped);
    return {};
}

u64 HandleTableRights(HandleTable& table, Handle h)
{
    if (!HandleInRange(h))
    {
        return 0;
    }
    const Handle masked_h = static_cast<Handle>(util::MaskedIndex32(static_cast<u32>(h), kHandleTableCapacity));
    KASSERT_WITH_VALUE(masked_h < kHandleTableCapacity, "ipc/handle_table", "masked handle oob",
                       static_cast<u64>(masked_h));
    sync::SpinLockGuard guard(table.lock);
    if (table.slots[masked_h].obj == nullptr)
    {
        return 0;
    }
    return table.slots[masked_h].rights;
}

bool HandleCheckRight(HandleTable& table, Handle h, u64 required_rights)
{
    if (!HandleInRange(h))
    {
        return false;
    }
    // required_rights == 0 is a vacuous request — every existing
    // handle "has" zero rights. Refuse it explicitly so a buggy
    // caller (forgot to pass the right) is caught loudly instead
    // of silently passing.
    if (required_rights == 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "CheckRight called with zero mask; handle",
                     static_cast<u64>(h));
        return false;
    }
    const Handle masked_h = static_cast<Handle>(util::MaskedIndex32(static_cast<u32>(h), kHandleTableCapacity));
    KASSERT_WITH_VALUE(masked_h < kHandleTableCapacity, "ipc/handle_table", "masked handle oob",
                       static_cast<u64>(masked_h));
    sync::SpinLockGuard guard(table.lock);
    if (table.slots[masked_h].obj == nullptr)
    {
        return false;
    }
    return (table.slots[masked_h].rights & required_rights) == required_rights;
}

namespace
{

// Snapshot (obj+rights) under src.lock and acquire an extra ref on
// the kernel object. Returns nullptr if h is invalid / empty.
// Caller MUST `KObjectRelease` the returned pointer (or hand it
// off to a destination Insert).
KObject* LookupRefWithRights(HandleTable& src, Handle h, u64* out_rights)
{
    if (!HandleInRange(h))
    {
        *out_rights = 0;
        return nullptr;
    }
    const Handle masked_h = static_cast<Handle>(util::MaskedIndex32(static_cast<u32>(h), kHandleTableCapacity));
    KASSERT_WITH_VALUE(masked_h < kHandleTableCapacity, "ipc/handle_table", "masked handle oob",
                       static_cast<u64>(masked_h));
    KObject* obj = nullptr;
    u64 rights = 0;
    {
        sync::SpinLockGuard guard(src.lock);
        obj = src.slots[masked_h].obj;
        if (obj == nullptr)
        {
            *out_rights = 0;
            return nullptr;
        }
        rights = src.slots[masked_h].rights;
        KObjectAcquire(obj);
    }
    *out_rights = rights;
    return obj;
}

} // namespace

::duetos::core::Result<Handle> HandleTableDuplicate(HandleTable& src, HandleTable& dst, Handle h)
{
    if (!HandleInRange(h))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "Duplicate: src handle out of range",
                     static_cast<u64>(h));
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    u64 src_rights = 0;
    KObject* obj = LookupRefWithRights(src, h, &src_rights);
    if (obj == nullptr)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table", "Duplicate: src handle empty",
                     static_cast<u64>(h));
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    // Carry the source's full rights mask through to the
    // destination — a same-rights duplicate. Callers wanting a
    // strictly-reduced-rights variant use HandleTableDuplicateRights.
    auto inserted = HandleTableInsert(dst, obj, src_rights);
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

::duetos::core::Result<Handle> HandleTableDuplicateRights(HandleTable& src, HandleTable& dst, Handle h,
                                                          u64 requested_rights)
{
    if (!HandleInRange(h))
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    u64 src_rights = 0;
    KObject* obj = LookupRefWithRights(src, h, &src_rights);
    if (obj == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    // Source must carry kHandleRightDuplicate, otherwise the
    // operation is denied regardless of the requested set.
    if ((src_rights & kHandleRightDuplicate) == 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table",
                     "DuplicateRights: src lacks Duplicate; src handle", static_cast<u64>(h));
        KObjectRelease(obj);
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};
    }

    // No escalation: every bit in requested_rights must already be
    // present in src_rights. This is the core "floor only narrows"
    // invariant — a caller cannot dup-with-rights to gain access it
    // didn't already have.
    if ((requested_rights & ~src_rights) != 0)
    {
        KLOG_WARN_AV(::duetos::core::LogArea::IPC, "ipc/handle_table",
                     "DuplicateRights: requested escalation; src handle", static_cast<u64>(h));
        KObjectRelease(obj);
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};
    }

    auto inserted = HandleTableInsert(dst, obj, requested_rights);
    if (!inserted.has_value())
    {
        KObjectRelease(obj);
        return ::duetos::core::Err{inserted.error()};
    }
    return inserted;
}

::duetos::core::Result<Handle> HandleReplace(HandleTable& table, Handle src_handle, u64 requested_rights)
{
    // Atomic dup-then-close. Insert the narrowed-rights handle
    // FIRST so a table-full failure leaves the source intact, then
    // remove the source slot. Both operations take the table lock
    // independently — they're atomic at the per-operation level,
    // and observers either see src OR new (briefly both, never
    // neither).
    auto dup_r = HandleTableDuplicateRights(table, table, src_handle, requested_rights);
    if (!dup_r.has_value())
    {
        return ::duetos::core::Err{dup_r.error()};
    }
    auto rm_r = HandleTableRemove(table, src_handle);
    if (!rm_r.has_value())
    {
        // Source went away between dup and remove (shouldn't be
        // possible without a concurrent close, but defensive).
        // The duplicate is valid; return it.
        return dup_r;
    }
    return dup_r;
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
                // Defensive: victim_count cannot exceed
                // kHandleTableCapacity by the loop bound, but a
                // KASSERT here turns a future refactor that breaks
                // the bound (e.g. nested loop over a virtual cap)
                // into a loud failure rather than a stack-buffer
                // overflow of the on-stack `victims` array.
                KASSERT_WITH_VALUE(victim_count < kHandleTableCapacity, "ipc/handle_table",
                                   "drain victim buffer overflow", static_cast<u64>(victim_count));
                victims[victim_count++] = table.slots[i].obj;
                table.slots[i].obj = nullptr;
                table.slots[i].rights = 0;
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

void HandleRightsSelfTest()
{
    KLOG_TRACE_SCOPE("ipc/handle_table", "HandleRightsSelfTest");
    KLOG_INFO_A(::duetos::core::LogArea::IPC, "ipc/handle_table",
                "rights self-test: type-allowed, dup-narrow, no-escalate, replace, check");

    // (1) TypeAllowedRights — KEvent has Wait+Signal but no Read/Write.
    const u64 evt_allowed = TypeAllowedRights(KObjectType::Event);
    if ((evt_allowed & kHandleRightWait) == 0 || (evt_allowed & kHandleRightSignal) == 0)
    {
        PanicHt("rights self-test: KEvent missing Wait/Signal in type-allowed");
    }
    if ((evt_allowed & (kHandleRightRead | kHandleRightWrite)) != 0)
    {
        PanicHt("rights self-test: KEvent unexpectedly carries Read/Write in type-allowed");
    }
    // File has Read/Write/Inspect but no Wait/Signal.
    const u64 file_allowed = TypeAllowedRights(KObjectType::File);
    if ((file_allowed & (kHandleRightRead | kHandleRightWrite | kHandleRightInspect)) !=
        (kHandleRightRead | kHandleRightWrite | kHandleRightInspect))
    {
        PanicHt("rights self-test: KFile missing Read/Write/Inspect");
    }
    if ((file_allowed & (kHandleRightWait | kHandleRightSignal)) != 0)
    {
        PanicHt("rights self-test: KFile unexpectedly carries Wait/Signal");
    }

    // (2) ProcessCapsToHandleRights — sandbox (empty caps) vs trusted.
    const u64 sandbox_rights = ProcessCapsToHandleRights(::duetos::core::CapSetEmpty());
    const u64 trusted_rights = ProcessCapsToHandleRights(::duetos::core::CapSetTrusted());
    // Trusted should have Signal; sandbox should not (no kCapSpawnThread).
    if ((trusted_rights & kHandleRightSignal) == 0)
    {
        PanicHt("rights self-test: trusted caps did not yield Signal right");
    }
    if ((sandbox_rights & kHandleRightSignal) != 0)
    {
        PanicHt("rights self-test: sandbox caps unexpectedly yielded Signal right");
    }

    // (3) Insert with default rights on a KEvent-typed test object;
    // the stored rights must be exactly TypeAllowedRights(Event).
    HandleTable table{};
    static StTestObject evt_obj{};
    KObjectInit(&evt_obj.base, KObjectType::Event, &StDestroy);
    auto h_evt_r = HandleTableInsert(table, &evt_obj.base);
    if (!h_evt_r.has_value())
    {
        PanicHt("rights self-test: Insert(KEvent) failed");
    }
    const Handle h_evt = h_evt_r.value();
    if (HandleTableRights(table, h_evt) != evt_allowed)
    {
        PanicHt("rights self-test: default rights != TypeAllowedRights(Event)");
    }
    // Read should NOT be present on an event handle.
    if (HandleCheckRight(table, h_evt, kHandleRightRead))
    {
        PanicHt("rights self-test: KEvent default rights claimed Read");
    }
    if (!HandleCheckRight(table, h_evt, kHandleRightWait))
    {
        PanicHt("rights self-test: KEvent default rights missing Wait");
    }
    if (!HandleCheckRight(table, h_evt, kHandleRightSignal))
    {
        PanicHt("rights self-test: KEvent default rights missing Signal");
    }

    // (4) HandleTableDuplicateRights with reduced rights — strip
    // Signal, keep Wait+Inspect+Duplicate (we keep Duplicate on
    // the intermediate handle so step (6)'s HandleReplace below
    // has a Duplicate-bearing source to drive the atomic-replace
    // path). The new handle id must be distinct and carry exactly
    // the requested narrowed set (after type-allowed masking).
    const u64 narrowed = kHandleRightWait | kHandleRightInspect | kHandleRightDuplicate;
    auto h_narrow_r = HandleTableDuplicateRights(table, table, h_evt, narrowed);
    if (!h_narrow_r.has_value())
    {
        PanicHt("rights self-test: DuplicateRights(narrowed) failed");
    }
    const Handle h_narrow = h_narrow_r.value();
    if (h_narrow == h_evt)
    {
        PanicHt("rights self-test: DuplicateRights returned the same handle id");
    }
    if (HandleTableRights(table, h_narrow) != narrowed)
    {
        PanicHt("rights self-test: narrowed handle did not store narrowed rights");
    }
    if (HandleCheckRight(table, h_narrow, kHandleRightSignal))
    {
        PanicHt("rights self-test: narrowed handle still claims Signal");
    }
    if (!HandleCheckRight(table, h_narrow, kHandleRightWait))
    {
        PanicHt("rights self-test: narrowed handle dropped Wait");
    }

    // (5) Attempt to ESCALATE rights via Duplicate — set a bit
    // (Signal) the source doesn't have. Must fail with
    // PermissionDenied; the source slot stays untouched. Signal
    // is the right we stripped in step (4) — re-adding it is the
    // canonical "escalation" attack pattern.
    const u32 live_before_escalate = HandleTableLiveCount(table);
    auto h_escalate_r = HandleTableDuplicateRights(table, table, h_narrow, narrowed | kHandleRightSignal);
    if (h_escalate_r.has_value())
    {
        PanicHt("rights self-test: escalation via DuplicateRights succeeded");
    }
    if (h_escalate_r.error() != ::duetos::core::ErrorCode::PermissionDenied)
    {
        PanicHt("rights self-test: escalation rejection used wrong error code");
    }
    if (HandleTableLiveCount(table) != live_before_escalate)
    {
        PanicHt("rights self-test: escalation attempt mutated the table");
    }

    // (6) HandleReplace — strictly-reduced-rights variant; old id
    // is invalidated, new id carries the narrower set.
    const u64 even_narrower = kHandleRightInspect;
    auto h_replaced_r = HandleReplace(table, h_narrow, even_narrower);
    if (!h_replaced_r.has_value())
    {
        PanicHt("rights self-test: HandleReplace(reduced) failed");
    }
    const Handle h_replaced = h_replaced_r.value();
    if (HandleTableLookup(table, h_narrow, KObjectType::Event) != nullptr)
    {
        PanicHt("rights self-test: HandleReplace did not invalidate source handle");
    }
    if (HandleTableRights(table, h_replaced) != even_narrower)
    {
        PanicHt("rights self-test: HandleReplace did not narrow rights");
    }

    // (6a) HandleReplace must REFUSE when the source lacks
    // kHandleRightDuplicate. h_replaced now has Inspect only — no
    // Duplicate. Asking to keep Inspect (a strict subset of its
    // current rights) still fails because the underlying op is a
    // duplicate. This is the structural form of "you cannot
    // narrow a handle you don't control."
    auto h_no_dup_r = HandleReplace(table, h_replaced, kHandleRightInspect);
    if (h_no_dup_r.has_value())
    {
        PanicHt("rights self-test: HandleReplace succeeded on a non-Duplicate handle");
    }
    if (h_no_dup_r.error() != ::duetos::core::ErrorCode::PermissionDenied)
    {
        PanicHt("rights self-test: HandleReplace no-Duplicate rejection used wrong error code");
    }

    // (7) HandleCheckRight on a handle missing the required right
    // must return false; the syscall-style call site would then
    // return PermissionDenied. Confirm Inspect passes, Wait fails.
    if (!HandleCheckRight(table, h_replaced, kHandleRightInspect))
    {
        PanicHt("rights self-test: replaced handle dropped Inspect unexpectedly");
    }
    if (HandleCheckRight(table, h_replaced, kHandleRightWait))
    {
        PanicHt("rights self-test: replaced handle unexpectedly granted Wait");
    }

    // (8) Cleanup — drain so the underlying KObject's refcount
    // returns to 0 and the destroy callback runs. The handle slots
    // are released by Drain; the rights field is cleared in the
    // same path.
    HandleTableDrain(table);
    if (HandleTableLiveCount(table) != 0)
    {
        PanicHt("rights self-test: drain left handles behind");
    }
    // Sanity check: every slot's rights mask is 0 after drain.
    for (u32 i = 1; i < kHandleTableCapacity; ++i)
    {
        if (table.slots[i].rights != 0)
        {
            PanicHt("rights self-test: drained slot retained stale rights");
        }
    }

    // Grep-able PASS sentinel for boot-log scrapers. Mirrors the
    // KLOG_INFO above the convention for self-tests but emits a
    // structural marker that doesn't depend on the runtime log
    // level (the WARN sentinels we'd otherwise see are gated to
    // failures only).
    ::duetos::arch::SerialWrite("[handle-rights] self-test OK (type-allowed, narrow, no-escalate, replace)\n");
}

} // namespace duetos::ipc
