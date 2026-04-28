#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — kernel object base type, v0 (plan A3).
 *
 * WHAT
 *   `KObject` is the refcounted, type-tagged base every kernel
 *   object placed in a `HandleTable` derives from. New IPC-style
 *   objects (Mutex / Event / Semaphore / Mailbox / Waitable) embed
 *   `KObject` as their first member so a `KObject*` can be
 *   reinterpret_cast'd back to the concrete type after a
 *   `KObjectType` check.
 *
 * WHY
 *   The current kernel has ~10 separate per-type fixed-size handle
 *   arrays on `Process` (Win32MutexHandle, Win32EventHandle,
 *   Win32SemaphoreHandle, Win32ProcessHandle, …) plus the Linux
 *   `LinuxFd` table. Every new ABI front-end either bolts on its
 *   own table or pretends one of the existing ones fits. The
 *   plan's hard rule — "one TCP stack, one VFS, one registry, one
 *   window manager" — implicitly demands the same shape for IPC
 *   objects. KObject is that shape.
 *
 * WHAT THIS COMMIT IS NOT
 *   v0 lands ONLY the base type + the per-process handle table
 *   (`handle_table.h`). The existing per-type handle arrays on
 *   `Process` keep working unchanged. Concrete `KMutex` / `KEvent`
 *   / `KSemaphore` subclasses, and migration of any existing
 *   handle surface, are tracked as follow-ups in the plan's
 *   Status table.
 *
 * REFCOUNT SEMANTICS
 *   `KObjectInit` sets refcount = 1. The first `HandleTableInsert`
 *   takes ownership of that initial reference (no extra acquire).
 *   `HandleTableDuplicate` calls `KObjectAcquire` to add a fresh
 *   reference for the destination handle. `HandleTableRemove`
 *   calls `KObjectRelease`; on the last release, the
 *   type-specific `destroy` callback runs and the storage is
 *   freed by whatever code owns it.
 *
 * THREADING
 *   Refcount mutations are atomic via a single global spinlock
 *   (`g_kobject_lock` in kobject.cpp). For v0 contention is
 *   negligible; a per-object atomic counter is the obvious upgrade
 *   when SMP profiling shows the global lock as a hotspot.
 */

namespace duetos::ipc
{

/// Type tag stored in every KObject. The numeric values are stable
/// — used by `inspect` / panic dumps. New types append at the end;
/// never re-use a retired tag.
enum class KObjectType : u32
{
    Invalid = 0,
    Mutex = 1,
    Event = 2,
    Semaphore = 3,
    Mailbox = 4,
    Waitable = 5,
    File = 6, ///< KFile — open file descriptor (plan A3-followup).

    /// Used by the v0 self-test exclusively. Real kernel code must
    /// never use this — it exists so the infrastructure can be
    /// exercised without tying the test to any concrete IPC type.
    Test = 0xFFFE,
};

struct KObject;

/// Type-specific tear-down. Called when the refcount hits zero.
/// Must NOT call `KObjectRelease` on the same object (would
/// recurse). Should free any backing storage owned by the
/// concrete type. May be nullptr for types whose storage is
/// caller-owned (the test type uses this).
using KObjectDestroyFn = void (*)(KObject* obj);

struct KObject
{
    KObjectType type;
    u32 refcount;
    KObjectDestroyFn destroy;
};

/// Initialise a newly-allocated KObject. Sets `refcount = 1`. The
/// caller still owns the only reference and is expected to hand it
/// off to a `HandleTable` (or release it explicitly via
/// `KObjectRelease`).
void KObjectInit(KObject* obj, KObjectType type, KObjectDestroyFn destroy);

/// Add a reference. Used by `HandleTableDuplicate`. Cheap (one
/// spinlock + increment).
void KObjectAcquire(KObject* obj);

/// Drop a reference. Calls `obj->destroy(obj)` on the last
/// release. Safe to call with `obj == nullptr` (no-op).
void KObjectRelease(KObject* obj);

/// Read the current refcount. Diagnostic use only — racy under
/// SMP. The runtime checker / shell `ipc list` (future) read this
/// for "live handle count" reporting.
u32 KObjectRefcount(const KObject* obj);

/// Stable human-readable type name. Returns "?" for out-of-range.
/// Used by panic dumps + the future `inspect ipc` command.
const char* KObjectTypeName(KObjectType type);

/// Boot-time self-test. Init / Acquire / Release / destroy-on-zero
/// path against a private test type. Panics on counter mismatch;
/// asserts destroy fires exactly once.
void KObjectSelfTest();

} // namespace duetos::ipc
