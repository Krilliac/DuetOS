/*
 * DuetOS — kernel object base implementation, v0 (plan A3).
 *
 * See `kobject.h` for the public contract. This TU owns the
 * refcount lock + the boot self-test.
 *
 * Why a single global spinlock for refcounts: for v0 the alternative
 * (a per-object atomic) is a micro-optimisation against contention
 * that doesn't exist yet (single CPU, low IPC traffic). The global
 * lock is held for ~5 instructions per Acquire/Release; trivially
 * upgradable when profiles say otherwise.
 */

#include "ipc/kobject.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "sync/spinlock.h"
#include "util/nospec.h"
#include "util/result.h"
#include "util/types.h"

namespace duetos::ipc
{

namespace
{

// Tagged with `kLockClassKObject` for lockdep.
constinit sync::SpinLock g_kobject_lock{
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassKObject};

[[noreturn]] void PanicKObj(const char* what)
{
    core::Panic("ipc/kobject", what);
}

} // namespace

const char* KObjectTypeName(KObjectType type)
{
    switch (type)
    {
    case KObjectType::Invalid:
        return "invalid";
    case KObjectType::Mutex:
        return "mutex";
    case KObjectType::Event:
        return "event";
    case KObjectType::Semaphore:
        return "semaphore";
    case KObjectType::Mailbox:
        return "mailbox";
    case KObjectType::Waitable:
        return "waitable";
    case KObjectType::File:
        return "file";
    case KObjectType::Test:
        return "test";
    default:
        KLOG_ONCE_WARN("ipc/kobject", "KObjectTypeName: unrecognised type enumerator");
        return "?";
    }
}

void KObjectInit(KObject* obj, KObjectType type, KObjectDestroyFn destroy)
{
    if (obj == nullptr)
    {
        // Caller passed a null kobject. Debug: panic so the bug
        // surfaces. Release: log and refuse — leaving obj null
        // means the caller's later dereference will fault loudly
        // anyway, which is no worse than the original panic and
        // doesn't take the rest of the kernel down.
        core::DebugPanicOrWarn("ipc/kobject", "KObjectInit on null");
        return;
    }
    if (type == KObjectType::Invalid)
    {
        core::DebugPanicOrWarn("ipc/kobject", "KObjectInit with KObjectType::Invalid");
        return;
    }
    obj->type = type;
    obj->refcount = 1;
    obj->destroy = destroy;
}

void KObjectAcquire(KObject* obj)
{
    if (obj == nullptr)
    {
        core::DebugPanicOrWarn("ipc/kobject", "KObjectAcquire on null");
        return;
    }
    sync::SpinLockGuard guard(g_kobject_lock);
    if (obj->refcount == 0)
    {
        // Use-after-free shape: object is on its way out, caller
        // raced. Release: refuse the bump rather than resurrect a
        // destroyed object. The guard's destructor unwinds the
        // spinlock on early return.
        core::DebugPanicOrWarn("ipc/kobject", "KObjectAcquire on dead object (refcount already 0)");
        return;
    }
    // Saturating increment — the spinlock makes the read+write
    // atomic, but a future "shareable handle" surface could let
    // an unprivileged path drive u32 increments to wrap. Refuse
    // at the ceiling rather than allow CVE-2016-0728-style
    // refcount-overflow-to-UAF. wiki/security/Linux-CVE-Audit.md
    // class O.
    if (!util::RefcountIncSaturating(&obj->refcount))
    {
        core::DebugPanicOrWarn("ipc/kobject", "KObjectAcquire refcount saturated");
        return;
    }
}

void KObjectRelease(KObject* obj)
{
    if (obj == nullptr)
    {
        // Convention: nullptr release is a no-op. Mirrors `KFree`.
        return;
    }

    bool reached_zero = false;
    {
        sync::SpinLockGuard guard(g_kobject_lock);
        if (obj->refcount == 0)
        {
            // Double-release. Debug: panic. Release: log and
            // return — touching `refcount` here would underflow
            // the counter and turn a one-time bug into permanent
            // miscount.
            core::DebugPanicOrWarn("ipc/kobject", "KObjectRelease on dead object (double-free?)");
            return;
        }
        --obj->refcount;
        reached_zero = (obj->refcount == 0);
    }

    if (reached_zero && obj->destroy != nullptr)
    {
        // Run destroy outside the lock — destroy may itself touch
        // other objects (Release them) and re-entering the global
        // lock from inside a destroy callback would deadlock.
        obj->destroy(obj);
    }
}

u32 KObjectRefcount(const KObject* obj)
{
    if (obj == nullptr)
    {
        return 0;
    }
    sync::SpinLockGuard guard(g_kobject_lock);
    return obj->refcount;
}

namespace
{

// Self-test scratch type. Embeds KObject as its first member so a
// reinterpret_cast<KObject*>(&t) is well-defined. The destroy
// callback bumps a counter so the test can verify it fired exactly
// once.
struct SelfTestObject
{
    KObject base;
    u32 destroy_count;
};

u32 g_selftest_destroyed_objects = 0;

void SelfTestDestroy(KObject* obj)
{
    auto* self = reinterpret_cast<SelfTestObject*>(obj);
    ++self->destroy_count;
    ++g_selftest_destroyed_objects;
}

} // namespace

void KObjectSelfTest()
{
    arch::SerialWrite("[ipc] kobject self-test: refcount + destroy semantics\n");

    SelfTestObject t{};
    KObjectInit(&t.base, KObjectType::Test, &SelfTestDestroy);
    if (t.base.type != KObjectType::Test || t.base.refcount != 1)
    {
        PanicKObj("Init did not set type / refcount=1");
    }
    if (KObjectRefcount(&t.base) != 1)
    {
        PanicKObj("Refcount accessor disagrees with init");
    }

    KObjectAcquire(&t.base);
    KObjectAcquire(&t.base);
    if (KObjectRefcount(&t.base) != 3)
    {
        PanicKObj("Acquire count != 3 after Init + 2 Acquire");
    }

    const u32 baseline_destroyed = g_selftest_destroyed_objects;

    KObjectRelease(&t.base); // 3 -> 2
    KObjectRelease(&t.base); // 2 -> 1
    if (KObjectRefcount(&t.base) != 1)
    {
        PanicKObj("Refcount != 1 after two Releases");
    }
    if (g_selftest_destroyed_objects != baseline_destroyed)
    {
        PanicKObj("Destroy fired before refcount reached zero");
    }

    KObjectRelease(&t.base); // 1 -> 0; destroy fires
    if (g_selftest_destroyed_objects != baseline_destroyed + 1)
    {
        PanicKObj("Destroy did not fire on last release");
    }
    if (t.destroy_count != 1)
    {
        PanicKObj("Destroy fired but counter wrong");
    }

    // nullptr Release is a no-op (matches KFree).
    KObjectRelease(nullptr);

    arch::SerialWrite("[ipc] kobject self-test OK (Init/Acquire/Release/destroy verified).\n");
}

} // namespace duetos::ipc
