/*
 * DuetOS — concrete KFile.
 *
 * See `kfile.h` for the contract. KFile is the unified "open
 * file" abstraction every Linux fd / Win32 file handle resolves
 * through. Hot-path Linux fds park their KFile reference on the
 * `LinuxFd` slot's `kf_handle` field; close / dup / fork all
 * go through HandleTableRemove / Duplicate so per-pool retain /
 * release happens via KObject refcounting instead of open-coded
 * call sites in the syscall layer.
 */

#include "ipc/kfile.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "mm/kheap.h"
#include "proc/process.h"

#include <stddef.h>

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KFile, base) == 0, "KObject must be the first member of KFile");

namespace
{

void KFileDestroy(KObject* obj)
{
    auto* f = reinterpret_cast<KFile*>(obj);
    // Release-callback exclusivity invariant. KFileCreate sets
    // `release_pool` and clears `release_pool_with_owner`;
    // KFileCreateWithOwner does the opposite. Both pointers
    // simultaneously non-null would mean either a wild store
    // scribbled one of them or a future `Create…` factory dropped
    // the mutual-exclusion contract — either way the pool ref
    // would be released TWICE (or against the wrong owner).
    KASSERT(!(f->release_pool != nullptr && f->release_pool_with_owner != nullptr), "ipc/kfile",
            "destroy: both release callbacks set");
    KASSERT((f->kind == KFileKind::Pidfd) == (f->retained_process_target != nullptr), "ipc/kfile",
            "destroy: pidfd Process target invariant broken");
    KASSERT(f->kind != KFileKind::Pidfd ||
                (f->release_pool == nullptr && f->release_pool_with_owner == nullptr && f->owner == nullptr),
            "ipc/kfile", "destroy: pidfd mixed identity ownership with pool callback");
    // Detach the Process edge before any callback. The field is immutable
    // while the KFile is live, and reaching this destroy callback proves the
    // final KFile reference is gone. ProcessRelease is deliberately deferred
    // until after KFile storage is freed so it cannot reclaim a self-target
    // Process while this destructor still needs either object.
    ::duetos::core::Process* retained_process_target = f->retained_process_target;
    f->retained_process_target = nullptr;
    // Per-kind pool release callback fires before the storage
    // is freed. For kinds with no pool ref to drop (None / Tty /
    // Fat32File) the callback is nullptr and we just free.
    if (f->release_pool != nullptr)
    {
        f->release_pool(f->pool_index);
    }
    if (f->release_pool_with_owner != nullptr && f->owner != nullptr)
    {
        f->release_pool_with_owner(f->owner, f->pool_index);
    }
    duetos::mm::KFree(f);
    // KObjectRelease invokes destroy outside its global spinlock, and
    // HandleTableRemove detaches before it releases the object. Therefore this
    // potentially final ProcessRelease runs outside every KObject/table lock.
    ::duetos::core::ProcessRelease(retained_process_target);
}

} // namespace

::duetos::core::Result<KFile*> KFileCreate(KFileKind kind, u32 pool_index, KFilePoolRelease release, void* vnode,
                                           u32 flags)
{
    // A pidfd without a strong target would silently regress to weak PID-only
    // identity. Force all pidfd construction through KFileCreatePidfd.
    if (kind == KFileKind::Pidfd)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    auto* f = static_cast<KFile*>(duetos::mm::KMalloc(sizeof(KFile)));
    if (f == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *f = KFile{};
    KObjectInit(&f->base, KObjectType::File, &KFileDestroy);
    f->kind = kind;
    f->cloexec = false;
    f->pool_index = pool_index;
    f->release_pool = release;
    f->release_pool_with_owner = nullptr;
    f->owner = nullptr;
    f->retained_process_target = nullptr;
    f->vnode = vnode;
    f->flags = flags;
    return f;
}

::duetos::core::Result<KFile*> KFileCreateWithOwner(KFileKind kind, u32 pool_index, KFileProcessRelease release,
                                                    ::duetos::core::Process* owner, void* vnode, u32 flags)
{
    if (kind == KFileKind::Pidfd)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    auto* f = static_cast<KFile*>(duetos::mm::KMalloc(sizeof(KFile)));
    if (f == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *f = KFile{};
    KObjectInit(&f->base, KObjectType::File, &KFileDestroy);
    f->kind = kind;
    f->cloexec = false;
    f->pool_index = pool_index;
    f->release_pool = nullptr;
    f->release_pool_with_owner = release;
    f->owner = owner;
    f->retained_process_target = nullptr;
    f->vnode = vnode;
    f->flags = flags;
    return f;
}

::duetos::core::Result<KFile*> KFileCreatePidfd(::duetos::core::Process* target)
{
    if (target == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    auto* f = static_cast<KFile*>(duetos::mm::KMalloc(sizeof(KFile)));
    if (f == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *f = KFile{};
    KObjectInit(&f->base, KObjectType::File, &KFileDestroy);
    f->kind = KFileKind::Pidfd;
    f->cloexec = false;
    f->pool_index = 0;
    f->release_pool = nullptr;
    f->release_pool_with_owner = nullptr;
    f->owner = nullptr;
    f->vnode = nullptr;
    f->flags = 0;
    // The caller owns a stable reference across this factory. Take exactly
    // one additional edge for the shared open-file description.
    ::duetos::core::ProcessRetain(target);
    f->retained_process_target = target;
    return f;
}

::duetos::core::Process* KFileAcquirePidfdTarget(const KFile* f)
{
    if (f == nullptr || f->kind != KFileKind::Pidfd || f->retained_process_target == nullptr)
    {
        return nullptr;
    }
    // The caller's retained KFile prevents KFileDestroy from clearing this
    // immutable field until after the new Process reference is published.
    ::duetos::core::Process* target = f->retained_process_target;
    ::duetos::core::ProcessRetain(target);
    return target;
}

u64 KFilePosition(const KFile* f)
{
    return f->pos;
}

u32 KFileFlagsRead(const KFile* f)
{
    return f->flags;
}

KFileKind KFileKindRead(const KFile* f)
{
    return f->kind;
}

u32 KFilePoolIndex(const KFile* f)
{
    return f->pool_index;
}

namespace
{

// Self-test side-channel — incremented by the synthetic release
// callback below. The self-test asserts it bumps exactly once
// when the second KFile's refcount drops to zero.
u32 g_selftest_release_calls = 0;
u32 g_selftest_release_index = 0;

void SelfTestPoolRelease(u32 pool_index)
{
    ++g_selftest_release_calls;
    g_selftest_release_index = pool_index;
}

u32 g_selftest_owner_release_calls = 0;
u32 g_selftest_owner_release_index = 0;
::duetos::core::Process* g_selftest_owner_release_owner = nullptr;

void SelfTestOwnerRelease(::duetos::core::Process* owner, u32 pool_index)
{
    ++g_selftest_owner_release_calls;
    g_selftest_owner_release_index = pool_index;
    g_selftest_owner_release_owner = owner;
}

} // namespace

void KFileSelfTest()
{
    arch::SerialWrite("[ipc] kfile self-test: lifecycle + HandleTable round-trip + pool-release callback\n");

    // Round 1 — kFileKindNone, no pool callback.
    auto r = KFileCreate(KFileKind::None, 0, nullptr, reinterpret_cast<void*>(0xDEAD'BEEFULL),
                         kFileReadable | kFileWritable);
    if (!r.has_value())
    {
        core::Panic("ipc/kfile", "self-test: KFileCreate(None) failed");
    }
    KFile* f = r.value();
    if (f->vnode != reinterpret_cast<void*>(0xDEAD'BEEFULL))
    {
        core::Panic("ipc/kfile", "self-test: vnode round-trip lost");
    }
    if (KFileFlagsRead(f) != (kFileReadable | kFileWritable))
    {
        core::Panic("ipc/kfile", "self-test: flags round-trip lost");
    }
    if (KFileKindRead(f) != KFileKind::None)
    {
        core::Panic("ipc/kfile", "self-test: kind round-trip lost");
    }
    if (KFilePosition(f) != 0)
    {
        core::Panic("ipc/kfile", "self-test: fresh KFile pos != 0");
    }
    if (f->cloexec)
    {
        core::Panic("ipc/kfile", "self-test: fresh KFile cloexec != false");
    }
    if (f->retained_process_target != nullptr || KFileAcquirePidfdTarget(f) != nullptr)
    {
        core::Panic("ipc/kfile", "self-test: ordinary KFile exposed a Process target");
    }

    // Construction policy is part of the lifetime contract: the generic
    // callback factory may never manufacture a weak pidfd.
    auto weak_pidfd = KFileCreate(KFileKind::Pidfd, 0, nullptr, nullptr, 0);
    if (weak_pidfd.has_value())
    {
        core::Panic("ipc/kfile", "self-test: generic factory accepted weak pidfd");
    }

    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &f->base, TypeAllowedRights(KObjectType::File));
    if (!insert_r.has_value())
    {
        core::Panic("ipc/kfile", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    KObject* looked_up = HandleTableLookupRef(table, h, KObjectType::File);
    if (looked_up != &f->base)
    {
        core::Panic("ipc/kfile", "self-test: lookup did not return file");
    }
    KObjectRelease(looked_up);
    if (HandleTableLookupRef(table, h, KObjectType::Mutex) != nullptr)
    {
        core::Panic("ipc/kfile", "self-test: lookup with wrong type-tag returned non-null");
    }
    if (!HandleTableRemove(table, h).has_value())
    {
        core::Panic("ipc/kfile", "self-test: HandleTableRemove failed");
    }
    if (HandleTableLiveCount(table) != 0)
    {
        core::Panic("ipc/kfile", "self-test: live count != 0 at end");
    }

    // Round 2 — synthetic kind with a pool-release callback.
    // Asserts the callback fires exactly once, with the right
    // pool index, when the last reference drops.
    g_selftest_release_calls = 0;
    g_selftest_release_index = 0;
    auto r2 = KFileCreate(KFileKind::Eventfd, 0xCAFE, &SelfTestPoolRelease, nullptr, 0);
    if (!r2.has_value())
    {
        core::Panic("ipc/kfile", "self-test: KFileCreate(Eventfd) failed");
    }
    KFile* f2 = r2.value();
    auto insert2_r = HandleTableInsert(table, &f2->base, TypeAllowedRights(KObjectType::File));
    if (!insert2_r.has_value())
    {
        core::Panic("ipc/kfile", "self-test: HandleTableInsert(2) failed");
    }
    if (g_selftest_release_calls != 0)
    {
        core::Panic("ipc/kfile", "self-test: release callback fired before refcount=0");
    }
    if (!HandleTableRemove(table, insert2_r.value()).has_value())
    {
        core::Panic("ipc/kfile", "self-test: HandleTableRemove(2) failed");
    }
    if (g_selftest_release_calls != 1)
    {
        core::Panic("ipc/kfile", "self-test: release callback did not fire exactly once");
    }
    if (g_selftest_release_index != 0xCAFE)
    {
        core::Panic("ipc/kfile", "self-test: release callback got wrong pool_index");
    }

    // Round 3 — owner-aware release shape (dirfd path).
    // Build a synthetic owner sentinel (cast of an integer — the
    // self-test never dereferences it, only round-trips it through
    // the callback) and assert it lands intact.
    g_selftest_owner_release_calls = 0;
    g_selftest_owner_release_index = 0;
    g_selftest_owner_release_owner = nullptr;
    auto* owner_sentinel = reinterpret_cast<::duetos::core::Process*>(0xFEEDFACEULL);
    auto r3 = KFileCreateWithOwner(KFileKind::DirSnapshot, 0xBEEF, &SelfTestOwnerRelease, owner_sentinel,
                                   /*vnode=*/nullptr, /*flags=*/0);
    if (!r3.has_value())
    {
        core::Panic("ipc/kfile", "self-test: KFileCreateWithOwner failed");
    }
    KFile* f3 = r3.value();
    if (f3->owner != owner_sentinel)
    {
        core::Panic("ipc/kfile", "self-test: owner round-trip lost");
    }
    if (f3->release_pool != nullptr)
    {
        core::Panic("ipc/kfile", "self-test: owner-aware Create left pool callback non-null");
    }
    auto insert3_r = HandleTableInsert(table, &f3->base, TypeAllowedRights(KObjectType::File));
    if (!insert3_r.has_value())
    {
        core::Panic("ipc/kfile", "self-test: HandleTableInsert(3) failed");
    }
    if (g_selftest_owner_release_calls != 0)
    {
        core::Panic("ipc/kfile", "self-test: owner release fired before refcount=0");
    }
    if (!HandleTableRemove(table, insert3_r.value()).has_value())
    {
        core::Panic("ipc/kfile", "self-test: HandleTableRemove(3) failed");
    }
    if (g_selftest_owner_release_calls != 1)
    {
        core::Panic("ipc/kfile", "self-test: owner release did not fire exactly once");
    }
    if (g_selftest_owner_release_index != 0xBEEF)
    {
        core::Panic("ipc/kfile", "self-test: owner release got wrong pool_index");
    }
    if (g_selftest_owner_release_owner != owner_sentinel)
    {
        core::Panic("ipc/kfile", "self-test: owner release got wrong owner pointer");
    }

    arch::SerialWrite("[ipc] kfile self-test OK (Create + kind/pool round-trip + HandleTable cycle + "
                      "per-kind release callback + owner-aware release callback + pidfd factory gate).\n");
}

} // namespace duetos::ipc
