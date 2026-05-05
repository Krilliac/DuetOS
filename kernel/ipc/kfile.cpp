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

#include <stddef.h>

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KFile, base) == 0, "KObject must be the first member of KFile");

namespace
{

void KFileDestroy(KObject* obj)
{
    auto* f = reinterpret_cast<KFile*>(obj);
    // Per-kind pool release callback fires before the storage
    // is freed. For kinds with no pool ref to drop (None / Tty /
    // Fat32File) the callback is nullptr and we just free.
    if (f->release_pool != nullptr)
    {
        f->release_pool(f->pool_index);
    }
    duetos::mm::KFree(f);
}

} // namespace

::duetos::core::Result<KFile*> KFileCreate(KFileKind kind, u32 pool_index, KFilePoolRelease release, void* vnode,
                                           u32 flags)
{
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
    f->vnode = vnode;
    f->flags = flags;
    return f;
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

    static HandleTable table{};
    auto insert_r = HandleTableInsert(table, &f->base);
    if (!insert_r.has_value())
    {
        core::Panic("ipc/kfile", "self-test: HandleTableInsert failed");
    }
    const Handle h = insert_r.value();
    if (HandleTableLookup(table, h, KObjectType::File) != &f->base)
    {
        core::Panic("ipc/kfile", "self-test: lookup did not return file");
    }
    if (HandleTableLookup(table, h, KObjectType::Mutex) != nullptr)
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
    auto insert2_r = HandleTableInsert(table, &f2->base);
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

    arch::SerialWrite("[ipc] kfile self-test OK (Create + kind/pool round-trip + HandleTable cycle + "
                      "per-kind release callback).\n");
}

} // namespace duetos::ipc
