/*
 * DuetOS — concrete KFile, v0 (plan A3-followup).
 *
 * See `kfile.h` for the contract. Sixth KObject subclass; the
 * Linux / Win32 fd-table migrations onto this type are the
 * next slice. v0 just lands the type + lifecycle + a
 * round-trip self-test.
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
    duetos::mm::KFree(f);
}

} // namespace

::duetos::core::Result<KFile*> KFileCreate(void* vnode, u32 flags)
{
    auto* f = static_cast<KFile*>(duetos::mm::KMalloc(sizeof(KFile)));
    if (f == nullptr)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *f = KFile{};
    KObjectInit(&f->base, KObjectType::File, &KFileDestroy);
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

void KFileSelfTest()
{
    arch::SerialWrite("[ipc] kfile self-test: lifecycle + HandleTable round-trip\n");

    auto r = KFileCreate(reinterpret_cast<void*>(0xDEAD'BEEFULL), kFileReadable | kFileWritable);
    if (!r.has_value())
    {
        core::Panic("ipc/kfile", "self-test: KFileCreate failed");
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
    if (KFilePosition(f) != 0)
    {
        core::Panic("ipc/kfile", "self-test: fresh KFile pos != 0");
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

    arch::SerialWrite("[ipc] kfile self-test OK (Create + vnode/flags round-trip + HandleTable cycle).\n");
}

} // namespace duetos::ipc
