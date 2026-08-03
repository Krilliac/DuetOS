/*
 * SYS_NAMED_KOBJ_OPEN_OR_CREATE — kernel-resident named-object
 * dispatcher. Backs Win32 Create{Mutex,Event,Semaphore} when a
 * name is provided and Open{Mutex,Event,Semaphore} on the
 * open-only path. See named_kobj_syscall.h + the syscall.h
 * ABI block for the contract.
 */

#include "subsystems/win32/named_kobj_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "ipc/handle_table.h"
#include "ipc/kevent.h"
#include "ipc/kmutex.h"
#include "ipc/kobject.h"
#include "ipc/ksemaphore.h"
#include "ipc/named_kobjects.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u64 kBadHandle = static_cast<u64>(-1);

u64 HandleBaseFor(::duetos::ipc::KObjectType type)
{
    switch (type)
    {
    case ::duetos::ipc::KObjectType::Mutex:
        return ::duetos::core::Process::kWin32MutexBase;
    case ::duetos::ipc::KObjectType::Event:
        return ::duetos::core::Process::kWin32EventBase;
    case ::duetos::ipc::KObjectType::Semaphore:
        return ::duetos::core::Process::kWin32SemaphoreBase;
    default:
        return 0; // unreachable for caller-validated types
    }
}

bool EncodePublicHandle(::duetos::ipc::KObjectType type, ::duetos::ipc::Handle handle, u64* out)
{
    return ::duetos::ipc::HandleEncodeTagged(handle, static_cast<u32>(HandleBaseFor(type)), out);
}

// Allocate a fresh kobject of the requested type using the
// type-specific Create function. `init_state_or_owner` carries
// the per-type init bits — see syscall.h for the encoding.
::duetos::ipc::KObject* CreateKObjectByType(::duetos::ipc::KObjectType type, u64 init_state_or_owner)
{
    using namespace ::duetos::ipc;
    switch (type)
    {
    case KObjectType::Mutex:
    {
        auto r = KMutexCreate();
        if (!r.has_value())
            return nullptr;
        KMutex* m = r.value();
        // Initial-owner semantics: rdi == 1 means caller owns the
        // new mutex with recursion = 1.
        if (init_state_or_owner != 0)
            KMutexAcquire(m);
        return &m->base;
    }
    case KObjectType::Event:
    {
        const bool manual_reset = (init_state_or_owner & 0x1) != 0;
        const bool initial_state = (init_state_or_owner & 0x2) != 0;
        auto r = KEventCreate(manual_reset, initial_state);
        if (!r.has_value())
            return nullptr;
        KEvent* e = r.value();
        return &e->base;
    }
    case KObjectType::Semaphore:
    {
        const u32 initial = static_cast<u32>(init_state_or_owner & 0xFFFFFFFFu);
        const u32 maximum = static_cast<u32>(init_state_or_owner >> 32);
        auto r = KSemaphoreCreate(initial, maximum);
        if (!r.has_value())
            return nullptr;
        KSemaphore* s = r.value();
        return &s->base;
    }
    default:
        return nullptr;
    }
}

void ReleaseFreshAfterFailure(::duetos::ipc::KObjectType type, ::duetos::ipc::KObject* object, u64 init_state_or_owner)
{
    using namespace ::duetos::ipc;
    if (type == KObjectType::Mutex && init_state_or_owner != 0)
        KMutexRelease(reinterpret_cast<KMutex*>(object));
    KObjectRelease(object);
}

} // namespace

void DoNamedKObjOpenOrCreate(arch::TrapFrame* frame)
{
    using namespace ::duetos::ipc;

    ::duetos::core::Process* proc = ::duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = kBadHandle;
        return;
    }

    // Validate type.
    KObjectType type;
    switch (frame->rdi)
    {
    case 0:
        type = KObjectType::Mutex;
        break;
    case 1:
        type = KObjectType::Event;
        break;
    case 2:
        type = KObjectType::Semaphore;
        break;
    default:
        frame->rax = kBadHandle;
        return;
    }

    // Copy the name into a kernel-side buffer. The user-supplied
    // length cap is bounded by the table's max name length so a
    // malicious caller can't drag the kernel into reading past
    // the user's buffer.
    char name[kNamedKObjectMaxNameLen] = {};
    const u64 user_len_cap = frame->rdx;
    const u64 cap =
        (user_len_cap == 0 || user_len_cap >= kNamedKObjectMaxNameLen) ? kNamedKObjectMaxNameLen : user_len_cap;
    const auto name_copy = ::duetos::mm::CopyUserCString(name, cap, reinterpret_cast<const void*>(frame->rsi));
    if (!name_copy.ok())
    {
        frame->rax = kBadHandle;
        return;
    }
    if (name[0] == '\0')
    {
        frame->rax = kBadHandle;
        return;
    }

    const u64 init_state_or_owner = frame->r10;
    const bool open_only = (frame->r8 != 0);

    // Hot path: lookup. On hit we hand the existing kobject
    // off to the caller's handle table and return.
    KObject* existing = NamedKObjectFind(type, name);
    if (existing != nullptr)
    {
        const u64 rights = HandleRightsForProcess(type, ::duetos::core::ProcessCapsSnapshot(proc));
        auto insert_r = HandleTableInsert(proc->kobj_handles, existing, rights);
        if (!insert_r.has_value())
        {
            // Drop the Find-time refcount on insert failure.
            KObjectRelease(existing);
            frame->rax = kBadHandle;
            return;
        }
        // Insert adopts the Find-time reference on success.
        u64 public_handle = 0;
        if (!EncodePublicHandle(type, insert_r.value(), &public_handle))
        {
            (void)HandleTableRemove(proc->kobj_handles, insert_r.value());
            frame->rax = kBadHandle;
            return;
        }
        frame->rax = public_handle;
        return;
    }

    // Miss path. Open-only callers fail here.
    if (open_only)
    {
        frame->rax = kBadHandle;
        return;
    }

    // Create a fresh kobject of the requested type and register
    // it under the name. The kobject's create-time refcount is
    // held by us until we hand it off to the handle table.
    KObject* fresh = CreateKObjectByType(type, init_state_or_owner);
    if (fresh == nullptr)
    {
        frame->rax = kBadHandle;
        return;
    }
    if (!NamedKObjectRegister(type, name, fresh))
    {
        ReleaseFreshAfterFailure(type, fresh, init_state_or_owner);
        frame->rax = kBadHandle;
        return;
    }

    // Register is deliberately idempotent: a concurrent creator may
    // have installed the same (type,name) first. Resolve the registry
    // winner after registration so this caller never publishes its
    // private loser object under a name that resolves elsewhere.
    KObject* registered = NamedKObjectFind(type, name);
    if (registered == nullptr)
    {
        // The bounded LRU registry can evict between Register and
        // Find. Fail closed instead of minting an unregistered name.
        ReleaseFreshAfterFailure(type, fresh, init_state_or_owner);
        frame->rax = kBadHandle;
        return;
    }
    const bool registry_used_fresh = (registered == fresh);
    if (registry_used_fresh)
    {
        // Keep the create-time ref for the handle table and discard
        // the verification lookup ref.
        KObjectRelease(registered);
    }
    else
    {
        // Initial-owner state applies only to a newly-created mutex.
        // Unwind the losing object and use the winner's Find ref.
        ReleaseFreshAfterFailure(type, fresh, init_state_or_owner);
        fresh = registered;
    }

    const u64 rights = HandleRightsForProcess(type, ::duetos::core::ProcessCapsSnapshot(proc));
    auto insert_r = HandleTableInsert(proc->kobj_handles, fresh, rights);
    if (!insert_r.has_value())
    {
        // Drop the selected reference. Only a genuine fresh initial-
        // owner mutex also carries a separate holder reference.
        if (registry_used_fresh)
            ReleaseFreshAfterFailure(type, fresh, init_state_or_owner);
        else
            KObjectRelease(fresh);
        frame->rax = kBadHandle;
        return;
    }
    // Insert adopts the create-time reference. NamedKObjectRegister
    // independently owns the registry reference.
    u64 public_handle = 0;
    if (!EncodePublicHandle(type, insert_r.value(), &public_handle))
    {
        if (registry_used_fresh && type == KObjectType::Mutex && init_state_or_owner != 0)
            KMutexRelease(reinterpret_cast<KMutex*>(fresh));
        (void)HandleTableRemove(proc->kobj_handles, insert_r.value());
        frame->rax = kBadHandle;
        return;
    }
    frame->rax = public_handle;
}

} // namespace duetos::subsystems::win32
