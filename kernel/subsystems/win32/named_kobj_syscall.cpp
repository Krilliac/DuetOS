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
        auto insert_r = HandleTableInsert(proc->kobj_handles, existing);
        if (!insert_r.has_value())
        {
            // Drop the Find-time refcount on insert failure.
            KObjectRelease(existing);
            frame->rax = kBadHandle;
            return;
        }
        // HandleTableInsert took its own refcount; drop the
        // Find-time one we held.
        KObjectRelease(existing);
        frame->rax = HandleBaseFor(type) + insert_r.value();
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
        KObjectRelease(fresh);
        frame->rax = kBadHandle;
        return;
    }
    auto insert_r = HandleTableInsert(proc->kobj_handles, fresh);
    if (!insert_r.has_value())
    {
        // Drop our create-time ref. The named-table still holds
        // its own ref so the kobject stays alive for future
        // openers; that's the documented behaviour.
        KObjectRelease(fresh);
        frame->rax = kBadHandle;
        return;
    }
    // HandleTableInsert took its own refcount; drop ours.
    KObjectRelease(fresh);
    frame->rax = HandleBaseFor(type) + insert_r.value();
}

} // namespace duetos::subsystems::win32
