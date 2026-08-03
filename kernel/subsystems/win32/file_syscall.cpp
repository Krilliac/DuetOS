#include "subsystems/win32/file_syscall.h"

#include "subsystems/win32/custom.h"
#include "subsystems/win32/dir_syscall.h"
#include "subsystems/win32/job_syscall.h"
#include "subsystems/win32/registry.h"
#include "subsystems/win32/section.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "core/service_directory.h"
#include "core/service_runtime.h"
#include "diag/kdbg.h"
#include "ipc/handle_table.h"
#include "ipc/iocp.h"
#include "ipc/kevent.h"
#include "ipc/kmutex.h"
#include "ipc/kobject.h"
#include "ipc/ksemaphore.h"
#include "proc/process.h"
#include "syscall/syscall.h"
#include "fs/file_route.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "mm/paging.h"
#include "sched/sched.h"

namespace duetos::subsystems::win32
{

void DoFileOpen(arch::TrapFrame* frame)
{
    KDBG_2V(Win32Thunk, "win32/file", "DoFileOpen", "user_path", frame->rdi, "path_cap", frame->rsi);
    // Path-based open. Routing (ramfs vs fat32 by /disk/<idx>/
    // prefix) lives in fs::routing — this layer only does the
    // syscall-context work (cap check, user-string copy, rax wiring).
    // Returns an opaque positive generation-tagged file handle on success or
    // u64(-1) on any failure.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::ProcessHasCap(proc, core::kCapFsRead))
    {
        const u64 pid = (proc != nullptr) ? proc->pid : 0;
        const u64 denial_index = core::RecordSandboxDenial(core::kCapFsRead);
        if (proc != nullptr && core::ShouldLogDenial(denial_index))
        {
            arch::SerialWrite("[sys] denied syscall=SYS_FILE_OPEN pid=");
            arch::SerialWriteHex(pid);
            arch::SerialWrite(" cap=");
            arch::SerialWrite(core::CapName(core::kCapFsRead));
            arch::SerialWrite(" denial_idx=");
            arch::SerialWriteHex(denial_index);
            arch::SerialWrite("\n");
        }
        frame->rax = static_cast<u64>(-1);
        return;
    }

    u64 path_cap = frame->rsi;
    if (path_cap >= core::kSyscallPathMax)
        path_cap = core::kSyscallPathMax - 1;
    if (path_cap == 0)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    char kpath[core::kSyscallPathMax];
    if (!mm::CopyUserCString(kpath, path_cap + 1, reinterpret_cast<const void*>(frame->rdi)).ok())
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u64 handle = fs::routing::OpenForProcess(proc, kpath);
    if (handle != static_cast<u64>(-1) && handle != 0)
        custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_FILE_OPEN), frame->rip);
    frame->rax = handle;
}

void DoFileRead(arch::TrapFrame* frame)
{
    KDBG_3V(Win32Thunk, "win32/file", "DoFileRead", "handle", frame->rdi, "buf", frame->rsi, "count", frame->rdx);
    // Read up to rdx bytes from the handle into rsi. Returns
    // bytes copied (0 at EOF) or u64(-1) on bad handle / bad user
    // ptr. Backing dispatch (ramfs direct copy vs fat32 cluster
    // walk) lives in fs::routing; we stage into a kernel buffer
    // and CopyToUser the result.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    u64 cap_bytes = frame->rdx;
    if (cap_bytes == 0)
    {
        frame->rax = 0;
        return;
    }
    // The routing layer owns the per-call staging buffer and the complete
    // snapshot -> backing read -> user delivery -> exact cursor commit
    // transaction while the handle slot operation guard remains held.
    constexpr u64 kStageBytes = 4096;
    if (cap_bytes > kStageBytes)
        cap_bytes = kStageBytes;

    const u64 got = fs::routing::ReadToUserForProcess(proc, handle, reinterpret_cast<void*>(frame->rsi), cap_bytes);
    if (got == u64(-1))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    if (got == 0)
    {
        frame->rax = 0;
        return;
    }
    frame->rax = got;
}

void DoFileClose(arch::TrapFrame* frame)
{
    KDBG_V(Win32Thunk, "win32/file", "DoFileClose handle", frame->rdi);
    // Generic Win32 CloseHandle. Every migrated KObject class uses a
    // generation-tagged opaque handle; malformed or stale handles are a
    // documented no-op.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 handle = frame->rdi;
    ipc::Handle mutex_ipc_h = ipc::kHandleInvalid;
    ipc::Handle event_ipc_h = ipc::kHandleInvalid;
    ipc::Handle semaphore_ipc_h = ipc::kHandleInvalid;
    ipc::Handle iocp_ipc_h = ipc::kHandleInvalid;
    const bool is_mutex = ipc::HandleDecodeTagged(handle, core::Process::kWin32MutexBase, &mutex_ipc_h);
    const bool is_event = ipc::HandleDecodeTagged(handle, core::Process::kWin32EventBase, &event_ipc_h);
    const bool is_semaphore = ipc::HandleDecodeTagged(handle, core::Process::kWin32SemaphoreBase, &semaphore_ipc_h);
    const bool is_iocp = ipc::HandleDecodeTagged(handle, core::Process::kWin32IocpBase, &iocp_ipc_h);

    // Service endpoints use the HandleTable's raw generation-bearing ABI, not
    // one of the Win32 low-tag bands. Only an exact live endpoint carrying the
    // Destroy right enters this path; malformed, stale, wrong-type, and
    // rights-narrowed values retain the existing CloseHandle no-op policy.
    ipc::Handle service_endpoint_ipc_h = ipc::kHandleInvalid;
    if (handle <= ipc::kHandlePositiveMax)
    {
        service_endpoint_ipc_h = static_cast<ipc::Handle>(handle);
        if (ipc::HandleDecode(service_endpoint_ipc_h, nullptr, nullptr))
        {
            ipc::KObject* endpoint_object =
                ipc::HandleTableLookupRef(proc->kobj_handles, service_endpoint_ipc_h, ipc::KObjectType::ServiceEndpoint,
                                          ipc::kHandleRightDestroy);
            if (endpoint_object != nullptr)
            {
                const core::ProcessKey caller_process = core::ProcessKeySnapshot(proc);
                core::ServiceRuntimeV1* runtime = core::ServiceRuntimeKernelV1();
                if (runtime == nullptr)
                {
                    ipc::KObjectRelease(endpoint_object);
                    frame->rax = static_cast<u64>(-1);
                    return;
                }

                // Accepted server ownership must drain before the table can
                // hide its exact handle. NotFound is the expected client-side
                // case; every other failure leaves the live handle available
                // for a truthful retry.
                const core::ServiceDirectoryReleaseAcceptedResult accepted_release =
                    core::ServiceDirectoryReleaseAcceptedHandle(&runtime->directory, caller_process,
                                                                service_endpoint_ipc_h);
                if (accepted_release.status != core::ServiceDirectoryStatus::Ok &&
                    accepted_release.status != core::ServiceDirectoryStatus::NotFound)
                {
                    ipc::KObjectRelease(endpoint_object);
                    frame->rax = static_cast<u64>(-1);
                    return;
                }

                auto detached = ipc::HandleTableDetach(proc->kobj_handles, service_endpoint_ipc_h,
                                                       ipc::KObjectType::ServiceEndpoint, ipc::kHandleRightDestroy);
                if (!detached.has_value())
                {
                    ipc::KObjectRelease(endpoint_object);
                    frame->rax = static_cast<u64>(-1);
                    return;
                }

                // Both calls above have dropped their locks. Release the
                // retained recognition reference and transferred table owner
                // only after the full directory/table transaction completes.
                ipc::KObjectRelease(endpoint_object);
                ipc::KObjectRelease(detached.value());
                custom::OnHandleClose(proc, handle);
                frame->rax = 0;
                return;
            }
        }
    }

    // Win32 custom: mark this handle as closed in the per-process
    // handle ledger. Anyone reading it later (via the ledger, not
    // via the actual handle table) sees `active=false` and the
    // generation count carries the use-after-close evidence.
    custom::OnHandleClose(proc, handle);
    // IsWin32FileHandle recognizes Process::kWin32HandleBase as the low-tag
    // band while rejecting generation-zero and stale-width encodings.
    if (core::IsWin32FileHandle(handle))
    {
        fs::routing::CloseForProcess(proc, handle);
    }
    else if (is_mutex)
    {
        // Detach transfers the table's reference only when the type,
        // generation, and Destroy right all still match. Closing a handle is
        // not thread ownership release: the holder reference keeps the object
        // alive, and Task teardown publishes abandonment if the owner exits.
        auto detached =
            ipc::HandleTableDetach(proc->kobj_handles, mutex_ipc_h, ipc::KObjectType::Mutex, ipc::kHandleRightDestroy);
        if (detached.has_value())
        {
            ipc::KObjectRelease(detached.value()); // drop transferred table reference
        }
    }
    else if (is_event)
    {
        // Migrated to KEvent + kobj_handles. Map the Win32 handle
        // back to its ipc::Handle slot, type-check via lookup-with-
        // ref so the storage stays alive across the table remove
        // below, then drop the table reference. Any waiters still
        // blocked on the KEvent's condvar carry their own implicit
        // reference (see KEventDestroy comment in kevent.cpp);
        // closing the last handle while a waiter is queued is the
        // future-audit edge documented there, not a regression
        // introduced by this slice.
        auto detached =
            ipc::HandleTableDetach(proc->kobj_handles, event_ipc_h, ipc::KObjectType::Event, ipc::kHandleRightDestroy);
        if (detached.has_value())
        {
            ipc::KObjectRelease(detached.value());
        }
    }
    else if (is_semaphore)
    {
        // Migrated to KSemaphore + kobj_handles. Same shape as the
        // event arm above — type-check, drop the table reference,
        // KSemaphoreDestroy fires when the last reference clears.
        // (Pre-migration: this arm did not exist; CloseHandle
        // silently leaked the legacy Win32SemaphoreHandle slot.
        // Fixed incidentally by routing through the unified
        // handle table.)
        auto detached = ipc::HandleTableDetach(proc->kobj_handles, semaphore_ipc_h, ipc::KObjectType::Semaphore,
                                               ipc::kHandleRightDestroy);
        if (detached.has_value())
        {
            ipc::KObjectRelease(detached.value());
        }
    }
    else if (is_iocp)
    {
        // Migrated to IocpPort + kobj_handles. Same shape as the
        // event / semaphore arms, plus an explicit IocpClose BEFORE
        // the table remove: a consumer parked inside IocpWait holds
        // its own lookup reference, so the destroy callback would
        // never fire while it sleeps — the explicit close-broadcast
        // is what wakes it (it then observes `closed` and returns
        // STATUS_ABANDONED-shaped failure to user mode).
        // (Pre-migration: this arm did not exist; NtClose on an
        // IOCP handle silently leaked the legacy pool slot. Fixed
        // incidentally by routing through the unified handle table.)
        auto detached =
            ipc::HandleTableDetach(proc->kobj_handles, iocp_ipc_h, ipc::KObjectType::Iocp, ipc::kHandleRightDestroy);
        if (detached.has_value())
        {
            ipc::KObject* obj = detached.value();
            ipc::IocpClose(reinterpret_cast<ipc::IocpPort*>(obj));
            ipc::KObjectRelease(obj); // drop transferred table reference
        }
    }
    else if (handle >= core::Process::kWin32RegistryBase &&
             handle < core::Process::kWin32RegistryBase + core::Process::kWin32RegistryCap)
    {
        // Registry handles share the CloseHandle / NtClose entry
        // point with file / mutex / event handles. The registry
        // module owns the per-slot bookkeeping, so route through
        // it rather than poking the table directly here.
        (void)registry::ReleaseHandleForCurrentProcess(handle);
    }
    else if (core::IsWin32ProcessHandle(handle))
    {
        // Process handles drop the retained reference on the target.
        // ProcessRelease may free the target if no other holder
        // remains — which is the right Windows-shape semantics:
        // closing the last handle to a dead process actually
        // reaps it.
        (void)core::ProcessCloseWin32ProcessHandle(proc, handle);
    }
    else if (handle >= core::Process::kWin32ThreadBase &&
             handle < core::Process::kWin32ThreadBase + core::Process::kWin32ThreadCap)
    {
        // Local CreateThread handles are metadata references, not
        // ownership of the scheduler Task itself: closing a live
        // handle must hide the handle without terminating the
        // thread. Reclaim the table slot only when the task exits.
        // Serialize against SYS_EXIT publication and the next
        // CreateThread claim so an old task can never publish its
        // exit code into a newly-reused slot. A row in `creating`
        // state is not yet a caller-visible handle, so a guessed
        // close cannot steal the creator's reservation.
        const u64 slot = handle - core::Process::kWin32ThreadBase;
        const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_thread_lock);
        auto& h = proc->win32_threads[slot];
        if (h.in_use && h.handle_open && !h.creating)
        {
            h.handle_open = false;
            if (h.exited)
            {
                // The task no longer needs its fixed per-slot
                // TEB/static-TLS pages. Only now is reuse safe.
                h.in_use = false;
                h.exited = false;
                h.exit_code = 0x103;
                h.tid = 0;
                h.user_stack_va = 0;
            }
        }
        sync::SpinLockRelease(proc->win32_thread_lock, flags);
    }
    else if (handle >= core::Process::kWin32ForeignThreadBase &&
             handle < core::Process::kWin32ForeignThreadBase + core::Process::kWin32ForeignThreadCap)
    {
        // Cross-process thread handles store only an immutable
        // scheduler TID. Serialize close against OpenThread and
        // every lookup snapshot; no Task or Process ownership is
        // carried by the row.
        const u64 slot = handle - core::Process::kWin32ForeignThreadBase;
        const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_thread_lock);
        auto& h = proc->win32_foreign_threads[slot];
        if (h.in_use)
        {
            h.in_use = false;
            h.tid = 0;
        }
        sync::SpinLockRelease(proc->win32_thread_lock, flags);
    }
    else if (handle >= core::Process::kWin32DirBase &&
             handle < core::Process::kWin32DirBase + core::Process::kWin32DirCap)
    {
        // Directory iteration handles — drop the snapshot + clear
        // the slot. SysDirClose owns the KFree of the entries
        // array; safe on already-closed slots.
        win32::SysDirClose(proc, handle);
    }
    else if (core::IsWin32SectionHandle(handle))
    {
        // Process::kWin32SectionBase remains the low 0x900..0x907 tag, while
        // the public value also carries a process-row generation. Detach the
        // exact identity under the process Section lock, then release the
        // generation-keyed pool reference with no process lock held. Closing
        // the handle deliberately leaves mapped views alive.
        section::SectionKey key{};
        if (core::ProcessDetachWin32SectionHandle(proc, handle, &key))
        {
            section::SectionRelease(key);
        }
    }
    else if (handle >= kJobHandleBase && IsJobHandle(handle))
    {
        // Job-object handles — route to SysJobClose which drops
        // the Job row's open reference. Membership consists only of immutable
        // ProcessKey completion records, so close cannot release ProcessCore.
        win32::SysJobClose(handle);
    }
    frame->rax = 0;
}

void DoFileSeek(arch::TrapFrame* frame)
{
    KDBG_3V(Win32Thunk, "win32/file", "DoFileSeek", "handle", frame->rdi, "offset", frame->rsi, "whence", frame->rdx);
    // SET / CUR / END seeking with clamp to [0, file_size].
    // Dispatch by handle kind lives in fs::routing.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    const i64 offset = static_cast<i64>(frame->rsi);
    const u64 whence = frame->rdx;
    frame->rax = fs::routing::SeekForProcess(proc, handle, offset, static_cast<u32>(whence));
}

void DoFileFstat(arch::TrapFrame* frame)
{
    KDBG_2V(Win32Thunk, "win32/file", "DoFileFstat", "handle", frame->rdi, "out_buf", frame->rsi);
    // Non-destructive size query for an open Win32 handle.
    // GetFileSizeEx maps here directly.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    u64 size = 0;
    if (fs::routing::FstatForProcess(proc, handle, &size) != 0)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), &size, sizeof(size)))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
}

void DoFileWrite(arch::TrapFrame* frame)
{
    KDBG_3V(Win32Thunk, "win32/file", "DoFileWrite", "handle", frame->rdi, "buf", frame->rsi, "count", frame->rdx);
    // Write up to rdx bytes from rsi into the handle at its
    // current cursor. kCapFsWrite is gated centrally by
    // `SyscallGate` (cap_table.def). Backing dispatch (ramfs
    // refused; fat32 in-place) lives in fs::routing.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    u64 cap_bytes = frame->rdx;
    if (cap_bytes == 0)
    {
        frame->rax = 0;
        return;
    }
    // Per-call on the kernel stack, NOT process-shared static —
    // see DoFileRead: the FS write can block, so a shared buffer
    // would let a concurrent WriteFile from another process inject
    // its bytes between CopyFromUser and WriteForProcess.
    constexpr u64 kStageBytes = 4096;
    if (cap_bytes > kStageBytes)
        cap_bytes = kStageBytes;
    u8 stage[kStageBytes];
    if (!mm::CopyFromUser(stage, reinterpret_cast<const void*>(frame->rsi), cap_bytes))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 wrote = fs::routing::WriteForProcess(proc, handle, stage, cap_bytes);
    frame->rax = wrote;
}

void DoFileCreate(arch::TrapFrame* frame)
{
    // CreateFileW(CREATE_NEW). rdi = path, rsi = path_cap,
    // rdx = init bytes (user pointer, may be 0), r10 = init len.
    // Returns an opaque positive generation-tagged handle or u64(-1).
    // kCapFsWrite (which also implies create privilege; splitting
    // create into its own cap would just bloat the sandbox profile
    // without buying anything today) is gated centrally by
    // `SyscallGate` (cap_table.def).
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    u64 path_cap = frame->rsi;
    if (path_cap >= core::kSyscallPathMax)
        path_cap = core::kSyscallPathMax - 1;
    if (path_cap == 0)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    char kpath[core::kSyscallPathMax];
    if (!mm::CopyUserCString(kpath, path_cap + 1, reinterpret_cast<const void*>(frame->rdi)).ok())
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Initial-content payload — optional, capped at 4 KiB for
    // the same staging-buffer reasons as DoFileWrite. Larger
    // initial files would loop SYS_FILE_WRITE after create.
    u64 init_len = frame->r10;
    constexpr u64 kStageBytes = 4096;
    if (init_len > kStageBytes)
    {
        // Reject rather than silently truncate — a Win32 caller
        // expecting a 100 KiB file from a single CreateFile would
        // be surprised to find a 4 KiB stub. The create + N
        // SYS_FILE_WRITE calls path keeps semantics honest.
        frame->rax = static_cast<u64>(-1);
        return;
    }
    // Per-call on the kernel stack, NOT process-shared static —
    // see DoFileRead: CreateForProcess can block, so a shared
    // buffer would let a concurrent CreateFile substitute another
    // process's initial-content payload.
    u8 init_stage[kStageBytes];
    if (init_len > 0)
    {
        if (frame->rdx == 0)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        if (!mm::CopyFromUser(init_stage, reinterpret_cast<const void*>(frame->rdx), init_len))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
    }

    frame->rax = fs::routing::CreateForProcess(proc, kpath, init_len > 0 ? init_stage : nullptr, init_len);
}

void DoFileUnlink(arch::TrapFrame* frame)
{
    // DeleteFileW. rdi = const char* user_path, rsi = path_cap.
    // rax = 0 on success, NTSTATUS on failure.
    KDBG_2V(Win32Thunk, "win32/file", "DoFileUnlink", "user_path", frame->rdi, "path_cap", frame->rsi);
    constexpr u64 kStatusSuccess = 0;
    constexpr u64 kStatusInvalidParameter = 0xC000000DULL;
    constexpr u64 kStatusAccessDenied = 0xC0000022ULL;
    constexpr u64 kStatusObjectNameNotFound = 0xC0000034ULL;
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::ProcessHasCap(proc, core::kCapFsWrite))
    {
        core::RecordSandboxDenial(core::kCapFsWrite);
        frame->rax = kStatusAccessDenied;
        return;
    }
    u64 path_cap = frame->rsi;
    if (path_cap == 0 || path_cap >= core::kSyscallPathMax)
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    char kpath[core::kSyscallPathMax];
    if (!mm::CopyUserCString(kpath, path_cap + 1, reinterpret_cast<const void*>(frame->rdi)).ok())
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    if (!fs::routing::UnlinkForProcess(proc, kpath))
    {
        frame->rax = kStatusObjectNameNotFound;
        return;
    }
    frame->rax = kStatusSuccess;
}

void DoFileRename(arch::TrapFrame* frame)
{
    // MoveFileW. rdi = src_path, rsi = src_cap,
    // rdx = dst_path, r10 = dst_cap. kCapFsWrite is gated centrally
    // by `SyscallGate` (cap_table.def).
    KDBG_2V(Win32Thunk, "win32/file", "DoFileRename", "user_src", frame->rdi, "user_dst", frame->rdx);
    constexpr u64 kStatusSuccess = 0;
    constexpr u64 kStatusInvalidParameter = 0xC000000DULL;
    constexpr u64 kStatusAccessDenied = 0xC0000022ULL;
    constexpr u64 kStatusObjectNameCollision = 0xC0000035ULL;
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = kStatusAccessDenied;
        return;
    }
    u64 src_cap = frame->rsi;
    u64 dst_cap = frame->r10;
    if (src_cap == 0 || dst_cap == 0 || src_cap >= core::kSyscallPathMax || dst_cap >= core::kSyscallPathMax)
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    char ksrc[core::kSyscallPathMax];
    char kdst[core::kSyscallPathMax];
    if (!mm::CopyUserCString(ksrc, src_cap + 1, reinterpret_cast<const void*>(frame->rdi)).ok() ||
        !mm::CopyUserCString(kdst, dst_cap + 1, reinterpret_cast<const void*>(frame->rdx)).ok())
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    if (!fs::routing::RenameForProcess(proc, ksrc, kdst))
    {
        // Rename failure could be missing src OR existing dst;
        // we don't disambiguate in v0. Pick the more common
        // misuse (collision) for a simple caller signal.
        frame->rax = kStatusObjectNameCollision;
        return;
    }
    frame->rax = kStatusSuccess;
}

namespace
{
constexpr u64 kStatusSuccess = 0;
constexpr u64 kStatusInvalidParameter = 0xC000000DULL;
constexpr u64 kStatusObjectNameCollision = 0xC0000035ULL;

bool CopyPathArg(arch::TrapFrame* frame, u64 user_ptr, u64 path_cap, char* dst)
{
    (void)frame;
    if (path_cap == 0 || path_cap >= core::kSyscallPathMax)
        return false;
    return mm::CopyUserCString(dst, path_cap + 1, reinterpret_cast<const void*>(user_ptr)).ok();
}
} // namespace

void DoFileMkdir(arch::TrapFrame* frame)
{
    // rdi = user path, rsi = path_cap (excluding NUL).
    KDBG_2V(Win32Thunk, "win32/file", "DoFileMkdir", "user_path", frame->rdi, "path_cap", frame->rsi);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    char kpath[core::kSyscallPathMax];
    if (!CopyPathArg(frame, frame->rdi, frame->rsi, kpath))
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    frame->rax = fs::routing::MkdirForProcess(proc, kpath) ? kStatusSuccess : kStatusObjectNameCollision;
}

void DoFileSymlink(arch::TrapFrame* frame)
{
    // rdi = symlink path, rsi = path_cap, rdx = target, r10 = target_cap.
    KDBG_2V(Win32Thunk, "win32/file", "DoFileSymlink", "user_path", frame->rdi, "user_target", frame->rdx);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    char kpath[core::kSyscallPathMax];
    char ktarget[core::kSyscallPathMax];
    if (!CopyPathArg(frame, frame->rdi, frame->rsi, kpath) || !CopyPathArg(frame, frame->rdx, frame->r10, ktarget))
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    frame->rax = fs::routing::SymlinkForProcess(proc, kpath, ktarget) ? kStatusSuccess : kStatusObjectNameCollision;
}

void DoFileLink(arch::TrapFrame* frame)
{
    // rdi = existing path, rsi = path_cap, rdx = new path, r10 = new path cap.
    KDBG_2V(Win32Thunk, "win32/file", "DoFileLink", "user_existing", frame->rdi, "user_new", frame->rdx);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    char kex[core::kSyscallPathMax];
    char knew[core::kSyscallPathMax];
    if (!CopyPathArg(frame, frame->rdi, frame->rsi, kex) || !CopyPathArg(frame, frame->rdx, frame->r10, knew))
    {
        frame->rax = kStatusInvalidParameter;
        return;
    }
    frame->rax = fs::routing::LinkForProcess(proc, kex, knew) ? kStatusSuccess : kStatusObjectNameCollision;
}

void DoFileReadlink(arch::TrapFrame* frame)
{
    // rdi = path, rsi = path_cap, rdx = user u8* dst, r10 = dst_max.
    KDBG_2V(Win32Thunk, "win32/file", "DoFileReadlink", "user_path", frame->rdi, "user_dst", frame->rdx);
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    char kpath[core::kSyscallPathMax];
    if (!CopyPathArg(frame, frame->rdi, frame->rsi, kpath))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 dst_max = frame->r10;
    if (dst_max == 0 || dst_max >= core::kSyscallPathMax)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    char kdst[core::kSyscallPathMax];
    const u64 copied = fs::routing::ReadlinkForProcess(proc, kpath, kdst, dst_max);
    if (copied == static_cast<u64>(-1))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rdx), kdst, copied + 1))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = copied;
}

} // namespace duetos::subsystems::win32
