#include "subsystems/win32/file_syscall.h"

#include "subsystems/win32/custom.h"
#include "subsystems/win32/dir_syscall.h"
#include "subsystems/win32/registry.h"
#include "subsystems/win32/section.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "diag/kdbg.h"
#include "ipc/handle_table.h"
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
    // Returns a Win32 pseudo-handle (kWin32HandleBase + slot_idx)
    // on success or u64(-1) on any failure.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::CapSetHas(proc->caps, core::kCapFsRead))
    {
        const u64 pid = (proc != nullptr) ? proc->pid : 0;
        core::RecordSandboxDenial(core::kCapFsRead);
        if (proc != nullptr && core::ShouldLogDenial(proc->sandbox_denials))
        {
            arch::SerialWrite("[sys] denied syscall=SYS_FILE_OPEN pid=");
            arch::SerialWriteHex(pid);
            arch::SerialWrite(" cap=");
            arch::SerialWrite(core::CapName(core::kCapFsRead));
            arch::SerialWrite(" denial_idx=");
            arch::SerialWriteHex(proc->sandbox_denials);
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
    // Bounded staging buffer. Larger reads loop in the caller; the
    // 4 KiB chunk matches the page size, ramfs cap reads, and the
    // FAT32 cluster scratch's effective per-call ceiling.
    // Per-call on the kernel stack, NOT process-shared static: the
    // backing read can block/reschedule on the pipe and FAT32 paths,
    // so a file-scope buffer would let a concurrent ReadFile from
    // another process clobber the staged bytes before CopyToUser.
    constexpr u64 kStageBytes = 4096;
    if (cap_bytes > kStageBytes)
        cap_bytes = kStageBytes;
    u8 stage[kStageBytes];

    const u64 got = fs::routing::ReadForProcess(proc, handle, stage, cap_bytes);
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
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), stage, got))
    {
        // Already consumed `got` bytes from the handle's cursor —
        // refund is impossible without a backing-specific seek.
        // Surface the user-copy failure as -1 so the caller
        // doesn't think it received zeros.
        arch::SerialWrite("[sys] file_read CopyToUser FAIL pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite(" dst=");
        arch::SerialWriteHex(frame->rsi);
        arch::SerialWrite(" got=");
        arch::SerialWriteHex(got);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = got;
}

void DoFileClose(arch::TrapFrame* frame)
{
    KDBG_V(Win32Thunk, "win32/file", "DoFileClose handle", frame->rdi);
    // Generic Win32 CloseHandle. Dispatches by handle range:
    // file table (0x100..), mutex table (0x200..), event table
    // (0x300..). Out-of-range handles are a documented no-op.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = 0;
        return;
    }
    const u64 handle = frame->rdi;
    // Win32 custom: mark this handle as closed in the per-process
    // handle ledger. Anyone reading it later (via the ledger, not
    // via the actual handle table) sees `active=false` and the
    // generation count carries the use-after-close evidence.
    custom::OnHandleClose(proc, handle);
    if (handle >= core::Process::kWin32HandleBase &&
        handle < core::Process::kWin32HandleBase + core::Process::kWin32HandleCap)
    {
        fs::routing::CloseForProcess(proc, handle);
    }
    else if (handle >= core::Process::kWin32MutexBase &&
             handle < core::Process::kWin32MutexBase + core::Process::kWin32MutexCap)
    {
        // Migrated to KMutex + kobj_handles. The Win32 handle is
        // `kWin32MutexBase + ipc_handle`; map it back, type-check
        // (via lookup-with-ref so the storage stays alive across
        // the force-release below), and drop the table reference.
        // Closer-as-holder is force-released through KMutexRelease
        // first — that drains the recursion counter and hands the
        // lock off to the longest-waiting blocker if any (KMutex's
        // wait-time refs keep the storage alive for those waiters
        // until they wake).
        const ipc::Handle ipc_h = static_cast<ipc::Handle>(handle - core::Process::kWin32MutexBase);
        ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Mutex);
        if (obj != nullptr)
        {
            auto* m = reinterpret_cast<ipc::KMutex*>(obj);
            sched::Task* me = sched::CurrentTask();
            while (ipc::KMutexOwner(m) == me)
            {
                ipc::KMutexRelease(m);
            }
            (void)ipc::HandleTableRemove(proc->kobj_handles, ipc_h);
            ipc::KObjectRelease(obj); // drop the lookup ref
        }
    }
    else if (handle >= core::Process::kWin32EventBase &&
             handle < core::Process::kWin32EventBase + core::Process::kWin32EventCap)
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
        const ipc::Handle ipc_h = static_cast<ipc::Handle>(handle - core::Process::kWin32EventBase);
        ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Event);
        if (obj != nullptr)
        {
            (void)ipc::HandleTableRemove(proc->kobj_handles, ipc_h);
            ipc::KObjectRelease(obj); // drop the lookup ref
        }
    }
    else if (handle >= core::Process::kWin32SemaphoreBase &&
             handle < core::Process::kWin32SemaphoreBase + core::Process::kWin32SemaphoreCap)
    {
        // Migrated to KSemaphore + kobj_handles. Same shape as the
        // event arm above — type-check, drop the table reference,
        // KSemaphoreDestroy fires when the last reference clears.
        // (Pre-migration: this arm did not exist; CloseHandle
        // silently leaked the legacy Win32SemaphoreHandle slot.
        // Fixed incidentally by routing through the unified
        // handle table.)
        const ipc::Handle ipc_h = static_cast<ipc::Handle>(handle - core::Process::kWin32SemaphoreBase);
        ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Semaphore);
        if (obj != nullptr)
        {
            (void)ipc::HandleTableRemove(proc->kobj_handles, ipc_h);
            ipc::KObjectRelease(obj); // drop the lookup ref
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
    else if (handle >= core::Process::kWin32ProcessBase &&
             handle < core::Process::kWin32ProcessBase + core::Process::kWin32ProcessCap)
    {
        // Process handles drop the retained reference on the target.
        // ProcessRelease may free the target if no other holder
        // remains — which is the right Windows-shape semantics:
        // closing the last handle to a dead process actually
        // reaps it.
        const u64 slot = handle - core::Process::kWin32ProcessBase;
        core::Process::Win32ProcessHandle& h = proc->win32_proc_handles[slot];
        if (h.in_use)
        {
            core::Process* target = h.target;
            h.in_use = false;
            h.target = nullptr;
            core::ProcessRelease(target);
        }
    }
    else if (handle >= core::Process::kWin32ForeignThreadBase &&
             handle < core::Process::kWin32ForeignThreadBase + core::Process::kWin32ForeignThreadCap)
    {
        // Cross-process thread handles (NtOpenThread results)
        // pin a Task* + a refcount on its owning Process. Drop
        // the refcount on close. The Task* itself isn't reaped
        // here — that's the scheduler's job once the task hits
        // Dead and the reaper picks it up. Closing the last
        // foreign-thread handle on a dead task's owner Process
        // simply lets the Process get reaped per the same
        // contract as the win32_proc_handles arm above.
        const u64 slot = handle - core::Process::kWin32ForeignThreadBase;
        core::Process::Win32ForeignThreadHandle& h = proc->win32_foreign_threads[slot];
        if (h.in_use)
        {
            core::Process* owner = h.owner;
            h.in_use = false;
            h.task = nullptr;
            h.owner = nullptr;
            if (owner != nullptr)
            {
                core::ProcessRelease(owner);
            }
        }
    }
    else if (handle >= core::Process::kWin32DirBase &&
             handle < core::Process::kWin32DirBase + core::Process::kWin32DirCap)
    {
        // Directory iteration handles — drop the snapshot + clear
        // the slot. SysDirClose owns the KFree of the entries
        // array; safe on already-closed slots.
        win32::SysDirClose(proc, handle);
    }
    else if (handle >= core::Process::kWin32SectionBase &&
             handle < core::Process::kWin32SectionBase + core::Process::kWin32SectionCap)
    {
        // Section handles drop one section-pool refcount per
        // close. The pool entry frees its frames + slot only
        // when refcount hits 0 (every handle AND every active
        // mapping has gone away). If the caller forgot to
        // unmap the view, the mapping refcount stays — closing
        // the handle won't tear the view down. v0 GAP for
        // ranks-of-leaks tests.
        const u64 slot = handle - core::Process::kWin32SectionBase;
        core::Process::Win32SectionHandle& h = proc->win32_section_handles[slot];
        if (h.in_use)
        {
            const u32 pool_idx = h.pool_index;
            h.in_use = false;
            h.pool_index = 0;
            section::SectionRelease(pool_idx);
        }
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
    // Returns a Win32 pseudo-handle on success or u64(-1).
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
    if (proc == nullptr || !core::CapSetHas(proc->caps, core::kCapFsWrite))
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
