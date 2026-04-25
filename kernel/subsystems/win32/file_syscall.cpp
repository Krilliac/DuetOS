#include "file_syscall.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/kdbg.h"
#include "../../core/process.h"
#include "../../core/syscall.h"
#include "../../fs/file_route.h"
#include "../../fs/ramfs.h"
#include "../../fs/vfs.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"

namespace duetos::subsystems::win32
{

void DoFileOpen(arch::TrapFrame* frame)
{
    KDBG_2V(Win32Thunk, "win32/file", "DoFileOpen", "user_path", frame->rdi, "path_cap", frame->rsi);
    // Path-based open. Routing (ramfs vs fat32 by /disk/<idx>/
    // prefix) lives in fs::routing — this layer only does the
    // syscall-context work (cap check, CopyFromUser, rax wiring).
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
    if (!mm::CopyFromUser(kpath, reinterpret_cast<const void*>(frame->rdi), path_cap))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    kpath[path_cap] = '\0';
    kpath[core::kSyscallPathMax - 1] = '\0';

    frame->rax = fs::routing::OpenForProcess(proc, kpath);
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
    constexpr u64 kStageBytes = 4096;
    if (cap_bytes > kStageBytes)
        cap_bytes = kStageBytes;
    static u8 s_stage[kStageBytes];

    const u64 got = fs::routing::ReadForProcess(proc, handle, s_stage, cap_bytes);
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
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), s_stage, got))
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
    if (handle >= core::Process::kWin32HandleBase &&
        handle < core::Process::kWin32HandleBase + core::Process::kWin32HandleCap)
    {
        fs::routing::CloseForProcess(proc, handle);
    }
    else if (handle >= core::Process::kWin32MutexBase &&
             handle < core::Process::kWin32MutexBase + core::Process::kWin32MutexCap)
    {
        const u64 slot = handle - core::Process::kWin32MutexBase;
        arch::Cli();
        core::Process::Win32MutexHandle& m = proc->win32_mutexes[slot];
        // Abandoned-mutex: hand off to the next waiter if any.
        sched::Task* next = sched::WaitQueueWakeOne(&m.waiters);
        m.owner = next;
        m.recursion = (next != nullptr) ? 1 : 0;
        m.in_use = false;
        arch::Sti();
    }
    else if (handle >= core::Process::kWin32EventBase &&
             handle < core::Process::kWin32EventBase + core::Process::kWin32EventCap)
    {
        const u64 slot = handle - core::Process::kWin32EventBase;
        arch::Cli();
        core::Process::Win32EventHandle& e = proc->win32_events[slot];
        (void)sched::WaitQueueWakeAll(&e.waiters);
        e.in_use = false;
        e.signaled = false;
        arch::Sti();
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
    // current cursor. Cap-gated on kCapFsWrite. Backing dispatch
    // (ramfs refused; fat32 in-place) lives in fs::routing.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::CapSetHas(proc->caps, core::kCapFsWrite))
    {
        const u64 pid = (proc != nullptr) ? proc->pid : 0;
        core::RecordSandboxDenial(core::kCapFsWrite);
        if (proc != nullptr && core::ShouldLogDenial(proc->sandbox_denials))
        {
            arch::SerialWrite("[sys] denied syscall=SYS_FILE_WRITE pid=");
            arch::SerialWriteHex(pid);
            arch::SerialWrite(" cap=");
            arch::SerialWrite(core::CapName(core::kCapFsWrite));
            arch::SerialWrite("\n");
        }
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
    constexpr u64 kStageBytes = 4096;
    if (cap_bytes > kStageBytes)
        cap_bytes = kStageBytes;
    static u8 s_stage[kStageBytes];
    if (!mm::CopyFromUser(s_stage, reinterpret_cast<const void*>(frame->rsi), cap_bytes))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 wrote = fs::routing::WriteForProcess(proc, handle, s_stage, cap_bytes);
    frame->rax = wrote;
}

void DoFileCreate(arch::TrapFrame* frame)
{
    // CreateFileW(CREATE_NEW). rdi = path, rsi = path_cap,
    // rdx = init bytes (user pointer, may be 0), r10 = init len.
    // Returns a Win32 pseudo-handle on success or u64(-1).
    // Cap-gated on kCapFsWrite (the cap also implies create
    // privilege — splitting create into its own cap would just
    // bloat the sandbox profile without buying anything today).
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::CapSetHas(proc->caps, core::kCapFsWrite))
    {
        const u64 pid = (proc != nullptr) ? proc->pid : 0;
        core::RecordSandboxDenial(core::kCapFsWrite);
        if (proc != nullptr && core::ShouldLogDenial(proc->sandbox_denials))
        {
            arch::SerialWrite("[sys] denied syscall=SYS_FILE_CREATE pid=");
            arch::SerialWriteHex(pid);
            arch::SerialWrite(" cap=");
            arch::SerialWrite(core::CapName(core::kCapFsWrite));
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
    if (!mm::CopyFromUser(kpath, reinterpret_cast<const void*>(frame->rdi), path_cap))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    kpath[path_cap] = '\0';
    kpath[core::kSyscallPathMax - 1] = '\0';

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
    static u8 s_init_stage[kStageBytes];
    if (init_len > 0)
    {
        if (frame->rdx == 0)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        if (!mm::CopyFromUser(s_init_stage, reinterpret_cast<const void*>(frame->rdx), init_len))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
    }

    frame->rax = fs::routing::CreateForProcess(proc, kpath, init_len > 0 ? s_init_stage : nullptr, init_len);
}

} // namespace duetos::subsystems::win32
