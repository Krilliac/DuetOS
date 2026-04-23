#include "file_syscall.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/process.h"
#include "../../core/syscall.h"
#include "../../fs/ramfs.h"
#include "../../fs/vfs.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"

namespace customos::subsystems::win32
{

void DoFileOpen(arch::TrapFrame* frame)
{
    // Path-based open backed by VfsLookup. Returns a Win32 pseudo-
    // handle (kWin32HandleBase + slot_idx) on success or u64(-1)
    // on any failure. Cap-gated on kCapFsRead; per-handle cursor
    // lives on the Process struct.
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

    const fs::RamfsNode* n = fs::VfsLookup(proc->root, kpath, core::kSyscallPathMax);
    if (n == nullptr || n->type != fs::RamfsNodeType::kFile)
    {
        arch::SerialWrite("[sys] file_open miss pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" path=\"");
        arch::SerialWrite(kpath);
        arch::SerialWrite("\"\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Find a free slot.
    u64 slot = core::Process::kWin32HandleCap;
    for (u64 i = 0; i < core::Process::kWin32HandleCap; ++i)
    {
        if (proc->win32_handles[i].node == nullptr)
        {
            slot = i;
            break;
        }
    }
    if (slot == core::Process::kWin32HandleCap)
    {
        arch::SerialWrite("[sys] file_open out-of-handles pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    proc->win32_handles[slot].node = n;
    proc->win32_handles[slot].cursor = 0;
    const u64 handle = core::Process::kWin32HandleBase + slot;
    arch::SerialWrite("[sys] file_open ok pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" path=\"");
    arch::SerialWrite(kpath);
    arch::SerialWrite("\" handle=");
    arch::SerialWriteHex(handle);
    arch::SerialWrite(" size=");
    arch::SerialWriteHex(n->file_size);
    arch::SerialWrite("\n");
    frame->rax = handle;
}

void DoFileRead(arch::TrapFrame* frame)
{
    // Read up to rdx bytes from the handle into rsi. Returns
    // bytes copied (0 at EOF) or -1 on bad handle / bad user ptr.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    if (handle < core::Process::kWin32HandleBase ||
        handle >= core::Process::kWin32HandleBase + core::Process::kWin32HandleCap)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 slot = handle - core::Process::kWin32HandleBase;
    core::Process::Win32FileHandle& h = proc->win32_handles[slot];
    if (h.node == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 cap_bytes = frame->rdx;
    if (cap_bytes == 0)
    {
        frame->rax = 0;
        return;
    }
    if (h.cursor >= h.node->file_size)
    {
        frame->rax = 0; // EOF
        return;
    }
    const u64 remaining = h.node->file_size - h.cursor;
    const u64 to_copy = (cap_bytes < remaining) ? cap_bytes : remaining;
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), h.node->file_bytes + h.cursor, to_copy))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    h.cursor += to_copy;
    frame->rax = to_copy;
}

void DoFileClose(arch::TrapFrame* frame)
{
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
        const u64 slot = handle - core::Process::kWin32HandleBase;
        proc->win32_handles[slot].node = nullptr;
        proc->win32_handles[slot].cursor = 0;
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
    // SET / CUR / END seeking with clamp to [0, file_size].
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    if (handle < core::Process::kWin32HandleBase ||
        handle >= core::Process::kWin32HandleBase + core::Process::kWin32HandleCap)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 slot = handle - core::Process::kWin32HandleBase;
    core::Process::Win32FileHandle& h = proc->win32_handles[slot];
    if (h.node == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const i64 offset = static_cast<i64>(frame->rsi);
    const u64 whence = frame->rdx;
    i64 base;
    switch (whence)
    {
    case 0:
        base = 0;
        break;
    case 1:
        base = static_cast<i64>(h.cursor);
        break;
    case 2:
        base = static_cast<i64>(h.node->file_size);
        break;
    default:
        frame->rax = static_cast<u64>(-1);
        return;
    }
    i64 newpos = base + offset;
    if (newpos < 0)
        newpos = 0;
    if (static_cast<u64>(newpos) > h.node->file_size)
        newpos = static_cast<i64>(h.node->file_size);
    h.cursor = static_cast<u64>(newpos);
    frame->rax = h.cursor;
}

void DoFileFstat(arch::TrapFrame* frame)
{
    // Non-destructive size query for an open Win32 handle.
    // GetFileSizeEx maps here directly.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 handle = frame->rdi;
    if (handle < core::Process::kWin32HandleBase ||
        handle >= core::Process::kWin32HandleBase + core::Process::kWin32HandleCap)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 slot = handle - core::Process::kWin32HandleBase;
    const core::Process::Win32FileHandle& h = proc->win32_handles[slot];
    if (h.node == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const u64 size = h.node->file_size;
    if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), &size, sizeof(size)))
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    frame->rax = 0;
}

} // namespace customos::subsystems::win32
