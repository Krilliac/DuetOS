/*
 * SYS_WIN32_CREATE_PIPE — Win32 CreatePipe backed by the
 * cross-process pipe pool. See pipe_syscall.h for the contract.
 */

#include "subsystems/win32/pipe_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "subsystems/linux/syscall_pipe.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u64 kBadResult = static_cast<u64>(-1);

// Find a free Win32FileHandle slot. Returns the slot index or
// kWin32HandleCap if the table is full.
u64 FindFreeSlot(::duetos::core::Process* proc)
{
    using ::duetos::core::Process;
    for (u64 i = 0; i < Process::kWin32HandleCap; ++i)
    {
        if (proc->win32_handles[i].kind == Process::FsBackingKind::None)
            return i;
    }
    return Process::kWin32HandleCap;
}

void StampPipeEnd(::duetos::core::Process::Win32FileHandle& h, u32 pool_idx, bool is_write_end)
{
    using ::duetos::core::Process;
    h.kind = Process::FsBackingKind::Pipe;
    h.ramfs_node = nullptr;
    h.fat32_volume_idx = 0;
    h.duetfs_block_handle = 0;
    h.duetfs_node_id = 0;
    h.duetfs_size_bytes = 0;
    h.cursor = 0;
    h.is_canary = false;
    h.fat32_path[0] = '\0';
    h.pipe_pool_idx = pool_idx;
    h.pipe_is_write_end = is_write_end;
    // Anonymous pipes don't sit in the named-pipe registry.
    h.named_pipe_registry_slot = -1;
}

} // namespace

void DoWin32CreatePipe(arch::TrapFrame* frame)
{
    using ::duetos::core::Process;

    Process* proc = ::duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = kBadResult;
        return;
    }

    const u64 user_read = frame->rdi;
    const u64 user_write = frame->rsi;
    if (user_read == 0 || user_write == 0)
    {
        frame->rax = kBadResult;
        return;
    }

    // Reserve two file-handle slots BEFORE allocating the pool
    // entry so a pool-leak can't happen on table-full failure.
    const u64 read_slot = FindFreeSlot(proc);
    if (read_slot == Process::kWin32HandleCap)
    {
        frame->rax = kBadResult;
        return;
    }
    // Tentatively mark the read slot busy so FindFreeSlot's next
    // call returns a different one.
    proc->win32_handles[read_slot].kind = Process::FsBackingKind::Pipe;
    const u64 write_slot = FindFreeSlot(proc);
    if (write_slot == Process::kWin32HandleCap)
    {
        proc->win32_handles[read_slot].kind = Process::FsBackingKind::None;
        frame->rax = kBadResult;
        return;
    }
    proc->win32_handles[write_slot].kind = Process::FsBackingKind::Pipe;

    // Allocate pool slot. PipeAlloc initialises both refcounts
    // to 1 so the read-end / write-end seats below land at the
    // right starting refcount.
    const i32 pool_idx = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_idx < 0)
    {
        proc->win32_handles[read_slot].kind = Process::FsBackingKind::None;
        proc->win32_handles[write_slot].kind = Process::FsBackingKind::None;
        frame->rax = kBadResult;
        return;
    }

    StampPipeEnd(proc->win32_handles[read_slot], static_cast<u32>(pool_idx), /*is_write=*/false);
    StampPipeEnd(proc->win32_handles[write_slot], static_cast<u32>(pool_idx), /*is_write=*/true);

    const u64 read_handle = Process::kWin32HandleBase + read_slot;
    const u64 write_handle = Process::kWin32HandleBase + write_slot;

    if (!::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_read), &read_handle, sizeof(read_handle)) ||
        !::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_write), &write_handle, sizeof(write_handle)))
    {
        // Roll back both ends — drop the per-end refcounts so
        // the pool entry's read_refs+write_refs both drop to 0
        // and PipeReleaseRead/Write tear it down.
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_idx));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_idx));
        proc->win32_handles[read_slot].kind = Process::FsBackingKind::None;
        proc->win32_handles[write_slot].kind = Process::FsBackingKind::None;
        frame->rax = kBadResult;
        return;
    }

    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
