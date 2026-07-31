/*
 * SYS_WIN32_CREATE_PIPE — Win32 CreatePipe backed by the
 * cross-process pipe pool. See pipe_syscall.h for the contract.
 */

#include "subsystems/win32/pipe_syscall.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "fs/file_route.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "subsystems/linux/syscall_pipe.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u64 kBadResult = static_cast<u64>(-1);

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
    h.named_pipe_registry_gen = 0;
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
    Process::Win32FileReservation read_reservation{};
    if (!::duetos::core::ProcessReserveWin32FileHandle(proc, &read_reservation))
    {
        frame->rax = kBadResult;
        return;
    }
    Process::Win32FileReservation write_reservation{};
    if (!::duetos::core::ProcessReserveWin32FileHandle(proc, &write_reservation))
    {
        ::duetos::core::ProcessAbortWin32FileHandle(proc, read_reservation);
        frame->rax = kBadResult;
        return;
    }

    // Allocate pool slot. PipeAlloc initialises both refcounts
    // to 1 so the read-end / write-end seats below land at the
    // right starting refcount.
    const i32 pool_idx = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_idx < 0)
    {
        ::duetos::core::ProcessAbortWin32FileHandle(proc, read_reservation);
        ::duetos::core::ProcessAbortWin32FileHandle(proc, write_reservation);
        frame->rax = kBadResult;
        return;
    }

    Process::Win32FileHandle read_candidate{};
    Process::Win32FileHandle write_candidate{};
    StampPipeEnd(read_candidate, static_cast<u32>(pool_idx), /*is_write=*/false);
    StampPipeEnd(write_candidate, static_cast<u32>(pool_idx), /*is_write=*/true);

    u64 read_handle = 0;
    u64 write_handle = 0;
    if (!::duetos::core::ProcessPublishWin32FileHandle(proc, read_reservation, read_candidate, &read_handle) ||
        !::duetos::core::ProcessPublishWin32FileHandle(proc, write_reservation, write_candidate, &write_handle))
    {
        ::duetos::core::ProcessAbortWin32FileHandle(proc, read_reservation);
        ::duetos::core::ProcessAbortWin32FileHandle(proc, write_reservation);
        if (read_handle != 0)
            (void)::duetos::fs::routing::CloseForProcess(proc, read_handle);
        else
            ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_idx));
        if (write_handle != 0)
            (void)::duetos::fs::routing::CloseForProcess(proc, write_handle);
        else
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_idx));
        frame->rax = kBadResult;
        return;
    }

    if (!::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_read), &read_handle, sizeof(read_handle)) ||
        !::duetos::mm::CopyToUser(reinterpret_cast<void*>(user_write), &write_handle, sizeof(write_handle)))
    {
        // Roll back both ends — drop the per-end refcounts so
        // the pool entry's read_refs+write_refs both drop to 0
        // and PipeReleaseRead/Write tear it down.
        (void)::duetos::fs::routing::CloseForProcess(proc, read_handle);
        (void)::duetos::fs::routing::CloseForProcess(proc, write_handle);
        frame->rax = kBadResult;
        return;
    }

    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
