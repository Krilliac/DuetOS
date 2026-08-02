/*
 * SYS_NAMED_PIPE_CREATE / SYS_NAMED_PIPE_OPEN — Win32 named-pipe
 * server + client paths.
 *
 * See ipc/named_pipes.h for the registry contract and named_pipe_syscall.h
 * for the user-visible ABI.
 */

#include "subsystems/win32/named_pipe_syscall.h"

#include "ipc/named_pipes.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "subsystems/linux/syscall_pipe.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u64 kBadResult = static_cast<u64>(-1);

// Win32 PIPE_ACCESS_* constants. We only honour INBOUND/OUTBOUND;
// DUPLEX requires two pool slots and a wider Win32FileHandle.
constexpr u64 kPipeAccessInbound = 0x00000001;
constexpr u64 kPipeAccessOutbound = 0x00000002;

void StampPipeHandle(::duetos::core::Process::Win32FileHandle& h, u32 pool_idx, bool is_write_end, i8 registry_slot,
                     u32 registry_gen)
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
    h.named_pipe_registry_slot = registry_slot;
    h.named_pipe_registry_gen = registry_gen;
}

bool CopyUserName(::duetos::core::Process* proc, const void* user_src, u64 cap_in, char* dst, u64 dst_cap)
{
    (void)proc;
    const u64 cap = (cap_in == 0 || cap_in > dst_cap) ? dst_cap : cap_in;
    if (cap < 2)
        return false;
    const auto r = ::duetos::mm::CopyUserCString(dst, cap, user_src);
    if (!r.ok() || dst[0] == '\0')
        return false;
    return true;
}

} // namespace

void DoNamedPipeCreate(arch::TrapFrame* frame)
{
    using ::duetos::core::Process;
    using namespace ::duetos::ipc;

    Process* proc = ::duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = kBadResult;
        return;
    }

    // Validate open_mode: only INBOUND and OUTBOUND.  DUPLEX needs
    // two pool slots; reject so callers know to fall back rather
    // than silently downgrading.
    const u64 open_mode = frame->rdx;
    bool server_is_writer;
    if (open_mode == kPipeAccessInbound)
        server_is_writer = false;
    else if (open_mode == kPipeAccessOutbound)
        server_is_writer = true;
    else
    {
        frame->rax = kBadResult;
        return;
    }

    // Copy the name into a kernel buffer.
    char name[kNamedPipeMaxNameLen] = {};
    if (!CopyUserName(proc, reinterpret_cast<const void*>(frame->rdi), frame->rsi, name, sizeof(name)))
    {
        frame->rax = kBadResult;
        return;
    }

    // Find a free Win32 file-handle slot before allocating the
    // pipe pool slot so we can fail without leaking.
    Process::Win32FileReservation reservation{};
    if (!::duetos::core::ProcessReserveWin32FileHandle(proc, &reservation))
    {
        frame->rax = kBadResult;
        return;
    }

    // Allocate the pipe pool slot. read_refs = write_refs = 1.
    const i32 pool_idx = ::duetos::subsystems::linux::internal::PipeAlloc();
    if (pool_idx < 0)
    {
        ::duetos::core::ProcessAbortWin32FileHandle(proc, reservation);
        frame->rax = kBadResult;
        return;
    }

    // Register the name. On collision (name already in use), free
    // both pool refs and bail out.
    u32 registry_gen = 0;
    const i32 registry_slot =
        NamedPipeRegisterServer(name, static_cast<u32>(pool_idx), server_is_writer, &registry_gen);
    if (registry_slot < 0)
    {
        ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_idx));
        ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_idx));
        ::duetos::core::ProcessAbortWin32FileHandle(proc, reservation);
        frame->rax = kBadResult;
        return;
    }

    // Plant the server-end handle. The server keeps ONE end's ref
    // (the matching one from PipeAlloc). The opposite end's ref
    // stays at 1 as the "registry reservation." Every client acquires
    // a fresh ref on top; NamedPipeOnServerClose always drops the
    // registry-owned ref after removing this exact registration.
    Process::Win32FileHandle candidate{};
    StampPipeHandle(candidate, static_cast<u32>(pool_idx), /*is_write_end=*/server_is_writer,
                    static_cast<i8>(registry_slot), registry_gen);
    u64 handle = 0;
    if (!::duetos::core::ProcessPublishWin32FileHandle(proc, reservation, candidate, &handle))
    {
        ::duetos::core::ProcessAbortWin32FileHandle(proc, reservation);
        if (server_is_writer)
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(static_cast<u32>(pool_idx));
        else
            ::duetos::subsystems::linux::internal::PipeReleaseRead(static_cast<u32>(pool_idx));
        NamedPipeOnServerClose(static_cast<i8>(registry_slot), registry_gen);
        frame->rax = kBadResult;
        return;
    }

    frame->rax = handle;
}

void DoNamedPipeOpen(arch::TrapFrame* frame)
{
    using ::duetos::core::Process;
    using namespace ::duetos::ipc;

    Process* proc = ::duetos::core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = kBadResult;
        return;
    }

    char name[kNamedPipeMaxNameLen] = {};
    if (!CopyUserName(proc, reinterpret_cast<const void*>(frame->rdi), frame->rsi, name, sizeof(name)))
    {
        frame->rax = kBadResult;
        return;
    }

    // Reserve the destination row before acquiring an opposite-end reference,
    // so a full table cannot consume a client retain.
    Process::Win32FileReservation reservation{};
    if (!::duetos::core::ProcessReserveWin32FileHandle(proc, &reservation))
    {
        frame->rax = kBadResult;
        return;
    }

    // Lookup and opposite-end retain are one registry transaction. Exact
    // server close cannot recycle the pool slot between those steps.
    u32 pool_idx = 0;
    bool server_is_writer = false;
    if (!NamedPipeConnectClient(name, &pool_idx, &server_is_writer))
    {
        ::duetos::core::ProcessAbortWin32FileHandle(proc, reservation);
        frame->rax = kBadResult;
        return;
    }

    const bool client_is_writer = !server_is_writer;

    // The client's handle does NOT touch the registry on close —
    // it's an ordinary pipe-pool end (slot = -1).
    Process::Win32FileHandle candidate{};
    StampPipeHandle(candidate, pool_idx, /*is_write_end=*/client_is_writer,
                    /*registry_slot=*/-1, /*registry_gen=*/0);
    u64 handle = 0;
    if (!::duetos::core::ProcessPublishWin32FileHandle(proc, reservation, candidate, &handle))
    {
        if (client_is_writer)
            ::duetos::subsystems::linux::internal::PipeReleaseWrite(pool_idx);
        else
            ::duetos::subsystems::linux::internal::PipeReleaseRead(pool_idx);
        ::duetos::core::ProcessAbortWin32FileHandle(proc, reservation);
        frame->rax = kBadResult;
        return;
    }

    frame->rax = handle;
}

} // namespace duetos::subsystems::win32
