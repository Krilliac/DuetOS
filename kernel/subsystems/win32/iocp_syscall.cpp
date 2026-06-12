/*
 * SYS_IOCP_* dispatch — backs ntdll's NtCreateIoCompletion /
 * NtSetIoCompletion / NtRemoveIoCompletion(Ex) family and the
 * Win32-shaped PostQueuedCompletionStatus.
 *
 * Routes through the unified `Process::kobj_handles` table + the
 * KObject-shaped `ipc::IocpPort` (kernel/ipc/iocp.{h,cpp}),
 * alongside KMutex / KEvent / KSemaphore. The legacy 8-port
 * global pool in `iocp_job.cpp` was retired by this migration:
 *   - per-process storage (a port no longer survives its owning
 *     process — kobj_handles drain reclaims it at teardown),
 *   - capacity 8 ports / 16 packets → 64 handles / 32 packets,
 *   - finite NtRemoveIoCompletion timeouts are now honoured
 *     (best-effort tick granularity) instead of "block forever".
 * Wire ABI unchanged: handles are `kWin32IocpBase (0xB00) +
 * ipc_handle`, return values keep the legacy 1 / 0 / -1 shape.
 *
 * Field mapping between the syscall ABI and `ipc::IocpCompletion`:
 *   completion_key  ↔ completion_key
 *   apc_context     ↔ overlapped_user_va (Win32 OVERLAPPED*)
 *   status          ↔ ntstatus (NTSTATUS is 32-bit; high bits drop)
 *   information     ↔ bytes_transferred
 *
 * GAP: a full ring fails the post (-1) instead of the legacy
 * drop-oldest — surface STATUS_TOO_MANY_OPENED_FILES properly when
 * a real workload hits the 32-packet cap.
 */

#include "subsystems/win32/iocp_syscall.h"

#include "ipc/handle_table.h"
#include "ipc/iocp.h"
#include "ipc/kobject.h"
#include "log/klog.h"
#include "mm/paging.h"
#include "proc/process.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u64 kMsPerTick = 10; // scheduler runs at 100 Hz
constexpr u64 kInfiniteMs = 0xFFFFFFFFu;

// Map a Win32 IOCP handle to a kobj_handles slot id, or
// `ipc::kHandleInvalid` if the value is out of range. Flat
// subtraction of the per-type base — same shape as the mutex /
// event / semaphore translations.
ipc::Handle Win32HandleToIpc(u64 handle)
{
    if (handle < core::Process::kWin32IocpBase ||
        handle >= core::Process::kWin32IocpBase + core::Process::kWin32IocpCap)
    {
        return ipc::kHandleInvalid;
    }
    return static_cast<ipc::Handle>(handle - core::Process::kWin32IocpBase);
}

// Resolve + type-check + take a lookup reference, after verifying
// the per-handle rights floor. Returns nullptr on any failure
// (bad range, missing right, closed slot, type mismatch). Caller
// MUST pair a non-null return with `ipc::KObjectRelease(&port->base)`.
ipc::IocpPort* LookupPortRef(core::Process* proc, u64 handle, u64 required_rights, const char* who)
{
    const ipc::Handle ipc_h = Win32HandleToIpc(handle);
    if (ipc_h == ipc::kHandleInvalid)
    {
        // First user-mode IOCP-handle escape lands in the boot log
        // so a regression in the Win32 thunk's handle-mint path is
        // visible; subsequent fires are dropped (the caller already
        // gets STATUS_INVALID_HANDLE via the -1 return).
        KLOG_ONCE_WARN_V("subsystems/win32/iocp", who, handle);
        return nullptr;
    }
    if (!ipc::HandleCheckRight(proc->kobj_handles, ipc_h, required_rights))
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/iocp", "handle lacks required right; handle", handle);
        return nullptr;
    }
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Iocp);
    if (obj == nullptr)
    {
        return nullptr;
    }
    // KObject is the first member of IocpPort — standard
    // handle-table round-trip cast (see kobject.h).
    return reinterpret_cast<ipc::IocpPort*>(obj);
}

} // namespace

i64 SysIocpCreate()
{
    using ::duetos::core::CapSetHas;
    using ::duetos::core::kCapSpawnThread;
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return -1;
    }
    // Same cap gate the legacy pool enforced: a completion port is
    // a cross-thread hand-off primitive, so creating one is tied to
    // the thread-spawning capability.
    if (!CapSetHas(proc->caps, kCapSpawnThread))
    {
        core::RecordSandboxDenial(kCapSpawnThread);
        return -1;
    }
    auto create_r = ipc::IocpCreate();
    if (!create_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/iocp", "create OOM in pid", proc->pid);
        return -1;
    }
    ipc::IocpPort* port = create_r.value();
    auto insert_r = ipc::HandleTableInsert(proc->kobj_handles, &port->base);
    if (!insert_r.has_value())
    {
        KLOG_WARN_AV(::duetos::core::LogArea::Win32, "win32/iocp", "create: kobj_handles full in pid", proc->pid);
        // Drop the create-time reference; IocpDestroy frees the port.
        ipc::KObjectRelease(&port->base);
        return -1;
    }
    const u64 handle = core::Process::kWin32IocpBase + insert_r.value();
    KLOG_INFO_AV(::duetos::core::LogArea::Win32, "win32/iocp", "NtCreateIoCompletion OK; handle", handle);
    return static_cast<i64>(handle);
}

i64 SysIocpSet(u64 handle, u64 completion_key, u64 apc_context, u64 status, u64 information)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return -1;
    }
    ipc::IocpPort* port = LookupPortRef(proc, handle, ipc::kHandleRightWrite, "SysIocpSet handle out of range");
    if (port == nullptr)
    {
        return -1;
    }
    ipc::IocpCompletion c = {};
    c.overlapped_user_va = apc_context;
    c.completion_key = completion_key;
    c.bytes_transferred = information;
    c.ntstatus = static_cast<u32>(status);
    const bool posted = ipc::IocpTryPost(port, c);
    ipc::KObjectRelease(&port->base);
    return posted ? 0 : -1;
}

// Returns: 1 packet dequeued, 0 timeout / no packet, -1 bad handle.
// Writes into the three out-pointers (completion_key, apc_context,
// io_status_block[2]). All can be null.
i64 SysIocpRemove(u64 handle, u64 user_key, u64 user_apc, u64 user_iosb, u64 timeout_ms)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return -1;
    }
    ipc::IocpPort* port = LookupPortRef(proc, handle, ipc::kHandleRightRead, "SysIocpRemove handle out of range");
    if (port == nullptr)
    {
        return -1;
    }
    // Timeout mapping: 0 = non-blocking probe, INFINITE (0xFFFFFFFF,
    // or the full-width -1 ntdll passes) = block until post/close,
    // anything else = best-effort tick-granularity budget. The
    // legacy pool treated every non-zero value as "block forever";
    // finite timeouts are honoured now.
    u64 timeout_ticks;
    if (timeout_ms == 0)
    {
        timeout_ticks = 0;
    }
    else if (timeout_ms >= kInfiniteMs)
    {
        timeout_ticks = ipc::kIocpTimeoutInfinite;
    }
    else
    {
        timeout_ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
    }
    ipc::IocpCompletion c = {};
    const bool got = ipc::IocpWait(port, &c, timeout_ticks);
    ipc::KObjectRelease(&port->base);
    if (!got)
    {
        return 0;
    }
    if (user_key != 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_key), &c.completion_key, sizeof(c.completion_key)))
        {
            return -1;
        }
    }
    if (user_apc != 0)
    {
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_apc), &c.overlapped_user_va, sizeof(c.overlapped_user_va)))
        {
            return -1;
        }
    }
    if (user_iosb != 0)
    {
        const u64 iosb[2] = {static_cast<u64>(c.ntstatus), c.bytes_transferred};
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_iosb), iosb, sizeof(iosb)))
        {
            return -1;
        }
    }
    return 1;
}

i64 SysIocpClose(u64 handle)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return -1;
    }
    const ipc::Handle ipc_h = Win32HandleToIpc(handle);
    if (ipc_h == ipc::kHandleInvalid)
    {
        KLOG_ONCE_WARN_V("subsystems/win32/iocp", "SysIocpClose handle out of range", handle);
        return -1;
    }
    ipc::KObject* obj = ipc::HandleTableLookupRef(proc->kobj_handles, ipc_h, ipc::KObjectType::Iocp);
    if (obj == nullptr)
    {
        return -1;
    }
    auto* port = reinterpret_cast<ipc::IocpPort*>(obj);
    // Flip `closed` + broadcast BEFORE dropping the table reference:
    // a consumer parked inside IocpWait holds its own lookup ref, so
    // the destroy callback (which also calls IocpClose) would never
    // fire while it sleeps — the explicit close is what wakes it.
    // GAP: this closes the port on the FIRST CloseHandle even if a
    // duplicated handle still exists — revisit if a workload
    // duplicates IOCP handles.
    ipc::IocpClose(port);
    (void)ipc::HandleTableRemove(proc->kobj_handles, ipc_h);
    ipc::KObjectRelease(obj); // drop the lookup ref
    return 0;
}

// SYS_IOCP_POST — Win32-shaped PostQueuedCompletionStatus: a
// caller-fabricated completion with STATUS_SUCCESS. Thin wrapper
// over IocpTryPost. Returns 0 on success, -1 on bad handle /
// missing Write right / full or closed port.
i64 SysIocpPost(u64 handle, u64 bytes_transferred, u64 completion_key, u64 overlapped)
{
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        return -1;
    }
    ipc::IocpPort* port = LookupPortRef(proc, handle, ipc::kHandleRightWrite, "SysIocpPost handle out of range");
    if (port == nullptr)
    {
        return -1;
    }
    ipc::IocpCompletion c = {};
    c.overlapped_user_va = overlapped;
    c.completion_key = completion_key;
    c.bytes_transferred = bytes_transferred;
    c.ntstatus = 0; // STATUS_SUCCESS — posted completions carry no error
    const bool posted = ipc::IocpTryPost(port, c);
    ipc::KObjectRelease(&port->base);
    return posted ? 0 : -1;
}

} // namespace duetos::subsystems::win32
