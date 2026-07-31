#pragma once

/*
 * Win32 JobObject syscall surface.
 *
 * Handles: low 12-bit tag kJobHandleBase = 0xC00..0xC07 plus a
 * non-wrapping generation in the high bits.
 *
 * (Formerly iocp_job.h — the IOCP half migrated to the KObject-
 * shaped ipc::IocpPort + kobj_handles; see iocp_syscall.h.)
 */

#include "util/types.h"

namespace duetos::core
{
struct Process;
}

namespace duetos::subsystems::win32
{

// Handle-band constants — shared with DoFileClose dispatch.
constexpr u64 kJobHandleBase = 0xC00ULL;
constexpr u32 kJobPoolCap = 8;
constexpr u64 kJobHandleTagMask = 0xFFFULL;

inline constexpr bool IsJobHandle(u64 handle)
{
    const u64 tag = handle & kJobHandleTagMask;
    return (handle >> 12) != 0 && tag >= kJobHandleBase && tag < kJobHandleBase + kJobPoolCap;
}

// JobObject — process-grouping container.
i64 SysJobCreate();
i64 SysJobAssign(u64 job_handle, u64 process_handle);
i64 SysJobIsProcessIn(u64 job_handle, u64 process_handle, u64 user_out);
i64 SysJobTerminate(u64 job_handle, u64 exit_code);
i64 SysJobQuery(u64 job_handle, u64 info_class, u64 user_buf, u64 buf_len);
i64 SysJobClose(u64 job_handle);

/// Last-task-exit hook for a Job owner. Detaches every owned job and
/// its member references under the Job pool lock, then drops those
/// references after unlocking. This must run before the owner's final
/// task reference is released so a self-membership cannot pin a dead
/// Process forever. Idempotent.
void JobDrainOwnedByProcess(core::Process* owner);

/// Heap-phase reference-balance test for the owner-exit drain. Must run
/// after KernelHeapInit and before user tasks can create Job objects.
void JobOwnerExitSelfTest();

} // namespace duetos::subsystems::win32
