#pragma once

/*
 * Win32 adapter for the protocol-neutral process Job service.
 *
 * This layer owns public handle tags, Win32 information-class layouts,
 * capability checks, user copies, and scheduler kill requests. Pool state,
 * exact ProcessKey completion records, accounting, termination pins, and
 * owner drain live in proc/job.{h,cpp}.
 *
 * (Formerly iocp_job.h — the IOCP half migrated to the KObject-
 * shaped ipc::IocpPort + kobj_handles; see iocp_syscall.h.)
 */

#include "proc/job.h"
#include "util/types.h"

namespace duetos::subsystems::win32
{

// Handle-band constants — shared with DoFileClose dispatch.
constexpr u64 kJobHandleBase = 0xC00ULL;
constexpr u32 kJobPoolCap = core::kJobPoolCapacity;
constexpr u64 kJobHandleTagMask = 0xFFFULL;
constexpr u32 kJobHandleGenerationShift = 12;

inline constexpr bool IsJobHandle(u64 handle)
{
    const u64 tag = handle & kJobHandleTagMask;
    return (handle & (1ULL << 63)) == 0 && (handle >> kJobHandleGenerationShift) != 0 && tag >= kJobHandleBase &&
           tag < kJobHandleBase + kJobPoolCap;
}

// JobObject — process-grouping container.
i64 SysJobCreate();
i64 SysJobAssign(u64 job_handle, u64 process_handle);
i64 SysJobIsProcessIn(u64 job_handle, u64 process_handle, u64 user_out);
i64 SysJobTerminate(u64 job_handle, u64 exit_code);
i64 SysJobQuery(u64 job_handle, u64 info_class, u64 user_buf, u64 buf_len);
i64 SysJobClose(u64 job_handle);

/// Last-task-exit hook for a Job owner. Retires every owned Job under the
/// Job-pool lock. Jobs contain exact ProcessKey completion records rather than
/// Process references, so this operation cannot pin or release ProcessCore.
/// Idempotent.
void JobDrainOwnedByProcess(core::Process* owner);

/// Heap-phase reference-balance test for the owner-exit drain. Must run
/// after KernelHeapInit and before user tasks can create Job objects.
void JobOwnerExitSelfTest();

/// Heap-phase handle-generation, owner-isolation, close-balance, and query-ABI
/// regression. Must run before user tasks can create Job objects.
void JobHandleLifetimeSelfTest();

} // namespace duetos::subsystems::win32
