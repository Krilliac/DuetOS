#pragma once

/*
 * Win32 JobObject syscall surface.
 *
 * Handles: kJobHandleBase = 0xC00..0xC07.
 *
 * (Formerly iocp_job.h — the IOCP half migrated to the KObject-
 * shaped ipc::IocpPort + kobj_handles; see iocp_syscall.h.)
 */

#include "util/types.h"

namespace duetos::subsystems::win32
{

// JobObject — process-grouping container.
i64 SysJobCreate();
i64 SysJobAssign(u64 job_handle, u64 process_handle);
i64 SysJobIsProcessIn(u64 job_handle, u64 process_handle, u64 user_out);
i64 SysJobTerminate(u64 job_handle, u64 exit_code);
i64 SysJobQuery(u64 job_handle, u64 info_class, u64 user_buf, u64 buf_len);
i64 SysJobClose(u64 job_handle);

} // namespace duetos::subsystems::win32
