#pragma once

/*
 * Win32 IOCP + JobObject syscall surface.
 *
 * Handles: kIocpHandleBase = 0xB00..0xB07 (IOCP),
 *          kJobHandleBase  = 0xC00..0xC07 (Jobs).
 */

#include "util/types.h"

namespace duetos::subsystems::win32
{

// IOCP — async I/O completion ports.
i64 SysIocpCreate();
i64 SysIocpSet(u64 handle, u64 completion_key, u64 apc_context, u64 status, u64 information);
i64 SysIocpRemove(u64 handle, u64 user_key, u64 user_apc, u64 user_iosb, u64 timeout_ms);
i64 SysIocpClose(u64 handle);

// JobObject — process-grouping container.
i64 SysJobCreate();
i64 SysJobAssign(u64 job_handle, u64 process_handle);
i64 SysJobIsProcessIn(u64 job_handle, u64 process_handle, u64 user_out);
i64 SysJobTerminate(u64 job_handle, u64 exit_code);
i64 SysJobQuery(u64 job_handle, u64 info_class, u64 user_buf, u64 buf_len);
i64 SysJobClose(u64 job_handle);

} // namespace duetos::subsystems::win32
