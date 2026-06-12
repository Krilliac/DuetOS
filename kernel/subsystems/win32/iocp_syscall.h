#pragma once

/*
 * Win32 IOCP syscall surface — SYS_IOCP_CREATE / SET / REMOVE /
 * CLOSE / POST.
 *
 * Routes through the KObject-shaped `ipc::IocpPort`
 * (kernel/ipc/iocp.{h,cpp}) + the unified `Process::kobj_handles`
 * table, alongside KMutex / KEvent / KSemaphore. The legacy
 * fixed 8-port global pool (`iocp_job.cpp`) was retired by this
 * migration; the wire ABI is unchanged — handles are
 * `kWin32IocpBase (0xB00) + ipc_handle`.
 */

#include "util/types.h"

namespace duetos::subsystems::win32
{

i64 SysIocpCreate();
i64 SysIocpSet(u64 handle, u64 completion_key, u64 apc_context, u64 status, u64 information);
i64 SysIocpRemove(u64 handle, u64 user_key, u64 user_apc, u64 user_iosb, u64 timeout_ms);
i64 SysIocpClose(u64 handle);
i64 SysIocpPost(u64 handle, u64 bytes_transferred, u64 completion_key, u64 overlapped);

} // namespace duetos::subsystems::win32
