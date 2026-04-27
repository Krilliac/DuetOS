#pragma once

/*
 * Win32 directory enumeration — SYS_DIR_OPEN / SYS_DIR_NEXT plus
 * the close-side hook the shared CloseHandle dispatch calls when a
 * handle in the kWin32DirBase range arrives.
 */

#include "util/types.h"

namespace duetos::core
{
struct Process;
}

namespace duetos::subsystems::win32
{

// Open a directory by path. Returns kWin32DirBase + idx on success,
// -1 on miss / pool full. Cap-gated on kCapFsRead.
i64 SysDirOpen(u64 user_path);

// Kernel-string variant — used when a sibling syscall (e.g. Linux
// `open(path, O_DIRECTORY)`) has already copied the path into a
// kernel buffer and wants to allocate a directory snapshot
// without re-doing the user copy. Same cap requirements; same
// return values.
i64 SysDirOpenKernel(const char* path);

// Advance the cursor and copy the next entry to user. Returns 1 on
// success, 0 at end-of-iteration, -1 on bad handle.
i64 SysDirNext(u64 handle, u64 user_report);

// Drop the snapshot + free the slot. Called from the existing
// SYS_FILE_CLOSE / NtClose handler when a handle in the
// kWin32DirBase range is closed; safe on already-closed slots.
void SysDirClose(core::Process* proc, u64 handle);

// Reset a directory handle's iterator to the first entry. Returns
// 0 on success, -1 on bad handle. Does not re-snapshot — the
// entries captured at OPEN time stay frozen for the handle's life.
i64 SysDirRewind(u64 handle);

} // namespace duetos::subsystems::win32
