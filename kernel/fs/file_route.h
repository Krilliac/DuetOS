#pragma once

#include "../core/types.h"

/*
 * CustomOS — Win32-handle file routing facade, v0.
 *
 * One layer between the Win32 file syscalls and the concrete FS
 * backends (ramfs + fat32). Owns:
 *
 *   - Path-prefix routing. "/disk/<idx>/<rest>" lands on the
 *     fat32 volume registered at <idx>; everything else lands
 *     on the per-process ramfs root. This is the smallest
 *     credible mount-table stand-in — no real mount table, no
 *     drive-letter resolver, just a prefix the loader and tests
 *     can rely on. Replace with named mounts the day a real
 *     mount table exists.
 *
 *   - Handle allocation against `Process::win32_handles`. Both
 *     ramfs- and fat32-backed slots reuse the same 0x100..0x10F
 *     handle range so user code (and the existing CloseHandle
 *     dispatch) doesn't have to learn a new range.
 *
 *   - The unified Read / Seek / Fstat / Close ops that
 *     dispatch by `Win32FileHandle::kind`. The syscall layer
 *     wraps these with cap checks + CopyFromUser/CopyToUser; a
 *     boot self-test calls them directly with kernel-space
 *     buffers to verify the routing without paying the trap-
 *     frame tax.
 *
 * Context: kernel. Per-process state — caller hands in the
 * `Process*` so the same helpers work for the current trap's
 * process AND for self-tests that synthesise their own.
 */

namespace customos::core
{
struct Process;
}

namespace customos::fs::routing
{

/// Resolve `path` and allocate a Win32FileHandle slot on `proc`.
/// Returns the handle id (`Process::kWin32HandleBase + slot`) on
/// success, or u64(-1) on miss / out-of-handles / bad input.
/// Performs NO capability check — caller (syscall layer or self-
/// test) is responsible for that gate.
u64 OpenForProcess(::customos::core::Process* proc, const char* path);

/// Read up to `len` bytes from the handle into the kernel-space
/// buffer `dst`. Advances the handle's cursor by the number of
/// bytes copied. Returns the byte count (0 at EOF) or u64(-1)
/// on bad handle / I/O failure.
u64 ReadForProcess(::customos::core::Process* proc, u64 handle, void* dst, u64 len);

/// Move the cursor. `whence`: 0 = SET (offset is absolute),
/// 1 = CUR (offset is signed delta from current), 2 = END
/// (offset is signed delta from end-of-file). Result is clamped
/// to [0, file_size]. Returns the new cursor value or u64(-1)
/// on bad handle / bad whence.
u64 SeekForProcess(::customos::core::Process* proc, u64 handle, i64 offset, u32 whence);

/// Write the current file size of the handle's backing object
/// to `*out_size`. Returns 0 on success, u64(-1) on bad handle.
u64 FstatForProcess(::customos::core::Process* proc, u64 handle, u64* out_size);

/// Release the handle's slot. Idempotent — closing an already-
/// free slot is a no-op. Always returns 0.
u64 CloseForProcess(::customos::core::Process* proc, u64 handle);

/// Boot self-test. Routes /disk/0/HELLO.TXT (the FAT32 image
/// builder seeds this file with known content) through
/// OpenForProcess + ReadForProcess + CloseForProcess, verifies
/// the bytes match, and panics on mismatch. Skipped silently
/// when no fat32 volume is registered (e.g. a kernel image that
/// boots without a disk).
void SelfTest();

} // namespace customos::fs::routing
