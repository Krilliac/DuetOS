#pragma once

/*
 * Win32 mutex syscall handlers — backs CreateMutexW /
 * WaitForSingleObject / ReleaseMutex. Recursive mutex with a
 * FIFO hand-off wait queue; owner is set before WakeOne so the
 * woken task sees the lock as already theirs.
 *
 *   SYS_MUTEX_CREATE  (25) — rdi = bInitialOwner. Returns handle.
 *   SYS_MUTEX_WAIT    (26) — rdi = handle, rsi = timeout_ms.
 *   SYS_MUTEX_RELEASE (27) — rdi = handle.
 */

namespace customos::arch
{
struct TrapFrame;
}

namespace customos::subsystems::win32
{

void DoMutexCreate(arch::TrapFrame* frame);
void DoMutexWait(arch::TrapFrame* frame);
void DoMutexRelease(arch::TrapFrame* frame);

} // namespace customos::subsystems::win32
