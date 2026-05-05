#pragma once

/*
 * Win32 semaphore syscall handlers — backs CreateSemaphoreW /
 * WaitForSingleObject(semaphore_handle) / ReleaseSemaphore.
 * Counted permit primitive built atop `KSemaphore` + the per-
 * process `kobj_handles` table.
 *
 *   SYS_SEM_CREATE  — rdi = initial count, rsi = max count.
 *                     Returns Win32 handle (0x500..) or -1.
 *   SYS_SEM_WAIT    — rdi = handle, rsi = timeout_ms.
 *                     Returns kWaitObject0 (0) or kWaitTimeout (0x102) or -1.
 *   SYS_SEM_RELEASE — rdi = handle, rsi = release_count.
 *                     Returns previous count, or -1 on overflow.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoSemCreate(arch::TrapFrame* frame);
void DoSemWait(arch::TrapFrame* frame);
void DoSemRelease(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
