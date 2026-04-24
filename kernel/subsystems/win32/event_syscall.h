#pragma once

/*
 * Win32 event syscall handlers — backs CreateEventW / SetEvent /
 * ResetEvent / WaitForSingleObject (event arm). Manual-reset
 * events stay signaled until Reset; auto-reset wake one waiter
 * then auto-clear.
 *
 *   SYS_EVENT_CREATE (30) — rdi=manual_reset, rsi=initial_state.
 *   SYS_EVENT_SET    (31) — signal + wake (all / one).
 *   SYS_EVENT_RESET  (32) — clear signal.
 *   SYS_EVENT_WAIT   (33) — rdi=handle, rsi=timeout_ms.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoEventCreate(arch::TrapFrame* frame);
void DoEventSet(arch::TrapFrame* frame);
void DoEventReset(arch::TrapFrame* frame);
void DoEventWait(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
