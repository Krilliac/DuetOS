#pragma once

/*
 * Win32 windowing-syscall handlers.
 *
 *   SYS_WIN_CREATE   (58) — rdi=x, rsi=y, rdx=w, r10=h, r8=title ptr
 *   SYS_WIN_DESTROY  (59) — rdi=HWND
 *   SYS_WIN_SHOW     (60) — rdi=HWND, rsi=cmd
 *   SYS_WIN_MSGBOX   (61) — rdi=text ptr, rsi=caption ptr
 *
 * v0 bridges user32.dll's CreateWindowExA/W etc. into the kernel-
 * mode compositor in kernel/drivers/video/widget.{h,cpp}. No
 * per-window message pump yet — GetMessage still returns 0 so
 * Win32 event loops exit cleanly. Windows leak at process exit
 * until a process-reaping pass lands (documented in
 * .claude/knowledge/win32-windowing-v0.md).
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoWinCreate(arch::TrapFrame* frame);
void DoWinDestroy(arch::TrapFrame* frame);
void DoWinShow(arch::TrapFrame* frame);
void DoWinMsgBox(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
