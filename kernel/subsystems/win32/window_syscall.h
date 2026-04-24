#pragma once

/*
 * Win32 windowing-syscall handlers.
 *
 *   SYS_WIN_CREATE    (58) — rdi=x, rsi=y, rdx=w, r10=h, r8=title ptr
 *   SYS_WIN_DESTROY   (59) — rdi=HWND
 *   SYS_WIN_SHOW      (60) — rdi=HWND, rsi=cmd
 *   SYS_WIN_MSGBOX    (61) — rdi=text ptr, rsi=caption ptr
 *   SYS_WIN_PEEK_MSG  (62) — rdi=out ptr, rsi=hwnd filter, rdx=remove
 *   SYS_WIN_GET_MSG   (63) — rdi=out ptr, rsi=hwnd filter
 *   SYS_WIN_POST_MSG  (64) — rdi=hwnd, rsi=msg, rdx=wparam, r10=lparam
 *   SYS_GDI_FILL_RECT (65) — rdi=hwnd, rsi=x, rdx=y, r10=w, r8=h, r9=rgb
 *   SYS_GDI_TEXT_OUT  (66) — rdi=hwnd, rsi=x, rdx=y, r10=text, r8=len, r9=rgb
 *   SYS_GDI_RECTANGLE (67) — same shape as FILL_RECT
 *   SYS_GDI_CLEAR     (68) — rdi=hwnd
 *
 * Bridges user32.dll + gdi32.dll into the kernel-mode compositor
 * and per-window message queues in
 * kernel/drivers/video/widget.{h,cpp}. Each window carries an
 * owner pid so the process-exit reaper (called from
 * `ProcessRelease` when the last task drops its reference) can
 * close every window belonging to a dying process in a single
 * walk.
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

void DoWinPeekMsg(arch::TrapFrame* frame);
void DoWinGetMsg(arch::TrapFrame* frame);
void DoWinPostMsg(arch::TrapFrame* frame);

void DoGdiFillRect(arch::TrapFrame* frame);
void DoGdiTextOut(arch::TrapFrame* frame);
void DoGdiRectangle(arch::TrapFrame* frame);
void DoGdiClear(arch::TrapFrame* frame);

void DoWinMove(arch::TrapFrame* frame);
void DoWinGetRect(arch::TrapFrame* frame);
void DoWinSetText(arch::TrapFrame* frame);

void DoWinTimerSet(arch::TrapFrame* frame);
void DoWinTimerKill(arch::TrapFrame* frame);

void DoGdiLine(arch::TrapFrame* frame);
void DoGdiEllipse(arch::TrapFrame* frame);
void DoGdiSetPixel(arch::TrapFrame* frame);

void DoWinGetKeyState(arch::TrapFrame* frame);
void DoWinGetCursor(arch::TrapFrame* frame);
void DoWinSetCursor(arch::TrapFrame* frame);

void DoWinSetCapture(arch::TrapFrame* frame);
void DoWinReleaseCapture(arch::TrapFrame* frame);
void DoWinGetCapture(arch::TrapFrame* frame);

void DoWinClipSetText(arch::TrapFrame* frame);
void DoWinClipGetText(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
