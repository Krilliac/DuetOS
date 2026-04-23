#pragma once

/*
 * Win32 file-handle syscall handlers — backs CreateFileW /
 * ReadFile / SetFilePointerEx / GetFileSizeEx / CloseHandle (file
 * arm). Ramfs-backed; per-handle cursor on Process::win32_handles.
 *
 *   SYS_FILE_OPEN   (20..23 range; see syscall.h) — path lookup +
 *                    slot assignment. Cap-gated on kCapFsRead.
 *   SYS_FILE_READ
 *   SYS_FILE_CLOSE  — generic CloseHandle; also handles mutex +
 *                    event handle ranges because real Win32
 *                    CloseHandle dispatches by handle value.
 *   SYS_FILE_SEEK
 *   SYS_FILE_FSTAT
 */

namespace customos::arch
{
struct TrapFrame;
}

namespace customos::subsystems::win32
{

void DoFileOpen(arch::TrapFrame* frame);
void DoFileRead(arch::TrapFrame* frame);
void DoFileClose(arch::TrapFrame* frame);
void DoFileSeek(arch::TrapFrame* frame);
void DoFileFstat(arch::TrapFrame* frame);

} // namespace customos::subsystems::win32
