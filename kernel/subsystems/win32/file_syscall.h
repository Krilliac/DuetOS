#pragma once

/*
 * Win32 file-handle syscall handlers — back CreateFileW /
 * ReadFile / WriteFile / SetFilePointerEx / GetFileSizeEx /
 * CloseHandle (file arm). Backing dispatch (ramfs vs fat32 by
 * /disk/<idx>/ prefix) lives in fs::routing; per-handle cursor
 * on Process::win32_handles.
 *
 *   SYS_FILE_OPEN   (20) — path lookup + slot assignment.
 *                    Cap-gated on kCapFsRead.
 *   SYS_FILE_READ   (21)
 *   SYS_FILE_CLOSE  (22) — generic CloseHandle; also handles
 *                    mutex + event handle ranges because real
 *                    Win32 CloseHandle dispatches by handle value.
 *   SYS_FILE_SEEK   (23)
 *   SYS_FILE_FSTAT  (24)
 *   SYS_FILE_WRITE  (43) — cap-gated on kCapFsWrite.
 *   SYS_FILE_CREATE (44) — cap-gated on kCapFsWrite.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoFileOpen(arch::TrapFrame* frame);
void DoFileRead(arch::TrapFrame* frame);
void DoFileClose(arch::TrapFrame* frame);
void DoFileSeek(arch::TrapFrame* frame);
void DoFileFstat(arch::TrapFrame* frame);
void DoFileWrite(arch::TrapFrame* frame);
void DoFileCreate(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
