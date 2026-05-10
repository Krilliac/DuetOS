#pragma once

/*
 * Win32 anonymous-pipe syscall handler — backs CreatePipe.
 *
 * Allocates a kernel pipe pool slot (the same pool the Linux
 * pipe(2) syscall uses) and inserts two Win32 file handles into
 * the calling process's win32_handles table — one for the read
 * end, one for the write end. Both handles route through the
 * existing SYS_FILE_READ / SYS_FILE_WRITE / SYS_FILE_CLOSE
 * syscalls so userland callers don't need to know they're
 * pipe-backed; the file_route layer dispatches by FsBackingKind.
 *
 * Cross-process semantics: a parent that calls CreatePipe and
 * then forks (or shares the handle via stdio redirect) hands
 * the child a Win32-shaped handle the kernel resolves to the
 * same pool slot. T11-02 — see the Roadmap entry.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoWin32CreatePipe(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
