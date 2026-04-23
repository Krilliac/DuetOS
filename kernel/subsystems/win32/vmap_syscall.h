#pragma once

/*
 * Win32 VirtualAlloc / VirtualFree — extracted syscall handlers.
 *
 *   SYS_VMAP   (28) — bump-arena VirtualAlloc. rdi=bytes.
 *                    Rounds up to pages, maps fresh frames RW+NX,
 *                    bumps cursor. Leaks on OOM partway through
 *                    (documented).
 *   SYS_VUNMAP (29) — VirtualFree. v0 no-op with a range check
 *                    — a bump-only arena can't free individually.
 */

namespace customos::arch
{
struct TrapFrame;
}

namespace customos::subsystems::win32
{

void DoVmap(arch::TrapFrame* frame);
void DoVunmap(arch::TrapFrame* frame);

} // namespace customos::subsystems::win32
