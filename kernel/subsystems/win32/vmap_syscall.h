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

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::subsystems::win32
{

void DoVmap(arch::TrapFrame* frame);
void DoVunmap(arch::TrapFrame* frame);

// SYS_VIRTUAL_ALLOC / SYS_VIRTUAL_FREE / SYS_VIRTUAL_PROTECT
// (T5-01 partial). Region-tracking variants honouring
// reserve/commit split + Win32 protection bits.
void DoVirtualAlloc(arch::TrapFrame* frame);
void DoVirtualFree(arch::TrapFrame* frame);
void DoVirtualProtect(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
