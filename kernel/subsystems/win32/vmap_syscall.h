#pragma once

#include "util/types.h"

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

/// PAGE_GUARD one-shot fault recovery. Called by the ring-3 #PF
/// handler in `kernel/arch/x86_64/traps.cpp` BEFORE the
/// IsolateTask policy fires: if `cr2` lies inside a Win32 vmap
/// region's currently-guard-armed page, clear the guard bit,
/// re-apply the underlying protection (PAGE_GUARD stripped), and
/// return true so the faulting instruction is retried. Returns
/// false on miss (cr2 not in a vmap region, page not guarded, or
/// page not committed) so the caller proceeds with normal fault
/// dispatch. Full STATUS_GUARD_PAGE_VIOLATION delivery is gated
/// on T6-02 (x64 SEH); v0 silently re-arms — which still serves
/// the common stack-grow probe pattern (the next write succeeds
/// after the first fault).
bool Win32VmapPageGuardClear(::duetos::u64 cr2);

} // namespace duetos::subsystems::win32
