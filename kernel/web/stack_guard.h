#pragma once

/*
 * DuetOS — native stack-exhaustion guard for the web engine's recursive
 * walkers (CSS parser, selector matcher, style/layout tree walks, the JS
 * DOM query helpers).
 *
 * All of those recurse on the native C++ stack over PAGE-SUPPLIED data:
 * stylesheet text, the DOM shape, the selector chain. A logical depth cap
 * alone cannot bound them safely because the per-level frame cost differs
 * by an order of magnitude between paths (a ParseCompound/ParsePseudo pair
 * is a couple hundred bytes; a StyleSubtree level carries a ComputedStyle),
 * so a cap calibrated to one path either rejects legitimate pages or lets
 * the other smash the kstack-arena guard page.
 *
 * The real guard therefore measures ACTUAL native stack consumption against
 * this thread's guard page, exactly like js/parser.cpp's ParseStackExhausted
 * (SEC-007) and interp.cpp's CallFunction. Callers pair it with a coarse
 * logical depth cap because boot-context / self-test threads run on a larger
 * NON-arena stack, where the range check below is false and the frame guard
 * consequently never fires.
 */

#include "mm/kstack.h"
#include "util/types.h"

namespace duetos::web
{

// Bytes of headroom to leave above the guard page. One web-walker level is
// a few hundred bytes to ~2 KiB under the debug build's KASAN/UBSAN frame
// inflation, so this leaves room for several levels of descent between the
// check and the next one — the guard must fire before the recursion could
// step past the guard page. (The JS interpreter needs 24 KiB because one JS
// call level costs ~15 KiB; web walker levels are far cheaper.)
inline constexpr u64 kWebStackGuardMargin = 8u * 1024u;

// Coarse logical-depth backstop for threads whose stack is NOT a kstack
// arena slot (boot context, self-tests). Deep enough that no real page's DOM
// or selector chain reaches it, shallow enough to bound a hostile one.
inline constexpr u32 kWebMaxWalkDepth = 512;

// True when the current frame is within `margin` bytes of this thread's
// kernel-stack guard page. Always false on non-arena stacks — pair it with
// a logical depth cap. Callers MUST bail (return a graceful no-match /
// partial result); there is no way to recover from the guard-page #PF.
inline bool WebStackExhausted(u64 margin = kWebStackGuardMargin)
{
    const u64 fr = reinterpret_cast<u64>(__builtin_frame_address(0));
    if (fr >= mm::kKernelStackArenaBase && fr < mm::kKernelStackArenaBase + mm::kKernelStackArenaBytes)
    {
        const u64 offInSlot = (fr - mm::kKernelStackArenaBase) % mm::kKernelStackSlotBytes;
        return offInSlot <= mm::kKernelStackGuardPages * mm::kPageSize + margin;
    }
    return false;
}

} // namespace duetos::web
