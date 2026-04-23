#pragma once

/*
 * CustomOS stack-canary public surface.
 *
 * The compiler symbols (__stack_chk_guard + __stack_chk_fail) live
 * in stack_canary.cpp and aren't called directly from C++ code.
 * What IS called from C++ — by kernel_main right after RandomInit —
 * is the post-boot canary randomization.
 */

namespace customos::core
{

/// Replace the boot-constant stack canary with an entropy-pool
/// value. MUST be called after `RandomInit` and MUST be called
/// from a function that never returns (canary update between
/// prologue and epilogue of a caller = guaranteed panic).
/// `kernel_main` is the intended caller.
void RandomizeStackCanary();

} // namespace customos::core
