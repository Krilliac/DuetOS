#pragma once

#include "util/types.h"

/*
 * DuetOS — UBSAN klog runtime, v0 (plan D5).
 *
 * WHAT
 *   The handful of `__ubsan_handle_*` symbols clang/gcc generate
 *   when a translation unit is built with `-fsanitize=undefined`
 *   (see also `-fno-sanitize-trap=all` to keep the calls instead
 *   of trapping). When a UB-class incident fires (signed-overflow,
 *   alignment violation, out-of-bounds index, …) the compiler
 *   emits a call to one of these symbols carrying a
 *   `SourceLocation { filename, line, column }` plus per-handler
 *   detail. This runtime answers them with one structured klog
 *   warning per incident and (by default) returns to the caller —
 *   the program continues. A future build-time knob can flip the
 *   policy to "panic on first hit" for adversarial workloads.
 *
 * WHY THIS RUNTIME, NOT VENDOR
 *   Compiler-rt's UBSAN runtime is ~3 KLOC of host-side machinery
 *   (libc, signals, demangling, pretty-printing). The kernel needs
 *   none of that — we just need to log the kind + source location.
 *   ~150 lines suffice. The handlers are extern "C" by ABI
 *   contract.
 *
 * SCOPE FOR v0
 *   - The 14 most-common handlers (overflow / shift / oob / null
 *     / alignment / type-mismatch / unreachable / pointer-overflow
 *     / divrem / negate / load-invalid / builtin-invalid).
 *   - Plain klog warning per hit, rate-limited via existing
 *     `KLOG_ONCE_*` for the noisiest classes (a tight loop with
 *     a UB might fire millions of times before the test ends).
 *   - The build flag itself is NOT enabled — landing the runtime
 *     first means flipping `-fsanitize=undefined` on a future
 *     debug preset is one CMake line. Verification: with the flag
 *     on, deliberately overflow a signed int and grep for the
 *     emitted line.
 *
 * NOT IN SCOPE
 *   - `__ubsan_handle_function_type_mismatch_v1` (type-info dance
 *     too elaborate for v0; rare in kernel code).
 *   - C++ vptr checks (`-fsanitize=vptr`) — kernel has no RTTI,
 *     and the existing build flags will never enable it.
 *   - The `_minimal` ABI variant — clang only emits the full ABI
 *     when `-fno-sanitize-trap=all` is set; we'll match that.
 */

namespace duetos::diag
{

/// Boot-time self-test. The kernel is not currently compiled with
/// UBSAN flags, so none of the handlers below are reachable from
/// real code at boot — the self-test instead invokes one handler
/// directly via its extern-"C" symbol and asserts the inversions
/// counter / klog reach increases. Mostly a sanity check that the
/// linker did link the runtime in (a dropped TU would silently
/// turn a UBSAN-enabled build into a black hole the day someone
/// turns the flag on).
void UbsanSelfTest();

/// Total UBSAN reports emitted since boot. Cheap u64 load. Becomes
/// useful the day a future debug preset turns the compile flag on
/// — until then it stays at 0 for a clean boot.
u64 UbsanReportsEmitted();

} // namespace duetos::diag
