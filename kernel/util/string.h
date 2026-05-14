#pragma once

#include "util/types.h"

/*
 * DuetOS — freestanding string operations.
 *
 * The kernel can't lean on a hosted libc. This header surfaces the
 * three primitives every C++ codegen path needs: memset, memcpy,
 * memmove. They're declared `extern "C"` because the compiler emits
 * unmangled calls to them when it lowers `T = {}` zero-init or
 * struct-copy expressions.
 *
 * The actual implementations live in `kernel/util/string.cpp`. They
 * are byte-oriented and SSE-free (the kernel runs `-mno-sse`); fast
 * enough for boot-time setup, copy-once tasks, and the occasional
 * IRQ-context move. Hot paths that need bulk throughput should reach
 * for an explicitly-vectorized helper, not memcpy.
 *
 * `memcpy` aliases to `memmove` — the strict-no-overlap guarantee
 * isn't worth a separate body when the trivial loop is already this
 * cheap.
 */

extern "C" void* memset(void* dst, int c, duetos::usize n);
extern "C" void* memmove(void* dst, const void* src, duetos::usize n);
extern "C" void* memcpy(void* dst, const void* src, duetos::usize n);

namespace duetos::core
{

/// Self-test: covers memset (length 0, partial range, full range,
/// value masking to low byte), memcpy (length 0, full copy, partial
/// preservation), and memmove (forward + backward overlap, identity).
/// Panics on any failure. Boot-time only — hot paths must not call
/// this from real workloads.
void StringSelfTest();

/// Length of a NUL-terminated C string. NULL-safe (returns 0). The
/// kernel can't reach for `<string.h>`'s strlen because we link
/// freestanding; this is the one canonical replacement. Defined
/// here because eleven separate kernel TUs used to roll their own
/// 5-line copy — all functionally identical, varying only in
/// return type (u32 / u64) and whether they NULL-check. This form
/// returns `usize` and is NULL-safe so it covers every prior
/// caller without churn.
inline duetos::usize StrLen(const char* s)
{
    if (s == nullptr)
    {
        return 0;
    }
    duetos::usize n = 0;
    while (s[n] != '\0')
    {
        ++n;
    }
    return n;
}

/// Lexicographic equality of two NUL-terminated C strings.
/// NULL-safe: two nullptrs (or the same pointer) compare equal;
/// one-nullptr-one-non-nullptr compares unequal. Replaces the
/// half-dozen ad-hoc `StrEqual` / `StrEqualLocal` / `LocalStrEq`
/// copies that used to live in `time/`, `security/`, `diag/`,
/// `debug/`, `subsystems/graphics/`, and `proc/` — all the same
/// loop, varying only in their NULL-handling and trailing check.
inline bool StrEqual(const char* a, const char* b)
{
    if (a == b)
    {
        return true;
    }
    if (a == nullptr || b == nullptr)
    {
        return false;
    }
    while (*a != '\0' && *b != '\0')
    {
        if (*a != *b)
        {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == *b;
}

/// Out-of-line panic helper for the bounds-checked wrappers. The
/// callers below invoke this when `__builtin_object_size` reports
/// a known destination size and `n` exceeds it. Out-of-line so
/// the inline call site stays small enough that the optimizer
/// happily inlines the wrapper itself.
[[noreturn]] void BoundsCheckedFailed(const char* op, duetos::usize requested, duetos::usize bound);

} // namespace duetos::core

// -----------------------------------------------------------------
// Bounds-checked wrappers.
//
// `MemcpyChecked(dst, src, n)` and `MemsetChecked(dst, c, n)` are
// drop-in replacements for memcpy/memset that consult
// `__builtin_object_size(dst, 1)` at compile time. When the
// destination's allocated size is statically known and `n` exceeds
// it, the call panics via `BoundsCheckedFailed` — catching a
// stack-buffer overflow at the call site rather than letting the
// kernel scribble past the bound.
//
// When the destination size is NOT statically known
// (`__builtin_object_size` returns SIZE_MAX), the check folds out
// and the wrapper is identical to plain memcpy/memset. This is the
// common case for heap pointers and pointers-into-larger-objects;
// the wrapper costs nothing in those situations.
//
// Use these for stack arrays, struct members, and any local where
// the destination's compile-time size is the load-bearing
// invariant. For raw-pointer parameters from caller-of-caller, the
// wrapper is no better than the underlying primitive — the static
// check is opt-in to the call site's context.
//
// Cost: one `__builtin_constant_p` check + one comparison in debug.
// In release with `-O2`+, the check folds entirely when the size
// is unknown OR when the call is provably safe; only known-unsafe
// calls retain the panic branch.
//
// Note: kAssertsEnabled doesn't gate this — bounds-checked memcpy
// is always-on because the static check has zero runtime cost when
// the bound is known to hold and infinite cost (a buffer overflow)
// when it doesn't. Skipping it in release would defeat the
// purpose.
// -----------------------------------------------------------------

namespace duetos::core
{

inline void* MemcpyChecked(void* dst, const void* src, duetos::usize n)
{
    const duetos::usize bound = __builtin_object_size(dst, 1);
    if (bound != static_cast<duetos::usize>(-1) && __builtin_expect(n > bound, 0))
    {
        BoundsCheckedFailed("memcpy", n, bound);
    }
    return memcpy(dst, src, n);
}

inline void* MemsetChecked(void* dst, int c, duetos::usize n)
{
    const duetos::usize bound = __builtin_object_size(dst, 1);
    if (bound != static_cast<duetos::usize>(-1) && __builtin_expect(n > bound, 0))
    {
        BoundsCheckedFailed("memset", n, bound);
    }
    return memset(dst, c, n);
}

inline void* MemmoveChecked(void* dst, const void* src, duetos::usize n)
{
    const duetos::usize bound = __builtin_object_size(dst, 1);
    if (bound != static_cast<duetos::usize>(-1) && __builtin_expect(n > bound, 0))
    {
        BoundsCheckedFailed("memmove", n, bound);
    }
    return memmove(dst, src, n);
}

} // namespace duetos::core
