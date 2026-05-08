#pragma once

#include "core/panic.h"
#include "util/build_config.h"
#include "util/types.h"

/*
 * DuetOS — debug-only assertion primitive.
 *
 * `DEBUG_ASSERT(cond, subsys, msg)` is a sibling to the existing
 * always-on `KASSERT` (see core/panic.h). The two complement each
 * other:
 *
 *   - KASSERT (panic.h) is for invariants whose violation is a
 *     security or stability hole that must be caught in every build.
 *     It panics on every flavor and is never compiled out.
 *
 *   - DEBUG_ASSERT (this file) is for invariants the engineer wants
 *     to verify during development BUT considers cheap-but-not-free
 *     enough that the optimizer should be allowed to strip them in
 *     a release image. Use it for:
 *       * inner-loop bounds checks where the surrounding code already
 *         validated the index but you want a belt-and-braces verify
 *         during development;
 *       * postconditions that hold by construction but document the
 *         intent for the next reader;
 *       * sanity checks downstream of a KASSERT-checked precondition,
 *         where the KASSERT already caught the only realistic failure
 *         mode and the DEBUG_ASSERT is just a noise reducer for
 *         future debuggers.
 *
 *     If the assertion fires, the failure is identical to KASSERT —
 *     it panics. The only difference is that release builds skip the
 *     check entirely. `cond` is NOT evaluated in release; side-effect-
 *     free conditions are mandatory.
 *
 * The `release-asserts` preset turns DEBUG_ASSERT back on while
 * keeping the optimizer at O2 — useful for paranoid production
 * builds where the cost of a dead branch on every assert site is
 * worth catching the invariant violation early.
 *
 * Context: kernel-only. Userland uses C library `assert()` (when we
 * have one).
 */

// -----------------------------------------------------------------
// DEBUG_ASSERT — predicate version. `cond` must be side-effect-free
// (it's not evaluated in release builds).
//
// `__builtin_expect(!(cond), 0)` biases the branch predictor toward
// the assertion holding. Combined with the `if constexpr` guard,
// release builds compile both the check AND the operand-evaluation
// out entirely — there is no static-branch left for DCE to clean up.
// -----------------------------------------------------------------
#define DEBUG_ASSERT(cond, subsys, msg)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if constexpr (::duetos::core::kAssertsEnabled)                                                                 \
        {                                                                                                              \
            if (__builtin_expect(!(cond), 0))                                                                          \
            {                                                                                                          \
                ::duetos::core::Panic((subsys), "DEBUG_ASSERT failed: " msg);                                          \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define DEBUG_ASSERT_VAL(cond, subsys, msg, value)                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if constexpr (::duetos::core::kAssertsEnabled)                                                                 \
        {                                                                                                              \
            if (__builtin_expect(!(cond), 0))                                                                          \
            {                                                                                                          \
                ::duetos::core::PanicWithValue((subsys), "DEBUG_ASSERT failed: " msg, (value));                        \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

/// Marks a code path as unreachable in correct builds. In debug,
/// firing this panics; in release, it executes `ud2` before telling
/// the optimizer control cannot continue. That keeps impossible-path
/// corruption fail-loud even when release assertions are compiled out.
///
/// Use this at the bottom of a switch on an exhaustive enum, or after
/// a guaranteed-noreturn call, to communicate "you can't get here" to
/// both readers and the optimizer.
#define DEBUG_UNREACHABLE(subsys, msg)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        if constexpr (::duetos::core::kAssertsEnabled)                                                                 \
        {                                                                                                              \
            ::duetos::core::Panic((subsys), "DEBUG_UNREACHABLE: " msg);                                                \
        }                                                                                                              \
        asm volatile("ud2" ::: "memory");                                                                              \
        __builtin_unreachable();                                                                                       \
    } while (0)
