#pragma once

#include "core/panic.h"
#include "log/klog.h"
#include "util/result.h"

/*
 * DuetOS — Result<T,E> handling policies.
 *
 * `Result<T,E>` is marked `[[nodiscard]]`, so every fallible call must
 * choose one of three policies for the returned status:
 *
 *   1. PROPAGATE — caller is also Result-returning. Use the existing
 *      `RESULT_TRY(expr)` / `RESULT_TRY_ASSIGN(decl, expr)` macros
 *      from `util/result.h`. Failure unwinds one stack frame.
 *
 *   2. LOG AND CONTINUE — caller cannot or should not propagate (e.g.
 *      a fire-and-forget background operation, a best-effort cleanup).
 *      Use `RESULT_LOG_AND_DROP(expr, klog_subsys, label)`. Emits one
 *      `KLOG_WARN_S` line with `err=<ErrorCodeName>` on failure and
 *      otherwise drops the result silently.
 *
 *   3. PANIC — failure indicates a kernel programmer bug, not a
 *      runtime condition (fixed pool exhausted at boot, registration
 *      table overflow, an invariant that the surrounding code is meant
 *      to guarantee). Use `RESULT_EXPECT(expr, panic_subsys, msg)`.
 *      Halts via `core::Panic` with the error code name appended to
 *      the supplied message.
 *
 * These macros exist so a future audit can grep for the three policies
 * separately — `RESULT_TRY` (recoverable propagation), `RESULT_LOG_AND_DROP`
 * (intentional swallow with diagnostic trail), `RESULT_EXPECT` (must
 * never fail). Bare `(void)expr;` casts on Result returns are
 * discouraged: they pass the compiler but tell the next reader nothing.
 */

// LOG AND CONTINUE. Evaluates `expr` once; on the error branch, emits a
// single `KLOG_WARN_S` line in `klog_subsys` carrying `label` and the
// error code name. Use only when failure must not abort the surrounding
// flow but should still leave a trail in the boot log.
#define RESULT_LOG_AND_DROP(expr, klog_subsys, label)                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        auto _rld = (expr);                                                                                            \
        if (!_rld)                                                                                                     \
            KLOG_WARN_S((klog_subsys), (label), "err", ::duetos::core::ErrorCodeName(_rld.error()));                   \
    } while (0)

// PANIC ON FAILURE. Evaluates `expr` once; on the error branch, halts the
// CPU via `core::Panic` with `panic_subsys` and `msg` followed by the
// error code name. Use only when the failure indicates a kernel
// programmer bug — never for runtime conditions a real caller could
// produce.
#define RESULT_EXPECT(expr, panic_subsys, msg)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        auto _rex = (expr);                                                                                            \
        if (!_rex)                                                                                                     \
            ::duetos::core::Panic((panic_subsys), (msg));                                                              \
    } while (0)
