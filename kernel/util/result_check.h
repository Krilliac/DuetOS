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
 *      from `util/result.h`. Failure unwinds one stack frame and
 *      preserves the original source location (when DUETOS_RESULT_LOC
 *      is on).
 *
 *   2. LOG AND CONTINUE — caller cannot or should not propagate (e.g.
 *      a fire-and-forget background operation, a best-effort cleanup).
 *      Use `RESULT_LOG_AND_DROP(expr, klog_subsys, label)`. Emits one
 *      `KLOG_WARN_S` line with `err=<ErrorCodeName>` on failure plus
 *      an optional `KLOG_DEBUG_S` line carrying the origin file:line
 *      (gated by DUETOS_RESULT_LOC + the klog debug floor — release
 *      builds drop it; debug builds surface it for triage).
 *
 *   3. PANIC — failure indicates a kernel programmer bug, not a
 *      runtime condition (fixed pool exhausted at boot, registration
 *      table overflow, an invariant that the surrounding code is meant
 *      to guarantee). Use `RESULT_EXPECT(expr, panic_subsys, msg)`.
 *      Halts via `core::Panic`. Before panicking, fires the
 *      `kResultExpectFail` probe (so an attached GDB can break at the
 *      pre-panic frame) and emits an ERROR log line with the throw
 *      site's file:line when DUETOS_RESULT_LOC is on.
 *
 * These macros exist so a future audit can grep for the three policies
 * separately — `RESULT_TRY` (recoverable propagation), `RESULT_LOG_AND_DROP`
 * (intentional swallow with diagnostic trail), `RESULT_EXPECT` (must
 * never fail). Bare `(void)expr;` casts on Result returns are
 * discouraged: they pass the compiler but tell the next reader nothing.
 */

// Gate: fire the `kResultExpectFail` probe before Panic in
// RESULT_EXPECT. Default ON. The probe lives behind its own arm
// state (ArmedLog by default), so a clean boot stays quiet and an
// attached GDB can break at the throw site by `b duetos::debug::ProbeFire`.
// Set to 0 in builds where probes.h shouldn't be a dependency of
// result_check.h (e.g. very-early bring-up TUs).
#ifndef DUETOS_RESULT_PROBE
#define DUETOS_RESULT_PROBE 1
#endif

#if DUETOS_RESULT_PROBE
#include "debug/probes.h"
#define DUETOS_RESULT_PROBE_FIRE_(err_code)                                                                            \
    KBP_PROBE_V(::duetos::debug::ProbeId::kResultExpectFail, static_cast<::duetos::u64>(err_code))
#else
#define DUETOS_RESULT_PROBE_FIRE_(err_code) ((void)0)
#endif

// LOG AND CONTINUE. Evaluates `expr` once; on the error branch, emits a
// single `KLOG_WARN_S` line in `klog_subsys` carrying `label` and the
// error code name, plus a DEBUG-gated origin line when source-location
// capture is on. Use only when failure must not abort the surrounding
// flow but should still leave a trail in the boot log.
#define RESULT_LOG_AND_DROP(expr, klog_subsys, label)                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        auto _rld = (expr);                                                                                            \
        if (!_rld)                                                                                                     \
        {                                                                                                              \
            KLOG_WARN_S((klog_subsys), (label), "err", ::duetos::core::ErrorCodeName(_rld.error()));                   \
            const ::duetos::core::SourceLocation _rld_loc = _rld.location();                                           \
            if (_rld_loc.file != nullptr)                                                                              \
            {                                                                                                          \
                KLOG_DEBUG_S((klog_subsys), "  origin", "at", _rld_loc.file);                                          \
                KLOG_DEBUG_V((klog_subsys), "  origin line", static_cast<::duetos::u64>(_rld_loc.line));               \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

// PANIC ON FAILURE. Evaluates `expr` once; on the error branch, halts the
// CPU via `core::Panic` with `panic_subsys` and `msg`. Before panicking,
// surfaces the throw site's file:line (when DUETOS_RESULT_LOC is on) via
// an ERROR log line and fires the `kResultExpectFail` probe (when
// DUETOS_RESULT_PROBE is on) so an attached GDB can break ONE frame
// before Panic obliterates the stack. Use only when the failure
// indicates a kernel programmer bug — never for runtime conditions a
// real caller could produce.
#define RESULT_EXPECT(expr, panic_subsys, msg)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        auto _rex = (expr);                                                                                            \
        if (!_rex)                                                                                                     \
        {                                                                                                              \
            const ::duetos::core::SourceLocation _rex_loc = _rex.location();                                           \
            if (_rex_loc.file != nullptr)                                                                              \
            {                                                                                                          \
                KLOG_ERROR_S((panic_subsys), (msg), "at", _rex_loc.file);                                              \
                KLOG_ERROR_V((panic_subsys), "  origin line", static_cast<::duetos::u64>(_rex_loc.line));              \
            }                                                                                                          \
            KLOG_ERROR_S((panic_subsys), (msg), "err", ::duetos::core::ErrorCodeName(_rex.error()));                   \
            DUETOS_RESULT_PROBE_FIRE_(_rex.error());                                                                   \
            ::duetos::core::Panic((panic_subsys), (msg));                                                              \
        }                                                                                                              \
    } while (0)
