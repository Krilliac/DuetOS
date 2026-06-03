#pragma once

#include "util/result.h"
#include "util/types.h"
#include "web/js/value.h"

/*
 * DuetOS — kernel/web/js: public engine API.
 *
 * A from-scratch tree-walking JavaScript interpreter CORE (language
 * only; DOM bindings are a later swarm). Evaluate a script, capture
 * its completion value and any `console.log` output.
 *
 * Bounded execution: every interpreter step decrements a budget. A
 * runaway script (`while(true){}`) hits the budget and returns
 * ErrorCode::Timeout instead of hanging the caller — CRITICAL for not
 * wedging the boot. Recursion depth is separately capped to bound the
 * native C++ stack.
 *
 * See value.h for the (tagged int / Sf32) number model and its GAP.
 */

namespace duetos::web::js
{

using duetos::core::ErrorCode;
using duetos::core::Result;

// Per-eval limits. Generous enough for the self-test battery, tight
// enough that a hostile loop dies in well under a scheduler tick.
inline constexpr u64 kDefaultStepBudget = 5'000'000;
inline constexpr u32 kMaxCallDepth = 200;

// Native (kernel) stack-overflow guard margin (bytes). The interpreter
// recurses on the C++ stack, so the kernel's 64 KiB arena stack — not
// kMaxCallDepth — is the true recursion limit: each JS call level costs
// several native frames (measured ~15 KiB in the debug build). When a JS
// eval runs on a kstack-arena slot, CallFunction returns Overflow once the
// current frame is within this many bytes of the slot's guard page, before
// a deep recursion can smash it. Must exceed one JS level's descent so the
// guard fires before the next check would land past the guard page.
// GAP: this makes deep JS recursion return Overflow rather than run; the
//      effective depth is shallow in debug (a few levels) and larger in
//      release (smaller frames). A heap-allocated interpreter stack, or
//      shrinking the per-level native frame, would lift the ceiling.
inline constexpr u64 kJsStackGuardMargin = 24u * 1024u;

// Total arena bytes the engine carves for one eval (tokens + AST +
// runtime values + console buffer headroom). Caller may pass its own.
inline constexpr u64 kDefaultArenaBytes = 512 * 1024;

struct EvalConfig
{
    u64 stepBudget = kDefaultStepBudget;
    u32 maxDepth = kMaxCallDepth;
};

/*
 * Evaluate `src` (length `len`). On success, *out receives the
 * completion value and `console_out` receives the captured
 * console.log output (NUL-terminated, truncated to console_cap-1).
 *
 * `scratch`/`scratchLen` is the arena backing store. If `scratch` is
 * null, the engine uses an internal static buffer (single-threaded
 * boot/self-test use only). Real concurrent callers must pass their
 * own buffer.
 *
 * Errors:
 *   InvalidArgument — lex/parse error (bad syntax)
 *   Timeout         — step budget exhausted (runaway script)
 *   Overflow        — call-depth limit hit (runaway recursion)
 *   OutOfMemory     — arena exhausted
 *   BadState        — a runtime type error (e.g. calling a non-fn)
 */
Result<void> JsEval(const char* src, u32 len, JsValue* out, char* console_out, u32 console_cap,
                    const EvalConfig& cfg = EvalConfig{}, u8* scratch = nullptr, u64 scratchLen = 0);

// Convenience for callers/tests that only want the console output and
// a coarse string form of the result. Writes the result's ToString
// into result_out (NUL-terminated, truncated).
Result<void> JsEvalToString(const char* src, u32 len, char* result_out, u32 result_cap, char* console_out,
                            u32 console_cap, const EvalConfig& cfg = EvalConfig{});

/*
 * Boot self-test. Evaluates a battery of snippets and asserts results
 * (arithmetic/precedence, closures, recursion, loops, string/array
 * methods, objects, ternary/logical short-circuit, typeof, ===vs==,
 * and the step-budget killing an infinite loop). Emits
 *   [js-selftest] PASS (N/N snippets)
 * on success; on any failure fires KBP_PROBE_V(kBootSelftestFail,...)
 * and emits a FAIL line. Wired into boot_bringup via
 * DUETOS_BOOT_SELFTEST after the browser/net self-tests.
 */
void JsSelfTest();

} // namespace duetos::web::js
