#pragma once

#include "util/result.h"
#include "web/js/arena.h"
#include "web/js/ast.h"
#include "web/js/object.h"
#include "web/js/value.h"

/*
 * DuetOS — kernel/web/js: interpreter internals shared by interp.cpp
 * and builtins.cpp. Not part of the public API (engine.h).
 *
 * NOTE on the local TRY macros below: the kernel-wide RESULT_TRY_ASSIGN
 * pastes a fixed `_resta___LINE__` identifier (it does NOT expand
 * __LINE__), so it can only appear once per scope. The interpreter
 * needs several propagations inside one scope (an expression with two
 * sub-evaluations, etc.), so we define JS_TRY / JS_TRY_ASSIGN that use
 * __COUNTER__ to mint a unique temporary name per use.
 */

// Two-level expansion so __COUNTER__ actually expands before paste.
#define JS_TRY_CAT2(a, b) a##b
#define JS_TRY_CAT(a, b) JS_TRY_CAT2(a, b)

// Inner forms take an already-unique temporary name so the expression
// is evaluated exactly once.
#define JS_TRY_IMPL(tmp, expr)                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        auto tmp = (expr);                                                                                             \
        if (!tmp)                                                                                                      \
            return ::duetos::core::Err{tmp.error(), tmp.location()};                                                   \
    } while (0)

#define JS_TRY_ASSIGN_IMPL(tmp, decl, expr)                                                                            \
    auto tmp = (expr);                                                                                                 \
    if (!tmp)                                                                                                          \
        return ::duetos::core::Err{tmp.error(), tmp.location()};                                                       \
    decl = tmp.take() // NOLINT(bugprone-macro-parentheses)

#define JS_TRY(expr) JS_TRY_IMPL(JS_TRY_CAT(_jstry_, __COUNTER__), expr)
#define JS_TRY_ASSIGN(decl, expr) JS_TRY_ASSIGN_IMPL(JS_TRY_CAT(_jsta_, __COUNTER__), decl, expr)

namespace duetos::web::js
{

using duetos::core::ErrorCode;
using duetos::core::Result;

// Append-only console buffer the interpreter writes into; the engine
// hands the final NUL-terminated contents back to the caller.
struct ConsoleBuf
{
    char* data;
    u32 cap;
    u32 len;

    void PutC(char c)
    {
        if (len + 1 < cap)
            data[len++] = c;
    }
    void Put(const char* s, u32 n)
    {
        for (u32 i = 0; i < n; ++i)
            PutC(s[i]);
    }
    void PutZ(const char* s);
};

// Completion signals propagated up the tree walk without C++
// exceptions (kernel: -fno-exceptions). Every Eval* returns a Result
// whose value is the completion; the Flow tells the statement loop
// whether to break/continue/return.
enum class Flow : u8
{
    Normal,
    Break,
    Continue,
    Return,
};

struct Interp
{
    Arena& arena;
    ConsoleBuf& console;
    Env* global;

    u64 stepBudget; // decremented each evaluated node; 0 => Timeout
    u32 depth;      // current call depth
    u32 maxDepth;

    // Set when a Flow::Return propagates so the caller can read it.
    JsValue returnValue;
    Flow flow;

    Interp(Arena& a, ConsoleBuf& c) : arena(a), console(c), global(nullptr) {}

    bool Tick()
    {
        if (stepBudget == 0)
            return false;
        --stepBudget;
        return true;
    }
};

// Evaluate an expression node to a value.
Result<JsValue> EvalExpr(Interp& I, const AstNode* n, Env* env);
// Evaluate a statement; sets I.flow / I.returnValue as needed. The
// returned value is the statement completion value (for ExprStmt).
Result<JsValue> EvalStmt(Interp& I, const AstNode* n, Env* env);
// Run a function/arrow body with bound params.
Result<JsValue> CallFunction(Interp& I, JsFunction* fn, const JsValue* args, u32 argc, const JsValue& thisArr);

// Builtins: install console/Math/parseInt/etc into the global env.
Result<void> InstallBuiltins(Interp& I);
// Dispatch a native function call by nativeId. `recvKind`/`recv`
// carry the method receiver for String/Array methods.
Result<JsValue> CallNative(Interp& I, u16 nativeId, const JsValue& recv, const JsValue* args, u32 argc);

// Resolve a member/method on a value (handles String.length,
// Array.length, builtin-object members, and String/Array methods by
// returning a bound native JsFunction). Returns Undefined for misses.
Result<JsValue> GetMember(Interp& I, const JsValue& obj, const char* key, u32 keyLen);

// ---- value <-> text ----
// Coerce any value to its JS string form into the arena.
JsString* ToJsString(Interp& I, const JsValue& v);
// Write a value's string form into a caller buffer (NUL-terminated).
u32 ValueToChars(const JsValue& v, char* out, u32 cap);
// Allocate an arena JsString from raw chars.
JsString* MakeString(Arena& a, const char* s, u32 n);

// Strict (===) and loose (==) equality.
bool StrictEquals(const JsValue& a, const JsValue& b);
bool LooseEquals(Interp& I, const JsValue& a, const JsValue& b);

// `typeof` operator string.
const char* TypeofString(const JsValue& v);

// Parse a numeric literal's fractional text into Sf32 (used by lexer
// fallback and parseFloat). Returns false if not a valid number.
bool ParseNumberText(const char* s, u32 len, bool& isInt, i64& iv, Sf32& fv);

} // namespace duetos::web::js
