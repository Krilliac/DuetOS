#pragma once

#include "util/soft_float.h"
#include "util/types.h"

/*
 * DuetOS — kernel/web/js: the JS value model.
 *
 * NUMBER REPRESENTATION (important):
 *   The kernel is built -mno-sse -mno-80387 -mgeneral-regs-only, so
 *   hardware `double`/`float` are unavailable. JS specifies all
 *   numbers as IEEE-754 binary64. We do NOT have a soft-f64 library
 *   (only `Sf32` in util/soft_float.h), so JsNumber is a TAGGED
 *   number: an exact i64 when the value is integral and fits in
 *   53 bits, otherwise a 32-bit soft-float (`Sf32`).
 *
 *   This keeps every integer-valued program exact (loop sums,
 *   factorial, array indices, comparisons, bitwise-free arithmetic)
 *   and degrades gracefully to ~7 significant digits for fractional
 *   results (Math.sqrt, division with a remainder, etc.).
 *
 *   GAP: full IEEE-754 binary64 precision. Fractional values carry
 *   binary32 precision, not binary64. -0, subnormal edge cases, and
 *   the exact ToString of irrational results differ from V8. Revisit
 *   when a soft-f64 library lands.
 *
 * Strings, objects, arrays, and functions are arena-allocated and
 * referred to by pointer. JsValue is a small trivially-copyable tag +
 * union, safe to pass by value and store in the arena.
 */

namespace duetos::web::js
{

using duetos::core::Sf32;

class Arena;
struct JsObject;
struct AstNode;
struct Env;

enum class JsType : u8
{
    Undefined = 0,
    Null,
    Boolean,
    Number,
    String,
    Object, // plain object OR array (JsObject::isArray distinguishes)
    Function,
};

// A heap string: length-prefixed, arena-allocated, NUL-terminated for
// convenience. Not interned.
struct JsString
{
    const char* data; // arena-owned, NUL-terminated
    u32 len;
};

// A closure: an AST function/arrow node + the lexical environment it
// captured at definition time.
struct JsFunction
{
    const AstNode* node; // FunctionExpr / ArrowExpr / FunctionDecl body
    Env* closure;        // captured environment (lexical scope chain)
    // Native builtins set `native` non-null and ignore node/closure.
    // The dispatcher (NativeId) selects which C++ routine runs.
    u16 nativeId; // 0 == not native; see builtins.h NativeFn enum
    const char* name;
};

struct JsValue
{
    JsType type;

    union
    {
        bool boolean;
        struct
        {
            bool isInt; // true: use ival; false: use fval (Sf32)
            i64 ival;   // exact integer payload
            Sf32 fval;  // soft-float payload for fractional values
        } num;
        JsString* str;
        JsObject* obj; // Object or Array
        JsFunction* fn;
    } as;

    // ---- constructors (value semantics) ----
    static JsValue Undefined()
    {
        JsValue v{};
        v.type = JsType::Undefined;
        return v;
    }
    static JsValue Null()
    {
        JsValue v{};
        v.type = JsType::Null;
        return v;
    }
    static JsValue Bool(bool b)
    {
        JsValue v{};
        v.type = JsType::Boolean;
        v.as.boolean = b;
        return v;
    }
    static JsValue Int(i64 n)
    {
        JsValue v{};
        v.type = JsType::Number;
        v.as.num.isInt = true;
        v.as.num.ival = n;
        return v;
    }
    static JsValue Float(Sf32 f)
    {
        JsValue v{};
        v.type = JsType::Number;
        v.as.num.isInt = false;
        v.as.num.fval = f;
        return v;
    }
    static JsValue Str(JsString* s)
    {
        JsValue v{};
        v.type = JsType::String;
        v.as.str = s;
        return v;
    }
    static JsValue Obj(JsObject* o)
    {
        JsValue v{};
        v.type = JsType::Object;
        v.as.obj = o;
        return v;
    }
    static JsValue Fn(JsFunction* f)
    {
        JsValue v{};
        v.type = JsType::Function;
        v.as.fn = f;
        return v;
    }

    bool IsNumber() const { return type == JsType::Number; }
    bool IsCallable() const { return type == JsType::Function; }
};

// -------- number helpers (the tagged-number arithmetic core) --------

// Promote a tagged number to Sf32 (lossy for large integers, fine for
// the fractional fallback path).
Sf32 NumberToSf32(const JsValue& v);

// Pull a number out as f64-ish double via i64 when integral. Used by
// comparison / ToInteger paths that want a single ordering.
// Returns true if both operands compared as integers (exact path).
bool NumberAsI64(const JsValue& v, i64& out);

// Arithmetic on two JS numbers, honoring the int-fast-path: if both
// are integers and the op stays integral & in range, result is Int;
// otherwise falls back to Sf32.
JsValue NumAdd(const JsValue& a, const JsValue& b);
JsValue NumSub(const JsValue& a, const JsValue& b);
JsValue NumMul(const JsValue& a, const JsValue& b);
JsValue NumDiv(const JsValue& a, const JsValue& b);
JsValue NumMod(const JsValue& a, const JsValue& b);
JsValue NumNeg(const JsValue& a);

// Number ordering: -1 a<b, 0 a==b, 1 a>b, 2 unordered (NaN).
int NumCompare(const JsValue& a, const JsValue& b);

// True if the number is NaN (only fval can be NaN; ints never are).
bool NumIsNaN(const JsValue& v);

// Truthiness per JS: 0/NaN/""/null/undefined/false are falsy.
bool ToBoolean(const JsValue& v);

} // namespace duetos::web::js
