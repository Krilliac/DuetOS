#include "web/js/interp.h"

#include "util/string.h"
#include "web/js/builtins.h"
#include "web/js/regexp.h"

/*
 * DuetOS — kernel/web/js: value <-> text conversion, equality, and
 * numeric-text parsing. Split out of interp.cpp to keep the tree-walker
 * (interp.cpp) focused purely on AST evaluation.
 *
 * Covers:
 *   - MakeString / ToJsString / ValueToChars  (value -> JS string)
 *   - TypeofString
 *   - StrictEquals / LooseEquals              (=== and == semantics)
 *   - ParseNumberText                          (numeric-literal parse)
 *
 * See value.h for the tagged-number (int / Sf32) model and its GAP.
 */

namespace duetos::web::js
{

using namespace duetos::core;

// ----------------------- string helpers -----------------------

JsString* MakeString(Arena& a, const char* s, u32 n)
{
    JsString* js = a.New<JsString>();
    if (!js)
        return nullptr;
    char* buf = static_cast<char*>(a.Alloc(n + 1, 1));
    if (!buf)
        return nullptr;
    for (u32 i = 0; i < n; ++i)
        buf[i] = s[i];
    buf[n] = '\0';
    js->data = buf;
    js->len = n;
    return js;
}

void ConsoleBuf::PutZ(const char* s)
{
    while (*s)
        PutC(*s++);
}

// Write an i64 as decimal. Returns chars written.
static u32 WriteI64(i64 v, char* out, u32 cap)
{
    if (cap == 0)
        return 0;
    char tmp[24];
    u32 t = 0;
    bool neg = v < 0;
    u64 mag = neg ? (u64(-(v + 1)) + 1) : u64(v);
    if (mag == 0)
        tmp[t++] = '0';
    while (mag)
    {
        tmp[t++] = char('0' + (mag % 10));
        mag /= 10;
    }
    u32 o = 0;
    if (neg && o < cap)
        out[o++] = '-';
    while (t && o < cap)
        out[o++] = tmp[--t];
    return o;
}

// Write an Sf32 in a simple fixed/decimal form. Not spec-exact (GAP)
// but readable: integer part + up to 6 fractional digits, trimmed.
static u32 WriteSf32(Sf32 v, char* out, u32 cap)
{
    if (Sf32IsNaN(v))
    {
        const char* s = "NaN";
        u32 i = 0;
        for (; s[i] && i < cap; ++i)
            out[i] = s[i];
        return i;
    }
    if (Sf32IsInf(v))
    {
        const char* s = Sf32IsNegative(v) ? "-Infinity" : "Infinity";
        u32 i = 0;
        for (; s[i] && i < cap; ++i)
            out[i] = s[i];
        return i;
    }
    u32 o = 0;
    bool neg = Sf32IsNegative(v) && !Sf32IsZero(v);
    if (neg && o < cap)
        out[o++] = '-';
    Sf32 a = Sf32Abs(v);
    i32 ip = Sf32ToI32(Sf32Floor(a));
    o += WriteI64(ip, out + o, cap - o);
    // fractional part
    Sf32 frac = Sf32Sub(a, Sf32Floor(a));
    if (!Sf32IsZero(frac))
    {
        if (o < cap)
            out[o++] = '.';
        Sf32 ten = Sf32FromI32(10);
        u32 digits = 0;
        // up to 6 digits, stop when frac becomes ~0
        while (digits < 6 && !Sf32IsZero(frac) && o < cap)
        {
            frac = Sf32Mul(frac, ten);
            i32 d = Sf32ToI32(Sf32Floor(frac));
            if (d < 0)
                d = 0;
            if (d > 9)
                d = 9;
            out[o++] = char('0' + d);
            frac = Sf32Sub(frac, Sf32FromI32(d));
            digits++;
        }
        // trim trailing zeros
        while (o > 0 && out[o - 1] == '0')
            o--;
        if (o > 0 && out[o - 1] == '.')
            o--;
    }
    return o;
}

// ----------------------- object-to-primitive -----------------------

// Is this value a primitive (i.e. not an object/array)? Functions count
// as objects for ToPrimitive but the engine never calls ToPrimitive on a
// bare function value, so treating only Object as the non-primitive case
// matches every reachable call site.
static bool IsPrimitive(const JsValue& v)
{
    return v.type != JsType::Object;
}

// Invoke a callable JsValue with the given receiver and no arguments,
// dispatching native / host-callback / JS-closure exactly as EvalCall
// does. Used to drive valueOf()/toString() during coercion.
static Result<JsValue> CallNullary(Interp& I, const JsValue& callee, const JsValue& recv)
{
    JsFunction* fn = callee.as.fn;
    if (fn->nativeId == kNativeCallback && fn->nativeCall)
        return fn->nativeCall(I, recv, nullptr, 0, fn->nativeCtx);
    if (fn->nativeId != 0)
        return CallNative(I, fn->nativeId, recv, nullptr, 0);
    return CallFunction(I, fn, nullptr, 0, recv);
}

// OrdinaryToPrimitive: for a "number"/default hint try valueOf() then
// toString(); for a "string" hint try toString() then valueOf(). The
// first method that exists, is callable, and returns a primitive wins.
// A non-object input is already primitive and returned unchanged.
//
// Lookup walks the prototype chain (GetMember -> GetMemberImpl), so a
// plain object with no own valueOf/toString still inherits them from
// Object.prototype: valueOf returns `this` (an object, skipped) and
// toString returns "[object Object]". Thus `obj + 1` now yields
// "[object Object]1" rather than NaN.
//
// GAP: no Symbol.toPrimitive (no Symbol keys), and a method that
// returns Err propagates rather than being skipped (the engine has no
// try/catch).
Result<JsValue> ToPrimitive(Interp& I, const JsValue& v, bool stringHint)
{
    if (IsPrimitive(v))
        return v;

    const char* order[2];
    if (stringHint)
    {
        order[0] = "toString";
        order[1] = "valueOf";
    }
    else
    {
        order[0] = "valueOf";
        order[1] = "toString";
    }

    for (u32 i = 0; i < 2; ++i)
    {
        const char* name = order[i];
        u32 nameLen = duetos::core::StrLen(name);
        JS_TRY_ASSIGN(JsValue method, GetMember(I, v, name, nameLen));
        if (!method.IsCallable())
            continue;
        JS_TRY_ASSIGN(JsValue r, CallNullary(I, method, v));
        if (IsPrimitive(r))
            return r;
    }

    // Both methods missing/non-callable/object-returning: fall back to
    // the engine's structural string form ("[object Object]" / joined
    // array) so a coercion never produces another object.
    return JsValue::Undefined();
}

u32 ValueToChars(const JsValue& v, char* out, u32 cap)
{
    if (cap == 0)
        return 0;
    auto lit = [&](const char* s) -> u32
    {
        u32 i = 0;
        for (; s[i] && i < cap; ++i)
            out[i] = s[i];
        return i;
    };
    switch (v.type)
    {
    case JsType::Undefined:
        return lit("undefined");
    case JsType::Null:
        return lit("null");
    case JsType::Boolean:
        return lit(v.as.boolean ? "true" : "false");
    case JsType::Number:
        if (v.as.num.isInt)
            return WriteI64(v.as.num.ival, out, cap);
        return WriteSf32(v.as.num.fval, out, cap);
    case JsType::String:
    {
        if (!v.as.str)
            return 0;
        u32 n = v.as.str->len < cap ? v.as.str->len : cap;
        for (u32 i = 0; i < n; ++i)
            out[i] = v.as.str->data[i];
        return n;
    }
    case JsType::Function:
        return lit("function");
    case JsType::Object:
    {
        if (v.as.obj && v.as.obj->isArray)
        {
            // join elements with ',' like Array.toString
            u32 o = 0;
            for (u32 i = 0; i < v.as.obj->length && o < cap; ++i)
            {
                if (i)
                    out[o++] = ',';
                o += ValueToChars(v.as.obj->elems[i], out + o, cap - o);
            }
            return o;
        }
        // A RegExp stringifies as /source/flags (its JsRegExp payload),
        // matching RegExp.prototype.toString.
        if (v.as.obj && v.as.obj->regexp)
        {
            const JsRegExp* re = v.as.obj->regexp;
            u32 o = 0;
            if (o < cap)
                out[o++] = '/';
            for (u32 i = 0; i < re->sourceLen && o < cap; ++i)
                out[o++] = re->source[i];
            if (o < cap)
                out[o++] = '/';
            for (u32 i = 0; i < re->flagsLen && o < cap; ++i)
                out[o++] = re->flags[i];
            return o;
        }
        return lit("[object Object]");
    }
    }
    return 0;
}

JsString* ToJsString(Interp& I, const JsValue& v)
{
    if (v.type == JsType::String)
        return v.as.str;
    // An object coerces through ToPrimitive (string hint): a user
    // valueOf()/toString() wins over the structural "[object Object]".
    // ToJsString has no Result channel, so a method error falls back to
    // the structural form rather than propagating.
    JsValue prim = v;
    if (v.type == JsType::Object)
    {
        Result<JsValue> p = ToPrimitive(I, v, /*stringHint=*/true);
        if (p && p.value().type != JsType::Undefined)
            prim = p.value();
    }
    if (prim.type == JsType::String)
        return prim.as.str;
    char buf[256];
    u32 n = ValueToChars(prim, buf, sizeof(buf));
    return MakeString(I.arena, buf, n);
}

const char* TypeofString(const JsValue& v)
{
    switch (v.type)
    {
    case JsType::Undefined:
        return "undefined";
    case JsType::Null:
        return "object"; // JS quirk
    case JsType::Boolean:
        return "boolean";
    case JsType::Number:
        return "number";
    case JsType::String:
        return "string";
    case JsType::Function:
        return "function";
    case JsType::Object:
        return "object";
    }
    return "undefined";
}

// ----------------------- equality -----------------------

static bool StrEq(const JsString* a, const JsString* b)
{
    if (a == b)
        return true;
    if (!a || !b || a->len != b->len)
        return false;
    for (u32 i = 0; i < a->len; ++i)
        if (a->data[i] != b->data[i])
            return false;
    return true;
}

bool StrictEquals(const JsValue& a, const JsValue& b)
{
    if (a.type != b.type)
        return false;
    switch (a.type)
    {
    case JsType::Undefined:
    case JsType::Null:
        return true;
    case JsType::Boolean:
        return a.as.boolean == b.as.boolean;
    case JsType::Number:
        return NumCompare(a, b) == 0;
    case JsType::String:
        return StrEq(a.as.str, b.as.str);
    case JsType::Object:
        return a.as.obj == b.as.obj;
    case JsType::Function:
        return a.as.fn == b.as.fn;
    }
    return false;
}

// Loose == with a documented coercion subset:
//   - null == undefined (and vice versa) -> true
//   - number vs string  -> string coerced to number
//   - boolean vs any    -> boolean coerced to number
//   - object vs primitive -> object coerced via ToPrimitive
//   - everything else falls back to ===.
bool LooseEquals(Interp& I, const JsValue& a, const JsValue& b)
{
    if (a.type == b.type)
        return StrictEquals(a, b);
    if ((a.type == JsType::Null && b.type == JsType::Undefined) ||
        (a.type == JsType::Undefined && b.type == JsType::Null))
        return true;

    // boolean -> number
    if (a.type == JsType::Boolean)
        return LooseEquals(I, JsValue::Int(a.as.boolean ? 1 : 0), b);
    if (b.type == JsType::Boolean)
        return LooseEquals(I, a, JsValue::Int(b.as.boolean ? 1 : 0));

    // number vs string
    if (a.type == JsType::Number && b.type == JsType::String)
    {
        bool isInt;
        i64 iv;
        Sf32 fv;
        if (ParseNumberText(b.as.str->data, b.as.str->len, isInt, iv, fv))
            return NumCompare(a, isInt ? JsValue::Int(iv) : JsValue::Float(fv)) == 0;
        return false;
    }
    if (a.type == JsType::String && b.type == JsType::Number)
        return LooseEquals(I, b, a);

    // object vs (number/string): coerce the object to a primitive
    // (default hint) and retry. null/undefined never == an object.
    if (a.type == JsType::Object && (b.type == JsType::Number || b.type == JsType::String))
    {
        Result<JsValue> p = ToPrimitive(I, a, /*stringHint=*/false);
        if (p && p.value().type != JsType::Undefined)
            return LooseEquals(I, p.value(), b);
        return false;
    }
    if (b.type == JsType::Object && (a.type == JsType::Number || a.type == JsType::String))
        return LooseEquals(I, b, a);

    return false;
}

// ----------------------- number-text parse -----------------------

bool ParseNumberText(const char* s, u32 len, bool& isInt, i64& iv, Sf32& fv)
{
    // trim leading/trailing whitespace
    u32 i = 0, e = len;
    while (i < e && (s[i] == ' ' || s[i] == '\t'))
        i++;
    while (e > i && (s[e - 1] == ' ' || s[e - 1] == '\t'))
        e--;
    if (i >= e)
        return false;

    bool neg = false;
    if (s[i] == '+' || s[i] == '-')
    {
        neg = (s[i] == '-');
        i++;
    }

    // hex
    if (e - i > 2 && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X'))
    {
        i64 v = 0;
        for (u32 k = i + 2; k < e; ++k)
        {
            char c = s[k];
            int d;
            if (c >= '0' && c <= '9')
                d = c - '0';
            else if (c >= 'a' && c <= 'f')
                d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                d = c - 'A' + 10;
            else
                return false;
            v = v * 16 + d;
        }
        isInt = true;
        iv = neg ? -v : v;
        return true;
    }

    bool sawDot = false, sawExp = false, sawDigit = false;
    i64 intPart = 0;
    Sf32 result = Sf32Zero();
    Sf32 scale = Sf32One();
    bool fractional = false;
    Sf32 fracAcc = Sf32Zero();
    Sf32 fracScale = Sf32One();
    Sf32 ten = Sf32FromI32(10);

    int expSign = 1;
    i64 expVal = 0;

    for (u32 k = i; k < e; ++k)
    {
        char c = s[k];
        if (c >= '0' && c <= '9')
        {
            sawDigit = true;
            if (sawExp)
                expVal = expVal * 10 + (c - '0');
            else if (sawDot)
            {
                fracScale = Sf32Div(fracScale, ten);
                fracAcc = Sf32Add(fracAcc, Sf32Mul(Sf32FromI32(c - '0'), fracScale));
                fractional = true;
            }
            else
            {
                intPart = intPart * 10 + (c - '0');
            }
        }
        else if (c == '.' && !sawDot && !sawExp)
        {
            sawDot = true;
        }
        else if ((c == 'e' || c == 'E') && !sawExp)
        {
            sawExp = true;
            if (k + 1 < e && (s[k + 1] == '+' || s[k + 1] == '-'))
            {
                expSign = (s[k + 1] == '-') ? -1 : 1;
                ++k;
            }
        }
        else
        {
            return false;
        }
    }
    if (!sawDigit)
        return false;

    (void)result;
    (void)scale;

    if (!sawDot && !sawExp && !fractional)
    {
        isInt = true;
        iv = neg ? -intPart : intPart;
        return true;
    }

    // float path
    Sf32 val = Sf32Add(Sf32FromI32(i32(intPart)), fracAcc);
    if (sawExp)
    {
        Sf32 factor = Sf32One();
        for (i64 q = 0; q < expVal; ++q)
            factor = Sf32Mul(factor, ten);
        if (expSign < 0)
            val = Sf32Div(val, factor);
        else
            val = Sf32Mul(val, factor);
    }
    if (neg)
        val = Sf32Neg(val);
    isInt = false;
    fv = val;
    return true;
}

} // namespace duetos::web::js
