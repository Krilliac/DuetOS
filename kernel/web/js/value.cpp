#include "web/js/value.h"

/*
 * DuetOS — kernel/web/js: tagged-number arithmetic + truthiness.
 *
 * Integers stay exact (i64) as long as the operation cannot overflow
 * 53 bits (the JS safe-integer range — beyond that, JS doubles lose
 * integer precision too, so falling to Sf32 there is acceptable). Any
 * fractional operand or out-of-range result promotes to Sf32.
 */

namespace duetos::web::js
{

using namespace duetos::core;

// Beyond +/-2^53 JS itself can't represent consecutive integers, so
// past this we drop to the soft-float path. Multiplication checks a
// tighter bound to avoid i64 overflow before the range test.
static constexpr i64 kSafeInt = (i64(1) << 53);

Sf32 NumberToSf32(const JsValue& v)
{
    if (v.type != JsType::Number)
        return Sf32QNaN();
    if (v.as.num.isInt)
    {
        const i64 n = v.as.num.ival;
        // Sf32FromI32 covers the common small-int range; for larger
        // magnitudes we lose precision but that's the documented GAP.
        if (n >= -2147483647LL && n <= 2147483647LL)
            return Sf32FromI32(i32(n));
        // Large integer: scale via two halves to keep it finite.
        const bool neg = n < 0;
        u64 mag = neg ? u64(-(n + 1)) + 1 : u64(n);
        Sf32 hi = Sf32FromU32(u32(mag >> 32));
        Sf32 two32 = Sf32FromBits(0x4F800000u); // 2^32
        Sf32 lo = Sf32FromU32(u32(mag & 0xFFFFFFFFu));
        Sf32 r = Sf32Add(Sf32Mul(hi, two32), lo);
        return neg ? Sf32Neg(r) : r;
    }
    return v.as.num.fval;
}

bool NumberAsI64(const JsValue& v, i64& out)
{
    if (v.type == JsType::Number && v.as.num.isInt)
    {
        out = v.as.num.ival;
        return true;
    }
    return false;
}

static bool BothInt(const JsValue& a, const JsValue& b, i64& x, i64& y)
{
    return NumberAsI64(a, x) && NumberAsI64(b, y);
}

JsValue NumAdd(const JsValue& a, const JsValue& b)
{
    i64 x, y;
    if (BothInt(a, b, x, y))
    {
        const i64 r = x + y;
        // overflow guard: if signs match but result sign flips, or
        // magnitude exceeds the safe range, fall to float.
        const bool overflow = ((x ^ r) & (y ^ r)) < 0;
        if (!overflow && r <= kSafeInt && r >= -kSafeInt)
            return JsValue::Int(r);
    }
    return JsValue::Float(Sf32Add(NumberToSf32(a), NumberToSf32(b)));
}

JsValue NumSub(const JsValue& a, const JsValue& b)
{
    i64 x, y;
    if (BothInt(a, b, x, y))
    {
        const i64 r = x - y;
        const bool overflow = ((x ^ y) & (x ^ r)) < 0;
        if (!overflow && r <= kSafeInt && r >= -kSafeInt)
            return JsValue::Int(r);
    }
    return JsValue::Float(Sf32Sub(NumberToSf32(a), NumberToSf32(b)));
}

JsValue NumMul(const JsValue& a, const JsValue& b)
{
    i64 x, y;
    if (BothInt(a, b, x, y))
    {
        // Only take the int path when the operands are small enough
        // that the product can't overflow i64 and stays safe-int.
        if (x > -3037000499LL && x < 3037000499LL && y > -3037000499LL && y < 3037000499LL)
        {
            const i64 r = x * y;
            if (r <= kSafeInt && r >= -kSafeInt)
                return JsValue::Int(r);
        }
    }
    return JsValue::Float(Sf32Mul(NumberToSf32(a), NumberToSf32(b)));
}

JsValue NumDiv(const JsValue& a, const JsValue& b)
{
    i64 x, y;
    if (BothInt(a, b, x, y) && y != 0 && (x % y) == 0)
        return JsValue::Int(x / y);
    return JsValue::Float(Sf32Div(NumberToSf32(a), NumberToSf32(b)));
}

JsValue NumMod(const JsValue& a, const JsValue& b)
{
    i64 x, y;
    if (BothInt(a, b, x, y) && y != 0)
        return JsValue::Int(x % y);
    // Float remainder: a - trunc(a/b)*b
    Sf32 fa = NumberToSf32(a), fb = NumberToSf32(b);
    Sf32 q = Sf32Div(fa, fb);
    // trunc toward zero
    i32 qi = Sf32ToI32(q);
    Sf32 prod = Sf32Mul(Sf32FromI32(qi), fb);
    return JsValue::Float(Sf32Sub(fa, prod));
}

JsValue NumNeg(const JsValue& a)
{
    i64 x;
    if (NumberAsI64(a, x))
        return JsValue::Int(-x);
    return JsValue::Float(Sf32Neg(NumberToSf32(a)));
}

bool NumIsNaN(const JsValue& v)
{
    return v.type == JsType::Number && !v.as.num.isInt && Sf32IsNaN(v.as.num.fval);
}

int NumCompare(const JsValue& a, const JsValue& b)
{
    if (NumIsNaN(a) || NumIsNaN(b))
        return 2;
    i64 x, y;
    if (BothInt(a, b, x, y))
        return x < y ? -1 : (x > y ? 1 : 0);
    Sf32 fa = NumberToSf32(a), fb = NumberToSf32(b);
    if (Sf32Equal(fa, fb))
        return 0;
    return Sf32LessThan(fa, fb) ? -1 : 1;
}

bool ToBoolean(const JsValue& v)
{
    switch (v.type)
    {
    case JsType::Undefined:
    case JsType::Null:
        return false;
    case JsType::Boolean:
        return v.as.boolean;
    case JsType::Number:
        if (v.as.num.isInt)
            return v.as.num.ival != 0;
        return !Sf32IsZero(v.as.num.fval) && !Sf32IsNaN(v.as.num.fval);
    case JsType::String:
        return v.as.str && v.as.str->len != 0;
    case JsType::Object:
    case JsType::Function:
        return true;
    }
    return false;
}

} // namespace duetos::web::js
