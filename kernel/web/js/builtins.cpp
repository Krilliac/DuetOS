#include "web/js/builtins.h"

#include "util/string.h"
#include "web/js/object.h"

/*
 * DuetOS — kernel/web/js: builtin functions and member resolution.
 *
 * GAP: JSON.parse is not implemented (returns undefined). JSON.stringify
 *      covers number/string/bool/null/array/flat-object; nested-object
 *      recursion is shallow-bounded by the step budget.
 * GAP: String/Array methods operate on ASCII; no Unicode awareness.
 */

namespace duetos::web::js
{

using namespace duetos::core;

// Helper: make a bound native JsFunction.
static JsValue NativeFnVal(Interp& I, u16 id, const char* name)
{
    JsFunction* fn = I.arena.New<JsFunction>();
    if (!fn)
        return JsValue::Undefined();
    fn->nativeId = id;
    fn->name = name;
    return JsValue::Fn(fn);
}

// Build a builtin namespace object (Math / JSON / console) holding
// native-fn properties.
static JsObject* MakeNamespace(Interp& I)
{
    return ObjNew(I.arena, false);
}

Result<void> InstallBuiltins(Interp& I)
{
    Arena& a = I.arena;
    Env* g = I.global;

    // console = { log: <native> }
    JsObject* console = MakeNamespace(I);
    if (!console)
        return Err{ErrorCode::OutOfMemory};
    ObjSet(console, a, "log", 3, NativeFnVal(I, kConsoleLog, "log"));
    EnvDefine(g, a, "console", 7, JsValue::Obj(console));

    // global free functions
    EnvDefine(g, a, "parseInt", 8, NativeFnVal(I, kParseInt, "parseInt"));
    EnvDefine(g, a, "parseFloat", 10, NativeFnVal(I, kParseFloat, "parseFloat"));
    EnvDefine(g, a, "isNaN", 5, NativeFnVal(I, kIsNaN, "isNaN"));

    // Math
    JsObject* math = MakeNamespace(I);
    if (!math)
        return Err{ErrorCode::OutOfMemory};
    ObjSet(math, a, "floor", 5, NativeFnVal(I, kMathFloor, "floor"));
    ObjSet(math, a, "ceil", 4, NativeFnVal(I, kMathCeil, "ceil"));
    ObjSet(math, a, "abs", 3, NativeFnVal(I, kMathAbs, "abs"));
    ObjSet(math, a, "max", 3, NativeFnVal(I, kMathMax, "max"));
    ObjSet(math, a, "min", 3, NativeFnVal(I, kMathMin, "min"));
    ObjSet(math, a, "pow", 3, NativeFnVal(I, kMathPow, "pow"));
    ObjSet(math, a, "sqrt", 4, NativeFnVal(I, kMathSqrt, "sqrt"));
    ObjSet(math, a, "round", 5, NativeFnVal(I, kMathRound, "round"));
    EnvDefine(g, a, "Math", 4, JsValue::Obj(math));

    // JSON
    JsObject* json = MakeNamespace(I);
    if (!json)
        return Err{ErrorCode::OutOfMemory};
    ObjSet(json, a, "stringify", 9, NativeFnVal(I, kJsonStringify, "stringify"));
    ObjSet(json, a, "parse", 5, NativeFnVal(I, kJsonParse, "parse"));
    EnvDefine(g, a, "JSON", 4, JsValue::Obj(json));

    return {};
}

// ----------------------- member resolution -----------------------

static bool NameEq(const char* a, u32 an, const char* lit)
{
    u32 ln = duetos::core::StrLen(lit);
    if (an != ln)
        return false;
    for (u32 i = 0; i < an; ++i)
        if (a[i] != lit[i])
            return false;
    return true;
}

Result<JsValue> GetMemberImpl(Interp& I, const JsValue& obj, const char* key, u32 keyLen)
{
    if (obj.type == JsType::String)
    {
        if (NameEq(key, keyLen, "length"))
            return JsValue::Int(obj.as.str ? i64(obj.as.str->len) : 0);
        if (NameEq(key, keyLen, "charAt"))
            return NativeFnVal(I, kStrCharAt, "charAt");
        if (NameEq(key, keyLen, "indexOf"))
            return NativeFnVal(I, kStrIndexOf, "indexOf");
        if (NameEq(key, keyLen, "slice"))
            return NativeFnVal(I, kStrSlice, "slice");
        if (NameEq(key, keyLen, "toUpperCase"))
            return NativeFnVal(I, kStrToUpper, "toUpperCase");
        if (NameEq(key, keyLen, "toLowerCase"))
            return NativeFnVal(I, kStrToLower, "toLowerCase");
        if (NameEq(key, keyLen, "split"))
            return NativeFnVal(I, kStrSplit, "split");
        return JsValue::Undefined();
    }
    if (obj.type == JsType::Object)
    {
        JsObject* o = obj.as.obj;
        // Host objects (DOM elements) resolve members through their C++
        // hook first. A non-Undefined result wins; Undefined falls
        // through so an ad-hoc JS property set on the host object (or a
        // shared method below) can still be read.
        if (o->hostGet)
        {
            Result<JsValue> hr = o->hostGet(I, o, key, keyLen);
            if (!hr)
                return hr;
            if (hr.value().type != JsType::Undefined)
                return hr.value();
        }
        if (o->isArray)
        {
            if (NameEq(key, keyLen, "length"))
                return JsValue::Int(i64(o->length));
            if (NameEq(key, keyLen, "push"))
                return NativeFnVal(I, kArrPush, "push");
            if (NameEq(key, keyLen, "pop"))
                return NativeFnVal(I, kArrPop, "pop");
            if (NameEq(key, keyLen, "join"))
                return NativeFnVal(I, kArrJoin, "join");
            if (NameEq(key, keyLen, "indexOf"))
                return NativeFnVal(I, kArrIndexOf, "indexOf");
            if (NameEq(key, keyLen, "map"))
                return NativeFnVal(I, kArrMap, "map");
            if (NameEq(key, keyLen, "filter"))
                return NativeFnVal(I, kArrFilter, "filter");
            if (NameEq(key, keyLen, "forEach"))
                return NativeFnVal(I, kArrForEach, "forEach");
        }
        JsValue v{};
        if (ObjGet(o, key, keyLen, v))
            return v;
        return JsValue::Undefined();
    }
    return JsValue::Undefined();
}

// ----------------------- native dispatch -----------------------

static JsValue ArgOr(const JsValue* args, u32 argc, u32 i)
{
    return i < argc ? args[i] : JsValue::Undefined();
}

// ToInteger: number -> i64 (truncate), else parse string / NaN -> 0.
static i64 ToInt(const JsValue& v)
{
    if (v.type == JsType::Number)
    {
        if (v.as.num.isInt)
            return v.as.num.ival;
        return Sf32ToI32(v.as.num.fval);
    }
    return 0;
}

// Lenient base-10 integer prefix parse for parseInt: skip leading
// whitespace, optional sign, consume the leading run of digits, ignore
// any trailing garbage ("42px" -> 42). Returns false (NaN) only when
// no digits are present. GAP: radix argument, 0x prefix detection.
static bool ParseIntPrefix(const char* s, u32 len, i64& out)
{
    u32 i = 0;
    while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n'))
        ++i;
    bool neg = false;
    if (i < len && (s[i] == '+' || s[i] == '-'))
    {
        neg = (s[i] == '-');
        ++i;
    }
    if (i >= len || s[i] < '0' || s[i] > '9')
        return false;
    i64 v = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9')
    {
        v = v * 10 + (s[i] - '0');
        ++i;
    }
    out = neg ? -v : v;
    return true;
}

// Lenient leading-number prefix parse for parseFloat: consume the
// longest leading numeric run (digits, one dot, optional exponent),
// ignore trailing garbage. Delegates the numeric conversion to
// ParseNumberText on the trimmed prefix.
static bool ParseFloatPrefix(const char* s, u32 len, bool& isInt, i64& iv, Sf32& fv)
{
    u32 i = 0;
    while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n'))
        ++i;
    u32 start = i;
    if (i < len && (s[i] == '+' || s[i] == '-'))
        ++i;
    bool sawDigit = false, sawDot = false, sawExp = false;
    while (i < len)
    {
        char c = s[i];
        if (c >= '0' && c <= '9')
        {
            sawDigit = true;
            ++i;
        }
        else if (c == '.' && !sawDot && !sawExp)
        {
            sawDot = true;
            ++i;
        }
        else if ((c == 'e' || c == 'E') && sawDigit && !sawExp)
        {
            sawExp = true;
            ++i;
            if (i < len && (s[i] == '+' || s[i] == '-'))
                ++i;
        }
        else
        {
            break;
        }
    }
    if (!sawDigit)
        return false;
    return ParseNumberText(s + start, i - start, isInt, iv, fv);
}

static Result<JsValue> ConsoleLog(Interp& I, const JsValue* args, u32 argc)
{
    char buf[256];
    for (u32 i = 0; i < argc; ++i)
    {
        if (i)
            I.console.PutC(' ');
        u32 n = ValueToChars(args[i], buf, sizeof(buf));
        I.console.Put(buf, n);
    }
    I.console.PutC('\n');
    return JsValue::Undefined();
}

static Result<JsValue> StrCharAt(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    const JsString* s = recv.as.str;
    i64 idx = ToInt(ArgOr(args, argc, 0));
    if (!s || idx < 0 || idx >= i64(s->len))
        return JsValue::Str(MakeString(I.arena, "", 0));
    char c = s->data[idx];
    return JsValue::Str(MakeString(I.arena, &c, 1));
}

static Result<JsValue> StrIndexOf(Interp&, const JsValue& recv, const JsValue* args, u32 argc)
{
    const JsString* s = recv.as.str;
    JsValue n = ArgOr(args, argc, 0);
    if (!s || n.type != JsType::String)
        return JsValue::Int(-1);
    const JsString* needle = n.as.str;
    if (needle->len == 0)
        return JsValue::Int(0);
    if (needle->len > s->len)
        return JsValue::Int(-1);
    for (u32 i = 0; i + needle->len <= s->len; ++i)
    {
        bool eq = true;
        for (u32 j = 0; j < needle->len; ++j)
            if (s->data[i + j] != needle->data[j])
            {
                eq = false;
                break;
            }
        if (eq)
            return JsValue::Int(i64(i));
    }
    return JsValue::Int(-1);
}

static Result<JsValue> StrSlice(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    const JsString* s = recv.as.str;
    if (!s)
        return JsValue::Str(MakeString(I.arena, "", 0));
    i64 len = i64(s->len);
    i64 start = ToInt(ArgOr(args, argc, 0));
    i64 end = argc >= 2 ? ToInt(args[1]) : len;
    if (start < 0)
        start = len + start;
    if (end < 0)
        end = len + end;
    if (start < 0)
        start = 0;
    if (end > len)
        end = len;
    if (start >= end)
        return JsValue::Str(MakeString(I.arena, "", 0));
    return JsValue::Str(MakeString(I.arena, s->data + start, u32(end - start)));
}

static Result<JsValue> StrCase(Interp& I, const JsValue& recv, bool upper)
{
    const JsString* s = recv.as.str;
    if (!s)
        return JsValue::Str(MakeString(I.arena, "", 0));
    char* buf = static_cast<char*>(I.arena.Alloc(s->len + 1, 1));
    if (!buf)
        return Err{ErrorCode::OutOfMemory};
    for (u32 i = 0; i < s->len; ++i)
    {
        char c = s->data[i];
        if (upper && c >= 'a' && c <= 'z')
            c = char(c - 32);
        else if (!upper && c >= 'A' && c <= 'Z')
            c = char(c + 32);
        buf[i] = c;
    }
    buf[s->len] = '\0';
    return JsValue::Str(MakeString(I.arena, buf, s->len));
}

static Result<JsValue> StrSplit(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    const JsString* s = recv.as.str;
    JsObject* arr = ObjNew(I.arena, true);
    if (!arr || !s)
        return JsValue::Obj(arr);
    JsValue sep = ArgOr(args, argc, 0);
    if (sep.type != JsType::String || sep.as.str->len == 0)
    {
        // split("") -> each char; split(undefined) -> whole string
        if (sep.type == JsType::String && sep.as.str->len == 0)
        {
            for (u32 i = 0; i < s->len; ++i)
                ArrPush(arr, I.arena, JsValue::Str(MakeString(I.arena, s->data + i, 1)));
        }
        else
        {
            ArrPush(arr, I.arena, JsValue::Str(MakeString(I.arena, s->data, s->len)));
        }
        return JsValue::Obj(arr);
    }
    const JsString* d = sep.as.str;
    u32 start = 0;
    for (u32 i = 0; i + d->len <= s->len;)
    {
        bool eq = true;
        for (u32 j = 0; j < d->len; ++j)
            if (s->data[i + j] != d->data[j])
            {
                eq = false;
                break;
            }
        if (eq)
        {
            ArrPush(arr, I.arena, JsValue::Str(MakeString(I.arena, s->data + start, i - start)));
            i += d->len;
            start = i;
        }
        else
        {
            ++i;
        }
    }
    ArrPush(arr, I.arena, JsValue::Str(MakeString(I.arena, s->data + start, s->len - start)));
    return JsValue::Obj(arr);
}

static Result<JsValue> ArrJoin(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    JsObject* arr = recv.as.obj;
    JsValue sepV = ArgOr(args, argc, 0);
    const char* sep = ",";
    u32 sepLen = 1;
    if (sepV.type == JsType::String)
    {
        sep = sepV.as.str->data;
        sepLen = sepV.as.str->len;
    }
    char out[512];
    u32 o = 0;
    for (u32 i = 0; i < arr->length && o < sizeof(out); ++i)
    {
        if (i)
            for (u32 k = 0; k < sepLen && o < sizeof(out); ++k)
                out[o++] = sep[k];
        o += ValueToChars(arr->elems[i], out + o, u32(sizeof(out)) - o);
    }
    return JsValue::Str(MakeString(I.arena, out, o));
}

static Result<JsValue> ArrIndexOf(Interp&, const JsValue& recv, const JsValue* args, u32 argc)
{
    JsObject* arr = recv.as.obj;
    JsValue target = ArgOr(args, argc, 0);
    for (u32 i = 0; i < arr->length; ++i)
        if (StrictEquals(arr->elems[i], target))
            return JsValue::Int(i64(i));
    return JsValue::Int(-1);
}

// Array higher-order helpers — invoke a user callback per element.
static Result<JsValue> ArrHof(Interp& I, const JsValue& recv, const JsValue* args, u32 argc, u16 which)
{
    JsObject* arr = recv.as.obj;
    JsValue cbv = ArgOr(args, argc, 0);
    if (!cbv.IsCallable())
        return Err{ErrorCode::BadState};
    JsFunction* cb = cbv.as.fn;

    JsObject* result = nullptr;
    if (which == kArrMap || which == kArrFilter)
    {
        result = ObjNew(I.arena, true);
        if (!result)
            return Err{ErrorCode::OutOfMemory};
    }
    for (u32 i = 0; i < arr->length; ++i)
    {
        JsValue cbArgs[2] = {arr->elems[i], JsValue::Int(i64(i))};
        Result<JsValue> r = CallFunction(I, cb, cbArgs, 2, JsValue::Undefined());
        if (!r)
            return r;
        JsValue rv = r.value();
        if (which == kArrMap)
            ArrPush(result, I.arena, rv);
        else if (which == kArrFilter)
        {
            if (ToBoolean(rv))
                ArrPush(result, I.arena, arr->elems[i]);
        }
        // forEach: discard
    }
    if (which == kArrMap || which == kArrFilter)
        return JsValue::Obj(result);
    return JsValue::Undefined();
}

// JSON.stringify (shallow + flat objects/arrays). GAP: nested objects
// recurse but cycle detection is absent (the step budget bounds it).
static u32 JsonStr(Interp& I, const JsValue& v, char* out, u32 cap);

static u32 JsonStrEscaped(const JsString* s, char* out, u32 cap)
{
    u32 o = 0;
    if (o < cap)
        out[o++] = '"';
    for (u32 i = 0; i < s->len && o + 2 < cap; ++i)
    {
        char c = s->data[i];
        if (c == '"' || c == '\\')
        {
            out[o++] = '\\';
            out[o++] = c;
        }
        else if (c == '\n')
        {
            out[o++] = '\\';
            out[o++] = 'n';
        }
        else
            out[o++] = c;
    }
    if (o < cap)
        out[o++] = '"';
    return o;
}

static u32 JsonStr(Interp& I, const JsValue& v, char* out, u32 cap)
{
    if (cap == 0)
        return 0;
    switch (v.type)
    {
    case JsType::Null:
    case JsType::Undefined:
    {
        const char* s = "null";
        u32 i = 0;
        for (; s[i] && i < cap; ++i)
            out[i] = s[i];
        return i;
    }
    case JsType::Boolean:
    case JsType::Number:
        return ValueToChars(v, out, cap);
    case JsType::String:
        return JsonStrEscaped(v.as.str, out, cap);
    case JsType::Object:
    {
        JsObject* o = v.as.obj;
        u32 used = 0;
        if (o->isArray)
        {
            out[used++] = '[';
            for (u32 i = 0; i < o->length && used < cap; ++i)
            {
                if (i && used < cap)
                    out[used++] = ',';
                used += JsonStr(I, o->elems[i], out + used, cap - used);
            }
            if (used < cap)
                out[used++] = ']';
            return used;
        }
        out[used++] = '{';
        bool first = true;
        for (PropChunk* c = o->head; c; c = c->next)
        {
            for (u32 i = 0; i < PropChunk::kSlots; ++i)
            {
                if (!c->slots[i].used)
                    continue;
                if (!first && used < cap)
                    out[used++] = ',';
                first = false;
                JsString tmp{c->slots[i].key, c->slots[i].keyLen};
                used += JsonStrEscaped(&tmp, out + used, cap - used);
                if (used < cap)
                    out[used++] = ':';
                used += JsonStr(I, c->slots[i].value, out + used, cap - used);
            }
        }
        if (used < cap)
            out[used++] = '}';
        return used;
    }
    default:
        return 0;
    }
}

Result<JsValue> CallNative(Interp& I, u16 id, const JsValue& recv, const JsValue* args, u32 argc)
{
    switch (id)
    {
    case kConsoleLog:
        return ConsoleLog(I, args, argc);

    case kParseInt:
    {
        JsValue v = ArgOr(args, argc, 0);
        if (v.type == JsType::Number)
            return JsValue::Int(ToInt(v));
        if (v.type == JsType::String)
        {
            i64 iv;
            if (ParseIntPrefix(v.as.str->data, v.as.str->len, iv))
                return JsValue::Int(iv);
        }
        return JsValue::Float(Sf32QNaN());
    }
    case kParseFloat:
    {
        JsValue v = ArgOr(args, argc, 0);
        if (v.type == JsType::Number)
            return v;
        if (v.type == JsType::String)
        {
            bool isInt;
            i64 iv;
            Sf32 fv;
            if (ParseFloatPrefix(v.as.str->data, v.as.str->len, isInt, iv, fv))
                return isInt ? JsValue::Int(iv) : JsValue::Float(fv);
        }
        return JsValue::Float(Sf32QNaN());
    }
    case kIsNaN:
    {
        JsValue v = ArgOr(args, argc, 0);
        return JsValue::Bool(NumIsNaN(v) || v.type != JsType::Number);
    }

    case kMathFloor:
    {
        JsValue v = ArgOr(args, argc, 0);
        if (v.IsNumber() && v.as.num.isInt)
            return v;
        return JsValue::Int(Sf32ToI32(Sf32Floor(NumberToSf32(v))));
    }
    case kMathCeil:
    {
        JsValue v = ArgOr(args, argc, 0);
        if (v.IsNumber() && v.as.num.isInt)
            return v;
        return JsValue::Int(Sf32ToI32(Sf32Ceil(NumberToSf32(v))));
    }
    case kMathRound:
    {
        JsValue v = ArgOr(args, argc, 0);
        if (v.IsNumber() && v.as.num.isInt)
            return v;
        return JsValue::Int(Sf32ToI32(Sf32Round(NumberToSf32(v))));
    }
    case kMathAbs:
    {
        JsValue v = ArgOr(args, argc, 0);
        if (v.IsNumber() && v.as.num.isInt)
            return JsValue::Int(v.as.num.ival < 0 ? -v.as.num.ival : v.as.num.ival);
        return JsValue::Float(Sf32Abs(NumberToSf32(v)));
    }
    case kMathMax:
    case kMathMin:
    {
        if (argc == 0)
            return JsValue::Float(id == kMathMax ? Sf32Neg(Sf32Inf()) : Sf32Inf());
        JsValue best = args[0];
        for (u32 i = 1; i < argc; ++i)
        {
            int cmp = NumCompare(args[i], best);
            if ((id == kMathMax && cmp > 0) || (id == kMathMin && cmp < 0))
                best = args[i];
        }
        return best;
    }
    case kMathPow:
    {
        JsValue b = ArgOr(args, argc, 0);
        JsValue e = ArgOr(args, argc, 1);
        // exact integer fast-path for small non-negative exponents
        if (b.IsNumber() && b.as.num.isInt && e.IsNumber() && e.as.num.isInt && e.as.num.ival >= 0 &&
            e.as.num.ival < 31)
        {
            i64 r = 1;
            for (i64 k = 0; k < e.as.num.ival; ++k)
                r *= b.as.num.ival;
            return JsValue::Int(r);
        }
        return JsValue::Float(Sf32Pow(NumberToSf32(b), NumberToSf32(e)));
    }
    case kMathSqrt:
        return JsValue::Float(Sf32Sqrt(NumberToSf32(ArgOr(args, argc, 0))));

    case kStrCharAt:
        return StrCharAt(I, recv, args, argc);
    case kStrIndexOf:
        return StrIndexOf(I, recv, args, argc);
    case kStrSlice:
        return StrSlice(I, recv, args, argc);
    case kStrToUpper:
        return StrCase(I, recv, true);
    case kStrToLower:
        return StrCase(I, recv, false);
    case kStrSplit:
        return StrSplit(I, recv, args, argc);

    case kArrPush:
    {
        for (u32 i = 0; i < argc; ++i)
            if (!ArrPush(recv.as.obj, I.arena, args[i]))
                return Err{ErrorCode::OutOfMemory};
        return JsValue::Int(i64(recv.as.obj->length));
    }
    case kArrPop:
    {
        JsObject* arr = recv.as.obj;
        if (arr->length == 0)
            return JsValue::Undefined();
        JsValue v = arr->elems[--arr->length];
        return v;
    }
    case kArrJoin:
        return ArrJoin(I, recv, args, argc);
    case kArrIndexOf:
        return ArrIndexOf(I, recv, args, argc);
    case kArrMap:
        return ArrHof(I, recv, args, argc, kArrMap);
    case kArrFilter:
        return ArrHof(I, recv, args, argc, kArrFilter);
    case kArrForEach:
        return ArrHof(I, recv, args, argc, kArrForEach);

    case kJsonStringify:
    {
        char out[1024];
        u32 n = JsonStr(I, ArgOr(args, argc, 0), out, sizeof(out));
        return JsValue::Str(MakeString(I.arena, out, n));
    }
    case kJsonParse:
        // GAP: JSON.parse is not implemented.
        return JsValue::Undefined();

    default:
        return Err{ErrorCode::Unsupported};
    }
}

} // namespace duetos::web::js
