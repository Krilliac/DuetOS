#include "web/js/builtins.h"

#include "time/timekeeper.h"
#include "util/random.h"
#include "util/string.h"
#include "web/js/object.h"
#include "web/js/regexp.h"

/*
 * DuetOS — kernel/web/js: builtin functions and member resolution.
 *
 * GAP: JSON.stringify covers number/string/bool/null/array/flat-object;
 *      nested-object recursion is shallow-bounded by the step budget.
 *      JSON.parse handles the full grammar but returns undefined (rather
 *      than throwing) on malformed input — the engine has no try/catch.
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

// Create a plain object carrying Object.prototype as its [[Prototype]].
JsObject* NewPlainObject(Interp& I)
{
    JsObject* o = ObjNew(I.arena, false);
    if (o)
        o->proto = I.objectProto;
    return o;
}

// Build a RegExp object from source + flags. The object is a plain
// JsObject (inherits Object.prototype) tagged with its compiled program
// via JsObject::regexp; test/exec/match/etc. dispatch on that tag.
Result<JsValue> MakeRegExp(Interp& I, const char* src, u32 srcLen, const char* flags, u32 flagsLen)
{
    Result<ReProgram*> pr = ReCompile(I.arena, src, srcLen, flags, flagsLen);
    if (!pr)
        return Err{pr.error()};

    JsObject* o = NewPlainObject(I);
    if (!o)
        return Err{ErrorCode::OutOfMemory};
    JsRegExp* re = I.arena.New<JsRegExp>();
    if (!re)
        return Err{ErrorCode::OutOfMemory};
    re->prog = pr.value();
    // Copy the source/flags text into the arena so the object owns it.
    JsString* s = MakeString(I.arena, src, srcLen);
    JsString* f = MakeString(I.arena, flags, flagsLen);
    if (!s || !f)
        return Err{ErrorCode::OutOfMemory};
    re->source = s->data;
    re->sourceLen = s->len;
    re->flags = f->data;
    re->flagsLen = f->len;
    re->lastIndex = 0;
    o->regexp = re;
    return JsValue::Obj(o);
}

Result<void> InstallBuiltins(Interp& I)
{
    Arena& a = I.arena;
    Env* g = I.global;

    // Object.prototype: the shared root of the prototype chain. It has
    // no [[Prototype]] of its own (proto stays null = chain end) and
    // carries the inherited toString/valueOf. Created first so every
    // plain object below (and via NewPlainObject) can inherit it.
    JsObject* objectProto = ObjNew(a, false);
    if (!objectProto)
        return Err{ErrorCode::OutOfMemory};
    ObjSet(objectProto, a, "toString", 8, NativeFnVal(I, kObjToString, "toString"));
    ObjSet(objectProto, a, "valueOf", 7, NativeFnVal(I, kObjValueOf, "valueOf"));
    I.objectProto = objectProto;

    // Object global, with Object.prototype reachable as a property.
    JsObject* objectCtor = ObjNew(a, false);
    if (!objectCtor)
        return Err{ErrorCode::OutOfMemory};
    objectCtor->proto = objectProto;
    ObjSet(objectCtor, a, "prototype", 9, JsValue::Obj(objectProto));
    ObjSet(objectCtor, a, "keys", 4, NativeFnVal(I, kObjKeys, "keys"));
    EnvDefine(g, a, "Object", 6, JsValue::Obj(objectCtor));

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
    EnvDefine(g, a, "isFinite", 8, NativeFnVal(I, kIsFinite, "isFinite"));

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
    ObjSet(math, a, "random", 6, NativeFnVal(I, kMathRandom, "random"));
    ObjSet(math, a, "sin", 3, NativeFnVal(I, kMathSin, "sin"));
    ObjSet(math, a, "cos", 3, NativeFnVal(I, kMathCos, "cos"));
    ObjSet(math, a, "tan", 3, NativeFnVal(I, kMathTan, "tan"));
    ObjSet(math, a, "log", 3, NativeFnVal(I, kMathLog, "log"));
    ObjSet(math, a, "exp", 3, NativeFnVal(I, kMathExp, "exp"));
    EnvDefine(g, a, "Math", 4, JsValue::Obj(math));

    // Date — the callable global (new Date() / Date()) is the native ctor
    // function. Its sole static, Date.now, is resolved specially in
    // GetMemberImpl's Function path (a JsFunction has no property map, so
    // the static can't be a stored property). Per-instance getters
    // dispatch via GetMemberImpl on a Date-tagged object
    // (JsObject::isDate), mirroring the RegExp special-case.
    EnvDefine(g, a, "Date", 4, NativeFnVal(I, kDateCtor, "Date"));

    // RegExp(pattern[, flags]) — callable to build a regex from strings.
    // (The /.../ literal path goes through MakeRegExp directly.)
    EnvDefine(g, a, "RegExp", 6, NativeFnVal(I, kRegExpCtor, "RegExp"));

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
        if (NameEq(key, keyLen, "charCodeAt"))
            return NativeFnVal(I, kStrCharCodeAt, "charCodeAt");
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
        if (NameEq(key, keyLen, "replace"))
            return NativeFnVal(I, kStrReplace, "replace");
        if (NameEq(key, keyLen, "trim"))
            return NativeFnVal(I, kStrTrim, "trim");
        if (NameEq(key, keyLen, "match"))
            return NativeFnVal(I, kStrMatch, "match");
        if (NameEq(key, keyLen, "search"))
            return NativeFnVal(I, kStrSearch, "search");
        return JsValue::Undefined();
    }
    if (obj.type == JsType::Number)
    {
        // Number.prototype methods dispatch on a Number receiver, mirroring
        // the String special-case above. toString/valueOf are also wired so
        // a Number coerces through the same path as other primitives.
        if (NameEq(key, keyLen, "toFixed"))
            return NativeFnVal(I, kNumToFixed, "toFixed");
        if (NameEq(key, keyLen, "toString"))
            return NativeFnVal(I, kNumToString, "toString");
        if (NameEq(key, keyLen, "valueOf"))
            return NativeFnVal(I, kObjValueOf, "valueOf");
        return JsValue::Undefined();
    }
    if (obj.type == JsType::Function)
    {
        // Statics on a native constructor function. The Date ctor exposes
        // Date.now(); a JsFunction has no property map, so this is the
        // only place the static can be resolved.
        if (obj.as.fn && obj.as.fn->nativeId == kDateCtor && NameEq(key, keyLen, "now"))
            return NativeFnVal(I, kDateNow, "now");
        return JsValue::Undefined();
    }
    if (obj.type == JsType::Object)
    {
        JsObject* o = obj.as.obj;
        // RegExp instances: test/exec methods + source/flags/global/
        // lastIndex accessors. Checked before the host/array paths since a
        // regex object is a plain object that happens to carry a program.
        if (o->regexp)
        {
            JsRegExp* re = o->regexp;
            if (NameEq(key, keyLen, "test"))
                return NativeFnVal(I, kReTest, "test");
            if (NameEq(key, keyLen, "exec"))
                return NativeFnVal(I, kReExec, "exec");
            if (NameEq(key, keyLen, "source"))
                return JsValue::Str(MakeString(I.arena, re->source, re->sourceLen));
            if (NameEq(key, keyLen, "flags"))
                return JsValue::Str(MakeString(I.arena, re->flags, re->flagsLen));
            if (NameEq(key, keyLen, "global"))
                return JsValue::Bool(re->prog->global);
            if (NameEq(key, keyLen, "ignoreCase"))
                return JsValue::Bool(re->prog->ignoreCase);
            if (NameEq(key, keyLen, "multiline"))
                return JsValue::Bool(re->prog->multiline);
            if (NameEq(key, keyLen, "lastIndex"))
                return JsValue::Int(i64(re->lastIndex));
            // other keys fall through to the plain property map below
        }
        // Date instances: the UTC getters dispatch on the isDate tag (the
        // epoch-ms time value lives in JsObject::dateMs). Checked before
        // the host/array paths since a Date is a plain object.
        if (o->isDate)
        {
            if (NameEq(key, keyLen, "getTime"))
                return NativeFnVal(I, kDateGetTime, "getTime");
            if (NameEq(key, keyLen, "getFullYear"))
                return NativeFnVal(I, kDateGetFullYear, "getFullYear");
            if (NameEq(key, keyLen, "getMonth"))
                return NativeFnVal(I, kDateGetMonth, "getMonth");
            if (NameEq(key, keyLen, "getDate"))
                return NativeFnVal(I, kDateGetDate, "getDate");
            if (NameEq(key, keyLen, "getDay"))
                return NativeFnVal(I, kDateGetDay, "getDay");
            if (NameEq(key, keyLen, "getHours"))
                return NativeFnVal(I, kDateGetHours, "getHours");
            if (NameEq(key, keyLen, "getMinutes"))
                return NativeFnVal(I, kDateGetMinutes, "getMinutes");
            if (NameEq(key, keyLen, "getSeconds"))
                return NativeFnVal(I, kDateGetSeconds, "getSeconds");
            if (NameEq(key, keyLen, "toISOString"))
                return NativeFnVal(I, kDateToISOString, "toISOString");
            // other keys fall through to the plain property map below
        }
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
            if (NameEq(key, keyLen, "slice"))
                return NativeFnVal(I, kArrSlice, "slice");
            if (NameEq(key, keyLen, "map"))
                return NativeFnVal(I, kArrMap, "map");
            if (NameEq(key, keyLen, "filter"))
                return NativeFnVal(I, kArrFilter, "filter");
            if (NameEq(key, keyLen, "forEach"))
                return NativeFnVal(I, kArrForEach, "forEach");
        }
        // Own property, then walk the prototype chain iteratively. The
        // loop (never recursion) keeps the native frame flat — see the
        // native-stack budget note in CallFunction.
        JsValue v{};
        for (const JsObject* cur = o; cur; cur = cur->proto)
            if (ObjGet(cur, key, keyLen, v))
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

// Write an unsigned 64-bit value as decimal into `out` (no sign, no
// NUL). Returns chars written; writes nothing if cap is 0.
static u32 WriteU64Dec(u64 v, char* out, u32 cap)
{
    char tmp[24];
    u32 t = 0;
    if (v == 0)
        tmp[t++] = '0';
    while (v)
    {
        tmp[t++] = char('0' + (v % 10));
        v /= 10;
    }
    u32 o = 0;
    while (t && o < cap)
        out[o++] = tmp[--t];
    return o;
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

// Map a single character to its digit value in [0, 35], or -1 if it is
// not an alphanumeric digit char.
static int DigitVal(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 10;
    return -1;
}

// Lenient radix-aware integer prefix parse for parseInt: skip leading
// whitespace, optional sign, consume the leading run of digits valid in
// `radix`, ignore trailing garbage ("42px" -> 42). `radix == 0` selects
// 16 when the text begins with a 0x/0X prefix, else 10. A radix of 16
// also tolerates (and skips) a leading 0x/0X. Returns false (NaN) only
// when no valid leading digit is present or the radix is out of range.
static bool ParseIntPrefix(const char* s, u32 len, int radix, i64& out)
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
    // 0x / 0X prefix handling: consumed when radix is auto-detect (0) or
    // explicitly 16; ignored for any other radix.
    if (i + 1 < len && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X') && (radix == 0 || radix == 16))
    {
        radix = 16;
        i += 2;
    }
    if (radix == 0)
        radix = 10;
    if (radix < 2 || radix > 36)
        return false;
    if (i >= len)
        return false;
    int d0 = DigitVal(s[i]);
    if (d0 < 0 || d0 >= radix)
        return false;
    i64 v = 0;
    while (i < len)
    {
        int d = DigitVal(s[i]);
        if (d < 0 || d >= radix)
            break;
        v = v * radix + d;
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

// Forward decls for the regex-aware delegations (definitions live in the
// RegExp-runtime section below). StrSplit / StrReplace dispatch to these
// when handed a regex argument.
static Result<JsValue> ReReplace(Interp& I, const JsString* s, JsObject* reObj, const JsString* rep);
static Result<JsValue> ReSplit(Interp& I, const JsString* s, JsObject* reObj);

static Result<JsValue> StrSplit(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    const JsString* s = recv.as.str;
    JsObject* arr = ObjNew(I.arena, true);
    if (!arr || !s)
        return JsValue::Obj(arr);
    JsValue sep = ArgOr(args, argc, 0);
    // Regex separator: delegate to the regex splitter.
    if (sep.type == JsType::Object && sep.as.obj && sep.as.obj->regexp)
        return ReSplit(I, s, sep.as.obj);
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

static Result<JsValue> StrCharCodeAt(Interp&, const JsValue& recv, const JsValue* args, u32 argc)
{
    const JsString* s = recv.as.str;
    i64 idx = ToInt(ArgOr(args, argc, 0));
    // GAP: ASCII only — returns the raw byte, not the UTF-16 code unit a
    // spec-compliant charCodeAt would for non-BMP / multibyte input.
    if (!s || idx < 0 || idx >= i64(s->len))
        return JsValue::Float(Sf32QNaN());
    return JsValue::Int(i64(static_cast<unsigned char>(s->data[idx])));
}

// String.prototype.replace. A regex pattern routes through ReReplace
// (which honors the `g` flag and `$&`/`$1` substitutions); a string
// pattern replaces the FIRST occurrence only.
// GAP: no function replacer; the string-pattern path is first-match only
// (use a /.../g regex for global string replacement).
static Result<JsValue> StrReplace(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    const JsString* s = recv.as.str;
    if (!s)
        return JsValue::Str(MakeString(I.arena, "", 0));
    JsValue patV = ArgOr(args, argc, 0);
    JsValue repV = ArgOr(args, argc, 1);
    // Regex pattern: delegate to the regex replacer.
    if (patV.type == JsType::Object && patV.as.obj && patV.as.obj->regexp && repV.type == JsType::String)
        return ReReplace(I, s, patV.as.obj, repV.as.str);
    // A non-string pattern can't match under the string-only contract:
    // return the receiver unchanged.
    if (patV.type != JsType::String || repV.type != JsType::String)
        return JsValue::Str(MakeString(I.arena, s->data, s->len));
    const JsString* pat = patV.as.str;
    const JsString* rep = repV.as.str;
    // Locate the first occurrence of the pattern.
    u32 at = s->len; // sentinel: "not found"
    if (pat->len == 0)
    {
        at = 0; // empty pattern matches at the start
    }
    else if (pat->len <= s->len)
    {
        for (u32 i = 0; i + pat->len <= s->len; ++i)
        {
            bool eq = true;
            for (u32 j = 0; j < pat->len; ++j)
                if (s->data[i + j] != pat->data[j])
                {
                    eq = false;
                    break;
                }
            if (eq)
            {
                at = i;
                break;
            }
        }
    }
    if (at == s->len && pat->len != 0)
        return JsValue::Str(MakeString(I.arena, s->data, s->len)); // no match
    u32 outLen = s->len - pat->len + rep->len;
    char* buf = static_cast<char*>(I.arena.Alloc(outLen + 1, 1));
    if (!buf)
        return Err{ErrorCode::OutOfMemory};
    u32 o = 0;
    for (u32 i = 0; i < at; ++i)
        buf[o++] = s->data[i];
    for (u32 i = 0; i < rep->len; ++i)
        buf[o++] = rep->data[i];
    for (u32 i = at + pat->len; i < s->len; ++i)
        buf[o++] = s->data[i];
    buf[o] = '\0';
    return JsValue::Str(MakeString(I.arena, buf, o));
}

// String.prototype.trim — strip leading/trailing ASCII whitespace.
// GAP: ASCII whitespace only (space/tab/newline/CR/FF/VT); Unicode
// whitespace (NBSP, the various spaces) is not recognised.
static Result<JsValue> StrTrim(Interp& I, const JsValue& recv)
{
    const JsString* s = recv.as.str;
    if (!s)
        return JsValue::Str(MakeString(I.arena, "", 0));
    auto isWs = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; };
    u32 start = 0;
    u32 end = s->len;
    while (start < end && isWs(s->data[start]))
        ++start;
    while (end > start && isWs(s->data[end - 1]))
        --end;
    return JsValue::Str(MakeString(I.arena, s->data + start, end - start));
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

// Array.prototype.slice — shallow copy of [start, end) with negative
// indices counting from the end (matching String.prototype.slice).
static Result<JsValue> ArrSlice(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    JsObject* arr = recv.as.obj;
    JsObject* out = ObjNew(I.arena, true);
    if (!out)
        return Err{ErrorCode::OutOfMemory};
    i64 len = i64(arr->length);
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
    for (i64 i = start; i < end; ++i)
        if (!ArrPush(out, I.arena, arr->elems[i]))
            return Err{ErrorCode::OutOfMemory};
    return JsValue::Obj(out);
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

// --------------------- Number.prototype.* ---------------------

// Number.prototype.toString(radix). For radix 10 (or absent) this
// defers to the canonical ValueToChars form. For radix 2/8/16 (and any
// 2..36) it formats the INTEGER part in that base — the common real-page
// use is `(n).toString(16)` / `(n).toString(2)` on whole numbers.
// GAP: a fractional value's digits after the point are NOT emitted for
// a non-decimal radix (spec would render e.g. (3.5).toString(2) ==
// "11.1"); the integer part is rendered correctly and the fraction is
// dropped. Revisit if a real page needs non-decimal fractional output.
static Result<JsValue> NumToString(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    int radix = 10;
    if (argc >= 1 && args[0].type == JsType::Number)
        radix = int(ToInt(args[0]));
    if (radix < 2 || radix > 36)
        return Err{ErrorCode::InvalidArgument};
    if (radix == 10)
    {
        char buf[64];
        u32 n = ValueToChars(recv, buf, sizeof(buf));
        return JsValue::Str(MakeString(I.arena, buf, n));
    }
    // Non-decimal radix: operate on the truncated integer magnitude.
    i64 v = ToInt(recv);
    bool neg = v < 0;
    u64 mag = neg ? (u64(-(v + 1)) + 1) : u64(v);
    char tmp[72];
    u32 t = 0;
    if (mag == 0)
        tmp[t++] = '0';
    const char* kDigits = "0123456789abcdefghijklmnopqrstuvwxyz";
    while (mag)
    {
        tmp[t++] = kDigits[mag % u64(radix)];
        mag /= u64(radix);
    }
    char out[80];
    u32 o = 0;
    if (neg)
        out[o++] = '-';
    while (t)
        out[o++] = tmp[--t];
    return JsValue::Str(MakeString(I.arena, out, o));
}

// Number.prototype.toFixed(digits): fixed-point decimal with exactly
// `digits` fractional places, 0..20 clamped. Uses exact i64 scaling
// (round-half-up) for integer receivers — exact — and Sf32 scaling for
// fractional receivers. GAP: rounding is round-half-AWAY-from-zero (the
// straightforward kernel form), whereas V8's toFixed uses the IEEE-754
// shortest-round-trip rounding; the two can differ in the last digit on
// values not exactly representable in binary32. Fractional receivers
// also carry only ~7 significant digits (the engine's binary32 GAP).
static Result<JsValue> NumToFixed(Interp& I, const JsValue& recv, const JsValue* args, u32 argc)
{
    i64 digits = (argc >= 1) ? ToInt(args[0]) : 0;
    if (digits < 0)
        digits = 0;
    if (digits > 20)
        digits = 20;

    // NaN / Infinity render textually, ignoring the digit count.
    if (recv.IsNumber() && !recv.as.num.isInt)
    {
        Sf32 f = recv.as.num.fval;
        if (Sf32IsNaN(f) || Sf32IsInf(f))
        {
            char buf[16];
            u32 n = ValueToChars(recv, buf, sizeof(buf));
            return JsValue::Str(MakeString(I.arena, buf, n));
        }
    }

    // pow10 fits in i64 for digits<=18; clamp the int fast-path there.
    i64 pow10 = 1;
    bool pow10Fits = digits <= 18;
    if (pow10Fits)
        for (i64 k = 0; k < digits; ++k)
            pow10 *= 10;

    char out[96];
    u32 o = 0;

    if (recv.IsNumber() && recv.as.num.isInt && pow10Fits)
    {
        // Exact integer path: the fractional digits are all zero.
        i64 v = recv.as.num.ival;
        if (v < 0)
        {
            out[o++] = '-';
            v = -v;
        }
        o += WriteU64Dec(u64(v), out + o, sizeof(out) - o);
        if (digits > 0)
        {
            out[o++] = '.';
            for (i64 k = 0; k < digits; ++k)
                out[o++] = '0';
        }
        return JsValue::Str(MakeString(I.arena, out, o));
    }

    // Fractional / large path: scale by 10^digits, round, split. Done in
    // Sf32 — carries the engine's binary32 precision (documented GAP).
    Sf32 val = NumberToSf32(recv);
    bool neg = Sf32IsNegative(val) && !Sf32IsZero(val);
    Sf32 mag = Sf32Abs(val);
    Sf32 scale = Sf32One();
    Sf32 ten = Sf32FromI32(10);
    for (i64 k = 0; k < digits; ++k)
        scale = Sf32Mul(scale, ten);
    // round-half-away: floor(mag*scale + 0.5)
    Sf32 scaled = Sf32Mul(mag, scale);
    Sf32 half = Sf32FromBits(0x3F000000u); // 0.5
    Sf32 rounded = Sf32Floor(Sf32Add(scaled, half));
    // Extract the scaled integer. ToI32 saturates beyond ~2.1e9; for the
    // common UI range (prices, percentages) this is ample. GAP: values
    // whose scaled magnitude exceeds INT32_MAX saturate.
    u64 scaledInt = u64(Sf32ToU32(rounded));

    if (neg && scaledInt != 0)
        out[o++] = '-';
    if (digits == 0 || !pow10Fits)
    {
        o += WriteU64Dec(scaledInt, out + o, sizeof(out) - o);
        return JsValue::Str(MakeString(I.arena, out, o));
    }
    u64 intPart = scaledInt / u64(pow10);
    u64 fracPart = scaledInt % u64(pow10);
    o += WriteU64Dec(intPart, out + o, sizeof(out) - o);
    out[o++] = '.';
    // Zero-pad the fractional part to exactly `digits` places.
    char fbuf[24];
    u32 fn = WriteU64Dec(fracPart, fbuf, sizeof(fbuf));
    for (i64 k = fn; k < digits; ++k)
        out[o++] = '0';
    for (u32 k = 0; k < fn; ++k)
        out[o++] = fbuf[k];
    return JsValue::Str(MakeString(I.arena, out, o));
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

// ----------------------- JSON.parse -----------------------

static bool IsHexDigit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int HexDigitVal(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - 'A' + 10;
}

// Encode a Unicode code point as UTF-8 into `out`; returns the byte
// count written (1..4). Astral code points (>= 0x10000, produced by
// combining a surrogate pair in JsonReadString) take the 4-byte form. A
// lone surrogate half (0xD800-0xDFFF) still encodes as 3-byte WTF-8 —
// see the JsonParse note.
static u32 EncodeUtf8(u32 cp, char* out)
{
    if (cp < 0x80)
    {
        out[0] = char(cp);
        return 1;
    }
    if (cp < 0x800)
    {
        out[0] = char(0xC0 | (cp >> 6));
        out[1] = char(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000)
    {
        out[0] = char(0xE0 | (cp >> 12));
        out[1] = char(0x80 | ((cp >> 6) & 0x3F));
        out[2] = char(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = char(0xF0 | (cp >> 18));
    out[1] = char(0x80 | ((cp >> 12) & 0x3F));
    out[2] = char(0x80 | ((cp >> 6) & 0x3F));
    out[3] = char(0x80 | (cp & 0x3F));
    return 4;
}

// Recursive-descent JSON reader over a NUL-bounded char span. `pos`
// walks the input; `ok` clears on any malformed token so the top-level
// entry can return undefined gracefully (the engine has no exceptions).
struct JsonReader
{
    Interp& I;
    const char* s;
    u32 n;
    u32 pos;
    bool ok;

    char Peek() const { return pos < n ? s[pos] : '\0'; }
    char Adv() { return pos < n ? s[pos++] : '\0'; }
    void SkipWs()
    {
        while (pos < n)
        {
            char c = s[pos];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
                ++pos;
            else
                break;
        }
    }
    bool Match(const char* lit, u32 len)
    {
        if (pos + len > n)
            return false;
        for (u32 i = 0; i < len; ++i)
            if (s[pos + i] != lit[i])
                return false;
        pos += len;
        return true;
    }
};

static JsValue JsonReadValue(JsonReader& r);

static JsValue JsonReadString(JsonReader& r)
{
    // Caller has verified the opening quote. Decode escapes into the
    // arena; the decoded form is never longer than the source span.
    r.Adv(); // opening quote
    const u32 maxLen = r.n - r.pos;
    char* buf = static_cast<char*>(r.I.arena.Alloc(maxLen + 1, 1));
    if (!buf)
    {
        r.ok = false;
        return JsValue::Undefined();
    }
    u32 out = 0;
    while (r.pos < r.n)
    {
        char c = r.Adv();
        if (c == '"')
        {
            buf[out] = '\0';
            return JsValue::Str(MakeString(r.I.arena, buf, out));
        }
        if (c == '\\')
        {
            char e = r.Adv();
            switch (e)
            {
            case '"':
                buf[out++] = '"';
                break;
            case '\\':
                buf[out++] = '\\';
                break;
            case '/':
                buf[out++] = '/';
                break;
            case 'n':
                buf[out++] = '\n';
                break;
            case 't':
                buf[out++] = '\t';
                break;
            case 'r':
                buf[out++] = '\r';
                break;
            case 'b':
                buf[out++] = '\b';
                break;
            case 'f':
                buf[out++] = '\f';
                break;
            case 'u':
            {
                // \uXXXX — decode a 16-bit unit, combining a high+low
                // surrogate pair (\uD800-\uDBFF followed by \uDC00-\uDFFF)
                // into the single astral code point it encodes, then emit
                // UTF-8. A lone / mismatched surrogate is emitted as-is
                // (3-byte WTF-8) — the engine has no exceptions so the
                // lenient form is preferable to rejecting the document.
                if (r.pos + 4 > r.n)
                {
                    r.ok = false;
                    return JsValue::Undefined();
                }
                u32 cp = 0;
                for (u32 k = 0; k < 4; ++k)
                {
                    char h = r.Adv();
                    if (!IsHexDigit(h))
                    {
                        r.ok = false;
                        return JsValue::Undefined();
                    }
                    cp = (cp << 4) | u32(HexDigitVal(h));
                }
                // High surrogate: look ahead for a "\uXXXX" low surrogate.
                if (cp >= 0xD800 && cp <= 0xDBFF && r.pos + 6 <= r.n && r.s[r.pos] == '\\' && r.s[r.pos + 1] == 'u')
                {
                    u32 lo = 0;
                    bool loOk = true;
                    for (u32 k = 0; k < 4; ++k)
                    {
                        char h = r.s[r.pos + 2 + k];
                        if (!IsHexDigit(h))
                        {
                            loOk = false;
                            break;
                        }
                        lo = (lo << 4) | u32(HexDigitVal(h));
                    }
                    if (loOk && lo >= 0xDC00 && lo <= 0xDFFF)
                    {
                        r.pos += 6; // consume the "\uXXXX" low half
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                }
                out += EncodeUtf8(cp, buf + out);
                break;
            }
            default:
                r.ok = false;
                return JsValue::Undefined();
            }
        }
        else if ((unsigned char)c < 0x20)
        {
            // Raw control chars are not legal inside a JSON string.
            r.ok = false;
            return JsValue::Undefined();
        }
        else
        {
            buf[out++] = c;
        }
    }
    r.ok = false; // unterminated string
    return JsValue::Undefined();
}

static JsValue JsonReadNumber(JsonReader& r)
{
    const u32 start = r.pos;
    if (r.Peek() == '-')
        r.Adv();
    while (r.pos < r.n)
    {
        char c = r.s[r.pos];
        if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-')
            ++r.pos;
        else
            break;
    }
    bool isInt;
    i64 iv;
    Sf32 fv;
    if (!ParseNumberText(r.s + start, r.pos - start, isInt, iv, fv))
    {
        r.ok = false;
        return JsValue::Undefined();
    }
    return isInt ? JsValue::Int(iv) : JsValue::Float(fv);
}

static JsValue JsonReadArray(JsonReader& r)
{
    r.Adv(); // '['
    JsObject* arr = ObjNew(r.I.arena, true);
    if (!arr)
    {
        r.ok = false;
        return JsValue::Undefined();
    }
    r.SkipWs();
    if (r.Peek() == ']')
    {
        r.Adv();
        return JsValue::Obj(arr);
    }
    for (;;)
    {
        JsValue v = JsonReadValue(r);
        if (!r.ok)
            return JsValue::Undefined();
        if (!ArrPush(arr, r.I.arena, v))
        {
            r.ok = false;
            return JsValue::Undefined();
        }
        r.SkipWs();
        char c = r.Adv();
        if (c == ',')
        {
            r.SkipWs();
            continue;
        }
        if (c == ']')
            break;
        r.ok = false;
        return JsValue::Undefined();
    }
    return JsValue::Obj(arr);
}

static JsValue JsonReadObject(JsonReader& r)
{
    r.Adv(); // '{'
    JsObject* obj = NewPlainObject(r.I);
    if (!obj)
    {
        r.ok = false;
        return JsValue::Undefined();
    }
    r.SkipWs();
    if (r.Peek() == '}')
    {
        r.Adv();
        return JsValue::Obj(obj);
    }
    for (;;)
    {
        r.SkipWs();
        if (r.Peek() != '"')
        {
            r.ok = false;
            return JsValue::Undefined();
        }
        JsValue key = JsonReadString(r);
        if (!r.ok)
            return JsValue::Undefined();
        r.SkipWs();
        if (r.Adv() != ':')
        {
            r.ok = false;
            return JsValue::Undefined();
        }
        JsValue val = JsonReadValue(r);
        if (!r.ok)
            return JsValue::Undefined();
        if (!ObjSet(obj, r.I.arena, key.as.str->data, key.as.str->len, val))
        {
            r.ok = false;
            return JsValue::Undefined();
        }
        r.SkipWs();
        char c = r.Adv();
        if (c == ',')
            continue;
        if (c == '}')
            break;
        r.ok = false;
        return JsValue::Undefined();
    }
    return JsValue::Obj(obj);
}

static JsValue JsonReadValue(JsonReader& r)
{
    r.SkipWs();
    char c = r.Peek();
    switch (c)
    {
    case '"':
        return JsonReadString(r);
    case '{':
        return JsonReadObject(r);
    case '[':
        return JsonReadArray(r);
    case 't':
        if (r.Match("true", 4))
            return JsValue::Bool(true);
        break;
    case 'f':
        if (r.Match("false", 5))
            return JsValue::Bool(false);
        break;
    case 'n':
        if (r.Match("null", 4))
            return JsValue::Null();
        break;
    default:
        if (c == '-' || (c >= '0' && c <= '9'))
            return JsonReadNumber(r);
        break;
    }
    r.ok = false;
    return JsValue::Undefined();
}

// JSON.parse(text): returns the parsed value, or undefined on any
// malformed input (the engine surfaces parse errors as undefined rather
// than throwing — it has no try/catch). A 𐀀 surrogate pair is
// combined into its astral code point and emitted as 4-byte UTF-8; a
// lone surrogate half is emitted as 3-byte WTF-8 (lenient, not rejected).
static JsValue JsonParse(Interp& I, const JsValue* args, u32 argc)
{
    JsValue v = ArgOr(args, argc, 0);
    if (v.type != JsType::String || !v.as.str)
        return JsValue::Undefined();
    JsonReader r{I, v.as.str->data, v.as.str->len, 0, true};
    JsValue result = JsonReadValue(r);
    if (!r.ok)
        return JsValue::Undefined();
    r.SkipWs();
    if (r.pos != r.n) // trailing garbage after the value
        return JsValue::Undefined();
    return result;
}

// ----------------------- RegExp runtime -----------------------

// The per-match VM step budget, capped to the interpreter's remaining
// budget so a regex can never out-run the global execution bound. A
// representative cost is then charged back against I.stepBudget so a
// script that runs many regexes still terminates.
static u64 ReBudget(Interp& I)
{
    u64 b = I.stepBudget < kReDefaultSteps ? I.stepBudget : kReDefaultSteps;
    return b;
}

// Charge `consumed`-ish work back against the interpreter budget. We
// don't thread the exact VM step count back out; charging a flat
// proportional amount keeps the accounting simple while ensuring forward
// progress toward Timeout under a regex-heavy loop.
static void ReCharge(Interp& I, u32 inputLen)
{
    u64 cost = 64 + u64(inputLen);
    I.stepBudget = (I.stepBudget > cost) ? (I.stepBudget - cost) : 0;
}

// Coerce an argument to the regex object it denotes: a regex value passes
// through; any other value is compiled as a literal source string (no
// flags). Returns null on a bad pattern.
static JsObject* AsRegExp(Interp& I, const JsValue& v)
{
    if (v.type == JsType::Object && v.as.obj && v.as.obj->regexp)
        return v.as.obj;
    JsString* s = ToJsString(I, v);
    if (!s)
        return nullptr;
    Result<JsValue> r = MakeRegExp(I, s->data, s->len, "", 0);
    if (!r || r.value().type != JsType::Object)
        return nullptr;
    return r.value().as.obj;
}

// Build the exec() result array: [whole, group1, group2, ...] plus an
// `index` property. Unmatched groups become undefined.
static Result<JsValue> ReBuildMatchArray(Interp& I, const JsString* s, const ReProgram* prog, const ReMatch& m)
{
    JsObject* arr = ObjNew(I.arena, true);
    if (!arr)
        return Err{ErrorCode::OutOfMemory};
    for (u32 gi = 0; gi < prog->groupCount; ++gi)
    {
        u32 a = m.caps[2 * gi];
        u32 b = m.caps[2 * gi + 1];
        if (a == kReNoCap || b == kReNoCap || b < a)
        {
            if (!ArrPush(arr, I.arena, JsValue::Undefined()))
                return Err{ErrorCode::OutOfMemory};
        }
        else
        {
            if (!ArrPush(arr, I.arena, JsValue::Str(MakeString(I.arena, s->data + a, b - a))))
                return Err{ErrorCode::OutOfMemory};
        }
    }
    ObjSet(arr, I.arena, "index", 5, JsValue::Int(i64(m.start)));
    return JsValue::Obj(arr);
}

// String.prototype.replace with a regex pattern. Supports `$&` (whole
// match) and `$1`..`$9` (captures) in the replacement; a `g` flag
// replaces every (non-overlapping) match, else only the first.
static Result<JsValue> ReReplace(Interp& I, const JsString* s, JsObject* reObj, const JsString* rep)
{
    JsRegExp* re = reObj->regexp;
    const ReProgram* prog = re->prog;

    char* out = nullptr;
    u32 outLen = 0, outCap = 0;
    auto append = [&](const char* src, u32 n) -> bool
    {
        if (outLen + n + 1 > outCap)
        {
            u32 nc = outCap ? outCap * 2 : 64;
            while (nc < outLen + n + 1)
                nc *= 2;
            char* nb = static_cast<char*>(I.arena.Alloc(nc, 1));
            if (!nb)
                return false;
            for (u32 i = 0; i < outLen; ++i)
                nb[i] = out[i];
            out = nb;
            outCap = nc;
        }
        for (u32 i = 0; i < n; ++i)
            out[outLen + i] = src[i];
        outLen += n;
        return true;
    };

    u32 pos = 0;
    bool any = false;
    while (pos <= s->len)
    {
        ReMatch m = ReExec(I.arena, prog, s->data, s->len, pos, ReBudget(I));
        ReCharge(I, s->len);
        if (!m.matched)
            break;
        // copy the gap before the match
        if (!append(s->data + pos, m.start - pos))
            return Err{ErrorCode::OutOfMemory};
        // expand the replacement, honoring $& and $1..$9
        for (u32 i = 0; i < rep->len; ++i)
        {
            char rc = rep->data[i];
            if (rc == '$' && i + 1 < rep->len)
            {
                char nx = rep->data[i + 1];
                if (nx == '&')
                {
                    if (!append(s->data + m.start, m.end - m.start))
                        return Err{ErrorCode::OutOfMemory};
                    ++i;
                    continue;
                }
                if (nx == '$')
                {
                    if (!append("$", 1))
                        return Err{ErrorCode::OutOfMemory};
                    ++i;
                    continue;
                }
                if (nx >= '1' && nx <= '9')
                {
                    u32 gi = u32(nx - '0');
                    if (gi < prog->groupCount)
                    {
                        u32 a = m.caps[2 * gi], b = m.caps[2 * gi + 1];
                        if (a != kReNoCap && b != kReNoCap && b >= a)
                            if (!append(s->data + a, b - a))
                                return Err{ErrorCode::OutOfMemory};
                    }
                    ++i;
                    continue;
                }
            }
            if (!append(&rc, 1))
                return Err{ErrorCode::OutOfMemory};
        }
        any = true;
        // advance; guard against a zero-width match looping forever.
        if (m.end > pos)
            pos = m.end;
        else
        {
            if (pos < s->len)
                if (!append(s->data + pos, 1))
                    return Err{ErrorCode::OutOfMemory};
            pos = pos + 1;
        }
        if (!prog->global)
            break;
    }
    // tail
    if (pos < s->len)
        if (!append(s->data + pos, s->len - pos))
            return Err{ErrorCode::OutOfMemory};
    (void)any;
    return JsValue::Str(MakeString(I.arena, out ? out : "", outLen));
}

// String.prototype.split with a regex separator. Splits at every match;
// GAP: capture groups in the separator are NOT spliced into the result
// (ES would insert them), and an empty-pattern match per-char is bounded
// by advancing one byte past a zero-width match.
static Result<JsValue> ReSplit(Interp& I, const JsString* s, JsObject* reObj)
{
    JsObject* arr = ObjNew(I.arena, true);
    if (!arr)
        return Err{ErrorCode::OutOfMemory};
    const ReProgram* prog = reObj->regexp->prog;
    u32 last = 0, pos = 0;
    while (pos <= s->len)
    {
        ReMatch m = ReExec(I.arena, prog, s->data, s->len, pos, ReBudget(I));
        ReCharge(I, s->len);
        if (!m.matched)
            break;
        if (m.end == m.start)
        {
            // zero-width separator match: skip a byte to make progress.
            if (m.start >= s->len)
                break;
            pos = m.start + 1;
            continue;
        }
        if (!ArrPush(arr, I.arena, JsValue::Str(MakeString(I.arena, s->data + last, m.start - last))))
            return Err{ErrorCode::OutOfMemory};
        last = m.end;
        pos = m.end;
    }
    if (!ArrPush(arr, I.arena, JsValue::Str(MakeString(I.arena, s->data + last, s->len - last))))
        return Err{ErrorCode::OutOfMemory};
    return JsValue::Obj(arr);
}

// ----------------------- Date runtime -----------------------
//
// A Date carries one number: `dateMs`, milliseconds since the Unix epoch
// (UTC). The getters derive the civil calendar from it on demand with a
// standard days-from-epoch algorithm; there is no per-field cache.
//
// GAP: UTC only — no local-timezone offset, no DST, so getHours/getDate/
//      etc. report the UTC wall clock. The setter family (setFullYear,
//      setHours, …), string parsing (Date.parse / new Date("...")), and
//      the locale formatters (toLocaleString / toDateString) are not
//      implemented; new Date("...") falls into the unrecognised-arg path
//      and yields an Invalid-Date (dateMs treated as 0 by the getters).

// Read the wall clock as milliseconds since the Unix epoch. Built on the
// kernel's CMOS-RTC FILETIME source (100ns ticks since 1601). Returns 0
// when the RTC is unavailable (FILETIME == 0) so Date degrades to the
// epoch rather than faulting — matching browser.cpp::NowUnix.
static i64 DateNowMs()
{
    constexpr u64 kFiletimePerMs = 10000ULL;                 // 100ns ticks per ms
    constexpr u64 kFiletimeUnixOffsetMs = 11644473600000ULL; // ms 1601->1970
    const u64 ft = duetos::time::RealtimeFiletime();
    if (ft == 0)
        return 0; // RTC unavailable — epoch
    const u64 ms1601 = ft / kFiletimePerMs;
    if (ms1601 <= kFiletimeUnixOffsetMs)
        return 0;
    return i64(ms1601 - kFiletimeUnixOffsetMs);
}

// Floor-divide / floor-mod for signed values (epoch ms can be negative
// for pre-1970 dates). C++ `/` and `%` truncate toward zero, which is
// wrong for the calendar arithmetic below when the numerator is negative.
static i64 FloorDiv(i64 a, i64 b)
{
    i64 q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0)))
        --q;
    return q;
}
static i64 FloorMod(i64 a, i64 b)
{
    i64 r = a % b;
    if (r != 0 && ((r < 0) != (b < 0)))
        r += b;
    return r;
}

// Broken-down UTC calendar fields derived from epoch milliseconds.
struct CivilTime
{
    i64 year;    // full year, e.g. 1970
    i64 month;   // 0..11 (0 = January)
    i64 day;     // 1..31
    i64 weekday; // 0..6 (0 = Sunday)
    i64 hour;    // 0..23
    i64 minute;  // 0..59
    i64 second;  // 0..59
};

// Convert epoch ms to broken-down UTC fields. The date math is Howard
// Hinnant's well-known days-from-epoch inverse (civil_from_days), which
// is exact for the full proleptic-Gregorian range and handles negative
// day counts (pre-1970) correctly.
static CivilTime CivilFromMs(i64 ms)
{
    i64 days = FloorDiv(ms, 86400000LL);
    i64 rem = FloorMod(ms, 86400000LL); // ms into the day, always >= 0

    CivilTime ct{};
    ct.hour = rem / 3600000LL;
    rem %= 3600000LL;
    ct.minute = rem / 60000LL;
    rem %= 60000LL;
    ct.second = rem / 1000LL;

    // Weekday: 1970-01-01 was a Thursday (4). Floor-mod keeps it in 0..6
    // even for negative `days`.
    ct.weekday = FloorMod(days + 4, 7);

    // civil_from_days: shift the era so the leap-day lands at the end of a
    // 400-year cycle, then unwind year/month/day.
    i64 z = days + 719468; // shift epoch to 0000-03-01
    i64 era = FloorDiv(z, 146097);
    i64 doe = z - era * 146097;                                      // [0, 146096]
    i64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    i64 y = yoe + era * 400;
    i64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    i64 mp = (5 * doy + 2) / 153;                      // [0, 11], Mar=0
    ct.day = doy - (153 * mp + 2) / 5 + 1;             // [1, 31]
    ct.month = mp < 10 ? mp + 3 : mp - 9;              // [1, 12], Jan=1
    ct.year = y + (ct.month <= 2 ? 1 : 0);
    ct.month -= 1; // JS months are 0-based
    return ct;
}

// Construct a Date object. `new Date()` / `Date()` -> now;
// `new Date(ms)` -> the given epoch ms. A non-numeric single argument
// (e.g. a date string) is unsupported (GAP) and yields dateMs == 0.
static Result<JsValue> DateConstruct(Interp& I, const JsValue* args, u32 argc)
{
    JsObject* o = NewPlainObject(I);
    if (!o)
        return Err{ErrorCode::OutOfMemory};
    o->isDate = true;
    if (argc == 0)
        o->dateMs = DateNowMs();
    else
    {
        JsValue a0 = args[0];
        if (a0.type == JsType::Number)
            // Integer epoch-ms is exact (the common case: Date.now()'s
            // value, a stored timestamp). GAP: a fractional/large numeric
            // arg goes through the binary32 path and Sf32ToI32 saturates
            // past ~2.1e9 ms — sufficient for the int-literal use here, not
            // for arbitrary post-2038 fractional millisecond inputs.
            o->dateMs = a0.as.num.isInt ? a0.as.num.ival : i64(Sf32ToI32(a0.as.num.fval));
        else
            o->dateMs = 0; // GAP: no date-string parsing
    }
    return JsValue::Obj(o);
}

// Dispatch the calendar getters (getFullYear/getMonth/.../getSeconds) on
// a Date receiver. Returns NaN if the receiver isn't a Date.
static Result<JsValue> DateGetField(const JsValue& recv, u16 id)
{
    if (recv.type != JsType::Object || !recv.as.obj || !recv.as.obj->isDate)
        return JsValue::Float(Sf32QNaN());
    CivilTime ct = CivilFromMs(recv.as.obj->dateMs);
    switch (id)
    {
    case kDateGetFullYear:
        return JsValue::Int(ct.year);
    case kDateGetMonth:
        return JsValue::Int(ct.month);
    case kDateGetDate:
        return JsValue::Int(ct.day);
    case kDateGetDay:
        return JsValue::Int(ct.weekday);
    case kDateGetHours:
        return JsValue::Int(ct.hour);
    case kDateGetMinutes:
        return JsValue::Int(ct.minute);
    case kDateGetSeconds:
        return JsValue::Int(ct.second);
    default:
        return JsValue::Float(Sf32QNaN());
    }
}

// Date.prototype.toISOString -> "YYYY-MM-DDTHH:MM:SS.mmmZ" (UTC).
static Result<JsValue> DateToISOString(Interp& I, const JsValue& recv)
{
    if (recv.type != JsType::Object || !recv.as.obj || !recv.as.obj->isDate)
        return JsValue::Str(MakeString(I.arena, "Invalid Date", 12));
    i64 ms = recv.as.obj->dateMs;
    CivilTime ct = CivilFromMs(ms);
    i64 millis = FloorMod(ms, 1000LL);

    // Fixed-width zero-padded fields. Year is 4 digits (GAP: years
    // outside 0..9999 are not given the ES +NNNNNN extended form).
    char buf[28];
    u32 o = 0;
    auto pad = [&](i64 v, u32 width)
    {
        char tmp[8];
        u32 t = 0;
        u64 uv = v < 0 ? 0 : u64(v);
        if (uv == 0)
            tmp[t++] = '0';
        while (uv)
        {
            tmp[t++] = char('0' + (uv % 10));
            uv /= 10;
        }
        for (u32 k = t; k < width; ++k)
            buf[o++] = '0';
        while (t)
            buf[o++] = tmp[--t];
    };
    pad(ct.year, 4);
    buf[o++] = '-';
    pad(ct.month + 1, 2);
    buf[o++] = '-';
    pad(ct.day, 2);
    buf[o++] = 'T';
    pad(ct.hour, 2);
    buf[o++] = ':';
    pad(ct.minute, 2);
    buf[o++] = ':';
    pad(ct.second, 2);
    buf[o++] = '.';
    pad(millis, 3);
    buf[o++] = 'Z';
    return JsValue::Str(MakeString(I.arena, buf, o));
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
        // Radix argument (arg[1]): 0 (or absent) auto-detects 0x/decimal.
        int radix = 0;
        if (argc >= 2 && args[1].type == JsType::Number)
            radix = int(ToInt(args[1]));
        if (v.type == JsType::Number)
        {
            // parseInt(number) with no/decimal radix truncates toward
            // zero; a non-trivial radix re-parses the decimal text form.
            if (radix == 0 || radix == 10)
                return JsValue::Int(ToInt(v));
            char buf[32];
            u32 n = ValueToChars(v, buf, sizeof(buf));
            i64 iv;
            if (ParseIntPrefix(buf, n, radix, iv))
                return JsValue::Int(iv);
            return JsValue::Float(Sf32QNaN());
        }
        if (v.type == JsType::String)
        {
            i64 iv;
            if (ParseIntPrefix(v.as.str->data, v.as.str->len, radix, iv))
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
    case kIsFinite:
    {
        // isFinite(v): true only for an actual finite Number. Integer
        // payloads are always finite; a float payload must be neither
        // NaN nor +/-Infinity. Non-numbers are not finite (no coercion —
        // matches Number.isFinite rather than the coercing global, which
        // is the safer subset for real-page scripts).
        JsValue v = ArgOr(args, argc, 0);
        if (v.type != JsType::Number)
            return JsValue::Bool(false);
        if (v.as.num.isInt)
            return JsValue::Bool(true);
        return JsValue::Bool(!Sf32IsNaN(v.as.num.fval) && !Sf32IsInf(v.as.num.fval));
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
    case kMathSin:
        return JsValue::Float(Sf32Sin(NumberToSf32(ArgOr(args, argc, 0))));
    case kMathCos:
        return JsValue::Float(Sf32Cos(NumberToSf32(ArgOr(args, argc, 0))));
    case kMathTan:
    {
        // tan(x) = sin(x) / cos(x). The soft-float lib has no Sf32Tan, so
        // we compose it; Sf32Div yields +/-Inf at the cos==0 poles, which
        // is the correct JS result (Math.tan(PI/2) ~ a huge finite value
        // in real JS too, since PI/2 isn't exactly representable).
        Sf32 x = NumberToSf32(ArgOr(args, argc, 0));
        return JsValue::Float(Sf32Div(Sf32Sin(x), Sf32Cos(x)));
    }
    case kMathLog:
        return JsValue::Float(Sf32Log(NumberToSf32(ArgOr(args, argc, 0))));
    case kMathExp:
        return JsValue::Float(Sf32Exp(NumberToSf32(ArgOr(args, argc, 0))));
    case kMathRandom:
    {
        // A double in [0, 1) from the kernel PRNG. We take 24 random bits
        // (the binary32 mantissa width) and scale by 2^-24 so the result
        // is always strictly < 1 and exactly representable in Sf32 — this
        // avoids any rounding that could land on 1.0. Non-deterministic by
        // nature; the self-test asserts the RANGE, never a specific value.
        u32 bits24 = u32(duetos::core::RandomU64() & 0xFFFFFFu);
        Sf32 num = Sf32FromU32(bits24);
        Sf32 denom = Sf32FromU32(1u << 24); // 16777216.0, exact in binary32
        return JsValue::Float(Sf32Div(num, denom));
    }

    case kDateCtor:
        return DateConstruct(I, args, argc);
    case kDateNow:
        return JsValue::Int(DateNowMs());
    case kDateGetTime:
        if (recv.type == JsType::Object && recv.as.obj && recv.as.obj->isDate)
            return JsValue::Int(recv.as.obj->dateMs);
        return JsValue::Float(Sf32QNaN());
    case kDateGetFullYear:
    case kDateGetMonth:
    case kDateGetDate:
    case kDateGetDay:
    case kDateGetHours:
    case kDateGetMinutes:
    case kDateGetSeconds:
        return DateGetField(recv, id);
    case kDateToISOString:
        return DateToISOString(I, recv);

    case kNumToFixed:
        return NumToFixed(I, recv, args, argc);
    case kNumToString:
        return NumToString(I, recv, args, argc);

    case kStrCharAt:
        return StrCharAt(I, recv, args, argc);
    case kStrCharCodeAt:
        return StrCharCodeAt(I, recv, args, argc);
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
    case kStrReplace:
        return StrReplace(I, recv, args, argc);
    case kStrTrim:
        return StrTrim(I, recv);

    case kStrMatch:
    {
        // String.prototype.match(re). Non-global: returns the exec-style
        // array (with `index`) or null. Global: returns an array of all
        // matched substrings (or null when none) — no capture groups,
        // matching the ES `g`-flag form.
        const JsString* s = recv.as.str;
        if (!s)
            return JsValue::Null();
        JsObject* reObj = AsRegExp(I, ArgOr(args, argc, 0));
        if (!reObj)
            return Err{ErrorCode::InvalidArgument};
        const ReProgram* prog = reObj->regexp->prog;
        if (!prog->global)
        {
            ReMatch m = ReExec(I.arena, prog, s->data, s->len, 0, ReBudget(I));
            ReCharge(I, s->len);
            if (!m.matched)
                return JsValue::Null();
            return ReBuildMatchArray(I, s, prog, m);
        }
        JsObject* arr = ObjNew(I.arena, true);
        if (!arr)
            return Err{ErrorCode::OutOfMemory};
        u32 pos = 0;
        bool any = false;
        while (pos <= s->len)
        {
            ReMatch m = ReExec(I.arena, prog, s->data, s->len, pos, ReBudget(I));
            ReCharge(I, s->len);
            if (!m.matched)
                break;
            any = true;
            if (!ArrPush(arr, I.arena, JsValue::Str(MakeString(I.arena, s->data + m.start, m.end - m.start))))
                return Err{ErrorCode::OutOfMemory};
            pos = (m.end > m.start) ? m.end : m.end + 1; // bound zero-width
        }
        if (!any)
            return JsValue::Null();
        return JsValue::Obj(arr);
    }
    case kStrSearch:
    {
        // String.prototype.search(re): index of the first match, or -1.
        const JsString* s = recv.as.str;
        if (!s)
            return JsValue::Int(-1);
        JsObject* reObj = AsRegExp(I, ArgOr(args, argc, 0));
        if (!reObj)
            return Err{ErrorCode::InvalidArgument};
        ReMatch m = ReExec(I.arena, reObj->regexp->prog, s->data, s->len, 0, ReBudget(I));
        ReCharge(I, s->len);
        return JsValue::Int(m.matched ? i64(m.start) : -1);
    }

    case kReTest:
    {
        // RegExp.prototype.test(str): true if the pattern matches. With a
        // `g` flag, the search starts at lastIndex and advances it.
        if (recv.type != JsType::Object || !recv.as.obj || !recv.as.obj->regexp)
            return Err{ErrorCode::BadState};
        JsRegExp* re = recv.as.obj->regexp;
        JsString* s = ToJsString(I, ArgOr(args, argc, 0));
        if (!s)
            return Err{ErrorCode::OutOfMemory};
        u32 startAt = re->prog->global ? re->lastIndex : 0;
        if (startAt > s->len)
            startAt = s->len;
        ReMatch m = ReExec(I.arena, re->prog, s->data, s->len, startAt, ReBudget(I));
        ReCharge(I, s->len);
        if (re->prog->global)
            re->lastIndex = m.matched ? (m.end > m.start ? m.end : m.end + 1) : 0;
        return JsValue::Bool(m.matched);
    }
    case kReExec:
    {
        // RegExp.prototype.exec(str): the match array (+ `index`) or null.
        if (recv.type != JsType::Object || !recv.as.obj || !recv.as.obj->regexp)
            return Err{ErrorCode::BadState};
        JsRegExp* re = recv.as.obj->regexp;
        JsString* s = ToJsString(I, ArgOr(args, argc, 0));
        if (!s)
            return Err{ErrorCode::OutOfMemory};
        u32 startAt = re->prog->global ? re->lastIndex : 0;
        if (startAt > s->len)
            startAt = s->len;
        ReMatch m = ReExec(I.arena, re->prog, s->data, s->len, startAt, ReBudget(I));
        ReCharge(I, s->len);
        if (!m.matched)
        {
            if (re->prog->global)
                re->lastIndex = 0;
            return JsValue::Null();
        }
        if (re->prog->global)
            re->lastIndex = (m.end > m.start) ? m.end : m.end + 1;
        return ReBuildMatchArray(I, s, re->prog, m);
    }
    case kRegExpCtor:
    {
        // RegExp(pattern[, flags]). A regex first-arg is re-wrapped with
        // (possibly new) flags; a string first-arg compiles directly.
        JsValue p = ArgOr(args, argc, 0);
        JsValue f = ArgOr(args, argc, 1);
        const char* flags = "";
        u32 flagsLen = 0;
        if (f.type == JsType::String)
        {
            flags = f.as.str->data;
            flagsLen = f.as.str->len;
        }
        if (p.type == JsType::Object && p.as.obj && p.as.obj->regexp)
        {
            JsRegExp* src = p.as.obj->regexp;
            if (argc < 2)
            {
                flags = src->flags;
                flagsLen = src->flagsLen;
            }
            return MakeRegExp(I, src->source, src->sourceLen, flags, flagsLen);
        }
        JsString* ps = ToJsString(I, p);
        if (!ps)
            return Err{ErrorCode::OutOfMemory};
        return MakeRegExp(I, ps->data, ps->len, flags, flagsLen);
    }

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
    case kArrSlice:
        return ArrSlice(I, recv, args, argc);
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
        return JsonParse(I, args, argc);

    case kObjToString:
        // Object.prototype.toString — the structural string form. Arrays
        // override this with their own join in GetMemberImpl/ValueToChars;
        // a plain object yields "[object Object]".
        return JsValue::Str(MakeString(I.arena, "[object Object]", 15));
    case kObjValueOf:
        // Object.prototype.valueOf returns `this` unchanged: a primitive
        // receiver passes through, an object receiver stays an object so
        // ToPrimitive falls on to toString.
        return recv;

    case kObjKeys:
    {
        // Object.keys(obj): own enumerable string keys as an array. For
        // an array, the keys are the decimal indices "0".."length-1".
        // GAP: inherited properties are excluded (no chain walk) but the
        // engine has no enumerability flag, so every own named prop is
        // treated as enumerable. GAP: property order follows the chunk
        // chain — within a single 8-slot chunk it is insertion order,
        // but once an object spills to a second chunk the newest chunk
        // (prepended at the head) enumerates first, so the cross-chunk
        // order diverges from strict insertion order.
        JsObject* result = ObjNew(I.arena, true);
        if (!result)
            return Err{ErrorCode::OutOfMemory};
        JsValue arg = ArgOr(args, argc, 0);
        if (arg.type != JsType::Object)
            return JsValue::Obj(result);
        JsObject* o = arg.as.obj;
        if (o->isArray)
        {
            char num[12];
            for (u32 i = 0; i < o->length; ++i)
            {
                u32 n = 0;
                if (i == 0)
                    num[n++] = '0';
                else
                {
                    char rev[12];
                    u32 t = 0;
                    for (u32 v = i; v; v /= 10)
                        rev[t++] = char('0' + (v % 10));
                    while (t)
                        num[n++] = rev[--t];
                }
                if (!ArrPush(result, I.arena, JsValue::Str(MakeString(I.arena, num, n))))
                    return Err{ErrorCode::OutOfMemory};
            }
        }
        // Named own properties (chunks are insertion-ordered).
        for (PropChunk* c = o->head; c; c = c->next)
            for (u32 i = 0; i < PropChunk::kSlots; ++i)
                if (c->slots[i].used)
                    if (!ArrPush(result, I.arena,
                                 JsValue::Str(MakeString(I.arena, c->slots[i].key, c->slots[i].keyLen))))
                        return Err{ErrorCode::OutOfMemory};
        return JsValue::Obj(result);
    }

    default:
        return Err{ErrorCode::Unsupported};
    }
}

} // namespace duetos::web::js
