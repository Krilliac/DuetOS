#pragma once

#include "util/result.h"
#include "web/js/interp.h"
#include "web/js/value.h"

/*
 * DuetOS — kernel/web/js: builtin function/object registry.
 *
 * Native functions are JsFunctions with nativeId != 0. The interpreter
 * dispatches them through CallNative. String/Array "methods" are also
 * native functions, bound to a receiver at member-access time.
 */

namespace duetos::web::js
{

using duetos::core::Result;

// Native function identifiers. 0 is reserved for "not native".
//
// kNativeCallback is a reserved sentinel: a JsFunction carrying it is
// dispatched through its `nativeCall` C++ callback pointer rather than
// the closed switch in CallNative. Host embedders (the DOM bindings in
// js_dom.cpp) use it to expose arbitrary native methods without
// growing this enum. It sits at the top of the u16 space so it can
// never collide with a real builtin id.
enum NativeFn : u16
{
    kNativeNone = 0,
    // global
    kConsoleLog,
    kParseInt,
    kParseFloat,
    kIsNaN,
    kIsFinite,
    // Math.*
    kMathFloor,
    kMathCeil,
    kMathAbs,
    kMathMax,
    kMathMin,
    kMathPow,
    kMathSqrt,
    kMathRound,
    // Number.prototype.*  (receiver = the number)
    kNumToFixed,
    kNumToString,
    // String.prototype.*  (receiver = the string)
    kStrCharAt,
    kStrCharCodeAt,
    kStrIndexOf,
    kStrSlice,
    kStrToUpper,
    kStrToLower,
    kStrSplit,
    kStrReplace,
    kStrTrim,
    // Array.prototype.*  (receiver = the array)
    kArrPush,
    kArrPop,
    kArrJoin,
    kArrIndexOf,
    kArrSlice,
    kArrMap,
    kArrFilter,
    kArrForEach,
    // JSON.*
    kJsonStringify,
    kJsonParse,
    // Object.prototype.*  (receiver = the object)
    kObjToString,
    kObjValueOf,
    // Object.* statics (receiver = undefined; arg[0] = the object)
    kObjKeys,
    // Sentinel: dispatch via JsFunction::nativeCall (host embedding).
    // Parked at the top of the u16 space so it never collides with a
    // real builtin id added above.
    kNativeCallback = 0xFFFF,
};

// Install all builtins into I.global. Implemented in builtins.cpp.
Result<void> InstallBuiltins(Interp& I);

// Member resolution for primitives & builtin objects. Returns a bound
// native function for methods, or a value for properties (e.g.
// String.length, Array.length). Implemented in builtins.cpp.
Result<JsValue> GetMemberImpl(Interp& I, const JsValue& obj, const char* key, u32 keyLen);

// Dispatch a native call. `recv` is the method receiver (or undefined
// for free functions). Implemented in builtins.cpp.
Result<JsValue> CallNative(Interp& I, u16 nativeId, const JsValue& recv, const JsValue* args, u32 argc);

} // namespace duetos::web::js
