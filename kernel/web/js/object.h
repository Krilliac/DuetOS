#pragma once

#include "web/js/arena.h"
#include "web/js/value.h"

/*
 * DuetOS — kernel/web/js: objects, arrays, and lexical environments.
 *
 * Objects are open-addressed string-keyed property maps backed by a
 * growable (chained-chunk) slot array out of the arena. Arrays share
 * the JsObject type but set `isArray` and maintain a dense `length`
 * plus integer-indexed slots stored under decimal-string keys; the
 * fast path for `arr[i]` indexes the dense vector directly.
 *
 * Environments are the lexical scope chain: a parent pointer plus a
 * small property map of bindings. Closures capture an Env pointer.
 *
 * Plain objects carry a `proto` ([[Prototype]]) pointer; member lookup
 * walks that chain iteratively (see GetMemberImpl). The shared
 * Object.prototype (installed in builtins.cpp) gives every plain object
 * a real toString/valueOf.
 *
 * GAP: prototypes are read-only here — no __proto__ accessor,
 * Object.create, Object.getPrototypeOf/setPrototypeOf, and only plain
 * objects get a default prototype (arrays/strings/functions still
 * dispatch their methods specially in GetMemberImpl, not via a
 * dedicated Array/String/Function.prototype). No getters/setters, no
 * property descriptors, no Symbol keys.
 */

namespace duetos::web::js
{

struct Prop
{
    const char* key; // arena-owned, NUL-terminated
    u32 keyLen;
    JsValue value;
    bool used;
};

// A chunk of property slots. Objects chain chunks as they grow so we
// never need to realloc inside the arena.
struct PropChunk
{
    static constexpr u32 kSlots = 8;
    Prop slots[kSlots];
    PropChunk* next;
};

// A RegExp instance's runtime payload: the compiled program, the
// original source/flags text (for .source / .toString), and the mutable
// `lastIndex` used by the `g` flag's stateful exec/test. Defined in
// regexp.h; carried by a JsObject whose `regexp` field is non-null.
struct JsRegExp;

// SEC-002: dense-array index upper bound. ECMAScript indices run 0..2^32-2,
// but DuetOS bounds the dense fast path far lower so `idx + 1` and the
// capacity doubling in ArrEnsure can never wrap a u32. Indices at/above this
// are treated as ordinary string-keyed properties. Shared by interp.cpp's
// index assignment fast path and object.cpp's ArrSet/ArrEnsure.
inline constexpr u32 kMaxArrayIndex = 1u << 24;

struct JsObject
{
    bool isArray;
    PropChunk* head; // linked list of property chunks (named props)
    u32 propCount;

    // Non-null iff this object is a RegExp instance. A regex object is a
    // plain JsObject (so it can still carry ad-hoc props) tagged with its
    // compiled program here; builtins dispatch test/exec on it.
    JsRegExp* regexp = nullptr;

    // Date instance tag. A Date is a plain JsObject (so it can still carry
    // ad-hoc props) whose `isDate` flag is set and whose `dateMs` carries
    // its time value — milliseconds since the Unix epoch (UTC). The
    // getTime/getFullYear/... methods dispatch on this tag in
    // GetMemberImpl, mirroring the RegExp special-case above.
    bool isDate = false;
    i64 dateMs = 0;

    // [[Prototype]] — the next link in the prototype chain, or null at
    // the chain's end. Plain objects get Object.prototype here at
    // creation; member lookup (GetMemberImpl) walks this iteratively.
    JsObject* proto;

    // Dense array storage. For arrays, elements 0..length-1 live here.
    JsValue* elems;
    u32 length;   // logical array length
    u32 elemsCap; // capacity of `elems`

    // ---- host embedding (DOM bindings etc.) ----
    // When `hostGet`/`hostSet` are non-null this object is a host
    // object: member reads/writes route to the C++ hooks first, with
    // `hostData` carrying the backing native pointer (a DOM Node*).
    // A miss in `hostGet` (Undefined) falls through to the plain
    // property map, so a host object can still hold ad-hoc JS props.
    void* hostData = nullptr;
    JsHostGet hostGet = nullptr;
    JsHostSet hostSet = nullptr;
};

// Lexical environment. `vars` is a small property map of name->value.
struct Env
{
    Env* parent;
    PropChunk* head;
    u32 count;
};

// ---- object property access ----
bool ObjGet(const JsObject* o, const char* key, u32 keyLen, JsValue& out);
bool ObjSet(JsObject* o, Arena& a, const char* key, u32 keyLen, const JsValue& v);
bool ObjHas(const JsObject* o, const char* key, u32 keyLen);
JsObject* ObjNew(Arena& a, bool isArray);

// ---- array helpers ----
bool ArrPush(JsObject* arr, Arena& a, const JsValue& v);
bool ArrGet(const JsObject* arr, u32 idx, JsValue& out);
bool ArrSet(JsObject* arr, Arena& a, u32 idx, const JsValue& v);

// ---- environment ----
Env* EnvNew(Arena& a, Env* parent);
bool EnvGet(const Env* e, const char* key, u32 keyLen, JsValue& out);
// Define a NEW binding in this exact scope (var/let/const/param).
bool EnvDefine(Env* e, Arena& a, const char* key, u32 keyLen, const JsValue& v);
// Assign to an EXISTING binding, walking the parent chain. Returns
// false if the name is not bound anywhere (caller may auto-global).
bool EnvAssign(Env* e, const char* key, u32 keyLen, const JsValue& v);

} // namespace duetos::web::js
