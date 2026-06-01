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
 * GAP: prototypes / prototype chain. Objects have no [[Prototype]];
 * String/Array "methods" are dispatched specially by the interpreter
 * rather than via a prototype lookup. No getters/setters, no property
 * descriptors, no Symbol keys.
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

struct JsObject
{
    bool isArray;
    PropChunk* head; // linked list of property chunks (named props)
    u32 propCount;

    // Dense array storage. For arrays, elements 0..length-1 live here.
    JsValue* elems;
    u32 length;   // logical array length
    u32 elemsCap; // capacity of `elems`
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
