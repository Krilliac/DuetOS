#include "web/js/object.h"

#include "util/string.h"

/*
 * DuetOS — kernel/web/js: object / array / environment storage.
 *
 * Property maps are linked chunks of fixed-size slot arrays out of the
 * arena (no realloc). Lookup is linear within the chunk chain — fine
 * for the small objects typical of scripts; a hash index is a future
 * optimisation, not a correctness need.
 */

namespace duetos::web::js
{

static bool KeyEq(const char* a, u32 an, const char* b, u32 bn)
{
    if (an != bn)
        return false;
    for (u32 i = 0; i < an; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

static const char* DupKey(Arena& a, const char* key, u32 keyLen)
{
    char* p = static_cast<char*>(a.Alloc(keyLen + 1, 1));
    if (!p)
        return nullptr;
    for (u32 i = 0; i < keyLen; ++i)
        p[i] = key[i];
    p[keyLen] = '\0';
    return p;
}

// Find a slot in a chunk chain matching key; or the first free slot.
static Prop* FindSlot(PropChunk* head, const char* key, u32 keyLen, bool& found)
{
    found = false;
    Prop* firstFree = nullptr;
    for (PropChunk* c = head; c; c = c->next)
    {
        for (u32 i = 0; i < PropChunk::kSlots; ++i)
        {
            Prop& s = c->slots[i];
            if (s.used && KeyEq(s.key, s.keyLen, key, keyLen))
            {
                found = true;
                return &s;
            }
            if (!s.used && !firstFree)
                firstFree = &s;
        }
    }
    return firstFree;
}

// Generic chunk-map set used by both objects and environments.
static bool ChunkSet(PropChunk** head, u32* count, Arena& a, const char* key, u32 keyLen, const JsValue& v)
{
    bool found = false;
    Prop* slot = FindSlot(*head, key, keyLen, found);
    if (!found && !slot)
    {
        // grow: prepend a new chunk
        PropChunk* nc = a.New<PropChunk>();
        if (!nc)
            return false;
        nc->next = *head;
        *head = nc;
        slot = &nc->slots[0];
    }
    if (!found)
    {
        const char* dk = DupKey(a, key, keyLen);
        if (!dk)
            return false;
        slot->key = dk;
        slot->keyLen = keyLen;
        slot->used = true;
        if (count)
            ++*count;
    }
    slot->value = v;
    return true;
}

static bool ChunkGet(PropChunk* head, const char* key, u32 keyLen, JsValue& out)
{
    bool found = false;
    Prop* slot = FindSlot(head, key, keyLen, found);
    if (found)
    {
        out = slot->value;
        return true;
    }
    return false;
}

// ---------------- objects ----------------

JsObject* ObjNew(Arena& a, bool isArray)
{
    JsObject* o = a.New<JsObject>();
    if (!o)
        return nullptr;
    o->isArray = isArray;
    return o;
}

bool ObjGet(const JsObject* o, const char* key, u32 keyLen, JsValue& out)
{
    if (!o)
        return false;
    return ChunkGet(o->head, key, keyLen, out);
}

bool ObjSet(JsObject* o, Arena& a, const char* key, u32 keyLen, const JsValue& v)
{
    if (!o)
        return false;
    return ChunkSet(&o->head, &o->propCount, a, key, keyLen, v);
}

bool ObjHas(const JsObject* o, const char* key, u32 keyLen)
{
    JsValue tmp{};
    return ObjGet(o, key, keyLen, tmp);
}

// ---------------- arrays ----------------

static bool ArrEnsure(JsObject* arr, Arena& a, u32 needCap)
{
    if (arr->elemsCap >= needCap)
        return true;
    u32 newCap = arr->elemsCap ? arr->elemsCap * 2 : 4;
    while (newCap < needCap)
        newCap *= 2;
    JsValue* ne = a.NewArray<JsValue>(newCap);
    if (!ne)
        return false;
    for (u32 i = 0; i < arr->length; ++i)
        ne[i] = arr->elems[i];
    arr->elems = ne;
    arr->elemsCap = newCap;
    return true;
}

bool ArrPush(JsObject* arr, Arena& a, const JsValue& v)
{
    if (!ArrEnsure(arr, a, arr->length + 1))
        return false;
    arr->elems[arr->length++] = v;
    return true;
}

bool ArrGet(const JsObject* arr, u32 idx, JsValue& out)
{
    if (idx >= arr->length)
        return false;
    out = arr->elems[idx];
    return true;
}

bool ArrSet(JsObject* arr, Arena& a, u32 idx, const JsValue& v)
{
    if (!ArrEnsure(arr, a, idx + 1))
        return false;
    // fill any gap with undefined
    for (u32 i = arr->length; i < idx; ++i)
        arr->elems[i] = JsValue::Undefined();
    arr->elems[idx] = v;
    if (idx >= arr->length)
        arr->length = idx + 1;
    return true;
}

// ---------------- environments ----------------

Env* EnvNew(Arena& a, Env* parent)
{
    Env* e = a.New<Env>();
    if (!e)
        return nullptr;
    e->parent = parent;
    return e;
}

bool EnvGet(const Env* e, const char* key, u32 keyLen, JsValue& out)
{
    for (const Env* s = e; s; s = s->parent)
        if (ChunkGet(s->head, key, keyLen, out))
            return true;
    return false;
}

bool EnvDefine(Env* e, Arena& a, const char* key, u32 keyLen, const JsValue& v)
{
    return ChunkSet(&e->head, &e->count, a, key, keyLen, v);
}

bool EnvAssign(Env* e, const char* key, u32 keyLen, const JsValue& v)
{
    for (Env* s = e; s; s = s->parent)
    {
        bool found = false;
        Prop* slot = FindSlot(s->head, key, keyLen, found);
        if (found)
        {
            slot->value = v;
            return true;
        }
    }
    return false;
}

} // namespace duetos::web::js
