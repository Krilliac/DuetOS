#include "web/js_dom.h"

#include "util/string.h"
#include "web/html.h"
#include "web/js/builtins.h"
#include "web/js/engine.h"
#include "web/js/interp.h"
#include "web/js/lexer.h"
#include "web/js/object.h"

/*
 * DuetOS — kernel/web: JavaScript ⇄ DOM bindings (see js_dom.h).
 *
 * Each DOM Node that a script touches is wrapped in a JS host object
 * whose `hostData` points at a NodeBind { Node*, DomCtx* }. Property
 * reads/writes route through HostGet/HostSet; methods are host-callback
 * JsFunctions (nativeId == kNativeCallback) whose nativeCtx carries the
 * DomCtx so they can allocate fresh DOM nodes out of the DOM arena.
 *
 * One wrapper is cached per Node (DomCtx::wrapCache) so identity holds:
 * `document.body === document.body`, and a node walked twice yields the
 * same JS object.
 */

namespace duetos::web
{

using namespace duetos::core;
using duetos::web::js::Interp;
using duetos::web::js::JsObject;
using duetos::web::js::JsString;
using duetos::web::js::JsType;
using duetos::web::js::JsValue;

namespace
{

// ---------------------------------------------------------------------------
// Binding context: ties the JS interpreter, the DOM arena (for
// mutations), and a small Node→wrapper cache together for one eval.
// ---------------------------------------------------------------------------

struct NodeBind; // fwd

// One addEventListener registration: a JS listener bound to a (Node,
// type) pair. `type` is a JS-arena copy (no interning table — the cap is
// small enough that a linear scan is fine). `fn` is the stored listener
// (normally a JS closure; a native callback is accepted too).
//
// `capture` selects which phase the listener fires in (capture-phase,
// outermost→target, vs the default bubble-phase, target→outermost) and is
// part of the listener's identity per the DOM spec — (type, fn, capture)
// is the key removeEventListener matches on. `once` removes the listener
// the first time it fires (in either phase). `passive` is recorded for
// fidelity but only documented, not enforced (see the GAP in MAddEventListener).
struct Listener
{
    Node* node = nullptr;
    const char* type = nullptr; // JS-arena copy, NUL-terminated
    js::JsFunction* fn = nullptr;
    bool live = false;    // false once removeEventListener clears the slot
    bool capture = false; // true: fire in the capture phase, not the bubble phase
    bool once = false;    // true: auto-remove after the first fire
    bool passive = false; // recorded only; preventDefault still honored (see GAP)
};

struct DomCtx
{
    Document* doc = nullptr;
    js::Arena* js = nullptr; // JS scratch arena (wrappers, transient values)
    Arena* dom = nullptr;    // DOM arena (new nodes/attrs/strings persist)

    // Set true whenever a DOM-tree mutation lands (setAttribute /
    // textContent / innerHTML / classList — classList routes through
    // SetAttribute). The browser consumes+clears it after a click dispatch
    // (JsDomContextConsumeDirty) to decide whether to re-lay-out the page so
    // a handler's change reaches the screen. Read-and-cleared, not latched.
    bool domMutated = false;

    // Per-Node wrapper cache for identity. Linear is fine: a script
    // touches a handful of distinct nodes.
    static constexpr u32 kMaxWrappers = 256;
    Node* cacheNode[kMaxWrappers] = {};
    JsObject* cacheObj[kMaxWrappers] = {};
    u32 cacheCount = 0;

    // Event-listener registry. A flat table is fine: dispatch walks the
    // ancestor chain and scans this list per node, and the cap bounds a
    // hostile script that registers in a loop. Cap documented below;
    // registrations past it are silently dropped (matching the parser's
    // arena-exhaustion "stop growing rather than fault" discipline).
    static constexpr u32 kMaxListeners = 128;
    Listener listeners[kMaxListeners] = {};
    u32 listenerCount = 0;
};

struct NodeBind
{
    Node* node = nullptr;
    DomCtx* ctx = nullptr;
};

// Pull the DomCtx out of a host method's nativeCtx.
DomCtx* CtxOf(void* nativeCtx)
{
    return static_cast<DomCtx*>(nativeCtx);
}

// Pull the NodeBind backing a receiver host object.
NodeBind* BindOf(const JsValue& recv)
{
    if (recv.type != JsType::Object || !recv.as.obj)
        return nullptr;
    return static_cast<NodeBind*>(recv.as.obj->hostData);
}

// ---------------------------------------------------------------------------
// Small string helpers.
// ---------------------------------------------------------------------------

u32 Slen(const char* s)
{
    return s ? static_cast<u32>(duetos::core::StrLen(s)) : 0;
}

// Compare a (ptr,len) key to a C-string literal.
bool KeyIs(const char* key, u32 keyLen, const char* lit)
{
    u32 ln = Slen(lit);
    if (keyLen != ln)
        return false;
    for (u32 i = 0; i < keyLen; ++i)
        if (key[i] != lit[i])
            return false;
    return true;
}

// Coerce a JsValue to a NUL-terminated C-string in a caller buffer.
u32 ValToCStr(const JsValue& v, char* out, u32 cap)
{
    u32 n = js::ValueToChars(v, out, cap > 0 ? cap - 1 : 0);
    if (cap > 0)
        out[n < cap ? n : cap - 1] = '\0';
    return n;
}

// Copy `n` bytes of `s` into the JS scratch arena as a NUL-terminated
// string and return the arena-owned pointer (or nullptr on exhaustion).
// The JS arena has no raw CopyString; MakeString gives us the arena-owned
// NUL-terminated buffer we want (we keep only its char* payload).
const char* JsCopyStr(js::Arena& a, const char* s, u32 n)
{
    js::JsString* js = js::MakeString(a, s, n);
    return js ? js->data : nullptr;
}

// ---------------------------------------------------------------------------
// DOM tree manipulation (allocates out of the DOM arena).
// ---------------------------------------------------------------------------

// Recursive id search, depth-first.
Node* FindById(Node* n, const char* id)
{
    for (Node* c = n->firstChild; c; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element)
        {
            const char* cid = c->GetAttr("id");
            if (cid && duetos::core::StrEqual(cid, id))
                return c;
        }
        Node* hit = FindById(c, id);
        if (hit)
            return hit;
    }
    return nullptr;
}

// Recursive tag collection into a flat list (snapshot, document order).
void CollectByTag(Node* n, const char* tag, Node** out, u32 cap, u32& count)
{
    for (Node* c = n->firstChild; c; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element && c->tag && duetos::core::StrEqual(c->tag, tag))
        {
            if (count < cap)
                out[count] = c;
            ++count;
        }
        CollectByTag(c, tag, out, cap, count);
    }
}

// True if the whitespace-delimited token list `list` (e.g. a `class`
// attribute value) contains `tok` (length `tokLen`) as a whole token.
bool TokenListHas(const char* list, const char* tok, u32 tokLen)
{
    if (!list || tokLen == 0)
        return false;
    u32 total = Slen(list);
    u32 i = 0;
    while (i < total)
    {
        while (i < total && (list[i] == ' ' || list[i] == '\t' || list[i] == '\n'))
            ++i;
        u32 s = i;
        while (i < total && list[i] != ' ' && list[i] != '\t' && list[i] != '\n')
            ++i;
        if (i - s == tokLen)
        {
            bool eq = true;
            for (u32 k = 0; k < tokLen; ++k)
                if (list[s + k] != tok[k])
                {
                    eq = false;
                    break;
                }
            if (eq)
                return true;
        }
    }
    return false;
}

// Recursive class collection into a flat list (snapshot, document order).
void CollectByClass(Node* n, const char* cls, Node** out, u32 cap, u32& count)
{
    u32 ln = Slen(cls);
    for (Node* c = n->firstChild; c; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element && TokenListHas(c->GetAttr("class"), cls, ln))
        {
            if (count < cap)
                out[count] = c;
            ++count;
        }
        CollectByClass(c, cls, out, cap, count);
    }
}

// ---------------------------------------------------------------------------
// querySelector / querySelectorAll selector matching.
//
// GAP: the CSS selector engine (kernel/web/css.cpp) keeps its selector
// PARSE + Matches()/MatchesCompound() entry points in an anonymous
// namespace — they are NOT reachable through css.h's public API
// (ParseStyleSheet / ComputeStyles / ParseColor / ParseLength only). So
// these query methods cannot reuse it without a new public css entry
// point (see js_dom.h GAP note + the final report). They support a
// single compound of tag / .class / #id (in any combination, e.g.
// `li.active`, `div#main`) and `*`; descendant combinators, attribute
// selectors, pseudo-classes, and selector lists are GAP — revisit once
// css.h exports a `ParseSelector` + `Matches(SimpleSelector*, Node*)`.
// ---------------------------------------------------------------------------

// One compound selector parsed out of a query string.
struct LiteSelector
{
    bool universal = false;
    char tag[64] = {}; // lowercased; empty == no type constraint
    char id[64] = {};  // bare id (no '#'); empty == none
    char cls[64] = {}; // bare class (no '.'); empty == none
    bool valid = false;
};

void LiteCopyLower(char* dst, u32 cap, const char* src, u32 len)
{
    u32 m = len < cap - 1 ? len : cap - 1;
    for (u32 i = 0; i < m; ++i)
    {
        char ch = src[i];
        dst[i] = (ch >= 'A' && ch <= 'Z') ? char(ch + 32) : ch;
    }
    dst[m] = '\0';
}

// Parse one compound selector. Leading run is the type (or '*'); '.' and
// '#' introduce class/id tokens. Whitespace ends parsing (no descendant
// combinator support — only the first compound is honored). `id` keeps
// the author's case (ids are case-sensitive); tag/class are lowercased
// to match the parser's lowercased tags / the token compare.
LiteSelector ParseLiteSelector(const char* sel, u32 len)
{
    LiteSelector ls{};
    u32 i = 0;
    while (i < len && (sel[i] == ' ' || sel[i] == '\t' || sel[i] == '\n'))
        ++i;
    // Leading type / universal (anything before the first . or #).
    u32 typeStart = i;
    while (i < len && sel[i] != '.' && sel[i] != '#' && sel[i] != ' ' && sel[i] != '\t' && sel[i] != '\n')
        ++i;
    u32 typeLen = i - typeStart;
    if (typeLen == 1 && sel[typeStart] == '*')
        ls.universal = true;
    else if (typeLen > 0)
        LiteCopyLower(ls.tag, sizeof(ls.tag), sel + typeStart, typeLen);
    // Trailing .class / #id tokens (single of each supported).
    while (i < len && sel[i] != ' ' && sel[i] != '\t' && sel[i] != '\n')
    {
        char kind = sel[i++];
        u32 tokStart = i;
        while (i < len && sel[i] != '.' && sel[i] != '#' && sel[i] != ' ' && sel[i] != '\t' && sel[i] != '\n')
            ++i;
        u32 tokLen = i - tokStart;
        if (tokLen == 0)
            return ls; // dangling '.'/'#' — invalid
        if (kind == '#')
        {
            u32 m = tokLen < sizeof(ls.id) - 1 ? tokLen : u32(sizeof(ls.id) - 1);
            for (u32 k = 0; k < m; ++k)
                ls.id[k] = sel[tokStart + k];
            ls.id[m] = '\0';
        }
        else // '.'
        {
            LiteCopyLower(ls.cls, sizeof(ls.cls), sel + tokStart, tokLen);
        }
    }
    ls.valid = ls.universal || ls.tag[0] || ls.id[0] || ls.cls[0];
    return ls;
}

// Test one element against a parsed compound selector.
bool LiteMatch(const Node* el, const LiteSelector& ls)
{
    if (el->kind != NodeKind::Element)
        return false;
    if (!ls.universal && ls.tag[0])
        if (!el->tag || !duetos::core::StrEqual(el->tag, ls.tag))
            return false;
    if (ls.id[0])
    {
        const char* elId = el->GetAttr("id");
        if (!elId || !duetos::core::StrEqual(elId, ls.id))
            return false;
    }
    if (ls.cls[0] && !TokenListHas(el->GetAttr("class"), ls.cls, Slen(ls.cls)))
        return false;
    return true;
}

// First descendant of `root` matching `ls` (document order), or null.
Node* LiteFindFirst(Node* root, const LiteSelector& ls)
{
    for (Node* c = root->firstChild; c; c = c->nextSibling)
    {
        if (LiteMatch(c, ls))
            return c;
        Node* hit = LiteFindFirst(c, ls);
        if (hit)
            return hit;
    }
    return nullptr;
}

// Collect every descendant of `root` matching `ls` (snapshot, doc order).
void LiteCollect(Node* root, const LiteSelector& ls, Node** out, u32 cap, u32& count)
{
    for (Node* c = root->firstChild; c; c = c->nextSibling)
    {
        if (LiteMatch(c, ls))
        {
            if (count < cap)
                out[count] = c;
            ++count;
        }
        LiteCollect(c, ls, out, cap, count);
    }
}

// Set or replace an attribute on an element (DOM-arena strings).
bool SetAttribute(DomCtx& ctx, Node* el, const char* name, u32 nameLen, const char* val, u32 valLen)
{
    const char* nameZ = ctx.dom->CopyString(name, nameLen);
    const char* valZ = ctx.dom->CopyString(val, valLen);
    if (!nameZ || !valZ)
        return false;
    for (Attr* a = el->attrs; a; a = a->next)
    {
        if (a->name && duetos::core::StrEqual(a->name, nameZ))
        {
            a->value = valZ;
            ctx.domMutated = true;
            return true;
        }
    }
    Attr* a = ctx.dom->AllocAttr();
    if (!a)
        return false;
    a->name = nameZ;
    a->value = valZ;
    a->next = nullptr;
    if (el->attrsTail)
        el->attrsTail->next = a;
    else
        el->attrs = a;
    el->attrsTail = a;
    ctx.domMutated = true;
    return true;
}

// Remove an attribute by name. No-op if absent.
void RemoveAttribute(Node* el, const char* name)
{
    Attr* prev = nullptr;
    for (Attr* a = el->attrs; a; prev = a, a = a->next)
    {
        if (a->name && duetos::core::StrEqual(a->name, name))
        {
            if (prev)
                prev->next = a->next;
            else
                el->attrs = a->next;
            if (el->attrsTail == a)
                el->attrsTail = prev;
            return;
        }
    }
}

// Append `child` to `parent`, unlinking it from any current parent.
void AppendChild(Node* parent, Node* child)
{
    // Unlink from a prior parent first.
    if (child->parent)
    {
        Node* p = child->parent;
        Node* prev = nullptr;
        for (Node* c = p->firstChild; c; prev = c, c = c->nextSibling)
        {
            if (c == child)
            {
                if (prev)
                    prev->nextSibling = c->nextSibling;
                else
                    p->firstChild = c->nextSibling;
                if (p->lastChild == c)
                    p->lastChild = prev;
                break;
            }
        }
    }
    child->parent = parent;
    child->nextSibling = nullptr;
    if (parent->lastChild)
        parent->lastChild->nextSibling = child;
    else
        parent->firstChild = child;
    parent->lastChild = child;
}

// Remove `child` from `parent`. Returns true if it was a child.
bool RemoveChild(Node* parent, Node* child)
{
    Node* prev = nullptr;
    for (Node* c = parent->firstChild; c; prev = c, c = c->nextSibling)
    {
        if (c == child)
        {
            if (prev)
                prev->nextSibling = c->nextSibling;
            else
                parent->firstChild = c->nextSibling;
            if (parent->lastChild == c)
                parent->lastChild = prev;
            child->parent = nullptr;
            child->nextSibling = nullptr;
            return true;
        }
    }
    return false;
}

// Create a fresh Text node carrying `text` (DOM-arena copy).
Node* MakeTextNode(DomCtx& ctx, const char* text, u32 len)
{
    Node* n = ctx.dom->AllocNode();
    if (!n)
        return nullptr;
    n->kind = NodeKind::Text;
    n->text = ctx.dom->CopyString(text, len);
    return n->text ? n : nullptr;
}

// Create a fresh Element with the given (lowercased copy of) tag.
Node* MakeElement(DomCtx& ctx, const char* tag, u32 len)
{
    Node* n = ctx.dom->AllocNode();
    if (!n)
        return nullptr;
    n->kind = NodeKind::Element;
    char low[64];
    u32 m = len < sizeof(low) ? len : u32(sizeof(low) - 1);
    for (u32 i = 0; i < m; ++i)
    {
        char c = tag[i];
        low[i] = (c >= 'A' && c <= 'Z') ? char(c + 32) : c;
    }
    n->tag = ctx.dom->CopyString(low, m);
    return n->tag ? n : nullptr;
}

// Detach every child of `el`, leaving it empty. Children keep their own
// subtrees intact (they are arena-owned and may be re-appended); we only
// sever the parent/sibling links so a later parse can repopulate `el`.
void ClearChildren(Node* el)
{
    for (Node* c = el->firstChild; c;)
    {
        Node* next = c->nextSibling;
        c->parent = nullptr;
        c->nextSibling = nullptr;
        c = next;
    }
    el->firstChild = nullptr;
    el->lastChild = nullptr;
}

// Replace all children of `el` with a single Text node carrying `text`
// (textContent setter).
bool SetTextContent(DomCtx& ctx, Node* el, const char* text, u32 len)
{
    Node* t = MakeTextNode(ctx, text, len);
    if (!t)
        return false;
    ClearChildren(el);
    AppendChild(el, t);
    ctx.domMutated = true;
    return true;
}

// Parse `html` as a fragment and replace all children of `el` with the
// parsed nodes (innerHTML setter). Fragment nodes are carved from the
// same DOM arena that owns `el`, so they persist with the document.
// Returns false only on a hard arena exhaustion (no container node);
// a partially-parsed fragment still installs what it built, mirroring
// the parser's own arena-exhaustion recovery.
bool SetInnerHtml(DomCtx& ctx, Node* el, const char* html, u32 len)
{
    // Parse in the target element's own fragment context (its lowercased
    // tag), so table-related contexts (tr/tbody/table/...) accept their
    // natural children instead of mis-parsing in a generic context.
    Node* frag = ParseHtmlFragment(html, len, *ctx.dom, el->tag);
    if (!frag)
        return false;
    ClearChildren(el);
    // Move each top-level fragment child under `el`. AppendChild unlinks
    // each from the scratch container first, so iterate by re-reading
    // `frag->firstChild` rather than caching nextSibling.
    while (Node* child = frag->firstChild)
        AppendChild(el, child);
    ctx.domMutated = true;
    return true;
}

// ---------------------------------------------------------------------------
// HTML serialization for innerHTML (get). Writes into a caller buffer;
// truncates at cap. GAP: attribute-value escaping is minimal (no &/<
// re-encoding) — fine for round-tripping our own parser output.
// ---------------------------------------------------------------------------

void SerOut(char* out, u32 cap, u32& o, const char* s, u32 n)
{
    for (u32 i = 0; i < n && o < cap; ++i)
        out[o++] = s[i];
}

void SerializeChildren(const Node* el, char* out, u32 cap, u32& o);

void SerializeNode(const Node* n, char* out, u32 cap, u32& o)
{
    if (n->kind == NodeKind::Text)
    {
        SerOut(out, cap, o, n->text ? n->text : "", Slen(n->text));
        return;
    }
    if (n->kind == NodeKind::Comment)
    {
        SerOut(out, cap, o, "<!--", 4);
        SerOut(out, cap, o, n->text ? n->text : "", Slen(n->text));
        SerOut(out, cap, o, "-->", 3);
        return;
    }
    if (n->kind != NodeKind::Element)
        return;
    SerOut(out, cap, o, "<", 1);
    SerOut(out, cap, o, n->tag, Slen(n->tag));
    for (const Attr* a = n->attrs; a; a = a->next)
    {
        SerOut(out, cap, o, " ", 1);
        SerOut(out, cap, o, a->name, Slen(a->name));
        SerOut(out, cap, o, "=\"", 2);
        SerOut(out, cap, o, a->value ? a->value : "", Slen(a->value));
        SerOut(out, cap, o, "\"", 1);
    }
    SerOut(out, cap, o, ">", 1);
    SerializeChildren(n, out, cap, o);
    SerOut(out, cap, o, "</", 2);
    SerOut(out, cap, o, n->tag, Slen(n->tag));
    SerOut(out, cap, o, ">", 1);
}

void SerializeChildren(const Node* el, char* out, u32 cap, u32& o)
{
    for (const Node* c = el->firstChild; c; c = c->nextSibling)
        SerializeNode(c, out, cap, o);
}

// ---------------------------------------------------------------------------
// Node ⇄ JS wrapper plumbing.
// ---------------------------------------------------------------------------

// Forward decls of the host hooks (defined after the methods).
Result<JsValue> ElemHostGet(Interp& I, JsObject* self, const char* key, u32 keyLen);
Result<bool> ElemHostSet(Interp& I, JsObject* self, const char* key, u32 keyLen, const JsValue& v);

// Make (or fetch the cached) JS host object wrapping `node`. Identity is
// preserved per eval so `document.body === document.body`.
JsValue WrapNode(DomCtx& ctx, Node* node)
{
    if (!node)
        return JsValue::Null();
    for (u32 i = 0; i < ctx.cacheCount; ++i)
        if (ctx.cacheNode[i] == node)
            return JsValue::Obj(ctx.cacheObj[i]);

    JsObject* o = js::ObjNew(*ctx.js, false);
    if (!o)
        return JsValue::Undefined();
    NodeBind* nb = ctx.js->New<NodeBind>();
    if (!nb)
        return JsValue::Undefined();
    nb->node = node;
    nb->ctx = &ctx;
    o->hostData = nb;
    o->hostGet = ElemHostGet;
    o->hostSet = ElemHostSet;

    if (ctx.cacheCount < DomCtx::kMaxWrappers)
    {
        ctx.cacheNode[ctx.cacheCount] = node;
        ctx.cacheObj[ctx.cacheCount] = o;
        ++ctx.cacheCount;
    }
    return JsValue::Obj(o);
}

// Build a bound host-callback method value (nativeId == kNativeCallback).
JsValue Method(DomCtx& ctx, js::JsNativeCall cb, const char* name)
{
    js::JsFunction* fn = ctx.js->New<js::JsFunction>();
    if (!fn)
        return JsValue::Undefined();
    fn->nativeId = js::kNativeCallback;
    fn->name = name;
    fn->nativeCall = cb;
    fn->nativeCtx = &ctx;
    return JsValue::Fn(fn);
}

// A JS array of wrapped nodes (snapshot).
JsValue WrapNodeList(DomCtx& ctx, Node** nodes, u32 count)
{
    JsObject* arr = js::ObjNew(*ctx.js, true);
    if (!arr)
        return JsValue::Undefined();
    for (u32 i = 0; i < count; ++i)
        js::ArrPush(arr, *ctx.js, WrapNode(ctx, nodes[i]));
    return JsValue::Obj(arr);
}

// Convenience: arg or undefined.
JsValue ArgOr(const JsValue* a, u32 c, u32 i)
{
    return i < c ? a[i] : JsValue::Undefined();
}

// ---------------------------------------------------------------------------
// Element methods (recv = the element host object).
// ---------------------------------------------------------------------------

Result<JsValue> MGetAttribute(Interp& I, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Null();
    char name[128];
    ValToCStr(ArgOr(args, argc, 0), name, sizeof(name));
    const char* v = nb->node->GetAttr(name);
    if (!v)
        return JsValue::Null();
    return JsValue::Str(js::MakeString(I.arena, v, Slen(v)));
}

Result<JsValue> MSetAttribute(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb || nb->node->kind != NodeKind::Element)
        return JsValue::Undefined();
    char name[128];
    char val[512];
    u32 nl = ValToCStr(ArgOr(args, argc, 0), name, sizeof(name));
    u32 vl = ValToCStr(ArgOr(args, argc, 1), val, sizeof(val));
    if (!SetAttribute(*nb->ctx, nb->node, name, nl, val, vl))
        return Err{ErrorCode::OutOfMemory};
    return JsValue::Undefined();
}

Result<JsValue> MHasAttribute(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Bool(false);
    char name[128];
    ValToCStr(ArgOr(args, argc, 0), name, sizeof(name));
    return JsValue::Bool(nb->node->GetAttr(name) != nullptr);
}

Result<JsValue> MRemoveAttribute(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Undefined();
    char name[128];
    ValToCStr(ArgOr(args, argc, 0), name, sizeof(name));
    RemoveAttribute(nb->node, name);
    return JsValue::Undefined();
}

Result<JsValue> MAppendChild(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* parent = BindOf(recv);
    NodeBind* child = BindOf(ArgOr(args, argc, 0));
    if (!parent || !child)
        return Err{ErrorCode::BadState};
    AppendChild(parent->node, child->node);
    return args[0]; // DOM appendChild returns the appended node
}

Result<JsValue> MRemoveChild(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* parent = BindOf(recv);
    NodeBind* child = BindOf(ArgOr(args, argc, 0));
    if (!parent || !child)
        return Err{ErrorCode::BadState};
    if (!RemoveChild(parent->node, child->node))
        return Err{ErrorCode::NotFound};
    return args[0];
}

// ---- element-scoped query methods (subtree rooted at the receiver) ----

Result<JsValue> MQuerySelector(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Null();
    char sel[128];
    u32 sl = ValToCStr(ArgOr(args, argc, 0), sel, sizeof(sel));
    LiteSelector ls = ParseLiteSelector(sel, sl);
    if (!ls.valid)
        return JsValue::Null();
    return WrapNode(*nb->ctx, LiteFindFirst(nb->node, ls));
}

Result<JsValue> MQuerySelectorAll(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Undefined();
    char sel[128];
    u32 sl = ValToCStr(ArgOr(args, argc, 0), sel, sizeof(sel));
    LiteSelector ls = ParseLiteSelector(sel, sl);
    Node* hits[256];
    u32 count = 0;
    if (ls.valid)
        LiteCollect(nb->node, ls, hits, 256, count);
    u32 n = count < 256 ? count : 256;
    return WrapNodeList(*nb->ctx, hits, n);
}

Result<JsValue> MGetElementsByTagName(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Undefined();
    char tag[64];
    u32 tl = ValToCStr(ArgOr(args, argc, 0), tag, sizeof(tag));
    for (u32 i = 0; i < tl; ++i)
        if (tag[i] >= 'A' && tag[i] <= 'Z')
            tag[i] = char(tag[i] + 32);
    Node* hits[256];
    u32 count = 0;
    // '*' collects all descendant elements (mirror querySelectorAll('*')).
    if (tl == 1 && tag[0] == '*')
    {
        LiteSelector ls{};
        ls.universal = true;
        ls.valid = true;
        LiteCollect(nb->node, ls, hits, 256, count);
    }
    else
    {
        CollectByTag(nb->node, tag, hits, 256, count);
    }
    u32 n = count < 256 ? count : 256;
    return WrapNodeList(*nb->ctx, hits, n);
}

Result<JsValue> MGetElementsByClassName(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Undefined();
    char cls[128];
    ValToCStr(ArgOr(args, argc, 0), cls, sizeof(cls));
    Node* hits[256];
    u32 count = 0;
    CollectByClass(nb->node, cls, hits, 256, count);
    u32 n = count < 256 ? count : 256;
    return WrapNodeList(*nb->ctx, hits, n);
}

// ---------------------------------------------------------------------------
// element.classList — a small live token-list facade over the `class`
// attribute. add/remove/toggle rewrite the attribute through SetAttribute
// (DOM-arena copy); contains tests membership. The receiver of each
// method is the classList object itself, whose hostData is the OWNING
// element's NodeBind (set up in MakeClassList), so mutations land on the
// real element. GAP: no `replace`, no `item(i)`, no iterable/length —
// the three mutators + contains cover the scripting need here.
// ---------------------------------------------------------------------------

// Rebuild a `class` attribute from the element's current tokens, with one
// token added or removed. `add` true => ensure `tok` present; false =>
// ensure absent. Writes the result back via SetAttribute. Returns whether
// the token is present AFTER the operation.
bool ClassListWrite(DomCtx& ctx, Node* el, const char* tok, u32 tokLen, bool add)
{
    char buf[1024];
    u32 o = 0;
    const char* cur = el->GetAttr("class");
    u32 total = Slen(cur);
    u32 i = 0;
    bool present = false;
    while (i < total)
    {
        while (i < total && (cur[i] == ' ' || cur[i] == '\t' || cur[i] == '\n'))
            ++i;
        u32 s = i;
        while (i < total && cur[i] != ' ' && cur[i] != '\t' && cur[i] != '\n')
            ++i;
        u32 wl = i - s;
        if (wl == 0)
            continue;
        bool same = (wl == tokLen);
        for (u32 k = 0; same && k < tokLen; ++k)
            if (cur[s + k] != tok[k])
                same = false;
        if (same)
        {
            present = true;
            if (!add)
                continue; // drop this token
        }
        // Keep this token.
        if (o > 0 && o < sizeof(buf))
            buf[o++] = ' ';
        for (u32 k = 0; k < wl && o < sizeof(buf); ++k)
            buf[o++] = cur[s + k];
    }
    if (add && !present)
    {
        if (o > 0 && o < sizeof(buf))
            buf[o++] = ' ';
        for (u32 k = 0; k < tokLen && o < sizeof(buf); ++k)
            buf[o++] = tok[k];
    }
    SetAttribute(ctx, el, "class", 5, buf, o);
    return add; // present-after: true for add, false for remove
}

Result<JsValue> MClassListAdd(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb || nb->node->kind != NodeKind::Element)
        return JsValue::Undefined();
    char tok[128];
    u32 tl = ValToCStr(ArgOr(args, argc, 0), tok, sizeof(tok));
    if (tl > 0)
        ClassListWrite(*nb->ctx, nb->node, tok, tl, true);
    return JsValue::Undefined();
}

Result<JsValue> MClassListRemove(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb || nb->node->kind != NodeKind::Element)
        return JsValue::Undefined();
    char tok[128];
    u32 tl = ValToCStr(ArgOr(args, argc, 0), tok, sizeof(tok));
    if (tl > 0)
        ClassListWrite(*nb->ctx, nb->node, tok, tl, false);
    return JsValue::Undefined();
}

Result<JsValue> MClassListContains(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Bool(false);
    char tok[128];
    u32 tl = ValToCStr(ArgOr(args, argc, 0), tok, sizeof(tok));
    return JsValue::Bool(TokenListHas(nb->node->GetAttr("class"), tok, tl));
}

// toggle(tok[, force]): if force given, behaves like add/remove; else
// flips membership. Returns the present-after-state as a JS bool.
Result<JsValue> MClassListToggle(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb || nb->node->kind != NodeKind::Element)
        return JsValue::Bool(false);
    char tok[128];
    u32 tl = ValToCStr(ArgOr(args, argc, 0), tok, sizeof(tok));
    if (tl == 0)
        return JsValue::Bool(false);
    bool has = TokenListHas(nb->node->GetAttr("class"), tok, tl);
    bool add = (argc >= 2) ? js::ToBoolean(args[1]) : !has;
    ClassListWrite(*nb->ctx, nb->node, tok, tl, add);
    return JsValue::Bool(add);
}

// Build the classList host object. Its hostData is the SAME NodeBind as
// the owning element (so its methods operate on that element); its
// hostGet exposes only the four classList methods.
Result<JsValue> ClassListHostGet(Interp&, JsObject* self, const char* key, u32 keyLen);

JsValue MakeClassList(DomCtx& ctx, NodeBind* owner)
{
    JsObject* o = js::ObjNew(*ctx.js, false);
    if (!o)
        return JsValue::Undefined();
    o->hostData = owner;
    o->hostGet = ClassListHostGet;
    return JsValue::Obj(o);
}

Result<JsValue> ClassListHostGet(Interp&, JsObject* self, const char* key, u32 keyLen)
{
    NodeBind* nb = static_cast<NodeBind*>(self->hostData);
    if (!nb)
        return JsValue::Undefined();
    DomCtx& ctx = *nb->ctx;
    if (KeyIs(key, keyLen, "add"))
        return Method(ctx, MClassListAdd, "add");
    if (KeyIs(key, keyLen, "remove"))
        return Method(ctx, MClassListRemove, "remove");
    if (KeyIs(key, keyLen, "contains"))
        return Method(ctx, MClassListContains, "contains");
    if (KeyIs(key, keyLen, "toggle"))
        return Method(ctx, MClassListToggle, "toggle");
    return JsValue::Undefined();
}

// ---------------------------------------------------------------------------
// DOM event model — addEventListener / removeEventListener / dispatchEvent
// / click(). Programmatic only: a script registers a listener, then
// dispatchEvent()/click() fires it on the target through a CAPTURE phase
// (outermost ancestor → target) followed by a BUBBLE phase (target →
// outermost ancestor, dom.h `parent` links). A listener registered with
// `capture: true` (or addEventListener(type, fn, true)) fires only in the
// capture phase; a default listener fires only in the bubble phase. The
// event object exposes type / target / preventDefault() / defaultPrevented
// / stopPropagation(); stopPropagation halts BOTH phases. `once: true`
// listeners are removed after their first fire (in whichever phase). All
// listeners run via the engine's normal call path (CallFunction) at +1
// interpreter depth — the native-stack guard in CallFunction bounds
// runaway recursion; we add no C++ recursion per listener beyond that
// single call.
//
// GAP: `passive: true` is accepted and stored but NOT enforced — a passive
//   listener can still call preventDefault() and it takes effect (the spec
//   says it must be ignored). Event delegation works through normal
//   bubbling but matchesSelector-style delegation helpers and the full
//   Event/UIEvent/MouseEvent property surface remain out of scope.
// Real user input is routed: a window-manager mouse click reaches page
//   listeners through the retained JsDomContext (see the retained-context
//   section at the bottom of this file), which keeps the DomCtx + listeners
//   alive across the run→dispatch gap. The browser app creates the context
//   at render, RunScripts() each page <script> into it (registering
//   listeners), and on a WM click translates the hit layout box back to its
//   Node and calls JsDomContextDispatchClick(ctx, node) — the live path is
//   boot_tasks.cpp (compositor) → BrowserMouseInput → ScreenToDoc →
//   BrowserHitTestNode → JsDomContextDispatchClick.
// GAP: only "click" is delivered to page listeners. mousedown/mouseup/
//   mousemove and keyboard events (keydown/keyup) are not yet routed to the
//   page DOM (mousemove reaches only the browser chrome); revisit when a
//   page needs them.
// ---------------------------------------------------------------------------

// Per-dispatch event state, backing the JS event host object. Lives on
// the JS arena for the duration of the eval (a dispatch completes before
// the eval returns, so the bool flags are only read during bubbling).
struct EventState
{
    DomCtx* ctx = nullptr;
    Node* target = nullptr;
    const char* type = nullptr; // JS-arena copy
    bool defaultPrevented = false;
    bool propagationStopped = false;
};

Result<JsValue> MEventPreventDefault(Interp&, const JsValue& recv, const JsValue*, u32, void*)
{
    if (recv.type == JsType::Object && recv.as.obj)
        if (auto* ev = static_cast<EventState*>(recv.as.obj->hostData))
            ev->defaultPrevented = true;
    return JsValue::Undefined();
}

Result<JsValue> MEventStopPropagation(Interp&, const JsValue& recv, const JsValue*, u32, void*)
{
    if (recv.type == JsType::Object && recv.as.obj)
        if (auto* ev = static_cast<EventState*>(recv.as.obj->hostData))
            ev->propagationStopped = true;
    return JsValue::Undefined();
}

// hostGet for the event object: type / target / defaultPrevented as
// properties, preventDefault / stopPropagation as bound methods.
Result<JsValue> EventHostGet(Interp& I, JsObject* self, const char* key, u32 keyLen)
{
    auto* ev = static_cast<EventState*>(self->hostData);
    if (!ev)
        return JsValue::Undefined();
    if (KeyIs(key, keyLen, "type"))
        return JsValue::Str(js::MakeString(I.arena, ev->type ? ev->type : "", Slen(ev->type)));
    if (KeyIs(key, keyLen, "target"))
        return WrapNode(*ev->ctx, ev->target);
    if (KeyIs(key, keyLen, "defaultPrevented"))
        return JsValue::Bool(ev->defaultPrevented);
    if (KeyIs(key, keyLen, "preventDefault"))
        return Method(*ev->ctx, MEventPreventDefault, "preventDefault");
    if (KeyIs(key, keyLen, "stopPropagation"))
        return Method(*ev->ctx, MEventStopPropagation, "stopPropagation");
    return JsValue::Undefined();
}

// Build the JS event host object wrapping `ev`.
JsValue MakeEventObject(DomCtx& ctx, EventState* ev)
{
    JsObject* o = js::ObjNew(*ctx.js, false);
    if (!o)
        return JsValue::Undefined();
    o->hostData = ev;
    o->hostGet = EventHostGet;
    return JsValue::Obj(o);
}

// Find an existing live registration for (node, type, fn, capture), or -1.
// `capture` is part of listener identity per the DOM spec: the same fn
// registered for both phases is two distinct listeners, and
// removeEventListener with a mismatched capture flag must NOT remove.
i32 FindListener(DomCtx& ctx, Node* node, const char* type, js::JsFunction* fn, bool capture)
{
    for (u32 i = 0; i < ctx.listenerCount; ++i)
    {
        Listener& l = ctx.listeners[i];
        if (l.live && l.node == node && l.fn == fn && l.capture == capture && l.type &&
            duetos::core::StrEqual(l.type, type))
            return i32(i);
    }
    return -1;
}

// Invoke one stored listener with the event object as the sole argument.
// Listeners are normally JS closures (CallFunction); a native-callback
// listener is dispatched through its nativeCall instead (CallFunction
// dereferences fn->node, which is null for native callbacks). Errors
// (Timeout, Overflow, OOM) propagate so dispatch fails the eval the same
// way any other script error does.
Result<void> InvokeListener(Interp& I, js::JsFunction* fn, const JsValue& eventVal, const JsValue& recv)
{
    if (!fn)
        return {};
    if (fn->node)
    {
        JS_TRY(js::CallFunction(I, fn, &eventVal, 1, recv));
    }
    else if (fn->nativeCall)
    {
        JS_TRY(fn->nativeCall(I, recv, &eventVal, 1, fn->nativeCtx));
    }
    return {};
}

// Fire the matching listeners on a single node for one phase. `wantCapture`
// selects capture-phase listeners (true) vs bubble/target-phase listeners
// (false). Returns Ok unless an invoked listener errors; sets `*outStopped`
// if stopPropagation was called (the caller halts the remaining path).
//
// The listener set is snapshotted by index up front (snap = listenerCount)
// so a listener that *adds* a registration during this fire is not itself
// fired until a future dispatch. `live` is re-checked per slot so a removal
// mid-dispatch — including a `once` self-removal — still takes effect for
// not-yet-fired slots. A `once` listener is tombstoned the instant it fires
// (before InvokeListener so a re-entrant dispatch of the same event can't
// double-fire it), regardless of which phase fired it.
Result<void> FireNodePhase(Interp& I, DomCtx& ctx, Node* node, const char* type, bool wantCapture,
                           const JsValue& eventVal, EventState* ev)
{
    JsValue recv = WrapNode(ctx, node);
    u32 snap = ctx.listenerCount;
    for (u32 i = 0; i < snap; ++i)
    {
        Listener& l = ctx.listeners[i];
        if (!l.live || l.node != node || l.capture != wantCapture || !l.type || !duetos::core::StrEqual(l.type, type))
            continue;
        js::JsFunction* fn = l.fn;
        if (l.once)
            l.live = false; // remove-before-invoke: a once listener fires exactly once
        JS_TRY(InvokeListener(I, fn, eventVal, recv));
        if (ev->propagationStopped)
            break;
    }
    return {};
}

// Dispatch `type` to `target` in two phases: a CAPTURE phase walking the
// ancestor chain from the OUTERMOST ancestor down toward (but not
// including) the target, then a BUBBLE phase from the target up to the
// root. Capture-phase listeners fire only in the first walk; default
// listeners fire only in the second. The target node itself participates in
// the bubble walk (its non-capture listeners are the "target phase"; a
// capture listener on the target also fires there per the DOM, which our
// bubble walk picks up — see below). stopPropagation() halts BOTH phases.
//
// The ancestor chain is materialized once into a bounded buffer (the DOM
// is shallow in practice; if it exceeds the buffer we cap the captured
// ancestors — capture phase then starts from the deepest captured ancestor,
// a graceful degradation rather than a fault).
//
// `defaultPrevented` (set by any listener calling preventDefault) is
// reported back through the out-param so dispatchEvent can return the
// DOM's "not cancelled" boolean.
Result<void> DispatchEvent(Interp& I, DomCtx& ctx, Node* target, const char* type, bool& outPrevented)
{
    outPrevented = false;
    EventState* ev = ctx.js->New<EventState>();
    if (!ev)
        return Err{ErrorCode::OutOfMemory};
    ev->ctx = &ctx;
    ev->target = target;
    ev->type = type;
    JsValue eventVal = MakeEventObject(ctx, ev);

    // Materialize the strict ancestor chain (target's parent up to the
    // root), nearest-first. Bounded buffer: a pathological depth caps the
    // captured ancestors rather than recursing or faulting.
    static constexpr u32 kMaxPath = 64;
    Node* ancestors[kMaxPath];
    u32 nAnc = 0;
    for (Node* cur = target->parent; cur && nAnc < kMaxPath; cur = cur->parent)
        ancestors[nAnc++] = cur;

    // Capture phase: outermost ancestor → toward the target (skips target).
    for (u32 i = nAnc; i-- > 0;)
    {
        JS_TRY(FireNodePhase(I, ctx, ancestors[i], type, /*wantCapture=*/true, eventVal, ev));
        if (ev->propagationStopped)
        {
            outPrevented = ev->defaultPrevented;
            return {};
        }
    }

    // Target + bubble phase: target → outermost ancestor. At the target,
    // both capture and bubble listeners fire (target-phase listeners are
    // not split by the spec); ancestors fire only their bubble listeners.
    JS_TRY(FireNodePhase(I, ctx, target, type, /*wantCapture=*/true, eventVal, ev));
    if (!ev->propagationStopped)
        JS_TRY(FireNodePhase(I, ctx, target, type, /*wantCapture=*/false, eventVal, ev));
    if (!ev->propagationStopped)
    {
        for (u32 i = 0; i < nAnc; ++i)
        {
            JS_TRY(FireNodePhase(I, ctx, ancestors[i], type, /*wantCapture=*/false, eventVal, ev));
            if (ev->propagationStopped)
                break;
        }
    }

    outPrevented = ev->defaultPrevented;
    return {};
}

// Parse addEventListener's 3rd argument. Per the DOM it may be omitted, a
// boolean (true == capture, the legacy form), or an options object
// { capture, once, passive } (each a truthy/falsy member; absent == false).
// `opt` may be Undefined. `outOnce`/`outPassive` are left untouched for the
// boolean/omitted forms (only the options-object form sets them).
void ParseListenerOptions(const JsValue& opt, bool& outCapture, bool& outOnce, bool& outPassive)
{
    if (opt.type == JsType::Object && opt.as.obj)
    {
        JsValue v{};
        if (js::ObjGet(opt.as.obj, "capture", 7, v))
            outCapture = js::ToBoolean(v);
        if (js::ObjGet(opt.as.obj, "once", 4, v))
            outOnce = js::ToBoolean(v);
        if (js::ObjGet(opt.as.obj, "passive", 7, v))
            outPassive = js::ToBoolean(v);
        return;
    }
    // Boolean or omitted/undefined: ToBoolean(undefined) == false, so the
    // omitted form correctly yields the default (bubble-phase) listener.
    outCapture = js::ToBoolean(opt);
}

Result<JsValue> MAddEventListener(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Undefined();
    JsValue typeArg = ArgOr(args, argc, 0);
    JsValue fnArg = ArgOr(args, argc, 1);
    if (!fnArg.IsCallable())
        return JsValue::Undefined(); // non-callable listener: no-op (DOM coerces; we drop)
    bool capture = false;
    bool once = false;
    bool passive = false;
    ParseListenerOptions(ArgOr(args, argc, 2), capture, once, passive);
    DomCtx& ctx = *nb->ctx;
    char tbuf[64];
    u32 tl = ValToCStr(typeArg, tbuf, sizeof(tbuf));
    const char* type = JsCopyStr(*ctx.js, tbuf, tl);
    if (!type)
        return Err{ErrorCode::OutOfMemory};
    // De-dupe: the DOM ignores a repeat (type, listener, capture)
    // registration. capture is part of identity; once/passive are not — a
    // duplicate that only changes once/passive is still ignored per spec.
    if (FindListener(ctx, nb->node, type, fnArg.as.fn, capture) >= 0)
        return JsValue::Undefined();
    if (ctx.listenerCount >= DomCtx::kMaxListeners)
        return JsValue::Undefined(); // cap reached — drop (documented bound)
    Listener& l = ctx.listeners[ctx.listenerCount++];
    l.node = nb->node;
    l.type = type;
    l.fn = fnArg.as.fn;
    l.live = true;
    l.capture = capture;
    l.once = once;
    // GAP: passive is recorded but not enforced — preventDefault() from a
    //   passive listener still takes effect (spec says it must be ignored).
    l.passive = passive;
    return JsValue::Undefined();
}

Result<JsValue> MRemoveEventListener(Interp&, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Undefined();
    JsValue fnArg = ArgOr(args, argc, 1);
    if (!fnArg.IsCallable())
        return JsValue::Undefined();
    // removeEventListener matches on (type, fn, capture). Only the capture
    // flag of the options arg matters here (once/passive are not identity).
    bool capture = false;
    bool ignoredOnce = false;
    bool ignoredPassive = false;
    ParseListenerOptions(ArgOr(args, argc, 2), capture, ignoredOnce, ignoredPassive);
    DomCtx& ctx = *nb->ctx;
    char tbuf[64];
    u32 tl = ValToCStr(ArgOr(args, argc, 0), tbuf, sizeof(tbuf));
    const char* type = JsCopyStr(*ctx.js, tbuf, tl);
    if (!type)
        return JsValue::Undefined();
    i32 idx = FindListener(ctx, nb->node, type, fnArg.as.fn, capture);
    if (idx >= 0)
        ctx.listeners[idx].live = false; // tombstone; slot reuse not needed at this cap
    return JsValue::Undefined();
}

Result<JsValue> MDispatchEvent(Interp& I, const JsValue& recv, const JsValue* args, u32 argc, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Bool(false);
    DomCtx& ctx = *nb->ctx;
    // The event argument may be a string ("click") or an event-like
    // object exposing a `type`. Pull the type out; default to the empty
    // string (no listener will match, returns true).
    JsValue arg = ArgOr(args, argc, 0);
    char tbuf[64];
    u32 tl = 0;
    if (arg.type == JsType::Object && arg.as.obj)
    {
        JsValue t{};
        if (js::ObjGet(arg.as.obj, "type", 4, t))
            tl = ValToCStr(t, tbuf, sizeof(tbuf));
        else if (arg.as.obj->hostGet)
        {
            // A host event object: read its `type` through the hook.
            Result<JsValue> tv = arg.as.obj->hostGet(I, arg.as.obj, "type", 4);
            if (tv)
                tl = ValToCStr(tv.value(), tbuf, sizeof(tbuf));
        }
    }
    else
    {
        tl = ValToCStr(arg, tbuf, sizeof(tbuf));
    }
    const char* type = JsCopyStr(*ctx.js, tbuf, tl);
    if (!type)
        return Err{ErrorCode::OutOfMemory};
    bool prevented = false;
    JS_TRY(DispatchEvent(I, ctx, nb->node, type, prevented));
    // DOM dispatchEvent returns false iff a listener called
    // preventDefault (the event is treated as cancelable), else true.
    return JsValue::Bool(!prevented);
}

Result<JsValue> MClick(Interp& I, const JsValue& recv, const JsValue*, u32, void*)
{
    NodeBind* nb = BindOf(recv);
    if (!nb)
        return JsValue::Undefined();
    DomCtx& ctx = *nb->ctx;
    const char* type = JsCopyStr(*ctx.js, "click", 5);
    if (!type)
        return Err{ErrorCode::OutOfMemory};
    bool prevented = false;
    JS_TRY(DispatchEvent(I, ctx, nb->node, type, prevented));
    return JsValue::Undefined();
}

// ---------------------------------------------------------------------------
// document methods (recv = the document host object; ctx via nativeCtx).
// ---------------------------------------------------------------------------

Result<JsValue> DGetElementById(Interp&, const JsValue&, const JsValue* args, u32 argc, void* ctxp)
{
    DomCtx* ctx = CtxOf(ctxp);
    char id[128];
    ValToCStr(ArgOr(args, argc, 0), id, sizeof(id));
    Node* hit = FindById(ctx->doc, id);
    return WrapNode(*ctx, hit); // Null when not found
}

Result<JsValue> DGetElementsByTagName(Interp&, const JsValue&, const JsValue* args, u32 argc, void* ctxp)
{
    DomCtx* ctx = CtxOf(ctxp);
    char tag[64];
    u32 tl = ValToCStr(ArgOr(args, argc, 0), tag, sizeof(tag));
    for (u32 i = 0; i < tl; ++i)
        if (tag[i] >= 'A' && tag[i] <= 'Z')
            tag[i] = char(tag[i] + 32);
    Node* hits[256];
    u32 count = 0;
    CollectByTag(ctx->doc, tag, hits, 256, count);
    u32 n = count < 256 ? count : 256;
    return WrapNodeList(*ctx, hits, n);
}

Result<JsValue> DGetElementsByClassName(Interp&, const JsValue&, const JsValue* args, u32 argc, void* ctxp)
{
    DomCtx* ctx = CtxOf(ctxp);
    char cls[128];
    ValToCStr(ArgOr(args, argc, 0), cls, sizeof(cls));
    Node* hits[256];
    u32 count = 0;
    CollectByClass(ctx->doc, cls, hits, 256, count);
    u32 n = count < 256 ? count : 256;
    return WrapNodeList(*ctx, hits, n);
}

// querySelector: first descendant matching a single compound selector
// (tag / .class / #id / *, in combination). GAP: descendant combinators,
// attribute / pseudo selectors, selector lists — see ParseLiteSelector.
Result<JsValue> DQuerySelector(Interp&, const JsValue&, const JsValue* args, u32 argc, void* ctxp)
{
    DomCtx* ctx = CtxOf(ctxp);
    char sel[128];
    u32 sl = ValToCStr(ArgOr(args, argc, 0), sel, sizeof(sel));
    LiteSelector ls = ParseLiteSelector(sel, sl);
    if (!ls.valid)
        return JsValue::Null();
    return WrapNode(*ctx, LiteFindFirst(ctx->doc, ls));
}

// querySelectorAll: a JS array of every descendant matching the selector.
Result<JsValue> DQuerySelectorAll(Interp&, const JsValue&, const JsValue* args, u32 argc, void* ctxp)
{
    DomCtx* ctx = CtxOf(ctxp);
    char sel[128];
    u32 sl = ValToCStr(ArgOr(args, argc, 0), sel, sizeof(sel));
    LiteSelector ls = ParseLiteSelector(sel, sl);
    Node* hits[256];
    u32 count = 0;
    if (ls.valid)
        LiteCollect(ctx->doc, ls, hits, 256, count);
    u32 n = count < 256 ? count : 256;
    return WrapNodeList(*ctx, hits, n);
}

Result<JsValue> DCreateElement(Interp&, const JsValue&, const JsValue* args, u32 argc, void* ctxp)
{
    DomCtx* ctx = CtxOf(ctxp);
    char tag[64];
    u32 tl = ValToCStr(ArgOr(args, argc, 0), tag, sizeof(tag));
    Node* el = MakeElement(*ctx, tag, tl);
    if (!el)
        return Err{ErrorCode::OutOfMemory};
    return WrapNode(*ctx, el);
}

Result<JsValue> DCreateTextNode(Interp&, const JsValue&, const JsValue* args, u32 argc, void* ctxp)
{
    DomCtx* ctx = CtxOf(ctxp);
    char buf[512];
    u32 n = ValToCStr(ArgOr(args, argc, 0), buf, sizeof(buf));
    Node* t = MakeTextNode(*ctx, buf, n);
    if (!t)
        return Err{ErrorCode::OutOfMemory};
    return WrapNode(*ctx, t);
}

// ---------------------------------------------------------------------------
// Host property hooks. One hook covers Document, Element, and Text
// wrappers (branch on node kind). Returns Undefined for a miss so the
// interpreter falls through to the plain property map (ad-hoc JS props).
// ---------------------------------------------------------------------------

// document.documentElement: the <html> element, else the first child
// element of the Document root.
Node* DocumentElement(Node* doc)
{
    Node* html = doc->FirstChildByTag("html");
    if (html)
        return html;
    for (Node* c = doc->firstChild; c; c = c->nextSibling)
        if (c->kind == NodeKind::Element)
            return c;
    return nullptr;
}

// document.body: <body> under <html> (or anywhere as a fallback).
Node* DocumentBody(Node* doc)
{
    Node* html = DocumentElement(doc);
    if (html)
    {
        Node* body = html->FirstChildByTag("body");
        if (body)
            return body;
    }
    Node* hits[1];
    u32 count = 0;
    CollectByTag(doc, "body", hits, 1, count);
    return count > 0 ? hits[0] : nullptr;
}

Result<JsValue> ElemHostGet(Interp& I, JsObject* self, const char* key, u32 keyLen)
{
    NodeBind* nb = static_cast<NodeBind*>(self->hostData);
    if (!nb)
        return JsValue::Undefined();
    DomCtx& ctx = *nb->ctx;
    Node* node = nb->node;

    // ---- document-only surface ----
    if (node->kind == NodeKind::Document)
    {
        if (KeyIs(key, keyLen, "getElementById"))
            return Method(ctx, DGetElementById, "getElementById");
        if (KeyIs(key, keyLen, "getElementsByTagName"))
            return Method(ctx, DGetElementsByTagName, "getElementsByTagName");
        if (KeyIs(key, keyLen, "getElementsByClassName"))
            return Method(ctx, DGetElementsByClassName, "getElementsByClassName");
        if (KeyIs(key, keyLen, "querySelector"))
            return Method(ctx, DQuerySelector, "querySelector");
        if (KeyIs(key, keyLen, "querySelectorAll"))
            return Method(ctx, DQuerySelectorAll, "querySelectorAll");
        if (KeyIs(key, keyLen, "createElement"))
            return Method(ctx, DCreateElement, "createElement");
        if (KeyIs(key, keyLen, "createTextNode"))
            return Method(ctx, DCreateTextNode, "createTextNode");
        if (KeyIs(key, keyLen, "body"))
            return WrapNode(ctx, DocumentBody(node));
        if (KeyIs(key, keyLen, "documentElement"))
            return WrapNode(ctx, DocumentElement(node));
    }

    // ---- shared Node surface ----
    if (KeyIs(key, keyLen, "parentNode"))
        return WrapNode(ctx, node->parent);
    if (KeyIs(key, keyLen, "firstChild"))
        return WrapNode(ctx, node->firstChild);
    if (KeyIs(key, keyLen, "nextSibling"))
        return WrapNode(ctx, node->nextSibling);
    if (KeyIs(key, keyLen, "childNodes"))
    {
        // Snapshot of all child nodes (text + element).
        Node* kids[256];
        u32 c = 0;
        for (Node* k = node->firstChild; k && c < 256; k = k->nextSibling)
            kids[c++] = k;
        return WrapNodeList(ctx, kids, c);
    }
    if (KeyIs(key, keyLen, "textContent"))
    {
        char buf[1024];
        u32 n = web::CollectText(node, buf, sizeof(buf));
        return JsValue::Str(js::MakeString(I.arena, buf, n));
    }

    // ---- element-only surface ----
    if (node->kind == NodeKind::Element)
    {
        if (KeyIs(key, keyLen, "tagName"))
        {
            // tagName is conventionally upper-case.
            char up[64];
            u32 tl = Slen(node->tag);
            u32 m = tl < sizeof(up) ? tl : u32(sizeof(up) - 1);
            for (u32 i = 0; i < m; ++i)
            {
                char ch = node->tag[i];
                up[i] = (ch >= 'a' && ch <= 'z') ? char(ch - 32) : ch;
            }
            return JsValue::Str(js::MakeString(I.arena, up, m));
        }
        if (KeyIs(key, keyLen, "id"))
        {
            const char* v = node->GetAttr("id");
            return JsValue::Str(js::MakeString(I.arena, v ? v : "", Slen(v)));
        }
        if (KeyIs(key, keyLen, "className"))
        {
            const char* v = node->GetAttr("class");
            return JsValue::Str(js::MakeString(I.arena, v ? v : "", Slen(v)));
        }
        if (KeyIs(key, keyLen, "children"))
        {
            // Element children only (skip text nodes).
            Node* kids[256];
            u32 c = 0;
            for (Node* k = node->firstChild; k && c < 256; k = k->nextSibling)
                if (k->kind == NodeKind::Element)
                    kids[c++] = k;
            return WrapNodeList(ctx, kids, c);
        }
        if (KeyIs(key, keyLen, "innerHTML"))
        {
            char buf[4096];
            u32 o = 0;
            SerializeChildren(node, buf, sizeof(buf), o);
            return JsValue::Str(js::MakeString(I.arena, buf, o));
        }
        if (KeyIs(key, keyLen, "getAttribute"))
            return Method(ctx, MGetAttribute, "getAttribute");
        if (KeyIs(key, keyLen, "setAttribute"))
            return Method(ctx, MSetAttribute, "setAttribute");
        if (KeyIs(key, keyLen, "hasAttribute"))
            return Method(ctx, MHasAttribute, "hasAttribute");
        if (KeyIs(key, keyLen, "removeAttribute"))
            return Method(ctx, MRemoveAttribute, "removeAttribute");
        if (KeyIs(key, keyLen, "appendChild"))
            return Method(ctx, MAppendChild, "appendChild");
        if (KeyIs(key, keyLen, "removeChild"))
            return Method(ctx, MRemoveChild, "removeChild");
        if (KeyIs(key, keyLen, "querySelector"))
            return Method(ctx, MQuerySelector, "querySelector");
        if (KeyIs(key, keyLen, "querySelectorAll"))
            return Method(ctx, MQuerySelectorAll, "querySelectorAll");
        if (KeyIs(key, keyLen, "getElementsByTagName"))
            return Method(ctx, MGetElementsByTagName, "getElementsByTagName");
        if (KeyIs(key, keyLen, "getElementsByClassName"))
            return Method(ctx, MGetElementsByClassName, "getElementsByClassName");
        if (KeyIs(key, keyLen, "classList"))
            return MakeClassList(ctx, nb);
    }

    // ---- event model (EventTarget surface — element + document) ----
    if (KeyIs(key, keyLen, "addEventListener"))
        return Method(ctx, MAddEventListener, "addEventListener");
    if (KeyIs(key, keyLen, "removeEventListener"))
        return Method(ctx, MRemoveEventListener, "removeEventListener");
    if (KeyIs(key, keyLen, "dispatchEvent"))
        return Method(ctx, MDispatchEvent, "dispatchEvent");
    if (node->kind == NodeKind::Element && KeyIs(key, keyLen, "click"))
        return Method(ctx, MClick, "click");

    return JsValue::Undefined(); // miss → fall through to plain props
}

Result<bool> ElemHostSet(Interp&, JsObject* self, const char* key, u32 keyLen, const JsValue& v)
{
    NodeBind* nb = static_cast<NodeBind*>(self->hostData);
    if (!nb || nb->node->kind != NodeKind::Element)
        return false;
    DomCtx& ctx = *nb->ctx;
    Node* node = nb->node;

    char buf[1024];
    if (KeyIs(key, keyLen, "id"))
    {
        u32 n = ValToCStr(v, buf, sizeof(buf));
        return SetAttribute(ctx, node, "id", 2, buf, n) ? Result<bool>{true} : Err{ErrorCode::OutOfMemory};
    }
    if (KeyIs(key, keyLen, "className"))
    {
        u32 n = ValToCStr(v, buf, sizeof(buf));
        return SetAttribute(ctx, node, "class", 5, buf, n) ? Result<bool>{true} : Err{ErrorCode::OutOfMemory};
    }
    if (KeyIs(key, keyLen, "textContent"))
    {
        u32 n = ValToCStr(v, buf, sizeof(buf));
        return SetTextContent(ctx, node, buf, n) ? Result<bool>{true} : Err{ErrorCode::OutOfMemory};
    }
    if (KeyIs(key, keyLen, "innerHTML"))
    {
        // Stage the assigned markup in a scratch buffer (sized to match
        // the innerHTML getter's serialization buffer), then parse-and-
        // replace. GAP: markup longer than the buffer is truncated — same
        // bound the getter round-trips against.
        char html[4096];
        u32 n = ValToCStr(v, html, sizeof(html));
        return SetInnerHtml(ctx, node, html, n) ? Result<bool>{true} : Err{ErrorCode::OutOfMemory};
    }
    return false; // not handled → plain property map takes the write
}

// JS engine scratch arena. Single-threaded boot/self-test use only; a
// concurrent caller would need a per-call buffer. Sized for the DOM
// binding battery plus wrapper objects with headroom.
alignas(16) u8 g_jsDomArena[768 * 1024];

} // namespace

// ---------------------------------------------------------------------------
// Retained DOM+JS context (singleton). See js_dom.h for the lifetime
// contract. The whole point: the Interp, its global env, and the DomCtx
// (listeners + wrapper cache) PERSIST across RunScript / DispatchClick so
// a listener a page <script> registers survives to a later user click.
//
// CRITICAL lifetime invariant: Interp holds `Arena&` and `ConsoleBuf&` by
// reference (interp.h), so those referents MUST outlive the Interp and
// MUST be the context's OWN members — not stack temporaries. Hence the
// member declaration order below is load-bearing: `jsArena` and `console`
// are declared (and so constructed) BEFORE `interp`, and the constructor
// member-initializes `interp(jsArena, console)` against THIS object's own
// members.
//
// The JS arena is reset (by assigning a fresh Arena over g_jsDomArena in
// Create — see the note there on why this rewinds the bump pointer while
// keeping interp's reference valid) ONLY on a new page. It is NEVER reset
// between RunScript and DispatchClick, so listeners + their closures + the
// wrapper cache stay live across the run→dispatch gap.
// ---------------------------------------------------------------------------

// JsDomContext is defined at namespace (not anonymous) scope because it is
// forward-declared in js_dom.h. It still names anonymous-namespace types
// (DomCtx / Interp) — legal within this TU, where the anonymous namespace
// is part of duetos::web.
struct JsDomContext
{
    // --- declaration order matters: jsArena + console BEFORE interp ---
    char consoleBuf[1024] = {};                                     // context-owned console backing store
    js::Arena jsArena{g_jsDomArena, sizeof(g_jsDomArena)};          // bump arena over g_jsDomArena
    js::ConsoleBuf console{consoleBuf, u32(sizeof(consoleBuf)), 0}; // writes into consoleBuf
    Interp interp{jsArena, console};                                // refs THIS object's jsArena + console
    DomCtx domCtx{};                                                // listeners + wrapper cache PERSIST here
    Document* doc = nullptr;
    bool live = false;

    // Optional mirror of the captured console output for the browser app.
    char* consoleOut = nullptr;
    u32 consoleOutCap = 0;
};

namespace
{

// Single active context. (GAP: one page at a time — no tabs / concurrent
// pages; Create resets this singleton.)
JsDomContext g_domContext;

// Wire a freshly (re)constructed context's interpreter: install the
// language builtins and the live `document` binding. Returns the status;
// on failure the context is left not-live.
Result<void> ContextInstall(JsDomContext& c, Document* doc, Arena& domArena)
{
    Interp& I = c.interp;
    I.stepBudget = js::kDefaultStepBudget;
    I.maxDepth = js::kMaxCallDepth;
    I.depth = 0;
    I.flow = js::Flow::Normal;
    I.returnValue = JsValue::Undefined();
    I.global = js::EnvNew(c.jsArena, nullptr);
    if (!I.global)
        return Err{ErrorCode::OutOfMemory};
    RESULT_TRY(js::InstallBuiltins(I));

    // Point the retained DomCtx at this page. The DomCtx is a member, so
    // its listener table + wrapper cache live for the context's lifetime
    // (i.e. until the next Create), NOT just one eval.
    c.domCtx.doc = doc;
    c.domCtx.js = &c.jsArena;
    c.domCtx.dom = &domArena;

    JsValue documentVal = WrapNode(c.domCtx, doc);
    js::EnvDefine(I.global, c.jsArena, "document", 8, documentVal);

    c.doc = doc;
    return {};
}

} // namespace

// ---------------------------------------------------------------------------
// Public entry points.
// ---------------------------------------------------------------------------

JsDomContext* JsDomContextCreate(Document* doc, Arena& domArena, char* console_out, u32 console_cap)
{
    if (!doc)
        return nullptr;

    // Reset the singleton WITHOUT reconstructing it — the freestanding
    // kernel provides no placement-new, and reconstructing would also
    // rebind interp's Arena&/ConsoleBuf& references. Instead reset each
    // member in place:
    //   - jsArena: assign a fresh Arena over g_jsDomArena. Arena is a
    //     trivially-copyable value (base/cap/used/oom), so this rewinds
    //     the bump pointer to 0 while interp.arena STILL references this
    //     same `c.jsArena` member object (reference unchanged — we only
    //     overwrote its bytes, not its address). This is the arena reset.
    //   - console: rewind len to 0 (the backing buffer is reused).
    //   - domCtx: assign a default DomCtx{} so the listener table and
    //     wrapper cache counts go back to zero for the new page.
    // interp itself is NOT reconstructed: its arena/console references
    // remain bound to c.jsArena / c.console, which we just reset.
    JsDomContext& c = g_domContext;
    c.jsArena = js::Arena(g_jsDomArena, sizeof(g_jsDomArena));
    c.console.len = 0;
    c.consoleBuf[0] = '\0';
    c.domCtx = DomCtx{};
    c.doc = nullptr;
    c.live = false;

    c.consoleOut = console_out;
    c.consoleOutCap = console_cap;
    if (console_out && console_cap)
        console_out[0] = '\0';

    if (Result<void> r = ContextInstall(c, doc, domArena); !r)
    {
        c.live = false;
        return nullptr;
    }
    c.live = true;
    return &c;
}

Result<void> JsDomContextRunScript(JsDomContext* ctx, const char* script, u32 len)
{
    if (!ctx || !ctx->live)
        return Err{ErrorCode::InvalidArgument};

    Interp& I = ctx->interp;

    // Lex + parse this script's AST into the RETAINED JS arena. (The AST
    // is reachable only during this eval, but it shares the arena with the
    // persistent listeners/closures — which is fine: the arena is reset
    // only by the next Create, and the AST simply becomes dead space until
    // then. A page runs a bounded number of <script> blocks.)
    js::TokenStream toks = js::Lex(script, len, ctx->jsArena);
    if (!toks.ok)
        return Err{ErrorCode::InvalidArgument};
    js::ParseResult pr = js::Parse(toks, ctx->jsArena);
    if (!pr.ok)
        return Err{ErrorCode::InvalidArgument};

    // Each RunScript gets a fresh step budget and starts from the normal
    // flow state; the global env + DomCtx (listeners) carry over.
    I.stepBudget = js::kDefaultStepBudget;
    I.depth = 0;
    I.flow = js::Flow::Normal;
    I.returnValue = JsValue::Undefined();

    Result<JsValue> r = js::EvalStmt(I, pr.program, I.global);

    // Mirror the (cumulative) console output into the caller's buffer.
    if (ctx->consoleOut && ctx->consoleOutCap)
    {
        u32 n = ctx->console.len < ctx->consoleOutCap ? ctx->console.len : ctx->consoleOutCap - 1;
        for (u32 i = 0; i < n; ++i)
            ctx->consoleOut[i] = ctx->consoleBuf[i];
        ctx->consoleOut[n] = '\0';
    }

    if (!r)
        return Err{r.error()};
    return {};
}

bool JsDomContextDispatchClick(JsDomContext* ctx, Node* target)
{
    if (!ctx || !ctx->live || !target)
        return false;

    Interp& I = ctx->interp;
    // A dispatch may run listener closures, so give it a fresh budget and
    // clean flow state (the same way RunScript primes each eval).
    I.stepBudget = js::kDefaultStepBudget;
    I.depth = 0;
    I.flow = js::Flow::Normal;
    I.returnValue = JsValue::Undefined();

    bool prevented = false;
    Result<void> r = DispatchEvent(I, ctx->domCtx, target, "click", prevented);
    if (!r)
        return false; // a faulting listener does not count as preventDefault
    return prevented;
}

bool JsDomContextConsumeDirty(JsDomContext* ctx)
{
    if (!ctx)
        return false;
    const bool dirty = ctx->domCtx.domMutated;
    ctx->domCtx.domMutated = false;
    return dirty;
}

// JsRunOnDocument is now a thin one-shot adapter over the retained
// context: Create a fresh context for `doc`, run the single script, map
// the status into JsDomResult. This proves the retained path is
// behaviorally identical to the old one-shot path (the self-test's 32
// existing checks all flow through here).
JsDomResult JsRunOnDocument(Document* doc, const char* script, u32 len, Arena& domArena, char* console_out,
                            u32 console_cap)
{
    JsDomResult out{};
    if (console_out && console_cap)
        console_out[0] = '\0';

    JsDomContext* ctx = JsDomContextCreate(doc, domArena, console_out, console_cap);
    if (!ctx)
    {
        // doc null → InvalidArgument; install failure → OutOfMemory. Only
        // a null doc reaches here with doc == nullptr.
        out.status = doc ? Err{ErrorCode::OutOfMemory} : Err{ErrorCode::InvalidArgument};
        return out;
    }

    out.status = JsDomContextRunScript(ctx, script, len);

    // Report the console byte count (excluding NUL), bounded like before.
    u32 cap = console_cap;
    out.consoleLen = ctx->console.len < cap ? ctx->console.len : (cap ? cap - 1 : 0);
    return out;
}

} // namespace duetos::web
