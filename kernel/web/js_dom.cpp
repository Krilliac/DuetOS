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

struct DomCtx
{
    Document* doc = nullptr;
    js::Arena* js = nullptr; // JS scratch arena (wrappers, transient values)
    Arena* dom = nullptr;    // DOM arena (new nodes/attrs/strings persist)

    // Per-Node wrapper cache for identity. Linear is fine: a script
    // touches a handful of distinct nodes.
    static constexpr u32 kMaxWrappers = 256;
    Node* cacheNode[kMaxWrappers] = {};
    JsObject* cacheObj[kMaxWrappers] = {};
    u32 cacheCount = 0;
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

// Recursive class search (first match, document order). `cls` is the
// bare class token (no leading dot).
Node* FindByClass(Node* n, const char* cls)
{
    for (Node* c = n->firstChild; c; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element)
        {
            const char* cn = c->GetAttr("class");
            if (cn)
            {
                // Match `cls` as a whitespace-delimited token.
                u32 ln = Slen(cls);
                u32 i = 0;
                u32 total = Slen(cn);
                while (i < total)
                {
                    while (i < total && (cn[i] == ' ' || cn[i] == '\t' || cn[i] == '\n'))
                        ++i;
                    u32 s = i;
                    while (i < total && cn[i] != ' ' && cn[i] != '\t' && cn[i] != '\n')
                        ++i;
                    if (i - s == ln)
                    {
                        bool eq = true;
                        for (u32 k = 0; k < ln; ++k)
                            if (cn[s + k] != cls[k])
                            {
                                eq = false;
                                break;
                            }
                        if (eq)
                            return c;
                    }
                }
            }
        }
        Node* hit = FindByClass(c, cls);
        if (hit)
            return hit;
    }
    return nullptr;
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

// querySelector lite: '#id', '.class', or a bare tag. GAP: compound /
// descendant / attribute selectors.
Result<JsValue> DQuerySelector(Interp&, const JsValue&, const JsValue* args, u32 argc, void* ctxp)
{
    DomCtx* ctx = CtxOf(ctxp);
    char sel[128];
    u32 sl = ValToCStr(ArgOr(args, argc, 0), sel, sizeof(sel));
    if (sl == 0)
        return JsValue::Null();
    if (sel[0] == '#')
        return WrapNode(*ctx, FindById(ctx->doc, sel + 1));
    if (sel[0] == '.')
        return WrapNode(*ctx, FindByClass(ctx->doc, sel + 1));
    for (u32 i = 0; i < sl; ++i)
        if (sel[i] >= 'A' && sel[i] <= 'Z')
            sel[i] = char(sel[i] + 32);
    Node* hits[1];
    u32 count = 0;
    CollectByTag(ctx->doc, sel, hits, 1, count);
    return WrapNode(*ctx, count > 0 ? hits[0] : nullptr);
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
        if (KeyIs(key, keyLen, "querySelector"))
            return Method(ctx, DQuerySelector, "querySelector");
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
    }

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
// Public entry point.
// ---------------------------------------------------------------------------

JsDomResult JsRunOnDocument(Document* doc, const char* script, u32 len, Arena& domArena, char* console_out,
                            u32 console_cap)
{
    JsDomResult out{};
    if (console_out && console_cap)
        console_out[0] = '\0';
    if (!doc)
    {
        out.status = Err{ErrorCode::InvalidArgument};
        return out;
    }

    js::Arena jsArena(g_jsDomArena, sizeof(g_jsDomArena));

    js::TokenStream toks = js::Lex(script, len, jsArena);
    if (!toks.ok)
    {
        out.status = Err{ErrorCode::InvalidArgument};
        return out;
    }
    js::ParseResult pr = js::Parse(toks, jsArena);
    if (!pr.ok)
    {
        out.status = Err{ErrorCode::InvalidArgument};
        return out;
    }

    js::ConsoleBuf console{console_out, console_cap, 0};
    Interp I(jsArena, console);
    I.stepBudget = js::kDefaultStepBudget;
    I.maxDepth = js::kMaxCallDepth;
    I.depth = 0;
    I.flow = js::Flow::Normal;
    I.returnValue = JsValue::Undefined();
    I.global = js::EnvNew(jsArena, nullptr);
    if (!I.global)
    {
        out.status = Err{ErrorCode::OutOfMemory};
        return out;
    }
    if (Result<void> r = js::InstallBuiltins(I); !r)
    {
        out.status = Err{r.error()};
        return out;
    }

    // Install the live `document` binding. The DomCtx lives on the JS
    // arena so its wrapper cache outlives the eval body.
    DomCtx* ctx = jsArena.New<DomCtx>();
    if (!ctx)
    {
        out.status = Err{ErrorCode::OutOfMemory};
        return out;
    }
    ctx->doc = doc;
    ctx->js = &jsArena;
    ctx->dom = &domArena;
    JsValue documentVal = WrapNode(*ctx, doc);
    js::EnvDefine(I.global, jsArena, "document", 8, documentVal);

    Result<JsValue> r = js::EvalStmt(I, pr.program, I.global);

    if (console_out && console_cap)
        console_out[console.len < console_cap ? console.len : console_cap - 1] = '\0';
    out.consoleLen = console.len < console_cap ? console.len : (console_cap ? console_cap - 1 : 0);

    if (!r)
        out.status = Err{r.error()};
    return out;
}

} // namespace duetos::web
