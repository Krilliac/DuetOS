/*
 * DuetOS — HTML tokenizer + pragmatic tree builder. See html.h for
 * the REAL/GAP scope contract.
 *
 * Design: a single forward pass over the byte buffer drives a small
 * tokenizer (text / start-tag / end-tag / comment / doctype) feeding
 * a tree builder that keeps a flat open-element stack. Recovery is a
 * handful of rules — void elements never get children, <li> closes
 * <li>, block starts close <p>, stray end-tags are dropped, EOF
 * closes everything — not the HTML5 insertion-mode machine (GAP).
 *
 * Every node/attr/string is arena-owned; nothing here allocates from
 * a global heap. Hostile input is bounded by the arena node cap and
 * by length checks on every read.
 */

#include "web/html.h"

#include "web/entities.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "util/string.h"

namespace duetos::web
{

namespace
{

bool IsSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

char Lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool NameStart(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// Copy a tag/attr name lowercased into the arena.
const char* CopyLower(Arena& arena, const char* s, u32 len)
{
    if (len == 0)
    {
        return arena.CopyString("", 0);
    }
    // Bump a buffer, fill lowercased. We reuse CopyString then lower
    // in place — CopyString returns a mutable arena region cast away.
    const char* copied = arena.CopyString(s, len);
    if (copied == nullptr)
    {
        return nullptr;
    }
    char* mut = const_cast<char*>(copied);
    for (u32 i = 0; i < len; ++i)
    {
        mut[i] = Lower(mut[i]);
    }
    return copied;
}

// ---- element classification ----

bool TagEq(const char* tag, const char* lit)
{
    return tag != nullptr && duetos::core::StrEqual(tag, lit);
}

bool IsVoidElement(const char* tag)
{
    static const char* kVoid[] = {"area",  "base", "br",   "col",   "embed",  "hr",    "img",
                                  "input", "link", "meta", "param", "source", "track", "wbr"};
    for (const char* v : kVoid)
    {
        if (TagEq(tag, v))
        {
            return true;
        }
    }
    return false;
}

// Raw-text elements: their content is captured verbatim, the only
// terminator is the matching close tag.
bool IsRawTextElement(const char* tag)
{
    return TagEq(tag, "script") || TagEq(tag, "style") || TagEq(tag, "title") || TagEq(tag, "textarea");
}

// Block-level starts that implicitly close an open <p>.
bool ClosesOpenParagraph(const char* tag)
{
    static const char* kBlock[] = {"address", "article", "aside",   "blockquote", "div",  "dl",  "fieldset",
                                   "figure",  "footer",  "form",    "h1",         "h2",   "h3",  "h4",
                                   "h5",      "h6",      "header",  "hr",         "main", "nav", "ol",
                                   "p",       "pre",     "section", "table",      "ul"};
    for (const char* b : kBlock)
    {
        if (TagEq(tag, b))
        {
            return true;
        }
    }
    return false;
}

// ---- tree builder state ----

struct Builder
{
    Arena& arena;
    Node* document;
    // Open-element stack; entry 0 is always the Document.
    static constexpr u32 kMaxDepth = 256;
    Node* stack[kMaxDepth];
    u32 depth;

    explicit Builder(Arena& a) : arena(a), document(nullptr), depth(0) {}

    Node* Current() { return stack[depth - 1]; }

    void Push(Node* n)
    {
        if (depth < kMaxDepth)
        {
            stack[depth++] = n;
        }
    }

    // Append node as a child of the current open element.
    void Append(Node* n)
    {
        Node* parent = Current();
        n->parent = parent;
        if (parent->lastChild == nullptr)
        {
            parent->firstChild = n;
            parent->lastChild = n;
        }
        else
        {
            parent->lastChild->nextSibling = n;
            parent->lastChild = n;
        }
    }

    // Pop the open-element stack until (and including) the element
    // whose tag matches `tag`. If no such element is open, do nothing
    // (stray end-tag recovery). Never pops the Document.
    void PopUntilTag(const char* tag)
    {
        u32 found = 0;
        for (u32 i = depth; i > 1; --i)
        {
            if (TagEq(stack[i - 1]->tag, tag))
            {
                found = i;
                break;
            }
        }
        if (found != 0)
        {
            depth = found - 1;
        }
    }

    // Pop a single open element by tag if it is the current top.
    void PopIfCurrent(const char* tag)
    {
        if (depth > 1 && TagEq(Current()->tag, tag))
        {
            --depth;
        }
    }
};

// Emit accumulated text [start,end) as a Text child, decoding
// entities. Empty / all-whitespace-only runs are still emitted when
// they contain a non-space char; pure inter-tag whitespace is kept
// too (callers can collapse later).
void EmitText(Builder& b, const char* start, const char* end)
{
    if (start >= end)
    {
        return;
    }
    u32 srcLen = static_cast<u32>(end - start);

    // Every entity reference is at least as many source bytes as its
    // UTF-8 expansion (the shortest reference, "&lt", is 3 bytes for
    // 1 output byte; the longest expansion in our table is 3 bytes
    // for a >= 6-byte "&hellip;" reference). So a buffer the size of
    // the source always holds the decoded result. Copy the source in
    // (also handles the no-entity fast path) then rewrite in place.
    char* buf = const_cast<char*>(b.arena.CopyString(start, srcLen));
    if (buf == nullptr)
    {
        return;
    }

    u32 w = 0;
    u32 i = 0;
    while (i < srcLen)
    {
        char c = start[i];
        if (c == '&')
        {
            char ent[4];
            u32 consumed = 0;
            u32 wrote = DecodeEntity(start + i, srcLen - i, ent, sizeof(ent), &consumed);
            if (wrote != 0 && consumed != 0)
            {
                for (u32 k = 0; k < wrote && w < srcLen; ++k)
                {
                    buf[w++] = ent[k];
                }
                i += consumed;
                continue;
            }
        }
        if (w < srcLen)
        {
            buf[w++] = c;
        }
        ++i;
    }
    buf[w] = '\0';

    Node* t = b.arena.AllocNode();
    if (t == nullptr)
    {
        return;
    }
    t->kind = NodeKind::Text;
    t->text = buf;
    b.Append(t);
}

// Parse attributes from inside a start tag. `p` points just past the
// tag name; scans until '>' or '/>' or EOF, appending Attr nodes to
// `el`. Returns the offset of the byte that ended the tag (the '>'
// or the '/' of '/>'), and sets `*selfClose` if a '/' preceded '>'.
u32 ParseAttributes(Builder& b, Node* el, const char* p, u32 len, bool* selfClose)
{
    *selfClose = false;
    u32 i = 0;
    while (i < len)
    {
        while (i < len && IsSpace(p[i]))
        {
            ++i;
        }
        if (i >= len)
        {
            break;
        }
        if (p[i] == '>')
        {
            return i;
        }
        if (p[i] == '/')
        {
            *selfClose = true;
            ++i;
            // Skip to '>'.
            while (i < len && p[i] != '>')
            {
                ++i;
            }
            return i;
        }

        // Attribute name: up to '=', whitespace, '/', or '>'.
        u32 nameStart = i;
        while (i < len && !IsSpace(p[i]) && p[i] != '=' && p[i] != '>' && p[i] != '/')
        {
            ++i;
        }
        u32 nameLen = i - nameStart;
        if (nameLen == 0)
        {
            ++i; // stray char, skip
            continue;
        }

        const char* value = nullptr;
        // Skip spaces before a possible '='.
        u32 j = i;
        while (j < len && IsSpace(p[j]))
        {
            ++j;
        }
        if (j < len && p[j] == '=')
        {
            ++j;
            while (j < len && IsSpace(p[j]))
            {
                ++j;
            }
            // Quoted or unquoted value.
            if (j < len && (p[j] == '"' || p[j] == '\''))
            {
                char quote = p[j];
                ++j;
                u32 valStart = j;
                while (j < len && p[j] != quote)
                {
                    ++j;
                }
                value = b.arena.CopyString(p + valStart, j - valStart);
                if (j < len)
                {
                    ++j; // consume closing quote
                }
            }
            else
            {
                u32 valStart = j;
                while (j < len && !IsSpace(p[j]) && p[j] != '>')
                {
                    ++j;
                }
                value = b.arena.CopyString(p + valStart, j - valStart);
            }
            i = j;
        }

        Attr* a = b.arena.AllocAttr();
        if (a == nullptr)
        {
            // Out of arena — stop parsing attributes but keep the
            // element we have so far.
            return i;
        }
        a->name = CopyLower(b.arena, p + nameStart, nameLen);
        a->value = (value != nullptr) ? value : b.arena.CopyString("", 0);
        if (el->attrsTail == nullptr)
        {
            el->attrs = a;
            el->attrsTail = a;
        }
        else
        {
            el->attrsTail->next = a;
            el->attrsTail = a;
        }
    }
    return i;
}

// Find the close tag for a raw-text element starting at p[0..len),
// i.e. the next "</tag" (case-insensitive). Returns the offset of the
// '<', or `len` if not found.
u32 FindRawClose(const char* p, u32 len, const char* tag)
{
    u32 tagLen = static_cast<u32>(duetos::core::StrLen(tag));
    for (u32 i = 0; i + 1 < len; ++i)
    {
        if (p[i] != '<' || p[i + 1] != '/')
        {
            continue;
        }
        u32 k = i + 2;
        u32 m = 0;
        while (m < tagLen && k < len && Lower(p[k]) == tag[m])
        {
            ++k;
            ++m;
        }
        if (m == tagLen)
        {
            return i;
        }
    }
    return len;
}

} // namespace

Node* ParseHtml(const char* html, u32 len, Arena& arena)
{
    Builder b(arena);
    Node* doc = arena.AllocNode();
    if (doc == nullptr)
    {
        return nullptr;
    }
    doc->kind = NodeKind::Document;
    b.document = doc;
    b.Push(doc);

    u32 i = 0;
    u32 textStart = 0;
    while (i < len)
    {
        if (html[i] != '<')
        {
            ++i;
            continue;
        }

        // Flush pending text before handling the markup.
        EmitText(b, html + textStart, html + i);

        // Comment / doctype / markup declaration.
        if (i + 3 < len && html[i + 1] == '!' && html[i + 2] == '-' && html[i + 3] == '-')
        {
            // <!-- ... -->
            u32 j = i + 4;
            while (j + 2 < len && !(html[j] == '-' && html[j + 1] == '-' && html[j + 2] == '>'))
            {
                ++j;
            }
            u32 contentEnd = j;
            Node* c = arena.AllocNode();
            if (c != nullptr)
            {
                c->kind = NodeKind::Comment;
                c->text = arena.CopyString(html + i + 4, contentEnd - (i + 4));
                b.Append(c);
            }
            i = (j + 2 < len) ? j + 3 : len;
            textStart = i;
            continue;
        }
        if (i + 1 < len && html[i + 1] == '!')
        {
            // Doctype or other declaration — skip to '>'.
            u32 j = i + 2;
            while (j < len && html[j] != '>')
            {
                ++j;
            }
            i = (j < len) ? j + 1 : len;
            textStart = i;
            continue;
        }

        bool isEnd = (i + 1 < len && html[i + 1] == '/');
        u32 nameStart = isEnd ? i + 2 : i + 1;
        if (nameStart >= len || !NameStart(html[nameStart]))
        {
            // A stray '<' that is not a tag — treat literally.
            textStart = i;
            ++i;
            continue;
        }

        u32 ne = nameStart;
        while (ne < len && (NameStart(html[ne]) || (html[ne] >= '0' && html[ne] <= '9')))
        {
            ++ne;
        }
        const char* tag = CopyLower(arena, html + nameStart, ne - nameStart);

        if (isEnd)
        {
            // Skip to '>'.
            u32 j = ne;
            while (j < len && html[j] != '>')
            {
                ++j;
            }
            b.PopUntilTag(tag);
            i = (j < len) ? j + 1 : len;
            textStart = i;
            continue;
        }

        // Start tag. Recovery rules before opening.
        if (TagEq(tag, "li"))
        {
            b.PopIfCurrent("li");
        }
        if (ClosesOpenParagraph(tag))
        {
            b.PopIfCurrent("p");
        }

        Node* el = arena.AllocNode();
        if (el == nullptr)
        {
            // Arena exhausted — stop building, return what we have.
            break;
        }
        el->kind = NodeKind::Element;
        el->tag = tag;

        bool selfClose = false;
        u32 tagEndOff = ParseAttributes(b, el, html + ne, len - ne, &selfClose);
        u32 afterTag = ne + tagEndOff;
        // Advance to just past '>'.
        while (afterTag < len && html[afterTag] != '>')
        {
            ++afterTag;
        }
        if (afterTag < len)
        {
            ++afterTag; // consume '>'
        }

        b.Append(el);

        bool isVoid = IsVoidElement(tag);
        if (isVoid || selfClose)
        {
            // Void/self-closing: no children, do not push.
            i = afterTag;
            textStart = i;
            continue;
        }

        if (IsRawTextElement(tag))
        {
            // Capture raw content verbatim up to the matching close.
            u32 rawOff = FindRawClose(html + afterTag, len - afterTag, tag);
            if (rawOff > 0)
            {
                Node* raw = arena.AllocNode();
                if (raw != nullptr)
                {
                    raw->kind = NodeKind::Text;
                    raw->text = arena.CopyString(html + afterTag, rawOff);
                    raw->parent = el;
                    el->firstChild = raw;
                    el->lastChild = raw;
                }
            }
            // Advance past the close tag "</tag ... >".
            u32 closeAbs = afterTag + rawOff;
            u32 j = closeAbs;
            while (j < len && html[j] != '>')
            {
                ++j;
            }
            i = (j < len) ? j + 1 : len;
            textStart = i;
            continue;
        }

        b.Push(el);
        i = afterTag;
        textStart = i;
    }

    // Flush trailing text; unclosed elements are closed implicitly by
    // the stack simply not being popped (EOF recovery).
    EmitText(b, html + textStart, html + len);
    return doc;
}

u32 CollectText(const Node* node, char* out, u32 outCap)
{
    if (node == nullptr || out == nullptr || outCap == 0)
    {
        return 0;
    }
    out[0] = '\0';
    u32 pos = 0;

    // Pre-order DFS over a small explicit "next-to-visit" stack. The
    // depth bound matches the builder's open-element cap, so a single
    // 256-entry stack on the kernel stack is enough and avoids any
    // recursion. Each frame is a node whose subtree we still owe.
    constexpr u32 kStackCap = 128;
    const Node* todo[kStackCap];
    u32 sp = 0;
    todo[sp++] = node;

    while (sp > 0 && pos + 1 < outCap)
    {
        const Node* n = todo[--sp];
        if (n->kind == NodeKind::Text && n->text != nullptr)
        {
            for (const char* s = n->text; *s != '\0' && pos + 1 < outCap; ++s)
            {
                out[pos++] = *s;
            }
        }
        // Push children in reverse so the first child is popped first
        // (pre-order, left-to-right). Drop overflow — bounded output.
        const Node* rev[kStackCap];
        u32 rc = 0;
        for (const Node* c = n->firstChild; c != nullptr && rc < kStackCap; c = c->nextSibling)
        {
            rev[rc++] = c;
        }
        for (u32 k = rc; k > 0 && sp < kStackCap; --k)
        {
            todo[sp++] = rev[k - 1];
        }
    }
    out[pos] = '\0';
    return pos;
}

} // namespace duetos::web
