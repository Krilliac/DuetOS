/*
 * DuetOS — DOM arena allocator + Node query helpers. See dom.h.
 *
 * The arena is a flat bump allocator: alignment-rounded sub-blocks
 * are handed out of one fixed buffer, and exhaustion returns null
 * rather than faulting. No global allocator, no naked new.
 */

#include "web/dom.h"

#include "util/string.h"

namespace duetos::web
{

void* Arena::Bump(u32 size, u32 align)
{
    // Round the current offset up to the requested alignment.
    u32 aligned = (m_used + (align - 1)) & ~(align - 1);
    if (aligned < m_used)
    {
        return nullptr; // alignment overflow
    }
    if (aligned > m_cap || size > m_cap - aligned)
    {
        return nullptr; // out of room
    }
    void* p = m_buf + aligned;
    m_used = aligned + size;
    return p;
}

Node* Arena::AllocNode()
{
    if (m_nodeCount >= kMaxNodes)
    {
        return nullptr;
    }
    void* mem = Bump(static_cast<u32>(sizeof(Node)), static_cast<u32>(alignof(Node)));
    if (mem == nullptr)
    {
        return nullptr;
    }
    Node* n = static_cast<Node*>(mem);
    *n = Node{}; // value-init: kind=Element, all pointers null
    ++m_nodeCount;
    return n;
}

Attr* Arena::AllocAttr()
{
    void* mem = Bump(static_cast<u32>(sizeof(Attr)), static_cast<u32>(alignof(Attr)));
    if (mem == nullptr)
    {
        return nullptr;
    }
    Attr* a = static_cast<Attr*>(mem);
    *a = Attr{};
    return a;
}

const char* Arena::CopyString(const char* s, u32 len)
{
    void* mem = Bump(len + 1, 1);
    if (mem == nullptr)
    {
        return nullptr;
    }
    char* dst = static_cast<char*>(mem);
    if (len != 0)
    {
        duetos::core::MemcpyChecked(dst, s, len);
    }
    dst[len] = '\0';
    return dst;
}

const char* Node::GetAttr(const char* name) const
{
    for (const Attr* a = attrs; a != nullptr; a = a->next)
    {
        if (a->name != nullptr && duetos::core::StrEqual(a->name, name))
        {
            return a->value;
        }
    }
    return nullptr;
}

Node* Node::FirstChildByTag(const char* tagName) const
{
    for (Node* c = firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element && c->tag != nullptr && duetos::core::StrEqual(c->tag, tagName))
        {
            return c;
        }
    }
    return nullptr;
}

} // namespace duetos::web
