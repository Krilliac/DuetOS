#pragma once

/*
 * DuetOS — minimal HTML DOM node model + bounded arena.
 *
 * This is the parse substrate for a future CSS/layout/JS swarm. It
 * is deliberately small: a Node carries a kind, a tag name (for
 * elements), an attribute list, a text payload (for Text/Comment),
 * and intrusive parent/child/sibling links. There is no styling,
 * no layout box, no scripting hook here — just the tree shape.
 *
 * Memory discipline (kernel rules: no naked new/delete, no libc):
 * every Node, attribute, and the small string blobs they point at
 * are carved out of a caller-supplied `Arena`. The arena is a flat
 * bump allocator over a fixed buffer; when it is exhausted further
 * allocations return null and the tree builder stops growing rather
 * than faulting. Nothing here calls a global allocator.
 *
 * Strings stored in nodes are NUL-terminated copies living inside
 * the arena, so a Document outlives the source HTML buffer.
 */

#include "util/types.h"

namespace duetos::web
{

using duetos::u32;
using duetos::u8;

/// What a Node is. Document is the synthetic root; Element is a tag;
/// Text and Comment are leaf payloads.
enum class NodeKind : u8
{
    Document,
    Element,
    Text,
    Comment,
};

/// A single name="value" pair on an element. Both strings are
/// arena-owned, NUL-terminated. An empty/valueless attribute has a
/// zero-length value string (not null).
struct Attr
{
    const char* name = nullptr;
    const char* value = nullptr;
    Attr* next = nullptr;
};

/// A DOM node. Children form a singly-linked list via `firstChild`/
/// `nextSibling`; `lastChild` is kept so append is O(1). `parent`
/// is the owning node (null for the Document root).
struct Node
{
    NodeKind kind = NodeKind::Element;

    // Element: lowercased tag name. Text/Comment/Document: nullptr.
    const char* tag = nullptr;

    // Text/Comment: the payload (entity-decoded for Text, raw for
    // Comment). Element/Document: nullptr.
    const char* text = nullptr;

    Attr* attrs = nullptr;
    Attr* attrsTail = nullptr;

    Node* parent = nullptr;
    Node* firstChild = nullptr;
    Node* lastChild = nullptr;
    Node* nextSibling = nullptr;

    /// Look up an attribute by (lowercase) name. Returns the value
    /// string, or nullptr if absent.
    const char* GetAttr(const char* name) const;

    /// First direct child element with the given (lowercase) tag, or
    /// nullptr. Does not recurse.
    Node* FirstChildByTag(const char* tagName) const;
};

/// Fixed-capacity bump arena. Hands out Node/Attr objects and string
/// copies from a single contiguous buffer. Exhaustion is signalled
/// by a null return — callers must check.
class Arena
{
  public:
    Arena(u8* buffer, u32 capacity) : m_buf(buffer), m_cap(capacity), m_used(0), m_nodeCount(0) {}

    /// Carve a zeroed Node. Null when out of room or over the node cap.
    Node* AllocNode();

    /// Carve a zeroed Attr. Null when out of room.
    Attr* AllocAttr();

    /// Copy `len` bytes of `s` plus a NUL into the arena; returns the
    /// arena-owned pointer, or nullptr when out of room.
    const char* CopyString(const char* s, u32 len);

    u32 NodeCount() const { return m_nodeCount; }
    u32 BytesUsed() const { return m_used; }

    /// Restore the bump pointer to a previous BytesUsed() mark, reclaiming
    /// everything allocated since. Only ever shrinks (a stale/forward mark
    /// is ignored). Used to scope transient layout scratch (per-block line
    /// fragment + run arrays) so it does NOT accumulate in this
    /// non-reclaiming arena — without this, a moderately complex page
    /// exhausts the arena and the render truncates. The caller MUST NOT
    /// retain any pointer into the reclaimed region.
    void Rewind(u32 mark)
    {
        if (mark <= m_used)
        {
            m_used = mark;
        }
    }

    // Cap on total live nodes — a hostile/pathological document can
    // not blow past this even if the byte buffer is huge.
    static constexpr u32 kMaxNodes = 4096;

  private:
    void* Bump(u32 size, u32 align);

    u8* m_buf;
    u32 m_cap;
    u32 m_used;
    u32 m_nodeCount;
};

} // namespace duetos::web
