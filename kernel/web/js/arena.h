#pragma once

#include "util/string.h"
#include "util/types.h"

/*
 * DuetOS — kernel/web/js: bump arena for the JS engine.
 *
 * The "scripts" engine allocates a lot of small short-lived nodes
 * (AST nodes, environments, property slots, string copies). The
 * kernel has no `malloc`/`new` available to portable subsystem code,
 * and the JS engine's lifetime is "one JsEval call". A bump arena is
 * the natural fit: every allocation comes off a single contiguous
 * buffer; the whole thing is reclaimed when the eval finishes.
 *
 * The arena does NOT own its backing memory — the caller hands it a
 * buffer (typically a static array in the self-test, or a kheap slab
 * from a real caller). When the buffer is exhausted, Alloc returns
 * nullptr and the engine surfaces ErrorCode::OutOfMemory rather than
 * faulting. This keeps the engine freestanding and bounded: a hostile
 * script cannot grow kernel memory without limit.
 *
 * Every node type allocated through the arena is trivially
 * constructible; Alloc zero-fills, which is the correct initial state
 * for all of them. No placement-new, no global operator new — we stay
 * inside the "no naked new" rule.
 *
 * Context: kernel, single-threaded per eval. No locking — one Arena
 * belongs to one JsEval invocation.
 */

namespace duetos::web::js
{

class Arena
{
  public:
    Arena(u8* buffer, u64 capacity) : m_base(buffer), m_cap(capacity), m_used(0) {}

    /// Allocate `bytes` zero-filled with the given alignment. Returns
    /// nullptr on exhaustion (the caller turns that into OutOfMemory).
    /// Alignment must be a power of two; the engine only needs 8/16.
    void* Alloc(u64 bytes, u64 align = 16)
    {
        const u64 mask = align - 1;
        const u64 aligned = (m_used + mask) & ~mask;
        if (aligned > m_cap || bytes > m_cap - aligned)
        {
            m_oom = true;
            return nullptr;
        }
        u8* p = m_base + aligned;
        m_used = aligned + bytes;
        memset(p, 0, bytes);
        return p;
    }

    /// Typed convenience: allocate one zero-filled T. All engine node
    /// types are trivially constructible, so a zeroed T is valid.
    template <typename T> T* New()
    {
        const u64 al = alignof(T) > 16 ? alignof(T) : 16;
        return static_cast<T*>(Alloc(sizeof(T), al));
    }

    /// Allocate a zero-filled array of `count` T.
    template <typename T> T* NewArray(u64 count)
    {
        if (count == 0)
            return nullptr;
        const u64 al = alignof(T) > 16 ? alignof(T) : 16;
        return static_cast<T*>(Alloc(sizeof(T) * count, al));
    }

    u64 Used() const { return m_used; }
    u64 Capacity() const { return m_cap; }
    bool OutOfMemory() const { return m_oom; }

  private:
    u8* m_base;
    u64 m_cap;
    u64 m_used;
    bool m_oom = false;
};

} // namespace duetos::web::js
