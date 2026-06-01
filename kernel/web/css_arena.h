#pragma once

/*
 * DuetOS — typed allocation over the DOM's web::Arena, for CSS.
 *
 * The DOM Arena (dom.h) only hands out Node / Attr / raw strings — it
 * has no generic "give me N aligned bytes" entry point, and we must NOT
 * edit dom.h to add one (the DOM is owned by another slice). The CSS
 * engine needs to carve SimpleSelector / Declaration / Rule / and the
 * StyleMap arrays out of the same arena.
 *
 * `ArenaNew<T>` does it by over-allocating `sizeof(T) + alignof(T)`
 * bytes via Arena::CopyString (which is the arena's public byte path),
 * then aligning the returned pointer up to alignof(T). The source bytes
 * are all zero, so the resulting object is value-initialised in place —
 * every CSS struct allocated this way is a trivial POD, so a
 * reinterpret_cast over a zeroed, aligned span IS a fully-constructed
 * object (no placement-new operator needed in freestanding kernel
 * code). The over-allocation slack is the price of not having a public
 * aligned-bump entry point; it is bounded (< alignof(T) per object) and
 * the arena is sized generously by callers. Returns nullptr on
 * exhaustion.
 *
 * ArenaArray<T>(n) does the same for a contiguous, value-initialised
 * array of n elements.
 */

#include "util/types.h"
#include "web/dom.h"

namespace duetos::web
{

using duetos::u32;
using duetos::uptr;

namespace detail
{

// A scratch source buffer of zero bytes for CopyString to copy from.
// CopyString copies `len` bytes from a readable source; since we want
// the destination value-initialised (zeroed), we hand it zeros. This
// static lives in BSS (zero runtime cost) and is sized to cover the
// largest single allocation the CSS engine makes: the StyleMap's
// parallel ComputedStyle / Node* arrays, which scale with the styled
// element count. 64 KiB matches the largest caller arena (the
// self-test's 96 KiB buffer can't hold a single array bigger than
// this), so in practice the bound is never the binding constraint —
// the arena exhausts first. Requests above this still degrade
// gracefully (nullptr → truncated style map) rather than faulting.
inline const unsigned char* ZeroSource(u32 needed)
{
    static const unsigned char k_zeros[64 * 1024] = {};
    return needed <= sizeof(k_zeros) ? k_zeros : nullptr;
}

inline void* AlignUp(void* p, u32 align)
{
    uptr v = reinterpret_cast<uptr>(p);
    uptr a = static_cast<uptr>(align);
    uptr aligned = (v + (a - 1)) & ~(a - 1);
    return reinterpret_cast<void*>(aligned);
}

} // namespace detail

/// Carve one zero-initialised T from `arena`. Returns nullptr on OOM.
template <typename T> T* ArenaNew(Arena& arena)
{
    constexpr u32 align = static_cast<u32>(alignof(T));
    constexpr u32 size = static_cast<u32>(sizeof(T));
    const u32 needed = size + align;
    const unsigned char* zeros = detail::ZeroSource(needed);
    if (zeros == nullptr)
    {
        return nullptr;
    }
    const char* raw = arena.CopyString(reinterpret_cast<const char*>(zeros), needed);
    if (raw == nullptr)
    {
        return nullptr;
    }
    void* aligned = detail::AlignUp(const_cast<char*>(raw), align);
    // Zeroed + aligned span; T is a trivial POD, so this IS a valid
    // value-initialised object without a placement-new operator.
    return static_cast<T*>(aligned);
}

/// Carve a zero-initialised array of `n` Ts. Returns nullptr on OOM or
/// if the total exceeds the zero-source scratch.
template <typename T> T* ArenaArray(Arena& arena, u32 n)
{
    if (n == 0)
    {
        return nullptr;
    }
    constexpr u32 align = static_cast<u32>(alignof(T));
    const u32 size = static_cast<u32>(sizeof(T)) * n;
    const u32 needed = size + align;
    const unsigned char* zeros = detail::ZeroSource(needed);
    if (zeros == nullptr)
    {
        return nullptr;
    }
    const char* raw = arena.CopyString(reinterpret_cast<const char*>(zeros), needed);
    if (raw == nullptr)
    {
        return nullptr;
    }
    void* aligned = detail::AlignUp(const_cast<char*>(raw), align);
    // Zeroed + aligned span of trivial PODs — valid array without
    // placement-new.
    return static_cast<T*>(aligned);
}

} // namespace duetos::web
