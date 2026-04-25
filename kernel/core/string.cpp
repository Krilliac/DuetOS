#include "types.h"

// Freestanding memset / memcpy / memmove. The Clang/GCC C++
// codegen emits implicit calls to these for `T = {}`, struct
// copies, and large literal initializers — even with
// `-fno-builtin`. A kernel without them fails to link the
// moment any subsystem zero-inits a ring-buffer entry.
//
// Implementations are deliberately minimal and byte-oriented:
// no SSE (kernel runs `-mno-sse`), no fancy alignment tricks.
// `memmove` handles overlap; `memcpy` aliases to it because the
// caller-correctness guarantee is weaker than the trivial gain
// from forbidding overlap.

extern "C" void* memset(void* dst, int c, duetos::usize n)
{
    auto* p = static_cast<duetos::u8*>(dst);
    const auto v = static_cast<duetos::u8>(c);
    for (duetos::usize i = 0; i < n; ++i)
        p[i] = v;
    return dst;
}

extern "C" void* memmove(void* dst, const void* src, duetos::usize n)
{
    auto* d = static_cast<duetos::u8*>(dst);
    const auto* s = static_cast<const duetos::u8*>(src);
    if (d == s || n == 0)
        return dst;
    if (d < s)
    {
        for (duetos::usize i = 0; i < n; ++i)
            d[i] = s[i];
    }
    else
    {
        for (duetos::usize i = n; i > 0; --i)
            d[i - 1] = s[i - 1];
    }
    return dst;
}

extern "C" void* memcpy(void* dst, const void* src, duetos::usize n)
{
    return memmove(dst, src, n);
}
