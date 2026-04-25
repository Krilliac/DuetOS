#include "types.h"

#include "../arch/x86_64/serial.h"
#include "klog.h"
#include "panic.h"

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

namespace duetos::core
{

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
    {
        return;
    }
    arch::SerialWrite("[string-selftest] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    Panic("core/string", "StringSelfTest assertion failed");
}

bool BytesEq(const u8* a, const u8* b, usize n)
{
    for (usize i = 0; i < n; ++i)
    {
        if (a[i] != b[i])
        {
            return false;
        }
    }
    return true;
}

bool BytesAll(const u8* a, u8 v, usize n)
{
    for (usize i = 0; i < n; ++i)
    {
        if (a[i] != v)
        {
            return false;
        }
    }
    return true;
}

} // namespace

void StringSelfTest()
{
    KLOG_TRACE_SCOPE("core/string", "StringSelfTest");

    // ----- memset -----
    {
        u8 buf[64];
        for (u32 i = 0; i < 64; ++i)
        {
            buf[i] = 0x11;
        }
        // n=0 leaves the buffer untouched.
        memset(buf, 0xFF, 0);
        Expect(buf[0] == 0x11, "memset(.,.,0) is a no-op");

        // Sentinel bytes around a partial fill must survive.
        memset(buf + 8, 0xAA, 16);
        Expect(buf[7] == 0x11, "memset preserves byte before range");
        Expect(buf[8 + 16] == 0x11, "memset preserves byte after range");
        Expect(BytesAll(buf + 8, 0xAA, 16), "memset wrote pattern across [8..24)");

        // Wide fill overwrites everything.
        memset(buf, 0x55, 64);
        Expect(BytesAll(buf, 0x55, 64), "memset wrote pattern across full buffer");

        // memset takes `int` for the value but only the low byte
        // is used. 0xCAFEBABE truncates to 0xBE.
        memset(buf, 0xCAFEBABE, 16);
        Expect(BytesAll(buf, 0xBE, 16), "memset masks value to low byte");
    }

    // ----- memcpy (no overlap) -----
    {
        u8 src[32];
        u8 dst[32];
        for (u32 i = 0; i < 32; ++i)
        {
            src[i] = static_cast<u8>(i + 1);
            dst[i] = 0;
        }
        // n=0 leaves the buffer untouched.
        memcpy(dst, src, 0);
        Expect(dst[0] == 0, "memcpy(.,.,0) is a no-op");

        memcpy(dst, src, 32);
        Expect(BytesEq(dst, src, 32), "memcpy 32 bytes copied verbatim");

        // Partial copy preserves trailing bytes.
        memset(dst, 0x77, 32);
        memcpy(dst, src, 8);
        Expect(BytesEq(dst, src, 8), "memcpy 8 bytes copied");
        Expect(BytesAll(dst + 8, 0x77, 24), "memcpy preserves bytes past n");
    }

    // ----- memmove forward overlap (dst < src) -----
    {
        u8 buf[16];
        for (u32 i = 0; i < 16; ++i)
        {
            buf[i] = static_cast<u8>(i);
        }
        // Shift left by 4: buf[0..12) = old buf[4..16).
        memmove(buf, buf + 4, 12);
        for (u32 i = 0; i < 12; ++i)
        {
            Expect(buf[i] == static_cast<u8>(i + 4), "memmove forward copy correct");
        }
    }

    // ----- memmove backward overlap (dst > src) -----
    {
        u8 buf[16];
        for (u32 i = 0; i < 16; ++i)
        {
            buf[i] = static_cast<u8>(i);
        }
        // Shift right by 4: buf[4..16) = old buf[0..12).
        memmove(buf + 4, buf, 12);
        // Earlier bytes are unmodified.
        Expect(buf[0] == 0 && buf[1] == 1 && buf[2] == 2 && buf[3] == 3, "memmove preserved low bytes");
        for (u32 i = 0; i < 12; ++i)
        {
            Expect(buf[4 + i] == static_cast<u8>(i), "memmove backward copy correct");
        }
    }

    // ----- memmove identity (dst == src) -----
    {
        u8 buf[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
        memmove(buf, buf, 8);
        const u8 expected[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
        Expect(BytesEq(buf, expected, 8), "memmove dst==src is identity");
    }

    arch::SerialWrite("[string-selftest] PASS (memset / memcpy / memmove + overlap directions)\n");
}

} // namespace duetos::core
