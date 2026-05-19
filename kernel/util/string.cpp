#include "util/types.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"

// Freestanding memset / memcpy / memmove. The Clang/GCC C++
// codegen emits implicit calls to these for `T = {}`, struct
// copies, and large literal initializers — even with
// `-fno-builtin`. A kernel without them fails to link the
// moment any subsystem zero-inits a ring-buffer entry.
//
// The kernel runs `-mno-sse -mgeneral-regs-only`, so no SIMD —
// but 64-bit integer regs (rax/rcx/...) are general-regs and
// safe. These routines copy/fill in 64-byte unrolled chunks of
// 8-byte stores, with a byte tail; for n < 8 they fall through
// to a byte loop directly.
//
// `memcpy` forwards to `memmove` because the strict-no-overlap
// guarantee isn't worth a duplicate body when the unrolled
// forward path is already the common case.

extern "C" void* memset(void* dst, int c, duetos::usize n)
{
    auto* p = static_cast<duetos::u8*>(dst);
    const auto v = static_cast<duetos::u8>(c);
    if (n < 8)
    {
        for (duetos::usize i = 0; i < n; ++i)
            p[i] = v;
        return dst;
    }
    // Build a 64-bit pattern from the byte value.
    duetos::u64 pat = v;
    pat |= pat << 8;
    pat |= pat << 16;
    pat |= pat << 32;
    // Align destination to 8 bytes for the chunked store.
    while ((reinterpret_cast<duetos::usize>(p) & 7u) != 0)
    {
        *p++ = v;
        --n;
    }
    // 64-byte chunks (8x 8-byte stores).
    while (n >= 64)
    {
        auto* q = reinterpret_cast<duetos::u64*>(p);
        q[0] = pat;
        q[1] = pat;
        q[2] = pat;
        q[3] = pat;
        q[4] = pat;
        q[5] = pat;
        q[6] = pat;
        q[7] = pat;
        p += 64;
        n -= 64;
    }
    // 8-byte tail.
    while (n >= 8)
    {
        *reinterpret_cast<duetos::u64*>(p) = pat;
        p += 8;
        n -= 8;
    }
    // Sub-8 byte tail.
    while (n != 0)
    {
        *p++ = v;
        --n;
    }
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
        // Forward copy. The wide path below copies in fixed 64/8-
        // byte units via __builtin_memcpy — valid only if those
        // units don't self-overlap. When the buffers actually
        // overlap (d < s and d + n > s, i.e. gap < n), a 64-byte
        // memcpy whose src/dst overlap by 62 bytes is UB: the
        // compiler may copy the chunk in any order and shred the
        // tail (ASan flags it memcpy-param-overlap). An ascending
        // byte copy is the correct order for a dst-below-src move,
        // so take it whenever the ranges are not disjoint.
        if (n < 8 || static_cast<duetos::usize>(s - d) < n)
        {
            for (duetos::usize i = 0; i < n; ++i)
                d[i] = s[i];
            return dst;
        }
        // 64-byte unrolled chunks of 8-byte loads/stores. We
        // don't require alignment — x86 tolerates unaligned
        // 8-byte access at a small (cache-line-cross) cost
        // that's still cheaper than per-byte work. The wide
        // unit goes through __builtin_memcpy rather than a
        // reinterpret_cast<u64*> deref: casting an arbitrarily-
        // aligned u8* to u64* and dereferencing it is C++ UB
        // (alignment), which -fsanitize=undefined flags on every
        // call and drowns the real UBSan signal. clang lowers a
        // fixed-size __builtin_memcpy to the same single unaligned
        // movq under -mno-sse, so this is UB-free at zero cost.
        while (n >= 64)
        {
            __builtin_memcpy(d, s, 64);
            d += 64;
            s += 64;
            n -= 64;
        }
        while (n >= 8)
        {
            __builtin_memcpy(d, s, 8);
            d += 8;
            s += 8;
            n -= 8;
        }
        while (n != 0)
        {
            *d++ = *s++;
            --n;
        }
    }
    else
    {
        // Backward copy for overlap where dst is above src.
        // Keep this branch byte-oriented — overlapping moves
        // are rare in the kernel and bulk throughput here
        // doesn't merit the complexity of a reverse 8-byte
        // unroll.
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
        // n=0 leaves the buffer untouched. Use a `volatile` zero
        // so clang doesn't fire -Wmemset-transposed-args (which
        // would otherwise hand-wave us toward "did you mean
        // memset(buf, 0, 0xFF)?").
        volatile usize kZeroSize = 0;
        memset(buf, 0xFF, kZeroSize);
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

[[noreturn]] void BoundsCheckedFailed(const char* op, duetos::usize requested, duetos::usize bound)
{
    // Use PanicWithValue so the requested size shows up in the
    // crash dump's value field. The bound is logged separately
    // beforehand so an operator can see both numbers in the
    // serial log even if the panic dump truncates.
    KLOG_ERROR_2V("core/string", "bounds-checked op overflow", "requested", requested, "bound", bound);
    arch::SerialWrite("[bounds-check] FAIL: ");
    arch::SerialWrite(op);
    arch::SerialWrite(" requested>bound\n");
    PanicWithValue("core/string", "bounds-checked op exceeded destination size", requested);
}

} // namespace duetos::core
