#include "util/types.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"

// memset / memcpy / memmove live in string_erms.S — ERMS-based
// `rep movsb` / `rep stosb` paths that the Clang/GCC codegen
// implicitly calls for struct copies, zero-init and large
// literal initializers. The asm forms supersede the prior
// scalar-unrolled C bodies (which only existed because earlier
// kernels assumed pre-ERMS hardware was in scope; today every
// commodity x86_64 CPU has it).
//
// Forward decls so the self-test below can call them; the asm
// definitions are the link-time providers.
extern "C" void* memset(void* dst, int c, duetos::usize n);
extern "C" void* memcpy(void* dst, const void* src, duetos::usize n);
extern "C" void* memmove(void* dst, const void* src, duetos::usize n);

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
        // is used. 0xCAFEBABE truncates to 0xBE. The cast is
        // explicit so -fsanitize=implicit-conversion doesn't flag
        // the (deliberate) unsigned→int narrowing this test exists
        // to exercise.
        memset(buf, static_cast<int>(0xCAFEBABEu), 16);
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
