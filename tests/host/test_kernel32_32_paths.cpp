// test_kernel32_32_paths.cpp — hosted unit test for the freestanding
// path / seek-resolution core of the i386 (PE32) kernel32 companion.
//
// Covers:
//   userland/libs/kernel32_32/kernel32_32_paths.h
//     (Duet32NormalizePathA — the Win32 → kernel path narrowing used
//      by CreateFileA/W and GetFileAttributesA/W;
//      Duet32WideToAscii — the UTF-16 low-byte narrowing on the W
//      paths;
//      Duet32ResolveSeekTarget — the SetFilePointer move resolution)
//
// Why Duet32ResolveSeekTarget exists at all, and why it is worth
// pinning here: the 32-bit syscall ABI ZERO-extends its arguments
// (kernel/arch/x86_64/exceptions.S remaps ebx/ecx/edx into rdi/rsi/rdx
// verbatim, and the CPU zero-extended each 32-bit register write on
// the user side). A negative distance handed straight to
// SYS_FILE_SEEK would therefore reach the kernel as a huge positive
// u64 and land at EOF instead of before it. Every backwards move must
// be resolved to an absolute forward offset in the DLL, so the
// arithmetic below is load-bearing rather than incidental.
//
// The i386 return path exposes only signed eax for syscall errors.
// Targets above INT_MAX are therefore rejected instead of being
// mistaken for negative errno values.

#include "host_test_helper.h"

#include "../../userland/libs/kernel32_32/kernel32_32_paths.h"

using namespace duetos_host_test;

namespace
{

// Convenience: normalise into a static buffer so EXPECT_STREQ can
// read it back.
const char* norm(const char* in)
{
    static char out[64];
    Duet32NormalizePathA(in, out, static_cast<int>(sizeof(out)));
    return out;
}

// Sentinel returned by the helpers below when the move is rejected.
// No legal resolution produces it for the inputs used here.
constexpr unsigned long long kRejected = 0xFFFFFFFFULL;

// Convenience: resolve a move and return the offset handed to
// SYS_FILE_SEEK, or kRejected.
unsigned long long resolve(long long anchor, int distance, unsigned whence)
{
    unsigned long long out = 0;
    unsigned out_whence = 0;
    if (!Duet32ResolveSeekTarget(anchor, distance, whence, &out, &out_whence))
        return kRejected;
    return out;
}

// Same, but returns the whence the DLL will actually issue: a
// backwards move must be rewritten to FILE_BEGIN, a forward one must
// keep the caller's.
unsigned resolve_whence(long long anchor, int distance, unsigned whence)
{
    unsigned long long out = 0;
    unsigned out_whence = 0xFFFFu;
    if (!Duet32ResolveSeekTarget(anchor, distance, whence, &out, &out_whence))
        return 0xFFFFu;
    return out_whence;
}

} // namespace

int main()
{
    // ---------------------------------------------------------------
    // Duet32NormalizePathA — drive letter stripped, backslashes
    // flipped. DuetOS has one logical volume, so "C:\x" and "\x" must
    // land on the same kernel path.
    // ---------------------------------------------------------------
    EXPECT_STREQ(norm("C:\\Foo\\bar.txt"), "/Foo/bar.txt");
    EXPECT_STREQ(norm("c:\\Foo\\bar.txt"), "/Foo/bar.txt");
    EXPECT_STREQ(norm("\\Foo\\bar.txt"), "/Foo/bar.txt");
    EXPECT_STREQ(norm("/etc/version"), "/etc/version");
    // Mixed separators — a real Win32 caller emits both.
    EXPECT_STREQ(norm("C:\\Foo/bar"), "/Foo/bar");
    // A relative path keeps its shape; the kernel anchors it.
    EXPECT_STREQ(norm("data\\cfg.ini"), "data/cfg.ini");
    // Only a *drive* prefix is stripped — "ab:" is not one.
    EXPECT_STREQ(norm("ab:\\x"), "ab:/x");
    // Empty / null are rejected, not silently turned into "/".
    EXPECT_EQ(Duet32NormalizePathA("", nullptr, 0), 0);
    {
        char buf[8] = {'z'};
        EXPECT_EQ(Duet32NormalizePathA(nullptr, buf, sizeof(buf)), 0);
        EXPECT_EQ(Duet32NormalizePathA("", buf, sizeof(buf)), 0);
    }
    // Truncation must stay in bounds and stay NUL-terminated.
    {
        char small[5];
        const int n = Duet32NormalizePathA("C:\\abcdefgh", small, static_cast<int>(sizeof(small)));
        EXPECT_EQ(n, 4);
        EXPECT_STREQ(small, "/abc");
    }

    // ---------------------------------------------------------------
    // Duet32WideToAscii — low-byte narrowing, NUL-terminated,
    // bounded.
    // ---------------------------------------------------------------
    {
        const unsigned short wide[] = {'/', 'e', 't', 'c', '/', 'v', 0};
        char out[16];
        EXPECT_EQ(Duet32WideToAscii(wide, out, static_cast<int>(sizeof(out))), 6);
        EXPECT_STREQ(out, "/etc/v");

        char tiny[4];
        EXPECT_EQ(Duet32WideToAscii(wide, tiny, static_cast<int>(sizeof(tiny))), 3);
        EXPECT_STREQ(tiny, "/et");

        EXPECT_EQ(Duet32WideToAscii(nullptr, out, static_cast<int>(sizeof(out))), 0);
    }

    // ---------------------------------------------------------------
    // Duet32ResolveSeekTarget — every move becomes an absolute
    // FILE_BEGIN offset so success stays distinguishable from errno.
    // ---------------------------------------------------------------
    EXPECT_EQ(resolve(0, 0, DUET32_FILE_BEGIN), 0ULL);
    EXPECT_EQ(resolve(0, 64, DUET32_FILE_BEGIN), 64ULL);
    EXPECT_EQ(resolve(100, 8, DUET32_FILE_CURRENT), 108ULL);
    EXPECT_EQ(resolve(100, 8, DUET32_FILE_END), 108ULL);
    EXPECT_EQ(resolve_whence(100, 8, DUET32_FILE_CURRENT), DUET32_FILE_BEGIN);
    EXPECT_EQ(resolve_whence(100, 8, DUET32_FILE_END), DUET32_FILE_BEGIN);

    // Backwards from EOF: the case pe32_rich exercises on target.
    EXPECT_EQ(resolve(25, -4, DUET32_FILE_END), 21ULL);
    EXPECT_EQ(resolve(25, -25, DUET32_FILE_END), 0ULL);
    // Backwards from the current cursor.
    EXPECT_EQ(resolve(10, -3, DUET32_FILE_CURRENT), 7ULL);
    // Every backwards move must be re-issued as an absolute
    // FILE_BEGIN seek — a relative one would be zero-extended by the
    // syscall ABI and land at EOF.
    EXPECT_EQ(resolve_whence(25, -4, DUET32_FILE_END), DUET32_FILE_BEGIN);
    EXPECT_EQ(resolve_whence(10, -3, DUET32_FILE_CURRENT), DUET32_FILE_BEGIN);

    // Win32 rejects a resulting position before byte zero.
    EXPECT_EQ(resolve(4, -100, DUET32_FILE_END), kRejected);
    EXPECT_EQ(resolve(0, -1, DUET32_FILE_CURRENT), kRejected);

    // A negative distance from FILE_BEGIN is invalid per Win32, and
    // must be rejected rather than clamped to 0 — a caller that asks
    // to seek before the start has a bug, and silently landing at 0
    // would hide it.
    EXPECT_EQ(resolve(0, -1, DUET32_FILE_BEGIN), kRejected);
    EXPECT_EQ(resolve(500, -1, DUET32_FILE_BEGIN), kRejected);

    // An unknown whence is rejected in both directions rather than
    // forwarded to the kernel.
    EXPECT_EQ(resolve(0, 4, 7u), kRejected);
    EXPECT_EQ(resolve(0, -4, 7u), kRejected);

    // INT_MIN must not overflow the resolution arithmetic: it is
    // widened to long long before the add, so a huge backwards move
    // rejects instead of wrapping positive.
    EXPECT_EQ(resolve(1024, -2147483647 - 1, DUET32_FILE_END), kRejected);

    // The largest forward move a 32-bit distance can express stays
    // positive after the (unsigned) conversion.
    EXPECT_EQ(resolve(0, 2147483647, DUET32_FILE_BEGIN), 2147483647ULL);
    EXPECT_EQ(resolve(1, 2147483647, DUET32_FILE_CURRENT), kRejected);
    EXPECT_EQ(resolve(0xFFFFFFFFLL, -1, DUET32_FILE_END), kRejected);

    // Null out-pointers are rejected, not dereferenced.
    {
        unsigned long long off = 0;
        unsigned wh = 0;
        EXPECT_TRUE(Duet32ResolveSeekTarget(0, 0, DUET32_FILE_BEGIN, nullptr, &wh) == 0);
        EXPECT_TRUE(Duet32ResolveSeekTarget(0, 0, DUET32_FILE_BEGIN, &off, nullptr) == 0);
    }

    return finish_main("kernel32_32_paths");
}
