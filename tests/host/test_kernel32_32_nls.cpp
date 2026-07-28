// test_kernel32_32_nls.cpp — hosted unit test for the code-page /
// collation core of the i386 (PE32) kernel32 companion.
//
// Covers:
//   userland/libs/kernel32_32/kernel32_32_nls.h
//     (Duet32MultiByteToWideChar, Duet32WideCharToMultiByte,
//      Duet32CompareStringW)
//
// These three are imported by a large share of the 32-bit binaries
// under SysWOW64 and their failure modes are all silent: a wrong
// length return makes the caller allocate a short buffer and then
// overrun it, and a wrong CSTR_* code makes a sorted insert land in
// the wrong place. The count conventions are the fiddly part and are
// what most of the cases below pin:
//
//   * a NEGATIVE input count means "walk to the NUL and INCLUDE it",
//     so the returned length is strlen + 1 — not strlen;
//   * a ZERO destination capacity (or a NULL destination) is a
//     size query and must not write;
//   * a non-negative input count is verbatim and may contain
//     embedded NULs.

#include "host_test_helper.h"

#include "../../userland/libs/kernel32_32/kernel32_32_nls.h"

using namespace duetos_host_test;

namespace
{

// Build a UTF-16 literal from an ASCII one for the wide-side calls.
struct W
{
    unsigned short buf[32];
    explicit W(const char* s)
    {
        int i = 0;
        for (; s[i] != 0 && i < 31; ++i)
            buf[i] = static_cast<unsigned short>(static_cast<unsigned char>(s[i]));
        buf[i] = 0;
    }
    const unsigned short* p() const { return buf; }
};

} // namespace

int main()
{
    // ---- MultiByteToWideChar --------------------------------------
    {
        unsigned short out[8] = {};
        // -1: NUL-terminated input, terminator included in the count.
        EXPECT_EQ(Duet32MultiByteToWideChar("abc", -1, out, 8), 4);
        EXPECT_EQ(out[0], static_cast<unsigned short>('a'));
        EXPECT_EQ(out[2], static_cast<unsigned short>('c'));
        EXPECT_EQ(out[3], static_cast<unsigned short>(0));

        // Size query: zero capacity must return the need and write
        // nothing. Pre-poison the buffer to prove it stays untouched.
        unsigned short poison[4] = {0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA};
        EXPECT_EQ(Duet32MultiByteToWideChar("abc", -1, poison, 0), 4);
        EXPECT_EQ(poison[0], static_cast<unsigned short>(0xAAAA));
        // A NULL destination is the same query.
        EXPECT_EQ(Duet32MultiByteToWideChar("abc", -1, nullptr, 8), 4);

        // Explicit count is verbatim — no terminator added.
        EXPECT_EQ(Duet32MultiByteToWideChar("abc", 3, out, 8), 3);

        // Truncation: the copy is capped at the destination capacity
        // and the return reports what was actually written.
        EXPECT_EQ(Duet32MultiByteToWideChar("abcdef", -1, out, 2), 2);

        // High-bit bytes zero-extend rather than sign-extend — a
        // char is signed on x86, so this is a real trap.
        const char latin[] = {static_cast<char>(0xE9), 0};
        EXPECT_EQ(Duet32MultiByteToWideChar(latin, 1, out, 8), 1);
        EXPECT_EQ(out[0], static_cast<unsigned short>(0x00E9));

        EXPECT_EQ(Duet32MultiByteToWideChar(nullptr, -1, out, 8), 0);
    }

    // ---- WideCharToMultiByte --------------------------------------
    {
        const W src("hi");
        char out[8] = {};
        EXPECT_EQ(Duet32WideCharToMultiByte(src.p(), -1, out, 8), 3);
        EXPECT_STREQ(out, "hi");

        EXPECT_EQ(Duet32WideCharToMultiByte(src.p(), -1, nullptr, 0), 3);
        EXPECT_EQ(Duet32WideCharToMultiByte(src.p(), 2, out, 8), 2);
        EXPECT_EQ(Duet32WideCharToMultiByte(src.p(), -1, out, 1), 1);
        EXPECT_EQ(Duet32WideCharToMultiByte(nullptr, -1, out, 8), 0);

        // Round trip: narrow -> wide -> narrow reproduces the input.
        unsigned short mid[8] = {};
        EXPECT_EQ(Duet32MultiByteToWideChar("round", -1, mid, 8), 6);
        char back[8] = {};
        EXPECT_EQ(Duet32WideCharToMultiByte(mid, -1, back, 8), 6);
        EXPECT_STREQ(back, "round");
    }

    // ---- CompareStringW -------------------------------------------
    {
        const W abc("abc");
        const W abd("abd");
        const W ABC("ABC");
        const W abcd("abcd");

        EXPECT_EQ(Duet32CompareStringW(0, abc.p(), -1, abc.p(), -1), DUET32_CSTR_EQUAL);
        EXPECT_EQ(Duet32CompareStringW(0, abc.p(), -1, abd.p(), -1), DUET32_CSTR_LESS_THAN);
        EXPECT_EQ(Duet32CompareStringW(0, abd.p(), -1, abc.p(), -1), DUET32_CSTR_GREATER_THAN);

        // Prefix ordering: the shorter string sorts first.
        EXPECT_EQ(Duet32CompareStringW(0, abc.p(), -1, abcd.p(), -1), DUET32_CSTR_LESS_THAN);
        EXPECT_EQ(Duet32CompareStringW(0, abcd.p(), -1, abc.p(), -1), DUET32_CSTR_GREATER_THAN);

        // Case: ordinal by default ('A' < 'a'), equal when folded.
        EXPECT_EQ(Duet32CompareStringW(0, ABC.p(), -1, abc.p(), -1), DUET32_CSTR_LESS_THAN);
        EXPECT_EQ(Duet32CompareStringW(DUET32_NORM_IGNORECASE, ABC.p(), -1, abc.p(), -1), DUET32_CSTR_EQUAL);

        // Explicit counts bound the comparison to a prefix.
        EXPECT_EQ(Duet32CompareStringW(0, abc.p(), 2, abd.p(), 2), DUET32_CSTR_EQUAL);

        // A NULL operand is the documented error return, not a code.
        EXPECT_EQ(Duet32CompareStringW(0, nullptr, -1, abc.p(), -1), 0);
        EXPECT_EQ(Duet32CompareStringW(0, abc.p(), -1, nullptr, -1), 0);
    }

    return duetos_host_test::finish_main("kernel32_32_nls");
}
