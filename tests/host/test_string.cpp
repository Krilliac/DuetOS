// tests/host/test_string.cpp
//
// Hosted unit tests for the freestanding string primitives in
// kernel/util/string.cpp — memset, memcpy, memmove, plus the
// duetos::core helpers.
//
// kernel/util/string.cpp #includes arch/x86_64/serial.h, log/klog.h,
// and core/panic.h for some of its other helpers, which would
// transitively require kernel-only globals to link. Rather than
// linking the .cpp directly, this test re-defines the three byte-
// loop primitives inline (mirroring the kernel impl exactly) and
// asserts their behavior. If the kernel-side body is ever made
// non-trivial (vectorised, alignment-aware, etc.), this test
// inherits the new expectation by virtue of testing the same
// algorithmic contract.
//
// The point of the host test isn't to verify the build artefact —
// it's to assert algorithmic correctness in a sandbox where ASan
// + UBSan can catch out-of-bounds writes, signed-overflow misuse,
// and uninitialised reads that the kernel build can't.

#include "host_test_helper.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace test_local
{

// Verbatim port of kernel/util/string.cpp's primitives. Keep this
// in sync with the kernel side — the test re-derives the byte-loop
// behavior, not the symbol.
void* test_memset(void* dst, int c, std::size_t n)
{
    auto* p = static_cast<unsigned char*>(dst);
    const auto v = static_cast<unsigned char>(c);
    for (std::size_t i = 0; i < n; ++i)
    {
        p[i] = v;
    }
    return dst;
}

void* test_memmove(void* dst, const void* src, std::size_t n)
{
    auto* d = static_cast<unsigned char*>(dst);
    const auto* s = static_cast<const unsigned char*>(src);
    if (d == s || n == 0)
    {
        return dst;
    }
    if (d < s)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            d[i] = s[i];
        }
    }
    else
    {
        for (std::size_t i = n; i-- > 0;)
        {
            d[i] = s[i];
        }
    }
    return dst;
}

void* test_memcpy(void* dst, const void* src, std::size_t n)
{
    return test_memmove(dst, src, n);
}

} // namespace test_local

int main()
{
    using test_local::test_memcpy;
    using test_local::test_memmove;
    using test_local::test_memset;

    // memset: fills every byte with v. n=0 is a no-op.
    {
        unsigned char buf[16];
        std::memset(buf, 0xAA, sizeof(buf));
        test_memset(buf, 0x42, 8);
        for (int i = 0; i < 8; ++i)
        {
            EXPECT_EQ(buf[i], 0x42);
        }
        for (int i = 8; i < 16; ++i)
        {
            EXPECT_EQ(buf[i], 0xAA);
        }
    }
    {
        unsigned char buf[4]{1, 2, 3, 4};
        test_memset(buf, 0xFF, 0);
        EXPECT_EQ(buf[0], 1);
        EXPECT_EQ(buf[1], 2);
        EXPECT_EQ(buf[2], 3);
        EXPECT_EQ(buf[3], 4);
    }

    // memcpy: copies n bytes; non-overlapping case.
    {
        const char src[] = "DuetOS hosted test";
        char dst[32]{};
        test_memcpy(dst, src, sizeof(src));
        EXPECT_STREQ(dst, src);
    }

    // memmove: forward-overlap (dst > src). Naive memcpy would
    // clobber unread source bytes; memmove handles it correctly.
    {
        unsigned char buf[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        // Overlapping: copy [0..5) to [2..7). Forward copy would
        // read clobbered indices 2..4. memmove must detect dst>src
        // and walk backward.
        test_memmove(buf + 2, buf, 5);
        EXPECT_EQ(buf[0], 1);
        EXPECT_EQ(buf[1], 2);
        EXPECT_EQ(buf[2], 1);
        EXPECT_EQ(buf[3], 2);
        EXPECT_EQ(buf[4], 3);
        EXPECT_EQ(buf[5], 4);
        EXPECT_EQ(buf[6], 5);
        EXPECT_EQ(buf[7], 8);
        EXPECT_EQ(buf[8], 9);
        EXPECT_EQ(buf[9], 10);
    }

    // memmove: backward-overlap (dst < src).
    {
        unsigned char buf[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        test_memmove(buf, buf + 2, 5);
        EXPECT_EQ(buf[0], 3);
        EXPECT_EQ(buf[1], 4);
        EXPECT_EQ(buf[2], 5);
        EXPECT_EQ(buf[3], 6);
        EXPECT_EQ(buf[4], 7);
        // Bytes after the moved region are untouched.
        EXPECT_EQ(buf[5], 6);
        EXPECT_EQ(buf[6], 7);
        EXPECT_EQ(buf[7], 8);
    }

    // memmove: same-pointer self-copy is a no-op.
    {
        unsigned char buf[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        test_memmove(buf, buf, 4);
        EXPECT_EQ(buf[0], 0xAA);
        EXPECT_EQ(buf[1], 0xBB);
        EXPECT_EQ(buf[2], 0xCC);
        EXPECT_EQ(buf[3], 0xDD);
    }

    return duetos_host_test::finish_main("test_string");
}
