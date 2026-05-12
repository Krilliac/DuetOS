// tests/host/test_registry_path.cpp
//
// Hosted unit tests for the registry-path concatenation +
// case-insensitive equality primitives that live inside
// kernel/subsystems/win32/registry.cpp (`ConcatRegPath` +
// `PathEqualCi`). Both are anonymous-namespace helpers in the
// kernel TU; we re-state the algorithm here and assert the
// contract against canonical Win32 inputs.
//
// Contract notes (cribbed from the kernel TU's comments):
//   - Real Windows is forgiving about leading / trailing
//     backslashes on subkey concatenation; the kernel routine
//     trims one trailing '\\' from the parent and one leading
//     '\\' from the sub.
//   - Empty subkey reopens the parent (result == parent path).
//   - PathEqualCi is ASCII-only case-fold (registry paths are
//     ASCII in v0); both NUL-termination and length-equality
//     must hold.
//
// T10-04: extends the host-test pillar list to cover the
// registry-lookup primitive. Companion to test_vfs_resolve.cpp
// landing alongside this slice.

#include "host_test_helper.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

using u64 = uint64_t;

// Mirror of kernel/subsystems/win32/registry.cpp::AsciiToLower
// (which is itself a one-liner inside the TU).
static char AsciiToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return static_cast<char>(c - 'A' + 'a');
    return c;
}

// Mirror of kernel/subsystems/win32/registry.cpp::PathEqualCi.
static bool PathEqualCi(const char* a, const char* b)
{
    while (*a != 0 && *b != 0)
    {
        if (AsciiToLower(*a) != AsciiToLower(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == 0 && *b == 0;
}

// Mirror of kernel/subsystems/win32/registry.cpp::ConcatRegPath.
static bool ConcatRegPath(const char* parent_path, const char* sub, char* out, u64 cap)
{
    u64 i = 0;
    if (parent_path != nullptr)
    {
        while (parent_path[i] != '\0')
        {
            if (i + 1 >= cap)
                return false;
            out[i] = parent_path[i];
            ++i;
        }
    }
    if (i > 0 && out[i - 1] == '\\')
        --i;
    if (sub != nullptr && sub[0] == '\\')
        ++sub;
    if (sub == nullptr || sub[0] == '\0')
    {
        out[i] = '\0';
        return true;
    }
    if (i > 0)
    {
        if (i + 1 >= cap)
            return false;
        out[i++] = '\\';
    }
    while (*sub != '\0')
    {
        if (i + 1 >= cap)
            return false;
        out[i++] = *sub++;
    }
    out[i] = '\0';
    return true;
}

int main()
{
    using namespace duetos_host_test;

    char buf[64];

    // ============================================================
    // PathEqualCi
    // ============================================================

    EXPECT_TRUE(PathEqualCi("Software", "software"));
    EXPECT_TRUE(PathEqualCi("Software\\Microsoft", "SOFTWARE\\MICROSOFT"));
    EXPECT_TRUE(PathEqualCi("", ""));
    EXPECT_FALSE(PathEqualCi("Software", "Softwar")); // length mismatch
    EXPECT_FALSE(PathEqualCi("Software", "Software2"));
    EXPECT_FALSE(PathEqualCi("Software", ""));
    EXPECT_FALSE(PathEqualCi("", "x"));
    // Non-alpha chars stay byte-equal under the fold.
    EXPECT_TRUE(PathEqualCi("Foo\\1\\2", "FOO\\1\\2"));
    EXPECT_FALSE(PathEqualCi("Foo\\1", "Foo\\2"));

    // ============================================================
    // ConcatRegPath — canonical happy path
    // ============================================================

    // 1. Parent + sub with no decoration.
    EXPECT_TRUE(ConcatRegPath("Software", "Microsoft", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Software\\Microsoft");

    // 2. Parent with trailing '\\' — must be trimmed.
    EXPECT_TRUE(ConcatRegPath("Software\\", "Microsoft", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Software\\Microsoft");

    // 3. Sub with leading '\\' — must be stripped.
    EXPECT_TRUE(ConcatRegPath("Software", "\\Microsoft", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Software\\Microsoft");

    // 4. Both decorated.
    EXPECT_TRUE(ConcatRegPath("Software\\", "\\Microsoft", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Software\\Microsoft");

    // 5. Empty sub reopens the parent.
    EXPECT_TRUE(ConcatRegPath("Software\\Microsoft", "", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Software\\Microsoft");

    // 6. NULL sub also reopens the parent.
    EXPECT_TRUE(ConcatRegPath("Software\\Microsoft", nullptr, buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Software\\Microsoft");

    // 7. NULL parent + sub → sub stays as written (minus a leading
    //    backslash, which would otherwise leak through).
    EXPECT_TRUE(ConcatRegPath(nullptr, "Microsoft", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Microsoft");
    EXPECT_TRUE(ConcatRegPath(nullptr, "\\Microsoft", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Microsoft");

    // 8. Empty parent + sub.
    EXPECT_TRUE(ConcatRegPath("", "Microsoft", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Microsoft");

    // 9. Trailing-backslash parent with empty sub: trim still happens.
    EXPECT_TRUE(ConcatRegPath("Software\\", "", buf, sizeof(buf)));
    EXPECT_STREQ(buf, "Software");

    // ============================================================
    // ConcatRegPath — overflow rejection
    // ============================================================

    // Cap too tight for parent.
    EXPECT_FALSE(ConcatRegPath("Software\\Microsoft\\Windows NT", "CurrentVersion", buf, 8));

    // Cap fits parent + separator but not full sub.
    EXPECT_FALSE(ConcatRegPath("Software", "MicrosoftWindowsNTCurrentVersionLongSub", buf, 20));

    // Exact-fit case: parent + '\' + sub + NUL == cap.
    // "Foo" + "\\" + "Bar" + NUL = 8 bytes. cap=7 must reject
    // (no room for the NUL); cap=8 just fits.
    EXPECT_FALSE(ConcatRegPath("Foo", "Bar", buf, 7));
    EXPECT_TRUE(ConcatRegPath("Foo", "Bar", buf, 8));
    EXPECT_STREQ(buf, "Foo\\Bar");

    // ============================================================
    // Combined: concat then case-insensitive compare
    // ============================================================

    EXPECT_TRUE(ConcatRegPath("Software", "MICROSOFT", buf, sizeof(buf)));
    EXPECT_TRUE(PathEqualCi(buf, "software\\microsoft"));
    EXPECT_TRUE(PathEqualCi(buf, "SOFTWARE\\MICROSOFT"));

    return finish_main(__FILE__);
}
