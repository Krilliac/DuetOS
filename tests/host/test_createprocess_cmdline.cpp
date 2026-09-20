// Hosted contract for kernel32 CreateProcess executable-token extraction.
// The production helper is header-only so these tests exercise the exact code
// compiled into kernel32.dll rather than a restated parser.

#include "host_test_helper.h"

#include "../../userland/libs/kernel32/createprocess_cmdline.h"

#include <cstring>
#include <string>

namespace
{

using namespace duetos_host_test;

void ExpectA(const char* application, const char* command_line, const char* expected)
{
    char path[128] = {};
    EXPECT_TRUE(Win32ExtractCreateProcessExecutableA(application, command_line, path, sizeof(path)));
    EXPECT_STREQ(path, expected);
}

void ExpectW(const unsigned short* application, const unsigned short* command_line, const char* expected)
{
    char path[128] = {};
    EXPECT_TRUE(Win32ExtractCreateProcessExecutableW(application, command_line, path, sizeof(path)));
    EXPECT_STREQ(path, expected);
}

} // namespace

int main()
{
    using namespace duetos_host_test;

    ExpectA("explicit.exe", nullptr, "explicit.exe");
    ExpectA("explicit.exe", "other.exe --flag", "explicit.exe");
    ExpectA(nullptr, "prog.exe --flag", "prog.exe");
    ExpectA(nullptr, " \t\r\n\v\fprog.exe --flag", "prog.exe");
    ExpectA(nullptr, "\"C:\\Program Files\\app.exe\" /x", "C:\\Program Files\\app.exe");
    ExpectA(nullptr, "/disk/0/app.exe arg-one arg-two", "/disk/0/app.exe");

    static const unsigned short kWideExplicit[] = {'C', ':', '\\', 'a', 'p', 'p', '.', 'e', 'x', 'e', 0};
    static const unsigned short kWideOther[] = {'o', 't', 'h', 'e', 'r', '.', 'e', 'x', 'e', ' ', 'x', 0};
    static const unsigned short kWideQuoted[] = {' ', '\"', 'C', ':', '\\', 'P', 'r', 'o',  'g', 'r', 'a',
                                                 'm', ' ',  'F', 'i', 'l',  'e', 's', '\\', 'a', 'p', 'p',
                                                 '.', 'e',  'x', 'e', '\"', ' ', '/', 'x',  0};
    ExpectW(kWideExplicit, kWideOther, "C:\\app.exe");
    ExpectW(nullptr, kWideQuoted, "C:\\Program Files\\app.exe");

    char path[128] = {'X', 0};
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA(nullptr, nullptr, path, sizeof(path)));
    EXPECT_STREQ(path, "");
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA(nullptr, "", path, sizeof(path)));
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA(nullptr, "   \t", path, sizeof(path)));
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA(nullptr, "\"unterminated path", path, sizeof(path)));
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA(nullptr, "\"\" argument", path, sizeof(path)));
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA("", "other.exe", path, sizeof(path)));
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA("app.exe", nullptr, nullptr, sizeof(path)));
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA("app.exe", nullptr, path, 0));

    std::string max_path(127, 'a');
    ExpectA(max_path.c_str(), nullptr, max_path.c_str());
    std::string oversized(128, 'b');
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA(oversized.c_str(), nullptr, path, sizeof(path)));
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableA(nullptr, (oversized + " arg").c_str(), path, sizeof(path)));

    unsigned short wide_max[128] = {};
    for (unsigned i = 0; i < 127; ++i)
        wide_max[i] = 'w';
    EXPECT_TRUE(Win32ExtractCreateProcessExecutableW(wide_max, nullptr, path, sizeof(path)));
    EXPECT_EQ(std::strlen(path), static_cast<size_t>(127));

    unsigned short wide_oversized[129] = {};
    for (unsigned i = 0; i < 128; ++i)
        wide_oversized[i] = 'z';
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableW(wide_oversized, nullptr, path, sizeof(path)));

    static const unsigned short kWideNonAscii[] = {'C', ':', '\\', 0x00E9, '.', 'e', 'x', 'e', 0};
    static const unsigned short kWideSurrogate[] = {'C', ':', '\\', 0xD800, 0};
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableW(kWideNonAscii, nullptr, path, sizeof(path)));
    EXPECT_FALSE(Win32ExtractCreateProcessExecutableW(kWideSurrogate, nullptr, path, sizeof(path)));

    return finish_main("test_createprocess_cmdline");
}
