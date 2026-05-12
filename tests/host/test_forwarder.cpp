// tests/host/test_forwarder.cpp
//
// Hosted unit tests for ParseForwarder — the kernel-side parser
// that splits Win32 PE forwarder strings ("Dll.Target") into
// (dll_name, function or ordinal). Lives in
// `kernel/loader/pe_loader.cpp` as a file-local anonymous-
// namespace helper; this test re-states the algorithm and
// asserts the contract against the canonical Windows-export
// forwarder shapes.
//
// Forwarder shapes covered (from the kernel docstring):
//   "Kernel32.HeapAlloc"   — name-form, library carries no .dll suffix
//   "kernel32.dll.HeapAlloc" — name-form, library carries .dll
//   "ntdll.#42"            — ordinal-form, decimal ordinal
//   ".Target"              — malformed (empty DLL segment)
//   "Dll."                 — malformed (empty target after '.')
//   "Dll.#"                — malformed (no digits)
//   "Dll.#abc"             — malformed (non-digit chars)
//   "Dll.#4294967296"      — malformed (overflows u32)
//
// T10-04 follow-on: adds a fourth host-side pillar (PE
// forwarder parsing) beyond the existing
// VFS/registry/disk-path/result/string set.

#include "host_test_helper.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

using u32 = uint32_t;
using u64 = uint64_t;

constexpr u64 kMaxForwarderDllLen = 64;

struct ParsedForwarder
{
    bool is_ordinal;
    u32 ordinal;
    const char* func; // pointer into the input string after the '.'
};

static char AsciiToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return static_cast<char>(c - 'A' + 'a');
    return c;
}

// Mirror of kernel/loader/pe_loader.cpp::ParseForwarder.
static bool ParseForwarder(const char* fwd, char* out_dll, ParsedForwarder& out)
{
    if (fwd == nullptr || out_dll == nullptr)
        return false;
    out = {};
    const char* dot = nullptr;
    for (const char* p = fwd; *p; ++p)
    {
        if (*p == '.')
        {
            dot = p;
            break;
        }
    }
    if (dot == nullptr || dot == fwd)
        return false;
    if (*(dot + 1) == '\0')
        return false;

    const u64 dll_chars = static_cast<u64>(dot - fwd);
    if (dll_chars + 5 > kMaxForwarderDllLen)
        return false;
    for (u64 i = 0; i < dll_chars; ++i)
        out_dll[i] = fwd[i];
    out_dll[dll_chars] = '\0';

    bool has_dll_suffix = false;
    if (dll_chars >= 4)
    {
        const char* tail = out_dll + (dll_chars - 4);
        if (AsciiToLower(tail[0]) == '.' && AsciiToLower(tail[1]) == 'd' && AsciiToLower(tail[2]) == 'l' &&
            AsciiToLower(tail[3]) == 'l')
            has_dll_suffix = true;
    }
    if (!has_dll_suffix)
    {
        out_dll[dll_chars + 0] = '.';
        out_dll[dll_chars + 1] = 'd';
        out_dll[dll_chars + 2] = 'l';
        out_dll[dll_chars + 3] = 'l';
        out_dll[dll_chars + 4] = '\0';
    }

    if (*(dot + 1) == '#')
    {
        const char* digits = dot + 2;
        if (*digits < '0' || *digits > '9')
            return false;
        u64 acc = 0;
        for (const char* p = digits; *p; ++p)
        {
            if (*p < '0' || *p > '9')
                return false;
            acc = acc * 10 + u64(*p - '0');
            if (acc > 0xFFFFFFFFULL)
                return false;
        }
        out.is_ordinal = true;
        out.ordinal = static_cast<u32>(acc);
        out.func = nullptr;
        return true;
    }

    out.is_ordinal = false;
    out.ordinal = 0;
    out.func = dot + 1;
    return true;
}

int main()
{
    using namespace duetos_host_test;

    char dll[kMaxForwarderDllLen];
    ParsedForwarder out;

    // 1. Canonical name-form, no .dll suffix on the source library.
    EXPECT_TRUE(ParseForwarder("Kernel32.HeapAlloc", dll, out));
    EXPECT_STREQ(dll, "Kernel32.dll");
    EXPECT_FALSE(out.is_ordinal);
    EXPECT_TRUE(out.func != nullptr && std::strcmp(out.func, "HeapAlloc") == 0);

    // 2. The split is on the FIRST '.' — Windows forwarder strings
    //    are written as "Library.Target" without an embedded ".dll"
    //    suffix, so this is the correct behaviour. A "Lib.dll.Func"
    //    input is treated as Lib="Lib.dll" (suffix re-appended) and
    //    target="dll.Func", which is technically malformed but the
    //    parser doesn't reject it; documenting the shape here.
    EXPECT_TRUE(ParseForwarder("Lib.dll.Func", dll, out));
    EXPECT_STREQ(dll, "Lib.dll");
    EXPECT_FALSE(out.is_ordinal);
    EXPECT_TRUE(out.func != nullptr && std::strcmp(out.func, "dll.Func") == 0);

    // 3. Forwarder library name with hyphens/digits — common for
    //    api-ms-win-* split DLLs.
    EXPECT_TRUE(ParseForwarder("api-ms-win-crt-runtime-l1-1-0.exit", dll, out));
    EXPECT_STREQ(dll, "api-ms-win-crt-runtime-l1-1-0.dll");
    EXPECT_FALSE(out.is_ordinal);
    EXPECT_TRUE(out.func != nullptr && std::strcmp(out.func, "exit") == 0);

    // 4. Ordinal-form: "Dll.#N".
    EXPECT_TRUE(ParseForwarder("ntdll.#42", dll, out));
    EXPECT_STREQ(dll, "ntdll.dll");
    EXPECT_TRUE(out.is_ordinal);
    EXPECT_TRUE(out.ordinal == 42u);

    // 6. Boundary: ordinal == 0 is legal (some forwarders use it).
    EXPECT_TRUE(ParseForwarder("dll.#0", dll, out));
    EXPECT_TRUE(out.is_ordinal && out.ordinal == 0u);

    // 7. Boundary: ordinal == UINT32_MAX (4294967295) is legal.
    EXPECT_TRUE(ParseForwarder("dll.#4294967295", dll, out));
    EXPECT_TRUE(out.is_ordinal && out.ordinal == 0xFFFFFFFFu);

    // 8. Malformed: no '.' at all.
    EXPECT_FALSE(ParseForwarder("Kernel32HeapAlloc", dll, out));

    // 9. Malformed: empty DLL segment ('.' at start).
    EXPECT_FALSE(ParseForwarder(".HeapAlloc", dll, out));

    // 10. Malformed: empty target (trailing '.').
    EXPECT_FALSE(ParseForwarder("kernel32.", dll, out));

    // 11. Malformed: '#' with no digits.
    EXPECT_FALSE(ParseForwarder("kernel32.#", dll, out));

    // 12. Malformed: '#' with non-digit garbage.
    EXPECT_FALSE(ParseForwarder("kernel32.#abc", dll, out));

    // 13. Malformed: ordinal overflows u32 (4294967296 = UINT32_MAX+1).
    EXPECT_FALSE(ParseForwarder("kernel32.#4294967296", dll, out));

    // 14. Malformed: source DLL name too long (≥ 60 chars before '.dll'
    //     would need ≥ 65 total with the suffix; cap is 64).
    {
        char too_long[80];
        for (int i = 0; i < 60; ++i)
            too_long[i] = 'a';
        too_long[60] = '.';
        too_long[61] = 'f';
        too_long[62] = '\0';
        EXPECT_FALSE(ParseForwarder(too_long, dll, out));
    }

    // 15. NULL inputs reject cleanly.
    EXPECT_FALSE(ParseForwarder(nullptr, dll, out));
    EXPECT_FALSE(ParseForwarder("kernel32.foo", nullptr, out));

    return finish_main(__FILE__);
}
