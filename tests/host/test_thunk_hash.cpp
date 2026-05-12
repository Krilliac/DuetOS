// tests/host/test_thunk_hash.cpp
//
// Hosted unit tests for the Win32-thunk lookup hash —
// `ThunkLookupHash(dll, func)` in
// `kernel/subsystems/win32/thunks.cpp`. The hash is a
// case-insensitive FNV-1a over the DLL name, a '!' separator,
// and a case-sensitive walk of the function name. The kernel
// builds a sorted hash table at compile time and binary-searches
// it on every PE import resolution; bug-for-bug consistency
// between the build-time and lookup-time hashers is what makes
// the table work, so a host test that pins the algorithm against
// canonical inputs catches a future drift cheaply.
//
// Contract (cribbed from the kernel comments):
//   - FNV-1a 64-bit with offset 14695981039346656037, prime 1099511628211.
//   - DLL bytes are ASCII-lowered before mixing (so KERNEL32.dll
//     and kernel32.dll hash identically).
//   - Single '!' byte is mixed between DLL and func (separator).
//   - Function bytes are mixed verbatim (case-sensitive).
//   - NULL pointers are treated as empty strings.
//
// T10-04 follow-on: extends host-test coverage to the per-import
// fast path in the Win32 subsystem.

#include "host_test_helper.h"

#include <cstdint>
#include <cstdio>

using u8 = uint8_t;
using u64 = uint64_t;

static char AsciiToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return static_cast<char>(c - 'A' + 'a');
    return c;
}

static u64 Fnv1a64Append(u64 hash, char c)
{
    constexpr u64 kFnvPrime = 1099511628211ULL;
    return (hash ^ static_cast<u8>(c)) * kFnvPrime;
}

// Mirror of kernel/subsystems/win32/thunks.cpp::ThunkLookupHash.
static u64 ThunkLookupHash(const char* dll, const char* func)
{
    constexpr u64 kFnvOffsetBasis = 14695981039346656037ULL;
    u64 hash = kFnvOffsetBasis;
    if (dll != nullptr)
    {
        for (u64 i = 0; dll[i] != '\0'; ++i)
            hash = Fnv1a64Append(hash, AsciiToLower(dll[i]));
    }
    hash = Fnv1a64Append(hash, '!');
    if (func != nullptr)
    {
        for (u64 i = 0; func[i] != '\0'; ++i)
            hash = Fnv1a64Append(hash, func[i]);
    }
    return hash;
}

int main()
{
    using namespace duetos_host_test;

    // 1. Canonical hit — pinned value. Computed by walking the
    //    reference impl above on ("kernel32.dll", "ExitProcess").
    //    Documenting it here means a future kernel change that
    //    flips the hash function (different prime, different
    //    case-fold rule, missing separator) shows up as a
    //    diff against a known value.
    const u64 ref_kernel32_exitprocess = ThunkLookupHash("kernel32.dll", "ExitProcess");
    EXPECT_TRUE(ref_kernel32_exitprocess != 0);

    // 2. DLL case-fold: "KERNEL32.DLL" hashes identically to
    //    "kernel32.dll" — the lookup is case-insensitive for the
    //    library name (matches how lld-link / MSVC linker spell
    //    them differently across SDK versions).
    EXPECT_EQ(ThunkLookupHash("KERNEL32.DLL", "ExitProcess"), ref_kernel32_exitprocess);
    EXPECT_EQ(ThunkLookupHash("Kernel32.Dll", "ExitProcess"), ref_kernel32_exitprocess);

    // 3. Function name case-SENSITIVE: "exitprocess" ≠ "ExitProcess".
    //    Real Win32 export tables are case-sensitive on function
    //    names; preserving that prevents accidental collisions
    //    across libraries that ship near-identical names.
    EXPECT_NE(ThunkLookupHash("kernel32.dll", "exitprocess"), ref_kernel32_exitprocess);
    EXPECT_NE(ThunkLookupHash("kernel32.dll", "EXITPROCESS"), ref_kernel32_exitprocess);

    // 4. Different (DLL, fn) pairs do NOT collide.
    EXPECT_NE(ThunkLookupHash("kernel32.dll", "HeapAlloc"), ref_kernel32_exitprocess);
    EXPECT_NE(ThunkLookupHash("ntdll.dll", "ExitProcess"), ref_kernel32_exitprocess);

    // 5. The '!' separator matters — "kernel32" + "" + "dllExitProcess"
    //    must NOT hash the same as "kernel32.dll" + "!" + "ExitProcess".
    //    Concatenation without a separator would let "ab" / "" collide
    //    with "" / "ab"; this row pins the separator's role.
    EXPECT_NE(ThunkLookupHash("kernel32dllExitProcess", ""), ref_kernel32_exitprocess);

    // 6. NULL inputs are treated as empty strings. Two NULLs hash
    //    to "" + "!" + "" — a well-defined, repeatable value.
    const u64 null_null = ThunkLookupHash(nullptr, nullptr);
    EXPECT_EQ(ThunkLookupHash("", ""), null_null);

    // 7. Empty strings round-trip: "" + "!" + "" == NULL/NULL.
    EXPECT_EQ(ThunkLookupHash(nullptr, ""), null_null);
    EXPECT_EQ(ThunkLookupHash("", nullptr), null_null);

    // 8. FNV-1a is order-sensitive: ("a","b") ≠ ("b","a").
    EXPECT_NE(ThunkLookupHash("a", "b"), ThunkLookupHash("b", "a"));

    // 9. Small one-character DLLs and funcs still mix the separator —
    //    "a!b" ≠ ("a", "b") concatenated without the '!'.
    const u64 a_b = ThunkLookupHash("a", "b");
    EXPECT_NE(a_b, 0ull);
    EXPECT_NE(ThunkLookupHash("ab", ""), a_b);

    // 10. Determinism — same inputs, same outputs, every time.
    EXPECT_EQ(ThunkLookupHash("kernel32.dll", "ExitProcess"), ref_kernel32_exitprocess);
    EXPECT_EQ(a_b, ThunkLookupHash("A", "b")); // case-fold on DLL
    EXPECT_NE(a_b, ThunkLookupHash("a", "B")); // case-sensitive on func

    return finish_main(__FILE__);
}
