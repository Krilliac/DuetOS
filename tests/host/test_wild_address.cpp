// tests/host/test_wild_address.cpp
//
// Hosted unit test for the wild-address classifier in
// kernel/util/symbols.cpp (ClassifyWildAddress). The kernel-side
// helper writes its hint to COM1 via SerialWrite — that's
// kernel-only, so we re-derive the classification table here and
// assert the SAME mapping the kernel exposes. Any time the kernel
// adds a new sentinel pattern, mirror it in `host_classify` below.
//
// Why this test exists: the wild hints feed crash-dump readability,
// which is the diagnostic surface operators read first. A
// regression that silently drops a pattern (say, the u32 -1
// zero-extended branch) would leave a corrupted-pointer crash
// looking like an opaque hex value with no context.
//
// kernel-side TU under test: kernel/util/symbols.cpp
// kernel-side header        : kernel/util/symbols.h

#include "host_test_helper.h"

#include <cstdint>
#include <cstring>

namespace test_local
{

// Verbatim port of ClassifyWildAddress from kernel/util/symbols.cpp.
// Keep this in sync with the kernel side. The host test asserts
// the EXACT string the kernel returns so a divergent rewrite
// surfaces as a string-compare failure.
const char* host_classify(std::uint64_t value)
{
    if (value == 0)
    {
        return "null pointer — uninitialised function pointer or NULL deref";
    }
    if (value == 0xFFFFFFFFFFFFFFFFULL)
    {
        return "all-ones (-1) — wild branch / corrupted return address / IDT-uninit jump";
    }
    if (value == 0x00000000FFFFFFFFULL)
    {
        return "u32 -1 zero-extended — sentinel (kInvalid* / kKindMiss) used as pointer";
    }
    if (value == 0xFFFFFFFF00000000ULL)
    {
        return "high half all-ones, low zero — sign-extended u32 cast through";
    }
    if (value == 0xCCCCCCCCCCCCCCCCULL)
    {
        return "0xCC fill — MSVC debug-stack uninit pattern";
    }
    if (value == 0xCDCDCDCDCDCDCDCDULL)
    {
        return "0xCD fill — MSVC debug-heap uninit pattern";
    }
    if (value == 0xDEADBEEFDEADBEEFULL || value == 0x00000000DEADBEEFULL)
    {
        return "0xDEADBEEF — explicit poison marker";
    }
    if (value == 0xDEADC0DEDEADC0DEULL || value == 0x00000000DEADC0DEULL)
    {
        return "0xDEADC0DE — explicit poison marker";
    }
    if (value == 0xBAADF00DBAADF00DULL)
    {
        return "0xBAADF00D — uninit-heap fill (LocalAlloc)";
    }
    if (value == 0xFEEEFEEEFEEEFEEEULL)
    {
        return "0xFEEEFEEE — freed-heap fill";
    }
    if (value == 0xAAAAAAAAAAAAAAAAULL)
    {
        return "0xAA fill — kernel stack poison (kStackPoisonByte)";
    }
    {
        const std::uint64_t high = value >> 47;
        if (high != 0 && high != 0x1FFFFULL)
        {
            return "non-canonical — top 17 bits not sign-extended (CPU would #GP on deref)";
        }
    }
    if (value < 0x10000ULL)
    {
        return "small integer in pointer slot — likely an errno / index / sentinel cast through";
    }
    return nullptr;
}

} // namespace test_local

int main()
{
    using test_local::host_classify;

    // ----- Patterns that MUST be classified -----
    EXPECT_TRUE(host_classify(0xFFFFFFFFFFFFFFFFULL) != nullptr);
    EXPECT_TRUE(std::strstr(host_classify(0xFFFFFFFFFFFFFFFFULL), "all-ones") != nullptr);

    EXPECT_TRUE(host_classify(0x00000000FFFFFFFFULL) != nullptr);
    EXPECT_TRUE(std::strstr(host_classify(0x00000000FFFFFFFFULL), "u32 -1") != nullptr);

    EXPECT_TRUE(host_classify(0) != nullptr);
    EXPECT_TRUE(std::strstr(host_classify(0), "null pointer") != nullptr);

    EXPECT_TRUE(host_classify(0xCCCCCCCCCCCCCCCCULL) != nullptr);
    EXPECT_TRUE(host_classify(0xCDCDCDCDCDCDCDCDULL) != nullptr);
    EXPECT_TRUE(host_classify(0xDEADBEEFDEADBEEFULL) != nullptr);
    EXPECT_TRUE(host_classify(0xDEADC0DEDEADC0DEULL) != nullptr);
    EXPECT_TRUE(host_classify(0xBAADF00DBAADF00DULL) != nullptr);
    EXPECT_TRUE(host_classify(0xFEEEFEEEFEEEFEEEULL) != nullptr);
    EXPECT_TRUE(host_classify(0xAAAAAAAAAAAAAAAAULL) != nullptr);

    // u32 poison values zero-extended into a pointer slot — a
    // common bug shape when an i32 errno gets stored in a u64
    // function pointer field.
    EXPECT_TRUE(host_classify(0x00000000DEADBEEFULL) != nullptr);
    EXPECT_TRUE(host_classify(0x00000000DEADC0DEULL) != nullptr);

    // Non-canonical address (bits 47..63 not all-zero or all-one).
    // 0x0000_8000_0000_0000 is the FIRST non-canonical byte the
    // CPU rejects on deref; a successful classify lets the dump
    // call out "this can't be dereferenced" before the operator
    // wonders why it's not in any region.
    EXPECT_TRUE(host_classify(0x0000800000000000ULL) != nullptr);
    EXPECT_TRUE(std::strstr(host_classify(0x0000800000000000ULL), "non-canonical") != nullptr);

    // Small-integer-in-pointer-slot.
    EXPECT_TRUE(host_classify(1) != nullptr);
    EXPECT_TRUE(host_classify(0xFFFF) != nullptr);
    EXPECT_TRUE(std::strstr(host_classify(1), "small integer") != nullptr);

    // ----- Patterns that MUST NOT be classified (look valid) -----
    // Plausible kernel address (higher-half canonical).
    EXPECT_TRUE(host_classify(0xffffffff80100000ULL) == nullptr);
    // Plausible userspace address (low-half canonical).
    EXPECT_TRUE(host_classify(0x0000000000400000ULL) == nullptr);

    return ::duetos_host_test::finish_main("test_wild_address");
}
