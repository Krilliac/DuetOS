// Tests for vmm_dbg:: read/write/sym/dump and ElfSymbols::FindBySuffix.
//
// Built with VMM_DBG_NO_LIVE so the LiveResolver body (which pulls in
// vmm.h / WHP) is excluded. All resolution goes through FakeResolver.
#include "test_main.h"

#include "debug/elf_symbols.h"
#include "debug/vmm_dbg.h"

#include <cstring>
#include <string>

namespace
{

// ---------------------------------------------------------------------------
// FakeResolver — backs a 64-byte host buffer at a fixed "guest VA".
// ---------------------------------------------------------------------------
struct FakeResolver final : duetos::vmm::vmm_dbg::Resolver
{
    static constexpr uint64_t kFakeVa   = 0xffffffff80001000ull;
    static constexpr uint64_t kFakeSize = 64;

    uint8_t  buf[kFakeSize] = {};
    bool     findFails      = false;    // set to test missing-symbol path
    std::string symResult   = "fake_sym+0x0 (0xffffffff80001000)";

    bool FindSym(const char* /*name*/, uint64_t& va, uint64_t& sz) override
    {
        if (findFails)
        {
            return false;
        }
        va = kFakeVa;
        sz = kFakeSize;
        return true;
    }

    void* HostPtrForGva(uint64_t gva, uint64_t len) override
    {
        if (gva < kFakeVa || gva + len > kFakeVa + kFakeSize)
        {
            return nullptr;
        }
        return buf + (gva - kFakeVa);
    }

    const char* Symbolize(uint64_t /*addr*/) override
    {
        return symResult.c_str();
    }
};

// RAII guard: installs resolver on construction, clears on destruction.
struct ResolverGuard
{
    explicit ResolverGuard(duetos::vmm::vmm_dbg::Resolver* r)
    {
        duetos::vmm::vmm_dbg::SetTestResolver(r);
    }
    ~ResolverGuard()
    {
        duetos::vmm::vmm_dbg::SetTestResolver(nullptr);
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Test 1: ReadQ returns the value placed in the fake buffer.
// ---------------------------------------------------------------------------
TEST(vmm_dbg_read_q_returns_value_at_symbol)
{
    FakeResolver fake;
    uint64_t expected = 0xdeadbeefcafebabe;
    std::memcpy(fake.buf, &expected, sizeof(expected));

    ResolverGuard g(&fake);
    CHECK_EQ(duetos::vmm::vmm_dbg::ReadQ("test_sym"), expected);
}

// ---------------------------------------------------------------------------
// Test 2: ReadQ returns 0 when symbol lookup fails.
// ---------------------------------------------------------------------------
TEST(vmm_dbg_read_q_missing_symbol_returns_zero)
{
    FakeResolver fake;
    fake.findFails = true;

    ResolverGuard g(&fake);
    CHECK_EQ(duetos::vmm::vmm_dbg::ReadQ("no_such_sym"), uint64_t{0});
}

// ---------------------------------------------------------------------------
// Test 3: WriteQ then ReadQ round-trips the value.
// ---------------------------------------------------------------------------
TEST(vmm_dbg_write_q_then_read_q_roundtrips)
{
    FakeResolver  fake;
    ResolverGuard g(&fake);

    duetos::vmm::vmm_dbg::WriteQ("x", 0x1122334455667788ull);
    CHECK_EQ(duetos::vmm::vmm_dbg::ReadQ("x"), 0x1122334455667788ull);
}

// ---------------------------------------------------------------------------
// Test 4: Smaller-width writes round-trip via their matching reads.
// ---------------------------------------------------------------------------
TEST(vmm_dbg_write_smaller_widths_match)
{
    FakeResolver  fake;
    ResolverGuard g(&fake);

    // WriteB / ReadB
    duetos::vmm::vmm_dbg::WriteB("b", 0xAB);
    CHECK_EQ(duetos::vmm::vmm_dbg::ReadB("b"), uint8_t{0xAB});

    // WriteW / ReadW
    duetos::vmm::vmm_dbg::WriteW("w", 0xBEEF);
    CHECK_EQ(duetos::vmm::vmm_dbg::ReadW("w"), uint16_t{0xBEEF});

    // WriteD / ReadD
    duetos::vmm::vmm_dbg::WriteD("d", 0xDEADBEEF);
    CHECK_EQ(duetos::vmm::vmm_dbg::ReadD("d"), uint32_t{0xDEADBEEF});
}

// ---------------------------------------------------------------------------
// Test 5: Sym returns a thread-local string containing the resolver result.
// ---------------------------------------------------------------------------
TEST(vmm_dbg_sym_returns_thread_local_string)
{
    FakeResolver fake;
    fake.symResult = "fake_sym+0x42 (0xffffffff80001042)";
    ResolverGuard g(&fake);

    const char* s = duetos::vmm::vmm_dbg::Sym(0xffffffff80001042ull);
    CHECK(s != nullptr);
    CHECK(std::string(s).find("fake_sym+0x42") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Test 6: Dump formats a short payload as "ab cd ef ..." correctly.
// ---------------------------------------------------------------------------
TEST(vmm_dbg_dump_formats_short_payload)
{
    FakeResolver fake;
    // Fill buffer: 00 01 02 03 ...
    for (int i = 0; i < static_cast<int>(FakeResolver::kFakeSize); ++i)
    {
        fake.buf[i] = static_cast<uint8_t>(i);
    }
    ResolverGuard g(&fake);

    const char* out = duetos::vmm::vmm_dbg::Dump("sym", 4);
    CHECK(out != nullptr);
    std::string s(out);
    // Must start with "00 01 02 03"
    CHECK(s.rfind("00 01 02 03", 0) == 0);
}

// ---------------------------------------------------------------------------
// Test 6b: Dump caps excess n at 256 bytes.
//
// Uses a dedicated FakeResolver with a 512-byte buffer and symSize=512.
// Calls Dump with n=1000 and verifies that exactly 256 hex pairs are
// emitted — no more.
// ---------------------------------------------------------------------------
namespace
{
struct LargeFakeResolver final : duetos::vmm::vmm_dbg::Resolver
{
    static constexpr uint64_t kFakeVa   = 0xffffffff80002000ull;
    static constexpr uint64_t kFakeSize = 512;

    uint8_t buf[kFakeSize] = {};

    bool FindSym(const char* /*name*/, uint64_t& va, uint64_t& sz) override
    {
        va = kFakeVa;
        sz = kFakeSize;
        return true;
    }

    void* HostPtrForGva(uint64_t gva, uint64_t len) override
    {
        if (gva < kFakeVa || gva + len > kFakeVa + kFakeSize)
        {
            return nullptr;
        }
        return buf + (gva - kFakeVa);
    }

    const char* Symbolize(uint64_t /*addr*/) override
    {
        return "large_sym+0x0";
    }
};
} // namespace

TEST(vmm_dbg_dump_caps_excess_n_to_256)
{
    LargeFakeResolver fake;
    // Fill with index-mod-256 so every byte value is predictable.
    for (int i = 0; i < static_cast<int>(LargeFakeResolver::kFakeSize); ++i)
    {
        fake.buf[i] = static_cast<uint8_t>(i % 256);
    }
    ResolverGuard g(&fake);

    const char* out = duetos::vmm::vmm_dbg::Dump("large_sym", 1000);
    CHECK(out != nullptr);

    // Dump trims the trailing space, so 256 bytes → "XX XX ... XX" with
    // spaces between = 256*3 - 1 = 767 characters.
    std::string s(out);
    CHECK_EQ(s.size(), static_cast<size_t>(256 * 3 - 1));

    // Spot-check: byte 0 → "00", byte 255 → "ff", byte 256 absent.
    CHECK(s.rfind("00 ", 0) == 0);
    // Last three chars should be "ff" (byte 255, no trailing space).
    CHECK(s.size() >= 2 && s.substr(s.size() - 2) == "ff");
}

// ---------------------------------------------------------------------------
// Test 7: ElfSymbols::FindBySuffix matches a mangled anonymous-namespace sym.
// ---------------------------------------------------------------------------
TEST(elf_symbols_find_by_suffix_matches_mangled_anonymous_namespace)
{
    duetos::vmm::ElfSymbols syms;
    syms.AddSymForTest({"_ZN6duetos4arch12_GLOBAL__N_17g_ticksE",
                        0xffffffff80e6f770ull, 8});

    const duetos::vmm::ElfSymbols::Sym* s = syms.FindBySuffix("g_ticks");
    CHECK(s != nullptr);
    CHECK_EQ(s->addr, 0xffffffff80e6f770ull);
}

// ---------------------------------------------------------------------------
// Test 8: FindBySuffix prefers the non-anonymous-namespace symbol.
// ---------------------------------------------------------------------------
TEST(elf_symbols_find_by_suffix_prefers_non_anonymous)
{
    duetos::vmm::ElfSymbols syms;
    // Anonymous-namespace version (lower address — must NOT be chosen).
    syms.AddSymForTest({"_ZN6duetos4arch12_GLOBAL__N_17g_ticksE",
                        0xffffffff80e00000ull, 8});
    // Named-namespace version (higher address — MUST be chosen).
    syms.AddSymForTest({"_ZN6duetos4arch7g_ticksE",
                        0xffffffff80e10000ull, 8});

    const duetos::vmm::ElfSymbols::Sym* s = syms.FindBySuffix("g_ticks");
    CHECK(s != nullptr);
    // Must pick the non-anonymous one regardless of address order.
    CHECK_EQ(s->addr, 0xffffffff80e10000ull);
}
