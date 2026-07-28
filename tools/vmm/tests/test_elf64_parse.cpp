// Hostile-input tests for ParseElf64 (src/elf64_parse.cpp).
//
// The kernel ELF is untrusted-by-construction input to the VMM. Before
// the hardening these cases wrapped past the loader's own range checks:
// `p_offset + p_filesz > buf.size()` reports "in range" when the sum
// overflows, after which LoadElf64 memcpy'd out-of-bounds host bytes
// straight into guest RAM.
#include "test_main.h"

#include "elf64_parse.h"

#include <cstring>
#include <vector>

using duetos::vmm::ParseElf64;
using duetos::vmm::ParsedElf;

namespace
{

constexpr size_t kEhdrSize = 64;
constexpr size_t kPhdrSize = 56;
constexpr uint32_t kPtLoad = 1;

struct Ph
{
    uint32_t type   = kPtLoad;
    uint64_t offset = 0;
    uint64_t paddr  = 0;
    uint64_t filesz = 0;
    uint64_t memsz  = 0;
};

void PutU16(std::vector<uint8_t>& v, size_t off, uint16_t x)
{
    std::memcpy(&v[off], &x, 2);
}
void PutU32(std::vector<uint8_t>& v, size_t off, uint32_t x)
{
    std::memcpy(&v[off], &x, 4);
}
void PutU64(std::vector<uint8_t>& v, size_t off, uint64_t x)
{
    std::memcpy(&v[off], &x, 8);
}

// A well-formed ELF64: 64-byte Ehdr, `phs` program headers at offset 64,
// then `tailBytes` of segment payload. Tests corrupt one field of the
// result to isolate exactly one defect per case.
std::vector<uint8_t> BuildElf(const std::vector<Ph>& phs, size_t tailBytes)
{
    std::vector<uint8_t> v(kEhdrSize + phs.size() * kPhdrSize + tailBytes, 0);
    v[0] = 0x7F;
    v[1] = 'E';
    v[2] = 'L';
    v[3] = 'F';
    v[4] = 2; // ELFCLASS64
    v[5] = 1; // little-endian
    PutU16(v, 16, 2);           // e_type = ET_EXEC
    PutU16(v, 18, 62);          // e_machine = EM_X86_64
    PutU64(v, 24, 0x100000);    // e_entry
    PutU64(v, 32, kEhdrSize);   // e_phoff
    PutU16(v, 54, kPhdrSize);   // e_phentsize
    PutU16(v, 56, static_cast<uint16_t>(phs.size())); // e_phnum
    for (size_t i = 0; i < phs.size(); ++i)
    {
        const size_t o = kEhdrSize + i * kPhdrSize;
        PutU32(v, o + 0, phs[i].type);
        PutU64(v, o + 8, phs[i].offset);
        PutU64(v, o + 24, phs[i].paddr);
        PutU64(v, o + 32, phs[i].filesz);
        PutU64(v, o + 40, phs[i].memsz);
    }
    return v;
}

bool Parse(const std::vector<uint8_t>& v, ParsedElf& pe)
{
    std::string err;
    return ParseElf64(v.data(), v.size(), pe, err);
}

} // namespace

TEST(elf64_parse_accepts_valid_two_segment_image)
{
    const size_t body = kEhdrSize + 2 * kPhdrSize;
    auto v = BuildElf({{kPtLoad, body, 0x100000, 32, 32},
                       {kPtLoad, body, 0x200000, 16, 64}},
                      64);
    ParsedElf pe;
    CHECK(Parse(v, pe));
    CHECK_EQ(pe.segments.size(), size_t(2));
    CHECK_EQ(pe.entry, 0x100000ull);
    CHECK_EQ(pe.lowPaddr, 0x100000ull);
    CHECK_EQ(pe.highPaddr, 0x200000ull + 64);
}

// e_phoff near UINT64_MAX: `phoff + phnum*phentsize` wraps to a small
// value, so the old check passed and the phdr read went out of bounds.
TEST(elf64_parse_rejects_phoff_overflow)
{
    auto v = BuildElf({{kPtLoad, kEhdrSize + kPhdrSize, 0x100000, 8, 8}}, 32);
    PutU64(v, 32, UINT64_MAX - 8); // e_phoff
    ParsedElf pe;
    CHECK(!Parse(v, pe));
}

// p_offset near UINT64_MAX with a small p_filesz: the sum wraps to a
// tiny number that compares "inside the file", then LoadElf64 would
// memcpy from buf.data() + p_offset into guest RAM.
TEST(elf64_parse_rejects_filesz_range_wrap)
{
    auto v = BuildElf({{kPtLoad, 0, 0x100000, 0, 0x1000}}, 64);
    const size_t ph = kEhdrSize;
    PutU64(v, ph + 8, UINT64_MAX - 4);  // p_offset
    PutU64(v, ph + 32, 16);             // p_filesz
    PutU64(v, ph + 40, 16);             // p_memsz
    ParsedElf pe;
    CHECK(!Parse(v, pe));
}

// p_paddr + p_memsz wrapping under-reports highPaddr, which is what the
// "--mem is too small" preflight compares against guest RAM size.
TEST(elf64_parse_rejects_paddr_memsz_overflow)
{
    auto v = BuildElf({{kPtLoad, kEhdrSize + kPhdrSize, 0, 8, 8}}, 32);
    const size_t ph = kEhdrSize;
    PutU64(v, ph + 24, UINT64_MAX - 0x1000); // p_paddr
    PutU64(v, ph + 40, 0x2000);              // p_memsz
    ParsedElf pe;
    CHECK(!Parse(v, pe));
}

TEST(elf64_parse_rejects_filesz_greater_than_memsz)
{
    auto v = BuildElf({{kPtLoad, kEhdrSize + kPhdrSize, 0x100000, 64, 8}}, 64);
    ParsedElf pe;
    CHECK(!Parse(v, pe));
}

TEST(elf64_parse_rejects_image_with_no_pt_load)
{
    auto v = BuildElf({{/*PT_NULL*/ 0, kEhdrSize + kPhdrSize, 0, 8, 8}}, 32);
    ParsedElf pe;
    CHECK(!Parse(v, pe));
}

TEST(elf64_parse_rejects_bad_magic_and_truncated)
{
    auto v = BuildElf({{kPtLoad, kEhdrSize + kPhdrSize, 0x100000, 8, 8}}, 32);
    v[1] = 'X';
    ParsedElf pe;
    CHECK(!Parse(v, pe));

    std::vector<uint8_t> tiny(16, 0);
    CHECK(!Parse(tiny, pe));

    std::string err;
    CHECK(!ParseElf64(nullptr, 0, pe, err));
}
