// Hostile-input tests for ElfSymbols::Load (src/debug/elf_symbols.cpp).
//
// Load() runs on every VMM start against whatever file --kernel points
// at. Before the hardening its only gate was 4 magic bytes plus
// e_shentsize, after which e_shoff, e_shnum, sh_link, sh_offset, sh_size
// and st_name were all dereferenced unvalidated — six out-of-bounds
// reads on one path. The worst was the last: st_name indexed a
// .strtab that Load then handed to std::string(const char*), which
// scans for a NUL and so ran off the end of the mapping entirely.
//
// Layout built here puts .strtab LAST so it ends exactly at EOF — that
// is what makes the unterminated-name case a genuine overrun rather
// than a merely-wrong name.
#include "test_main.h"

#include "debug/elf_symbols.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using duetos::vmm::ElfSymbols;

namespace
{

constexpr size_t kEhdrSize  = 64;
constexpr size_t kShdrSize  = 64;
constexpr size_t kSymSize   = 24;
constexpr size_t kShnum     = 3; // NULL, .symtab, .strtab
constexpr size_t kShoff     = kEhdrSize;
constexpr size_t kSymOff    = kEhdrSize + kShnum * kShdrSize; // 256

// Absolute file offsets of the fields tests corrupt.
constexpr size_t kEhShoff      = 40;
constexpr size_t kEhShnum      = 60;
constexpr size_t kSymShOffset  = kShoff + 1 * kShdrSize + 24;
constexpr size_t kSymShSize    = kShoff + 1 * kShdrSize + 32;
constexpr size_t kSymShLink    = kShoff + 1 * kShdrSize + 40;
constexpr size_t kStrShOffset  = kShoff + 2 * kShdrSize + 24;
constexpr size_t kStrShSize    = kShoff + 2 * kShdrSize + 32;

struct Sym
{
    uint32_t name  = 0;
    uint8_t  info  = 1; // STT_OBJECT
    uint64_t value = 0x1000;
    uint64_t size  = 8;
};

void PutU16(std::vector<uint8_t>& v, size_t o, uint16_t x)
{
    std::memcpy(&v[o], &x, 2);
}
void PutU32(std::vector<uint8_t>& v, size_t o, uint32_t x)
{
    std::memcpy(&v[o], &x, 4);
}
void PutU64(std::vector<uint8_t>& v, size_t o, uint64_t x)
{
    std::memcpy(&v[o], &x, 8);
}

// [Ehdr][3 shdrs][symtab][strtab] — strtab flush against EOF.
std::vector<uint8_t> BuildElf(const std::vector<Sym>& syms,
                              const std::vector<uint8_t>& strtab)
{
    const size_t symBytes = syms.size() * kSymSize;
    const size_t strOff   = kSymOff + symBytes;
    std::vector<uint8_t> v(strOff + strtab.size(), 0);

    v[0] = 0x7F;
    v[1] = 'E';
    v[2] = 'L';
    v[3] = 'F';
    v[4] = 2;
    v[5] = 1;
    PutU16(v, 16, 2);
    PutU16(v, 18, 62);
    PutU64(v, kEhShoff, kShoff);
    PutU16(v, 58, static_cast<uint16_t>(kShdrSize)); // e_shentsize
    PutU16(v, kEhShnum, static_cast<uint16_t>(kShnum));

    // shdr[1] = .symtab (SHT_SYMTAB=2), sh_link -> .strtab index 2.
    const size_t sh1 = kShoff + 1 * kShdrSize;
    PutU32(v, sh1 + 4, 2);
    PutU64(v, sh1 + 24, kSymOff);
    PutU64(v, sh1 + 32, symBytes);
    PutU32(v, sh1 + 40, 2);
    PutU64(v, sh1 + 56, kSymSize); // sh_entsize

    // shdr[2] = .strtab (SHT_STRTAB=3).
    const size_t sh2 = kShoff + 2 * kShdrSize;
    PutU32(v, sh2 + 4, 3);
    PutU64(v, sh2 + 24, strOff);
    PutU64(v, sh2 + 32, strtab.size());

    for (size_t i = 0; i < syms.size(); ++i)
    {
        const size_t o = kSymOff + i * kSymSize;
        PutU32(v, o + 0, syms[i].name);
        v[o + 4] = syms[i].info;
        PutU64(v, o + 8, syms[i].value);
        PutU64(v, o + 16, syms[i].size);
    }
    if (!strtab.empty())
    {
        std::memcpy(&v[strOff], strtab.data(), strtab.size());
    }
    return v;
}

struct TempElf
{
    std::filesystem::path path;

    TempElf(const char* stem, const std::vector<uint8_t>& bytes)
    {
        path = std::filesystem::temp_directory_path() /
               (std::string("duetos-vmm-") + stem + ".elf");
        std::FILE* f = std::fopen(path.string().c_str(), "wb");
        CHECK(f != nullptr);
        if (!bytes.empty())
        {
            std::fwrite(bytes.data(), 1, bytes.size(), f);
        }
        std::fclose(f);
    }
    ~TempElf() { std::error_code ec; std::filesystem::remove(path, ec); }

    std::string str() const { return path.string(); }
};

// NUL-terminated ".strtab" content: leading NUL then "g_ticks".
std::vector<uint8_t> GoodStrtab()
{
    const char* s = "\0g_ticks\0";
    return std::vector<uint8_t>(s, s + 9);
}

} // namespace

TEST(elf_symbols_load_reads_a_valid_symtab)
{
    TempElf f("sym-ok", BuildElf({{1, 1, 0x1000, 8}}, GoodStrtab()));
    ElfSymbols syms;
    CHECK(syms.Load(f.str()));
    CHECK_EQ(syms.count(), size_t(1));
    const ElfSymbols::Sym* s = syms.Find("g_ticks");
    CHECK(s != nullptr);
    CHECK_EQ(s->addr, 0x1000ull);
}

// e_shoff is dereferenced to fetch every section header.
TEST(elf_symbols_load_rejects_huge_shoff)
{
    auto v = BuildElf({{1, 1, 0x1000, 8}}, GoodStrtab());
    PutU64(v, kEhShoff, UINT64_MAX - 8);
    TempElf f("sym-shoff", v);
    ElfSymbols syms;
    CHECK(!syms.Load(f.str()));
    CHECK_EQ(syms.count(), size_t(0));
}

// e_shnum bounds the shdr() loop; a count past EOF walked off the end.
TEST(elf_symbols_load_rejects_shnum_past_eof)
{
    auto v = BuildElf({{1, 1, 0x1000, 8}}, GoodStrtab());
    PutU16(v, kEhShnum, 1000);
    TempElf f("sym-shnum", v);
    ElfSymbols syms;
    CHECK(!syms.Load(f.str()));
}

// sh_link is the .strtab section index; it was truncated to u16 and used
// as an index with no comparison against e_shnum.
TEST(elf_symbols_load_rejects_symtab_link_out_of_range)
{
    auto v = BuildElf({{1, 1, 0x1000, 8}}, GoodStrtab());
    PutU32(v, kSymShLink, 99);
    TempElf f("sym-link", v);
    ElfSymbols syms;
    CHECK(!syms.Load(f.str()));
}

TEST(elf_symbols_load_rejects_symtab_offset_past_eof)
{
    auto v = BuildElf({{1, 1, 0x1000, 8}}, GoodStrtab());
    PutU64(v, kSymShOffset, UINT64_MAX - 16);
    TempElf f("sym-symoff", v);
    ElfSymbols syms;
    CHECK(!syms.Load(f.str()));
}

// sh_size is what divides into the per-symbol loop count.
TEST(elf_symbols_load_rejects_symtab_size_past_eof)
{
    auto v = BuildElf({{1, 1, 0x1000, 8}}, GoodStrtab());
    PutU64(v, kSymShSize, UINT64_MAX / 2);
    TempElf f("sym-symsize", v);
    ElfSymbols syms;
    CHECK(!syms.Load(f.str()));
}

TEST(elf_symbols_load_rejects_strtab_offset_past_eof)
{
    auto v = BuildElf({{1, 1, 0x1000, 8}}, GoodStrtab());
    PutU64(v, kStrShOffset, UINT64_MAX - 16);
    TempElf f("sym-stroff", v);
    ElfSymbols syms;
    CHECK(!syms.Load(f.str()));
}

// st_name past the end of .strtab used to index a wild pointer.
TEST(elf_symbols_load_skips_symbol_name_past_strtab)
{
    auto v = BuildElf({{9999, 1, 0x1000, 8}}, GoodStrtab());
    TempElf f("sym-name-oob", v);
    ElfSymbols syms;
    CHECK(!syms.Load(f.str())); // the one symbol is skipped -> empty
}

// THE unbounded read: .strtab's last byte is 'c', not NUL, and the
// section ends at EOF. std::string(strtab + st_name) would scan past the
// mapping looking for a zero byte; the name must instead stop at the
// section end.
TEST(elf_symbols_load_bounds_unterminated_strtab_name)
{
    const char* raw = "\0abc";
    std::vector<uint8_t> strtab(raw, raw + 4); // {0,'a','b','c'} — no NUL
    TempElf f("sym-unterm", BuildElf({{1, 1, 0x2000, 8}}, strtab));
    ElfSymbols syms;
    CHECK(syms.Load(f.str()));
    CHECK_EQ(syms.count(), size_t(1));
    const ElfSymbols::Sym* s = syms.Find("abc");
    CHECK(s != nullptr);
    CHECK_EQ(s->addr, 0x2000ull);
}

TEST(elf_symbols_load_rejects_short_and_non_elf_files)
{
    TempElf tiny("sym-tiny", std::vector<uint8_t>(16, 0));
    ElfSymbols a;
    CHECK(!a.Load(tiny.str()));

    auto v = BuildElf({{1, 1, 0x1000, 8}}, GoodStrtab());
    v[1] = 'X';
    TempElf bad("sym-magic", v);
    ElfSymbols b;
    CHECK(!b.Load(bad.str()));

    ElfSymbols c;
    CHECK(!c.Load("duetos-vmm-nonexistent-kernel.elf"));
}
