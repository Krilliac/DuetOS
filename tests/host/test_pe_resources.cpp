// test_pe_resources.cpp — hosted unit test for the freestanding PE
// `.rsrc` walker shared by the x86_64 and i386 Win32 companion DLLs.
//
// Covers userland/libs/common/pe_resources.h:
//   - duet_res_init over both PE32 (0x10B) and PE32+ (0x20B) headers
//   - the three-level Type -> Name/ID -> Language walk
//   - named (high-bit) vs integer directory entries, and the ASCII
//     case-insensitive fold applied to named entries
//   - language selection: exact LANGID, LANG_NEUTRAL fallback, then
//     first-entry fallback
//   - LoadString bundling: string `id` lives at slot `id % 16` of the
//     RT_STRING resource whose integer name is `(id / 16) + 1`
//   - malformed trees failing CLOSED rather than walking out of the
//     image: out-of-section directory offsets, an entry table running
//     past the section, a data entry whose OffsetToData/Size escapes
//     the image, a self-referential subdirectory, an oversized
//     IMAGE_RESOURCE_DIR_STRING_U length, and a string bundle whose
//     counted length runs past the resource
//
// The images are synthesised here rather than compiled by windres so
// that the malformed cases can be constructed at all — windres will
// not emit a tree that points outside its own section.
//
// Expected behaviour is pinned to the PE/COFF specification section 6.9
// ("The .rsrc Section") and the documented LoadStringW contract.

#include "host_test_helper.h"

#include "../../userland/libs/common/pe_resources.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace duetos_host_test;

// host_test_helper.h's ASSERT_TRUE returns finish_main(), so it only
// compiles inside main(). These tests live in helper functions, so they
// need the same "record and stop" behaviour with a plain `return`.
#define REQUIRE(cond)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            std::fprintf(stderr, "%s:%d: FATAL: REQUIRE(%s)\n", __FILE__, __LINE__, #cond);                            \
            ++::duetos_host_test::failure_count();                                                                     \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

namespace
{

// ------------------------------------------------------------------
// Synthetic image builder
// ------------------------------------------------------------------
//
// Lays out a minimal but structurally honest module:
//
//   RVA 0x0000  headers (DOS stub, NT headers, one section header)
//   RVA 0x1000  ".rsrc" section, kRsrcBytes long
//
// The image buffer IS the mapped view: RVA == buffer offset, which is
// what the kernel's MapSection produces for a SectionAlignment ==
// FileAlignment == 0x1000 image. Resource-directory offsets used by the
// tests are therefore relative to kRsrcRva.

constexpr uint32_t kHeadersSize = 0x1000;
constexpr uint32_t kRsrcRva = 0x1000;
constexpr uint32_t kRsrcBytes = 0x1000;
constexpr uint32_t kImageSize = kRsrcRva + kRsrcBytes;

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v)
{
    b[off] = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v)
{
    for (int i = 0; i < 4; ++i)
        b[off + static_cast<size_t>(i)] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

// `pe32` selects the i386 optional-header layout (magic 0x10B,
// DataDirectory at +96) instead of PE32+ (0x20B, DataDirectory at
// +112). Everything the walker reads is at the same offset in both
// except the directory array, which is exactly the difference the
// parser has to get right.
std::vector<uint8_t> make_image(bool pe32, uint32_t dir_rva = kRsrcRva, uint32_t dir_size = kRsrcBytes,
                                uint32_t rsrc_virtual_size = kRsrcBytes)
{
    std::vector<uint8_t> image(kImageSize, 0);

    constexpr uint32_t kLfanew = 0x80;
    image[0] = 'M';
    image[1] = 'Z';
    put32(image, 0x3C, kLfanew);

    image[kLfanew + 0] = 'P';
    image[kLfanew + 1] = 'E';
    put16(image, kLfanew + 4, pe32 ? 0x014C : 0x8664); // Machine
    put16(image, kLfanew + 6, 1);                      // NumberOfSections

    const uint16_t optional_size = pe32 ? 224 : 240;
    put16(image, kLfanew + 20, optional_size);

    const size_t opt = kLfanew + 24;
    put16(image, opt + 0, pe32 ? 0x010B : 0x020B);
    put32(image, opt + 56, kImageSize);   // SizeOfImage
    put32(image, opt + 60, kHeadersSize); // SizeOfHeaders

    const size_t dd = opt + (pe32 ? 96 : 112);
    put32(image, dd - 4, 16); // NumberOfRvaAndSizes
    put32(image, dd + 2 * 8 + 0, dir_rva);
    put32(image, dd + 2 * 8 + 4, dir_size);

    const size_t sec = opt + optional_size;
    const char name[8] = {'.', 'r', 's', 'r', 'c', 0, 0, 0};
    for (int i = 0; i < 8; ++i)
        image[sec + static_cast<size_t>(i)] = static_cast<uint8_t>(name[i]);
    put32(image, sec + 8, rsrc_virtual_size); // VirtualSize
    put32(image, sec + 12, kRsrcRva);         // VirtualAddress
    put32(image, sec + 16, kRsrcBytes);       // SizeOfRawData
    put32(image, sec + 20, kRsrcRva);         // PointerToRawData
    put32(image, sec + 36, 0x40000040);       // INITIALIZED_DATA | MEM_READ
    return image;
}

// --- resource-tree writers (offsets are .rsrc-relative) -----------

void write_dir_header(std::vector<uint8_t>& image, uint32_t off, uint16_t named, uint16_t ids)
{
    put16(image, kRsrcRva + off + 12, named);
    put16(image, kRsrcRva + off + 14, ids);
}

// `name` already carries the high bit when it is a string offset;
// `child` gets the high bit set here when `is_dir`.
void write_dir_entry(std::vector<uint8_t>& image, uint32_t dir_off, uint32_t index, uint32_t name, uint32_t child,
                     bool is_dir)
{
    const uint32_t off = kRsrcRva + dir_off + 16 + index * 8;
    put32(image, off, name);
    put32(image, off + 4, is_dir ? (child | 0x80000000u) : child);
}

void write_data_entry(std::vector<uint8_t>& image, uint32_t off, uint32_t data_rva, uint32_t size)
{
    put32(image, kRsrcRva + off, data_rva);
    put32(image, kRsrcRva + off + 4, size);
}

void write_utf16(std::vector<uint8_t>& image, uint32_t rva, const std::u16string& s)
{
    for (size_t i = 0; i < s.size(); ++i)
        put16(image, rva + i * 2, static_cast<uint16_t>(s[i]));
}

// IMAGE_RESOURCE_DIR_STRING_U at `off`: u16 length + chars.
void write_dir_string(std::vector<uint8_t>& image, uint32_t off, const std::u16string& s)
{
    put16(image, kRsrcRva + off, static_cast<uint16_t>(s.size()));
    write_utf16(image, kRsrcRva + off + 2, s);
}

// A whole three-level chain for one integer-ID resource, laid out at
// fixed offsets so the tests can point at any level.
//
//   0x000 root dir      (1 id entry: `type`)
//   0x020 name dir      (1 id entry: `name`)
//   0x040 lang dir      (`langs` entries)
//   0x0C0 data entries  (one per lang, 16 bytes each)
//   0x200 payload
constexpr uint32_t kRootDir = 0x000;
constexpr uint32_t kNameDir = 0x020;
constexpr uint32_t kLangDir = 0x040;
constexpr uint32_t kDataEntries = 0x0C0;
constexpr uint32_t kPayload = 0x200;

void build_chain(std::vector<uint8_t>& image, uint32_t type, uint32_t name, const std::vector<uint32_t>& langs,
                 uint32_t payload_rva, uint32_t payload_size)
{
    write_dir_header(image, kRootDir, 0, 1);
    write_dir_entry(image, kRootDir, 0, type, kNameDir, true);
    write_dir_header(image, kNameDir, 0, 1);
    write_dir_entry(image, kNameDir, 0, name, kLangDir, true);
    write_dir_header(image, kLangDir, 0, static_cast<uint16_t>(langs.size()));
    for (size_t i = 0; i < langs.size(); ++i)
    {
        const uint32_t data_off = kDataEntries + static_cast<uint32_t>(i) * 16;
        write_dir_entry(image, kLangDir, static_cast<uint32_t>(i), langs[i], data_off, false);
        write_data_entry(image, data_off, payload_rva, payload_size);
    }
}

// One RT_STRING bundle: 16 counted UTF-16 slots, in order.
// Returns the byte length written at `rva`.
uint32_t write_string_bundle(std::vector<uint8_t>& image, uint32_t rva, const std::vector<std::u16string>& slots)
{
    uint32_t cursor = rva;
    for (const std::u16string& s : slots)
    {
        put16(image, cursor, static_cast<uint16_t>(s.size()));
        cursor += 2;
        write_utf16(image, cursor, s);
        cursor += static_cast<uint32_t>(s.size()) * 2;
    }
    return cursor - rva;
}

DUET_RES_KEY id_key(unsigned int id)
{
    DUET_RES_KEY k;
    k.by_name = 0;
    k.id = id;
    k.name = nullptr;
    k.name_len = 0;
    return k;
}

DUET_RES_KEY name_key(const std::u16string& s)
{
    DUET_RES_KEY k;
    k.by_name = 1;
    k.id = 0;
    k.name = reinterpret_cast<const unsigned short*>(s.data());
    k.name_len = static_cast<unsigned int>(s.size());
    return k;
}

std::u16string read_back(const unsigned short* p, unsigned int len)
{
    std::u16string s;
    for (unsigned int i = 0; i < len; ++i)
        s.push_back(static_cast<char16_t>(p[i]));
    return s;
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

void test_init_accepts_both_bitnesses()
{
    for (bool pe32 : {false, true})
    {
        std::vector<uint8_t> image = make_image(pe32);
        DUET_RES_VIEW view{};
        EXPECT_TRUE(duet_res_init(image.data(), &view) == 1);
        EXPECT_EQ(view.image_size, kImageSize);
        EXPECT_EQ(view.dir_rva, kRsrcRva);
        // The tree bound is the section's mapped extent, not the
        // declared DataDirectory size.
        EXPECT_EQ(view.dir_span, kRsrcBytes);
    }
}

void test_init_rejects_garbage()
{
    DUET_RES_VIEW view{};
    EXPECT_TRUE(duet_res_init(nullptr, &view) == 0);

    std::vector<uint8_t> image = make_image(false);
    EXPECT_TRUE(duet_res_init(image.data(), nullptr) == 0);

    // No MZ.
    std::vector<uint8_t> no_mz = make_image(false);
    no_mz[0] = 'X';
    EXPECT_TRUE(duet_res_init(no_mz.data(), &view) == 0);

    // No PE signature.
    std::vector<uint8_t> no_pe = make_image(false);
    no_pe[0x80] = 'Q';
    EXPECT_TRUE(duet_res_init(no_pe.data(), &view) == 0);

    // Unknown optional-header magic.
    std::vector<uint8_t> bad_magic = make_image(false);
    put16(bad_magic, 0x80 + 24, 0x0107);
    EXPECT_TRUE(duet_res_init(bad_magic.data(), &view) == 0);

    // e_lfanew past the guaranteed header probe.
    std::vector<uint8_t> far_lfanew = make_image(false);
    put32(far_lfanew, 0x3C, 0x0FF8);
    EXPECT_TRUE(duet_res_init(far_lfanew.data(), &view) == 0);

    // No resource directory at all.
    std::vector<uint8_t> no_rsrc = make_image(false, 0, 0);
    EXPECT_TRUE(duet_res_init(no_rsrc.data(), &view) == 0);

    // Resource directory RVA outside every mapped section.
    std::vector<uint8_t> stray = make_image(false, kImageSize - 8, 0x100);
    EXPECT_TRUE(duet_res_init(stray.data(), &view) == 0);

    // Declared directory size larger than the section that holds it —
    // a header claiming more than the kernel mapped.
    std::vector<uint8_t> oversize = make_image(false, kRsrcRva, kRsrcBytes + 1);
    EXPECT_TRUE(duet_res_init(oversize.data(), &view) == 0);

    // SizeOfHeaders larger than SizeOfImage.
    std::vector<uint8_t> fat_headers = make_image(false);
    put32(fat_headers, 0x80 + 24 + 60, kImageSize + 0x1000);
    EXPECT_TRUE(duet_res_init(fat_headers.data(), &view) == 0);
}

void test_three_level_walk_by_id()
{
    std::vector<uint8_t> image = make_image(false);
    const std::u16string payload = u"hello";
    write_utf16(image, kRsrcRva + kPayload, payload);
    build_chain(image, DUET_RES_TYPE_MANIFEST, 101, {0x0409}, kRsrcRva + kPayload, 10);

    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    DUET_RES_KEY type = id_key(DUET_RES_TYPE_MANIFEST);
    DUET_RES_KEY name = id_key(101);
    unsigned int rva = 0;
    unsigned int size = 0;
    EXPECT_TRUE(duet_res_find(&view, &type, &name, 0x0409, 1, &rva, &size) == 1);
    EXPECT_EQ(rva, kRsrcRva + kPayload);
    EXPECT_EQ(size, 10u);
    EXPECT_TRUE(duet_res_at(&view, rva, size) == image.data() + rva);

    // Wrong type / wrong name miss cleanly.
    DUET_RES_KEY other_type = id_key(DUET_RES_TYPE_DIALOG);
    EXPECT_TRUE(duet_res_find(&view, &other_type, &name, 0x0409, 1, &rva, &size) == 0);
    DUET_RES_KEY other_name = id_key(102);
    EXPECT_TRUE(duet_res_find(&view, &type, &other_name, 0x0409, 1, &rva, &size) == 0);
}

void test_named_entries_and_case_fold()
{
    std::vector<uint8_t> image = make_image(false);
    // Named type at level 1 and named name at level 2, both stored as
    // IMAGE_RESOURCE_DIR_STRING_U blobs with the high bit set.
    constexpr uint32_t kTypeStr = 0x300;
    constexpr uint32_t kNameStr = 0x340;
    write_dir_string(image, kTypeStr, u"CUSTOMTYPE");
    write_dir_string(image, kNameStr, u"MyResource");

    write_dir_header(image, kRootDir, 1, 0);
    write_dir_entry(image, kRootDir, 0, kTypeStr | 0x80000000u, kNameDir, true);
    write_dir_header(image, kNameDir, 1, 0);
    write_dir_entry(image, kNameDir, 0, kNameStr | 0x80000000u, kLangDir, true);
    write_dir_header(image, kLangDir, 0, 1);
    write_dir_entry(image, kLangDir, 0, 0, kDataEntries, false);
    write_data_entry(image, kDataEntries, kRsrcRva + kPayload, 4);

    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    std::u16string type_s = u"CUSTOMTYPE";
    std::u16string name_s = u"MyResource";
    DUET_RES_KEY type = name_key(type_s);
    DUET_RES_KEY name = name_key(name_s);
    unsigned int rva = 0;
    unsigned int size = 0;
    EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 1);
    EXPECT_EQ(size, 4u);

    // ASCII case-insensitive, which is what the resource compiler and
    // the Win32 loader both do.
    std::u16string lower_type = u"customtype";
    std::u16string upper_name = u"MYRESOURCE";
    DUET_RES_KEY type_lc = name_key(lower_type);
    DUET_RES_KEY name_uc = name_key(upper_name);
    EXPECT_TRUE(duet_res_find(&view, &type_lc, &name_uc, 0, 0, &rva, &size) == 1);

    // A named key never matches an integer entry and vice versa.
    DUET_RES_KEY type_as_id = id_key(0x300);
    EXPECT_TRUE(duet_res_find(&view, &type_as_id, &name, 0, 0, &rva, &size) == 0);

    // Prefix must not match.
    std::u16string prefix = u"MyResourc";
    DUET_RES_KEY name_prefix = name_key(prefix);
    EXPECT_TRUE(duet_res_find(&view, &type, &name_prefix, 0, 0, &rva, &size) == 0);
}

void test_language_fallback()
{
    // Only 0x0407 (de-DE) present: an 0x0409 request must still find it
    // through the first-entry fallback, which is what a single-language
    // binary depends on.
    {
        std::vector<uint8_t> image = make_image(false);
        build_chain(image, DUET_RES_TYPE_MANIFEST, 1, {0x0407}, kRsrcRva + kPayload, 8);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        DUET_RES_KEY type = id_key(DUET_RES_TYPE_MANIFEST);
        DUET_RES_KEY name = id_key(1);
        unsigned int rva = 0;
        unsigned int size = 0;
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0x0409, 1, &rva, &size) == 1);
        EXPECT_EQ(size, 8u);
    }

    // Exact match wins over the others: three languages, three distinct
    // payload sizes, so the selected entry is identifiable.
    {
        std::vector<uint8_t> image = make_image(false);
        build_chain(image, DUET_RES_TYPE_MANIFEST, 1, {0x0407, 0x0000, 0x0409}, kRsrcRva + kPayload, 8);
        write_data_entry(image, kDataEntries + 0, kRsrcRva + kPayload, 7);  // de
        write_data_entry(image, kDataEntries + 16, kRsrcRva + kPayload, 5); // neutral
        write_data_entry(image, kDataEntries + 32, kRsrcRva + kPayload, 9); // en-US

        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        DUET_RES_KEY type = id_key(DUET_RES_TYPE_MANIFEST);
        DUET_RES_KEY name = id_key(1);
        unsigned int rva = 0;
        unsigned int size = 0;

        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0x0409, 1, &rva, &size) == 1);
        EXPECT_EQ(size, 9u); // exact
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0x0C0A, 1, &rva, &size) == 1);
        EXPECT_EQ(size, 5u); // LANG_NEUTRAL fallback
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 1);
        EXPECT_EQ(size, 7u); // no language requested -> first entry
    }
}

void test_string_table_indexing()
{
    // The classic bug: string id N lives in bundle (N / 16) + 1 at slot
    // N % 16. Build TWO bundles so an off-by-one in either half of that
    // formula produces a visibly wrong string rather than a near miss.
    //
    //   bundle 1 (name id 1) -> string ids   0..15
    //   bundle 3 (name id 3) -> string ids  32..47
    std::vector<uint8_t> image = make_image(false);

    std::vector<std::u16string> bundle1;
    std::vector<std::u16string> bundle3;
    for (int i = 0; i < 16; ++i)
    {
        bundle1.push_back(u"b1s" + std::u16string(1, static_cast<char16_t>(u'0' + i % 10)));
        bundle3.push_back(u"b3s" + std::u16string(1, static_cast<char16_t>(u'0' + i % 10)));
    }
    bundle1[7] = u"lucky-seven";
    bundle3[0] = u"thirty-two";
    bundle3[15] = u"forty-seven";
    // Slot 3 of bundle 1 is deliberately unused (length 0) — the
    // documented encoding for "this id has no string".
    bundle1[3] = u"";

    constexpr uint32_t kB1 = 0x400;
    constexpr uint32_t kB3 = 0x600;
    const uint32_t b1_len = write_string_bundle(image, kRsrcRva + kB1, bundle1);
    const uint32_t b3_len = write_string_bundle(image, kRsrcRva + kB3, bundle3);

    // Two names under RT_STRING, each with one language.
    write_dir_header(image, kRootDir, 0, 1);
    write_dir_entry(image, kRootDir, 0, DUET_RES_TYPE_STRING, kNameDir, true);
    write_dir_header(image, kNameDir, 0, 2);
    write_dir_entry(image, kNameDir, 0, 1, kLangDir, true);
    write_dir_entry(image, kNameDir, 1, 3, kLangDir + 0x20, true);
    write_dir_header(image, kLangDir, 0, 1);
    write_dir_entry(image, kLangDir, 0, 0x0409, kDataEntries, false);
    write_data_entry(image, kDataEntries, kRsrcRva + kB1, b1_len);
    write_dir_header(image, kLangDir + 0x20, 0, 1);
    write_dir_entry(image, kLangDir + 0x20, 0, 0x0409, kDataEntries + 16, false);
    write_data_entry(image, kDataEntries + 16, kRsrcRva + kB3, b3_len);

    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    const unsigned short* chars = nullptr;
    unsigned int len = 0;

    EXPECT_TRUE(duet_res_find_string(&view, 7, 0x0409, 1, &chars, &len) == 1);
    EXPECT_TRUE(read_back(chars, len) == u"lucky-seven");

    EXPECT_TRUE(duet_res_find_string(&view, 32, 0x0409, 1, &chars, &len) == 1);
    EXPECT_TRUE(read_back(chars, len) == u"thirty-two");

    EXPECT_TRUE(duet_res_find_string(&view, 47, 0x0409, 1, &chars, &len) == 1);
    EXPECT_TRUE(read_back(chars, len) == u"forty-seven");

    // Boundary of bundle 1: id 15 is its last slot, id 16 belongs to
    // bundle 2 which does not exist.
    EXPECT_TRUE(duet_res_find_string(&view, 15, 0x0409, 1, &chars, &len) == 1);
    EXPECT_TRUE(read_back(chars, len) == u"b1s5");
    EXPECT_TRUE(duet_res_find_string(&view, 16, 0x0409, 1, &chars, &len) == 0);
    EXPECT_TRUE(duet_res_find_string(&view, 31, 0x0409, 1, &chars, &len) == 0);

    // Zero-length slot reads as "not found", not as an empty success.
    EXPECT_TRUE(duet_res_find_string(&view, 3, 0x0409, 1, &chars, &len) == 0);

    // id 0 is bundle 1 slot 0 — an easy off-by-one victim.
    EXPECT_TRUE(duet_res_find_string(&view, 0, 0x0409, 1, &chars, &len) == 1);
    EXPECT_TRUE(read_back(chars, len) == u"b1s0");

    // Far-out id lands in a bundle that does not exist.
    EXPECT_TRUE(duet_res_find_string(&view, 0xDEAD, 0x0409, 1, &chars, &len) == 0);
    EXPECT_TRUE(duet_res_find_string(&view, 0xFFFFFFFFu, 0x0409, 1, &chars, &len) == 0);
}

void test_malformed_trees_fail_closed()
{
    DUET_RES_KEY type = id_key(DUET_RES_TYPE_MANIFEST);
    DUET_RES_KEY name = id_key(1);
    unsigned int rva = 0;
    unsigned int size = 0;

    // (a) Level-2 subdirectory offset points past the .rsrc section.
    {
        std::vector<uint8_t> image = make_image(false);
        build_chain(image, DUET_RES_TYPE_MANIFEST, 1, {0}, kRsrcRva + kPayload, 4);
        write_dir_entry(image, kRootDir, 0, DUET_RES_TYPE_MANIFEST, kRsrcBytes, true);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 0);
    }

    // (b) Entry table runs past the section: a directory near the end
    //     claiming 65535 entries.
    {
        std::vector<uint8_t> image = make_image(false);
        build_chain(image, DUET_RES_TYPE_MANIFEST, 1, {0}, kRsrcRva + kPayload, 4);
        const uint32_t late = kRsrcBytes - 0x20;
        write_dir_entry(image, kRootDir, 0, DUET_RES_TYPE_MANIFEST, late, true);
        write_dir_header(image, late, 0, 0xFFFF);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 0);
    }

    // (c) Data entry whose OffsetToData/Size escapes the image.
    {
        std::vector<uint8_t> image = make_image(false);
        build_chain(image, DUET_RES_TYPE_MANIFEST, 1, {0}, kRsrcRva + kPayload, 4);
        write_data_entry(image, kDataEntries, kImageSize - 4, 0x1000);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 0);

        // ...and the integer-overflow shape of the same attack.
        write_data_entry(image, kDataEntries, 0xFFFFFFF0u, 0xFFFFFFF0u);
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 0);
    }

    // (d) Data entry landing in the hole between the mapped header
    //     block and the section — an RVA inside SizeOfImage but inside
    //     no mapped extent. This is the case a plain
    //     "rva + size <= SizeOfImage" check would wave through.
    {
        std::vector<uint8_t> image = make_image(false);
        put32(image, 0x80 + 24 + 60, 0x200); // SizeOfHeaders = 0x200
        build_chain(image, DUET_RES_TYPE_MANIFEST, 1, {0}, 0x800, 4);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 0);

        // The same RVA inside the header block IS mapped, so the walk
        // must succeed there — otherwise this test would pass for the
        // wrong reason (an unconditional reject).
        write_data_entry(image, kDataEntries, 0x100, 4);
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 1);
        EXPECT_EQ(rva, 0x100u);
    }

    // (e) Self-referential subdirectory: level 1 points at itself. The
    //     walk is three flat levels, so this terminates — it must not
    //     hang and must not report a hit.
    {
        std::vector<uint8_t> image = make_image(false);
        write_dir_header(image, kRootDir, 0, 1);
        write_dir_entry(image, kRootDir, 0, DUET_RES_TYPE_MANIFEST, kRootDir, true);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        DUET_RES_KEY self_name = id_key(DUET_RES_TYPE_MANIFEST);
        EXPECT_TRUE(duet_res_find(&view, &type, &self_name, 0, 0, &rva, &size) == 0);
    }

    // (f) IMAGE_RESOURCE_DIR_STRING_U with a length that runs past the
    //     section.
    {
        std::vector<uint8_t> image = make_image(false);
        const uint32_t str_off = kRsrcBytes - 0x10;
        put16(image, kRsrcRva + str_off, 0xFFFF);
        write_dir_header(image, kRootDir, 1, 0);
        write_dir_entry(image, kRootDir, 0, str_off | 0x80000000u, kNameDir, true);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        std::u16string wanted = u"anything";
        DUET_RES_KEY named = name_key(wanted);
        EXPECT_TRUE(duet_res_find(&view, &named, &name, 0, 0, &rva, &size) == 0);
    }

    // (g) String bundle whose counted length runs past the resource.
    {
        std::vector<uint8_t> image = make_image(false);
        build_chain(image, DUET_RES_TYPE_STRING, 1, {0}, kRsrcRva + kPayload, 8);
        put16(image, kRsrcRva + kPayload, 0xFFFF); // slot 0 claims 65535 chars
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        const unsigned short* chars = nullptr;
        unsigned int len = 0;
        EXPECT_TRUE(duet_res_find_string(&view, 0, 0, 0, &chars, &len) == 0);
        EXPECT_TRUE(duet_res_find_string(&view, 5, 0, 0, &chars, &len) == 0);
    }

    // (h) Level-3 entry marked as a subdirectory rather than data. The
    //     format has no fourth level, so it is skipped, not walked.
    {
        std::vector<uint8_t> image = make_image(false);
        build_chain(image, DUET_RES_TYPE_MANIFEST, 1, {0}, kRsrcRva + kPayload, 4);
        write_dir_entry(image, kLangDir, 0, 0, kLangDir, true);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(duet_res_find(&view, &type, &name, 0, 0, &rva, &size) == 0);
    }
}

void test_enumeration_surface()
{
    // EnumResourceTypesW / EnumResourceNamesW are built out of
    // duet_res_dir_count + duet_res_dir_entry; check they agree with
    // what duet_res_find resolves.
    std::vector<uint8_t> image = make_image(false);
    constexpr uint32_t kNameStr = 0x340;
    write_dir_string(image, kNameStr, u"NamedOne");

    write_dir_header(image, kRootDir, 0, 2);
    write_dir_entry(image, kRootDir, 0, DUET_RES_TYPE_STRING, kNameDir, true);
    write_dir_entry(image, kRootDir, 1, DUET_RES_TYPE_MANIFEST, kNameDir + 0x40, true);
    // RT_STRING subtree: one named + one integer entry.
    write_dir_header(image, kNameDir, 1, 1);
    write_dir_entry(image, kNameDir, 0, kNameStr | 0x80000000u, kLangDir, true);
    write_dir_entry(image, kNameDir, 1, 42, kLangDir, true);
    write_dir_header(image, kLangDir, 0, 1);
    write_dir_entry(image, kLangDir, 0, 0, kDataEntries, false);
    write_data_entry(image, kDataEntries, kRsrcRva + kPayload, 4);
    write_dir_header(image, kNameDir + 0x40, 0, 0);

    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    unsigned int named = 0;
    EXPECT_EQ(duet_res_dir_count(&view, 0, &named), 2u);
    EXPECT_EQ(named, 0u);

    DUET_RES_KEY type = id_key(DUET_RES_TYPE_STRING);
    unsigned int type_dir = 0;
    int is_dir = 0;
    REQUIRE(duet_res_lookup(&view, 0, &type, &type_dir, &is_dir) == 1);
    EXPECT_TRUE(is_dir == 1);

    EXPECT_EQ(duet_res_dir_count(&view, type_dir, &named), 2u);
    EXPECT_EQ(named, 1u);

    // Entry 0 is the named one (the format requires named entries to
    // sort before integer entries).
    DUET_RES_KEY got{};
    unsigned int child = 0;
    REQUIRE(duet_res_dir_entry(&view, type_dir, 0, &got, &child, &is_dir) == 1);
    EXPECT_TRUE(got.by_name == 1);
    EXPECT_EQ(got.name_len, 8u);
    EXPECT_TRUE(read_back(got.name, got.name_len) == u"NamedOne");

    REQUIRE(duet_res_dir_entry(&view, type_dir, 1, &got, &child, &is_dir) == 1);
    EXPECT_TRUE(got.by_name == 0);
    EXPECT_EQ(got.id, 42u);

    // duet_res_dir_entry's gate is spatial, not semantic: index 2 is
    // past the declared entry count but still inside the section, so it
    // decodes zero bytes rather than failing. Callers must bound their
    // loop with duet_res_dir_count — which is exactly what
    // duet_res_lookup and the EnumResource* thunks do. An index whose
    // byte offset would overflow is rejected outright.
    EXPECT_TRUE(duet_res_dir_entry(&view, type_dir, 2, &got, &child, &is_dir) == 1);
    EXPECT_TRUE(duet_res_dir_entry(&view, type_dir, 0xFFFFFFFFu, &got, &child, &is_dir) == 0);
    // An index far enough out to leave the section fails.
    EXPECT_TRUE(duet_res_dir_entry(&view, type_dir, kRsrcBytes / 8, &got, &child, &is_dir) == 0);

    // An empty subtree enumerates as zero entries.
    DUET_RES_KEY manifest = id_key(DUET_RES_TYPE_MANIFEST);
    unsigned int empty_dir = 0;
    REQUIRE(duet_res_lookup(&view, 0, &manifest, &empty_dir, &is_dir) == 1);
    EXPECT_EQ(duet_res_dir_count(&view, empty_dir, &named), 0u);
}

} // namespace

int main()
{
    test_init_accepts_both_bitnesses();
    test_init_rejects_garbage();
    test_three_level_walk_by_id();
    test_named_entries_and_case_fold();
    test_language_fallback();
    test_string_table_indexing();
    test_malformed_trees_fail_closed();
    test_enumeration_surface();
    return finish_main("pe_resources");
}
