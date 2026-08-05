// test_pe_named_resources.cpp — hosted unit test for name-STRING
// (UTF-16) `.rsrc` directory entries, the shape LoadIcon / LoadCursor /
// LoadBitmap / LoadImage need in order to accept a `.rc` resource
// declared by name rather than by MAKEINTRESOURCE ordinal.
//
// Covers the key-taking half of userland/libs/common/pe_resources.h:
//   - duet_res_key_id / duet_res_key_name / duet_res_name_len
//   - duet_res_pick_icon_key over a named RT_GROUP_ICON, including the
//     ASCII case-insensitive fold the resource compiler applies
//   - duet_res_bitmap_info_key / duet_res_decode_bitmap_key over a
//     named RT_BITMAP, pixels verified against the authored palette
//   - the integer-ordinal wrappers still resolving the ID entries of a
//     directory that ALSO holds named entries (the regression that
//     matters: routing the string path must not disturb ordinals)
//   - the two keys never crossing: the string "7" must not match
//     ordinal 7, and ordinal 7 must not match a named entry
//   - hostile IMAGE_RESOURCE_DIR_STRING_U forms failing CLOSED — a
//     Length that runs past the resource section, a string offset past
//     the directory extent, and a "canary" name that is inside the
//     buffer but OUTSIDE the section extent the kernel mapped. The
//     canary is the load-bearing one: it proves the bound enforced is
//     the mapped extent and not merely the host allocation, which a
//     plain out-of-range read would not distinguish.
//
// The images are synthesised here rather than produced by windres for
// the same reason test_pe_resources.cpp synthesises its own: windres
// will not emit a directory string that points outside its section.
//
// Expected behaviour is pinned to the PE/COFF specification section 6.9
// ("The .rsrc Section") and the documented LoadImage / MAKEINTRESOURCE
// contract. Added 2026-08-05 for the named-resource slice.

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
// Synthetic image layout
// ------------------------------------------------------------------
//
//   RVA 0x0000  headers (DOS stub, NT headers, one section header)
//   RVA 0x1000  ".rsrc", kRsrcRaw bytes on disk
//
// The buffer IS the mapped view (RVA == buffer offset), which is what
// the kernel's MapSection produces when SectionAlignment ==
// FileAlignment == 0x1000. Resource-directory offsets below are
// therefore .rsrc-relative and the payload RVAs are absolute.

constexpr uint32_t kHeadersSize = 0x1000;
constexpr uint32_t kRsrcRva = 0x1000;
constexpr uint32_t kRsrcRaw = 0x1000;
constexpr uint32_t kImageSize = kRsrcRva + kRsrcRaw;

// .rsrc-relative directory offsets.
constexpr uint32_t kRootDir = 0x000;
constexpr uint32_t kIconNameDir = 0x040;
constexpr uint32_t kIconLangDir = 0x080;
constexpr uint32_t kIconData = 0x0A0;
constexpr uint32_t kMemberNameDir = 0x0C0;
constexpr uint32_t kMemberLangDir = 0x100;
constexpr uint32_t kMemberData = 0x120;
constexpr uint32_t kBmpNameDir = 0x140;
constexpr uint32_t kBmpLangDir = 0x180;
constexpr uint32_t kBmpData = 0x1A0;
constexpr uint32_t kIconNameStr = 0x1C0; // "MyIcon"
constexpr uint32_t kBmpNameStr = 0x1E0;  // "MyBitmap"
constexpr uint32_t kCanaryStr = 0x500;   // outside the shrunken extent
constexpr uint32_t kGroupPayload = 0x200;
constexpr uint32_t kIconPayload = 0x240;
constexpr uint32_t kBmpPayload = 0x300;

// The RT_ICON member the group points at, and the ordinals that live
// alongside the named entries in the same directories.
constexpr uint16_t kIconMemberId = 101;
constexpr uint32_t kIconOrdinal = 7;
constexpr uint32_t kBmpOrdinal = 9;
constexpr uint32_t kDim = 4; // icon and bitmap are both 4x4

void put16(std::vector<uint8_t>& b, size_t off, uint16_t v)
{
    b[off] = static_cast<uint8_t>(v & 0xFFu);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
}

void put32(std::vector<uint8_t>& b, size_t off, uint32_t v)
{
    for (uint32_t i = 0; i < 4; ++i)
        b[off + static_cast<size_t>(i)] = static_cast<uint8_t>((v >> (8u * i)) & 0xFFu);
}

// `rsrc_extent` becomes both VirtualSize and SizeOfRawData, so it is
// exactly the span duet_res_mapped_span_from will compute — that is the
// knob the canary test turns.
std::vector<uint8_t> make_image(uint32_t rsrc_extent = kRsrcRaw)
{
    std::vector<uint8_t> image(kImageSize, 0);

    constexpr uint32_t kLfanew = 0x80;
    image[0] = 'M';
    image[1] = 'Z';
    put32(image, 0x3C, kLfanew);

    image[kLfanew + 0] = 'P';
    image[kLfanew + 1] = 'E';
    put16(image, kLfanew + 4, 0x8664); // Machine
    put16(image, kLfanew + 6, 1);      // NumberOfSections

    constexpr uint16_t kOptionalSize = 240; // PE32+
    put16(image, kLfanew + 20, kOptionalSize);

    constexpr size_t opt = kLfanew + 24;
    put16(image, opt + 0, 0x020B);
    put32(image, opt + 56, kImageSize);
    put32(image, opt + 60, kHeadersSize);

    constexpr size_t dd = opt + 112;
    put32(image, dd - 4, 16); // NumberOfRvaAndSizes
    put32(image, dd + 2 * 8 + 0, kRsrcRva);
    put32(image, dd + 2 * 8 + 4, rsrc_extent);

    constexpr size_t sec = opt + kOptionalSize;
    const char name[8] = {'.', 'r', 's', 'r', 'c', 0, 0, 0};
    for (uint32_t i = 0; i < 8; ++i)
        image[sec + static_cast<size_t>(i)] = static_cast<uint8_t>(name[i]);
    put32(image, sec + 8, rsrc_extent);  // VirtualSize
    put32(image, sec + 12, kRsrcRva);    // VirtualAddress
    put32(image, sec + 16, rsrc_extent); // SizeOfRawData
    put32(image, sec + 20, kRsrcRva);    // PointerToRawData
    put32(image, sec + 36, 0x40000040);  // INITIALIZED_DATA | MEM_READ
    return image;
}

// --- directory writers (offsets are .rsrc-relative) ---------------

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
    const size_t off = kRsrcRva + dir_off + 16 + index * 8;
    put32(image, off, name);
    put32(image, off + 4, is_dir ? (child | 0x80000000u) : child);
}

void write_data_entry(std::vector<uint8_t>& image, uint32_t off, uint32_t data_rva, uint32_t size)
{
    put32(image, kRsrcRva + off, data_rva);
    put32(image, kRsrcRva + off + 4, size);
}

// IMAGE_RESOURCE_DIR_STRING_U at .rsrc-relative `off`: u16 Length, then
// Length UTF-16 code units, NOT NUL-terminated. `declared_len` overrides
// the honest length so the hostile cases can lie about it.
void write_dir_string(std::vector<uint8_t>& image, uint32_t off, const std::u16string& s, uint16_t declared_len)
{
    put16(image, kRsrcRva + off, declared_len);
    for (size_t i = 0; i < s.size(); ++i)
        put16(image, kRsrcRva + off + 2 + i * 2, static_cast<uint16_t>(s[i]));
}

void write_dir_string(std::vector<uint8_t>& image, uint32_t off, const std::u16string& s)
{
    write_dir_string(image, off, s, static_cast<uint16_t>(s.size()));
}

// --- payload writers ----------------------------------------------

// NEWHEADER + one GRPICONDIRENTRY. Returns bytes written.
uint32_t write_group_icon(std::vector<uint8_t>& image, uint32_t rva, uint8_t dim, uint16_t icon_id)
{
    put16(image, rva + 0, 0);  // idReserved
    put16(image, rva + 2, 1);  // idType == icon
    put16(image, rva + 4, 1);  // idCount
    image[rva + 6] = dim;      // bWidth
    image[rva + 7] = dim;      // bHeight
    image[rva + 8] = 0;        // bColorCount
    image[rva + 9] = 0;        // bReserved
    put16(image, rva + 10, 1); // wPlanes
    put16(image, rva + 12, 32);
    put32(image, rva + 14, 0); // dwBytesInRes
    put16(image, rva + 18, icon_id);
    return 20;
}

// BITMAPINFOHEADER + 32bpp XOR rows + an all-zero (opaque) AND mask.
// Every XOR pixel is B=0x10 G=0x20 R=0x30 A=0xFF.
uint32_t write_icon_body_32bpp(std::vector<uint8_t>& image, uint32_t rva, uint32_t dim)
{
    constexpr uint32_t kHeader = 40;
    const uint32_t xor_stride = dim * 4;
    const uint32_t and_stride = ((dim + 31u) / 32u) * 4u;

    put32(image, rva + 0, kHeader);
    put32(image, rva + 4, dim);
    put32(image, rva + 8, dim * 2u); // XOR height + AND height
    put16(image, rva + 12, 1);       // biPlanes
    put16(image, rva + 14, 32);      // biBitCount
    put32(image, rva + 16, 0);       // biCompression == BI_RGB
    put32(image, rva + 20, 0);       // biSizeImage
    put32(image, rva + 24, 0);
    put32(image, rva + 28, 0);
    put32(image, rva + 32, 0); // biClrUsed
    put32(image, rva + 36, 0);

    for (uint32_t y = 0; y < dim; ++y)
    {
        const size_t row = rva + kHeader + static_cast<size_t>(y) * xor_stride;
        for (uint32_t x = 0; x < dim; ++x)
        {
            const size_t px = row + static_cast<size_t>(x) * 4u;
            image[px + 0] = 0x10; // B
            image[px + 1] = 0x20; // G
            image[px + 2] = 0x30; // R
            image[px + 3] = 0xFF; // A
        }
    }
    // The AND mask stays zero (fully opaque) — the buffer starts zeroed.
    return kHeader + dim * xor_stride + dim * and_stride;
}

// A packed DIB: BITMAPINFOHEADER + a 4-entry BGRX colour table + 8bpp
// bottom-up rows whose palette index is (x + y) % 4.
uint32_t write_packed_dib_8bpp(std::vector<uint8_t>& image, uint32_t rva, uint32_t w, uint32_t h)
{
    constexpr uint32_t kHeader = 40;
    constexpr uint32_t kPaletteEntries = 4;
    const uint32_t stride = ((w * 8u + 31u) / 32u) * 4u;

    put32(image, rva + 0, kHeader);
    put32(image, rva + 4, w);
    put32(image, rva + 8, h); // positive == bottom-up rows
    put16(image, rva + 12, 1);
    put16(image, rva + 14, 8);
    put32(image, rva + 16, 0); // BI_RGB
    put32(image, rva + 20, 0);
    put32(image, rva + 24, 0);
    put32(image, rva + 28, 0);
    put32(image, rva + 32, kPaletteEntries); // biClrUsed
    put32(image, rva + 36, 0);

    // Colour table, BGRX quads: black, blue, green, red.
    static const uint8_t kPalette[kPaletteEntries][4] = {
        {0x00, 0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00, 0x00}, {0x00, 0xFF, 0x00, 0x00}, {0x00, 0x00, 0xFF, 0x00}};
    for (uint32_t i = 0; i < kPaletteEntries; ++i)
    {
        for (uint32_t c = 0; c < 4; ++c)
            image[rva + kHeader + static_cast<size_t>(i) * 4u + c] = kPalette[i][c];
    }

    const uint32_t pixels = rva + kHeader + kPaletteEntries * 4u;
    for (uint32_t y = 0; y < h; ++y)
    {
        for (uint32_t x = 0; x < w; ++x)
            image[pixels + static_cast<size_t>(y) * stride + x] = static_cast<uint8_t>((x + y) % 4u);
    }
    return kHeader + kPaletteEntries * 4u + stride * h;
}

// ------------------------------------------------------------------
// The full tree
// ------------------------------------------------------------------
//
// Root: three ID entries (RT_GROUP_ICON, RT_ICON, RT_BITMAP).
// The group-icon and bitmap name directories each hold a named entry
// AND an ID entry, both resolving to the same payload — that is what
// makes "ordinals still work next to names" a real assertion rather
// than two independent fixtures.
std::vector<uint8_t> build_named_tree(uint32_t rsrc_extent = kRsrcRaw)
{
    std::vector<uint8_t> image = make_image(rsrc_extent);

    const uint32_t group_bytes =
        write_group_icon(image, kRsrcRva + kGroupPayload, static_cast<uint8_t>(kDim), kIconMemberId);
    const uint32_t icon_bytes = write_icon_body_32bpp(image, kRsrcRva + kIconPayload, kDim);
    const uint32_t bmp_bytes = write_packed_dib_8bpp(image, kRsrcRva + kBmpPayload, kDim, kDim);

    write_dir_string(image, kIconNameStr, u"MyIcon");
    write_dir_string(image, kBmpNameStr, u"MyBitmap");

    write_dir_header(image, kRootDir, 0, 3);
    write_dir_entry(image, kRootDir, 0, DUET_RES_TYPE_GROUP_ICON, kIconNameDir, true);
    write_dir_entry(image, kRootDir, 1, DUET_RES_TYPE_ICON, kMemberNameDir, true);
    write_dir_entry(image, kRootDir, 2, DUET_RES_TYPE_BITMAP, kBmpNameDir, true);

    // RT_GROUP_ICON: named "MyIcon" first (spec order), then ordinal 7.
    write_dir_header(image, kIconNameDir, 1, 1);
    write_dir_entry(image, kIconNameDir, 0, kIconNameStr | DUET_RES_HIGH_BIT, kIconLangDir, true);
    write_dir_entry(image, kIconNameDir, 1, kIconOrdinal, kIconLangDir, true);
    write_dir_header(image, kIconLangDir, 0, 1);
    write_dir_entry(image, kIconLangDir, 0, 0, kIconData, false);
    write_data_entry(image, kIconData, kRsrcRva + kGroupPayload, group_bytes);

    // RT_ICON member: always an integer nID by format definition.
    write_dir_header(image, kMemberNameDir, 0, 1);
    write_dir_entry(image, kMemberNameDir, 0, kIconMemberId, kMemberLangDir, true);
    write_dir_header(image, kMemberLangDir, 0, 1);
    write_dir_entry(image, kMemberLangDir, 0, 0, kMemberData, false);
    write_data_entry(image, kMemberData, kRsrcRva + kIconPayload, icon_bytes);

    // RT_BITMAP: named "MyBitmap" and ordinal 9.
    write_dir_header(image, kBmpNameDir, 1, 1);
    write_dir_entry(image, kBmpNameDir, 0, kBmpNameStr | DUET_RES_HIGH_BIT, kBmpLangDir, true);
    write_dir_entry(image, kBmpNameDir, 1, kBmpOrdinal, kBmpLangDir, true);
    write_dir_header(image, kBmpLangDir, 0, 1);
    write_dir_entry(image, kBmpLangDir, 0, 0, kBmpData, false);
    write_data_entry(image, kBmpData, kRsrcRva + kBmpPayload, bmp_bytes);

    return image;
}

// Wraps a u16 literal so a key can be built from it without the caller
// juggling the reinterpret_cast on every line.
//
// This takes the literal directly rather than a std::u16string: a
// DUET_RES_KEY only borrows the characters, so building one from a
// temporary string would leave it pointing at freed storage the moment
// the full expression ended. A u16 string literal has static storage
// duration, so the key stays valid for as long as the test needs it.
DUET_RES_KEY key_of(const char16_t* s)
{
    unsigned int n = 0;
    while (s[n] != 0)
        ++n;
    return duet_res_key_name(reinterpret_cast<const unsigned short*>(s), n);
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

void test_key_constructors()
{
    const DUET_RES_KEY id = duet_res_key_id(42);
    EXPECT_EQ(id.by_name, 0);
    EXPECT_EQ(id.id, 42u);
    EXPECT_EQ(id.name_len, 0u);
    EXPECT_TRUE(id.name == nullptr);

    static const unsigned short kName[] = {'A', 'b', 'C', 0};
    EXPECT_EQ(duet_res_name_len(kName), 3u);
    EXPECT_EQ(duet_res_name_len(nullptr), 0u);

    const DUET_RES_KEY named = duet_res_key_name(kName, duet_res_name_len(kName));
    EXPECT_EQ(named.by_name, 1);
    EXPECT_EQ(named.name_len, 3u);
    EXPECT_EQ(named.id, 0u);

    // A null name never claims a length, so duet_res_key_equal can't be
    // tricked into dereferencing it.
    const DUET_RES_KEY empty = duet_res_key_name(nullptr, 9);
    EXPECT_EQ(empty.name_len, 0u);
}

void test_named_icon_lookup()
{
    std::vector<uint8_t> image = build_named_tree();
    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    unsigned int icon_id = 0;
    unsigned int w = 0;
    unsigned int h = 0;
    DUET_RES_KEY name = key_of(u"MyIcon");
    REQUIRE(duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &name, kDim, kDim, &icon_id, &w, &h) == 1);
    EXPECT_EQ(icon_id, static_cast<unsigned int>(kIconMemberId));
    EXPECT_EQ(w, kDim);
    EXPECT_EQ(h, kDim);

    // The fold is ASCII case-insensitive, matching the resource
    // compiler and the Win32 loader.
    for (const char16_t* spelling : {u"myicon", u"MYICON", u"mYiCoN"})
    {
        DUET_RES_KEY folded = key_of(spelling);
        unsigned int got = 0;
        EXPECT_TRUE(
            duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &folded, kDim, kDim, &got, nullptr, nullptr) == 1);
        EXPECT_EQ(got, static_cast<unsigned int>(kIconMemberId));
    }

    // Near misses must not resolve: a prefix, a suffix, and a name that
    // differs only past the authored length.
    for (const char16_t* miss : {u"MyIco", u"MyIcons", u"XyIcon", u""})
    {
        DUET_RES_KEY bad = key_of(miss);
        unsigned int got = 0;
        EXPECT_TRUE(duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &bad, kDim, kDim, &got, nullptr, nullptr) ==
                    0);
    }

    // A NULL key is rejected rather than dereferenced.
    EXPECT_TRUE(
        duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, nullptr, kDim, kDim, &icon_id, nullptr, nullptr) == 0);
}

void test_ordinals_still_resolve_alongside_names()
{
    std::vector<uint8_t> image = build_named_tree();
    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    // The integer wrapper reaches the ID entry that shares the
    // directory with the named one.
    unsigned int icon_id = 0;
    REQUIRE(duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_ICON, kIconOrdinal, kDim, kDim, &icon_id, nullptr, nullptr) ==
            1);
    EXPECT_EQ(icon_id, static_cast<unsigned int>(kIconMemberId));

    unsigned int bw = 0;
    unsigned int bh = 0;
    unsigned int bpp = 0;
    REQUIRE(duet_res_bitmap_info(&view, kBmpOrdinal, &bw, &bh, &bpp) == 1);
    EXPECT_EQ(bw, kDim);
    EXPECT_EQ(bh, kDim);
    EXPECT_EQ(bpp, 8u);

    // An ordinal that is not present still misses.
    EXPECT_TRUE(duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_ICON, 8, kDim, kDim, &icon_id, nullptr, nullptr) == 0);
}

void test_key_kinds_never_cross()
{
    std::vector<uint8_t> image = build_named_tree();
    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    // The STRING "7" is not the ORDINAL 7 — duet_res_key_equal compares
    // by_name first, so a decimal spelling can never alias an ordinal.
    DUET_RES_KEY digits = key_of(u"7");
    unsigned int got = 0;
    EXPECT_TRUE(duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &digits, kDim, kDim, &got, nullptr, nullptr) ==
                0);

    // ...and the ordinal form of the .rsrc string offset must not reach
    // the named entry either. kIconNameStr is the offset the named
    // entry stores; as a bare ordinal it names nothing.
    EXPECT_TRUE(duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_ICON, kIconNameStr, kDim, kDim, &got, nullptr, nullptr) ==
                0);
}

void test_named_bitmap_decode()
{
    std::vector<uint8_t> image = build_named_tree();
    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    DUET_RES_KEY name = key_of(u"mybitmap"); // lowercase on purpose
    unsigned int w = 0;
    unsigned int h = 0;
    unsigned int bpp = 0;
    REQUIRE(duet_res_bitmap_info_key(&view, &name, &w, &h, &bpp) == 1);
    EXPECT_EQ(w, kDim);
    EXPECT_EQ(h, kDim);
    EXPECT_EQ(bpp, 8u);

    unsigned char bgra[kDim * kDim * 4] = {};
    REQUIRE(duet_res_decode_bitmap_key(&view, &name, bgra, kDim * kDim, &w, &h) == 1);
    EXPECT_EQ(w, kDim);
    EXPECT_EQ(h, kDim);

    // Source rows are bottom-up, so authored row y lands at output row
    // (kDim - 1 - y). Palette index (x + y) % 4 maps to
    // black / blue / green / red.
    static const uint8_t kExpect[4][3] = {
        {0x00, 0x00, 0x00}, {0xFF, 0x00, 0x00}, {0x00, 0xFF, 0x00}, {0x00, 0x00, 0xFF}};
    for (uint32_t y = 0; y < kDim; ++y)
    {
        for (uint32_t x = 0; x < kDim; ++x)
        {
            const uint32_t dst_y = kDim - 1u - y;
            const size_t px = (static_cast<size_t>(dst_y) * kDim + x) * 4u;
            const uint8_t idx = static_cast<uint8_t>((x + y) % 4u);
            EXPECT_EQ(bgra[px + 0], kExpect[idx][0]);
            EXPECT_EQ(bgra[px + 1], kExpect[idx][1]);
            EXPECT_EQ(bgra[px + 2], kExpect[idx][2]);
            EXPECT_EQ(bgra[px + 3], 0xFFu); // RT_BITMAP alpha is forced opaque
        }
    }

    // A named bitmap that does not exist fails closed, and so does a
    // buffer too small for the decode.
    DUET_RES_KEY missing = key_of(u"NoSuchBitmap");
    EXPECT_TRUE(duet_res_bitmap_info_key(&view, &missing, &w, &h, &bpp) == 0);
    EXPECT_TRUE(duet_res_decode_bitmap_key(&view, &name, bgra, kDim * kDim - 1u, nullptr, nullptr) == 0);
    EXPECT_TRUE(duet_res_bitmap_info_key(&view, nullptr, &w, &h, &bpp) == 0);
}

void test_named_group_reaches_icon_body()
{
    // The whole point of the named path: a by-name LoadIcon must still
    // land on the RT_ICON member and decode real pixels.
    std::vector<uint8_t> image = build_named_tree();
    DUET_RES_VIEW view{};
    REQUIRE(duet_res_init(image.data(), &view) == 1);

    DUET_RES_KEY name = key_of(u"MyIcon");
    unsigned int icon_id = 0;
    unsigned int w = 0;
    unsigned int h = 0;
    REQUIRE(duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &name, kDim, kDim, &icon_id, &w, &h) == 1);

    unsigned char bgra[kDim * kDim * 4] = {};
    REQUIRE(duet_res_decode_icon(&view, DUET_RES_TYPE_ICON, icon_id, w, h, bgra, kDim * kDim, nullptr, nullptr) == 1);
    for (uint32_t i = 0; i < kDim * kDim; ++i)
    {
        EXPECT_EQ(bgra[i * 4 + 0], 0x10u);
        EXPECT_EQ(bgra[i * 4 + 1], 0x20u);
        EXPECT_EQ(bgra[i * 4 + 2], 0x30u);
        EXPECT_EQ(bgra[i * 4 + 3], 0xFFu); // AND mask is all-zero == opaque
    }
}

void test_hostile_name_strings_fail_closed()
{
    DUET_RES_KEY name = key_of(u"MyIcon");
    unsigned int got = 0;

    // 1. A Length that runs past the resource section. The honest
    //    string is six characters; the header claims 0x8000, whose
    //    character array would leave the section entirely.
    {
        std::vector<uint8_t> image = build_named_tree();
        write_dir_string(image, kIconNameStr, u"MyIcon", 0x8000);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(
            duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &name, kDim, kDim, &got, nullptr, nullptr) == 0);
    }

    // 2. A Length whose byte count would wrap a u32 (0xFFFF chars is
    //    the widest a u16 can state, so the overflow guard is exercised
    //    by the multiply rather than the field).
    {
        std::vector<uint8_t> image = build_named_tree();
        write_dir_string(image, kIconNameStr, u"MyIcon", 0xFFFF);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(
            duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &name, kDim, kDim, &got, nullptr, nullptr) == 0);
    }

    // 3. A name-string offset past the directory extent altogether.
    {
        std::vector<uint8_t> image = build_named_tree();
        write_dir_entry(image, kIconNameDir, 0, (kRsrcRaw + 0x10u) | DUET_RES_HIGH_BIT, kIconLangDir, true);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(
            duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &name, kDim, kDim, &got, nullptr, nullptr) == 0);
    }

    // 4. The canary. The section extent is shrunk to 0x400, but the
    //    buffer still holds the bytes past it, and a perfectly
    //    well-formed "Canary" string is written at 0x500 with an entry
    //    pointing at it. A walker that bounded reads by the allocation
    //    rather than by the mapped extent would MATCH here. Failing to
    //    match is the assertion.
    {
        std::vector<uint8_t> image = build_named_tree(0x400);
        write_dir_string(image, kCanaryStr, u"Canary");
        write_dir_entry(image, kIconNameDir, 0, kCanaryStr | DUET_RES_HIGH_BIT, kIconLangDir, true);
        DUET_RES_VIEW view{};
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_EQ(view.dir_span, 0x400u);

        DUET_RES_KEY canary = key_of(u"Canary");
        EXPECT_TRUE(
            duet_res_pick_icon_key(&view, DUET_RES_TYPE_GROUP_ICON, &canary, kDim, kDim, &got, nullptr, nullptr) == 0);

        // ...and the same tree still resolves the ordinal that lives
        // inside the extent, so the canary failed for the right reason
        // (the bound) and not because the fixture was broken.
        //
        // duet_res_lookup fails closed on the FIRST unreadable entry,
        // so the ordinal is only reachable once the poisoned named
        // entry is put back in bounds.
        write_dir_entry(image, kIconNameDir, 0, kIconNameStr | DUET_RES_HIGH_BIT, kIconLangDir, true);
        REQUIRE(duet_res_init(image.data(), &view) == 1);
        EXPECT_TRUE(
            duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_ICON, kIconOrdinal, kDim, kDim, &got, nullptr, nullptr) == 1);
    }
}

} // namespace

int main()
{
    test_key_constructors();
    test_named_icon_lookup();
    test_ordinals_still_resolve_alongside_names();
    test_key_kinds_never_cross();
    test_named_bitmap_decode();
    test_named_group_reaches_icon_body();
    test_hostile_name_strings_fail_closed();
    return finish_main("pe_named_resources");
}
