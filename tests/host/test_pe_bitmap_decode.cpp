// test_pe_bitmap_decode.cpp — hosted unit test for the RT_BITMAP
// resource decoder functions in pe_resources.h:
//   - duet_res_bitmap_info (geometry query without decoding)
//   - duet_res_decode_bitmap (packed DIB -> top-down opaque BGRA)
//
// Uses a synthetic PE image with a hand-crafted RT_BITMAP (type 2)
// resource, so each byte is under test control. The windres-produced
// variant is exercised by bitmap_smoke.exe at boot.

#include "host_test_helper.h"

#include "../../userland/libs/common/pe_resources.h"

#include <cstdint>
#include <cstring>
#include <vector>

using namespace duetos_host_test;

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
// Synthetic image builder (same skeleton as test_pe_icon_decode.cpp)
// ------------------------------------------------------------------

constexpr uint32_t kHeadersSize = 0x1000;
constexpr uint32_t kRsrcRva = 0x1000;
constexpr uint32_t kRsrcBytes = 0x2000;
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

std::vector<uint8_t> make_image()
{
    std::vector<uint8_t> image(kImageSize, 0);

    constexpr uint32_t kLfanew = 0x80;
    image[0] = 'M';
    image[1] = 'Z';
    put32(image, 0x3C, kLfanew);

    image[kLfanew + 0] = 'P';
    image[kLfanew + 1] = 'E';
    put16(image, kLfanew + 4, 0x8664); // Machine (x86_64 / PE32+)
    put16(image, kLfanew + 6, 1);      // NumberOfSections

    const uint16_t optional_size = 240; // PE32+ optional header
    put16(image, kLfanew + 20, optional_size);

    const size_t opt = kLfanew + 24;
    put16(image, opt + 0, 0x020B);        // PE32+ magic
    put32(image, opt + 56, kImageSize);   // SizeOfImage
    put32(image, opt + 60, kHeadersSize); // SizeOfHeaders

    const size_t dd = opt + 112; // DataDirectory for PE32+
    put32(image, dd - 4, 16);    // NumberOfRvaAndSizes
    put32(image, dd + 2 * 8 + 0, kRsrcRva);
    put32(image, dd + 2 * 8 + 4, kRsrcBytes);

    const size_t sec = opt + optional_size;
    const char name[8] = {'.', 'r', 's', 'r', 'c', 0, 0, 0};
    for (int i = 0; i < 8; ++i)
        image[sec + static_cast<size_t>(i)] = static_cast<uint8_t>(name[i]);
    put32(image, sec + 8, kRsrcBytes);  // VirtualSize
    put32(image, sec + 12, kRsrcRva);   // VirtualAddress
    put32(image, sec + 16, kRsrcBytes); // SizeOfRawData
    put32(image, sec + 20, kRsrcRva);   // PointerToRawData
    put32(image, sec + 36, 0x40000040); // INITIALIZED_DATA | MEM_READ
    return image;
}

void write_dir_header(std::vector<uint8_t>& image, uint32_t off, uint16_t named, uint16_t ids)
{
    put16(image, kRsrcRva + off + 12, named);
    put16(image, kRsrcRva + off + 14, ids);
}

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

// Build the three-level tree for one RT_BITMAP (type 2), id 1, lang 0,
// whose body lives at rsrc + 0x100 and spans `body_size` bytes:
//
// Off 0x000: root dir (1 id entry: type 2)
// Off 0x020: type-2 dir (1 id entry: id=1)
// Off 0x038: type-2/id-1 lang dir (1 entry: lang=0)
// Off 0x050: type-2/id-1/lang-0 data entry -> DIB body
//
std::vector<uint8_t> make_bitmap_image(uint32_t body_size)
{
    auto image = make_image();
    write_dir_header(image, 0x000, 0, 1);
    write_dir_entry(image, 0x000, 0, 2, 0x020, true); // RT_BITMAP -> sub at 0x020
    write_dir_header(image, 0x020, 0, 1);
    write_dir_entry(image, 0x020, 0, 1, 0x038, true); // id=1 -> lang dir
    write_dir_header(image, 0x038, 0, 1);
    write_dir_entry(image, 0x038, 0, 0, 0x050, false); // lang=0 -> data entry
    write_data_entry(image, 0x050, kRsrcRva + 0x100, body_size);
    return image;
}

// The DIB body base inside every make_bitmap_image() result.
constexpr size_t kBodyBase = kRsrcRva + 0x100;

// Writes a 40-byte BITMAPINFOHEADER at kBodyBase.
void write_bih(std::vector<uint8_t>& image, uint32_t w, int32_t h, uint16_t bpp, uint32_t clr_used)
{
    put32(image, kBodyBase + 0, 40);
    put32(image, kBodyBase + 4, w);
    put32(image, kBodyBase + 8, static_cast<uint32_t>(h));
    put16(image, kBodyBase + 12, 1);
    put16(image, kBodyBase + 14, bpp);
    put32(image, kBodyBase + 16, 0); // BI_RGB
    put32(image, kBodyBase + 32, clr_used);
}

// 4x4 32bpp: stored row 0 solid blue, stored rows 1-3 solid green. All
// source alpha bytes are 0 so the decoder's forced-opaque output is
// observable. `top_down` selects negative biHeight.
// Body: 40 + 4*4*4 = 104 bytes.
void write_dib_32bpp(std::vector<uint8_t>& image, bool top_down)
{
    write_bih(image, 4, top_down ? -4 : 4, 32, 0);
    for (uint32_t y = 0; y < 4; ++y)
    {
        for (uint32_t x = 0; x < 4; ++x)
        {
            const size_t px = kBodyBase + 40 + (y * 4 + x) * 4;
            image[px + 0] = (y == 0) ? 0xFF : 0x00; // B
            image[px + 1] = (y == 0) ? 0x00 : 0xFF; // G
            image[px + 2] = 0x00;                   // R
            image[px + 3] = 0x00;                   // A (padding byte)
        }
    }
}

// 3x3 24bpp bottom-up, stride 12 (9 pixel bytes + 3 pad): solid green
// except x=0 of stored row 2 — the TOP image row — which is red.
// Body: 40 + 12*3 = 76 bytes.
void write_dib_24bpp(std::vector<uint8_t>& image)
{
    write_bih(image, 3, 3, 24, 0);
    for (uint32_t y = 0; y < 3; ++y)
    {
        for (uint32_t x = 0; x < 3; ++x)
        {
            const size_t px = kBodyBase + 40 + y * 12 + x * 3;
            const bool red = (y == 2 && x == 0);
            image[px + 0] = 0x00;              // B
            image[px + 1] = red ? 0x00 : 0xFF; // G
            image[px + 2] = red ? 0xFF : 0x00; // R
        }
    }
}

// Two-entry palette shared by the 8/4/1bpp bodies: index 0 = blue,
// index 1 = red (BGRX quads at kBodyBase + 40).
void write_two_entry_palette(std::vector<uint8_t>& image)
{
    image[kBodyBase + 40] = 0xFF; // blue: B
    image[kBodyBase + 41] = 0x00;
    image[kBodyBase + 42] = 0x00;
    image[kBodyBase + 43] = 0x00;
    image[kBodyBase + 44] = 0x00; // red: B
    image[kBodyBase + 45] = 0x00;
    image[kBodyBase + 46] = 0xFF;
    image[kBodyBase + 47] = 0x00;
}

// 2x2 8bpp, biClrUsed=2, stride 4. Stored row 0 (bottom) = red red,
// stored row 1 (top) = blue blue. Body: 40 + 8 + 8 = 56 bytes.
void write_dib_8bpp(std::vector<uint8_t>& image)
{
    write_bih(image, 2, 2, 8, 2);
    write_two_entry_palette(image);
    image[kBodyBase + 48] = 0x01;
    image[kBodyBase + 49] = 0x01;
    image[kBodyBase + 52] = 0x00;
    image[kBodyBase + 53] = 0x00;
}

// 2x2 4bpp, biClrUsed=2, stride 4. Stored row 0 byte 0x11 = both red;
// stored row 1 byte 0x00 = both blue. Body: 56 bytes.
void write_dib_4bpp(std::vector<uint8_t>& image)
{
    write_bih(image, 2, 2, 4, 2);
    write_two_entry_palette(image);
    image[kBodyBase + 48] = 0x11;
    image[kBodyBase + 52] = 0x00;
}

// 2x2 1bpp, biClrUsed=2, stride 4. Stored row 0 byte 0xC0 (bits 7,6
// set) = both red; stored row 1 = both blue. Body: 56 bytes.
void write_dib_1bpp(std::vector<uint8_t>& image)
{
    write_bih(image, 2, 2, 1, 2);
    write_two_entry_palette(image);
    image[kBodyBase + 48] = 0xC0;
    image[kBodyBase + 52] = 0x00;
}

// Expect pixel `i` (top-down index) of a decoded BGRA buffer to match.
bool px_is(const uint8_t* bgra, uint32_t i, uint8_t b, uint8_t g, uint8_t r, uint8_t a)
{
    return bgra[i * 4 + 0] == b && bgra[i * 4 + 1] == g && bgra[i * 4 + 2] == r && bgra[i * 4 + 3] == a;
}

// ---- Tests ----

void test_bitmap_info()
{
    auto image = make_bitmap_image(104);
    write_dib_32bpp(image, false);
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    unsigned int w = 0, h = 0, bpp = 0;
    REQUIRE(duet_res_bitmap_info(&view, 1, &w, &h, &bpp));
    EXPECT_TRUE(w == 4);
    EXPECT_TRUE(h == 4);
    EXPECT_TRUE(bpp == 32);
}

void test_bitmap_missing_id()
{
    auto image = make_bitmap_image(104);
    write_dib_32bpp(image, false);
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    unsigned int w = 0, h = 0, bpp = 0;
    EXPECT_TRUE(duet_res_bitmap_info(&view, 2, &w, &h, &bpp) == 0);
}

void test_decode_32bpp_bottom_up()
{
    auto image = make_bitmap_image(104);
    write_dib_32bpp(image, false);
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    uint8_t bgra[4 * 4 * 4];
    std::memset(bgra, 0xCC, sizeof(bgra));
    unsigned int w = 0, h = 0;
    REQUIRE(duet_res_decode_bitmap(&view, 1, bgra, 16, &w, &h) == 1);
    EXPECT_TRUE(w == 4 && h == 4);

    // Stored row 0 (blue) is the BOTTOM image row -> output row 3.
    // Alpha was 0 in the source; the decoder must force 255.
    EXPECT_TRUE(px_is(bgra, 3 * 4 + 0, 0xFF, 0x00, 0x00, 0xFF)); // row 3: blue
    EXPECT_TRUE(px_is(bgra, 0 * 4 + 0, 0x00, 0xFF, 0x00, 0xFF)); // row 0: green
}

void test_decode_32bpp_top_down()
{
    auto image = make_bitmap_image(104);
    write_dib_32bpp(image, true);
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    uint8_t bgra[4 * 4 * 4];
    std::memset(bgra, 0xCC, sizeof(bgra));
    REQUIRE(duet_res_decode_bitmap(&view, 1, bgra, 16, nullptr, nullptr) == 1);

    // Negative biHeight: stored row 0 (blue) IS the top image row.
    EXPECT_TRUE(px_is(bgra, 0 * 4 + 0, 0xFF, 0x00, 0x00, 0xFF)); // row 0: blue
    EXPECT_TRUE(px_is(bgra, 3 * 4 + 0, 0x00, 0xFF, 0x00, 0xFF)); // row 3: green
}

void test_decode_24bpp_stride()
{
    auto image = make_bitmap_image(76);
    write_dib_24bpp(image);
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    uint8_t bgra[3 * 3 * 4];
    std::memset(bgra, 0xCC, sizeof(bgra));
    REQUIRE(duet_res_decode_bitmap(&view, 1, bgra, 9, nullptr, nullptr) == 1);

    // Red marker at stored row 2 x=0 = top-left after the flip.
    EXPECT_TRUE(px_is(bgra, 0, 0x00, 0x00, 0xFF, 0xFF)); // (0,0): red
    EXPECT_TRUE(px_is(bgra, 1, 0x00, 0xFF, 0x00, 0xFF)); // (1,0): green
    EXPECT_TRUE(px_is(bgra, 8, 0x00, 0xFF, 0x00, 0xFF)); // (2,2): green
}

void test_decode_palette_depths()
{
    // 8bpp, 4bpp and 1bpp all encode the same 2x2 picture: bottom
    // stored row red, top stored row blue -> after the flip, output
    // row 0 is blue and output row 1 is red.
    struct Case
    {
        void (*write)(std::vector<uint8_t>&);
        const char* name;
    };
    const Case cases[] = {
        {write_dib_8bpp, "8bpp"},
        {write_dib_4bpp, "4bpp"},
        {write_dib_1bpp, "1bpp"},
    };
    for (const auto& c : cases)
    {
        auto image = make_bitmap_image(56);
        c.write(image);
        DUET_RES_VIEW view;
        REQUIRE(duet_res_init(image.data(), &view));

        uint8_t bgra[2 * 2 * 4];
        std::memset(bgra, 0xCC, sizeof(bgra));
        const int ok = duet_res_decode_bitmap(&view, 1, bgra, 4, nullptr, nullptr);
        if (ok != 1)
        {
            std::fprintf(stderr, "  %s: decode failed\n", c.name);
            ++failure_count();
            continue;
        }
        const bool good = px_is(bgra, 0, 0xFF, 0x00, 0x00, 0xFF) && px_is(bgra, 1, 0xFF, 0x00, 0x00, 0xFF) &&
                          px_is(bgra, 2, 0x00, 0x00, 0xFF, 0xFF) && px_is(bgra, 3, 0x00, 0x00, 0xFF, 0xFF);
        if (!good)
        {
            std::fprintf(stderr, "  %s: wrong pixels\n", c.name);
            ++failure_count();
        }
    }
    std::printf("  palette depths (8/4/1bpp): done\n");
}

void test_truncated_body_fails_closed()
{
    // Declared resource size covers the header but not every row.
    auto image = make_bitmap_image(103); // 32bpp body needs 104
    write_dib_32bpp(image, false);
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    uint8_t bgra[4 * 4 * 4];
    EXPECT_TRUE(duet_res_decode_bitmap(&view, 1, bgra, 16, nullptr, nullptr) == 0);
}

void test_unsupported_headers_fail_closed()
{
    DUET_RES_VIEW view;
    uint8_t bgra[4 * 4 * 4];

    // Non-BI_RGB compression.
    {
        auto image = make_bitmap_image(104);
        write_dib_32bpp(image, false);
        put32(image, kBodyBase + 16, 3); // BI_BITFIELDS
        REQUIRE(duet_res_init(image.data(), &view));
        EXPECT_TRUE(duet_res_decode_bitmap(&view, 1, bgra, 16, nullptr, nullptr) == 0);
    }
    // Unsupported bpp (16).
    {
        auto image = make_bitmap_image(104);
        write_dib_32bpp(image, false);
        put16(image, kBodyBase + 14, 16);
        REQUIRE(duet_res_init(image.data(), &view));
        EXPECT_TRUE(duet_res_decode_bitmap(&view, 1, bgra, 16, nullptr, nullptr) == 0);
    }
    // Zero width.
    {
        auto image = make_bitmap_image(104);
        write_dib_32bpp(image, false);
        put32(image, kBodyBase + 4, 0);
        REQUIRE(duet_res_init(image.data(), &view));
        EXPECT_TRUE(duet_res_decode_bitmap(&view, 1, bgra, 16, nullptr, nullptr) == 0);
    }
}

void test_max_pixels_guard()
{
    auto image = make_bitmap_image(104);
    write_dib_32bpp(image, false);
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    uint8_t bgra[4 * 4 * 4];
    // 4x4 = 16 pixels; a 15-pixel buffer must be refused.
    EXPECT_TRUE(duet_res_decode_bitmap(&view, 1, bgra, 15, nullptr, nullptr) == 0);
    EXPECT_TRUE(duet_res_decode_bitmap(&view, 1, bgra, 16, nullptr, nullptr) == 1);
}

} // namespace

int main()
{
    test_bitmap_info();
    test_bitmap_missing_id();
    test_decode_32bpp_bottom_up();
    test_decode_32bpp_top_down();
    test_decode_24bpp_stride();
    test_decode_palette_depths();
    test_truncated_body_fails_closed();
    test_unsupported_headers_fail_closed();
    test_max_pixels_guard();
    return finish_main("test_pe_bitmap_decode");
}
