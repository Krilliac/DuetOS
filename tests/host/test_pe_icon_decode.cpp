// test_pe_icon_decode.cpp — hosted unit test for the icon / cursor
// resource decoder functions in pe_resources.h:
//   - duet_res_pick_icon (RT_GROUP_ICON directory walk + best-fit size)
//   - duet_res_decode_icon (BITMAPINFOHEADER + DIB + AND-mask -> BGRA)
//
// Uses a synthetic PE image with a hand-crafted RT_GROUP_ICON (type 14)
// and RT_ICON (type 3) resource, so each byte is under test control.
// The windres-produced variant is exercised by icon_smoke.exe at boot.

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
// Synthetic image builder (same skeleton as test_pe_resources.cpp)
// ------------------------------------------------------------------

constexpr uint32_t kHeadersSize = 0x1000;
constexpr uint32_t kRsrcRva = 0x1000;
constexpr uint32_t kRsrcBytes = 0x2000; // bigger section for icon data
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
    put16(image, opt + 0, 0x020B);       // PE32+ magic
    put32(image, opt + 56, kImageSize);  // SizeOfImage
    put32(image, opt + 60, kHeadersSize); // SizeOfHeaders

    const size_t dd = opt + 112; // DataDirectory for PE32+
    put32(image, dd - 4, 16);   // NumberOfRvaAndSizes
    // Resource directory entry (index 2)
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

// Build a synthetic PE with a 4x4 32bpp icon. Layout in .rsrc:
//
// Off 0x000: root dir (2 id entries: type 3=RT_ICON, type 14=RT_GROUP_ICON)
// Off 0x020: type-3 dir (1 id entry: id=1)
// Off 0x038: type-3/id-1 lang dir (1 entry: lang=0)
// Off 0x050: type-3/id-1/lang-0 data entry -> icon DIB body
// Off 0x070: type-14 dir (1 id entry: id=1)
// Off 0x088: type-14/id-1 lang dir (1 entry: lang=0)
// Off 0x0A0: type-14/id-1/lang-0 data entry -> group header
// Off 0x100: RT_GROUP_ICON data (6-byte header + 14-byte entry)
// Off 0x200: RT_ICON data (BIH + 4x4 BGRA + AND mask)
//
std::vector<uint8_t> make_icon_image()
{
    auto image = make_image();

    // Root dir: 2 ID entries (RT_ICON=3, RT_GROUP_ICON=14)
    write_dir_header(image, 0x000, 0, 2);
    write_dir_entry(image, 0x000, 0, 3, 0x020, true);    // RT_ICON -> sub at 0x020
    write_dir_entry(image, 0x000, 1, 14, 0x070, true);   // RT_GROUP_ICON -> sub at 0x070

    // Type-3 (RT_ICON) dir: 1 entry, id=1
    write_dir_header(image, 0x020, 0, 1);
    write_dir_entry(image, 0x020, 0, 1, 0x038, true);    // id=1 -> lang dir at 0x038

    // Type-3/id-1 lang dir: 1 entry, lang=0
    write_dir_header(image, 0x038, 0, 1);
    write_dir_entry(image, 0x038, 0, 0, 0x050, false);   // lang=0 -> data entry at 0x050

    // Type-3/id-1/lang-0 data entry -> icon body at RVA 0x1200 (rsrc + 0x200)
    // Icon body: BIH(40) + XOR(4*4*4=64) + AND(4*4=4 per row, 4 rows, stride=4 -> 16)
    // Total: 40 + 64 + 16 = 120
    write_data_entry(image, 0x050, kRsrcRva + 0x200, 120);

    // Type-14 (RT_GROUP_ICON) dir: 1 entry, id=1
    write_dir_header(image, 0x070, 0, 1);
    write_dir_entry(image, 0x070, 0, 1, 0x088, true);    // id=1 -> lang dir at 0x088

    // Type-14/id-1 lang dir: 1 entry, lang=0
    write_dir_header(image, 0x088, 0, 1);
    write_dir_entry(image, 0x088, 0, 0, 0x0A0, false);   // lang=0 -> data entry at 0x0A0

    // Type-14/id-1/lang-0 data entry -> group data at RVA 0x1100 (rsrc + 0x100)
    // Group: 6-byte header + 14-byte GRPICONDIRENTRY = 20
    write_data_entry(image, 0x0A0, kRsrcRva + 0x100, 20);

    // --- RT_GROUP_ICON data at rsrc + 0x100 ---
    // GRPICONDIR: reserved=0, type=1 (icon), count=1
    size_t grp = kRsrcRva + 0x100;
    put16(image, grp + 0, 0);    // reserved
    put16(image, grp + 2, 1);    // type = icon
    put16(image, grp + 4, 1);    // count = 1
    // GRPICONDIRENTRY: 4x4, 0 colours, 0 reserved, 1 plane, 32 bpp, size, nID=1
    image[grp + 6] = 4;          // bWidth
    image[grp + 7] = 4;          // bHeight
    image[grp + 8] = 0;          // bColorCount
    image[grp + 9] = 0;          // bReserved
    put16(image, grp + 10, 1);   // wPlanes
    put16(image, grp + 12, 32);  // wBitCount
    put32(image, grp + 14, 120); // dwBytesInRes
    put16(image, grp + 18, 1);   // nID = 1 (matches RT_ICON id)

    // --- RT_ICON data at rsrc + 0x200 ---
    size_t ico = kRsrcRva + 0x200;
    // BITMAPINFOHEADER (40 bytes)
    put32(image, ico + 0, 40);   // biSize
    put32(image, ico + 4, 4);    // biWidth
    put32(image, ico + 8, 8);    // biHeight = 4*2 (XOR + AND)
    put16(image, ico + 12, 1);   // biPlanes
    put16(image, ico + 14, 32);  // biBitCount
    put32(image, ico + 16, 0);   // biCompression = BI_RGB
    // rest are zeros (biSizeImage, biX/YPels, biClrUsed, biClrImportant)

    // XOR bitmap: 4x4 BGRA, bottom-up. Each pixel is solid red
    // (B=0, G=0, R=0xFF, A=0xFF).
    for (uint32_t y = 0; y < 4; ++y)
    {
        for (uint32_t x = 0; x < 4; ++x)
        {
            size_t px = ico + 40 + (y * 4 + x) * 4;
            image[px + 0] = 0x00; // B
            image[px + 1] = 0x00; // G
            image[px + 2] = 0xFF; // R
            image[px + 3] = 0xFF; // A
        }
    }

    // AND mask: 4x4 1bpp, all zeros (opaque). Stride = 4 bytes.
    // Already zeroed by make_image.

    return image;
}

// ---- Tests ----

void test_pick_icon_basic()
{
    auto image = make_icon_image();
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    unsigned int icon_id = 0, w = 0, h = 0;
    REQUIRE(duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_ICON, 1, 4, 4, &icon_id, &w, &h));
    REQUIRE(icon_id == 1);
    REQUIRE(w == 4);
    REQUIRE(h == 4);
    std::printf("  pick_icon basic hit: PASS\n");
}

void test_pick_icon_missing()
{
    auto image = make_icon_image();
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    unsigned int icon_id = 99;
    // id 2 does not exist in our .rsrc
    int found = duet_res_pick_icon(&view, DUET_RES_TYPE_GROUP_ICON, 2, 4, 4, &icon_id, nullptr, nullptr);
    EXPECT_TRUE(found == 0);
}

void test_decode_icon_32bpp()
{
    auto image = make_icon_image();
    DUET_RES_VIEW view;
    REQUIRE(duet_res_init(image.data(), &view));

    uint8_t bgra[4 * 4 * 4];
    std::memset(bgra, 0xCC, sizeof(bgra));

    int ok = duet_res_decode_icon(&view, DUET_RES_TYPE_ICON, 1, 4, 4, bgra, 16, nullptr, nullptr);
    REQUIRE(ok == 1);

    // The XOR bitmap was solid red (B=0, G=0, R=0xFF, A=0xFF) and the
    // AND mask was all zeros (opaque), so every pixel should be
    // (B=0, G=0, R=0xFF, A=0xFF). The decoder flips bottom-up to
    // top-down, so check all 16 pixels.
    bool all_red = true;
    for (int i = 0; i < 16; ++i)
    {
        if (bgra[i * 4 + 0] != 0x00 || bgra[i * 4 + 1] != 0x00 || bgra[i * 4 + 2] != 0xFF || bgra[i * 4 + 3] != 0xFF)
        {
            all_red = false;
            std::fprintf(stderr, "  pixel %d: B=%02x G=%02x R=%02x A=%02x\n", i, bgra[i * 4 + 0], bgra[i * 4 + 1],
                         bgra[i * 4 + 2], bgra[i * 4 + 3]);
        }
    }
    EXPECT_TRUE(all_red);
}

void test_decode_icon_and_mask_transparency()
{
    auto image = make_icon_image();
    DUET_RES_VIEW view;

    // Modify the AND mask: set the top-left pixel's AND bit to 1,
    // making it transparent. AND mask is at icon body + 40 + 64.
    // Row 0 of AND (bottom row of image) is at offset 0.
    // Bit 7 of byte 0 controls x=0.
    size_t and_base = kRsrcRva + 0x200 + 40 + 64;
    image[and_base] = 0x80; // bit 7 = 1 -> x=0, AND-row-0 (bottom)

    REQUIRE(duet_res_init(image.data(), &view));

    uint8_t bgra[4 * 4 * 4];
    std::memset(bgra, 0xCC, sizeof(bgra));

    int ok = duet_res_decode_icon(&view, DUET_RES_TYPE_ICON, 1, 4, 4, bgra, 16, nullptr, nullptr);
    REQUIRE(ok == 1);

    // After bottom-up flip, AND-row-0 (bottom) becomes top-down row 3.
    // Pixel (0, 3) should have alpha=0 (transparent).
    uint8_t a_transparent = bgra[3 * 4 * 4 + 0 * 4 + 3]; // row 3, col 0, alpha
    uint8_t a_opaque = bgra[0 * 4 * 4 + 0 * 4 + 3];      // row 0, col 0, alpha
    EXPECT_TRUE(a_transparent == 0);
    EXPECT_TRUE(a_opaque == 0xFF);
}

} // namespace

int main()
{
    test_pick_icon_basic();
    test_pick_icon_missing();
    test_decode_icon_32bpp();
    test_decode_icon_and_mask_transparency();
    return finish_main("test_pe_icon_decode");
}
