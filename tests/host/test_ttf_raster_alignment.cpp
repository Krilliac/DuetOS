// Real-font regression for kernel/drivers/video/{ttf,ttf_raster}.cpp.
//
// Liberation Sans deliberately gives round capitals a tiny typographic
// overshoot.  At 13 px that overshoot is far below one pixel, so it must not
// turn into a full-row jump between flat and round capitals.  If glyphs are
// rasterized in unrelated local coordinate systems, "BIG.TXT" and "CLOCK"
// visibly resemble mixed-case text even though every character is uppercase.

#include "host_test_helper.h"

#include "drivers/video/ttf.h"
#include "drivers/video/ttf_raster.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <limits>
#include <vector>

#ifndef DUETOS_SOURCE_DIR
#error "DUETOS_SOURCE_DIR must name the repository root"
#endif

namespace duetos::arch
{

void SerialWrite(const char* /*str*/) {}

} // namespace duetos::arch

namespace duetos::drivers::video
{

void FramebufferBlendFill(u32 /*x*/, u32 /*y*/, u32 /*w*/, u32 /*h*/, u32 /*argb*/) {}

} // namespace duetos::drivers::video

namespace
{

struct InkBounds
{
    int top;
    int bottom;
};

InkBounds RenderInkBounds(const duetos::drivers::video::TtfFont& font, char ch)
{
    using namespace duetos::drivers::video;

    constexpr duetos::u32 kPixelHeight = 13;
    constexpr duetos::u8 kVisibleInk = 64;

    std::array<duetos::u8, 128U * 128U> pixels{};
    std::array<TtfPoint, 1024> points{};
    std::array<duetos::u16, 64> endpoints{};
    TtfRenderedGlyph rendered{};

    const bool ok =
        TtfRenderGlyph(font, static_cast<duetos::u32>(static_cast<unsigned char>(ch)), kPixelHeight, pixels.data(),
                       static_cast<duetos::u32>(pixels.size()), points.data(), static_cast<duetos::u32>(points.size()),
                       endpoints.data(), static_cast<duetos::u16>(endpoints.size()), &rendered);
    if (!ok)
        return {std::numeric_limits<int>::max(), std::numeric_limits<int>::min()};

    int top = std::numeric_limits<int>::max();
    int bottom = std::numeric_limits<int>::min();
    for (duetos::u32 y = 0; y < rendered.height; ++y)
    {
        for (duetos::u32 x = 0; x < rendered.width; ++x)
        {
            if (pixels[y * rendered.width + x] < kVisibleInk)
                continue;
            const int screen_y = static_cast<int>(y) - rendered.ascent;
            if (screen_y < top)
                top = screen_y;
            if (screen_y > bottom)
                bottom = screen_y;
        }
    }
    return {top, bottom};
}

} // namespace

int main()
{
    using namespace duetos::drivers::video;

    const char* const font_path = DUETOS_SOURCE_DIR "/userland/assets/fonts/duet-chrome-bold.ttf";
    std::ifstream file(font_path, std::ios::binary | std::ios::ate);
    ASSERT_TRUE(file.is_open());
    const std::streamsize size = file.tellg();
    ASSERT_TRUE(size > 0);
    file.seekg(0, std::ios::beg);

    std::vector<duetos::u8> bytes(static_cast<std::size_t>(size));
    ASSERT_TRUE(file.read(reinterpret_cast<char*>(bytes.data()), size).good());

    auto font_result = TtfLoad(bytes.data(), static_cast<duetos::u32>(bytes.size()));
    ASSERT_TRUE(font_result.has_value());
    const TtfFont font = font_result.value();

    // Pillow/FreeType's grid-fitted reference for this bundled face at 13 px
    // puts all of these capitals on the same visible cap and baseline rows.
    // The literal expectation is deliberately independent of our rasterizer.
    constexpr char kCapitals[] = "BIGTXCLOCK";
    const InkBounds reference = RenderInkBounds(font, kCapitals[0]);
    ASSERT_TRUE(reference.top != std::numeric_limits<int>::max());

    for (std::size_t i = 1; i < sizeof(kCapitals) - 1U; ++i)
    {
        const InkBounds actual = RenderInkBounds(font, kCapitals[i]);
        if (actual.top != reference.top || actual.bottom != reference.bottom)
        {
            std::fprintf(stderr, "glyph %c ink rows [%d,%d], expected [%d,%d]\n", kCapitals[i], actual.top,
                         actual.bottom, reference.top, reference.bottom);
            ++::duetos_host_test::failure_count();
        }
    }

    return ::duetos_host_test::finish_main("tests/host/test_ttf_raster_alignment.cpp");
}
