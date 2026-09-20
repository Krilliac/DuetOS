// A centred bold label must use the bold face's advance width. Measuring the
// regular face and painting the bold face shifts the visible label sideways
// whenever the two fonts have different metrics.

#include "host_test_helper.h"

#include "drivers/video/app_widgets/app_label.h"

namespace
{

constexpr duetos::u32 kRegularWidth = 40;
constexpr duetos::u32 kBoldWidth = 50;
constexpr duetos::u32 kLineHeight = 13;

duetos::u32 g_draw_x = 0;
duetos::u32 g_draw_y = 0;
duetos::drivers::video::ChromeTextWeight g_draw_weight = duetos::drivers::video::ChromeTextWeight::Regular;

} // namespace

namespace duetos::drivers::video
{

// Existing two-argument measurement models the current bug: it can only
// return the regular face's advance.
u32 ChromeTextMeasure(ChromeTextRole /*role*/, const char* /*text*/)
{
    return kRegularWidth;
}

// The weight-aware overload is the intended contract. The production label
// painter must call this overload with its own weight.
u32 ChromeTextMeasure(ChromeTextRole /*role*/, const char* /*text*/, ChromeTextWeight weight)
{
    return weight == ChromeTextWeight::Bold ? kBoldWidth : kRegularWidth;
}

u32 ChromeTextRoleHeight(ChromeTextRole /*role*/)
{
    return kLineHeight;
}

void ChromeTextDraw(ChromeTextRole /*role*/, u32 x, u32 y, const char* /*text*/, u32 /*fg*/, u32 /*bg*/,
                    ChromeTextWeight weight)
{
    g_draw_x = x;
    g_draw_y = y;
    g_draw_weight = weight;
}

} // namespace duetos::drivers::video

int main()
{
    using namespace duetos::drivers::video;
    using namespace duetos::drivers::video::app_widgets;

    AppLabel label;
    label.bounds = Rect{10, 20, 100, 30};
    label.text = "Centered";
    label.role = ChromeTextRole::Body;
    label.weight = ChromeTextWeight::Bold;
    label.align_left = false;

    Compose compose;
    label.Paint(compose);

    EXPECT_EQ(g_draw_x, 10U + (100U - kBoldWidth) / 2U);
    EXPECT_EQ(g_draw_y, 20U + (30U - kLineHeight) / 2U);
    EXPECT_EQ(g_draw_weight, ChromeTextWeight::Bold);

    return ::duetos_host_test::finish_main("tests/host/test_app_label_alignment.cpp");
}
