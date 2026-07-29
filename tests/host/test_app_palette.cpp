// tests/host/test_app_palette.cpp
//
// Hosted unit tests for the Aurora app-interior palette math in
// kernel/drivers/video/app_widgets/app_palette.h (AppPaletteMake).
//
// The math is pure — it takes a client fill plus the theme's accent
// pair and resolves the design's rgba() tokens to opaque colours — so
// it tests without a kernel boot. The invariants that matter for the
// restyle are:
//
//   * the ink ramp flips on a light client fill (Notes' cream paper,
//     the DuetLight family) so dark-on-light still reads;
//   * every surface token stays distinguishable from the body it sits
//     on, and the wash / hover / recess ordering never collapses;
//   * a palette with no second accent channel collapses `accent_peer`
//     onto `accent` rather than publishing black;
//   * `aurora` is carried through untouched — it is the flat-theme
//     opt-out every restyled app branches on.

#include "host_test_helper.h"

#include "drivers/video/app_widgets/app_palette.h"

using duetos::u32;
using duetos::drivers::video::app_widgets::AppPalette;
using duetos::drivers::video::app_widgets::AppPaletteMake;
using duetos::drivers::video::app_widgets::kAppInk3Dark;
using duetos::drivers::video::app_widgets::kAppInkDark;
using duetos::drivers::video::app_widgets::kAppInkLight;

namespace
{

constexpr u32 kTeal = 0x002DD4BF;  // Duet's native-ABI accent
constexpr u32 kAmber = 0x00FFC046; // Duet's Win32 PE peer accent

// Dark slate client fill — role_client[TaskManager] in the Duet family.
constexpr u32 kDarkBody = 0x00141A22;
// Notes' cream paper — the one light client in an otherwise dark theme.
constexpr u32 kLightBody = 0x00F3F0E6;

u32 Luma(u32 rgb)
{
    return duetos::drivers::video::app_widgets::AppLuma(rgb);
}

} // namespace

int main()
{
    // ----- dark client: dark-mode ink ramp, descending contrast -----
    {
        const AppPalette p = AppPaletteMake(kDarkBody, kTeal, kAmber, /*aurora=*/true);
        EXPECT_TRUE(p.aurora);
        EXPECT_EQ(p.body, kDarkBody);
        EXPECT_EQ(p.ink, kAppInkDark);
        EXPECT_EQ(p.ink_3, kAppInk3Dark);
        // ink > ink_2 > ink_3 in luminance: the three-step ramp is what
        // lets a table put its values above its labels without colour.
        EXPECT_TRUE(Luma(p.ink) > Luma(p.ink_2));
        EXPECT_TRUE(Luma(p.ink_2) > Luma(p.ink_3));
        // ...and every ink still out-contrasts the surface it lands on.
        EXPECT_TRUE(Luma(p.ink_3) > Luma(p.body));
    }

    // ----- light client flips the ramp -----
    {
        const AppPalette p = AppPaletteMake(kLightBody, kTeal, kAmber, /*aurora=*/true);
        EXPECT_EQ(p.ink, kAppInkLight);
        EXPECT_TRUE(Luma(p.ink) < Luma(p.body));
        EXPECT_TRUE(Luma(p.ink) < Luma(p.ink_2));
        EXPECT_TRUE(Luma(p.ink_2) < Luma(p.ink_3));
    }

    // ----- surface ordering: recess < body < wash < hover (dark) -----
    {
        const AppPalette p = AppPaletteMake(kDarkBody, kTeal, kAmber, /*aurora=*/true);
        EXPECT_TRUE(Luma(p.recess) < Luma(p.body));
        EXPECT_TRUE(Luma(p.wash) > Luma(p.body));
        EXPECT_TRUE(Luma(p.hover) > Luma(p.wash));
        EXPECT_TRUE(Luma(p.line) > Luma(p.wash));
        // A zebra row that equals the body is a zebra row nobody sees.
        EXPECT_TRUE(p.wash != p.body);
        EXPECT_TRUE(p.recess != p.body);
    }

    // ----- surface ordering inverts on a light client -----
    {
        const AppPalette p = AppPaletteMake(kLightBody, kTeal, kAmber, /*aurora=*/true);
        EXPECT_TRUE(Luma(p.recess) < Luma(p.body));
        EXPECT_TRUE(Luma(p.wash) < Luma(p.body));
        EXPECT_TRUE(Luma(p.hover) < Luma(p.wash));
    }

    // ----- selection tint leans toward the accent, not past it -----
    {
        const AppPalette p = AppPaletteMake(kDarkBody, kTeal, kAmber, /*aurora=*/true);
        EXPECT_TRUE(p.sel != p.body);
        // 14 % of the accent: closer to the body than to the accent, so
        // the row text (still ink) keeps its contrast.
        EXPECT_TRUE(Luma(p.sel) > Luma(p.body));
        EXPECT_TRUE(Luma(p.sel) < Luma(p.accent));
    }

    // ----- accent pair passthrough + single-channel collapse -----
    {
        const AppPalette pair = AppPaletteMake(kDarkBody, kTeal, kAmber, /*aurora=*/true);
        EXPECT_EQ(pair.accent, kTeal);
        EXPECT_EQ(pair.accent_peer, kAmber);

        const AppPalette solo = AppPaletteMake(kDarkBody, kTeal, /*accent_peer=*/0, /*aurora=*/true);
        EXPECT_EQ(solo.accent_peer, kTeal);
    }

    // ----- the flat-theme opt-out is carried, not inferred -----
    {
        const AppPalette flat = AppPaletteMake(kDarkBody, kTeal, /*accent_peer=*/0, /*aurora=*/false);
        EXPECT_FALSE(flat.aurora);
        // The tokens are still resolved — an app that opts out simply
        // never reads them — so a caller can't trip over garbage.
        EXPECT_EQ(flat.ink, kAppInkDark);
    }

    // ----- constexpr-usable: the whole resolve folds at compile time --
    {
        constexpr AppPalette p = AppPaletteMake(kDarkBody, kTeal, kAmber, true);
        static_assert(p.aurora, "AppPaletteMake must be usable in a constant expression");
        static_assert(p.ink == kAppInkDark, "dark client fill must select the dark ink ramp");
        EXPECT_EQ(p.danger, 0x00FF5F57u);
    }

    return ::duetos_host_test::finish_main(__FILE__);
}
