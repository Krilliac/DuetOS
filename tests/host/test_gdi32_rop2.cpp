// test_gdi32_rop2.cpp — hosted unit test for the ROP2 (SetROP2)
// pixel math in kernel/subsystems/win32/gdi_surface_math.h. The
// memory-DC paint helpers (GdiPaintRectOnBitmapRop /
// GdiDrawLineOnBitmapRop) apply this per pixel; this test pins the
// truth table so a raster-op regression shows up on the host, not
// in a bare-metal PE smoke.

#include "host_test_helper.h"

#include "subsystems/win32/gdi_surface_math.h"

using namespace duetos_host_test;
using namespace duetos::subsystems::win32;

int main()
{
    // --- R2_COPYPEN: src wins, dst ignored ---
    EXPECT_EQ(Rop2Apply(kRop2CopyPen, 0x00123456u, 0x00AA55CCu), 0x00AA55CCu);

    // --- R2_BLACK / R2_WHITE: constants, operands ignored ---
    EXPECT_EQ(Rop2Apply(kRop2Black, 0x00123456u, 0x00AA55CCu), 0x00000000u);
    EXPECT_EQ(Rop2Apply(kRop2White, 0x00123456u, 0x00AA55CCu), 0x00FFFFFFu);

    // --- R2_NOT: destination inverted, masked to 24 bits ---
    EXPECT_EQ(Rop2Apply(kRop2Not, 0x00FF00FFu, 0x00ABCDEFu), 0x0000FF00u);
    EXPECT_EQ(Rop2Apply(kRop2Not, 0x00000000u, 0x00000000u), 0x00FFFFFFu);

    // --- R2_XORPEN: dst ^ pen; involutive ---
    EXPECT_EQ(Rop2Apply(kRop2XorPen, 0x00F0F0F0u, 0x000F0F0Fu), 0x00FFFFFFu);
    EXPECT_EQ(Rop2Apply(kRop2XorPen, 0x00ABCDEFu, 0x00ABCDEFu), 0x00000000u);
    // XOR twice with the same pen restores the destination.
    EXPECT_EQ(Rop2Apply(kRop2XorPen, Rop2Apply(kRop2XorPen, 0x00123456u, 0x00ABCDEFu), 0x00ABCDEFu), 0x00123456u);

    // --- High byte: the dst-reading ops mask to 24 bits even when
    // the destination carries alpha garbage. (COPYPEN passes src
    // through verbatim — it trusts the caller's 24-bit COLORREF.) ---
    EXPECT_EQ(Rop2Apply(kRop2Black, 0xFF123456u, 0xFFABCDEFu) & 0xFF000000u, 0u);
    EXPECT_EQ(Rop2Apply(kRop2White, 0xFF123456u, 0xFFABCDEFu) & 0xFF000000u, 0u);
    EXPECT_EQ(Rop2Apply(kRop2Not, 0xFF123456u, 0xFFABCDEFu) & 0xFF000000u, 0u);
    EXPECT_EQ(Rop2Apply(kRop2XorPen, 0xFF123456u, 0xFFABCDEFu) & 0xFF000000u, 0u);
    EXPECT_EQ(Rop2Apply(kRop2Not, 0xFF123456u, 0xFFABCDEFu), 0x00EDCBA9u);
    EXPECT_EQ(Rop2Apply(kRop2XorPen, 0xFF123456u, 0xFFABCDEFu), 0x00B9F9B9u);

    // --- GAP fallback: every other R2_* code behaves as COPYPEN ---
    {
        const duetos::u8 fallback[] = {2, 3, 4, 5, 8, 9, 10, 11, 12, 14, 15};
        for (duetos::u8 code : fallback)
        {
            EXPECT_EQ(Rop2Apply(code, 0x00123456u, 0x00AA55CCu), 0x00AA55CCu);
        }
    }

    // --- Rop2NeedsDst: read-modify-write ops only ---
    EXPECT_TRUE(Rop2NeedsDst(kRop2Not));
    EXPECT_TRUE(Rop2NeedsDst(kRop2XorPen));
    EXPECT_FALSE(Rop2NeedsDst(kRop2Black));
    EXPECT_FALSE(Rop2NeedsDst(kRop2White));
    EXPECT_FALSE(Rop2NeedsDst(kRop2CopyPen));

    // --- Rop2ModeValid: the R2_* range is 1..16 ---
    EXPECT_FALSE(Rop2ModeValid(0));
    EXPECT_TRUE(Rop2ModeValid(1));
    EXPECT_TRUE(Rop2ModeValid(16));
    EXPECT_FALSE(Rop2ModeValid(17));

    return finish_main("gdi32_rop2");
}
