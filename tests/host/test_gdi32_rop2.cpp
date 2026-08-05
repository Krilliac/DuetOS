// test_gdi32_rop2.cpp — hosted unit test for the ROP2 (SetROP2)
// pixel math in kernel/subsystems/win32/gdi_surface_math.h. The
// memory-DC paint helpers (GdiPaintRectOnBitmapRop /
// GdiDrawLineOnBitmapRop / PaintFilledEllipseOnBitmapRop) apply this
// per pixel; this test pins the full 16-entry truth table so a
// raster-op regression shows up on the host, not in a bare-metal PE
// smoke.

#include "host_test_helper.h"

#include "subsystems/win32/gdi_surface_math.h"

using namespace duetos_host_test;
using namespace duetos::subsystems::win32;

int main()
{
    // Every R2_* code against one nontrivial operand pair.
    // P = pen/src = 0x00AA55CC, D = dst = 0x00123456.
    constexpr duetos::u32 dst = 0x00123456u;
    constexpr duetos::u32 src = 0x00AA55CCu;

    // --- R2_BLACK: always 0 ---
    EXPECT_EQ(Rop2Apply(kRop2Black, dst, src), 0x00000000u);

    // --- R2_NOTMERGEPEN: ~(D | P) ---
    EXPECT_EQ(Rop2Apply(kRop2NotMergePen, dst, src), 0x00458A21u);

    // --- R2_MASKNOTPEN: D & ~P ---
    EXPECT_EQ(Rop2Apply(kRop2MaskNotPen, dst, src), 0x00102012u);

    // --- R2_NOTCOPYPEN: ~P ---
    EXPECT_EQ(Rop2Apply(kRop2NotCopyPen, dst, src), 0x0055AA33u);

    // --- R2_MASKPENNOT: P & ~D ---
    EXPECT_EQ(Rop2Apply(kRop2MaskPenNot, dst, src), 0x00A84188u);

    // --- R2_NOT: ~D ---
    EXPECT_EQ(Rop2Apply(kRop2Not, dst, src), 0x00EDCBA9u);
    EXPECT_EQ(Rop2Apply(kRop2Not, 0x00FF00FFu, 0x00ABCDEFu), 0x0000FF00u);
    EXPECT_EQ(Rop2Apply(kRop2Not, 0x00000000u, 0x00000000u), 0x00FFFFFFu);

    // --- R2_XORPEN: D ^ P; involutive ---
    EXPECT_EQ(Rop2Apply(kRop2XorPen, dst, src), 0x00B8619Au);
    EXPECT_EQ(Rop2Apply(kRop2XorPen, 0x00F0F0F0u, 0x000F0F0Fu), 0x00FFFFFFu);
    EXPECT_EQ(Rop2Apply(kRop2XorPen, 0x00ABCDEFu, 0x00ABCDEFu), 0x00000000u);
    // XOR twice with the same pen restores the destination.
    EXPECT_EQ(Rop2Apply(kRop2XorPen, Rop2Apply(kRop2XorPen, dst, 0x00ABCDEFu), 0x00ABCDEFu), dst);

    // --- R2_NOTMASKPEN: ~(D & P) ---
    EXPECT_EQ(Rop2Apply(kRop2NotMaskPen, dst, src), 0x00FDEBBBu);

    // --- R2_MASKPEN: D & P ---
    EXPECT_EQ(Rop2Apply(kRop2MaskPen, dst, src), 0x00021444u);

    // --- R2_NOTXORPEN: ~(D ^ P) ---
    EXPECT_EQ(Rop2Apply(kRop2NotXorPen, dst, src), 0x00479E65u);

    // --- R2_NOP: D, bit-exact (alpha garbage included) ---
    EXPECT_EQ(Rop2Apply(kRop2Nop, dst, src), dst);
    EXPECT_EQ(Rop2Apply(kRop2Nop, 0xFF123456u, 0xFFABCDEFu), 0xFF123456u);

    // --- R2_MERGENOTPEN: D | ~P ---
    EXPECT_EQ(Rop2Apply(kRop2MergeNotPen, dst, src), 0x0057BE77u);

    // --- R2_COPYPEN: P, dst ignored ---
    EXPECT_EQ(Rop2Apply(kRop2CopyPen, dst, src), src);

    // --- R2_MERGEPENNOT: P | ~D ---
    EXPECT_EQ(Rop2Apply(kRop2MergePenNot, dst, src), 0x00EFDFEDu);

    // --- R2_MERGEPEN: D | P ---
    EXPECT_EQ(Rop2Apply(kRop2MergePen, dst, src), 0x00BA75DEu);

    // --- R2_WHITE: always 1s ---
    EXPECT_EQ(Rop2Apply(kRop2White, dst, src), 0x00FFFFFFu);

    // --- Algebraic identities: the NOT*-family ops equal R2_NOT
    // applied to their plain counterpart's result ---
    EXPECT_EQ(Rop2Apply(kRop2NotXorPen, dst, src), Rop2Apply(kRop2Not, Rop2Apply(kRop2XorPen, dst, src), src));
    EXPECT_EQ(Rop2Apply(kRop2NotMaskPen, dst, src), Rop2Apply(kRop2Not, Rop2Apply(kRop2MaskPen, dst, src), src));
    EXPECT_EQ(Rop2Apply(kRop2NotMergePen, dst, src), Rop2Apply(kRop2Not, Rop2Apply(kRop2MergePen, dst, src), src));
    EXPECT_EQ(Rop2Apply(kRop2NotCopyPen, dst, src), Rop2Apply(kRop2Not, src, src));

    // --- Identity elements: AND with all-1s, OR/XOR with 0 ---
    EXPECT_EQ(Rop2Apply(kRop2MaskPen, dst, 0x00FFFFFFu), dst);
    EXPECT_EQ(Rop2Apply(kRop2MergePen, dst, 0x00000000u), dst);
    EXPECT_EQ(Rop2Apply(kRop2XorPen, dst, 0x00000000u), dst);

    // --- High byte: every dst-reading op except the deliberate
    // NOP pass-through masks to 24 bits even when the destination
    // carries alpha garbage. (COPYPEN passes src through verbatim
    // — it trusts the caller's 24-bit COLORREF.) ---
    {
        const duetos::u8 masked[] = {kRop2Black,      kRop2NotMergePen, kRop2MaskNotPen,  kRop2NotCopyPen,
                                     kRop2MaskPenNot, kRop2Not,         kRop2XorPen,      kRop2NotMaskPen,
                                     kRop2MaskPen,    kRop2NotXorPen,   kRop2MergeNotPen, kRop2MergePenNot,
                                     kRop2MergePen,   kRop2White};
        for (duetos::u8 code : masked)
        {
            EXPECT_EQ(Rop2Apply(code, 0xFF123456u, 0x00ABCDEFu) & 0xFF000000u, 0u);
        }
    }
    EXPECT_EQ(Rop2Apply(kRop2Not, 0xFF123456u, 0xFFABCDEFu), 0x00EDCBA9u);
    EXPECT_EQ(Rop2Apply(kRop2XorPen, 0xFF123456u, 0xFFABCDEFu), 0x00B9F9B9u);

    // --- Rop2NeedsDst: only BLACK / NOTCOPYPEN / COPYPEN / WHITE
    // are destination-independent ---
    EXPECT_FALSE(Rop2NeedsDst(kRop2Black));
    EXPECT_FALSE(Rop2NeedsDst(kRop2NotCopyPen));
    EXPECT_FALSE(Rop2NeedsDst(kRop2CopyPen));
    EXPECT_FALSE(Rop2NeedsDst(kRop2White));
    EXPECT_TRUE(Rop2NeedsDst(kRop2NotMergePen));
    EXPECT_TRUE(Rop2NeedsDst(kRop2MaskNotPen));
    EXPECT_TRUE(Rop2NeedsDst(kRop2MaskPenNot));
    EXPECT_TRUE(Rop2NeedsDst(kRop2Not));
    EXPECT_TRUE(Rop2NeedsDst(kRop2XorPen));
    EXPECT_TRUE(Rop2NeedsDst(kRop2NotMaskPen));
    EXPECT_TRUE(Rop2NeedsDst(kRop2MaskPen));
    EXPECT_TRUE(Rop2NeedsDst(kRop2NotXorPen));
    EXPECT_TRUE(Rop2NeedsDst(kRop2Nop));
    EXPECT_TRUE(Rop2NeedsDst(kRop2MergeNotPen));
    EXPECT_TRUE(Rop2NeedsDst(kRop2MergePenNot));
    EXPECT_TRUE(Rop2NeedsDst(kRop2MergePen));

    // --- Rop2ModeValid: the R2_* range is 1..16 ---
    EXPECT_FALSE(Rop2ModeValid(0));
    EXPECT_TRUE(Rop2ModeValid(1));
    EXPECT_TRUE(Rop2ModeValid(16));
    EXPECT_FALSE(Rop2ModeValid(17));

    return finish_main("gdi32_rop2");
}
