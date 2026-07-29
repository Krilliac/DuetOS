// test_gdi_surface.cpp — off-screen GDI surface arithmetic.
//
// Exercises kernel/subsystems/win32/gdi_surface_math.h, the freestanding
// header the kernel uses to decide whether a guest-supplied surface
// request is sane and where a guest-supplied blit actually lands.
//
// Every input here is one a ring-3 PE controls directly, so the cases
// that matter are the hostile ones: dimensions that overflow 32-bit
// pixel math, a DIB height of INT32_MIN, blits whose rectangle starts
// off the left edge of one surface and off the top of the other, and a
// caller that keeps asking for one more bitmap until the table is gone.

#include "host_test_helper.h"

#include "subsystems/win32/gdi_surface_math.h"

using namespace duetos::subsystems::win32;

int main()
{
    // --- SurfaceByteSize: overflow and ceiling ---------------------
    EXPECT_EQ(SurfaceByteSize(16, 16), 16u * 16u * 4u);
    EXPECT_EQ(SurfaceByteSize(1024, 1024), 1024u * 1024u * 4u); // exactly on the ceiling
    EXPECT_EQ(SurfaceByteSize(0, 16), 0u);
    EXPECT_EQ(SurfaceByteSize(16, 0), 0u);
    EXPECT_EQ(SurfaceByteSize(1025, 1024), 0u); // one pixel over the ceiling

    // 65536 * 65536 == 2^32, which wraps to 0 in 32-bit math. A naive
    // implementation allocates nothing and then blits into it.
    EXPECT_EQ(SurfaceByteSize(65536, 65536), 0u);
    EXPECT_EQ(SurfaceByteSize(0xFFFFFFFFu, 0xFFFFFFFFu), 0u);
    EXPECT_EQ(SurfaceByteSize(0x40000000u, 4), 0u); // 2^30 * 4 also wraps in 32-bit

    // --- DibStrideBytes: DWORD row padding -------------------------
    // The 24bpp cases are the whole reason this function exists: a
    // 3-pixel row holds 9 bytes of pixels but occupies 12.
    EXPECT_EQ(DibStrideBytes(1, 24), 4u);
    EXPECT_EQ(DibStrideBytes(2, 24), 8u);
    EXPECT_EQ(DibStrideBytes(3, 24), 12u);
    EXPECT_EQ(DibStrideBytes(4, 24), 12u); // exactly 12, no padding
    EXPECT_EQ(DibStrideBytes(5, 24), 16u);

    EXPECT_EQ(DibStrideBytes(1, 32), 4u); // 32bpp never needs padding
    EXPECT_EQ(DibStrideBytes(7, 32), 28u);

    EXPECT_EQ(DibStrideBytes(1, 16), 4u);
    EXPECT_EQ(DibStrideBytes(2, 16), 4u); // exactly 4
    EXPECT_EQ(DibStrideBytes(3, 16), 8u);

    // Unsupported depths are refused rather than silently mis-rendered.
    EXPECT_EQ(DibStrideBytes(8, 8), 0u); // palettised
    EXPECT_EQ(DibStrideBytes(8, 1), 0u);
    EXPECT_EQ(DibStrideBytes(8, 48), 0u); // invented depth
    EXPECT_EQ(DibStrideBytes(0, 32), 0u);

    // --- DibImageByteSize + orientation ----------------------------
    EXPECT_EQ(DibImageByteSize(3, 2, 24), 24u);  // 2 rows of 12-byte stride
    EXPECT_EQ(DibImageByteSize(3, -2, 24), 24u); // top-down is the same size
    EXPECT_EQ(DibImageByteSize(4, 4, 32), 64u);
    EXPECT_EQ(DibImageByteSize(3, 0, 24), 0u);
    EXPECT_EQ(DibImageByteSize(4096, 4096, 32), 0u); // over the ceiling

    // INT32_MIN: negating it as an i32 is UB, and a guest can pass it.
    EXPECT_EQ(DibImageByteSize(4, -2147483647 - 1, 32), 0u);

    EXPECT_TRUE(DibIsTopDown(-8)); // negative biHeight
    EXPECT_FALSE(DibIsTopDown(8)); // positive == bottom-up, the Windows default
    EXPECT_FALSE(DibIsTopDown(0));

    // --- ClipBlit: fully inside ------------------------------------
    {
        const BlitRect r = ClipBlit(0, 0, 0, 0, 8, 8, 16, 16, 16, 16);
        EXPECT_EQ(r.width, 8);
        EXPECT_EQ(r.height, 8);
        EXPECT_EQ(r.src_x, 0);
        EXPECT_EQ(r.dst_x, 0);
    }

    // Right/bottom overhang on the DESTINATION only: crops the far
    // edge, leaves both origins alone.
    {
        const BlitRect r = ClipBlit(0, 0, 12, 12, 8, 8, 16, 16, 16, 16);
        EXPECT_EQ(r.width, 4);
        EXPECT_EQ(r.height, 4);
        EXPECT_EQ(r.src_x, 0);
        EXPECT_EQ(r.dst_x, 12);
    }

    // Right/bottom overhang on the SOURCE only.
    {
        const BlitRect r = ClipBlit(6, 6, 0, 0, 8, 8, 8, 8, 32, 32);
        EXPECT_EQ(r.width, 2);
        EXPECT_EQ(r.height, 2);
    }

    // Negative DESTINATION origin: both origins must advance together,
    // or the copied pixels shift instead of cropping.
    {
        const BlitRect r = ClipBlit(0, 0, -3, -2, 8, 8, 16, 16, 16, 16);
        EXPECT_EQ(r.dst_x, 0);
        EXPECT_EQ(r.dst_y, 0);
        EXPECT_EQ(r.src_x, 3); // src advanced by the same trim
        EXPECT_EQ(r.src_y, 2);
        EXPECT_EQ(r.width, 5);
        EXPECT_EQ(r.height, 6);
    }

    // Negative SOURCE origin: symmetric.
    {
        const BlitRect r = ClipBlit(-4, -1, 5, 5, 8, 8, 16, 16, 16, 16);
        EXPECT_EQ(r.src_x, 0);
        EXPECT_EQ(r.dst_x, 9);
        EXPECT_EQ(r.width, 4);
        EXPECT_EQ(r.height, 7);
    }

    // Both negative, different magnitudes: the LARGER trim wins on each
    // axis, otherwise one surface is still out of bounds.
    {
        const BlitRect r = ClipBlit(-2, -5, -6, -1, 10, 10, 16, 16, 16, 16);
        EXPECT_EQ(r.src_x, 4); // x trim is 6, from dst
        EXPECT_EQ(r.dst_x, 0);
        EXPECT_EQ(r.width, 4);
        EXPECT_EQ(r.src_y, 0); // y trim is 5, from src
        EXPECT_EQ(r.dst_y, 4);
        EXPECT_EQ(r.height, 5);
    }

    // Fully outside / degenerate: nothing survives.
    EXPECT_EQ(ClipBlit(0, 0, 64, 0, 8, 8, 16, 16, 16, 16).width, 0);
    EXPECT_EQ(ClipBlit(0, 0, -8, 0, 8, 8, 16, 16, 16, 16).width, 0);
    EXPECT_EQ(ClipBlit(0, 0, 0, 0, 0, 8, 16, 16, 16, 16).width, 0);
    EXPECT_EQ(ClipBlit(0, 0, 0, 0, -4, 8, 16, 16, 16, 16).width, 0);
    EXPECT_EQ(ClipBlit(0, 0, 0, 0, 8, 8, 0, 16, 16, 16).width, 0);

    // A blit ending exactly on both far edges is fully inside.
    {
        const BlitRect r = ClipBlit(8, 8, 8, 8, 8, 8, 16, 16, 16, 16);
        EXPECT_EQ(r.width, 8);
        EXPECT_EQ(r.height, 8);
    }

    // --- BudgetAdmits ----------------------------------------------
    EXPECT_TRUE(BudgetAdmits(0, 0, 4096, 16, 1u << 20));
    EXPECT_TRUE(BudgetAdmits(15, 0, 4096, 16, 1u << 20));  // last free slot
    EXPECT_FALSE(BudgetAdmits(16, 0, 4096, 16, 1u << 20)); // one past the object cap
    EXPECT_FALSE(BudgetAdmits(0, 0, 0, 16, 1u << 20));     // zero-byte request
    EXPECT_FALSE(BudgetAdmits(0, 0, (1u << 20) + 1, 16, 1u << 20));
    EXPECT_TRUE(BudgetAdmits(1, (1u << 20) - 4096, 4096, 16, 1u << 20)); // lands exactly on budget
    EXPECT_FALSE(BudgetAdmits(1, (1u << 20) - 4095, 4096, 16, 1u << 20));
    EXPECT_FALSE(BudgetAdmits(1, (1u << 21), 4096, 16, 1u << 20)); // already over budget

    return duetos_host_test::finish_main("gdi_surface");
}
