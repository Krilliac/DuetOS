// tests/host/test_intel_blt.cpp
//
// Hosted contract tests for the pure Intel BLT geometry gate and packet
// encoder. MMIO submission remains silicon-only; these cases pin the
// rejection boundary that keeps a compositor caller from handing the ring
// an unsupported format, a wrapped surface, or a rectangle that cannot fit
// in Intel's 16-bit XY fields.

#include "drivers/gpu/intel_gpu_cmds.h"
#include "host_test_helper.h"

using duetos::drivers::gpu::intel::BltSurfaceGeometry;
using duetos::drivers::gpu::intel::ColorBltPacket;
using duetos::drivers::gpu::intel::EncodeColorBlt;
using duetos::drivers::gpu::intel::IsBltRectValid;
using duetos::drivers::gpu::intel::IsBltSurfaceGeometryValid;

int main()
{
    const BltSurfaceGeometry valid{0x40000u, 320u, 200u, 1280u, 32u};
    EXPECT_TRUE(IsBltSurfaceGeometryValid(valid));
    EXPECT_TRUE(IsBltRectValid(valid, 0u, 0u, 320u, 200u));
    EXPECT_TRUE(IsBltRectValid(valid, 16u, 12u, 64u, 48u));

    const BltSurfaceGeometry wrong_format{0x40000u, 320u, 200u, 1280u, 16u};
    EXPECT_FALSE(IsBltSurfaceGeometryValid(wrong_format));

    const BltSurfaceGeometry short_pitch{0x40000u, 320u, 200u, 1276u, 32u};
    EXPECT_FALSE(IsBltSurfaceGeometryValid(short_pitch));

    const BltSurfaceGeometry short_buffer{0x400u, 320u, 200u, 1280u, 32u};
    EXPECT_FALSE(IsBltSurfaceGeometryValid(short_buffer));

    EXPECT_FALSE(IsBltRectValid(valid, 319u, 0u, 2u, 1u));
    EXPECT_FALSE(IsBltRectValid(valid, 0u, 199u, 1u, 2u));
    EXPECT_FALSE(IsBltRectValid(valid, 0u, 0u, 0u, 1u));

    const BltSurfaceGeometry packet_surface{0x4000u, 640u, 480u, 2560u, 32u};
    const ColorBltPacket packet =
        EncodeColorBlt(0x12345000ull, packet_surface.pitch_bytes, 10u, 20u, 110u, 70u, 0x003366CCu);
    EXPECT_EQ(packet.dw[0], 0x54300005u);
    EXPECT_EQ(packet.dw[1], 0x03F00A00u);
    EXPECT_EQ(packet.dw[2], 0x0014000Au);
    EXPECT_EQ(packet.dw[3], 0x0046006Eu);
    EXPECT_EQ(packet.dw[4], 0x12345000u);
    EXPECT_EQ(packet.dw[5], 0x00000000u);
    EXPECT_EQ(packet.dw[6], 0x003366CCu);

    static_assert(IsBltSurfaceGeometryValid(BltSurfaceGeometry{0x4000u, 64u, 64u, 256u, 32u}));
    static_assert(!IsBltRectValid(BltSurfaceGeometry{0x4000u, 64u, 64u, 256u, 32u}, 63u, 0u, 2u, 1u));

    return ::duetos_host_test::finish_main("intel_blt");
}
