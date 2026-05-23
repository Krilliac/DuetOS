#include "subsystems/graphics/graphics_vk_spirv.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "util/soft_float.h"

/*
 * DuetOS — SPIR-V interpreter boot self-test.
 *
 * Verifies the interpreter against a small set of hand-crafted
 * SPIR-V modules. Each module is the exact word stream a glslang
 * compile would emit for a trivial GLSL shader; the bytes are
 * baked here so the self-test doesn't depend on a runtime
 * compiler or a filesystem fetch.
 *
 * Cases:
 *   1. `const_color_frag` — a fragment shader that writes
 *      `vec4(0.5, 0.25, 0.75, 1.0)` to Location 0. Exercises
 *      OpConstant + OpConstantComposite + OpStore via a
 *      Location-decorated Output.
 *   2. `add_two_floats` — a vertex-shader-shaped module with a
 *      single function that loads two scalar Input floats by
 *      Location, adds them via OpFAdd, and stores the sum to a
 *      Location-decorated Output. Confirms the Sf32 add path
 *      threads through the executor end-to-end.
 *   3. `mul_vec3_scalar` — Output[0..2] = Input * 2.0. Exercises
 *      OpVectorTimesScalar + vector-form Output read.
 *
 * Each module's bytes are commented inline so a maintainer can
 * verify them against the SPIR-V spec word-by-word without
 * re-running glslang.
 */

namespace duetos::subsystems::graphics::spirv
{

namespace
{

using ::duetos::core::Sf32FromBits;
using ::duetos::core::Sf32ToBits;

void Fail(const char* msg, u32 v)
{
    arch::SerialWrite("[subsys/graphics/spirv] FAIL ");
    arch::SerialWrite(msg);
    arch::SerialWrite(" v=");
    arch::SerialWriteHex(v);
    arch::SerialWrite("\n");
    ::duetos::core::Panic("subsys/graphics/spirv", "interpreter self-test regression");
}

// ------------------------------------------------------------------
// Module 1: fragment shader emitting a constant vec4 colour.
//
// GLSL equivalent:
//   #version 450
//   layout(location = 0) out vec4 outColor;
//   void main() { outColor = vec4(0.5, 0.25, 0.75, 1.0); }
//
// SPIR-V (assembled by hand from SPIRV-Headers numbering):
//   Header: magic, version 1.0 (0x00010000), generator 0,
//           bound 17, schema 0.
//   1: OpCapability Shader
//   3: OpMemoryModel Logical GLSL450
//   4: OpEntryPoint Fragment %4 "main" %outColor
//   2: OpExecutionMode %4 OriginUpperLeft
//   3: OpDecorate %outColor Location 0
//   2: OpTypeVoid -> %2
//   3: OpTypeFunction %2 -> %3
//   3: OpTypeFloat 32 -> %6
//   4: OpTypeVector %6 4 -> %7
//   4: OpTypePointer Output %7 -> %8
//   4: OpVariable %8 Output -> %outColor (%9)
//   4: OpConstant %6 0.5 -> %10
//   4: OpConstant %6 0.25 -> %11
//   4: OpConstant %6 0.75 -> %12
//   4: OpConstant %6 1.0 -> %13
//   7: OpConstantComposite %7 %10 %11 %12 %13 -> %14
//   5: OpFunction %2 None %3 -> %4 (main)
//   2: OpLabel -> %15
//   3: OpStore %9 %14
//   1: OpReturn
//   1: OpFunctionEnd
constexpr u32 const_color_frag[] = {
    0x07230203,
    0x00010000,
    0x00000000,
    17u,
    0u,
    // OpCapability Shader (wc=2, op=17): 17|2<<16 = 0x00020011
    (2u << 16) | 17u,
    1u, // Shader = 1
    // OpMemoryModel Logical(0) GLSL450(1) (wc=3, op=14)
    (3u << 16) | 14u,
    0u,
    1u,
    // OpEntryPoint Fragment(4) %4 "main" %9 (wc=5: opcode word + 3 fixed + 1 interface)
    // String "main" packed: 'm','a','i','n','\0','\0','\0','\0' -> 0x6E69616D 0x00000000
    (6u << 16) | 15u,
    4u,
    4u,
    0x6E69616Du,
    0x00000000u,
    9u,
    // OpExecutionMode %4 OriginUpperLeft(7) (wc=3, op=16)
    (3u << 16) | 16u,
    4u,
    7u,
    // OpDecorate %9 Location(30) 0 (wc=4, op=71)
    (4u << 16) | 71u,
    9u,
    30u,
    0u,
    // OpTypeVoid %2 (wc=2, op=19)
    (2u << 16) | 19u,
    2u,
    // OpTypeFunction %3 %2 (wc=3, op=33)
    (3u << 16) | 33u,
    3u,
    2u,
    // OpTypeFloat %6 32 (wc=3, op=22)
    (3u << 16) | 22u,
    6u,
    32u,
    // OpTypeVector %7 %6 4 (wc=4, op=23)
    (4u << 16) | 23u,
    7u,
    6u,
    4u,
    // OpTypePointer %8 Output(3) %7 (wc=4, op=32)
    (4u << 16) | 32u,
    8u,
    3u,
    7u,
    // OpVariable %8 %9 Output(3) (wc=4, op=59)
    (4u << 16) | 59u,
    8u,
    9u,
    3u,
    // OpConstant %6 %10 0.5 (= 0x3F000000) (wc=4, op=43)
    (4u << 16) | 43u,
    6u,
    10u,
    0x3F000000u,
    // OpConstant %6 %11 0.25 (= 0x3E800000)
    (4u << 16) | 43u,
    6u,
    11u,
    0x3E800000u,
    // OpConstant %6 %12 0.75 (= 0x3F400000)
    (4u << 16) | 43u,
    6u,
    12u,
    0x3F400000u,
    // OpConstant %6 %13 1.0 (= 0x3F800000)
    (4u << 16) | 43u,
    6u,
    13u,
    0x3F800000u,
    // OpConstantComposite %7 %14 %10 %11 %12 %13 (wc=7, op=44)
    (7u << 16) | 44u,
    7u,
    14u,
    10u,
    11u,
    12u,
    13u,
    // OpFunction %2 %4 None(0) %3 (wc=5, op=54)
    (5u << 16) | 54u,
    2u,
    4u,
    0u,
    3u,
    // OpLabel %15 (wc=2, op=248)
    (2u << 16) | 248u,
    15u,
    // OpStore %9 %14 (wc=3, op=62)
    (3u << 16) | 62u,
    9u,
    14u,
    // OpReturn (wc=1, op=253)
    (1u << 16) | 253u,
    // OpFunctionEnd (wc=1, op=56)
    (1u << 16) | 56u,
};

// Run the const-color test against a Program parsed from the
// bytes above.
void TestConstColor()
{
    static Program prog;
    const u32 wc = sizeof(const_color_frag) / sizeof(const_color_frag[0]);
    if (!Parse(const_color_frag, wc, &prog))
        Fail("const_color: Parse rejected", wc);
    if (prog.entry_point_count != 1)
        Fail("const_color: wrong entry point count", prog.entry_point_count);
    if (prog.entry_points[0].execution_model != execution_models::kFragment)
        Fail("const_color: wrong execution model", prog.entry_points[0].execution_model);
    if (prog.function_count != 1)
        Fail("const_color: wrong function count", prog.function_count);

    ResetIO(&prog);
    if (!ExecuteEntryPoint(&prog, "main"))
        Fail("const_color: ExecuteEntryPoint returned false", 0);

    u32 out_color[4] = {0, 0, 0, 0};
    if (!ReadOutputLocation(&prog, 0, out_color, sizeof(out_color)))
        Fail("const_color: ReadOutputLocation 0 missing", 0);
    if (out_color[0] != 0x3F000000u)
        Fail("const_color: r mismatch", out_color[0]);
    if (out_color[1] != 0x3E800000u)
        Fail("const_color: g mismatch", out_color[1]);
    if (out_color[2] != 0x3F400000u)
        Fail("const_color: b mismatch", out_color[2]);
    if (out_color[3] != 0x3F800000u)
        Fail("const_color: a mismatch", out_color[3]);
}

// ------------------------------------------------------------------
// Module 2: add two scalar float inputs into a scalar output.
//
// GLSL equivalent:
//   #version 450
//   layout(location = 0) in  float a;
//   layout(location = 1) in  float b;
//   layout(location = 0) out float r;
//   void main() { r = a + b; }
constexpr u32 add_two_floats[] = {
    0x07230203, 0x00010000, 0u, 20u, 0u, (2u << 16) | 17u, 1u, // Capability Shader
    (3u << 16) | 14u, 0u, 1u,                                  // MemoryModel Logical GLSL450
    // EntryPoint Vertex(0) %4 "main" %a %b %r — interface 3 vars (a=10, b=11, r=12)
    (8u << 16) | 15u, 0u, 4u, 0x6E69616Du, 0u, 10u, 11u, 12u, (4u << 16) | 71u, 10u, 30u, 0u, // Decorate %a Location 0
    (4u << 16) | 71u, 11u, 30u, 1u,                                                           // Decorate %b Location 1
    (4u << 16) | 71u, 12u, 30u, 0u,                                                           // Decorate %r Location 0
    (2u << 16) | 19u, 2u,                                                                     // TypeVoid
    (3u << 16) | 33u, 3u, 2u,                                                                 // TypeFunction () -> void
    (3u << 16) | 22u, 6u, 32u,                                                                // TypeFloat 32
    (4u << 16) | 32u, 7u, 1u, 6u,                                                             // TypePointer Input %6
    (4u << 16) | 32u, 8u, 3u, 6u,                                                             // TypePointer Output %6
    (4u << 16) | 59u, 7u, 10u, 1u,                                                            // Variable %a Input
    (4u << 16) | 59u, 7u, 11u, 1u,                                                            // Variable %b Input
    (4u << 16) | 59u, 8u, 12u, 3u,                                                            // Variable %r Output
    (5u << 16) | 54u, 2u, 4u, 0u, 3u,                                                         // Function main
    (2u << 16) | 248u, 15u,                                                                   // Label
    (4u << 16) | 61u, 6u, 16u, 10u,                                                           // %16 = Load %a
    (4u << 16) | 61u, 6u, 17u, 11u,                                                           // %17 = Load %b
    (5u << 16) | 129u, 6u, 18u, 16u, 17u,                                                     // %18 = FAdd %16 %17
    (3u << 16) | 62u, 12u, 18u,                                                               // Store %r %18
    (1u << 16) | 253u,                                                                        // Return
    (1u << 16) | 56u,                                                                         // FunctionEnd
};

void TestAddTwoFloats()
{
    static Program prog;
    const u32 wc = sizeof(add_two_floats) / sizeof(add_two_floats[0]);
    if (!Parse(add_two_floats, wc, &prog))
        Fail("add_floats: Parse rejected", wc);

    // Inputs: a=1.5 (0x3FC00000), b=2.25 (0x40100000). Expected r=3.75
    // (0x40700000).
    ResetIO(&prog);
    const u32 a_bits = 0x3FC00000u;
    const u32 b_bits = 0x40100000u;
    if (!WriteInputLocation(&prog, 0, &a_bits, sizeof(a_bits)))
        Fail("add_floats: WriteInputLocation 0 missing", 0);
    if (!WriteInputLocation(&prog, 1, &b_bits, sizeof(b_bits)))
        Fail("add_floats: WriteInputLocation 1 missing", 0);

    if (!ExecuteEntryPoint(&prog, "main"))
        Fail("add_floats: ExecuteEntryPoint returned false", 0);

    u32 r_bits = 0;
    if (!ReadOutputLocation(&prog, 0, &r_bits, sizeof(r_bits)))
        Fail("add_floats: ReadOutputLocation 0 missing", 0);
    // Tolerate any IEEE 754 form of 3.75 — the Sf32 implementation
    // is exact for representable values, so a strict bit compare
    // is the right check.
    if (r_bits != 0x40700000u)
        Fail("add_floats: 1.5+2.25 should be 3.75", r_bits);
}

// ------------------------------------------------------------------
// Module 3: vec3 * scalar.
//
// GLSL equivalent:
//   #version 450
//   layout(location = 0) in  vec3 v;
//   layout(location = 0) out vec3 r;
//   void main() { r = v * 2.0; }
constexpr u32 mul_vec3_scalar[] = {
    0x07230203,
    0x00010000,
    0u,
    25u,
    0u,
    (2u << 16) | 17u,
    1u,
    (3u << 16) | 14u,
    0u,
    1u,
    (7u << 16) | 15u,
    0u,
    4u,
    0x6E69616Du,
    0u,
    10u,
    11u, // EntryPoint Vertex main %v %r
    (4u << 16) | 71u,
    10u,
    30u,
    0u, // Decorate %v Location 0
    (4u << 16) | 71u,
    11u,
    30u,
    0u, // Decorate %r Location 0
    (2u << 16) | 19u,
    2u, // TypeVoid
    (3u << 16) | 33u,
    3u,
    2u, // TypeFunction () -> void
    (3u << 16) | 22u,
    6u,
    32u, // TypeFloat 32
    (4u << 16) | 23u,
    7u,
    6u,
    3u, // TypeVector vec3
    (4u << 16) | 32u,
    8u,
    1u,
    7u, // TypePointer Input vec3
    (4u << 16) | 32u,
    9u,
    3u,
    7u, // TypePointer Output vec3
    (4u << 16) | 59u,
    8u,
    10u,
    1u, // Variable %v Input
    (4u << 16) | 59u,
    9u,
    11u,
    3u, // Variable %r Output
    (4u << 16) | 43u,
    6u,
    12u,
    0x40000000u, // Constant 2.0
    (5u << 16) | 54u,
    2u,
    4u,
    0u,
    3u, // Function main
    (2u << 16) | 248u,
    15u, // Label
    (4u << 16) | 61u,
    7u,
    16u,
    10u, // %16 = Load %v
    (5u << 16) | 142u,
    7u,
    17u,
    16u,
    12u, // %17 = VectorTimesScalar %16 %12
    (3u << 16) | 62u,
    11u,
    17u,               // Store %r %17
    (1u << 16) | 253u, // Return
    (1u << 16) | 56u,  // FunctionEnd
};

void TestMulVec3Scalar()
{
    static Program prog;
    const u32 wc = sizeof(mul_vec3_scalar) / sizeof(mul_vec3_scalar[0]);
    if (!Parse(mul_vec3_scalar, wc, &prog))
        Fail("mul_vec3: Parse rejected", wc);

    // Input v = (1.0, 2.0, 3.0). Expected r = (2.0, 4.0, 6.0).
    ResetIO(&prog);
    const u32 v_bits[3] = {0x3F800000u, 0x40000000u, 0x40400000u};
    if (!WriteInputLocation(&prog, 0, v_bits, sizeof(v_bits)))
        Fail("mul_vec3: WriteInputLocation 0 missing", 0);

    if (!ExecuteEntryPoint(&prog, "main"))
        Fail("mul_vec3: ExecuteEntryPoint returned false", 0);

    u32 r_bits[3] = {0, 0, 0};
    if (!ReadOutputLocation(&prog, 0, r_bits, sizeof(r_bits)))
        Fail("mul_vec3: ReadOutputLocation 0 missing", 0);
    if (r_bits[0] != 0x40000000u)
        Fail("mul_vec3: r.x should be 2.0", r_bits[0]);
    if (r_bits[1] != 0x40800000u)
        Fail("mul_vec3: r.y should be 4.0", r_bits[1]);
    if (r_bits[2] != 0x40C00000u)
        Fail("mul_vec3: r.z should be 6.0", r_bits[2]);
}

} // namespace

void SelfTest()
{
    TestConstColor();
    TestAddTwoFloats();
    TestMulVec3Scalar();
    arch::SerialWrite("[subsys/graphics/spirv] self-test PASS (3 modules executed)\n");
}

} // namespace duetos::subsystems::graphics::spirv
