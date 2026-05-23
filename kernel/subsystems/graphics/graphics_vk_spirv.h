#pragma once

#include "util/soft_float.h"
#include "util/types.h"

/*
 * DuetOS — SPIR-V interpreter (graphics_vk subsystem).
 *
 * Translates a SPIR-V module into a typed program graph at
 * `VkCreateShaderModule` time, then executes one entry point per
 * call. The interpreter is the gating piece between the existing
 * fixed-function CPU rasterizer (which paints colour-per-vertex
 * fed via the DuetOS v0/v1 vertex format) and an actual Vulkan
 * implementation that runs caller-supplied shaders.
 *
 * Scope (v1):
 *   - Parses the canonical subset described in
 *     `wiki/subsystems/Vulkan-ICD.md` §"SPIR-V interpreter": types
 *     (Bool, Int, Float, Vector, Array, Struct, Pointer, Function),
 *     constants, variables in every storage class we care about
 *     (Input, Output, UniformConstant, Uniform, PushConstant,
 *     Function, Private), decorations (Location, BuiltIn, Block,
 *     Offset, ArrayStride, MatrixStride), entry points, function
 *     bodies (basic blocks).
 *   - Executes arithmetic (Int + Float via `util::soft_float`),
 *     vector/composite ops, conversions, comparisons, control
 *     flow (Branch, BranchConditional, Phi, Return), memory ops
 *     (Load, Store, AccessChain), the GLSL.std.450 sub-set the
 *     shader interpreter needs (Sqrt, FMin, FMax, FClamp, FMix,
 *     Step, Sin, Cos, Pow, Length, Normalize, Dot — Dot is core).
 *   - Per-entry-point I/O binding: maps Input variables to the
 *     caller-supplied vertex-attribute fetch, Output variables to
 *     the rasterizer/output buffer.
 *
 * Out of scope (v1):
 *   - Texture sampling (no descriptor-set fetch path in the v0
 *     rasterizer to consume samples).
 *   - Geometry / tessellation / mesh / task shaders.
 *   - Compute shaders bigger than 1 workgroup of 1 thread.
 *   - Subgroup / wave intrinsics.
 *   - Atomics, barriers (no real parallelism in this v1 — every
 *     shader invocation is serialised on the CPU rasterizer).
 *   - Matrix types beyond what GLSL `mat4 * vec4` needs
 *     (OpMatrixTimesVector handled; other matrix ops are GAP).
 *
 * Context: kernel. Allocates parsed-program storage through
 * `mm::KMalloc` (the same backing as `ShaderRecord`); freed in
 * the matching `VkDestroyShaderModule` path.
 *
 * Reference: https://registry.khronos.org/SPIR-V/specs/unified1/SPIRV.html
 * Opcode + decoration numbering: SPIRV-Headers (KhronosGroup).
 */

namespace duetos::subsystems::graphics::spirv
{

// SPIR-V "kind" tags for entries in the id table. One id maps to
// at most one entity of one kind. The interpreter switches on
// these to dispatch loads / stores / arithmetic.
enum class IdKind : u8
{
    None = 0,
    Type,     // Type definition (TypeRecord)
    Constant, // Constant value
    Variable, // OpVariable (per-storage-class memory)
    Function, // Function definition
    Label,    // Basic-block label
    Param,    // OpFunctionParameter
    ExtInst,  // OpExtInstImport (only GLSL.std.450 recognised)
};

// Type-kind tag inside the type table.
enum class TypeKind : u8
{
    Void = 0,
    Bool,
    Int,
    Float,
    Vector,
    Matrix,
    Array,
    Struct,
    Pointer,
    Function,
};

// Storage class — matches the SPIR-V enum verbatim.
enum class StorageClass : u8
{
    UniformConstant = 0,
    Input = 1,
    Uniform = 2,
    Output = 3,
    Private = 6,
    Function = 7,
    PushConstant = 9,
};

// Per-type record. Compact — the type table is fixed-size at
// `kMaxIds`. For composite types (Vector, Matrix, Array, Struct,
// Pointer, Function) the row holds component types as id refs
// into the same table.
struct TypeRecord
{
    TypeKind kind;
    u32 width;              // Int/Float: bit width (8/16/32/64). 32 only in v1.
    u32 signedness;         // Int: 0=unsigned, 1=signed.
    u32 component_id;       // Vector/Matrix/Array element type id. Pointer pointee id.
    u32 component_count;    // Vector dim, Matrix column count, Array length (resolved from OpConstant).
    StorageClass ptr_class; // Pointer storage class.
    u32 member_count;       // Struct member count (max kMaxStructMembers).
    u32 members[16];        // Struct member type ids.
    u32 member_offsets[16]; // Decorated byte offsets (0 if undecorated).
    u32 return_id;          // Function return type id (Function only).
    u32 param_count;        // Function param count (max kMaxFnParams).
    u32 params[8];          // Function param type ids.
    u32 byte_size;          // Pre-computed total byte size for fast allocation.
};

// A single scalar value in the interpreter — either a 32-bit int
// bit pattern, an Sf32 bit pattern, or a bool. Vectors are
// stored as a stride of `Value`s in the SSA table.
struct Value
{
    u32 bits; // The actual data — interpret per associated type.
};

// A constant is identified by a type-id + a vector of Values
// (one Value per scalar component, in row-major order for matrices
// and natural-order for vectors / arrays).
struct ConstantRecord
{
    u32 type_id;
    u32 component_count; // 1 for scalar, N for vector/array/struct.
    Value components[16];
};

// A variable — per-storage-class memory backing. The interpreter
// keeps separate flat heaps for each storage class; this record
// just names the offset.
struct VariableRecord
{
    u32 type_id;
    StorageClass storage;
    u32 storage_offset; // Byte offset into the per-storage backing buffer.
    u32 byte_size;
    u32 initializer_id; // OpConstant id, or 0.
    u32 location;       // -1 if undecorated; else the OpDecorate Location value.
    u32 builtin;        // 0xFFFFFFFF if undecorated; else the BuiltIn enum value.
};

// Basic block — a label id + a (begin, end) range into the
// instruction table.
struct BasicBlockRecord
{
    u32 label_id;
    u32 instr_begin; // Inclusive index into Program::instructions[].
    u32 instr_end;   // Exclusive end.
};

// One parsed instruction. The full word-stream is kept as a flat
// `u32[]` so we don't duplicate the operand storage; this row
// records the opcode, the start of the operand window, and any
// pre-resolved type/result ids for fast dispatch.
struct InstructionRecord
{
    u16 opcode;
    u16 word_count;
    u32 operands_word_offset; // Index into Program::words[].
    u32 type_id;              // Pre-resolved IdResultType (0 if absent).
    u32 result_id;            // Pre-resolved IdResult (0 if absent).
};

// Function definition: id, parameter list, basic blocks.
struct FunctionRecord
{
    u32 result_id;
    u32 type_id;
    u32 param_count;
    u32 params[8];
    u32 bb_begin; // Inclusive index into Program::blocks[].
    u32 bb_end;   // Exclusive.
};

// Entry-point manifest entry: matches one OpEntryPoint.
struct EntryPointRecord
{
    u32 function_id;
    u32 execution_model; // Vertex=0, TessControl=1, TessEvaluation=2, Geometry=3, Fragment=4, Compute=5.
    char name[32];
    u32 interface_count; // Number of Input/Output vars below.
    u32 interface_ids[16];
};

// Fixed-size capacity for the parser. SPIR-V modules from a
// glslangValidator pass of a trivial shader top out around
// ~200 ids and ~150 instructions; we round up.
inline constexpr u32 kMaxIds = 512;
inline constexpr u32 kMaxInstructions = 1024;
inline constexpr u32 kMaxBasicBlocks = 64;
inline constexpr u32 kMaxFunctions = 16;
inline constexpr u32 kMaxEntryPoints = 4;
inline constexpr u32 kMaxConstants = 128;
inline constexpr u32 kMaxVariables = 64;
inline constexpr u32 kMaxStorageBytes = 4096; // per storage-class backing buffer

// Per-storage-class heap. Variables get assigned an offset at
// parse time; loads/stores resolve via VariableRecord::storage_offset.
struct StorageHeap
{
    u8 bytes[kMaxStorageBytes];
    u32 used;
};

// Parsed program. Owned by ShaderRecord; freed in
// VkDestroyShaderModule. Sized for one trivial shader; bigger
// modules are rejected with `parse_ok=false` and the existing
// ShaderModuleInfo counters still see the entry-point/decoration
// summary so diagnostics aren't lost.
struct Program
{
    bool parse_ok;

    // Flat word stream — we keep a copy so AccessChain index
    // resolution can peek at the operand words.
    const u32* words; // borrowed, not owned (points into ShaderRecord-side blob)
    u32 word_count;

    IdKind id_kinds[kMaxIds];
    u32 id_to_index[kMaxIds]; // index into the matching table for the id's kind

    TypeRecord types[kMaxIds];
    ConstantRecord constants[kMaxConstants];
    VariableRecord variables[kMaxVariables];
    BasicBlockRecord blocks[kMaxBasicBlocks];
    InstructionRecord instructions[kMaxInstructions];
    FunctionRecord functions[kMaxFunctions];
    EntryPointRecord entry_points[kMaxEntryPoints];

    u32 type_count;
    u32 constant_count;
    u32 variable_count;
    u32 block_count;
    u32 instruction_count;
    u32 function_count;
    u32 entry_point_count;

    u32 ext_inst_glsl_id; // id of the OpExtInstImport "GLSL.std.450", 0 if absent

    // Per-storage-class backing memory.
    StorageHeap input;
    StorageHeap output;
    StorageHeap uniform_constant;
    StorageHeap uniform;
    StorageHeap push_constant;
    StorageHeap private_storage;
};

// Parse a SPIR-V module into Program form. Returns true if the
// module conformed to the v1 subset; false on any structural
// issue. `prog->parse_ok` mirrors the return value.
bool Parse(const u32* words, u32 word_count, Program* prog);

// Bind input data for the next ExecuteEntryPoint call. The
// `data` pointer is copied into the per-storage-class backing
// for the named Location (vertex shaders) or BuiltIn slot
// (fragment shaders read interpolated values into matching
// Inputs; the rasterizer fills those before invoking).
//
// For vertex shaders: bind one call per attribute location with
// `data` pointing at the attribute's per-vertex value (`vec3` =
// 12 bytes, etc.).
// For fragment shaders: bind one call per varying location.
bool WriteInputLocation(Program* prog, u32 location, const void* data, u32 byte_size);

// After ExecuteEntryPoint, fetch the value of an Output by
// Location. Returns true if such an output exists and fits in
// `byte_size`. For vertex shaders, location-decorated Outputs
// are varyings; the BuiltIn-Position output is fetched via
// ReadOutputBuiltin (below).
bool ReadOutputLocation(const Program* prog, u32 location, void* out, u32 byte_size);

// Fetch a BuiltIn-decorated Output (e.g. gl_Position written by
// a vertex shader; gl_FragDepth written by a fragment shader).
// Returns true if the BuiltIn was written.
bool ReadOutputBuiltin(const Program* prog, u32 builtin, void* out, u32 byte_size);

// Write a BuiltIn-decorated Input (e.g. gl_FragCoord for a
// fragment shader). Mostly used by the rasterizer hook to feed
// per-pixel coordinates.
bool WriteInputBuiltin(Program* prog, u32 builtin, const void* data, u32 byte_size);

// Reset Input/Output storage between invocations without
// reparsing the program. Call once per vkCmdDraw replay before
// the per-vertex/per-pixel loop.
void ResetIO(Program* prog);

/// Per-variable descriptor returned by `EnumerateLocationVars`:
/// the Location number, the byte size of the variable's pointee,
/// and the number of 32-bit components (size / 4 for the common
/// case but tracked separately so the interpolation loop knows
/// how many lanes to walk).
struct LocationVar
{
    u32 location;
    u32 byte_size;
    u32 component_count;
};

/// Enumerate Variable records that match a storage class (Input
/// or Output) AND carry an explicit Location decoration. Writes
/// up to `cap` entries into `out`; returns the count actually
/// written. Used by the rasterizer hook to discover the
/// vertex/fragment varying layout without re-walking the SPIR-V
/// word stream.
u32 EnumerateLocationVars(const Program* prog, StorageClass storage, LocationVar* out, u32 cap);

// Execute the named entry point. Returns true on a clean
// completion (OpReturn reached), false on out-of-budget /
// malformed instruction / unsupported opcode.
bool ExecuteEntryPoint(Program* prog, const char* name);

// Public SPIR-V BuiltIn enum values that the interpreter
// recognises and the rasterizer hook needs to reference.
namespace builtins
{
inline constexpr u32 kPosition = 0;
inline constexpr u32 kPointSize = 1;
inline constexpr u32 kFragCoord = 15;
inline constexpr u32 kFragDepth = 22;
inline constexpr u32 kVertexIndex = 42;
inline constexpr u32 kInstanceIndex = 43;
} // namespace builtins

namespace execution_models
{
inline constexpr u32 kVertex = 0;
inline constexpr u32 kFragment = 4;
inline constexpr u32 kGLCompute = 5;
} // namespace execution_models

/// Boot self-test. Parses + executes three canonical SPIR-V
/// modules (constant fragment colour; scalar Float add;
/// vec3 * scalar) and asserts the outputs. Panics on
/// regression. Wired into boot_bringup.cpp behind
/// DUETOS_BOOT_SELFTEST so it runs once at boot and emits
/// `[subsys/graphics/spirv] self-test PASS (3 modules
/// executed)`.
void SelfTest();

} // namespace duetos::subsystems::graphics::spirv
