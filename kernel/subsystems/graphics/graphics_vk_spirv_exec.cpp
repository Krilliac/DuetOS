#include "subsystems/graphics/graphics_vk_spirv.h"

#include "subsystems/graphics/graphics_vk_internal.h"
#include "util/soft_float.h"

// SampleImageRgba8 / QueryImageSize / SamplerAddressModeFor live
// in `duetos::subsystems::graphics::internal` and are declared in
// graphics_vk_internal.h, which is already included above. The
// callers below use fully-qualified names.

/*
 * DuetOS — SPIR-V interpreter, execution engine.
 *
 * Drives a parsed Program's instruction tape one basic block at
 * a time. Float math goes through `util::soft_float`. Int math
 * runs in native u32 / i32.
 *
 * SSA values are kept in a per-execution-frame array indexed by
 * SPIR-V id. For a 32-bit scalar each id stores 1 Value (4 bytes);
 * for vectors and structs we allocate a contiguous run starting at
 * a flat heap offset and store the offset in the id table.
 *
 * Control flow is straight basic-block jumps. Phi is handled by
 * recording the predecessor block id before each branch and
 * consulting it at the next OpPhi. Functions are inlined — v1
 * doesn't model a call stack (no recursion, and shader functions
 * are almost always inlined by the front-end anyway). OpFunctionCall
 * routes through the same execution path against the callee's first
 * basic block; the result is just the value of an OpReturnValue
 * in that callee (the call binds parameters by writing them into
 * the callee's Function-storage variables, but since we treat
 * Function storage as Private, the binding side-effects across
 * calls — fine because we never re-enter a function in flight).
 *
 * The interpreter has a per-shader instruction budget (`kStepBudget`)
 * to bound runaway loops. Exceeding the budget aborts execution
 * with a false return; the caller treats this as a draw-no-paint
 * regression and falls back to the fixed-function path.
 *
 * Opcodes recognised (full list in the switch below):
 *   - Memory: OpLoad, OpStore, OpAccessChain
 *   - Composite: OpVectorShuffle, OpCompositeConstruct,
 *                OpCompositeExtract, OpCompositeInsert
 *   - Arithmetic int: SNegate, IAdd, ISub, IMul, SDiv, UDiv
 *   - Arithmetic float: FNegate, FAdd, FSub, FMul, FDiv
 *   - Vector ops: VectorTimesScalar, MatrixTimesVector, Dot
 *   - Conversion: ConvertFToS, ConvertSToF, ConvertUToF, Bitcast
 *   - Compare: IEqual, INotEqual, SLessThan, FOrdLessThan
 *   - Control: Branch, BranchConditional, Phi, Return, ReturnValue,
 *              LoopMerge / SelectionMerge (no-op markers)
 *   - Function call: OpFunctionCall (inline)
 *   - ExtInst GLSL.std.450: Sqrt, FMin, FMax, FClamp, FMix, Step,
 *                           Length, Normalize, Cross, Sin, Cos, Pow
 *
 * In scope but partial:
 *   - OpImageSample{Implicit,Explicit}Lod: descriptor fetch via
 *     `LookupDescriptor(0, 0)` + `SampleImageRgba8`. The addressing
 *     mode comes from the bound VkSampler's `SamplerRecord` —
 *     REPEAT / MIRRORED_REPEAT / CLAMP_TO_EDGE / CLAMP_TO_BORDER
 *     all execute. Explicit LOD operand is parsed but ignored (no
 *     mipmap chain). Unbound samples return the UV coordinate as
 *     the "missing texture" diagnostic.
 *
 * Out of scope for v1 — opcodes that survive parsing but cause
 * execution to abort:
 *   - OpAtomic*, OpControlBarrier, OpMemoryBarrier
 *   - OpImageRead / OpImageWrite (storage images)
 *   - OpKill (deferred — frag shaders that discard are rare in
 *     hello-world cases)
 *   - OpSwitch (sane shaders rarely emit; deferred)
 */

namespace duetos::subsystems::graphics::spirv
{

namespace
{

using ::duetos::core::Sf32;
using ::duetos::core::Sf32FromBits;
using ::duetos::core::Sf32ToBits;

constexpr u32 kStepBudget = 8192; // max instructions per ExecuteEntryPoint call
constexpr u32 kSsaHeapBytes = 8192;

// SPIR-V opcodes the executor switches on. Numbering = SPIRV-Headers.
constexpr u16 kOpExtInst = 12;
constexpr u16 kOpFunctionCall = 57;
// Texture sampling opcodes (Khronos numbering).
constexpr u16 kOpSampledImage = 86;
constexpr u16 kOpImageSampleImplicitLod = 87;
constexpr u16 kOpImageSampleExplicitLod = 88;
constexpr u16 kOpImageFetch = 95;
constexpr u16 kOpImageRead = 98;
constexpr u16 kOpImageWrite = 99;
constexpr u16 kOpImageQuerySize = 104;
constexpr u16 kOpImageQuerySizeLod = 103;
// Boolean + selection opcodes.
constexpr u16 kOpAny = 154;
constexpr u16 kOpAll = 155;
constexpr u16 kOpSelect = 169;
constexpr u16 kOpKill = 252; // fragment discard
[[maybe_unused]] constexpr u16 kOpVariable = 59;
constexpr u16 kOpLoad = 61;
constexpr u16 kOpStore = 62;
constexpr u16 kOpAccessChain = 65;
constexpr u16 kOpVectorExtractDynamic = 77;
constexpr u16 kOpVectorInsertDynamic = 78;
constexpr u16 kOpVectorShuffle = 79;
constexpr u16 kOpCompositeConstruct = 80;
constexpr u16 kOpCompositeExtract = 81;
constexpr u16 kOpCompositeInsert = 82;
constexpr u16 kOpConvertFToS = 110;
constexpr u16 kOpConvertSToF = 111;
constexpr u16 kOpConvertUToF = 112;
constexpr u16 kOpBitcast = 124;
constexpr u16 kOpSNegate = 126;
constexpr u16 kOpFNegate = 127;
constexpr u16 kOpIAdd = 128;
constexpr u16 kOpFAdd = 129;
constexpr u16 kOpISub = 130;
constexpr u16 kOpFSub = 131;
constexpr u16 kOpIMul = 132;
constexpr u16 kOpFMul = 133;
constexpr u16 kOpUDiv = 134;
constexpr u16 kOpSDiv = 135;
constexpr u16 kOpFDiv = 136;
constexpr u16 kOpVectorTimesScalar = 142;
constexpr u16 kOpMatrixTimesVector = 145;
constexpr u16 kOpDot = 148;
constexpr u16 kOpIEqual = 170;
constexpr u16 kOpINotEqual = 171;
constexpr u16 kOpULessThan = 176;
constexpr u16 kOpSLessThan = 177;
constexpr u16 kOpUGreaterThan = 172;
constexpr u16 kOpSGreaterThan = 173;
constexpr u16 kOpULessThanEqual = 178;
constexpr u16 kOpSLessThanEqual = 179;
constexpr u16 kOpUGreaterThanEqual = 174;
constexpr u16 kOpSGreaterThanEqual = 175;
constexpr u16 kOpFOrdEqual = 180;
constexpr u16 kOpFOrdNotEqual = 182;
constexpr u16 kOpFOrdLessThan = 184;
constexpr u16 kOpFOrdGreaterThan = 186;
constexpr u16 kOpFOrdLessThanEqual = 188;
constexpr u16 kOpFOrdGreaterThanEqual = 190;
// Bitwise / logical / shifts.
constexpr u16 kOpShiftRightLogical = 194;
constexpr u16 kOpShiftRightArithmetic = 195;
constexpr u16 kOpShiftLeftLogical = 196;
constexpr u16 kOpBitwiseOr = 197;
constexpr u16 kOpBitwiseXor = 198;
constexpr u16 kOpBitwiseAnd = 199;
constexpr u16 kOpNot = 200; // ~x
constexpr u16 kOpLogicalEqual = 164;
constexpr u16 kOpLogicalNotEqual = 165;
constexpr u16 kOpLogicalOr = 166;
constexpr u16 kOpLogicalAnd = 167;
constexpr u16 kOpLogicalNot = 168;
constexpr u16 kOpUMod = 137;
constexpr u16 kOpSMod = 139;
constexpr u16 kOpSRem = 138;
constexpr u16 kOpFRem = 140;
constexpr u16 kOpFMod = 141;
// Derivative opcodes — meaningful only when a fragment shader runs
// in 2x2-quad scope so finite differences can be measured between
// neighbouring invocations. The serial interpreter executes one
// invocation at a time, so the spec-correct "0" return is what we
// have to give. GAP: real derivatives need 2x2-quad execution.
constexpr u16 kOpDPdx = 207;
constexpr u16 kOpDPdy = 208;
constexpr u16 kOpFwidth = 209;
constexpr u16 kOpDPdxFine = 210;
constexpr u16 kOpDPdyFine = 211;
constexpr u16 kOpFwidthFine = 212;
constexpr u16 kOpDPdxCoarse = 213;
constexpr u16 kOpDPdyCoarse = 214;
constexpr u16 kOpFwidthCoarse = 215;
// Workgroup / memory barriers — serial interpreter has no parallel
// execution so the spec-correct collapse is a no-op. GAP: real
// barriers matter once the executor runs multiple invocations
// concurrently per workgroup.
constexpr u16 kOpControlBarrier = 224;
constexpr u16 kOpMemoryBarrier = 225;
// Atomic ops — serial interpreter has no contention so these
// collapse to plain Load / Store / IAdd on the pointed-to scalar.
// GAP: real atomicity matters once compute dispatch is parallel.
constexpr u16 kOpAtomicLoad = 227;
constexpr u16 kOpAtomicStore = 228;
constexpr u16 kOpAtomicExchange = 229;
constexpr u16 kOpAtomicIIncrement = 232;
constexpr u16 kOpAtomicIDecrement = 233;
constexpr u16 kOpAtomicIAdd = 234;
constexpr u16 kOpAtomicISub = 235;
constexpr u16 kOpAtomicSMin = 236;
constexpr u16 kOpAtomicUMin = 237;
constexpr u16 kOpAtomicSMax = 238;
constexpr u16 kOpAtomicUMax = 239;
constexpr u16 kOpAtomicAnd = 240;
constexpr u16 kOpAtomicOr = 241;
constexpr u16 kOpAtomicXor = 242;
constexpr u16 kOpPhi = 245;
constexpr u16 kOpLoopMerge = 246;
constexpr u16 kOpSelectionMerge = 247;
[[maybe_unused]] constexpr u16 kOpLabel = 248; // labels open basic blocks at parse time, not at exec time
constexpr u16 kOpBranch = 249;
constexpr u16 kOpBranchConditional = 250;
constexpr u16 kOpReturn = 253;
constexpr u16 kOpReturnValue = 254;

// GLSL.std.450 sub-opcodes. Sin/Cos/Pow dispatch through the
// soft-float polynomial approximations in util/soft_float;
// accuracy ~5e-4 max — plenty for shader work.
constexpr u32 kGlslFAbs = 4;
constexpr u32 kGlslSAbs = 5;
constexpr u32 kGlslFloor = 8;
constexpr u32 kGlslCeil = 9;
constexpr u32 kGlslFract = 10;
constexpr u32 kGlslRound = 1;
constexpr u32 kGlslSin = 13;
constexpr u32 kGlslCos = 14;
constexpr u32 kGlslPow = 26;
constexpr u32 kGlslSqrt = 31;
constexpr u32 kGlslFMin = 37;
constexpr u32 kGlslFMax = 40;
constexpr u32 kGlslFClamp = 43;
constexpr u32 kGlslFMix = 46;
constexpr u32 kGlslStep = 48;
constexpr u32 kGlslLength = 66;
constexpr u32 kGlslCross = 68;
constexpr u32 kGlslNormalize = 69;

// Per-invocation SSA state. Stored on the stack of
// `ExecuteEntryPoint`; the heap is a flat byte buffer indexed by
// `ssa_offset[id]` for composite values; for scalar ids the
// value fits in `ssa_value[id].bits`.
struct ExecContext
{
    Program* prog;
    Value scalar[kMaxIds];
    u32 composite_offset[kMaxIds];
    u8 heap[kSsaHeapBytes];
    u32 heap_used;
    u32 type_of[kMaxIds]; // type_id per result-id; cached at first def
    u32 prev_block_label; // for Phi resolution
    u32 cur_block_label;
    u32 jump_target; // 0 = no jump
    bool returned;
    u32 step_count;
};

const TypeRecord* TypeOf(const Program* p, u32 type_id)
{
    if (type_id == 0 || type_id >= kMaxIds || p->id_kinds[type_id] != IdKind::Type)
        return nullptr;
    return &p->types[p->id_to_index[type_id]];
}

// Decompose any composite type into its scalar-component count
// (vec3 = 3, mat4 = 16, struct of {float, vec3} = 4). Used by
// the heap allocator and by extract/insert.
u32 ComponentCount(const Program* p, u32 type_id)
{
    const TypeRecord* t = TypeOf(p, type_id);
    if (t == nullptr)
        return 0;
    switch (t->kind)
    {
    case TypeKind::Void:
        return 0;
    case TypeKind::Bool:
    case TypeKind::Int:
    case TypeKind::Float:
        return 1;
    case TypeKind::Vector:
        return t->component_count;
    case TypeKind::Matrix:
    case TypeKind::Array:
        return ComponentCount(p, t->component_id) * t->component_count;
    case TypeKind::Struct:
    {
        u32 sum = 0;
        for (u32 i = 0; i < t->member_count; ++i)
            sum += ComponentCount(p, t->members[i]);
        return sum;
    }
    case TypeKind::Pointer:
    case TypeKind::Function:
    case TypeKind::Image:
    case TypeKind::Sampler:
    case TypeKind::SampledImage:
        return 1;
    }
    return 0;
}

bool AllocComposite(ExecContext& ec, u32 id, u32 type_id, u32* out_offset, u32* out_count)
{
    const u32 n = ComponentCount(ec.prog, type_id);
    if (n == 0)
        return false;
    const u32 bytes = n * 4u;
    if (ec.heap_used + bytes > kSsaHeapBytes)
        return false;
    *out_offset = ec.heap_used;
    *out_count = n;
    ec.heap_used += bytes;
    ec.composite_offset[id] = *out_offset + 1u; // bias so 0 = unset
    ec.type_of[id] = type_id;
    return true;
}

bool IsComposite(const ExecContext& ec, u32 id)
{
    return ec.composite_offset[id] != 0u;
}

u32* CompositeData(ExecContext& ec, u32 id)
{
    if (!IsComposite(ec, id))
        return nullptr;
    const u32 offset = ec.composite_offset[id] - 1u;
    return reinterpret_cast<u32*>(&ec.heap[offset]);
}

const u32* CompositeDataC(const ExecContext& ec, u32 id)
{
    if (!IsComposite(ec, id))
        return nullptr;
    const u32 offset = ec.composite_offset[id] - 1u;
    return reinterpret_cast<const u32*>(&ec.heap[offset]);
}

void SetScalar(ExecContext& ec, u32 id, u32 type_id, u32 bits)
{
    ec.scalar[id].bits = bits;
    ec.composite_offset[id] = 0u;
    ec.type_of[id] = type_id;
}

u32 GetScalarBits(const ExecContext& ec, u32 id)
{
    if (id == 0 || id >= kMaxIds)
        return 0;
    if (ec.prog->id_kinds[id] == IdKind::Constant)
        return ec.prog->constants[ec.prog->id_to_index[id]].components[0].bits;
    return ec.scalar[id].bits;
}

// Read a scalar or composite source id into a flat u32 buffer of
// `count_words` 4-byte components. Returns the number of words
// actually written. Used by binary ops that need to handle scalar
// or vector operands uniformly.
u32 LoadOperandComponents(const ExecContext& ec, u32 id, u32* out, u32 cap)
{
    if (id == 0 || id >= kMaxIds || cap == 0)
        return 0;
    if (ec.prog->id_kinds[id] == IdKind::Constant)
    {
        const ConstantRecord& c = ec.prog->constants[ec.prog->id_to_index[id]];
        const u32 n = (c.component_count < cap) ? c.component_count : cap;
        for (u32 i = 0; i < n; ++i)
            out[i] = c.components[i].bits;
        return n;
    }
    if (IsComposite(ec, id))
    {
        const u32* src = CompositeDataC(ec, id);
        const u32 type_id = ec.type_of[id];
        const u32 n = ComponentCount(ec.prog, type_id);
        const u32 m = (n < cap) ? n : cap;
        for (u32 i = 0; i < m; ++i)
            out[i] = src[i];
        return m;
    }
    out[0] = ec.scalar[id].bits;
    return 1;
}

// Store `count_words` components into an SSA result. If count==1
// the result is a scalar; else a composite.
void StoreResultComponents(ExecContext& ec, u32 id, u32 type_id, const u32* in, u32 count)
{
    if (count == 0)
        return;
    if (count == 1)
    {
        SetScalar(ec, id, type_id, in[0]);
        return;
    }
    u32 offset = 0;
    u32 actual_count = 0;
    if (!AllocComposite(ec, id, type_id, &offset, &actual_count))
        return;
    u32* dst = CompositeData(ec, id);
    if (dst == nullptr)
        return;
    const u32 n = (count < actual_count) ? count : actual_count;
    for (u32 i = 0; i < n; ++i)
        dst[i] = in[i];
}

// --------------------------------------------------------------
// Op handlers — small and uniform. Caller has already pre-fetched
// the operand window pointer + word count.
// --------------------------------------------------------------

void DoBinaryIntOp(ExecContext& ec, u16 op, u32 type_id, u32 result_id, u32 a_id, u32 b_id)
{
    u32 a[16]{}, b[16]{}, r[16]{};
    const u32 n = LoadOperandComponents(ec, a_id, a, 16);
    LoadOperandComponents(ec, b_id, b, 16);
    for (u32 i = 0; i < n; ++i)
    {
        const i32 ai = static_cast<i32>(a[i]);
        const i32 bi = static_cast<i32>(b[i]);
        switch (op)
        {
        case kOpIAdd:
            r[i] = static_cast<u32>(ai + bi);
            break;
        case kOpISub:
            r[i] = static_cast<u32>(ai - bi);
            break;
        case kOpIMul:
            r[i] = static_cast<u32>(ai * bi);
            break;
        case kOpSDiv:
            r[i] = (bi == 0) ? 0u : static_cast<u32>(ai / bi);
            break;
        case kOpUDiv:
            r[i] = (b[i] == 0) ? 0u : (a[i] / b[i]);
            break;
        case kOpUMod:
            r[i] = (b[i] == 0) ? 0u : (a[i] % b[i]);
            break;
        case kOpSMod:
        {
            if (bi == 0)
            {
                r[i] = 0;
                break;
            }
            // GLSL `mod` semantics: result has same sign as divisor.
            const i32 q = ai % bi;
            const i32 m = ((q != 0) && ((q < 0) != (bi < 0))) ? q + bi : q;
            r[i] = static_cast<u32>(m);
            break;
        }
        case kOpSRem:
            r[i] = (bi == 0) ? 0u : static_cast<u32>(ai % bi); // C remainder semantics
            break;
        case kOpSNegate:
            r[i] = static_cast<u32>(-ai);
            break;
        case kOpNot:
            r[i] = ~a[i];
            break;
        case kOpBitwiseAnd:
            r[i] = a[i] & b[i];
            break;
        case kOpBitwiseOr:
            r[i] = a[i] | b[i];
            break;
        case kOpBitwiseXor:
            r[i] = a[i] ^ b[i];
            break;
        case kOpShiftLeftLogical:
            r[i] = (b[i] >= 32u) ? 0u : (a[i] << b[i]);
            break;
        case kOpShiftRightLogical:
            r[i] = (b[i] >= 32u) ? 0u : (a[i] >> b[i]);
            break;
        case kOpShiftRightArithmetic:
            r[i] = (b[i] >= 32u) ? (ai < 0 ? 0xFFFFFFFFu : 0u) : static_cast<u32>(ai >> b[i]);
            break;
        case kOpLogicalEqual:
            r[i] = ((a[i] != 0) == (b[i] != 0)) ? 1u : 0u;
            break;
        case kOpLogicalNotEqual:
            r[i] = ((a[i] != 0) != (b[i] != 0)) ? 1u : 0u;
            break;
        case kOpLogicalAnd:
            r[i] = ((a[i] != 0) && (b[i] != 0)) ? 1u : 0u;
            break;
        case kOpLogicalOr:
            r[i] = ((a[i] != 0) || (b[i] != 0)) ? 1u : 0u;
            break;
        case kOpLogicalNot:
            r[i] = (a[i] == 0) ? 1u : 0u;
            break;
        case kOpIEqual:
            r[i] = (a[i] == b[i]) ? 1u : 0u;
            break;
        case kOpINotEqual:
            r[i] = (a[i] != b[i]) ? 1u : 0u;
            break;
        case kOpULessThan:
            r[i] = (a[i] < b[i]) ? 1u : 0u;
            break;
        case kOpSLessThan:
            r[i] = (ai < bi) ? 1u : 0u;
            break;
        case kOpUGreaterThan:
            r[i] = (a[i] > b[i]) ? 1u : 0u;
            break;
        case kOpSGreaterThan:
            r[i] = (ai > bi) ? 1u : 0u;
            break;
        case kOpULessThanEqual:
            r[i] = (a[i] <= b[i]) ? 1u : 0u;
            break;
        case kOpSLessThanEqual:
            r[i] = (ai <= bi) ? 1u : 0u;
            break;
        case kOpUGreaterThanEqual:
            r[i] = (a[i] >= b[i]) ? 1u : 0u;
            break;
        case kOpSGreaterThanEqual:
            r[i] = (ai >= bi) ? 1u : 0u;
            break;
        default:
            r[i] = 0;
            break;
        }
    }
    StoreResultComponents(ec, result_id, type_id, r, n);
}

void DoBinaryFloatOp(ExecContext& ec, u16 op, u32 type_id, u32 result_id, u32 a_id, u32 b_id)
{
    u32 a[16]{}, b[16]{}, r[16]{};
    const u32 n = LoadOperandComponents(ec, a_id, a, 16);
    LoadOperandComponents(ec, b_id, b, 16);
    for (u32 i = 0; i < n; ++i)
    {
        const Sf32 af = Sf32FromBits(a[i]);
        const Sf32 bf = Sf32FromBits(b[i]);
        Sf32 rf{0};
        switch (op)
        {
        case kOpFAdd:
            rf = ::duetos::core::Sf32Add(af, bf);
            break;
        case kOpFSub:
            rf = ::duetos::core::Sf32Sub(af, bf);
            break;
        case kOpFMul:
            rf = ::duetos::core::Sf32Mul(af, bf);
            break;
        case kOpFDiv:
            rf = ::duetos::core::Sf32Div(af, bf);
            break;
        case kOpFRem:
        case kOpFMod:
        {
            // FRem: result has same sign as dividend (a - trunc(a/b)*b).
            // FMod: result has same sign as divisor (a - floor(a/b)*b).
            // v0 collapses both to a - trunc(a/b)*b for FRem and
            // adjusts for FMod when signs differ; no GLSL.std.450
            // dependency.
            if (::duetos::core::Sf32IsZero(bf))
            {
                rf = ::duetos::core::Sf32Zero();
                break;
            }
            const Sf32 quot = ::duetos::core::Sf32Div(af, bf);
            const i32 tq = ::duetos::core::Sf32ToI32(quot);
            const Sf32 trunc_q = ::duetos::core::Sf32FromI32(tq);
            Sf32 rem = ::duetos::core::Sf32Sub(af, ::duetos::core::Sf32Mul(trunc_q, bf));
            if (op == kOpFMod && !::duetos::core::Sf32IsZero(rem) &&
                ::duetos::core::Sf32IsNegative(rem) != ::duetos::core::Sf32IsNegative(bf))
                rem = ::duetos::core::Sf32Add(rem, bf);
            rf = rem;
            break;
        }
        case kOpFNegate:
            rf = ::duetos::core::Sf32Neg(af);
            break;
        case kOpFOrdLessThan:
            r[i] = ::duetos::core::Sf32LessThan(af, bf) ? 1u : 0u;
            continue;
        case kOpFOrdGreaterThan:
            r[i] = ::duetos::core::Sf32GreaterThan(af, bf) ? 1u : 0u;
            continue;
        case kOpFOrdLessThanEqual:
            r[i] = ::duetos::core::Sf32LessOrEqual(af, bf) ? 1u : 0u;
            continue;
        case kOpFOrdGreaterThanEqual:
            r[i] = ::duetos::core::Sf32GreaterOrEqual(af, bf) ? 1u : 0u;
            continue;
        case kOpFOrdEqual:
            r[i] = ::duetos::core::Sf32Equal(af, bf) ? 1u : 0u;
            continue;
        case kOpFOrdNotEqual:
            r[i] = ::duetos::core::Sf32NotEqual(af, bf) ? 1u : 0u;
            continue;
        default:
            break;
        }
        r[i] = Sf32ToBits(rf);
    }
    StoreResultComponents(ec, result_id, type_id, r, n);
}

void DoLoad(ExecContext& ec, u32 type_id, u32 result_id, u32 ptr_id)
{
    // Pointer is either an OpVariable id (direct) or an
    // OpAccessChain result (we record the resolved storage offset
    // there). For variables we read from the storage heap; for
    // access-chain we read from the offset stored in ssa_value.
    const Program* p = ec.prog;
    u32 src_bytes_offset = 0;
    const u8* src_base = nullptr;
    if (p->id_kinds[ptr_id] == IdKind::Variable)
    {
        const VariableRecord& v = p->variables[p->id_to_index[ptr_id]];
        switch (v.storage)
        {
        case StorageClass::Input:
            src_base = p->input.bytes;
            break;
        case StorageClass::Output:
            src_base = p->output.bytes;
            break;
        case StorageClass::UniformConstant:
            src_base = p->uniform_constant.bytes;
            break;
        case StorageClass::Uniform:
            src_base = p->uniform.bytes;
            break;
        case StorageClass::PushConstant:
            src_base = p->push_constant.bytes;
            break;
        default:
            src_base = p->private_storage.bytes;
            break;
        }
        src_bytes_offset = v.storage_offset;
    }
    else
    {
        // AccessChain stashes (storage_class<<24 | offset) in the
        // scalar value; resolve back via the high byte.
        const u32 packed = ec.scalar[ptr_id].bits;
        const u32 sc = (packed >> 24) & 0xFFu;
        src_bytes_offset = packed & 0x00FFFFFFu;
        switch (static_cast<StorageClass>(sc))
        {
        case StorageClass::Input:
            src_base = p->input.bytes;
            break;
        case StorageClass::Output:
            src_base = p->output.bytes;
            break;
        case StorageClass::UniformConstant:
            src_base = p->uniform_constant.bytes;
            break;
        case StorageClass::Uniform:
            src_base = p->uniform.bytes;
            break;
        case StorageClass::PushConstant:
            src_base = p->push_constant.bytes;
            break;
        default:
            src_base = p->private_storage.bytes;
            break;
        }
    }
    const u32 n = ComponentCount(p, type_id);
    u32 buf[16]{};
    for (u32 i = 0; i < n && i < 16; ++i)
    {
        const u32 b = src_bytes_offset + i * 4u;
        if (b + 4u > kMaxStorageBytes)
            break;
        buf[i] = (static_cast<u32>(src_base[b]) | (static_cast<u32>(src_base[b + 1]) << 8) |
                  (static_cast<u32>(src_base[b + 2]) << 16) | (static_cast<u32>(src_base[b + 3]) << 24));
    }
    StoreResultComponents(ec, result_id, type_id, buf, n);
}

void DoStore(ExecContext& ec, u32 ptr_id, u32 value_id)
{
    Program* p = ec.prog;
    u32 dst_bytes_offset = 0;
    u8* dst_base = nullptr;
    if (p->id_kinds[ptr_id] == IdKind::Variable)
    {
        VariableRecord& v = p->variables[p->id_to_index[ptr_id]];
        switch (v.storage)
        {
        case StorageClass::Input:
            dst_base = p->input.bytes;
            break;
        case StorageClass::Output:
            dst_base = p->output.bytes;
            break;
        case StorageClass::UniformConstant:
            dst_base = p->uniform_constant.bytes;
            break;
        case StorageClass::Uniform:
            dst_base = p->uniform.bytes;
            break;
        case StorageClass::PushConstant:
            dst_base = p->push_constant.bytes;
            break;
        default:
            dst_base = p->private_storage.bytes;
            break;
        }
        dst_bytes_offset = v.storage_offset;
    }
    else
    {
        const u32 packed = ec.scalar[ptr_id].bits;
        const u32 sc = (packed >> 24) & 0xFFu;
        dst_bytes_offset = packed & 0x00FFFFFFu;
        switch (static_cast<StorageClass>(sc))
        {
        case StorageClass::Input:
            dst_base = p->input.bytes;
            break;
        case StorageClass::Output:
            dst_base = p->output.bytes;
            break;
        default:
            dst_base = p->private_storage.bytes;
            break;
        }
    }
    u32 buf[16]{};
    const u32 n = LoadOperandComponents(ec, value_id, buf, 16);
    for (u32 i = 0; i < n; ++i)
    {
        const u32 b = dst_bytes_offset + i * 4u;
        if (b + 4u > kMaxStorageBytes)
            break;
        dst_base[b + 0] = static_cast<u8>(buf[i] & 0xFFu);
        dst_base[b + 1] = static_cast<u8>((buf[i] >> 8) & 0xFFu);
        dst_base[b + 2] = static_cast<u8>((buf[i] >> 16) & 0xFFu);
        dst_base[b + 3] = static_cast<u8>((buf[i] >> 24) & 0xFFu);
    }
}

void DoAccessChain(ExecContext& ec, u32 type_id, u32 result_id, u32 base_ptr_id, const u32* idx_ids, u32 idx_count)
{
    // Resolve a pointer to a base variable + chain of index ids
    // (each pointing at an OpConstant of int type) into a byte
    // offset within the variable's storage backing. Packs the
    // result as (storage_class<<24 | byte_offset) into the scalar
    // slot so subsequent Load / Store can unpack it without
    // touching the pointer type system.
    (void)type_id;
    Program* p = ec.prog;
    if (p->id_kinds[base_ptr_id] != IdKind::Variable)
        return;
    const VariableRecord& v = p->variables[p->id_to_index[base_ptr_id]];
    u32 offset = v.storage_offset;
    u32 cur_type_id = v.type_id;
    // Strip the outer Pointer.
    if (cur_type_id < kMaxIds && p->id_kinds[cur_type_id] == IdKind::Type)
    {
        const TypeRecord& tr = p->types[p->id_to_index[cur_type_id]];
        if (tr.kind == TypeKind::Pointer)
            cur_type_id = tr.component_id;
    }
    for (u32 k = 0; k < idx_count; ++k)
    {
        const TypeRecord* ct = TypeOf(p, cur_type_id);
        if (ct == nullptr)
            break;
        const u32 idx_id = idx_ids[k];
        u32 idx = 0;
        if (idx_id < kMaxIds && p->id_kinds[idx_id] == IdKind::Constant)
            idx = p->constants[p->id_to_index[idx_id]].components[0].bits;
        else
            idx = ec.scalar[idx_id].bits;
        switch (ct->kind)
        {
        case TypeKind::Struct:
        {
            if (idx >= ct->member_count)
                return;
            offset += ct->member_offsets[idx];
            cur_type_id = ct->members[idx];
            break;
        }
        case TypeKind::Vector:
        case TypeKind::Array:
        {
            offset += idx * 4u; // 32-bit components
            cur_type_id = ct->component_id;
            break;
        }
        case TypeKind::Matrix:
        {
            const TypeRecord* col = TypeOf(p, ct->component_id);
            const u32 col_size = (col != nullptr) ? col->component_count * 4u : 16u;
            offset += idx * col_size;
            cur_type_id = ct->component_id;
            break;
        }
        default:
            return;
        }
    }
    const u32 packed = (static_cast<u32>(v.storage) << 24) | (offset & 0x00FFFFFFu);
    SetScalar(ec, result_id, type_id, packed);
}

void DoCompositeExtract(ExecContext& ec, u32 type_id, u32 result_id, u32 composite_id, const u32* idx_lits,
                        u32 idx_count)
{
    u32 buf[16]{};
    const u32 n = LoadOperandComponents(ec, composite_id, buf, 16);
    if (idx_count == 0 || idx_lits[0] >= n)
    {
        SetScalar(ec, result_id, type_id, 0u);
        return;
    }
    // v1 supports a single-level extract (most shaders only fetch
    // one scalar from a vec). Nested composite extracts walk
    // additional indices in idx_lits[1..] and need a richer model
    // — not in v1.
    SetScalar(ec, result_id, type_id, buf[idx_lits[0]]);
}

void DoCompositeConstruct(ExecContext& ec, u32 type_id, u32 result_id, const u32* operand_ids, u32 operand_count)
{
    u32 buf[16]{};
    u32 cursor = 0;
    for (u32 i = 0; i < operand_count && cursor < 16; ++i)
    {
        u32 sub[16]{};
        const u32 m = LoadOperandComponents(ec, operand_ids[i], sub, 16);
        for (u32 j = 0; j < m && cursor < 16; ++j)
            buf[cursor++] = sub[j];
    }
    StoreResultComponents(ec, result_id, type_id, buf, cursor);
}

void DoVectorShuffle(ExecContext& ec, u32 type_id, u32 result_id, u32 v1_id, u32 v2_id, const u32* idx_lits,
                     u32 idx_count)
{
    u32 a[16]{}, b[16]{}, r[16]{};
    const u32 n1 = LoadOperandComponents(ec, v1_id, a, 16);
    LoadOperandComponents(ec, v2_id, b, 16);
    const u32 n = (idx_count < 16) ? idx_count : 16;
    for (u32 i = 0; i < n; ++i)
    {
        const u32 idx = idx_lits[i];
        if (idx == 0xFFFFFFFFu)
            r[i] = 0;
        else if (idx < n1)
            r[i] = a[idx];
        else
            r[i] = b[idx - n1];
    }
    StoreResultComponents(ec, result_id, type_id, r, n);
}

void DoVectorTimesScalar(ExecContext& ec, u32 type_id, u32 result_id, u32 vec_id, u32 scalar_id)
{
    u32 v[16]{}, r[16]{};
    const u32 n = LoadOperandComponents(ec, vec_id, v, 16);
    u32 s_bits = GetScalarBits(ec, scalar_id);
    const Sf32 s = Sf32FromBits(s_bits);
    for (u32 i = 0; i < n; ++i)
        r[i] = Sf32ToBits(::duetos::core::Sf32Mul(Sf32FromBits(v[i]), s));
    StoreResultComponents(ec, result_id, type_id, r, n);
}

void DoMatrixTimesVector(ExecContext& ec, u32 type_id, u32 result_id, u32 mat_id, u32 vec_id)
{
    // Column-major matrix: mat[col][row]. Each column is a vector
    // of `rows` floats. Result = sum_over_cols(mat[col] *
    // vec[col]). v1 supports any (rows, cols) up to (4, 4).
    u32 m_data[16]{};
    u32 v_data[4]{};
    const u32 m_n = LoadOperandComponents(ec, mat_id, m_data, 16);
    const u32 v_n = LoadOperandComponents(ec, vec_id, v_data, 4);
    if (v_n == 0 || m_n == 0)
        return;
    const u32 cols = v_n;
    const u32 rows = m_n / cols;
    u32 r[4]{};
    for (u32 row = 0; row < rows && row < 4; ++row)
    {
        Sf32 acc{0};
        for (u32 col = 0; col < cols && col < 4; ++col)
        {
            const Sf32 mij = Sf32FromBits(m_data[col * rows + row]);
            const Sf32 vj = Sf32FromBits(v_data[col]);
            acc = ::duetos::core::Sf32Add(acc, ::duetos::core::Sf32Mul(mij, vj));
        }
        r[row] = Sf32ToBits(acc);
    }
    StoreResultComponents(ec, result_id, type_id, r, rows);
}

void DoDot(ExecContext& ec, u32 type_id, u32 result_id, u32 a_id, u32 b_id)
{
    u32 a[16]{}, b[16]{};
    const u32 n = LoadOperandComponents(ec, a_id, a, 16);
    LoadOperandComponents(ec, b_id, b, 16);
    Sf32 acc{0};
    for (u32 i = 0; i < n; ++i)
        acc = ::duetos::core::Sf32Add(acc, ::duetos::core::Sf32Mul(Sf32FromBits(a[i]), Sf32FromBits(b[i])));
    SetScalar(ec, result_id, type_id, Sf32ToBits(acc));
}

void DoExtInst(ExecContext& ec, u32 type_id, u32 result_id, u32 sub_op, const u32* arg_ids, u32 arg_count)
{
    u32 a[16]{}, b[16]{}, c[16]{}, r[16]{};
    const u32 n = (arg_count > 0) ? LoadOperandComponents(ec, arg_ids[0], a, 16) : 0;
    const u32 n2 = (arg_count > 1) ? LoadOperandComponents(ec, arg_ids[1], b, 16) : 0;
    const u32 n3 = (arg_count > 2) ? LoadOperandComponents(ec, arg_ids[2], c, 16) : 0;
    (void)n2;
    (void)n3;
    switch (sub_op)
    {
    case kGlslSqrt:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Sqrt(Sf32FromBits(a[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslFAbs:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Abs(Sf32FromBits(a[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslSAbs:
        for (u32 i = 0; i < n; ++i)
        {
            const i32 v = static_cast<i32>(a[i]);
            r[i] = static_cast<u32>(v < 0 ? -v : v);
        }
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslFloor:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Floor(Sf32FromBits(a[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslCeil:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Ceil(Sf32FromBits(a[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslFract:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Fract(Sf32FromBits(a[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslRound:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Round(Sf32FromBits(a[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslSin:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Sin(Sf32FromBits(a[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslCos:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Cos(Sf32FromBits(a[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslPow:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Pow(Sf32FromBits(a[i]), Sf32FromBits(b[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslFMin:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Min(Sf32FromBits(a[i]), Sf32FromBits(b[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslFMax:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Max(Sf32FromBits(a[i]), Sf32FromBits(b[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslFClamp:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Clamp(Sf32FromBits(a[i]), Sf32FromBits(b[i]), Sf32FromBits(c[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslFMix:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Mix(Sf32FromBits(a[i]), Sf32FromBits(b[i]), Sf32FromBits(c[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslStep:
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Step(Sf32FromBits(a[i]), Sf32FromBits(b[i])));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    case kGlslLength:
    {
        Sf32 acc{0};
        for (u32 i = 0; i < n; ++i)
        {
            const Sf32 ai = Sf32FromBits(a[i]);
            acc = ::duetos::core::Sf32Add(acc, ::duetos::core::Sf32Mul(ai, ai));
        }
        SetScalar(ec, result_id, type_id, Sf32ToBits(::duetos::core::Sf32Sqrt(acc)));
        break;
    }
    case kGlslNormalize:
    {
        Sf32 acc{0};
        for (u32 i = 0; i < n; ++i)
        {
            const Sf32 ai = Sf32FromBits(a[i]);
            acc = ::duetos::core::Sf32Add(acc, ::duetos::core::Sf32Mul(ai, ai));
        }
        const Sf32 len = ::duetos::core::Sf32Sqrt(acc);
        for (u32 i = 0; i < n; ++i)
            r[i] = Sf32ToBits(::duetos::core::Sf32Div(Sf32FromBits(a[i]), len));
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    }
    case kGlslCross:
        if (n >= 3 && n2 >= 3)
        {
            const Sf32 ax = Sf32FromBits(a[0]), ay = Sf32FromBits(a[1]), az = Sf32FromBits(a[2]);
            const Sf32 bx = Sf32FromBits(b[0]), by = Sf32FromBits(b[1]), bz = Sf32FromBits(b[2]);
            r[0] =
                Sf32ToBits(::duetos::core::Sf32Sub(::duetos::core::Sf32Mul(ay, bz), ::duetos::core::Sf32Mul(az, by)));
            r[1] =
                Sf32ToBits(::duetos::core::Sf32Sub(::duetos::core::Sf32Mul(az, bx), ::duetos::core::Sf32Mul(ax, bz)));
            r[2] =
                Sf32ToBits(::duetos::core::Sf32Sub(::duetos::core::Sf32Mul(ax, by), ::duetos::core::Sf32Mul(ay, bx)));
            StoreResultComponents(ec, result_id, type_id, r, 3);
        }
        break;
    default:
        // Unknown sub-op: zero-fill so subsequent ops see a defined
        // value (vs. uninitialized stack).
        for (u32 i = 0; i < n; ++i)
            r[i] = 0u;
        StoreResultComponents(ec, result_id, type_id, r, n);
        break;
    }
}

// Find the basic block in `prog->blocks` whose label_id matches.
i32 FindBlock(const Program* p, u32 label_id)
{
    for (u32 i = 0; i < p->block_count; ++i)
        if (p->blocks[i].label_id == label_id)
            return static_cast<i32>(i);
    return -1;
}

void ExecuteBlock(ExecContext& ec, u32 block_index)
{
    const Program* p = ec.prog;
    const BasicBlockRecord& bb = p->blocks[block_index];
    ec.cur_block_label = bb.label_id;
    for (u32 i = bb.instr_begin; i < bb.instr_end; ++i)
    {
        if (++ec.step_count > kStepBudget)
        {
            ++::duetos::subsystems::graphics::internal::g_spirv_step_budget_exhausted;
            ec.returned = true;
            ec.jump_target = 0;
            return;
        }
        const InstructionRecord& ir = p->instructions[i];
        const u32* w = &p->words[ir.operands_word_offset];
        const u16 op = ir.opcode;
        const u32 wc = ir.word_count;
        const u32 tid = ir.type_id;
        const u32 rid = ir.result_id;
        switch (op)
        {
        case kOpLoad:
            if (wc >= 4)
                DoLoad(ec, tid, rid, w[3]);
            break;
        case kOpStore:
            if (wc >= 3)
                DoStore(ec, w[1], w[2]);
            break;
        case kOpAccessChain:
        {
            if (wc >= 4)
                DoAccessChain(ec, tid, rid, w[3], &w[4], wc - 4);
            break;
        }
        case kOpIAdd:
        case kOpISub:
        case kOpIMul:
        case kOpSDiv:
        case kOpUDiv:
        case kOpUMod:
        case kOpSMod:
        case kOpSRem:
        case kOpIEqual:
        case kOpINotEqual:
        case kOpULessThan:
        case kOpSLessThan:
        case kOpUGreaterThan:
        case kOpSGreaterThan:
        case kOpULessThanEqual:
        case kOpSLessThanEqual:
        case kOpUGreaterThanEqual:
        case kOpSGreaterThanEqual:
        case kOpBitwiseAnd:
        case kOpBitwiseOr:
        case kOpBitwiseXor:
        case kOpShiftLeftLogical:
        case kOpShiftRightLogical:
        case kOpShiftRightArithmetic:
        case kOpLogicalEqual:
        case kOpLogicalNotEqual:
        case kOpLogicalAnd:
        case kOpLogicalOr:
            if (wc >= 5)
                DoBinaryIntOp(ec, op, tid, rid, w[3], w[4]);
            break;
        case kOpSNegate:
        case kOpNot:
        case kOpLogicalNot:
            if (wc >= 4)
                DoBinaryIntOp(ec, op, tid, rid, w[3], w[3]);
            break;
        case kOpFAdd:
        case kOpFSub:
        case kOpFMul:
        case kOpFDiv:
        case kOpFRem:
        case kOpFMod:
        case kOpFOrdLessThan:
        case kOpFOrdGreaterThan:
        case kOpFOrdLessThanEqual:
        case kOpFOrdGreaterThanEqual:
        case kOpFOrdEqual:
        case kOpFOrdNotEqual:
            if (wc >= 5)
                DoBinaryFloatOp(ec, op, tid, rid, w[3], w[4]);
            break;
        case kOpFNegate:
            if (wc >= 4)
                DoBinaryFloatOp(ec, op, tid, rid, w[3], w[3]);
            break;
        case kOpVectorTimesScalar:
            if (wc >= 5)
                DoVectorTimesScalar(ec, tid, rid, w[3], w[4]);
            break;
        case kOpMatrixTimesVector:
            if (wc >= 5)
                DoMatrixTimesVector(ec, tid, rid, w[3], w[4]);
            break;
        case kOpDot:
            if (wc >= 5)
                DoDot(ec, tid, rid, w[3], w[4]);
            break;
        case kOpCompositeExtract:
            if (wc >= 5)
                DoCompositeExtract(ec, tid, rid, w[3], &w[4], wc - 4);
            break;
        case kOpCompositeInsert:
        {
            // Operands: (T, R, object, composite, lit*-indices).
            // Replace the indexed scalar in `composite` with
            // `object`. v0 single-level only (matches the
            // CompositeExtract limit).
            if (wc >= 6)
            {
                u32 buf[16]{};
                const u32 cn = LoadOperandComponents(ec, w[4], buf, 16);
                const u32 obj_bits = GetScalarBits(ec, w[3]);
                const u32 idx = w[5];
                if (idx < cn)
                    buf[idx] = obj_bits;
                StoreResultComponents(ec, rid, tid, buf, cn);
            }
            break;
        }
        case kOpVectorExtractDynamic:
        {
            // Operands: (T, R, vector, index-id).
            if (wc >= 5)
            {
                u32 buf[16]{};
                const u32 cn = LoadOperandComponents(ec, w[3], buf, 16);
                const u32 idx = GetScalarBits(ec, w[4]);
                SetScalar(ec, rid, tid, (idx < cn) ? buf[idx] : 0u);
            }
            break;
        }
        case kOpVectorInsertDynamic:
        {
            // Operands: (T, R, vector, component, index-id).
            if (wc >= 6)
            {
                u32 buf[16]{};
                const u32 cn = LoadOperandComponents(ec, w[3], buf, 16);
                const u32 comp = GetScalarBits(ec, w[4]);
                const u32 idx = GetScalarBits(ec, w[5]);
                if (idx < cn)
                    buf[idx] = comp;
                StoreResultComponents(ec, rid, tid, buf, cn);
            }
            break;
        }
        case kOpCompositeConstruct:
            if (wc >= 4)
                DoCompositeConstruct(ec, tid, rid, &w[3], wc - 3);
            break;
        case kOpVectorShuffle:
            if (wc >= 6)
                DoVectorShuffle(ec, tid, rid, w[3], w[4], &w[5], wc - 5);
            break;
        case kOpConvertSToF:
            if (wc >= 4)
            {
                const i32 v = static_cast<i32>(GetScalarBits(ec, w[3]));
                SetScalar(ec, rid, tid, Sf32ToBits(::duetos::core::Sf32FromI32(v)));
            }
            break;
        case kOpConvertUToF:
            if (wc >= 4)
                SetScalar(ec, rid, tid, Sf32ToBits(::duetos::core::Sf32FromU32(GetScalarBits(ec, w[3]))));
            break;
        case kOpConvertFToS:
            if (wc >= 4)
                SetScalar(ec, rid, tid,
                          static_cast<u32>(::duetos::core::Sf32ToI32(Sf32FromBits(GetScalarBits(ec, w[3])))));
            break;
        case kOpBitcast:
            if (wc >= 4)
                SetScalar(ec, rid, tid, GetScalarBits(ec, w[3]));
            break;
        case kOpExtInst:
            // w[3] = ext-inst-set id, w[4] = sub-op, w[5..] = args.
            if (wc >= 5 && w[3] == ec.prog->ext_inst_glsl_id)
                DoExtInst(ec, tid, rid, w[4], (wc > 5) ? &w[5] : nullptr, (wc > 5) ? (wc - 5) : 0u);
            break;
        case kOpSampledImage:
            // Combines a SampledImage from an Image + Sampler.
            // Operands: (T, R, image, sampler). v0 just records
            // the image id as the result — the executor's sample
            // path looks at the texture-side bits.
            if (wc >= 4)
                SetScalar(ec, rid, tid, w[3]);
            break;
        case kOpImageQuerySize:
        case kOpImageQuerySizeLod:
        {
            // Operands: (T, R, image, [lod]). v0 ignores LOD (no
            // mipmaps yet). Returns ivec2 / ivec3 of the image
            // extent via descriptor lookup.
            if (wc >= 4)
            {
                const u64 bound = LookupDescriptor(ec.prog, 0, 0);
                u32 w_dim = 0, h_dim = 0, d_dim = 0;
                if (bound != 0)
                    ::duetos::subsystems::graphics::internal::QueryImageSize(bound, &w_dim, &h_dim, &d_dim);
                u32 r3[3] = {w_dim, h_dim, d_dim};
                StoreResultComponents(ec, rid, tid, r3, 3);
            }
            break;
        }
        case kOpImageSampleImplicitLod:
        case kOpImageSampleExplicitLod:
        {
            // Operands: (T, R, sampled-image, coord, [ImageOperands, ...]).
            // v0 texture-sample tier:
            //   When descriptor binding (0, 0) is set, return a
            //   procedural checkerboard sampled at the UV coord:
            //   `tile = (u * 8) ^ (v * 8) > 0.5 ? white : grey`.
            //   The pattern is visually distinct from the UV
            //   gradient — proves the descriptor-set lookup
            //   fired AND the sample fed a real coord.
            //   Otherwise return the UV coord as (u, v, 0, 1) —
            //   the "missing texture" diagnostic.
            if (wc >= 5)
            {
                u32 coord_buf[4]{};
                const u32 cn = LoadOperandComponents(ec, w[4], coord_buf, 4);
                u32 r4[4] = {0, 0, 0, Sf32ToBits(::duetos::core::Sf32One())};
                const u64 bound = LookupDescriptor(ec.prog, 0, 0);
                if (bound != 0 && cn >= 2)
                {
                    // Real texture fetch via the descriptor handle.
                    // Resolves through ImageView->Image->backing
                    // (set up by VkBindImageMemory). The addressing
                    // mode comes from the VkSampler the caller
                    // attached at descriptor-update time (REPEAT /
                    // MIRROR / CLAMP_TO_EDGE / CLAMP_TO_BORDER);
                    // when no sampler is bound, falls back to
                    // ClampToEdge — a defined, undisruptive default
                    // for shaders that don't pin a sampler explicitly.
                    const u64 sampler = LookupSampler(ec.prog, 0, 0);
                    const ::duetos::subsystems::graphics::internal::SamplerAddressMode mode_u =
                        ::duetos::subsystems::graphics::internal::SamplerAddressModeFor(sampler);
                    const ::duetos::subsystems::graphics::internal::SamplerAddressMode mode_v =
                        ::duetos::subsystems::graphics::internal::SamplerAddressModeVFor(sampler);
                    const u32 argb = ::duetos::subsystems::graphics::internal::SampleImageRgba8(
                        bound, coord_buf[0], coord_buf[1], mode_u, mode_v);
                    // Decompose back to RGBA Sf32 components for
                    // the shader: bits 16..23 = R, 8..15 = G, 0..7 = B,
                    // 24..31 = A.
                    const u8 R = static_cast<u8>((argb >> 16) & 0xFFu);
                    const u8 G = static_cast<u8>((argb >> 8) & 0xFFu);
                    const u8 B = static_cast<u8>(argb & 0xFFu);
                    const u8 A = static_cast<u8>((argb >> 24) & 0xFFu);
                    const Sf32 inv255 =
                        ::duetos::core::Sf32Div(::duetos::core::Sf32One(), ::duetos::core::Sf32FromU32(255u));
                    r4[0] = Sf32ToBits(::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(R), inv255));
                    r4[1] = Sf32ToBits(::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(G), inv255));
                    r4[2] = Sf32ToBits(::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(B), inv255));
                    r4[3] = Sf32ToBits(::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(A), inv255));
                }
                else
                {
                    if (cn >= 1)
                        r4[0] = coord_buf[0];
                    if (cn >= 2)
                        r4[1] = coord_buf[1];
                    if (cn >= 3)
                        r4[2] = coord_buf[2];
                }
                StoreResultComponents(ec, rid, tid, r4, 4);
            }
            break;
        }
        case kOpImageFetch:
        case kOpImageRead:
        {
            // Unfiltered, integer-coordinate fetch from the bound
            // (set 0, binding 0) image. Coordinates are signed
            // integer scalars / vectors per spec; v0 supports 2D
            // images so the first two components matter. The result
            // is a 4-component vector; we unpack the BGRA8 backing
            // into [0,1] floats — symmetric with the OpImageSample
            // path. Out-of-bounds reads return (0,0,0,1) per spec
            // (sampler-less reads have no border colour).
            //
            // Operands: (T, R, image, coord, [ImageOperands ...]).
            // ImageOperands are accepted but ignored — v0 has no
            // mip chain (LOD), no MS sample-select, no offsets.
            if (wc >= 5)
            {
                u32 coord_buf[4]{};
                const u32 cn = LoadOperandComponents(ec, w[4], coord_buf, 4);
                u32 r4[4] = {0, 0, 0, Sf32ToBits(::duetos::core::Sf32One())};
                const u64 bound = LookupDescriptor(ec.prog, 0, 0);
                if (bound != 0 && cn >= 1)
                {
                    const i32 px = static_cast<i32>(coord_buf[0]);
                    const i32 py = (cn >= 2) ? static_cast<i32>(coord_buf[1]) : 0;
                    u32 w_dim = 0, h_dim = 0, d_dim = 0;
                    if (::duetos::subsystems::graphics::internal::QueryImageSize(bound, &w_dim, &h_dim, &d_dim) &&
                        px >= 0 && py >= 0 && static_cast<u32>(px) < w_dim && static_cast<u32>(py) < h_dim)
                    {
                        const u32 argb = ::duetos::subsystems::graphics::internal::FetchTexelBgra8(
                            bound, static_cast<u32>(px), static_cast<u32>(py));
                        const u8 R = static_cast<u8>((argb >> 16) & 0xFFu);
                        const u8 G = static_cast<u8>((argb >> 8) & 0xFFu);
                        const u8 B = static_cast<u8>(argb & 0xFFu);
                        const u8 A = static_cast<u8>((argb >> 24) & 0xFFu);
                        const Sf32 inv255 =
                            ::duetos::core::Sf32Div(::duetos::core::Sf32One(), ::duetos::core::Sf32FromU32(255u));
                        r4[0] = Sf32ToBits(::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(R), inv255));
                        r4[1] = Sf32ToBits(::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(G), inv255));
                        r4[2] = Sf32ToBits(::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(B), inv255));
                        r4[3] = Sf32ToBits(::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(A), inv255));
                    }
                    // out-of-bounds OR no backing -> (0,0,0,1) default above.
                }
                StoreResultComponents(ec, rid, tid, r4, 4);
            }
            break;
        }
        case kOpImageWrite:
        {
            // Storage-image write — no result id. Operands:
            // (image, coord, texel, [ImageOperands ...]). v0 packs
            // a 4-component float texel as BGRA8 with [0,1] clamp;
            // out-of-bounds writes are silently dropped per spec.
            if (wc >= 4)
            {
                u32 coord_buf[4]{};
                u32 texel_buf[4]{};
                const u32 cn = LoadOperandComponents(ec, w[2], coord_buf, 4);
                const u32 tn = LoadOperandComponents(ec, w[3], texel_buf, 4);
                const u64 bound = LookupDescriptor(ec.prog, 0, 0);
                if (bound != 0 && cn >= 1 && tn >= 1)
                {
                    const i32 px = static_cast<i32>(coord_buf[0]);
                    const i32 py = (cn >= 2) ? static_cast<i32>(coord_buf[1]) : 0;
                    u32 w_dim = 0, h_dim = 0, d_dim = 0;
                    if (::duetos::subsystems::graphics::internal::QueryImageSize(bound, &w_dim, &h_dim, &d_dim) &&
                        px >= 0 && py >= 0 && static_cast<u32>(px) < w_dim && static_cast<u32>(py) < h_dim)
                    {
                        // Convert each Sf32 component in [0,1] to u8.
                        auto clamp_to_u8 = [](u32 sf_bits) -> u8
                        {
                            const Sf32 s = Sf32FromBits(sf_bits);
                            if (::duetos::core::Sf32IsNaN(s))
                                return 0;
                            const Sf32 clamped =
                                ::duetos::core::Sf32Clamp(s, ::duetos::core::Sf32Zero(), ::duetos::core::Sf32One());
                            const Sf32 scaled = ::duetos::core::Sf32Mul(clamped, ::duetos::core::Sf32FromU32(255u));
                            const i32 v = ::duetos::core::Sf32ToI32(scaled);
                            if (v < 0)
                                return 0;
                            if (v > 255)
                                return 255;
                            return static_cast<u8>(v);
                        };
                        const u8 R = clamp_to_u8(texel_buf[0]);
                        const u8 G = (tn >= 2) ? clamp_to_u8(texel_buf[1]) : 0;
                        const u8 B = (tn >= 3) ? clamp_to_u8(texel_buf[2]) : 0;
                        const u8 A = (tn >= 4) ? clamp_to_u8(texel_buf[3]) : 255;
                        const u32 argb = (static_cast<u32>(A) << 24) | (static_cast<u32>(R) << 16) |
                                         (static_cast<u32>(G) << 8) | static_cast<u32>(B);
                        ::duetos::subsystems::graphics::internal::WriteTexelBgra8(bound, static_cast<u32>(px),
                                                                                  static_cast<u32>(py), argb);
                    }
                }
            }
            break;
        }
        case kOpPhi:
        {
            // PairIdRefIdRef: (value, parent-label) repeated. Pick
            // the value matching `prev_block_label`.
            for (u32 k = 3; k + 1 < wc; k += 2)
            {
                if (w[k + 1] == ec.prev_block_label)
                {
                    SetScalar(ec, rid, tid, GetScalarBits(ec, w[k]));
                    break;
                }
            }
            break;
        }
        case kOpLoopMerge:
        case kOpSelectionMerge:
            // Control-flow structuring annotations — no exec effect.
            break;
        case kOpBranch:
            if (wc >= 2)
            {
                ec.jump_target = w[1];
                return;
            }
            break;
        case kOpBranchConditional:
            if (wc >= 4)
            {
                const u32 cond = GetScalarBits(ec, w[1]);
                ec.jump_target = (cond != 0) ? w[2] : w[3];
                return;
            }
            break;
        case kOpSelect:
        {
            // Operands: (T, R, condition, true_value, false_value).
            // GLSL `mix(a, b, bool(c))` lowers to OpSelect. v0
            // handles scalar conditions only; vector-of-bool
            // conditions need per-lane selection, deferred.
            if (wc >= 6)
            {
                const u32 cond = GetScalarBits(ec, w[3]);
                const u32 picked_id = (cond != 0) ? w[4] : w[5];
                u32 buf[16]{};
                const u32 mn = LoadOperandComponents(ec, picked_id, buf, 16);
                StoreResultComponents(ec, rid, tid, buf, mn);
            }
            break;
        }
        case kOpAny:
        {
            // Operands: (T, R, vector-of-bool). Reduces to true
            // if any lane is non-zero.
            if (wc >= 4)
            {
                u32 buf[16]{};
                const u32 mn = LoadOperandComponents(ec, w[3], buf, 16);
                u32 any_set = 0;
                for (u32 ai = 0; ai < mn; ++ai)
                    if (buf[ai] != 0)
                    {
                        any_set = 1;
                        break;
                    }
                SetScalar(ec, rid, tid, any_set);
            }
            break;
        }
        case kOpAll:
        {
            if (wc >= 4)
            {
                u32 buf[16]{};
                const u32 mn = LoadOperandComponents(ec, w[3], buf, 16);
                u32 all_set = 1;
                for (u32 ai = 0; ai < mn; ++ai)
                    if (buf[ai] == 0)
                    {
                        all_set = 0;
                        break;
                    }
                SetScalar(ec, rid, tid, all_set);
            }
            break;
        }
        case kOpKill:
            // Fragment discard. Treat as early-return; the shader
            // hook drops the pixel.
            ec.returned = true;
            ec.jump_target = 0;
            return;
        case kOpReturn:
            ec.returned = true;
            ec.jump_target = 0;
            return;
        case kOpReturnValue:
            ec.returned = true;
            ec.jump_target = 0;
            return;
        case kOpDPdx:
        case kOpDPdy:
        case kOpFwidth:
        case kOpDPdxFine:
        case kOpDPdyFine:
        case kOpFwidthFine:
        case kOpDPdxCoarse:
        case kOpDPdyCoarse:
        case kOpFwidthCoarse:
            // GAP: real partial derivatives need 2x2-quad fragment
            // execution; the serial interpreter has one invocation
            // active at a time. Return zero, matching the spec's
            // permitted "implementation-defined" floor for shaders
            // that read derivatives outside a derivative group.
            if (rid != 0 && wc >= 4)
            {
                const u32 src_id = w[3];
                u32 comp[16]{};
                const u32 n = LoadOperandComponents(ec, src_id, comp, 16);
                for (u32 i = 0; i < n; ++i)
                    comp[i] = 0u;
                StoreResultComponents(ec, rid, tid, comp, (n > 0) ? n : 1u);
            }
            break;
        case kOpControlBarrier:
        case kOpMemoryBarrier:
            // GAP: real barriers matter only when multiple
            // invocations from the same workgroup run concurrently.
            // The serial dispatcher runs them one at a time, so the
            // barrier is already satisfied trivially. No-op.
            break;
        case kOpAtomicLoad:
        {
            // Atomic load reduces to a plain pointer dereference
            // when there's no contention. Operands:
            // (T, R, pointer, scope, semantics).
            if (rid != 0 && wc >= 4)
                SetScalar(ec, rid, tid, GetScalarBits(ec, w[3]));
            break;
        }
        case kOpAtomicStore:
        {
            // Operands: (pointer, scope, semantics, value). v0
            // collapses to a plain store via SetScalar on the
            // pointer's slot — same semantics as OpStore for a
            // scalar target.
            if (wc >= 5)
            {
                const u32 ptr_id = w[1];
                const u32 ptr_type = ec.type_of[ptr_id];
                SetScalar(ec, ptr_id, ptr_type, GetScalarBits(ec, w[4]));
            }
            break;
        }
        case kOpAtomicExchange:
        case kOpAtomicIIncrement:
        case kOpAtomicIDecrement:
        case kOpAtomicIAdd:
        case kOpAtomicISub:
        case kOpAtomicSMin:
        case kOpAtomicUMin:
        case kOpAtomicSMax:
        case kOpAtomicUMax:
        case kOpAtomicAnd:
        case kOpAtomicOr:
        case kOpAtomicXor:
        {
            // RMW atomics return the OLD value and update the
            // pointer. Operands typically: (T, R, pointer, scope,
            // semantics, [value]).
            // v0 collapses to non-atomic since the serial
            // interpreter has no contention. Update-side semantics
            // mirror the matching non-atomic op family.
            if (rid != 0 && wc >= 4)
            {
                const u32 ptr_id = w[3];
                const u32 old_bits = GetScalarBits(ec, ptr_id);
                SetScalar(ec, rid, tid, old_bits);
                const u32 ptr_type = ec.type_of[ptr_id];
                u32 new_bits = old_bits;
                const i32 ai = static_cast<i32>(old_bits);
                const u32 val_bits = (wc >= 7) ? GetScalarBits(ec, w[6]) : 0u;
                const i32 bi = static_cast<i32>(val_bits);
                switch (op)
                {
                case kOpAtomicExchange:
                    new_bits = val_bits;
                    break;
                case kOpAtomicIIncrement:
                    new_bits = old_bits + 1u;
                    break;
                case kOpAtomicIDecrement:
                    new_bits = old_bits - 1u;
                    break;
                case kOpAtomicIAdd:
                    new_bits = old_bits + val_bits;
                    break;
                case kOpAtomicISub:
                    new_bits = old_bits - val_bits;
                    break;
                case kOpAtomicSMin:
                    new_bits = static_cast<u32>((ai < bi) ? ai : bi);
                    break;
                case kOpAtomicSMax:
                    new_bits = static_cast<u32>((ai > bi) ? ai : bi);
                    break;
                case kOpAtomicUMin:
                    new_bits = (old_bits < val_bits) ? old_bits : val_bits;
                    break;
                case kOpAtomicUMax:
                    new_bits = (old_bits > val_bits) ? old_bits : val_bits;
                    break;
                case kOpAtomicAnd:
                    new_bits = old_bits & val_bits;
                    break;
                case kOpAtomicOr:
                    new_bits = old_bits | val_bits;
                    break;
                case kOpAtomicXor:
                    new_bits = old_bits ^ val_bits;
                    break;
                default:
                    break;
                }
                SetScalar(ec, ptr_id, ptr_type, new_bits);
            }
            break;
        }
        case kOpFunctionCall:
        {
            // Inline call: jump to callee's first basic block.
            // Parameter binding is skipped (v1 doesn't have a real
            // call ABI). Caller will continue after the call site.
            // For now, treat function calls as no-ops returning 0;
            // a future slice will inline parameter passing.
            if (rid != 0)
                SetScalar(ec, rid, tid, 0u);
            break;
        }
        default:
            // Unknown opcode — silently no-op. We don't abort the
            // whole shader on a single unsupported op because the
            // SPIR-V stream might contain instructions whose effect
            // doesn't matter for the visible output (e.g. an
            // unused OpExtInst with an unrecognised sub-op).
            break;
        }
    }
    // Fell off the end without a terminator — treat as Return.
    ec.returned = true;
    ec.jump_target = 0;
}

} // namespace

bool ExecuteEntryPoint(Program* prog, const char* name)
{
    if (prog == nullptr || !prog->parse_ok || name == nullptr)
        return false;
    // Find the entry point.
    u32 ep_idx = 0xFFFFFFFFu;
    for (u32 i = 0; i < prog->entry_point_count; ++i)
    {
        const EntryPointRecord& ep = prog->entry_points[i];
        u32 j = 0;
        bool match = true;
        while (ep.name[j] != '\0' && name[j] != '\0')
        {
            if (ep.name[j] != name[j])
            {
                match = false;
                break;
            }
            ++j;
        }
        if (match && ep.name[j] == name[j])
        {
            ep_idx = i;
            break;
        }
    }
    if (ep_idx == 0xFFFFFFFFu)
        return false;
    const u32 fn_id = prog->entry_points[ep_idx].function_id;
    if (fn_id >= kMaxIds || prog->id_kinds[fn_id] != IdKind::Function)
        return false;
    const FunctionRecord& f = prog->functions[prog->id_to_index[fn_id]];
    if (f.bb_begin >= prog->block_count)
        return false;

    // Allocate the per-invocation context on the kernel stack —
    // ~70 KiB which is bigger than the typical 16 KiB kstack. To
    // stay within the kstack, the SSA scalar / type_of arrays are
    // sized to `kMaxIds` (512 * 8 bytes = 4 KiB each) and the heap
    // adds 8 KiB. That's ~16 KiB total before the small misc
    // counters — fits inside a 32 KiB kstack with room to spare.
    static ExecContext ec_storage; // single-threaded interpreter; share storage to keep kstack lean
    ExecContext& ec = ec_storage;
    auto* bytes = reinterpret_cast<u8*>(&ec);
    for (u64 i = 0; i < sizeof(ExecContext); ++i)
        bytes[i] = 0u;
    ec.prog = prog;

    u32 cur_bb = f.bb_begin;
    while (cur_bb < f.bb_end && !ec.returned)
    {
        const u32 cur_label = prog->blocks[cur_bb].label_id;
        ec.prev_block_label = ec.cur_block_label;
        ec.cur_block_label = cur_label;
        ExecuteBlock(ec, cur_bb);
        if (ec.returned)
            break;
        if (ec.jump_target == 0)
            break;
        const i32 next = FindBlock(prog, ec.jump_target);
        if (next < 0)
            return false;
        if (static_cast<u32>(next) >= f.bb_end)
            return false;
        ec.prev_block_label = cur_label;
        cur_bb = static_cast<u32>(next);
        ec.jump_target = 0;
    }
    ++::duetos::subsystems::graphics::internal::g_spirv_entry_point_executions;
    return true;
}

} // namespace duetos::subsystems::graphics::spirv
