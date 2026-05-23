#include "subsystems/graphics/graphics_vk_spirv.h"

#include "log/klog.h"

/*
 * DuetOS — SPIR-V module parser.
 *
 * Walks a SPIR-V word stream and populates the Program tables.
 * Two passes:
 *   1. First pass: scan every instruction to record each
 *      IdResult's kind (Type / Constant / Variable / Function /
 *      Label / ExtInst). Resolve all forward references this way
 *      so the second pass can dispatch on kind without lookahead.
 *   2. Second pass: build the actual records. Types resolve
 *      compositionally (TypeVector needs its TypeFloat; the
 *      first-pass kind table guarantees it's already known when
 *      we get here because SPIR-V requires types to be defined
 *      before use).
 *
 * Decorations are also applied in the second pass — OpDecorate /
 * OpMemberDecorate are walked separately after types/variables
 * are known. Order in the source stream doesn't matter for
 * decorations as long as the targets exist.
 *
 * Variable storage is assigned at parse time: each variable gets
 * a fixed offset into its storage-class heap. Loads / stores
 * resolve via `VariableRecord::storage_offset`. This sidesteps
 * an actual heap allocator for the interpreter.
 *
 * Strict bounds: every table is fixed-size. Modules that exceed
 * any cap (too many ids, too many instructions, …) are rejected
 * with `parse_ok=false` and the caller falls back to the
 * fixed-function rasterizer.
 */

namespace duetos::subsystems::graphics::spirv
{

namespace
{

// SPIR-V opcodes used by the parser. Numbers match SPIRV-Headers
// unified1/spirv.h (the canonical Khronos numbering). A handful
// are not switched on inside this TU but are kept for reference
// (they're the canonical "skip these — already handled elsewhere
// in the pipeline" set: debug strings, capability declarations).
[[maybe_unused]] constexpr u16 kOpSource = 3;
[[maybe_unused]] constexpr u16 kOpSourceExtension = 4;
[[maybe_unused]] constexpr u16 kOpName = 5;
[[maybe_unused]] constexpr u16 kOpMemberName = 6;
constexpr u16 kOpExtInstImport = 11;
[[maybe_unused]] constexpr u16 kOpExtInst = 12;
[[maybe_unused]] constexpr u16 kOpMemoryModel = 14;
constexpr u16 kOpEntryPoint = 15;
[[maybe_unused]] constexpr u16 kOpExecutionMode = 16;
[[maybe_unused]] constexpr u16 kOpCapability = 17;
constexpr u16 kOpTypeVoid = 19;
constexpr u16 kOpTypeBool = 20;
constexpr u16 kOpTypeInt = 21;
constexpr u16 kOpTypeFloat = 22;
constexpr u16 kOpTypeVector = 23;
constexpr u16 kOpTypeMatrix = 24;
constexpr u16 kOpTypeArray = 28;
constexpr u16 kOpTypeStruct = 30;
constexpr u16 kOpTypePointer = 32;
constexpr u16 kOpTypeFunction = 33;
constexpr u16 kOpConstantTrue = 41;
constexpr u16 kOpConstantFalse = 42;
constexpr u16 kOpConstant = 43;
constexpr u16 kOpConstantComposite = 44;
constexpr u16 kOpConstantNull = 46;
constexpr u16 kOpFunction = 54;
constexpr u16 kOpFunctionParameter = 55;
constexpr u16 kOpFunctionEnd = 56;
constexpr u16 kOpVariable = 59;
constexpr u16 kOpDecorate = 71;
constexpr u16 kOpMemberDecorate = 72;
constexpr u16 kOpLabel = 248;

// Decoration enum values. Reference set covers everything we
// need to recognise; we currently apply Location, BuiltIn, and
// member Offset. Block / ArrayStride / Binding / DescriptorSet
// matter when descriptor / UBO/SSBO loads land in a future slice.
[[maybe_unused]] constexpr u32 kDecorationBlock = 2;
[[maybe_unused]] constexpr u32 kDecorationArrayStride = 6;
[[maybe_unused]] constexpr u32 kDecorationMatrixStride = 7;
constexpr u32 kDecorationBuiltIn = 11;
constexpr u32 kDecorationLocation = 30;
[[maybe_unused]] constexpr u32 kDecorationBinding = 33;
[[maybe_unused]] constexpr u32 kDecorationDescriptorSet = 34;
constexpr u32 kDecorationOffset = 35;

// Compare two SPIR-V LiteralString operands against a C string.
// `words` is a pointer to the first word of the string's
// payload. `max_words` bounds the comparison (so we don't run
// off the end of the operand window for a malformed string).
bool StringEqualsC(const u32* words, u32 max_words, const char* c)
{
    const u32 max_bytes = max_words * 4u;
    const auto* bytes = reinterpret_cast<const char*>(words);
    u32 i = 0;
    while (c[i] != '\0' && i < max_bytes)
    {
        if (bytes[i] != c[i])
            return false;
        ++i;
    }
    return i < max_bytes && bytes[i] == '\0';
}

void CopyString(char* dst, u32 dst_cap, const u32* src_words, u32 max_words)
{
    const u32 max_bytes = max_words * 4u;
    const auto* bytes = reinterpret_cast<const char*>(src_words);
    u32 i = 0;
    while (i + 1 < dst_cap && i < max_bytes && bytes[i] != '\0')
    {
        dst[i] = bytes[i];
        ++i;
    }
    dst[i] = '\0';
}

// Count the number of words occupied by a LiteralString starting
// at `words[0]`. The string is NUL-terminated; pads to 4 bytes.
// Returns 0 if the string runs off `max_words`.
u32 StringWordCount(const u32* words, u32 max_words)
{
    const u32 max_bytes = max_words * 4u;
    const auto* bytes = reinterpret_cast<const char*>(words);
    for (u32 i = 0; i < max_bytes; ++i)
    {
        if (bytes[i] == '\0')
            return (i / 4u) + 1u; // round up to whole word + 1 (the NUL word)
    }
    return 0;
}

void RegisterId(Program* p, u32 id, IdKind kind, u32 table_index)
{
    if (id == 0 || id >= kMaxIds)
        return;
    p->id_kinds[id] = kind;
    p->id_to_index[id] = table_index;
}

// Round byte size up to 4-byte alignment for storage placement.
u32 AlignUp4(u32 n)
{
    return (n + 3u) & ~3u;
}

// Resolve a type's byte size. Called after the type has been
// fully built (composite types depend on prior types being
// sized).
u32 ComputeByteSize(Program* p, u32 type_id);

u32 ComputeByteSize(Program* p, u32 type_id)
{
    if (type_id == 0 || type_id >= kMaxIds || p->id_kinds[type_id] != IdKind::Type)
        return 0;
    TypeRecord& t = p->types[p->id_to_index[type_id]];
    if (t.byte_size != 0)
        return t.byte_size;
    switch (t.kind)
    {
    case TypeKind::Void:
        t.byte_size = 0;
        break;
    case TypeKind::Bool:
        t.byte_size = 4;
        break;
    case TypeKind::Int:
    case TypeKind::Float:
        t.byte_size = (t.width + 7u) / 8u;
        if (t.byte_size < 4u)
            t.byte_size = 4u;
        break;
    case TypeKind::Vector:
        t.byte_size = ComputeByteSize(p, t.component_id) * t.component_count;
        break;
    case TypeKind::Matrix:
    {
        // Column-major: each column is a vector of `component_count` rows;
        // `component_id` is the column-vector type. Matrix size = column_count * column_size.
        const u32 col_size = ComputeByteSize(p, t.component_id);
        t.byte_size = col_size * t.component_count;
        break;
    }
    case TypeKind::Array:
        t.byte_size = ComputeByteSize(p, t.component_id) * t.component_count;
        break;
    case TypeKind::Struct:
    {
        u32 sz = 0;
        for (u32 i = 0; i < t.member_count; ++i)
        {
            const u32 ms = ComputeByteSize(p, t.members[i]);
            const u32 effective = (t.member_offsets[i] != 0) ? t.member_offsets[i] + ms : sz + ms;
            if (effective > sz)
                sz = effective;
            else
                sz += ms;
        }
        t.byte_size = AlignUp4(sz);
        break;
    }
    case TypeKind::Pointer:
        t.byte_size = 4; // pointer-as-id sized for the interpreter
        break;
    case TypeKind::Function:
        t.byte_size = 0;
        break;
    }
    return t.byte_size;
}

// Assign a fresh offset for `var` in its storage heap and bump
// `used`. Returns true on success, false if the heap would overflow.
bool AssignStorage(Program* p, VariableRecord& var)
{
    StorageHeap* h = nullptr;
    switch (var.storage)
    {
    case StorageClass::Input:
        h = &p->input;
        break;
    case StorageClass::Output:
        h = &p->output;
        break;
    case StorageClass::UniformConstant:
        h = &p->uniform_constant;
        break;
    case StorageClass::Uniform:
        h = &p->uniform;
        break;
    case StorageClass::PushConstant:
        h = &p->push_constant;
        break;
    case StorageClass::Private:
    case StorageClass::Function: // for v1 Function storage is treated as Private (no recursion)
        h = &p->private_storage;
        break;
    }
    if (h == nullptr)
        return false;
    const u32 size = AlignUp4(var.byte_size);
    if (h->used + size > kMaxStorageBytes)
        return false;
    var.storage_offset = h->used;
    h->used += size;
    // Zero-initialise the slot so undefined SPIR-V "default" reads
    // return zero (not stack-garbage).
    for (u32 i = 0; i < size; ++i)
        h->bytes[var.storage_offset + i] = 0u;
    return true;
}

// Walk every instruction and pre-record the IdKind for the
// instruction's IdResult. Builds the id table the second pass
// relies on to resolve operands without lookahead.
bool FirstPassScan(Program* p)
{
    u32 i = 5; // skip header
    u32 next_type_idx = 0;
    u32 next_const_idx = 0;
    u32 next_var_idx = 0;
    u32 next_func_idx = 0;
    while (i < p->word_count)
    {
        const u32 w0 = p->words[i];
        const u32 wc = w0 >> 16;
        const u16 op = static_cast<u16>(w0 & 0xFFFFu);
        if (wc == 0 || i + wc > p->word_count)
            return false;
        switch (op)
        {
        case kOpTypeVoid:
        case kOpTypeBool:
        case kOpTypeInt:
        case kOpTypeFloat:
        case kOpTypeVector:
        case kOpTypeMatrix:
        case kOpTypeArray:
        case kOpTypeStruct:
        case kOpTypePointer:
        case kOpTypeFunction:
            if (next_type_idx >= kMaxIds)
                return false;
            RegisterId(p, p->words[i + 1], IdKind::Type, next_type_idx++);
            break;
        case kOpConstantTrue:
        case kOpConstantFalse:
        case kOpConstant:
        case kOpConstantComposite:
        case kOpConstantNull:
            if (next_const_idx >= kMaxConstants)
                return false;
            RegisterId(p, p->words[i + 2], IdKind::Constant, next_const_idx++);
            break;
        case kOpVariable:
            if (next_var_idx >= kMaxVariables)
                return false;
            RegisterId(p, p->words[i + 2], IdKind::Variable, next_var_idx++);
            break;
        case kOpFunction:
            if (next_func_idx >= kMaxFunctions)
                return false;
            RegisterId(p, p->words[i + 2], IdKind::Function, next_func_idx++);
            break;
        case kOpFunctionParameter:
            RegisterId(p, p->words[i + 2], IdKind::Param, 0);
            break;
        case kOpLabel:
            RegisterId(p, p->words[i + 1], IdKind::Label, 0);
            break;
        case kOpExtInstImport:
            RegisterId(p, p->words[i + 1], IdKind::ExtInst, 0);
            if (StringEqualsC(&p->words[i + 2], wc - 2, "GLSL.std.450"))
                p->ext_inst_glsl_id = p->words[i + 1];
            break;
        default:
            break;
        }
        i += wc;
    }
    p->type_count = next_type_idx;
    p->constant_count = next_const_idx;
    p->variable_count = next_var_idx;
    p->function_count = next_func_idx;
    return true;
}

bool BuildTypesAndConstants(Program* p)
{
    u32 i = 5;
    while (i < p->word_count)
    {
        const u32 w0 = p->words[i];
        const u32 wc = w0 >> 16;
        const u16 op = static_cast<u16>(w0 & 0xFFFFu);
        switch (op)
        {
        case kOpTypeVoid:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Void;
            break;
        }
        case kOpTypeBool:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Bool;
            t.width = 1;
            break;
        }
        case kOpTypeInt:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Int;
            t.width = p->words[i + 2];
            t.signedness = p->words[i + 3];
            break;
        }
        case kOpTypeFloat:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Float;
            t.width = p->words[i + 2];
            break;
        }
        case kOpTypeVector:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Vector;
            t.component_id = p->words[i + 2];
            t.component_count = p->words[i + 3];
            break;
        }
        case kOpTypeMatrix:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Matrix;
            t.component_id = p->words[i + 2];
            t.component_count = p->words[i + 3];
            break;
        }
        case kOpTypeArray:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Array;
            t.component_id = p->words[i + 2];
            // OpTypeArray's length is an id pointing at an OpConstant of int type.
            const u32 len_id = p->words[i + 3];
            if (len_id >= kMaxIds || p->id_kinds[len_id] != IdKind::Constant)
                return false;
            ConstantRecord& c = p->constants[p->id_to_index[len_id]];
            t.component_count = c.components[0].bits;
            break;
        }
        case kOpTypeStruct:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Struct;
            t.member_count = wc - 2;
            if (t.member_count > 16)
                t.member_count = 16;
            for (u32 m = 0; m < t.member_count; ++m)
                t.members[m] = p->words[i + 2 + m];
            break;
        }
        case kOpTypePointer:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Pointer;
            t.ptr_class = static_cast<StorageClass>(p->words[i + 2]);
            t.component_id = p->words[i + 3];
            break;
        }
        case kOpTypeFunction:
        {
            TypeRecord& t = p->types[p->id_to_index[p->words[i + 1]]];
            t.kind = TypeKind::Function;
            t.return_id = p->words[i + 2];
            t.param_count = wc - 3;
            if (t.param_count > 8)
                t.param_count = 8;
            for (u32 m = 0; m < t.param_count; ++m)
                t.params[m] = p->words[i + 3 + m];
            break;
        }
        case kOpConstantTrue:
        case kOpConstantFalse:
        {
            ConstantRecord& c = p->constants[p->id_to_index[p->words[i + 2]]];
            c.type_id = p->words[i + 1];
            c.component_count = 1;
            c.components[0].bits = (op == kOpConstantTrue) ? 1u : 0u;
            break;
        }
        case kOpConstant:
        {
            ConstantRecord& c = p->constants[p->id_to_index[p->words[i + 2]]];
            c.type_id = p->words[i + 1];
            c.component_count = 1;
            c.components[0].bits = p->words[i + 3];
            break;
        }
        case kOpConstantComposite:
        {
            ConstantRecord& c = p->constants[p->id_to_index[p->words[i + 2]]];
            c.type_id = p->words[i + 1];
            const u32 n = wc - 3;
            c.component_count = (n > 16) ? 16 : n;
            for (u32 m = 0; m < c.component_count; ++m)
            {
                const u32 child_id = p->words[i + 3 + m];
                if (child_id >= kMaxIds || p->id_kinds[child_id] != IdKind::Constant)
                    return false;
                ConstantRecord& cc = p->constants[p->id_to_index[child_id]];
                // Composite of scalars: copy the scalar bits. For
                // composite-of-vector we copy the first component
                // (good enough for v1 — caller can still walk
                // the constant table directly).
                c.components[m].bits = cc.components[0].bits;
            }
            break;
        }
        case kOpConstantNull:
        {
            ConstantRecord& c = p->constants[p->id_to_index[p->words[i + 2]]];
            c.type_id = p->words[i + 1];
            c.component_count = 1;
            c.components[0].bits = 0u;
            break;
        }
        default:
            break;
        }
        i += wc;
    }
    return true;
}

bool BuildVariablesAndEntries(Program* p)
{
    u32 i = 5;
    u32 ep_idx = 0;
    while (i < p->word_count)
    {
        const u32 w0 = p->words[i];
        const u32 wc = w0 >> 16;
        const u16 op = static_cast<u16>(w0 & 0xFFFFu);
        switch (op)
        {
        case kOpVariable:
        {
            VariableRecord& v = p->variables[p->id_to_index[p->words[i + 2]]];
            v.type_id = p->words[i + 1];
            v.storage = static_cast<StorageClass>(p->words[i + 3]);
            v.initializer_id = (wc >= 5) ? p->words[i + 4] : 0u;
            v.location = 0xFFFFFFFFu;
            v.builtin = 0xFFFFFFFFu;
            // Pointee type -> byte size.
            if (p->id_kinds[v.type_id] == IdKind::Type)
            {
                const TypeRecord& tr = p->types[p->id_to_index[v.type_id]];
                if (tr.kind == TypeKind::Pointer)
                    v.byte_size = ComputeByteSize(p, tr.component_id);
                else
                    v.byte_size = ComputeByteSize(p, v.type_id);
            }
            if (v.byte_size == 0)
                v.byte_size = 4;
            if (!AssignStorage(p, v))
                return false;
            break;
        }
        case kOpEntryPoint:
        {
            if (ep_idx >= kMaxEntryPoints)
                return false;
            EntryPointRecord& ep = p->entry_points[ep_idx++];
            ep.execution_model = p->words[i + 1];
            ep.function_id = p->words[i + 2];
            // String operand starts at i+3.
            const u32 max_str_words = wc - 3;
            const u32 nw = StringWordCount(&p->words[i + 3], max_str_words);
            if (nw == 0)
                return false;
            CopyString(ep.name, sizeof(ep.name), &p->words[i + 3], nw);
            const u32 iface_start = i + 3 + nw;
            const u32 iface_end = i + wc;
            const u32 iface_n = (iface_start < iface_end) ? iface_end - iface_start : 0u;
            ep.interface_count = (iface_n > 16) ? 16 : iface_n;
            for (u32 j = 0; j < ep.interface_count; ++j)
                ep.interface_ids[j] = p->words[iface_start + j];
            break;
        }
        default:
            break;
        }
        i += wc;
    }
    p->entry_point_count = ep_idx;
    return true;
}

void ApplyDecorations(Program* p)
{
    u32 i = 5;
    while (i < p->word_count)
    {
        const u32 w0 = p->words[i];
        const u32 wc = w0 >> 16;
        const u16 op = static_cast<u16>(w0 & 0xFFFFu);
        if (op == kOpDecorate)
        {
            const u32 target = p->words[i + 1];
            const u32 decoration = p->words[i + 2];
            if (target < kMaxIds && p->id_kinds[target] == IdKind::Variable)
            {
                VariableRecord& v = p->variables[p->id_to_index[target]];
                if (decoration == kDecorationLocation && wc >= 4)
                    v.location = p->words[i + 3];
                else if (decoration == kDecorationBuiltIn && wc >= 4)
                    v.builtin = p->words[i + 3];
            }
        }
        else if (op == kOpMemberDecorate)
        {
            const u32 target = p->words[i + 1];
            const u32 member = p->words[i + 2];
            const u32 decoration = p->words[i + 3];
            if (target < kMaxIds && p->id_kinds[target] == IdKind::Type)
            {
                TypeRecord& t = p->types[p->id_to_index[target]];
                if (decoration == kDecorationOffset && wc >= 5 && member < 16)
                    t.member_offsets[member] = p->words[i + 4];
            }
        }
        i += wc;
    }
}

bool BuildFunctionsAndInstructions(Program* p)
{
    u32 i = 5;
    u32 fn_idx = 0;
    u32 cur_fn = 0xFFFFFFFFu;
    u32 cur_bb_label = 0;
    u32 cur_bb_first_instr = 0;
    bool in_bb = false;
    while (i < p->word_count)
    {
        const u32 w0 = p->words[i];
        const u32 wc = w0 >> 16;
        const u16 op = static_cast<u16>(w0 & 0xFFFFu);
        switch (op)
        {
        case kOpFunction:
        {
            if (fn_idx >= kMaxFunctions)
                return false;
            FunctionRecord& f = p->functions[fn_idx];
            f.result_id = p->words[i + 2];
            f.type_id = p->words[i + 1];
            f.param_count = 0;
            f.bb_begin = p->block_count;
            cur_fn = fn_idx;
            ++fn_idx;
            break;
        }
        case kOpFunctionParameter:
        {
            if (cur_fn == 0xFFFFFFFFu)
                return false;
            FunctionRecord& f = p->functions[cur_fn];
            if (f.param_count >= 8)
                return false;
            f.params[f.param_count++] = p->words[i + 2];
            break;
        }
        case kOpFunctionEnd:
        {
            if (cur_fn == 0xFFFFFFFFu)
                return false;
            // Close any in-flight basic block.
            if (in_bb)
            {
                if (p->block_count >= kMaxBasicBlocks)
                    return false;
                BasicBlockRecord& bb = p->blocks[p->block_count++];
                bb.label_id = cur_bb_label;
                bb.instr_begin = cur_bb_first_instr;
                bb.instr_end = p->instruction_count;
                in_bb = false;
            }
            FunctionRecord& f = p->functions[cur_fn];
            f.bb_end = p->block_count;
            cur_fn = 0xFFFFFFFFu;
            break;
        }
        case kOpLabel:
        {
            // Start a new basic block. Close the prior one first
            // (a basic block always ends with a terminator, but we
            // close defensively in case the module is non-canonical).
            if (in_bb)
            {
                if (p->block_count >= kMaxBasicBlocks)
                    return false;
                BasicBlockRecord& bb = p->blocks[p->block_count++];
                bb.label_id = cur_bb_label;
                bb.instr_begin = cur_bb_first_instr;
                bb.instr_end = p->instruction_count;
            }
            cur_bb_label = p->words[i + 1];
            cur_bb_first_instr = p->instruction_count;
            in_bb = true;
            break;
        }
        default:
        {
            // Skip module-level instructions (capability,
            // extension, types, constants, decorations, names,
            // sources, entry points, execution modes, variables,
            // functions). Only instructions INSIDE a basic block
            // (between OpLabel and the block terminator) get
            // recorded as executable.
            if (in_bb)
            {
                if (p->instruction_count >= kMaxInstructions)
                    return false;
                InstructionRecord& ir = p->instructions[p->instruction_count++];
                ir.opcode = op;
                ir.word_count = static_cast<u16>(wc);
                ir.operands_word_offset = i;
                ir.type_id = 0;
                ir.result_id = 0;
                // Most ops have <Type,Result>. Common exceptions: terminator ops,
                // memory writes, control-flow merges. We capture both when wc >= 3
                // by checking the result-id table.
                if (wc >= 3 && p->id_kinds[p->words[i + 2]] != IdKind::None)
                {
                    ir.type_id = p->words[i + 1];
                    ir.result_id = p->words[i + 2];
                }
                else if (wc >= 2 && p->id_kinds[p->words[i + 1]] != IdKind::None)
                {
                    ir.result_id = p->words[i + 1];
                }
            }
            break;
        }
        }
        i += wc;
    }
    return true;
}

} // namespace

bool Parse(const u32* words, u32 word_count, Program* prog)
{
    if (prog == nullptr || words == nullptr || word_count < 5)
        return false;
    if (words[0] != 0x07230203u)
        return false;
    // Zero everything; `Program` is plain-old-data.
    auto* bytes = reinterpret_cast<u8*>(prog);
    for (u64 i = 0; i < sizeof(Program); ++i)
        bytes[i] = 0u;
    prog->words = words;
    prog->word_count = word_count;
    for (u32 i = 0; i < kMaxIds; ++i)
        prog->id_kinds[i] = IdKind::None;

    if (!FirstPassScan(prog))
        return false;
    if (!BuildTypesAndConstants(prog))
        return false;
    if (!BuildVariablesAndEntries(prog))
        return false;
    ApplyDecorations(prog);
    if (!BuildFunctionsAndInstructions(prog))
        return false;
    prog->parse_ok = true;
    return true;
}

bool WriteInputLocation(Program* prog, u32 location, const void* data, u32 byte_size)
{
    if (prog == nullptr || data == nullptr)
        return false;
    for (u32 i = 0; i < prog->variable_count; ++i)
    {
        VariableRecord& v = prog->variables[i];
        if (v.storage != StorageClass::Input || v.location != location)
            continue;
        const u32 n = (byte_size < v.byte_size) ? byte_size : v.byte_size;
        const auto* src = static_cast<const u8*>(data);
        for (u32 b = 0; b < n; ++b)
            prog->input.bytes[v.storage_offset + b] = src[b];
        return true;
    }
    return false;
}

bool WriteInputBuiltin(Program* prog, u32 builtin, const void* data, u32 byte_size)
{
    if (prog == nullptr || data == nullptr)
        return false;
    for (u32 i = 0; i < prog->variable_count; ++i)
    {
        VariableRecord& v = prog->variables[i];
        if (v.storage != StorageClass::Input || v.builtin != builtin)
            continue;
        const u32 n = (byte_size < v.byte_size) ? byte_size : v.byte_size;
        const auto* src = static_cast<const u8*>(data);
        for (u32 b = 0; b < n; ++b)
            prog->input.bytes[v.storage_offset + b] = src[b];
        return true;
    }
    return false;
}

bool ReadOutputLocation(const Program* prog, u32 location, void* out, u32 byte_size)
{
    if (prog == nullptr || out == nullptr)
        return false;
    for (u32 i = 0; i < prog->variable_count; ++i)
    {
        const VariableRecord& v = prog->variables[i];
        if (v.storage != StorageClass::Output || v.location != location)
            continue;
        const u32 n = (byte_size < v.byte_size) ? byte_size : v.byte_size;
        auto* dst = static_cast<u8*>(out);
        for (u32 b = 0; b < n; ++b)
            dst[b] = prog->output.bytes[v.storage_offset + b];
        return true;
    }
    return false;
}

bool ReadOutputBuiltin(const Program* prog, u32 builtin, void* out, u32 byte_size)
{
    if (prog == nullptr || out == nullptr)
        return false;
    for (u32 i = 0; i < prog->variable_count; ++i)
    {
        const VariableRecord& v = prog->variables[i];
        if (v.storage != StorageClass::Output)
            continue;
        // Output vars with `Block` decoration carry per-member
        // BuiltIns (gl_PerVertex's Position). For v1 we look at
        // the variable's own BuiltIn AND the first member's
        // builtin via OpMemberDecorate. The Struct-member path is
        // wired via t.member_offsets[0]; if the variable points
        // at a Block struct, we fetch from offset 0 (the
        // canonical place glslang puts Position).
        if (v.builtin == builtin)
        {
            const u32 n = (byte_size < v.byte_size) ? byte_size : v.byte_size;
            auto* dst = static_cast<u8*>(out);
            for (u32 b = 0; b < n; ++b)
                dst[b] = prog->output.bytes[v.storage_offset + b];
            return true;
        }
        // Block-wrapped builtin (gl_PerVertex.gl_Position). Walk
        // the pointee type if it's a Struct and check member 0.
        if (v.type_id < kMaxIds && prog->id_kinds[v.type_id] == IdKind::Type)
        {
            const TypeRecord& ptr = prog->types[prog->id_to_index[v.type_id]];
            if (ptr.kind != TypeKind::Pointer)
                continue;
            const u32 pointee_id = ptr.component_id;
            if (pointee_id >= kMaxIds || prog->id_kinds[pointee_id] != IdKind::Type)
                continue;
            // We can't see OpMemberDecorate BuiltIn directly without
            // re-walking, but the typical glslang output places
            // Position at member 0 with byte offset 0 — so for v1
            // we satisfy the request by reading from offset 0 when
            // the requested builtin is Position.
            if (builtin == builtins::kPosition)
            {
                const u32 n = (byte_size < v.byte_size) ? byte_size : v.byte_size;
                auto* dst = static_cast<u8*>(out);
                for (u32 b = 0; b < n; ++b)
                    dst[b] = prog->output.bytes[v.storage_offset + b];
                return true;
            }
        }
    }
    return false;
}

void ResetIO(Program* prog)
{
    if (prog == nullptr)
        return;
    for (u32 i = 0; i < prog->input.used; ++i)
        prog->input.bytes[i] = 0u;
    for (u32 i = 0; i < prog->output.used; ++i)
        prog->output.bytes[i] = 0u;
}

} // namespace duetos::subsystems::graphics::spirv
