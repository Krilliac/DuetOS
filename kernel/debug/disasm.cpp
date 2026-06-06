#include "debug/disasm.h"

#include "diag/fix_journal.h"
#include "util/symbols.h"
#include "log/klog.h"

namespace duetos::debug::disasm
{

namespace
{

// Tiny per-byte category for `db` rows. Real x86_64 has hundreds
// of opcodes; the categories here are deliberately coarse — the
// goal is to give the operator a one-word hint why the decoder
// rejected a byte, not to reimplement a full opcode map.
const char* ClassifyRejectedByte(u8 b)
{
    if (b >= 0xC4 && b <= 0xC5)
        return "vex";
    if (b == 0x62)
        return "evex";
    if (b == 0xD8 || b == 0xD9 || b == 0xDA || b == 0xDB || b == 0xDC || b == 0xDD || b == 0xDE || b == 0xDF)
        return "x87";
    if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3)
        return "prefix";
    if (b >= 0x40 && b <= 0x4F)
        return "rex";
    if (b == 0xCA || b == 0xCB)
        return "ret-far";
    if (b == 0x9A || b == 0xEA)
        return "far-jmp";
    if (b == 0x0F)
        return "0f-escape";
    return "unknown";
}

// ---- string helpers (allocation-free, NUL-safe) -------------

constexpr u32 kBufBytes = sizeof(DecodedInsn::bytes_text);
constexpr u32 kBufMnem = sizeof(DecodedInsn::mnemonic);
constexpr u32 kBufOpr = sizeof(DecodedInsn::operands);

void StrCopy(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    while (src[i] != 0 && i + 1 < cap)
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = 0;
}

void StrAppend(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    while (i + 1 < cap && dst[i] != 0)
        ++i;
    u32 j = 0;
    while (src[j] != 0 && i + 1 < cap)
    {
        dst[i++] = src[j++];
    }
    dst[i] = 0;
}

void AppendChar(char* dst, u32 cap, char c)
{
    u32 i = 0;
    while (i + 1 < cap && dst[i] != 0)
        ++i;
    if (i + 1 < cap)
    {
        dst[i] = c;
        dst[i + 1] = 0;
    }
}

void AppendHexU8(char* dst, u32 cap, u8 v)
{
    static const char kHex[] = "0123456789abcdef";
    char two[3] = {kHex[(v >> 4) & 0xF], kHex[v & 0xF], 0};
    StrAppend(dst, cap, two);
}

void AppendHexU64(char* dst, u32 cap, u64 v)
{
    static const char kHex[] = "0123456789abcdef";
    if (v == 0)
    {
        StrAppend(dst, cap, "0x0");
        return;
    }
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    char tmp[17];
    u32 n = 0;
    while (v != 0 && n < 16)
    {
        tmp[n++] = kHex[v & 0xF];
        v >>= 4;
    }
    u32 w = 2;
    while (n > 0 && w + 1 < sizeof(buf))
        buf[w++] = tmp[--n];
    buf[w] = 0;
    StrAppend(dst, cap, buf);
}

// Signed displacement printed as +0xNN / -0xNN with a leading
// space so the caller can blindly concatenate inside an operand.
void AppendSignedHex(char* dst, u32 cap, i64 v)
{
    if (v < 0)
    {
        AppendChar(dst, cap, '-');
        AppendHexU64(dst, cap, static_cast<u64>(-v));
    }
    else
    {
        AppendChar(dst, cap, '+');
        AppendHexU64(dst, cap, static_cast<u64>(v));
    }
}

// ---- register name tables -----------------------------------

// Indexed by REX.B/X/R-extended 4-bit register number. Width
// selectors live in the four arrays below.
constexpr const char* k64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                 "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
constexpr const char* k32[16] = {"eax", "ecx", "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
                                 "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
constexpr const char* k16[16] = {"ax",  "cx",  "dx",   "bx",   "sp",   "bp",   "si",   "di",
                                 "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
// 8-bit gets two arrays — REX-present uses spl/bpl/sil/dil for 4..7;
// no-REX uses ah/ch/dh/bh.
constexpr const char* k8RexPresent[16] = {"al",  "cl",  "dl",   "bl",   "spl",  "bpl",  "sil",  "dil",
                                          "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
constexpr const char* k8NoRex[8] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
// SSE/SSE2 XMM register file (REX.R/B-extended 4-bit index).
constexpr const char* kXmm[16] = {"xmm0", "xmm1", "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7",
                                  "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"};

// 16 condition-code mnemonics for Jcc / SETcc / CMOVcc. Indexed by
// the low nibble of the opcode (0x70..0x7F for short Jcc).
constexpr const char* kCc[16] = {"o", "no", "b", "ae", "e", "ne", "be", "a",
                                 "s", "ns", "p", "np", "l", "ge", "le", "g"};

// Operand width selector. 64 only when REX.W=1; 32 default; 16 when
// 0x66 prefix; 8 for byte-form opcodes.
enum class OpW : u8
{
    B8,
    W16,
    D32,
    Q64,
    X128 // XMM register / 128-bit SSE memory operand
};

const char* RegName(u8 idx, OpW w, bool rex_seen)
{
    idx &= 0xF;
    switch (w)
    {
    case OpW::B8:
        if (rex_seen)
            return k8RexPresent[idx];
        return idx < 8 ? k8NoRex[idx] : k8RexPresent[idx];
    case OpW::W16:
        return k16[idx];
    case OpW::D32:
        return k32[idx];
    case OpW::Q64:
        return k64[idx];
    case OpW::X128:
        return kXmm[idx];
    }
    return "?";
}

// Width-keyword used inside `[...]` for memory operands.
const char* PtrKeyword(OpW w)
{
    switch (w)
    {
    case OpW::B8:
        return "byte ptr ";
    case OpW::W16:
        return "word ptr ";
    case OpW::D32:
        return "dword ptr ";
    case OpW::Q64:
        return "qword ptr ";
    case OpW::X128:
        return "xmmword ptr ";
    }
    return "";
}

// ---- prefix / REX state -------------------------------------

struct PrefixState
{
    bool osize;    // 0x66
    bool asize;    // 0x67
    bool lock;     // 0xF0
    bool repne;    // 0xF2
    bool rep;      // 0xF3
    u8 seg;        // 0=none, 0x2E cs, 0x36 ss, 0x3E ds, 0x26 es, 0x64 fs, 0x65 gs
    bool rex_seen; // any REX byte in 0x40..0x4F was consumed
    bool rex_w;    // REX.W
    bool rex_r;    // REX.R
    bool rex_x;    // REX.X
    bool rex_b;    // REX.B
};

const char* SegName(u8 seg)
{
    switch (seg)
    {
    case 0x26:
        return "es:";
    case 0x2E:
        return "cs:";
    case 0x36:
        return "ss:";
    case 0x3E:
        return "ds:";
    case 0x64:
        return "fs:";
    case 0x65:
        return "gs:";
    }
    return "";
}

OpW GprWidth(const PrefixState& p, bool byte_form)
{
    if (byte_form)
        return OpW::B8;
    if (p.rex_w)
        return OpW::Q64;
    if (p.osize)
        return OpW::W16;
    return OpW::D32;
}

// ---- ModRM / SIB / displacement -----------------------------

struct ModRm
{
    u8 mod;     // 0..3
    u8 reg_idx; // 0..15 (with REX.R extension)
    u8 rm_idx;  // 0..15 (with REX.B extension)
    u8 raw;
};

ModRm DecodeModRmByte(u8 b, const PrefixState& p)
{
    ModRm m;
    m.raw = b;
    m.mod = (b >> 6) & 0x3;
    m.reg_idx = (b >> 3) & 0x7;
    m.rm_idx = b & 0x7;
    if (p.rex_r)
        m.reg_idx |= 0x8;
    if (p.rex_b)
        m.rm_idx |= 0x8;
    return m;
}

// Format the r/m operand into `dst`. When `mod == 3` the operand
// is a register, sized per `w`. Otherwise the operand is a memory
// reference; the caller already knows the implicit width and
// passes it through `mem_w`. Returns bytes consumed AFTER the
// ModRM byte itself (SIB + displacement). On under-run, returns
// 0xFF — the caller must treat this as a `db` row.
u8 FormatRmOperand(char* dst, u32 cap, const ModRm& mod_rm, OpW reg_w, OpW mem_w, const PrefixState& p,
                   const u8* trailing, u64 trailing_avail)
{
    if (mod_rm.mod == 3)
    {
        StrAppend(dst, cap, RegName(mod_rm.rm_idx, reg_w, p.rex_seen));
        return 0;
    }

    // Build the "[base+index*scale+disp]" string. Track the
    // bytes consumed past the ModRM byte for the caller.
    u8 consumed = 0;
    u8 base_idx = mod_rm.rm_idx;
    bool has_index = false;
    u8 index_idx = 0;
    u8 scale = 0;
    bool needs_disp32_only = false;

    // SIB present when base 3 bits == 4 (rm_idx low nibble == 4).
    if ((mod_rm.rm_idx & 0x7) == 4)
    {
        if (trailing_avail < 1)
            return 0xFF;
        const u8 sib = trailing[0];
        consumed = 1;
        scale = (sib >> 6) & 0x3;
        index_idx = (sib >> 3) & 0x7;
        if (p.rex_x)
            index_idx |= 0x8;
        u8 sib_base = sib & 0x7;
        if (p.rex_b)
            sib_base |= 0x8;
        base_idx = sib_base;
        // index == 4 (rsp) means "no index" by encoding rule.
        has_index = (index_idx & 0x7) != 4;
        // Special case: mod==0, base==5 (low 3 bits) → no base
        // register, just disp32.
        if (mod_rm.mod == 0 && (sib_base & 0x7) == 5)
        {
            needs_disp32_only = true;
        }
    }

    // RIP-relative: mod==0, rm low3==5, no SIB. 32-bit disp added
    // to RIP-of-next-insn at runtime; we surface it as a numeric
    // VA computed against the caller's `va` later — but the
    // formatter doesn't know the VA, so emit "[rip+/-disp]". The
    // caller may rewrite this to a symbol name post-hoc.
    bool rip_rel = (mod_rm.mod == 0 && (mod_rm.rm_idx & 0x7) == 5 && (mod_rm.rm_idx & 0x7) != 4);
    if (rip_rel)
    {
        needs_disp32_only = false;
    }

    // Displacement bytes: mod 1 → 1 byte, mod 2 → 4 bytes,
    // mod 0 with the special cases above → 4 bytes; otherwise 0.
    u8 disp_bytes = 0;
    if (mod_rm.mod == 1)
        disp_bytes = 1;
    else if (mod_rm.mod == 2)
        disp_bytes = 4;
    else if (rip_rel || needs_disp32_only)
        disp_bytes = 4;

    if (trailing_avail < static_cast<u64>(consumed) + disp_bytes)
        return 0xFF;

    i64 disp = 0;
    if (disp_bytes == 1)
    {
        disp = static_cast<i64>(static_cast<i8>(trailing[consumed]));
    }
    else if (disp_bytes == 4)
    {
        u32 raw = static_cast<u32>(trailing[consumed]) | (static_cast<u32>(trailing[consumed + 1]) << 8) |
                  (static_cast<u32>(trailing[consumed + 2]) << 16) | (static_cast<u32>(trailing[consumed + 3]) << 24);
        disp = static_cast<i64>(static_cast<i32>(raw));
    }
    consumed += disp_bytes;

    // Emit the assembly text.
    StrAppend(dst, cap, PtrKeyword(mem_w));
    StrAppend(dst, cap, SegName(p.seg));
    AppendChar(dst, cap, '[');
    bool wrote_term = false;
    if (rip_rel)
    {
        StrAppend(dst, cap, "rip");
        wrote_term = true;
    }
    else if (!needs_disp32_only)
    {
        StrAppend(dst, cap, k64[base_idx]);
        wrote_term = true;
    }
    if (has_index)
    {
        if (wrote_term)
            AppendChar(dst, cap, '+');
        StrAppend(dst, cap, k64[index_idx]);
        if (scale > 0)
        {
            AppendChar(dst, cap, '*');
            char s[2] = {static_cast<char>('0' + (1 << scale)), 0};
            StrAppend(dst, cap, s);
        }
        wrote_term = true;
    }
    if (disp_bytes != 0 && (disp != 0 || !wrote_term))
    {
        if (wrote_term)
        {
            AppendSignedHex(dst, cap, disp);
        }
        else
        {
            AppendHexU64(dst, cap, static_cast<u64>(disp) & 0xFFFFFFFFULL);
        }
    }
    AppendChar(dst, cap, ']');
    return consumed;
}

// Read a little-endian unsigned immediate of `bytes` width
// from `src` (caller has bounds-checked). Sign-extends on demand.
i64 ReadImmSigned(const u8* src, u8 bytes)
{
    switch (bytes)
    {
    case 1:
        return static_cast<i64>(static_cast<i8>(src[0]));
    case 2:
        return static_cast<i64>(static_cast<i16>(static_cast<u16>(src[0]) | (static_cast<u16>(src[1]) << 8)));
    case 4:
        return static_cast<i64>(static_cast<i32>(static_cast<u32>(src[0]) | (static_cast<u32>(src[1]) << 8) |
                                                 (static_cast<u32>(src[2]) << 16) | (static_cast<u32>(src[3]) << 24)));
    case 8:
    {
        u64 v = 0;
        for (u8 i = 0; i < 8; ++i)
            v |= (static_cast<u64>(src[i]) << (i * 8));
        return static_cast<i64>(v);
    }
    }
    return 0;
}

u64 ReadImmU(const u8* src, u8 bytes)
{
    u64 v = 0;
    for (u8 i = 0; i < bytes; ++i)
        v |= (static_cast<u64>(src[i]) << (i * 8));
    return v;
}

// ---- branch-target formatter --------------------------------

// Append "0xVA" and, if the symbol resolver knows it, " <symbol>+0xOFF".
// Used by Jcc / CALL / JMP rel-emitters. Pulls from the embedded
// kernel .symtab via ResolveAddress; safe in any context (no
// allocation, no locks).
void AppendBranchTarget(char* dst, u32 cap, u64 va)
{
    AppendHexU64(dst, cap, va);
    core::SymbolResolution sr;
    if (!core::ResolveAddress(va, &sr) || sr.entry == nullptr)
        return;
    StrAppend(dst, cap, " <");
    StrAppend(dst, cap, sr.entry->name);
    if (sr.offset != 0)
    {
        AppendChar(dst, cap, '+');
        AppendHexU64(dst, cap, sr.offset);
    }
    AppendChar(dst, cap, '>');
}

} // namespace

// ---- public API ---------------------------------------------

u8 DecodeOne(const u8* bytes, u64 available, u64 va, DecodedInsn* out)
{
    if (out == nullptr || bytes == nullptr || available == 0)
        return 0;

    out->addr = va;
    out->len = 0;
    out->decoded = false;
    out->bytes_text[0] = 0;
    out->mnemonic[0] = 0;
    out->operands[0] = 0;

    u8 cur = 0;
    PrefixState p = {};

    // 1. Prefix loop. REX (0x40..0x4F) terminates the loop.
    while (cur < available && cur < kMaxInsnLen)
    {
        const u8 b = bytes[cur];
        if (b == 0x66)
        {
            p.osize = true;
        }
        else if (b == 0x67)
        {
            p.asize = true;
        }
        else if (b == 0xF0)
        {
            p.lock = true;
        }
        else if (b == 0xF2)
        {
            p.repne = true;
        }
        else if (b == 0xF3)
        {
            p.rep = true;
        }
        else if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x64 || b == 0x65)
        {
            p.seg = b;
        }
        else if (b >= 0x40 && b <= 0x4F)
        {
            p.rex_seen = true;
            p.rex_w = (b & 0x8) != 0;
            p.rex_r = (b & 0x4) != 0;
            p.rex_x = (b & 0x2) != 0;
            p.rex_b = (b & 0x1) != 0;
            ++cur;
            break;
        }
        else
        {
            break;
        }
        ++cur;
    }

    if (cur >= available)
    {
        // Truncated — emit a `db 0x??` for the first byte.
        out->len = 1;
        out->decoded = false;
        AppendHexU8(out->bytes_text, kBufBytes, bytes[0]);
        StrCopy(out->mnemonic, kBufMnem, "db");
        AppendChar(out->operands, kBufOpr, '0');
        AppendChar(out->operands, kBufOpr, 'x');
        AppendHexU8(out->operands, kBufOpr, bytes[0]);
        return 1;
    }

    auto fail_db = [&](u8 byte_at) -> u8
    {
        out->len = 1;
        out->decoded = false;
        out->bytes_text[0] = 0;
        AppendHexU8(out->bytes_text, kBufBytes, byte_at);
        StrCopy(out->mnemonic, kBufMnem, "db");
        out->operands[0] = 0;
        AppendChar(out->operands, kBufOpr, '0');
        AppendChar(out->operands, kBufOpr, 'x');
        AppendHexU8(out->operands, kBufOpr, byte_at);
        const char* hint = ClassifyRejectedByte(byte_at);
        if (hint != nullptr && hint[0] != 0)
        {
            StrAppend(out->operands, kBufOpr, "  ; ");
            StrAppend(out->operands, kBufOpr, hint);
        }
        return 1;
    };

    auto record_bytes = [&](u8 total)
    {
        out->bytes_text[0] = 0;
        for (u8 i = 0; i < total; ++i)
        {
            if (i != 0)
                AppendChar(out->bytes_text, kBufBytes, ' ');
            AppendHexU8(out->bytes_text, kBufBytes, bytes[i]);
        }
    };

    // 2. Read the primary opcode.
    const u8 op = bytes[cur];
    u8 opc_at = cur;
    ++cur;

    // ---- helper: ALU base forms (0x00..0x3D regular pattern) ----
    auto handle_alu_base = [&](const char* mnem, u8 form) -> u8
    {
        // form 0: rm8, reg8     (op + ModRM)
        // form 1: rm,  reg      (op + ModRM)
        // form 2: reg8, rm8     (op + ModRM)
        // form 3: reg, rm       (op + ModRM)
        // form 4: AL, imm8      (op + imm8)
        // form 5: rAX, imm{32}  (op + imm32, sign-ext if Q64)
        if (form == 4)
        {
            if (cur >= available)
                return fail_db(bytes[opc_at]);
            const u8 imm = bytes[cur];
            ++cur;
            StrCopy(out->mnemonic, kBufMnem, mnem);
            StrAppend(out->operands, kBufOpr, "al, ");
            AppendChar(out->operands, kBufOpr, '0');
            AppendChar(out->operands, kBufOpr, 'x');
            AppendHexU8(out->operands, kBufOpr, imm);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        if (form == 5)
        {
            const u8 imm_bytes = p.osize ? 2 : 4;
            if (cur + imm_bytes > available)
                return fail_db(bytes[opc_at]);
            const i64 imm = ReadImmSigned(&bytes[cur], imm_bytes);
            cur += imm_bytes;
            StrCopy(out->mnemonic, kBufMnem, mnem);
            const OpW w = GprWidth(p, false);
            StrAppend(out->operands, kBufOpr, RegName(0, w, p.rex_seen));
            StrAppend(out->operands, kBufOpr, ", ");
            AppendHexU64(out->operands, kBufOpr, static_cast<u64>(imm));
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // form 0..3: read ModRM.
        if (cur >= available)
            return fail_db(bytes[opc_at]);
        const ModRm mr = DecodeModRmByte(bytes[cur], p);
        ++cur;
        const bool byte_form = (form == 0) || (form == 2);
        const OpW w = GprWidth(p, byte_form);
        char rm_buf[48] = {0};
        const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
        if (rm_extra == 0xFF)
            return fail_db(bytes[opc_at]);
        cur += rm_extra;
        StrCopy(out->mnemonic, kBufMnem, mnem);
        if (form == 0 || form == 1)
        {
            StrAppend(out->operands, kBufOpr, rm_buf);
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
        }
        else
        {
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, rm_buf);
        }
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    };

    // ---- ALU base opcode dispatch (0x00..0x3D regular grid) ----
    // Only the six valid ALU forms (op & 0x7 < 6) — forms 6/7 are
    // segment-prefix / push-seg encodings (0x06/0x07/0x0E/0x16/...
    // /0x3F). 0x0F in particular is the two-byte-opcode escape and
    // must reach the dedicated handler below; falling into the
    // ALU branch would `fail_db` it and lose syscall/jcc-rel32/etc.
    if (op <= 0x3D && (op & 0x7) < 6)
    {
        static const char* const kAluMnem[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
        const u8 group = (op >> 3) & 0x7;
        const u8 form = op & 0x7;
        return handle_alu_base(kAluMnem[group], form);
    }

    // ---- 0x50..0x5F: PUSH/POP reg short forms ----
    if (op >= 0x50 && op <= 0x5F)
    {
        const bool is_pop = (op & 0x8) != 0;
        const u8 idx = (op & 0x7) | (p.rex_b ? 0x8 : 0);
        StrCopy(out->mnemonic, kBufMnem, is_pop ? "pop" : "push");
        StrAppend(out->operands, kBufOpr, k64[idx]);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0x68 PUSH imm32 / 0x6A PUSH imm8 ----
    if (op == 0x68 || op == 0x6A)
    {
        const u8 imm_bytes = (op == 0x6A) ? 1 : 4;
        if (cur + imm_bytes > available)
            return fail_db(op);
        const i64 imm = ReadImmSigned(&bytes[cur], imm_bytes);
        cur += imm_bytes;
        StrCopy(out->mnemonic, kBufMnem, "push");
        AppendHexU64(out->operands, kBufOpr, static_cast<u64>(imm));
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0x70..0x7F: Jcc rel8 ----
    if (op >= 0x70 && op <= 0x7F)
    {
        if (cur + 1 > available)
            return fail_db(op);
        const i8 rel = static_cast<i8>(bytes[cur]);
        ++cur;
        const u64 target = va + cur + static_cast<i64>(rel);
        char m[8] = {0};
        StrAppend(m, sizeof(m), "j");
        StrAppend(m, sizeof(m), kCc[op & 0xF]);
        StrCopy(out->mnemonic, kBufMnem, m);
        AppendBranchTarget(out->operands, kBufOpr, target);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0x80/0x81/0x83: ALU group 1 (rm, imm) ----
    if (op == 0x80 || op == 0x81 || op == 0x83)
    {
        if (cur >= available)
            return fail_db(op);
        const ModRm mr = DecodeModRmByte(bytes[cur], p);
        ++cur;
        static const char* const kAluMnem[8] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
        const bool byte_form = (op == 0x80);
        const OpW w = GprWidth(p, byte_form);
        char rm_buf[48] = {0};
        const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
        if (rm_extra == 0xFF)
            return fail_db(op);
        cur += rm_extra;
        u8 imm_bytes = 1;
        if (op == 0x81)
            imm_bytes = p.osize ? 2 : 4;
        if (cur + imm_bytes > available)
            return fail_db(op);
        const i64 imm = ReadImmSigned(&bytes[cur], imm_bytes);
        cur += imm_bytes;
        StrCopy(out->mnemonic, kBufMnem, kAluMnem[mr.reg_idx & 0x7]);
        StrAppend(out->operands, kBufOpr, rm_buf);
        StrAppend(out->operands, kBufOpr, ", ");
        AppendHexU64(out->operands, kBufOpr, static_cast<u64>(imm));
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0x84/0x85: TEST rm, reg ----
    if (op == 0x84 || op == 0x85)
    {
        if (cur >= available)
            return fail_db(op);
        const ModRm mr = DecodeModRmByte(bytes[cur], p);
        ++cur;
        const bool byte_form = (op == 0x84);
        const OpW w = GprWidth(p, byte_form);
        char rm_buf[48] = {0};
        const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
        if (rm_extra == 0xFF)
            return fail_db(op);
        cur += rm_extra;
        StrCopy(out->mnemonic, kBufMnem, "test");
        StrAppend(out->operands, kBufOpr, rm_buf);
        StrAppend(out->operands, kBufOpr, ", ");
        StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0x88..0x8B: MOV rm,reg / reg,rm ----
    if (op >= 0x88 && op <= 0x8B)
    {
        if (cur >= available)
            return fail_db(op);
        const ModRm mr = DecodeModRmByte(bytes[cur], p);
        ++cur;
        const bool byte_form = (op == 0x88) || (op == 0x8A);
        const bool reg_first = (op == 0x8A) || (op == 0x8B);
        const OpW w = GprWidth(p, byte_form);
        char rm_buf[48] = {0};
        const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
        if (rm_extra == 0xFF)
            return fail_db(op);
        cur += rm_extra;
        StrCopy(out->mnemonic, kBufMnem, "mov");
        if (reg_first)
        {
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, rm_buf);
        }
        else
        {
            StrAppend(out->operands, kBufOpr, rm_buf);
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
        }
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0x8D: LEA reg, mem ----
    if (op == 0x8D)
    {
        if (cur >= available)
            return fail_db(op);
        const ModRm mr = DecodeModRmByte(bytes[cur], p);
        ++cur;
        if (mr.mod == 3)
            return fail_db(op); // LEA with reg src is invalid
        const OpW w = GprWidth(p, false);
        char rm_buf[48] = {0};
        const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
        if (rm_extra == 0xFF)
            return fail_db(op);
        cur += rm_extra;
        StrCopy(out->mnemonic, kBufMnem, "lea");
        StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
        StrAppend(out->operands, kBufOpr, ", ");
        StrAppend(out->operands, kBufOpr, rm_buf);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0x90: NOP (also XCHG eax, eax — alias) ----
    if (op == 0x90 && !p.rep && !p.repne)
    {
        StrCopy(out->mnemonic, kBufMnem, "nop");
        out->operands[0] = 0;
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0xB0..0xBF: MOV reg, imm ----
    if (op >= 0xB0 && op <= 0xBF)
    {
        const bool byte_form = (op < 0xB8);
        const u8 reg_idx = (op & 0x7) | (p.rex_b ? 0x8 : 0);
        const OpW w = GprWidth(p, byte_form);
        u8 imm_bytes = 1;
        if (!byte_form)
            imm_bytes = p.osize ? 2 : (p.rex_w ? 8 : 4);
        if (cur + imm_bytes > available)
            return fail_db(op);
        const u64 imm = ReadImmU(&bytes[cur], imm_bytes);
        cur += imm_bytes;
        StrCopy(out->mnemonic, kBufMnem, "mov");
        StrAppend(out->operands, kBufOpr, RegName(reg_idx, w, p.rex_seen));
        StrAppend(out->operands, kBufOpr, ", ");
        AppendHexU64(out->operands, kBufOpr, imm);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0xC2 RET imm16 / 0xC3 RET ----
    if (op == 0xC3)
    {
        StrCopy(out->mnemonic, kBufMnem, "ret");
        out->operands[0] = 0;
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }
    if (op == 0xC2)
    {
        if (cur + 2 > available)
            return fail_db(op);
        const u16 imm = static_cast<u16>(bytes[cur]) | (static_cast<u16>(bytes[cur + 1]) << 8);
        cur += 2;
        StrCopy(out->mnemonic, kBufMnem, "ret");
        AppendHexU64(out->operands, kBufOpr, static_cast<u64>(imm));
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0xC6/0xC7: MOV rm, imm (group 11) ----
    if (op == 0xC6 || op == 0xC7)
    {
        if (cur >= available)
            return fail_db(op);
        const ModRm mr = DecodeModRmByte(bytes[cur], p);
        ++cur;
        if ((mr.reg_idx & 0x7) != 0)
            return fail_db(op); // /0 only for MOV
        const bool byte_form = (op == 0xC6);
        const OpW w = GprWidth(p, byte_form);
        char rm_buf[48] = {0};
        const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
        if (rm_extra == 0xFF)
            return fail_db(op);
        cur += rm_extra;
        u8 imm_bytes = byte_form ? 1 : (p.osize ? 2 : 4);
        if (cur + imm_bytes > available)
            return fail_db(op);
        const u64 imm = ReadImmU(&bytes[cur], imm_bytes);
        cur += imm_bytes;
        StrCopy(out->mnemonic, kBufMnem, "mov");
        StrAppend(out->operands, kBufOpr, rm_buf);
        StrAppend(out->operands, kBufOpr, ", ");
        AppendHexU64(out->operands, kBufOpr, imm);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0xC9: LEAVE ----
    if (op == 0xC9)
    {
        StrCopy(out->mnemonic, kBufMnem, "leave");
        out->operands[0] = 0;
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0xCC INT3 / 0xCD INT imm8 / 0xCF IRETQ ----
    if (op == 0xCC)
    {
        StrCopy(out->mnemonic, kBufMnem, "int3");
        out->operands[0] = 0;
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }
    if (op == 0xCD)
    {
        if (cur + 1 > available)
            return fail_db(op);
        const u8 imm = bytes[cur];
        ++cur;
        StrCopy(out->mnemonic, kBufMnem, "int");
        AppendChar(out->operands, kBufOpr, '0');
        AppendChar(out->operands, kBufOpr, 'x');
        AppendHexU8(out->operands, kBufOpr, imm);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }
    if (op == 0xCF)
    {
        StrCopy(out->mnemonic, kBufMnem, p.rex_w ? "iretq" : "iretd");
        out->operands[0] = 0;
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0xE8 CALL rel32 / 0xE9 JMP rel32 / 0xEB JMP rel8 ----
    if (op == 0xE8 || op == 0xE9)
    {
        if (cur + 4 > available)
            return fail_db(op);
        const i32 rel = static_cast<i32>(ReadImmU(&bytes[cur], 4));
        cur += 4;
        const u64 target = va + cur + static_cast<i64>(rel);
        StrCopy(out->mnemonic, kBufMnem, op == 0xE8 ? "call" : "jmp");
        AppendBranchTarget(out->operands, kBufOpr, target);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }
    if (op == 0xEB)
    {
        if (cur + 1 > available)
            return fail_db(op);
        const i8 rel = static_cast<i8>(bytes[cur]);
        ++cur;
        const u64 target = va + cur + static_cast<i64>(rel);
        StrCopy(out->mnemonic, kBufMnem, "jmp");
        AppendBranchTarget(out->operands, kBufOpr, target);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0xF4 HLT, 0xFA CLI, 0xFB STI, 0xFC CLD, 0xFD STD ----
    static const struct
    {
        u8 byte;
        const char* mnem;
    } kOneByteSimple[] = {{0xF4, "hlt"}, {0xFA, "cli"}, {0xFB, "sti"}, {0xFC, "cld"}, {0xFD, "std"}};
    for (const auto& e : kOneByteSimple)
    {
        if (op == e.byte)
        {
            StrCopy(out->mnemonic, kBufMnem, e.mnem);
            out->operands[0] = 0;
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
    }

    // ---- 0xF6/0xF7: unary group 3 (TEST/NOT/NEG/MUL/IMUL/DIV/IDIV) ----
    if (op == 0xF6 || op == 0xF7)
    {
        if (cur >= available)
            return fail_db(op);
        const ModRm mr = DecodeModRmByte(bytes[cur], p);
        ++cur;
        static const char* const kUnary[8] = {"test", "test", "not", "neg", "mul", "imul", "div", "idiv"};
        const bool byte_form = (op == 0xF6);
        const OpW w = GprWidth(p, byte_form);
        char rm_buf[48] = {0};
        const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
        if (rm_extra == 0xFF)
            return fail_db(op);
        cur += rm_extra;
        const u8 sub = mr.reg_idx & 0x7;
        StrCopy(out->mnemonic, kBufMnem, kUnary[sub]);
        StrAppend(out->operands, kBufOpr, rm_buf);
        if (sub == 0 || sub == 1)
        {
            // TEST has imm form
            const u8 imm_bytes = byte_form ? 1 : (p.osize ? 2 : 4);
            if (cur + imm_bytes > available)
                return fail_db(op);
            const u64 imm = ReadImmU(&bytes[cur], imm_bytes);
            cur += imm_bytes;
            StrAppend(out->operands, kBufOpr, ", ");
            AppendHexU64(out->operands, kBufOpr, imm);
        }
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0xFE/0xFF: INC/DEC + indirect CALL/JMP/PUSH ----
    if (op == 0xFE || op == 0xFF)
    {
        if (cur >= available)
            return fail_db(op);
        const ModRm mr = DecodeModRmByte(bytes[cur], p);
        ++cur;
        const bool byte_form = (op == 0xFE);
        const u8 sub = mr.reg_idx & 0x7;
        const char* mnem = nullptr;
        OpW w = GprWidth(p, byte_form);
        bool force_q = false; // 0xFF /2,/4,/6 are 64-bit by default
        if (sub == 0)
            mnem = "inc";
        else if (sub == 1)
            mnem = "dec";
        else if (!byte_form && sub == 2)
        {
            mnem = "call";
            force_q = true;
        }
        else if (!byte_form && sub == 4)
        {
            mnem = "jmp";
            force_q = true;
        }
        else if (!byte_form && sub == 6)
        {
            mnem = "push";
            force_q = true;
        }
        else
            return fail_db(op);
        if (force_q)
            w = OpW::Q64;
        char rm_buf[48] = {0};
        const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
        if (rm_extra == 0xFF)
            return fail_db(op);
        cur += rm_extra;
        StrCopy(out->mnemonic, kBufMnem, mnem);
        StrAppend(out->operands, kBufOpr, rm_buf);
        out->len = cur;
        out->decoded = true;
        record_bytes(cur);
        return cur;
    }

    // ---- 0x0F escape ----
    if (op == 0x0F)
    {
        if (cur >= available)
            return fail_db(op);
        const u8 op2 = bytes[cur];
        ++cur;
        // 0F 05: SYSCALL
        if (op2 == 0x05)
        {
            StrCopy(out->mnemonic, kBufMnem, "syscall");
            out->operands[0] = 0;
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F 07: SYSRET
        if (op2 == 0x07)
        {
            StrCopy(out->mnemonic, kBufMnem, "sysret");
            out->operands[0] = 0;
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F 1F /0..7: multi-byte NOP
        if (op2 == 0x1F)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const OpW w = GprWidth(p, false);
            char rm_buf[48] = {0};
            const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            StrCopy(out->mnemonic, kBufMnem, "nop");
            StrAppend(out->operands, kBufOpr, rm_buf);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F 80..8F: Jcc rel32
        if (op2 >= 0x80 && op2 <= 0x8F)
        {
            if (cur + 4 > available)
                return fail_db(op);
            const i32 rel = static_cast<i32>(ReadImmU(&bytes[cur], 4));
            cur += 4;
            const u64 target = va + cur + static_cast<i64>(rel);
            char m[8] = {0};
            StrAppend(m, sizeof(m), "j");
            StrAppend(m, sizeof(m), kCc[op2 & 0xF]);
            StrCopy(out->mnemonic, kBufMnem, m);
            AppendBranchTarget(out->operands, kBufOpr, target);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F 40..4F: CMOVcc r{16,32,64}, r/m{16,32,64}.
        // The dest reg width follows the standard 16/32/64 GPR
        // selection (REX.W → 64, 0x66 → 16, default 32). Both
        // operands share the same width.
        if (op2 >= 0x40 && op2 <= 0x4F)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const OpW w = GprWidth(p, false);
            char rm_buf[48] = {0};
            const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            char m[16] = {0};
            StrAppend(m, sizeof(m), "cmov");
            StrAppend(m, sizeof(m), kCc[op2 & 0xF]);
            StrCopy(out->mnemonic, kBufMnem, m);
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, rm_buf);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F 90..9F: SETcc r/m8. Single 8-bit destination; only
        // the r/m operand prints.
        if (op2 >= 0x90 && op2 <= 0x9F)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            char rm_buf[48] = {0};
            const u8 rm_extra =
                FormatRmOperand(rm_buf, sizeof(rm_buf), mr, OpW::B8, OpW::B8, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            char m[16] = {0};
            StrAppend(m, sizeof(m), "set");
            StrAppend(m, sizeof(m), kCc[op2 & 0xF]);
            StrCopy(out->mnemonic, kBufMnem, m);
            StrAppend(out->operands, kBufOpr, rm_buf);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F B6 / 0F B7: MOVZX r{16,32,64}, r/m{8,16}.
        // 0F BE / 0F BF: MOVSX r{16,32,64}, r/m{8,16}.
        // Source width is 8 (B6/BE) or 16 (B7/BF); destination
        // follows standard GPR selection.
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const OpW dst_w = GprWidth(p, false);
            const OpW src_w = (op2 == 0xB6 || op2 == 0xBE) ? OpW::B8 : OpW::W16;
            char rm_buf[48] = {0};
            const u8 rm_extra =
                FormatRmOperand(rm_buf, sizeof(rm_buf), mr, dst_w, src_w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            const bool is_signed = (op2 == 0xBE || op2 == 0xBF);
            StrCopy(out->mnemonic, kBufMnem, is_signed ? "movsx" : "movzx");
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, dst_w, p.rex_seen));
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, rm_buf);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F BC: BSF r{16,32,64}, r/m{16,32,64} — bit scan forward.
        // 0F BD: BSR r{16,32,64}, r/m{16,32,64} — bit scan reverse.
        //
        // The F3 REP prefix changes the semantics: F3 0F BC = TZCNT
        // (BMI1) and F3 0F BD = LZCNT (LZCNT/ABM). Skip this BSF/BSR
        // branch when `p.rep` is set so the dedicated POPCNT/LZCNT
        // handler below catches the prefixed encoding. Without this
        // gate, the LZCNT bytes `F3 48 0F BD D8` decoded as BSR
        // (the F3 was correctly stored on the prefix struct but the
        // BSF/BSR branch never consulted it).
        if ((op2 == 0xBC || op2 == 0xBD) && !p.rep)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const OpW w = GprWidth(p, false);
            char rm_buf[48] = {0};
            const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            StrCopy(out->mnemonic, kBufMnem, op2 == 0xBC ? "bsf" : "bsr");
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, rm_buf);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F C8..CF: BSWAP r{32,64} — operand in low 3 bits + REX.B.
        // No ModR/M byte. 0x66 prefix produces an undefined encoding
        // on Intel; refuse it as `db` rather than guess.
        if (op2 >= 0xC8 && op2 <= 0xCF)
        {
            if (p.osize)
                return fail_db(op);
            const OpW w = p.rex_w ? OpW::Q64 : OpW::D32;
            const u8 reg_idx = (op2 & 0x7) | (p.rex_b ? 0x8 : 0);
            StrCopy(out->mnemonic, kBufMnem, "bswap");
            StrAppend(out->operands, kBufOpr, RegName(reg_idx, w, p.rex_seen));
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F A3 + ModR/M: BT r/m, r (bit test).
        // 0F AB / B3 / BB: BTS / BTR / BTC (set / reset / complement).
        if (op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const OpW w = GprWidth(p, false);
            char rm_buf[48] = {0};
            const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            const char* mnem = (op2 == 0xA3) ? "bt" : (op2 == 0xAB) ? "bts" : (op2 == 0xB3) ? "btr" : "btc";
            StrCopy(out->mnemonic, kBufMnem, mnem);
            StrAppend(out->operands, kBufOpr, rm_buf);
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F BA /4..7 + ModR/M + imm8: BT/BTS/BTR/BTC r/m, imm8.
        // ModR/M.reg field encodes the operation (4=BT, 5=BTS,
        // 6=BTR, 7=BTC); /0..3 are undefined.
        if (op2 == 0xBA)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const u8 sub = mr.reg_idx & 0x7; // /N field, raw (no REX.R extension wanted)
            if (sub < 4)
                return fail_db(op);
            const OpW w = GprWidth(p, false);
            char rm_buf[48] = {0};
            const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            if (cur >= available)
                return fail_db(op);
            const u8 imm = bytes[cur];
            ++cur;
            const char* mnem = (sub == 4) ? "bt" : (sub == 5) ? "bts" : (sub == 6) ? "btr" : "btc";
            StrCopy(out->mnemonic, kBufMnem, mnem);
            StrAppend(out->operands, kBufOpr, rm_buf);
            StrAppend(out->operands, kBufOpr, ", ");
            AppendHexU64(out->operands, kBufOpr, imm);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F B0 + ModR/M: CMPXCHG r/m8, r8  (byte form)
        // 0F B1 + ModR/M: CMPXCHG r/m{16,32,64}, r{16,32,64}.
        // Both compare the accumulator (al/ax/eax/rax) against
        // r/m; on equal write source into r/m, else load r/m into
        // accumulator. We only print the explicit operands; the
        // implicit accumulator is documented in the mnemonic.
        if (op2 == 0xB0 || op2 == 0xB1)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const bool byte_form = (op2 == 0xB0);
            const OpW w = GprWidth(p, byte_form);
            char rm_buf[48] = {0};
            const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            StrCopy(out->mnemonic, kBufMnem, "cmpxchg");
            StrAppend(out->operands, kBufOpr, rm_buf);
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F C0 + ModR/M: XADD r/m8, r8 (byte form)
        // 0F C1 + ModR/M: XADD r/m{16,32,64}, r{16,32,64}.
        // Exchange-and-add: dst += src; then src = old dst. We
        // print (r/m, r) in dst-first order matching the spec.
        if (op2 == 0xC0 || op2 == 0xC1)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const bool byte_form = (op2 == 0xC0);
            const OpW w = GprWidth(p, byte_form);
            char rm_buf[48] = {0};
            const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            StrCopy(out->mnemonic, kBufMnem, "xadd");
            StrAppend(out->operands, kBufOpr, rm_buf);
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // 0F 18 + ModR/M: PREFETCHh m8. The /N field picks the
        // hint level: /0 PREFETCHNTA, /1 PREFETCHT0, /2 PREFETCHT1,
        // /3 PREFETCHT2; /4..7 are reserved-NOP on most CPUs but
        // assemble identically. The operand is always a byte
        // memory reference.
        if (op2 == 0x18)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            char rm_buf[48] = {0};
            const u8 rm_extra =
                FormatRmOperand(rm_buf, sizeof(rm_buf), mr, OpW::B8, OpW::B8, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            const u8 sub = mr.reg_idx & 0x7;
            const char* mnem = (sub == 0)   ? "prefetchnta"
                               : (sub == 1) ? "prefetcht0"
                               : (sub == 2) ? "prefetcht1"
                               : (sub == 3) ? "prefetcht2"
                                            : "prefetch";
            StrCopy(out->mnemonic, kBufMnem, mnem);
            StrAppend(out->operands, kBufOpr, rm_buf);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // F3 0F B8 / F3 0F BC / F3 0F BD: POPCNT / TZCNT / LZCNT
        // r{16,32,64}, r/m{16,32,64}. Same opcode shape; the F3
        // REP prefix distinguishes them from BSWAP / BSF / BSR.
        // The 0F B8 base is JMP-far in real mode and unused in
        // long mode, so when the REP prefix is present we read
        // it as POPCNT. 0F BD without F3 is BSR; with F3 it's
        // LZCNT. 0F BC without F3 is BSF; with F3 it's TZCNT.
        if (p.rep && (op2 == 0xB8 || op2 == 0xBC || op2 == 0xBD))
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            ++cur;
            const OpW w = GprWidth(p, false);
            char rm_buf[48] = {0};
            const u8 rm_extra = FormatRmOperand(rm_buf, sizeof(rm_buf), mr, w, w, p, &bytes[cur], available - cur);
            if (rm_extra == 0xFF)
                return fail_db(op);
            cur += rm_extra;
            const char* mnem = "popcnt";
            if (op2 == 0xBC)
                mnem = "tzcnt";
            else if (op2 == 0xBD)
                mnem = "lzcnt";
            StrCopy(out->mnemonic, kBufMnem, mnem);
            StrAppend(out->operands, kBufOpr, RegName(mr.reg_idx, w, p.rex_seen));
            StrAppend(out->operands, kBufOpr, ", ");
            StrAppend(out->operands, kBufOpr, rm_buf);
            out->len = cur;
            out->decoded = true;
            record_bytes(cur);
            return cur;
        }
        // ---- SSE / SSE2 two-XMM-operand subset ----
        // Legacy-encoded (non-VEX) SSE/SSE2 instructions whose reg
        // and r/m operands are both XMM (or xmm + memory). The
        // mandatory prefix selects the mnemonic: none / 0x66 / 0xF3
        // (scalar single) / 0xF2 (scalar double). `store` = true
        // means the r/m is the destination (0F11/29/7F store forms),
        // so operands print r/m-first. This covers the bulk of
        // compiler-emitted SSE in kernel C++ (scalar double/float
        // math, 16-byte struct moves, xorps/pxor zeroing). GPR-
        // mixing forms and integer-SIMD stay GAP below.
        {
            struct SseRow
            {
                u8 op2;
                const char* np;
                const char* p66;
                const char* pf3;
                const char* pf2;
                bool store;
            };
            static constexpr SseRow kSse[] = {
                {0x10, "movups", "movupd", "movss", "movsd", false},
                {0x11, "movups", "movupd", "movss", "movsd", true},
                {0x14, "unpcklps", "unpcklpd", nullptr, nullptr, false},
                {0x15, "unpckhps", "unpckhpd", nullptr, nullptr, false},
                {0x28, "movaps", "movapd", nullptr, nullptr, false},
                {0x29, "movaps", "movapd", nullptr, nullptr, true},
                {0x2E, "ucomiss", "ucomisd", nullptr, nullptr, false},
                {0x2F, "comiss", "comisd", nullptr, nullptr, false},
                {0x51, "sqrtps", "sqrtpd", "sqrtss", "sqrtsd", false},
                {0x54, "andps", "andpd", nullptr, nullptr, false},
                {0x55, "andnps", "andnpd", nullptr, nullptr, false},
                {0x56, "orps", "orpd", nullptr, nullptr, false},
                {0x57, "xorps", "xorpd", nullptr, nullptr, false},
                {0x58, "addps", "addpd", "addss", "addsd", false},
                {0x59, "mulps", "mulpd", "mulss", "mulsd", false},
                {0x5A, "cvtps2pd", "cvtpd2ps", "cvtss2sd", "cvtsd2ss", false},
                {0x5C, "subps", "subpd", "subss", "subsd", false},
                {0x5D, "minps", "minpd", "minss", "minsd", false},
                {0x5E, "divps", "divpd", "divss", "divsd", false},
                {0x5F, "maxps", "maxpd", "maxss", "maxsd", false},
                {0x6F, nullptr, "movdqa", "movdqu", nullptr, false},
                {0x7F, nullptr, "movdqa", "movdqu", nullptr, true},
                {0xDB, nullptr, "pand", nullptr, nullptr, false},
                {0xDF, nullptr, "pandn", nullptr, nullptr, false},
                {0xEB, nullptr, "por", nullptr, nullptr, false},
                {0xEF, nullptr, "pxor", nullptr, nullptr, false},
            };
            const SseRow* row = nullptr;
            for (const SseRow& r : kSse)
            {
                if (r.op2 == op2)
                {
                    row = &r;
                    break;
                }
            }
            if (row != nullptr)
            {
                const char* mnem = row->np;
                if (p.rep)
                    mnem = row->pf3;
                else if (p.repne)
                    mnem = row->pf2;
                else if (p.osize)
                    mnem = row->p66;
                if (mnem != nullptr)
                {
                    if (cur >= available)
                        return fail_db(op);
                    const ModRm mr = DecodeModRmByte(bytes[cur], p);
                    ++cur;
                    // Scalar single → dword mem, scalar double →
                    // qword mem, packed / integer → xmmword. A
                    // register r/m always prints as xmm (reg_w).
                    OpW mem_w = OpW::X128;
                    if (p.rep)
                        mem_w = OpW::D32;
                    else if (p.repne)
                        mem_w = OpW::Q64;
                    char rm_buf[48] = {0};
                    const u8 rm_extra =
                        FormatRmOperand(rm_buf, sizeof(rm_buf), mr, OpW::X128, mem_w, p, &bytes[cur], available - cur);
                    if (rm_extra == 0xFF)
                        return fail_db(op);
                    cur += rm_extra;
                    StrCopy(out->mnemonic, kBufMnem, mnem);
                    const char* xreg = RegName(mr.reg_idx, OpW::X128, p.rex_seen);
                    if (row->store)
                    {
                        StrAppend(out->operands, kBufOpr, rm_buf);
                        StrAppend(out->operands, kBufOpr, ", ");
                        StrAppend(out->operands, kBufOpr, xreg);
                    }
                    else
                    {
                        StrAppend(out->operands, kBufOpr, xreg);
                        StrAppend(out->operands, kBufOpr, ", ");
                        StrAppend(out->operands, kBufOpr, rm_buf);
                    }
                    out->len = cur;
                    out->decoded = true;
                    record_bytes(cur);
                    return cur;
                }
            }
        }
        // ---- SSE/SSE2 GPR-mixing forms ----
        // The XMM<->GPR move + integer/float conversion encodings.
        // Operand kinds vary per opcode, so each is resolved into a
        // common (mnem, reg-kind, rm-kind, store) shape then emitted
        // by the shared tail. `gw` is the GPR width: REX.W → 64,
        // else 32 (0x66 here is a mandatory SSE prefix, NOT
        // operand-size, so it must not narrow the GPR to 16-bit).
        {
            const OpW gw = p.rex_w ? OpW::Q64 : OpW::D32;
            const char* mnem = nullptr;
            char mbuf[12] = {0};
            bool store = false;
            OpW reg_w = OpW::X128;    // ModRM.reg operand kind
            OpW rm_reg_w = OpW::X128; // r/m when mod==3 (register)
            OpW rm_mem_w = OpW::X128; // r/m ptr-keyword when memory
            if (op2 == 0x6E && p.osize)
            {
                // 66 0F 6E: MOVD xmm, r/m32  (MOVQ if REX.W)
                mnem = p.rex_w ? "movq" : "movd";
                rm_reg_w = gw;
                rm_mem_w = gw;
            }
            else if (op2 == 0x7E && p.osize)
            {
                // 66 0F 7E: MOVD r/m32, xmm  (store; MOVQ if REX.W)
                mnem = p.rex_w ? "movq" : "movd";
                store = true;
                rm_reg_w = gw;
                rm_mem_w = gw;
            }
            else if (op2 == 0x7E && p.rep)
            {
                // F3 0F 7E: MOVQ xmm, xmm/m64
                mnem = "movq";
                rm_mem_w = OpW::Q64;
            }
            else if (op2 == 0xD6 && p.osize)
            {
                // 66 0F D6: MOVQ xmm/m64, xmm  (store)
                mnem = "movq";
                store = true;
                rm_mem_w = OpW::Q64;
            }
            else if (op2 == 0x2A && (p.rep || p.repne))
            {
                // F3/F2 0F 2A: CVTSI2SS/SD xmm, r/m32 (r/m64 if W)
                mnem = p.rep ? "cvtsi2ss" : "cvtsi2sd";
                rm_reg_w = gw;
                rm_mem_w = gw;
            }
            else if ((op2 == 0x2C || op2 == 0x2D) && (p.rep || p.repne))
            {
                // F3/F2 0F 2C/2D: CVT(T)SS2SI/SD2SI r32/64, xmm/m
                StrAppend(mbuf, sizeof(mbuf), op2 == 0x2C ? "cvtt" : "cvt");
                StrAppend(mbuf, sizeof(mbuf), p.rep ? "ss2si" : "sd2si");
                mnem = mbuf;
                reg_w = gw; // dest is a GPR
                rm_mem_w = p.rep ? OpW::D32 : OpW::Q64;
            }
            else if (op2 == 0xC3 && !p.rep && !p.repne && !p.osize)
            {
                // 0F C3: MOVNTI m32/64, r32/64  (store)
                mnem = "movnti";
                store = true;
                reg_w = gw;    // source is a GPR
                rm_reg_w = gw; // (mem-only in practice)
                rm_mem_w = gw;
            }
            if (mnem != nullptr)
            {
                if (cur >= available)
                    return fail_db(op);
                const ModRm mr = DecodeModRmByte(bytes[cur], p);
                ++cur;
                char rm_buf[48] = {0};
                const u8 rm_extra =
                    FormatRmOperand(rm_buf, sizeof(rm_buf), mr, rm_reg_w, rm_mem_w, p, &bytes[cur], available - cur);
                if (rm_extra == 0xFF)
                    return fail_db(op);
                cur += rm_extra;
                StrCopy(out->mnemonic, kBufMnem, mnem);
                const char* reg = RegName(mr.reg_idx, reg_w, p.rex_seen);
                if (store)
                {
                    StrAppend(out->operands, kBufOpr, rm_buf);
                    StrAppend(out->operands, kBufOpr, ", ");
                    StrAppend(out->operands, kBufOpr, reg);
                }
                else
                {
                    StrAppend(out->operands, kBufOpr, reg);
                    StrAppend(out->operands, kBufOpr, ", ");
                    StrAppend(out->operands, kBufOpr, rm_buf);
                }
                out->len = cur;
                out->decoded = true;
                record_bytes(cur);
                return cur;
            }
        }
        // ---- MOVLPS/MOVHPS/MOVLHPS/MOVHLPS ----
        // 0F 12/13/16/17 (np / 0x66). For 0F 12 and 0F 16 the
        // mnemonic depends on ModRM.mod: a register source is the
        // MOVHLPS / MOVLHPS reg-reg shuffle, a memory source is the
        // 64-bit MOVLPS / MOVHPS load. 13/17 are store-only (m64,
        // xmm). The F2/F3-prefixed SSE3 dup variants (MOVDDUP /
        // MOVSLDUP / MOVSHDUP) stay GAP.
        if ((op2 == 0x12 || op2 == 0x13 || op2 == 0x16 || op2 == 0x17) && !p.rep && !p.repne)
        {
            if (cur >= available)
                return fail_db(op);
            const ModRm mr = DecodeModRmByte(bytes[cur], p);
            const bool is_reg = (mr.mod == 3);
            const bool store = (op2 == 0x13 || op2 == 0x17);
            const char* mnem = nullptr;
            if (op2 == 0x12)
                mnem = is_reg ? (p.osize ? nullptr : "movhlps") : (p.osize ? "movlpd" : "movlps");
            else if (op2 == 0x16)
                mnem = is_reg ? (p.osize ? nullptr : "movlhps") : (p.osize ? "movhpd" : "movhps");
            else if (op2 == 0x13)
                mnem = is_reg ? nullptr : (p.osize ? "movlpd" : "movlps");
            else // 0x17
                mnem = is_reg ? nullptr : (p.osize ? "movhpd" : "movhps");
            if (mnem != nullptr)
            {
                ++cur;
                char rm_buf[48] = {0};
                const u8 rm_extra =
                    FormatRmOperand(rm_buf, sizeof(rm_buf), mr, OpW::X128, OpW::Q64, p, &bytes[cur], available - cur);
                if (rm_extra == 0xFF)
                    return fail_db(op);
                cur += rm_extra;
                StrCopy(out->mnemonic, kBufMnem, mnem);
                const char* xreg = RegName(mr.reg_idx, OpW::X128, p.rex_seen);
                if (store)
                {
                    StrAppend(out->operands, kBufOpr, rm_buf);
                    StrAppend(out->operands, kBufOpr, ", ");
                    StrAppend(out->operands, kBufOpr, xreg);
                }
                else
                {
                    StrAppend(out->operands, kBufOpr, xreg);
                    StrAppend(out->operands, kBufOpr, ", ");
                    StrAppend(out->operands, kBufOpr, rm_buf);
                }
                out->len = cur;
                out->decoded = true;
                record_bytes(cur);
                return cur;
            }
        }
        // GAP: remaining 0x0F SSE space — the integer-SIMD
        // PUNPCK/PSHUF/PADD/PCMP/PMOVMSKB family, the SSE3 dup
        // moves (MOVDDUP / MOVS[LH]DUP), and all VEX/EVEX
        // (AVX/AVX-512) decode as `db` until they earn a slice.
        // The two-XMM-operand subset, the XMM<->GPR move/conversion
        // forms, and MOV{L,H}PS/MOV{L,H}LPS are decoded above.
        FIX_NOTE_GAP("debug/disasm.cpp:0x0F-sse-rest", "decode SSE integer-SIMD + SSE3 dup + AVX");
        return fail_db(op);
    }

    // Anything else: emit `db 0xXX`.
    return fail_db(op);
}

u64 DecodeStream(const u8* bytes, u64 available, u64 va, DecodedInsn* out, u64 row_cap)
{
    if (out == nullptr || bytes == nullptr || row_cap == 0)
        return 0;
    u64 rows = 0;
    u64 off = 0;
    while (rows < row_cap && off < available)
    {
        DecodedInsn* slot = &out[rows];
        const u8 used = DecodeOne(&bytes[off], available - off, va + off, slot);
        if (used == 0)
            break;
        // Don't emit a ragged row that ran past `available`.
        if (static_cast<u64>(used) > available - off)
            break;
        off += used;
        ++rows;
    }
    return rows;
}

namespace
{

// Compare two NUL-terminated strings without depending on libc.
bool SeqEq(const char* a, const char* b)
{
    u32 i = 0;
    while (a[i] != 0 && b[i] != 0)
    {
        if (a[i] != b[i])
            return false;
        ++i;
    }
    return a[i] == 0 && b[i] == 0;
}

} // namespace

bool SelfTest()
{
    // Hand-assembled bytes covering one row of each major family.
    // The sequence is sized so DecodeStream consumes it cleanly with
    // the expected mnemonics, in order, on the first pass. Adding
    // more rows is fine — keep them distinct so a regression in one
    // family produces a focused FAIL line.
    static constexpr u8 kFixture[] = {
        0xCC,                                     // int3
        0x90,                                     // nop
        0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00, // mov rax, 0x2a
        0x48, 0x89, 0xC3,                         // mov rbx, rax
        0x48, 0x8B, 0x45, 0xF0,                   // mov rax, [rbp-0x10]
        0x55,                                     // push rbp
        0x5D,                                     // pop rbp
        0xC3,                                     // ret
        0xEB, 0x02,                               // jmp +2 → past two bytes
        0x90, 0x90,                               // padding for the jmp
        0xE8, 0x00, 0x00, 0x00, 0x00,             // call rel32 → next insn
        0x0F, 0x05,                               // syscall
        0xC9,                                     // leave
        // 0x0F-prefix extensions:
        0x0F, 0xB6, 0xC0,                         // movzx eax, al
        0x0F, 0xBE, 0xC0,                         // movsx eax, al
        0x48, 0x0F, 0x44, 0xC3,                   // cmove rax, rbx
        0x0F, 0x94, 0xC0,                         // sete al
        0x0F, 0xBC, 0xC0,                         // bsf eax, eax
        0x48, 0x0F, 0xBD, 0xD8,                   // bsr rbx, rax
        0x48, 0x0F, 0xC8,                         // bswap rax
        0x0F, 0xA3, 0xC8,                         // bt eax, ecx
        0x0F, 0xBA, 0xE0, 0x05,                   // bt eax, 5
        0x0F, 0xB1, 0xCB,                         // cmpxchg ebx, ecx
        0x48, 0x0F, 0xC1, 0xCB,                   // xadd rbx, rcx
        0x0F, 0x18, 0x0D, 0x00, 0x00, 0x00, 0x00, // prefetcht0 [rip+0]
        0xF3, 0x0F, 0xB8, 0xC1,                   // popcnt eax, ecx
        0xF3, 0x48, 0x0F, 0xBD, 0xD8,             // lzcnt rbx, rax
        // SSE / SSE2 two-XMM-operand subset:
        0x0F, 0x28, 0xC1,       // movaps xmm0, xmm1
        0x0F, 0x11, 0x08,       // movups [rax], xmm1 (store)
        0xF3, 0x0F, 0x10, 0xC1, // movss xmm0, xmm1
        0xF2, 0x0F, 0x58, 0xC1, // addsd xmm0, xmm1
        0x66, 0x0F, 0x6F, 0xC1, // movdqa xmm0, xmm1
        0x0F, 0x57, 0xC1,       // xorps xmm0, xmm1
        0x66, 0x0F, 0xEF, 0xC1, // pxor xmm0, xmm1
        0x66, 0x0F, 0x2E, 0xC1, // ucomisd xmm0, xmm1
        0x44, 0x0F, 0x28, 0xC1, // movaps xmm8, xmm1 (REX.R)
        // SSE/SSE2 GPR-mixing forms:
        0x66, 0x0F, 0x6E, 0xC0,       // movd xmm0, eax
        0x66, 0x48, 0x0F, 0x6E, 0xC0, // movq xmm0, rax (REX.W)
        0x66, 0x0F, 0x7E, 0xC0,       // movd eax, xmm0 (store)
        0xF3, 0x0F, 0x7E, 0xC1,       // movq xmm0, xmm1
        0x66, 0x0F, 0xD6, 0xC1,       // movq xmm1, xmm0 (store)
        0xF2, 0x0F, 0x2A, 0xC0,       // cvtsi2sd xmm0, eax
        0xF2, 0x0F, 0x2D, 0xC1,       // cvtsd2si eax, xmm1
        0xF3, 0x0F, 0x2C, 0xC1,       // cvttss2si eax, xmm1
        0x0F, 0xC3, 0x03,             // movnti [rbx], eax
        // MOVLPS/MOVHPS/MOVLHPS/MOVHLPS:
        0x0F, 0x12, 0xC1,                   // movhlps xmm0, xmm1 (reg)
        0x0F, 0x12, 0x00,                   // movlps xmm0, [rax] (mem)
        0x0F, 0x16, 0xC1,                   // movlhps xmm0, xmm1 (reg)
        0x0F, 0x13, 0x08,                   // movlps [rax], xmm1 (store)
        0x66, 0x0F, 0x16, 0x00,             // movhpd xmm0, [rax]
        0x0F, 0x17, 0x08,                   // movhps [rax], xmm1 (store)
        0xC4, 0xE3, 0x71, 0x60, 0xC1, 0x00, // VEX-prefixed → must reject as `db`
    };
    struct Expected
    {
        const char* mnem;
        u8 len;
    };
    static constexpr Expected kExpected[] = {
        {"int3", 1},
        {"nop", 1},
        {"mov", 7},
        {"mov", 3},
        {"mov", 4},
        {"push", 1},
        {"pop", 1},
        {"ret", 1},
        {"jmp", 2},
        {"nop", 1},
        {"nop", 1},
        {"call", 5},
        {"syscall", 2},
        {"leave", 1},
        {"movzx", 3},
        {"movsx", 3},
        {"cmove", 4},
        {"sete", 3},
        {"bsf", 3},
        {"bsr", 4},
        {"bswap", 3},
        {"bt", 3},
        {"bt", 4},
        {"cmpxchg", 3},
        {"xadd", 4},
        {"prefetcht0", 7},
        {"popcnt", 4},
        {"lzcnt", 5},
        {"movaps", 3},
        {"movups", 3},
        {"movss", 4},
        {"addsd", 4},
        {"movdqa", 4},
        {"xorps", 3},
        {"pxor", 4},
        {"ucomisd", 4},
        {"movaps", 4},
        {"movd", 4},
        {"movq", 5},
        {"movd", 4},
        {"movq", 4},
        {"movq", 4},
        {"cvtsi2sd", 4},
        {"cvtsd2si", 4},
        {"cvttss2si", 4},
        {"movnti", 3},
        {"movhlps", 3},
        {"movlps", 3},
        {"movlhps", 3},
        {"movlps", 3},
        {"movhpd", 4},
        {"movhps", 3},
        // The VEX byte rejects as `db 0xC4`, then the decoder walks
        // forward one byte at a time through the rest until end.
        {"db", 1},
    };

    DecodedInsn rows[64];
    const u64 n = DecodeStream(kFixture, sizeof(kFixture), 0x140000000ULL, rows, 64);
    if (n < sizeof(kExpected) / sizeof(kExpected[0]))
    {
        KLOG_WARN_V("dbg", "[smoke] disasm=FAIL too-few-rows", n);
        return false;
    }

    for (u64 i = 0; i < sizeof(kExpected) / sizeof(kExpected[0]); ++i)
    {
        if (!SeqEq(rows[i].mnemonic, kExpected[i].mnem) || rows[i].len != kExpected[i].len)
        {
            KLOG_WARN_S("dbg", "[smoke] disasm=FAIL", "want", kExpected[i].mnem);
            KLOG_WARN_S("dbg", "[smoke] disasm=FAIL", "got", rows[i].mnemonic);
            KLOG_WARN_V("dbg", "[smoke] disasm=FAIL row=", i);
            return false;
        }
    }

    KLOG_INFO_V("dbg", "[smoke] disasm=ok rows=", n);
    return true;
}

} // namespace duetos::debug::disasm
