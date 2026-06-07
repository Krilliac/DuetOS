/*
 * DuetOS — AML method interpreter (v0): implementation.
 *
 * See aml_eval.h for the supported subset, the object model, and the
 * bounded GAPs. This is a recursive tree-walker over a method body's
 * TermList: EvalTermArg() yields a value, ExecTermList() runs
 * statements. No IR, no JIT — state is a small per-evaluation struct
 * with an AmlValue arena (so nested Packages don't touch the heap).
 *
 * Structure (top → bottom):
 *   - PkgLength / NameString decode (compact, file-local).
 *   - Region + Field runtime access.
 *   - EvalState + the arena.
 *   - EvalTermArg (operands + expression opcodes).
 *   - ExecTermList (statement opcodes + control flow).
 *   - Public API + self-test.
 */

#include "acpi/aml_eval.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "diag/fix_journal.h"
#include "drivers/pci/pci.h"
#include "log/klog.h"
#include "mm/page.h"
#include "time/timekeeper.h"

namespace duetos::acpi
{

namespace
{

// --- PkgLength (ACPI 6.x §20.2.4) -----------------------------------
bool ReadPkgLength(const u8* p, u32 remaining, u32* out_len, u32* out_consumed)
{
    if (remaining < 1)
        return false;
    const u8 lead = p[0];
    const u32 follow = (lead >> 6) & 0x3;
    if (remaining < 1 + follow)
        return false;
    if (follow == 0)
    {
        *out_len = lead & 0x3F;
        *out_consumed = 1;
        return true;
    }
    u32 len = lead & 0x0F;
    for (u32 i = 0; i < follow; ++i)
        len |= u32(p[1 + i]) << (4 + i * 8);
    *out_len = len;
    *out_consumed = 1 + follow;
    return true;
}

inline bool IsLeadNameChar(u8 c)
{
    return c == '_' || (c >= 'A' && c <= 'Z');
}
inline bool IsNameChar(u8 c)
{
    return IsLeadNameChar(c) || (c >= '0' && c <= '9');
}

// Parse a NameString into its prefix shape + segments. We only need
// enough to (a) know how many bytes it consumed and (b) rebuild a
// candidate absolute path for namespace lookup.
struct NameRef
{
    char segs[15][5]; // up to 15 NameSegs, NUL-terminated
    u8 seg_count = 0;
    u8 caret = 0;      // leading '^' count
    bool root = false; // leading '\'
};

bool ReadNameRef(const u8* p, u32 remaining, NameRef* out, u32* consumed)
{
    *out = NameRef{};
    u32 pos = 0;
    if (pos < remaining && p[pos] == '\\')
    {
        out->root = true;
        ++pos;
    }
    else
    {
        while (pos < remaining && p[pos] == '^' && out->caret < 255)
        {
            ++out->caret;
            ++pos;
        }
    }
    if (pos >= remaining)
        return false;
    if (p[pos] == 0x00)
    {
        *consumed = pos + 1;
        return true; // NullName
    }
    u8 seg_count = 1;
    if (p[pos] == 0x2E)
    {
        seg_count = 2;
        ++pos;
    }
    else if (p[pos] == 0x2F)
    {
        ++pos;
        if (pos >= remaining)
            return false;
        seg_count = p[pos++];
        if (seg_count == 0 || seg_count > 15)
            return false;
    }
    if (pos + u32(seg_count) * 4 > remaining)
        return false;
    for (u8 s = 0; s < seg_count; ++s)
    {
        for (u8 i = 0; i < 4; ++i)
        {
            const u8 c = p[pos + i];
            if (i == 0 ? !IsLeadNameChar(c) : !IsNameChar(c))
                return false;
            out->segs[s][i] = char(c);
        }
        out->segs[s][4] = '\0';
        pos += 4;
    }
    out->seg_count = seg_count;
    *consumed = pos;
    return true;
}

void StrCopy(char* dst, const char* src, u32 cap)
{
    u32 i = 0;
    while (src[i] != '\0' && i + 1 < cap)
    {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

// Build the absolute path a NameRef denotes given the evaluating
// method's scope. ACPI's full multi-scope upward search is reduced
// to: absolute → as-is; caret → trim N segments off scope; relative
// → scope-prefixed, then (caller) progressively trims toward root.
bool ResolveAbsolute(const char* scope, const NameRef& nr, u32 trim_extra, char* out, u32 cap)
{
    char buf[64];
    u32 w = 0;
    if (nr.root)
    {
        buf[w++] = '\\';
    }
    else
    {
        u32 i = 0;
        while (scope[i] != '\0' && w + 1 < sizeof(buf))
            buf[w++] = scope[i++];
        u32 trims = nr.caret + trim_extra;
        for (u32 c = 0; c < trims; ++c)
        {
            while (w > 0 && buf[w - 1] != '.' && buf[w - 1] != '\\')
                --w;
            if (w > 0 && buf[w - 1] == '.')
                --w;
            else if (w == 0 || buf[w - 1] == '\\')
                return false;
        }
    }
    for (u8 s = 0; s < nr.seg_count; ++s)
    {
        const bool need_dot = (w > 0 && buf[w - 1] != '\\');
        if (need_dot)
        {
            if (w + 1 >= sizeof(buf))
                return false;
            buf[w++] = '.';
        }
        for (u8 i = 0; i < 4 && nr.segs[s][i] != '\0'; ++i)
        {
            if (w + 1 >= sizeof(buf))
                return false;
            buf[w++] = nr.segs[s][i];
        }
    }
    if (w + 1 > sizeof(buf) || w + 1 > cap)
        return false;
    buf[w] = '\0';
    StrCopy(out, buf, cap);
    return true;
}

// --- Region + Field runtime access ----------------------------------

struct RegionHandlerSlot
{
    AmlRegionHandler fn = nullptr;
    void* ctx = nullptr;
};
constinit RegionHandlerSlot g_region_handlers[6] = {}; // indexed by AmlRegionSpace 0..5

bool DirectRegionAccess(AmlRegionSpace space, bool write, u64 addr, u32 width_bits, u64* value)
{
    switch (space)
    {
    case AmlRegionSpace::SystemIO:
    {
        const u16 port = u16(addr);
        if (write)
        {
            if (width_bits <= 8)
                arch::Outb(port, u8(*value));
            else if (width_bits <= 16)
                arch::Outw(port, u16(*value));
            else
                arch::Outl(port, u32(*value));
            return true;
        }
        if (width_bits <= 8)
            *value = arch::Inb(port);
        else if (width_bits <= 16)
            *value = arch::Inw(port);
        else
            *value = arch::Inl(port);
        return true;
    }
    case AmlRegionSpace::SystemMemory:
    {
        // v0: only the 1 GiB kernel direct map. Higher SystemMemory
        // regions (rare on the EC/battery path) read back as Ones.
        // GAP: no >1 GiB SystemMemory — revisit if a real DSDT needs it.
        if (addr >= mm::kDirectMapBytes)
        {
            FIX_NOTE_GAP("acpi/aml_eval.cpp:SystemMemoryAccess", "map >1 GiB SystemMemory regions on demand");
            return false;
        }
        volatile u8* base = static_cast<volatile u8*>(mm::PhysToVirt(addr));
        if (base == nullptr)
            return false;
        if (write)
        {
            if (width_bits <= 8)
                *base = u8(*value);
            else if (width_bits <= 16)
                *reinterpret_cast<volatile u16*>(base) = u16(*value);
            else if (width_bits <= 32)
                *reinterpret_cast<volatile u32*>(base) = u32(*value);
            else
                *reinterpret_cast<volatile u64*>(base) = *value;
            return true;
        }
        if (width_bits <= 8)
            *value = *base;
        else if (width_bits <= 16)
            *value = *reinterpret_cast<volatile u16*>(base);
        else if (width_bits <= 32)
            *value = *reinterpret_cast<volatile u32*>(base);
        else
            *value = *reinterpret_cast<volatile u64*>(base);
        return true;
    }
    default:
        return false;
    }
}

bool RegionAccess(AmlRegionSpace space, bool write, u64 addr, u32 width_bits, u64* value)
{
    if (space == AmlRegionSpace::SystemIO || space == AmlRegionSpace::SystemMemory)
        return DirectRegionAccess(space, write, addr, width_bits, value);
    const u8 idx = u8(space);
    if (idx < 6 && g_region_handlers[idx].fn != nullptr)
        return g_region_handlers[idx].fn(g_region_handlers[idx].ctx, write, addr, width_bits, value);
    return false; // no backend → Ones on read, dropped write
}

// Read/write a FieldUnit. Splits the access into access_bytes-sized
// units (the AccessType the Field declared) and assembles up to 64
// bits. Read-modify-write on the partial head/tail unit for writes.
bool FieldRead(const AmlFieldInfo* fi, u64* out)
{
    const AmlRegionInfo* ri = AmlRegionFind(fi->region);
    if (ri == nullptr || fi->bit_width == 0 || fi->bit_width > 64)
        return false;
    const u32 acc = fi->access_bytes ? fi->access_bytes : 1;
    const u32 acc_bits = acc * 8;
    u64 result = 0;
    u32 got = 0;
    u32 bit = fi->bit_offset;
    while (got < fi->bit_width)
    {
        const u64 unit_index = bit / acc_bits;
        const u32 unit_lo = bit % acc_bits;
        const u64 unit_addr = ri->base + unit_index * acc;
        u64 raw = 0;
        if (!RegionAccess(ri->space, false, unit_addr, acc_bits, &raw))
            return false;
        u32 take = acc_bits - unit_lo;
        if (take > fi->bit_width - got)
            take = fi->bit_width - got;
        const u64 mask = (take >= 64) ? ~0ULL : ((1ULL << take) - 1);
        result |= ((raw >> unit_lo) & mask) << got;
        got += take;
        bit += take;
    }
    *out = result;
    return true;
}

bool FieldWrite(const AmlFieldInfo* fi, u64 in)
{
    const AmlRegionInfo* ri = AmlRegionFind(fi->region);
    if (ri == nullptr || fi->bit_width == 0 || fi->bit_width > 64)
        return false;
    const u32 acc = fi->access_bytes ? fi->access_bytes : 1;
    const u32 acc_bits = acc * 8;
    u32 done = 0;
    u32 bit = fi->bit_offset;
    while (done < fi->bit_width)
    {
        const u64 unit_index = bit / acc_bits;
        const u32 unit_lo = bit % acc_bits;
        const u64 unit_addr = ri->base + unit_index * acc;
        u32 put = acc_bits - unit_lo;
        if (put > fi->bit_width - done)
            put = fi->bit_width - done;
        const u64 fmask = (put >= 64) ? ~0ULL : ((1ULL << put) - 1);
        u64 raw = 0;
        if (put != acc_bits)
        {
            if (!RegionAccess(ri->space, false, unit_addr, acc_bits, &raw))
                raw = 0; // write-only region: assume zero background
        }
        raw &= ~(fmask << unit_lo);
        raw |= ((in >> done) & fmask) << unit_lo;
        if (!RegionAccess(ri->space, true, unit_addr, acc_bits, &raw))
            return false;
        done += put;
        bit += put;
    }
    return true;
}

} // namespace

void AmlRegisterRegionHandler(AmlRegionSpace space, AmlRegionHandler handler, void* ctx)
{
    const u8 idx = u8(space);
    if (idx >= 6)
        return;
    g_region_handlers[idx] = RegionHandlerSlot{handler, ctx};
    KLOG_INFO_V("acpi/aml-eval", "region handler registered for space", idx);
}

namespace
{

// Per-evaluation node arena for Package elements (so nested packages
// don't churn the kernel heap). Lives on the stack of the outermost
// AmlEvaluate frame and is threaded through every recursive call.
struct Arena
{
    AmlValue nodes[kAmlArenaCap];
    u16 used = 0;
    int Alloc() { return used < kAmlArenaCap ? int(used++) : -1; }
};

constexpr u8 kMaxCallDepth = 12;
// ML-04: bound TermArg operand recursion (e.g. nested Add(Add(...))).
// The operand path (binop -> ReadIntArg -> EvalTermArg) consumes no arena
// and is otherwise limited only by table length, so a crafted DSDT/SSDT
// can recurse ~300+ bytes/frame and overrun the 64 KiB kernel stack.
constexpr u16 kMaxExprDepth = 64;

struct EvalState
{
    Arena& arena;
    const char* scope; // canonical path of the running method
    const AmlValue* args;
    u8 argc;
    AmlValue locals[8] = {};
    AmlValue retval{};
    bool returned = false;
    bool brk = false;
    bool cont = false;
    u16 expr_depth = 0; // TermArg operand recursion depth (ML-04 guard)
    u8 depth = 0;       // method-call recursion depth
};

u64 AsInteger(const AmlValue& v)
{
    switch (v.type)
    {
    case AmlType::Integer:
        return v.integer;
    case AmlType::Buffer:
    {
        u64 r = 0;
        const u32 n = v.len > 8 ? 8 : v.len;
        for (u32 i = 0; i < n; ++i)
            r |= u64(v.bytes[i]) << (i * 8);
        return r;
    }
    default:
        return 0;
    }
}

// Forward decls — the evaluator is mutually recursive.
bool EvalTermArg(const u8* p, u32 len, u32& pos, EvalState& st, AmlValue& out);
bool ExecTermList(const u8* p, u32 len, u32 begin, u32 end, EvalState& st);
bool InvokeMethod(const char* abs_path, const AmlNamespaceEntry* m, EvalState& st, const u8* caller, u32 caller_len,
                  u32& pos, AmlValue& out);

// A store destination. NullName / unsupported → kDiscard (store is a
// no-op, evaluation continues — documented GAP for store-to-Name).
struct Target
{
    enum class Kind : u8
    {
        Discard,
        Local,
        Arg,
        Field
    } kind = Kind::Discard;
    u8 index = 0;
    const AmlFieldInfo* field = nullptr;
};

bool ReadTarget(const u8* p, u32 len, u32& pos, EvalState& st, Target& tgt)
{
    if (pos >= len)
        return false;
    const u8 op = p[pos];
    if (op == 0x00) // NullName — discard
    {
        ++pos;
        tgt.kind = Target::Kind::Discard;
        return true;
    }
    if (op >= 0x60 && op <= 0x67)
    {
        ++pos;
        tgt.kind = Target::Kind::Local;
        tgt.index = op - 0x60;
        return true;
    }
    if (op >= 0x68 && op <= 0x6E)
    {
        ++pos;
        tgt.kind = Target::Kind::Arg;
        tgt.index = op - 0x68;
        return true;
    }
    // NameString → must resolve to a writable FieldUnit for v0.
    NameRef nr;
    u32 c = 0;
    if (!ReadNameRef(p + pos, len - pos, &nr, &c))
        return false;
    pos += c;
    char abs[64];
    for (u32 trim = 0;; ++trim)
    {
        if (!ResolveAbsolute(st.scope, nr, trim, abs, sizeof(abs)))
            break;
        const AmlFieldInfo* fi = AmlFieldFind(abs);
        if (fi != nullptr)
        {
            tgt.kind = Target::Kind::Field;
            tgt.field = fi;
            return true;
        }
        if (nr.root || nr.caret || StrLen(abs) <= 1)
            break;
    }
    tgt.kind = Target::Kind::Discard; // store-to-Name: accept + drop (GAP)
    return true;
}

void StoreToTarget(const Target& tgt, const AmlValue& v, EvalState& st)
{
    switch (tgt.kind)
    {
    case Target::Kind::Local:
        st.locals[tgt.index] = v;
        break;
    case Target::Kind::Arg:
        // Args are by-value copies in our model; writing one is legal
        // AML and observable within the method only.
        const_cast<AmlValue&>(st.args[tgt.index]) = v;
        break;
    case Target::Kind::Field:
        FieldWrite(tgt.field, AsInteger(v));
        break;
    case Target::Kind::Discard:
    default:
        break;
    }
}

// Resolve a NameString operand to a value: Method → invoke; Field →
// read; Name → decode its DataRefObject; otherwise Uninit.
bool ResolveNameValue(const NameRef& nr, EvalState& st, const u8* p, u32 len, u32& pos, AmlValue& out)
{
    char abs[64];
    for (u32 trim = 0;; ++trim)
    {
        if (!ResolveAbsolute(st.scope, nr, trim, abs, sizeof(abs)))
            break;
        if (const AmlFieldInfo* fi = AmlFieldFind(abs))
        {
            u64 v = 0;
            out = AmlValue::Int(FieldRead(fi, &v) ? v : ~0ULL);
            return true;
        }
        if (const AmlNamespaceEntry* e = AmlNamespaceFind(abs))
        {
            if (e->kind == AmlObjectKind::Method)
                return InvokeMethod(abs, e, st, p, len, pos, out);
            // Name: decode its value via a one-shot mini-eval of the
            // DataRefObject sitting at the recorded aml_offset.
            const u8* body = nullptr;
            u32 blen = 0;
            u8 dummy = 0;
            (void)dummy;
            if (AmlNameValue(e, &body, &blen))
            {
                u32 sp = 0;
                EvalState sub{st.arena, abs, st.args, st.argc};
                sub.depth = st.depth;
                return EvalTermArg(body, blen, sp, sub, out);
            }
            out = AmlValue{};
            return true;
        }
        if (nr.root || nr.caret || StrLen(abs) <= 1)
            break;
    }
    out = AmlValue{}; // unresolved → Uninit (caller decides)
    return true;
}

bool ReadIntArg(const u8* p, u32 len, u32& pos, EvalState& st, u64& v)
{
    AmlValue a;
    if (!EvalTermArg(p, len, pos, st, a))
        return false;
    v = AsInteger(a);
    return true;
}

bool IsNameStart(u8 c)
{
    return c == '\\' || c == '^' || c == 0x2E || c == 0x2F || IsLeadNameChar(c);
}

// ML-04: RAII depth guard — bumps st.expr_depth on entry and restores it on
// every exit (EvalTermArg has ~40 return points). Over the cap -> bail false.
struct ExprDepthGuard
{
    EvalState& st;
    bool ok;
    explicit ExprDepthGuard(EvalState& s) : st(s), ok(++s.expr_depth <= kMaxExprDepth) {}
    ~ExprDepthGuard() { --st.expr_depth; }
};

// EvalTermArg — decode and evaluate one TermArg at p[pos], advance pos.
bool EvalTermArg(const u8* p, u32 len, u32& pos, EvalState& st, AmlValue& out)
{
    ExprDepthGuard guard(st);
    if (!guard.ok)
        return false;
    if (pos >= len)
        return false;
    const u8 op = p[pos++];

    // Constants.
    if (op == 0x00)
    {
        out = AmlValue::Int(0);
        return true;
    }
    if (op == 0x01)
    {
        out = AmlValue::Int(1);
        return true;
    }
    if (op == 0xFF)
    {
        out = AmlValue::Int(~0ULL);
        return true;
    }
    if (op == 0x0A)
    {
        if (pos >= len)
            return false;
        out = AmlValue::Int(p[pos++]);
        return true;
    }
    if (op == 0x0B)
    {
        if (pos + 2 > len)
            return false;
        out = AmlValue::Int(u64(p[pos]) | u64(p[pos + 1]) << 8);
        pos += 2;
        return true;
    }
    if (op == 0x0C)
    {
        if (pos + 4 > len)
            return false;
        u64 v = 0;
        for (u32 i = 0; i < 4; ++i)
            v |= u64(p[pos + i]) << (i * 8);
        pos += 4;
        out = AmlValue::Int(v);
        return true;
    }
    if (op == 0x0E)
    {
        if (pos + 8 > len)
            return false;
        u64 v = 0;
        for (u32 i = 0; i < 8; ++i)
            v |= u64(p[pos + i]) << (i * 8);
        pos += 8;
        out = AmlValue::Int(v);
        return true;
    }
    if (op == 0x0D) // String
    {
        out = AmlValue{};
        out.type = AmlType::String;
        u32 i = 0;
        while (pos < len && p[pos] != 0 && i + 1 < kAmlBufCap)
            out.bytes[i++] = p[pos++];
        if (pos >= len)
            return false;
        ++pos; // NUL
        out.bytes[i] = 0;
        out.len = u16(i);
        return true;
    }

    // Arg / Local.
    if (op >= 0x68 && op <= 0x6E)
    {
        const u8 i = op - 0x68;
        out = (i < st.argc) ? st.args[i] : AmlValue{};
        return true;
    }
    if (op >= 0x60 && op <= 0x67)
    {
        out = st.locals[op - 0x60];
        return true;
    }

    // Buffer: PkgLength BufferSize ByteList.
    if (op == 0x11)
    {
        u32 plen = 0, pc = 0;
        if (!ReadPkgLength(p + pos, len - pos, &plen, &pc))
            return false;
        const u32 pkg_end = pos + plen;
        if (plen > len - pos)
            return false;
        pos += pc;
        u64 bufsz = 0;
        if (!ReadIntArg(p, len, pos, st, bufsz))
            return false;
        out = AmlValue{};
        out.type = AmlType::Buffer;
        out.len = u16(bufsz > kAmlBufCap ? kAmlBufCap : bufsz);
        u32 i = 0;
        while (pos < pkg_end && i < out.len)
            out.bytes[i++] = p[pos++];
        pos = pkg_end;
        return true;
    }

    // Package / VarPackage.
    if (op == 0x12 || op == 0x13)
    {
        u32 plen = 0, pc = 0;
        if (!ReadPkgLength(p + pos, len - pos, &plen, &pc))
            return false;
        if (plen > len - pos)
            return false;
        const u32 pkg_end = pos + plen;
        pos += pc;
        u64 nelem = 0;
        if (op == 0x12)
        {
            if (pos >= len)
                return false;
            nelem = p[pos++];
        }
        else if (!ReadIntArg(p, len, pos, st, nelem))
            return false;
        out = AmlValue{};
        out.type = AmlType::Package;
        out.pkg_count = 0;
        out.pkg_first = st.arena.used;
        // ML-08: reserve all parent element slots up front so they stay
        // contiguous. Evaluating an element may recursively allocate arena
        // slots (a nested Package), which would otherwise push the parent's
        // later elements to non-contiguous indices and make nodes[pkg_first+idx]
        // resolve to a nested child's slot in Index/AmlEvaluatePackageInts.
        const u32 first = st.arena.used;
        for (u64 e = 0; e < nelem; ++e)
        {
            if (st.arena.Alloc() < 0)
                break;
            ++out.pkg_count;
        }
        for (u32 e = 0; e < out.pkg_count && pos < pkg_end; ++e)
        {
            AmlValue ev;
            if (!EvalTermArg(p, pkg_end, pos, st, ev))
                ev = AmlValue{};
            st.arena.nodes[first + e] = ev;
        }
        pos = pkg_end;
        return true;
    }

    // Two-operand arithmetic / bitwise: op A B Target.
    auto binop = [&](u64 (*f)(u64, u64)) -> bool
    {
        u64 a = 0, b = 0;
        if (!ReadIntArg(p, len, pos, st, a) || !ReadIntArg(p, len, pos, st, b))
            return false;
        Target t;
        if (!ReadTarget(p, len, pos, st, t))
            return false;
        out = AmlValue::Int(f(a, b));
        StoreToTarget(t, out, st);
        return true;
    };
    switch (op)
    {
    case 0x72:
        return binop([](u64 a, u64 b) { return a + b; });
    case 0x74:
        return binop([](u64 a, u64 b) { return a - b; });
    case 0x77:
        return binop([](u64 a, u64 b) { return a * b; });
    case 0x79:
        return binop([](u64 a, u64 b) { return b >= 64 ? 0 : a << b; });
    case 0x7A:
        return binop([](u64 a, u64 b) { return b >= 64 ? 0 : a >> b; });
    case 0x7B:
        return binop([](u64 a, u64 b) { return a & b; });
    case 0x7C:
        return binop([](u64 a, u64 b) { return ~(a & b); });
    case 0x7D:
        return binop([](u64 a, u64 b) { return a | b; });
    case 0x7E:
        return binop([](u64 a, u64 b) { return ~(a | b); });
    case 0x7F:
        return binop([](u64 a, u64 b) { return a ^ b; });
    case 0x85:
        return binop([](u64 a, u64 b) { return b ? a % b : 0; });
    default:
        break;
    }

    // Divide: Divide Dividend Divisor Remainder Quotient.
    if (op == 0x78)
    {
        u64 a = 0, b = 0;
        if (!ReadIntArg(p, len, pos, st, a) || !ReadIntArg(p, len, pos, st, b))
            return false;
        Target rem, quo;
        if (!ReadTarget(p, len, pos, st, rem) || !ReadTarget(p, len, pos, st, quo))
            return false;
        const u64 q = b ? a / b : 0;
        const u64 r = b ? a % b : 0;
        StoreToTarget(rem, AmlValue::Int(r), st);
        StoreToTarget(quo, AmlValue::Int(q), st);
        out = AmlValue::Int(q);
        return true;
    }

    // Not (1 operand + Target), FindSetLeft/RightBit.
    if (op == 0x80 || op == 0x81 || op == 0x82)
    {
        u64 a = 0;
        if (!ReadIntArg(p, len, pos, st, a))
            return false;
        Target t;
        if (!ReadTarget(p, len, pos, st, t))
            return false;
        u64 r = 0;
        if (op == 0x80)
            r = ~a;
        else if (op == 0x81)
        {
            for (int i = 63; i >= 0; --i)
                if (a & (1ULL << i))
                {
                    r = u64(i) + 1;
                    break;
                }
        }
        else
        {
            for (int i = 0; i < 64; ++i)
                if (a & (1ULL << i))
                {
                    r = u64(i) + 1;
                    break;
                }
        }
        out = AmlValue::Int(r);
        StoreToTarget(t, out, st);
        return true;
    }

    // Increment / Decrement (SuperName, read-modify-write).
    if (op == 0x75 || op == 0x76)
    {
        const u32 save = pos;
        AmlValue cur;
        if (!EvalTermArg(p, len, pos, st, cur))
            return false;
        const u64 nv = op == 0x75 ? AsInteger(cur) + 1 : AsInteger(cur) - 1;
        pos = save;
        Target t;
        if (!ReadTarget(p, len, pos, st, t))
            return false;
        out = AmlValue::Int(nv);
        StoreToTarget(t, out, st);
        return true;
    }

    // Logical. LNot (0x92) doubles as a prefix for LNotEqual /
    // LLessEqual / LGreaterEqual (0x92 0x93/0x95/0x94).
    if (op == 0x90 || op == 0x91)
    {
        u64 a = 0, b = 0;
        if (!ReadIntArg(p, len, pos, st, a) || !ReadIntArg(p, len, pos, st, b))
            return false;
        out = AmlValue::Int((op == 0x90 ? (a && b) : (a || b)) ? ~0ULL : 0);
        return true;
    }
    if (op == 0x92)
    {
        if (pos < len && (p[pos] == 0x93 || p[pos] == 0x94 || p[pos] == 0x95))
        {
            const u8 sub = p[pos++];
            u64 a = 0, b = 0;
            if (!ReadIntArg(p, len, pos, st, a) || !ReadIntArg(p, len, pos, st, b))
                return false;
            bool r = sub == 0x93 ? (a != b) : sub == 0x94 ? (a <= b) : (a >= b);
            out = AmlValue::Int(r ? ~0ULL : 0);
            return true;
        }
        u64 a = 0;
        if (!ReadIntArg(p, len, pos, st, a))
            return false;
        out = AmlValue::Int(a ? 0 : ~0ULL);
        return true;
    }
    if (op == 0x93 || op == 0x94 || op == 0x95)
    {
        u64 a = 0, b = 0;
        if (!ReadIntArg(p, len, pos, st, a) || !ReadIntArg(p, len, pos, st, b))
            return false;
        bool r = op == 0x93 ? (a == b) : op == 0x94 ? (a > b) : (a < b);
        out = AmlValue::Int(r ? ~0ULL : 0);
        return true;
    }

    // Store(Source, Target) → value of Source.
    if (op == 0x70)
    {
        AmlValue v;
        if (!EvalTermArg(p, len, pos, st, v))
            return false;
        Target t;
        if (!ReadTarget(p, len, pos, st, t))
            return false;
        StoreToTarget(t, v, st);
        out = v;
        return true;
    }

    // SizeOf / ToInteger / ToBuffer / ToHexString / ToDecimalString /
    // ToString / DerefOf — single-operand, best-effort coercions.
    if (op == 0x87) // SizeOf
    {
        AmlValue v;
        if (!EvalTermArg(p, len, pos, st, v))
            return false;
        u64 s = v.type == AmlType::Package                                 ? v.pkg_count
                : (v.type == AmlType::Buffer || v.type == AmlType::String) ? v.len
                                                                           : 8;
        out = AmlValue::Int(s);
        return true;
    }
    if (op == 0x99 || op == 0x83) // ToInteger / DerefOf
    {
        AmlValue v;
        if (!EvalTermArg(p, len, pos, st, v))
            return false;
        if (op == 0x99)
        {
            out = AmlValue::Int(AsInteger(v));
            // ToInteger has an optional Target in ASL but the encoded
            // form here is the 1-arg expression; no Target byte.
        }
        else
            out = v;
        return true;
    }
    if (op == 0x96 || op == 0x98 || op == 0x97 || op == 0x9C) // To{Buffer,Hex,Dec,String}
    {
        AmlValue v;
        if (!EvalTermArg(p, len, pos, st, v))
            return false;
        Target t;
        if (!ReadTarget(p, len, pos, st, t))
            return false;
        out = v; // v0: identity coercion (callers on this path want the bytes)
        StoreToTarget(t, out, st);
        return true;
    }

    // Index(Source, Index, Target) — element of Buffer/Package.
    if (op == 0x88)
    {
        AmlValue src;
        if (!EvalTermArg(p, len, pos, st, src))
            return false;
        u64 idx = 0;
        if (!ReadIntArg(p, len, pos, st, idx))
            return false;
        Target t;
        if (!ReadTarget(p, len, pos, st, t))
            return false;
        if (src.type == AmlType::Package && idx < src.pkg_count)
            out = st.arena.nodes[src.pkg_first + idx];
        else if ((src.type == AmlType::Buffer || src.type == AmlType::String) && idx < src.len)
            out = AmlValue::Int(src.bytes[idx]);
        else
            out = AmlValue{};
        StoreToTarget(t, out, st);
        return true;
    }

    // ObjectType(SuperName).
    if (op == 0x8E)
    {
        AmlValue v;
        if (!EvalTermArg(p, len, pos, st, v))
            return false;
        u64 ty = v.type == AmlType::Integer   ? 1
                 : v.type == AmlType::String  ? 2
                 : v.type == AmlType::Buffer  ? 3
                 : v.type == AmlType::Package ? 4
                                              : 0;
        out = AmlValue::Int(ty);
        return true;
    }

    // Extended-opcode TermArgs.
    if (op == 0x5B)
    {
        if (pos >= len)
            return false;
        const u8 ext = p[pos++];
        if (ext == 0x12) // CondRefOf(Source, Target) → bool
        {
            NameRef nr;
            u32 c = 0;
            bool exists = false;
            if (IsNameStart(p[pos]) && ReadNameRef(p + pos, len - pos, &nr, &c))
            {
                pos += c;
                char abs[64];
                for (u32 trim = 0; ResolveAbsolute(st.scope, nr, trim, abs, sizeof(abs)); ++trim)
                {
                    if (AmlNamespaceFind(abs) || AmlFieldFind(abs))
                    {
                        exists = true;
                        break;
                    }
                    if (nr.root || nr.caret || StrLen(abs) <= 1)
                        break;
                }
            }
            Target t;
            if (!ReadTarget(p, len, pos, st, t))
                return false;
            out = AmlValue::Int(exists ? ~0ULL : 0);
            return true;
        }
        if (ext == 0x23 || ext == 0x27 || ext == 0x21 || ext == 0x22) // Acquire/Release/Stall/Sleep
        {
            // Acquire(mutex, timeout)→bool0; Release(mutex);
            // Stall(us); Sleep(ms) — operands are TermArgs/SuperName.
            if (ext == 0x23)
            {
                AmlValue m;
                EvalTermArg(p, len, pos, st, m);
                if (pos + 2 <= len)
                    pos += 2;           // WordData timeout
                out = AmlValue::Int(0); // acquired
                return true;
            }
            AmlValue a;
            if (ext == 0x27)
            {
                EvalTermArg(p, len, pos, st, a);
                out = AmlValue::Int(0);
                return true;
            }
            u64 d = 0;
            ReadIntArg(p, len, pos, st, d);
            const u64 ns = (ext == 0x21 ? d * 1000ULL : d * 1000000ULL);
            const u64 deadline = time::MonotonicNs() + ns;
            while (time::MonotonicNs() < deadline)
                arch::Inb(0x80); // ~1us I/O delay
            out = AmlValue::Int(0);
            return true;
        }
        return false; // other ext opcodes not used as TermArgs in v0
    }

    // NameString → Name / Method / Field.
    if (IsNameStart(op))
    {
        --pos;
        NameRef nr;
        u32 c = 0;
        if (!ReadNameRef(p + pos, len - pos, &nr, &c))
            return false;
        pos += c;
        return ResolveNameValue(nr, st, p, len, pos, out);
    }

    return false; // unknown TermArg opcode → fail (caller falls back)
}

// ExecTermList — run statements in p[begin, end).
bool ExecTermList(const u8* p, u32 len, u32 begin, u32 end, EvalState& st)
{
    u32 pos = begin;
    while (pos < end && pos < len)
    {
        if (st.returned || st.brk || st.cont)
            return true;
        const u8 op = p[pos];

        if (op == 0xA4) // Return(TermArg)
        {
            ++pos;
            AmlValue v;
            if (!EvalTermArg(p, len, pos, st, v))
                return false;
            st.retval = v;
            st.returned = true;
            return true;
        }
        if (op == 0xA3 || op == 0xCC) // Noop / BreakPoint
        {
            ++pos;
            continue;
        }
        if (op == 0xA5) // Break
        {
            ++pos;
            st.brk = true;
            return true;
        }
        if (op == 0x9F) // Continue
        {
            ++pos;
            st.cont = true;
            return true;
        }
        if (op == 0xA0) // If(Predicate) { TermList } [Else]
        {
            ++pos;
            u32 plen = 0, pc = 0;
            if (!ReadPkgLength(p + pos, len - pos, &plen, &pc))
                return false;
            if (plen > len - pos)
                return false;
            const u32 if_end = pos + plen;
            pos += pc;
            u64 pred = 0;
            if (!ReadIntArg(p, if_end, pos, st, pred))
                return false;
            if (pred)
            {
                if (!ExecTermList(p, len, pos, if_end, st))
                    return false;
            }
            pos = if_end;
            if (pos < end && p[pos] == 0xA1) // Else
            {
                ++pos;
                u32 elen = 0, ec = 0;
                if (!ReadPkgLength(p + pos, len - pos, &elen, &ec))
                    return false;
                if (elen > len - pos)
                    return false;
                const u32 else_end = pos + elen;
                pos += ec;
                if (!pred)
                {
                    if (!ExecTermList(p, len, pos, else_end, st))
                        return false;
                }
                pos = else_end;
            }
            continue;
        }
        if (op == 0xA1) // stray Else (taken-If path) → skip its package
        {
            ++pos;
            u32 elen = 0, ec = 0;
            if (!ReadPkgLength(p + pos, len - pos, &elen, &ec))
                return false;
            if (elen > len - pos)
                return false;
            pos += elen;
            continue;
        }
        if (op == 0xA2) // While(Predicate) { TermList }
        {
            ++pos;
            u32 wlen = 0, wc = 0;
            if (!ReadPkgLength(p + pos, len - pos, &wlen, &wc))
                return false;
            if (wlen > len - pos)
                return false;
            const u32 w_end = pos + wlen;
            const u32 body0 = pos + wc;
            u32 guard = 0;
            for (;;)
            {
                if (++guard > 100000)
                    break; // runaway-loop guard
                u32 pp = body0;
                u64 pred = 0;
                if (!ReadIntArg(p, w_end, pp, st, pred))
                    return false;
                if (!pred)
                    break;
                if (!ExecTermList(p, len, pp, w_end, st))
                    return false;
                if (st.returned || st.brk)
                {
                    st.brk = false;
                    break;
                }
                st.cont = false;
            }
            pos = w_end;
            continue;
        }
        if (op == 0x86) // Notify(Object, Value)
        {
            ++pos;
            AmlValue o, v;
            EvalTermArg(p, len, pos, st, o);
            EvalTermArg(p, len, pos, st, v);
            continue; // v0: no Notify sink wired (GAP — EC slice adds one)
        }

        // Otherwise it's an expression-statement (Store, method call,
        // Acquire, arithmetic-with-Target, …). Evaluate + discard.
        AmlValue tmp;
        if (!EvalTermArg(p, len, pos, st, tmp))
            return false;
    }
    return true;
}

bool InvokeMethod(const char* abs_path, const AmlNamespaceEntry* m, EvalState& st, const u8* caller, u32 caller_len,
                  u32& cpos, AmlValue& out)
{
    if (st.depth >= kMaxCallDepth)
        return false;
    const u8* body = nullptr;
    u32 blen = 0;
    u8 margc = 0;
    if (!AmlMethodBody(m, &body, &blen, &margc))
        return false;
    AmlValue callee_args[7] = {};
    for (u8 i = 0; i < margc && i < 7; ++i)
    {
        if (!EvalTermArg(caller, caller_len, cpos, st, callee_args[i]))
            return false;
    }
    EvalState sub{st.arena, abs_path, callee_args, margc};
    sub.depth = st.depth + 1;
    if (!ExecTermList(body, blen, 0, blen, sub))
        return false;
    out = sub.returned ? sub.retval : AmlValue{};
    return true;
}

} // namespace

::duetos::core::Result<void> AmlEvaluateRaw(const u8* aml, u32 len, const AmlValue* args, u32 argc, AmlValue* out)
{
    if (aml == nullptr || out == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    Arena arena;
    EvalState st{arena, "\\", args, u8(argc > 7 ? 7 : argc)};
    if (!ExecTermList(aml, len, 0, len, st))
        return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
    *out = st.returned ? st.retval : AmlValue{};
    return {};
}

::duetos::core::Result<void> AmlEvaluate(const char* path, const AmlValue* args, u32 argc, AmlValue* out)
{
    if (path == nullptr || out == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    *out = AmlValue{};

    if (const AmlFieldInfo* fi = AmlFieldFind(path))
    {
        u64 v = 0;
        if (!FieldRead(fi, &v))
            return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
        *out = AmlValue::Int(v);
        return {};
    }

    const AmlNamespaceEntry* e = AmlNamespaceFind(path);
    if (e == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::NotFound};

    Arena arena;
    if (e->kind == AmlObjectKind::Method)
    {
        const u8* body = nullptr;
        u32 blen = 0;
        u8 margc = 0;
        if (!AmlMethodBody(e, &body, &blen, &margc))
            return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
        AmlValue ca[7] = {};
        for (u8 i = 0; i < margc && i < 7; ++i)
            ca[i] = (i < argc && args) ? args[i] : AmlValue{};
        EvalState st{arena, path, ca, margc};
        if (!ExecTermList(body, blen, 0, blen, st))
            return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
        *out = st.returned ? st.retval : AmlValue{};
        return {};
    }
    if (e->kind == AmlObjectKind::Name)
    {
        const u8* data = nullptr;
        u32 dlen = 0;
        if (!AmlNameValue(e, &data, &dlen))
            return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
        EvalState st{arena, path, args, u8(argc > 7 ? 7 : argc)};
        u32 sp = 0;
        if (!EvalTermArg(data, dlen, sp, st, *out))
            return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
        return {};
    }
    return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
}

bool AmlEvaluateInteger(const char* path, u64* out, const AmlValue* args, u32 argc)
{
    if (out == nullptr)
        return false;
    AmlValue v;
    if (!AmlEvaluate(path, args, argc, &v).has_value())
        return false;
    if (v.type != AmlType::Integer && v.type != AmlType::Buffer)
        return false;
    *out = AsInteger(v);
    return true;
}

bool AmlEvaluatePackageInts(const char* path, u64* out, u32 cap, u32* count, const AmlValue* args, u32 argc)
{
    if (path == nullptr || out == nullptr || count == nullptr)
        return false;
    *count = 0;
    const AmlNamespaceEntry* e = AmlNamespaceFind(path);
    if (e == nullptr)
        return false;

    Arena arena;
    AmlValue r{};
    if (e->kind == AmlObjectKind::Method)
    {
        const u8* body = nullptr;
        u32 blen = 0;
        u8 margc = 0;
        if (!AmlMethodBody(e, &body, &blen, &margc))
            return false;
        AmlValue ca[7] = {};
        for (u8 i = 0; i < margc && i < 7; ++i)
            ca[i] = (i < argc && args) ? args[i] : AmlValue{};
        EvalState st{arena, path, ca, margc};
        if (!ExecTermList(body, blen, 0, blen, st) || !st.returned)
            return false;
        r = st.retval;
    }
    else if (e->kind == AmlObjectKind::Name)
    {
        const u8* data = nullptr;
        u32 dlen = 0;
        if (!AmlNameValue(e, &data, &dlen))
            return false;
        EvalState st{arena, path, args, u8(argc > 7 ? 7 : argc)};
        u32 sp = 0;
        if (!EvalTermArg(data, dlen, sp, st, r))
            return false;
    }
    else
    {
        return false;
    }
    if (r.type != AmlType::Package)
        return false;
    // Arena still alive here — flatten before it dies with this frame.
    const u32 n = r.pkg_count < cap ? r.pkg_count : cap;
    for (u32 i = 0; i < n; ++i)
    {
        const AmlValue& el = arena.nodes[r.pkg_first + i];
        out[i] = (el.type == AmlType::Integer || el.type == AmlType::Buffer) ? AsInteger(el) : 0;
    }
    *count = n;
    return true;
}

void AmlEvalSelfTest()
{
    struct Case
    {
        const u8* aml;
        u32 len;
        u64 arg0;
        bool has_arg;
        u64 expect;
        const char* tag;
    };
    // 1. Return(Add(5, 3)) == 8
    static const u8 p1[] = {0xA4, 0x72, 0x0A, 0x05, 0x0A, 0x03, 0x00};
    // 2. If(LEqual(Arg0,1)){Return(0x2A)} Else {Return(0x0D)}
    static const u8 p2[] = {0xA0, 0x07, 0x93, 0x68, 0x01, 0xA4, 0x0A, 0x2A, 0xA1, 0x04, 0xA4, 0x0A, 0x0D};
    // 3. Local0=0; While(LLess(Local0,5)) Local0=Add(Local0,1); Return(Local0) == 5
    static const u8 p3[] = {0x70, 0x00, 0x60, 0xA2, 0x0B, 0x95, 0x60, 0x0A, 0x05,
                            0x70, 0x72, 0x60, 0x01, 0x00, 0x60, 0xA4, 0x60};
    // 4. Return(Index(Package(2){7,9}, 1)) == 9
    static const u8 p4[] = {0xA4, 0x88, 0x12, 0x06, 0x02, 0x0A, 0x07, 0x0A, 0x09, 0x01, 0x00};
    // ML-08: 5. Return(Index(Package(2){Package(1){5}, 9}, 1)) == 9 — a nested
    // Package as a non-last element must not shift the parent's later slots.
    static const u8 p5[] = {0xA4, 0x88, 0x12, 0x09, 0x02, 0x12, 0x04, 0x01, 0x0A, 0x05, 0x0A, 0x09, 0x01, 0x00};
    const Case cases[] = {
        {p1, sizeof(p1), 0, false, 8, "add"},           {p2, sizeof(p2), 1, true, 0x2A, "if-true"},
        {p2, sizeof(p2), 0, true, 0x0D, "if-false"},    {p3, sizeof(p3), 0, false, 5, "while"},
        {p4, sizeof(p4), 0, false, 9, "package-index"}, {p5, sizeof(p5), 0, false, 9, "nested-package-index"},
    };
    for (const Case& c : cases)
    {
        AmlValue a0 = AmlValue::Int(c.arg0);
        AmlValue r;
        const auto rr = AmlEvaluateRaw(c.aml, c.len, c.has_arg ? &a0 : nullptr, c.has_arg ? 1 : 0, &r);
        if (!rr.has_value() || r.type != AmlType::Integer || r.integer != c.expect)
        {
            arch::SerialWrite("[acpi/aml-eval] selftest FAIL: ");
            arch::SerialWrite(c.tag);
            arch::SerialWrite(" got=");
            arch::SerialWriteHex(r.integer);
            arch::SerialWrite(" want=");
            arch::SerialWriteHex(c.expect);
            arch::SerialWrite("\n");
            core::PanicWithValue("acpi/aml-eval", "method-interpreter selftest failed", r.integer);
        }
    }
    arch::SerialWrite(
        "[acpi/aml-eval] selftest PASS (6 programs: add/if/while/package/nested-package + namespace methods=");
    arch::SerialWriteHex(AmlNamespaceCountByKind(AmlObjectKind::Method));
    arch::SerialWrite(")\n");
    KLOG_INFO_V("acpi/aml-eval", "selftest PASS — namespace method count",
                AmlNamespaceCountByKind(AmlObjectKind::Method));
}

} // namespace duetos::acpi
