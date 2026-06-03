#include "web/js/regexp.h"

/*
 * DuetOS — kernel/web/js: bounded regex COMPILER (the matcher VM is in
 * regexp_exec.cpp).
 *
 * Compiler: a recursive-descent parse of the SUBSET grammar (see
 * regexp.h) that builds the program as relocatable FRAGMENTS. A fragment
 * is a contiguous run of ReInst whose internal Jmp/Split targets are
 * stored as OFFSETS relative to the fragment's first instruction, so a
 * fragment can be copied to a new base and rebased trivially (add the new
 * base to every internal target). Quantifiers and alternation wrap an
 * atom fragment in fresh scaffolding without any in-place rewriting —
 * the source of the earlier bug-class. Parser recursion is a host-side
 * compile step bounded by the program-instruction cap (kReMaxProgram).
 *
 * Matcher (ReExec): a flat loop over the bytecode with an EXPLICIT
 * arena-allocated backtracking stack and a step budget — never C++
 * recursion, so the kernel stack cannot be smashed by a hostile pattern.
 *
 *   alt    := concat ('|' concat)*
 *   concat := (atom quantifier?)*
 *   atom   := '(' ['?:'] alt ')' | '[' class ']' | '.' | '^' | '$'
 *           | '\' escape | literal
 */

namespace duetos::web::js
{

using namespace duetos::core;

namespace
{

bool IsDigit(char c)
{
    return c >= '0' && c <= '9';
}

bool IsWordChar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

bool IsSpaceChar(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

char Lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? char(c + 32) : c;
}

// A relocatable instruction fragment. `code`/`len` are an arena buffer
// whose internal Jmp/Split targets are OFFSETS from index 0 of the
// fragment. AssembleInto() copies it to an absolute base and rebases.
struct Frag
{
    ReInst* code;
    u32 len;
};

// The compiler state. Builds fragments in the arena; `ok`/`err` latch the
// first failure so a malformed pattern stops emitting.
struct ReCompiler
{
    Arena& arena;
    const char* p;
    u32 n;
    u32 pos;

    ReClass* classes;
    u32 classCap;
    u32 classCount;

    u32 nextGroup; // next capturing-group index (group 0 is the whole match)
    bool ignoreCase;

    u32 instBudget; // remaining instruction allowance (bounds total program)

    bool ok;
    ErrorCode err;

    char Peek(u32 o = 0) const { return (pos + o < n) ? p[pos + o] : '\0'; }
    bool Eof() const { return pos >= n; }
    char Adv() { return p[pos++]; }

    void Fail(ErrorCode e)
    {
        if (ok)
        {
            ok = false;
            err = e;
        }
    }

    // Charge `count` instructions against the program budget. Latches
    // Overflow when a pattern would exceed kReMaxProgram. Centralising the
    // budget here means every fragment-building helper is bounded.
    bool Charge(u32 count)
    {
        if (count > instBudget)
        {
            Fail(ErrorCode::Overflow);
            return false;
        }
        instBudget -= count;
        return true;
    }

    // Allocate a fragment buffer of `cap` instructions (zero-filled).
    ReInst* NewCode(u32 cap)
    {
        if (cap == 0)
            cap = 1;
        ReInst* c = arena.NewArray<ReInst>(cap);
        if (!c)
            Fail(ErrorCode::OutOfMemory);
        return c;
    }

    u32 NewClass(ReClass*& out)
    {
        if (classCount >= classCap)
        {
            Fail(ErrorCode::Overflow);
            out = nullptr;
            return 0;
        }
        out = &classes[classCount];
        return classCount++;
    }
};

void ClassAddByte(ReClass* c, u8 b)
{
    c->bits[b >> 3] |= u8(1u << (b & 7));
}

void ClassAddRange(ReClass* c, u8 lo, u8 hi)
{
    for (u32 b = lo; b <= hi; ++b)
        ClassAddByte(c, u8(b));
}

// Fold an ASCII-case-insensitive class: if a letter bit is set, set its
// opposite-case partner too. Applied once after a class is built when the
// `i` flag is active.
void ClassFoldCase(ReClass* c)
{
    for (u8 ch = 'a'; ch <= 'z'; ++ch)
    {
        bool lo = (c->bits[ch >> 3] >> (ch & 7)) & 1;
        u8 up = u8(ch - 32);
        bool hi = (c->bits[up >> 3] >> (up & 7)) & 1;
        if (lo || hi)
        {
            ClassAddByte(c, ch);
            ClassAddByte(c, up);
        }
    }
}

// Add an escape's character set to a class. Returns false if `e` is not a
// class-shorthand escape (the caller then treats it as a literal).
bool ClassAddEscape(ReClass* c, char e)
{
    switch (e)
    {
    case 'd':
        ClassAddRange(c, '0', '9');
        return true;
    case 'D':
        for (u32 b = 0; b < 256; ++b)
            if (!IsDigit(char(b)))
                ClassAddByte(c, u8(b));
        return true;
    case 'w':
        for (u32 b = 0; b < 256; ++b)
            if (IsWordChar(char(b)))
                ClassAddByte(c, u8(b));
        return true;
    case 'W':
        for (u32 b = 0; b < 256; ++b)
            if (!IsWordChar(char(b)))
                ClassAddByte(c, u8(b));
        return true;
    case 's':
        for (u32 b = 0; b < 256; ++b)
            if (IsSpaceChar(char(b)))
                ClassAddByte(c, u8(b));
        return true;
    case 'S':
        for (u32 b = 0; b < 256; ++b)
            if (!IsSpaceChar(char(b)))
                ClassAddByte(c, u8(b));
        return true;
    default:
        return false;
    }
}

// Decode a single-char escape after `\` into its literal byte. Unknown
// escapes yield the char itself (`\.` `\/` `\(` -> literal punctuation).
char DecodeLiteralEscape(char e)
{
    switch (e)
    {
    case 'n':
        return '\n';
    case 't':
        return '\t';
    case 'r':
        return '\r';
    case 'f':
        return '\f';
    case 'v':
        return '\v';
    case '0':
        return '\0';
    default:
        return e;
    }
}

// ---- fragment helpers ----

// A 1-instruction fragment carrying `inst` (no internal targets).
Frag FragSingle(ReCompiler& c, const ReInst& inst)
{
    Frag f{nullptr, 0};
    if (!c.Charge(1))
        return f;
    ReInst* code = c.NewCode(1);
    if (!code)
        return f;
    code[0] = inst;
    f.code = code;
    f.len = 1;
    return f;
}

// Concatenate two fragments: copy `a` then `b`, rebasing `b`'s internal
// targets by a.len. Internal targets that point at-or-past the fragment
// length (the "fall through to next instruction" target == len) are kept
// relative so the concatenation chains correctly.
Frag FragConcat(ReCompiler& c, const Frag& a, const Frag& b)
{
    if (!c.ok)
        return Frag{nullptr, 0};
    u32 total = a.len + b.len;
    if (!c.Charge(0)) // budget already charged when each frag was built
        return Frag{nullptr, 0};
    ReInst* code = c.NewCode(total ? total : 1);
    if (!code)
        return Frag{nullptr, 0};
    for (u32 i = 0; i < a.len; ++i)
        code[i] = a.code[i];
    for (u32 i = 0; i < b.len; ++i)
    {
        ReInst s = b.code[i];
        if (s.op == ReOp::Jmp)
            s.x += a.len;
        else if (s.op == ReOp::Split)
        {
            s.x += a.len;
            s.y += a.len;
        }
        code[a.len + i] = s;
    }
    Frag f{code, total};
    return f;
}

// ---- class / atom builders (each returns a fragment) ----

// Parse a `[...]` body (leading '[' consumed) into a Class fragment.
Frag BuildCharClass(ReCompiler& c)
{
    ReClass* cls = nullptr;
    u32 idx = c.NewClass(cls);
    if (!c.ok)
        return Frag{nullptr, 0};

    bool negated = false;
    if (c.Peek() == '^')
    {
        negated = true;
        c.Adv();
    }

    bool first = true;
    while (!c.Eof() && (c.Peek() != ']' || first))
    {
        first = false;
        char ch = c.Adv();
        if (ch == '\\')
        {
            if (c.Eof())
            {
                c.Fail(ErrorCode::InvalidArgument);
                return Frag{nullptr, 0};
            }
            char e = c.Adv();
            if (ClassAddEscape(cls, e))
                continue; // a shorthand class can't be a range endpoint
            ch = DecodeLiteralEscape(e);
        }
        if (c.Peek() == '-' && c.Peek(1) != ']' && (c.pos + 1) < c.n)
        {
            c.Adv(); // '-'
            char hi = c.Adv();
            if (hi == '\\')
            {
                if (c.Eof())
                {
                    c.Fail(ErrorCode::InvalidArgument);
                    return Frag{nullptr, 0};
                }
                hi = DecodeLiteralEscape(c.Adv());
            }
            u8 a = u8(ch), b = u8(hi);
            if (a > b)
            {
                c.Fail(ErrorCode::InvalidArgument);
                return Frag{nullptr, 0};
            }
            ClassAddRange(cls, a, b);
        }
        else
        {
            ClassAddByte(cls, u8(ch));
        }
    }
    if (c.Eof())
    {
        c.Fail(ErrorCode::InvalidArgument); // missing ']'
        return Frag{nullptr, 0};
    }
    c.Adv(); // ']'

    if (c.ignoreCase)
        ClassFoldCase(cls);
    if (negated)
        for (u32 i = 0; i < 32; ++i)
            cls->bits[i] = u8(~cls->bits[i]);

    ReInst inst{};
    inst.op = ReOp::Class;
    inst.n = idx;
    return FragSingle(c, inst);
}

// Build a Class fragment from a shorthand escape (\d \w \s …); returns
// {nullptr,0} with `isShort=false` if `e` is not a shorthand.
Frag BuildShorthand(ReCompiler& c, char e, bool& isShort)
{
    ReClass* cls = nullptr;
    u32 idx = c.NewClass(cls);
    if (!c.ok)
    {
        isShort = true;
        return Frag{nullptr, 0};
    }
    if (!ClassAddEscape(cls, e))
    {
        c.classCount--; // roll back the unused slot
        isShort = false;
        return Frag{nullptr, 0};
    }
    isShort = true;
    ReInst inst{};
    inst.op = ReOp::Class;
    inst.n = idx;
    return FragSingle(c, inst);
}

// Build a literal-char fragment. Under `i`, a letter becomes a 2-element
// Class so the VM matches either case with no per-step folding.
Frag BuildLiteral(ReCompiler& c, char ch)
{
    if (c.ignoreCase && ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')))
    {
        ReClass* cls = nullptr;
        u32 idx = c.NewClass(cls);
        if (!c.ok)
            return Frag{nullptr, 0};
        ClassAddByte(cls, u8(Lower(ch)));
        ClassAddByte(cls, u8(Lower(ch) - 32));
        ReInst inst{};
        inst.op = ReOp::Class;
        inst.n = idx;
        return FragSingle(c, inst);
    }
    ReInst inst{};
    inst.op = ReOp::Char;
    inst.ch = ch;
    return FragSingle(c, inst);
}

// ---- forward decls ----
Frag BuildAlt(ReCompiler& c);

// atom := group | class | '.' | '^' | '$' | escape | literal.
Frag BuildAtom(ReCompiler& c)
{
    char ch = c.Peek();
    switch (ch)
    {
    case '(':
    {
        c.Adv();
        bool capturing = true;
        if (c.Peek() == '?' && c.Peek(1) == ':')
        {
            capturing = false;
            c.Adv();
            c.Adv();
        }
        else if (c.Peek() == '?')
        {
            // (?=...) (?!...) (?<...) — lookahead/behind/named: GAP.
            c.Fail(ErrorCode::InvalidArgument);
            return Frag{nullptr, 0};
        }
        u32 groupNo = 0;
        if (capturing)
        {
            if (c.nextGroup >= kReMaxGroups)
            {
                c.Fail(ErrorCode::Overflow);
                return Frag{nullptr, 0};
            }
            groupNo = c.nextGroup++;
        }
        Frag inner = BuildAlt(c);
        if (!c.ok)
            return Frag{nullptr, 0};
        if (c.Peek() != ')')
        {
            c.Fail(ErrorCode::InvalidArgument);
            return Frag{nullptr, 0};
        }
        c.Adv(); // ')'
        if (!capturing)
            return inner;
        // Wrap: Save(2g) ; inner ; Save(2g+1).
        ReInst s0{};
        s0.op = ReOp::Save;
        s0.n = 2 * groupNo;
        ReInst s1{};
        s1.op = ReOp::Save;
        s1.n = 2 * groupNo + 1;
        Frag pre = FragSingle(c, s0);
        Frag post = FragSingle(c, s1);
        Frag body = FragConcat(c, pre, inner);
        return FragConcat(c, body, post);
    }
    case '[':
        c.Adv();
        return BuildCharClass(c);
    case '.':
    {
        c.Adv();
        ReInst inst{};
        inst.op = ReOp::Any;
        return FragSingle(c, inst);
    }
    case '^':
    {
        c.Adv();
        ReInst inst{};
        inst.op = ReOp::AssertBol;
        return FragSingle(c, inst);
    }
    case '$':
    {
        c.Adv();
        ReInst inst{};
        inst.op = ReOp::AssertEol;
        return FragSingle(c, inst);
    }
    case '\\':
    {
        c.Adv();
        if (c.Eof())
        {
            c.Fail(ErrorCode::InvalidArgument);
            return Frag{nullptr, 0};
        }
        char e = c.Adv();
        if (e == 'b' || e == 'B')
        {
            ReInst inst{};
            inst.op = (e == 'b') ? ReOp::AssertWordB : ReOp::AssertNotWordB;
            return FragSingle(c, inst);
        }
        bool isShort = false;
        Frag sf = BuildShorthand(c, e, isShort);
        if (isShort)
            return sf;
        return BuildLiteral(c, DecodeLiteralEscape(e));
    }
    default:
        c.Adv();
        return BuildLiteral(c, ch);
    }
}

// Parse a `{n}` / `{n,}` / `{n,m}` count at the '{'. Returns false
// (consuming nothing) when it is not a valid brace-quantifier so the '{'
// is treated as a literal. hi == kReNoCap means "unbounded".
bool ParseBraceCount(ReCompiler& c, u32& lo, u32& hi)
{
    u32 save = c.pos;
    if (c.Peek() != '{')
        return false;
    c.Adv();
    if (!IsDigit(c.Peek()))
    {
        c.pos = save;
        return false;
    }
    u32 a = 0;
    while (IsDigit(c.Peek()))
        a = a * 10 + u32(c.Adv() - '0');
    u32 b = a;
    bool hasHi = true;
    if (c.Peek() == ',')
    {
        c.Adv();
        if (c.Peek() == '}')
        {
            hasHi = false;
        }
        else
        {
            if (!IsDigit(c.Peek()))
            {
                c.pos = save;
                return false;
            }
            b = 0;
            while (IsDigit(c.Peek()))
                b = b * 10 + u32(c.Adv() - '0');
        }
    }
    if (c.Peek() != '}')
    {
        c.pos = save;
        return false;
    }
    c.Adv();
    lo = a;
    hi = hasHi ? b : kReNoCap;
    return true;
}

// Re-emit a fresh copy of `atom` as a new fragment (so a quantifier can
// repeat it). The copy is independent (its own arena buffer).
Frag CopyFrag(ReCompiler& c, const Frag& atom)
{
    if (!c.ok)
        return Frag{nullptr, 0};
    if (!c.Charge(atom.len))
        return Frag{nullptr, 0};
    ReInst* code = c.NewCode(atom.len ? atom.len : 1);
    if (!code)
        return Frag{nullptr, 0};
    for (u32 i = 0; i < atom.len; ++i)
        code[i] = atom.code[i];
    return Frag{code, atom.len};
}

// Wrap `atom` in `?` semantics: Split(body, end) ; body=atom.
//   greedy: Split.x = body (index 1), Split.y = end (index 1+len)
//   lazy:   swapped.
Frag QuantOptional(ReCompiler& c, const Frag& atom, bool lazy)
{
    if (!c.ok || !c.Charge(1))
        return Frag{nullptr, 0};
    u32 total = 1 + atom.len;
    ReInst* code = c.NewCode(total);
    if (!code)
        return Frag{nullptr, 0};
    code[0].op = ReOp::Split;
    code[0].x = lazy ? total : 1;
    code[0].y = lazy ? 1 : total;
    for (u32 i = 0; i < atom.len; ++i)
    {
        ReInst s = atom.code[i];
        if (s.op == ReOp::Jmp)
            s.x += 1;
        else if (s.op == ReOp::Split)
        {
            s.x += 1;
            s.y += 1;
        }
        code[1 + i] = s;
    }
    return Frag{code, total};
}

// Wrap `atom` in `*` semantics: L0: Split(body, end) ; body ; Jmp L0.
Frag QuantStar(ReCompiler& c, const Frag& atom, bool lazy)
{
    if (!c.ok || !c.Charge(2))
        return Frag{nullptr, 0};
    u32 total = 1 + atom.len + 1; // Split + body + Jmp
    ReInst* code = c.NewCode(total);
    if (!code)
        return Frag{nullptr, 0};
    u32 end = total;
    code[0].op = ReOp::Split;
    code[0].x = lazy ? end : 1;
    code[0].y = lazy ? 1 : end;
    for (u32 i = 0; i < atom.len; ++i)
    {
        ReInst s = atom.code[i];
        if (s.op == ReOp::Jmp)
            s.x += 1;
        else if (s.op == ReOp::Split)
        {
            s.x += 1;
            s.y += 1;
        }
        code[1 + i] = s;
    }
    code[1 + atom.len].op = ReOp::Jmp;
    code[1 + atom.len].x = 0; // loop back to the Split
    return Frag{code, total};
}

// Wrap `atom` in `+` semantics: body ; L: Split(body, end).
Frag QuantPlus(ReCompiler& c, const Frag& atom, bool lazy)
{
    if (!c.ok || !c.Charge(1))
        return Frag{nullptr, 0};
    u32 total = atom.len + 1;
    ReInst* code = c.NewCode(total);
    if (!code)
        return Frag{nullptr, 0};
    for (u32 i = 0; i < atom.len; ++i)
        code[i] = atom.code[i]; // internal targets unchanged (base 0)
    u32 split = atom.len;
    code[split].op = ReOp::Split;
    code[split].x = lazy ? total : 0; // back to body start (index 0)
    code[split].y = lazy ? 0 : total;
    return Frag{code, total};
}

// Apply a quantifier to `atom`, returning the wrapped fragment. General
// {n,m} is realised by concatenating mandatory copies and Split-guarded
// optional copies — all at COMPILE time, bounded by the instruction
// budget, so a huge `{0,1000000}` fails to compile rather than exploding.
Frag ApplyQuantifier(ReCompiler& c, const Frag& atom, u32 lo, u32 hi, bool lazy)
{
    if (lo == 0 && hi == 1)
        return QuantOptional(c, atom, lazy);
    if (lo == 0 && hi == kReNoCap)
        return QuantStar(c, atom, lazy);
    if (lo == 1 && hi == kReNoCap)
        return QuantPlus(c, atom, lazy);

    // Build the mandatory prefix: lo sequential copies.
    Frag acc{nullptr, 0};
    bool haveAcc = false;
    for (u32 k = 0; k < lo; ++k)
    {
        Frag copy = (k == 0) ? atom : CopyFrag(c, atom);
        if (!c.ok)
            return Frag{nullptr, 0};
        if (!haveAcc)
        {
            acc = copy;
            haveAcc = true;
        }
        else
            acc = FragConcat(c, acc, copy);
        if (!c.ok)
            return Frag{nullptr, 0};
    }

    if (hi == kReNoCap)
    {
        // {n,} == n mandatory + one `*` of the atom.
        Frag star = QuantStar(c, (lo == 0) ? atom : CopyFrag(c, atom), lazy);
        if (!c.ok)
            return Frag{nullptr, 0};
        if (!haveAcc)
            return star;
        return FragConcat(c, acc, star);
    }

    // {n,m}: append (hi - lo) optional copies. Each optional is a
    // Split-guarded body; we chain them so an early skip bails the rest.
    u32 optional = hi - lo;
    for (u32 k = 0; k < optional; ++k)
    {
        Frag opt = QuantOptional(c, CopyFrag(c, atom), lazy);
        if (!c.ok)
            return Frag{nullptr, 0};
        // Nesting matters for correct skip-the-tail behaviour: wrap so
        // each subsequent optional sits INSIDE the previous one's body.
        // Concatenation already yields that because an optional that is
        // skipped jumps past only ITS body; the following optional is the
        // next fragment, also skippable. Sequential concat is correct for
        // {n,m} greedy/lazy here.
        if (!haveAcc)
        {
            acc = opt;
            haveAcc = true;
        }
        else
            acc = FragConcat(c, acc, opt);
        if (!c.ok)
            return Frag{nullptr, 0};
    }
    if (!haveAcc)
        return Frag{nullptr, 0}; // {0,0}: matches empty (empty fragment)
    return acc;
}

// concat := (atom quantifier?)*
Frag BuildConcat(ReCompiler& c)
{
    Frag acc{nullptr, 0};
    bool haveAcc = false;
    while (c.ok && !c.Eof())
    {
        char ch = c.Peek();
        if (ch == '|' || ch == ')')
            break;

        Frag atom = BuildAtom(c);
        if (!c.ok)
            return Frag{nullptr, 0};

        char q = c.Peek();
        u32 lo = 0, hi = 0;
        bool haveQuant = false;
        if (q == '*')
        {
            c.Adv();
            lo = 0;
            hi = kReNoCap;
            haveQuant = true;
        }
        else if (q == '+')
        {
            c.Adv();
            lo = 1;
            hi = kReNoCap;
            haveQuant = true;
        }
        else if (q == '?')
        {
            c.Adv();
            lo = 0;
            hi = 1;
            haveQuant = true;
        }
        else if (q == '{')
        {
            if (ParseBraceCount(c, lo, hi))
                haveQuant = true;
        }

        if (haveQuant)
        {
            bool lazy = false;
            if (c.Peek() == '?')
            {
                lazy = true;
                c.Adv();
            }
            if (hi != kReNoCap && hi < lo)
            {
                c.Fail(ErrorCode::InvalidArgument);
                return Frag{nullptr, 0};
            }
            atom = ApplyQuantifier(c, atom, lo, hi, lazy);
            if (!c.ok)
                return Frag{nullptr, 0};
        }

        if (!haveAcc)
        {
            acc = atom;
            haveAcc = true;
        }
        else
            acc = FragConcat(c, acc, atom);
    }
    if (!haveAcc)
    {
        // empty concatenation matches the empty string: a zero-length
        // fragment. Represent it as an empty Frag (len 0).
        return Frag{nullptr, 0};
    }
    return acc;
}

// alt := concat ('|' concat)* — wire alternatives:
//   Split(L1, L2) ; L1: alt1 ; Jmp END ; L2: rest ; END
Frag BuildAlt(ReCompiler& c)
{
    Frag left = BuildConcat(c);
    if (!c.ok)
        return Frag{nullptr, 0};
    if (c.Peek() != '|')
        return left;
    c.Adv();                  // consume '|'
    Frag right = BuildAlt(c); // right-leaning chain handles further '|'
    if (!c.ok)
        return Frag{nullptr, 0};

    if (!c.Charge(2)) // Split + Jmp
        return Frag{nullptr, 0};
    u32 total = 1 + left.len + 1 + right.len;
    ReInst* code = c.NewCode(total);
    if (!code)
        return Frag{nullptr, 0};
    u32 l1 = 1;
    u32 jmp = l1 + left.len;
    u32 l2 = jmp + 1;
    u32 end = total;
    code[0].op = ReOp::Split;
    code[0].x = l1;
    code[0].y = l2;
    for (u32 i = 0; i < left.len; ++i)
    {
        ReInst s = left.code[i];
        if (s.op == ReOp::Jmp)
            s.x += l1;
        else if (s.op == ReOp::Split)
        {
            s.x += l1;
            s.y += l1;
        }
        code[l1 + i] = s;
    }
    code[jmp].op = ReOp::Jmp;
    code[jmp].x = end;
    for (u32 i = 0; i < right.len; ++i)
    {
        ReInst s = right.code[i];
        if (s.op == ReOp::Jmp)
            s.x += l2;
        else if (s.op == ReOp::Split)
        {
            s.x += l2;
            s.y += l2;
        }
        code[l2 + i] = s;
    }
    return Frag{code, total};
}

} // namespace

Result<ReProgram*> ReCompile(Arena& arena, const char* pattern, u32 patLen, const char* flags, u32 flagLen)
{
    ReProgram* prog = arena.New<ReProgram>();
    if (!prog)
        return Err{ErrorCode::OutOfMemory};

    bool g = false, ic = false, ml = false;
    for (u32 i = 0; i < flagLen; ++i)
    {
        switch (flags[i])
        {
        case 'g':
            g = true;
            break;
        case 'i':
            ic = true;
            break;
        case 'm':
            ml = true;
            break;
        default:
            // GAP: 's' (dotAll), 'u' (unicode), 'y' (sticky) unsupported.
            return Err{ErrorCode::InvalidArgument};
        }
    }

    ReClass* classes = arena.NewArray<ReClass>(kReMaxClasses);
    if (!classes)
        return Err{ErrorCode::OutOfMemory};

    ReCompiler c{arena, pattern, patLen, 0, classes, kReMaxClasses, 0, 1, ic, kReMaxProgram, true, ErrorCode::Ok};

    Frag body = BuildAlt(c);
    if (c.ok && !c.Eof())
        c.Fail(ErrorCode::InvalidArgument); // stray ')' / trailing input
    if (!c.ok)
        return Err{c.err};

    // Final program: body ; Match. (Group 0 is recorded by ReExec's outer
    // Save pair, not an in-pattern Save.)
    if (!c.Charge(1))
        return Err{c.err};
    u32 total = body.len + 1;
    ReInst* code = arena.NewArray<ReInst>(total ? total : 1);
    if (!code)
        return Err{ErrorCode::OutOfMemory};
    for (u32 i = 0; i < body.len; ++i)
        code[i] = body.code[i];
    code[body.len].op = ReOp::Match;

    prog->code = code;
    prog->codeLen = total;
    prog->classes = classes;
    prog->classCount = c.classCount;
    prog->groupCount = c.nextGroup; // includes group 0
    prog->global = g;
    prog->ignoreCase = ic;
    prog->multiline = ml;
    return prog;
}

} // namespace duetos::web::js
