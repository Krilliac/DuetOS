#include "web/js/lexer.h"

#include "web/js/arena.h"

/*
 * DuetOS — kernel/web/js: hand-written lexer.
 *
 * Two-pass-free: one forward scan emitting tokens into an arena-backed
 * vector. Numbers and strings are parsed/decoded as they're scanned so
 * the parser sees ready payloads. See lexer.h for the GAP list.
 */

namespace duetos::web::js
{

namespace
{

constexpr u32 kMaxTokens = 65536;
constexpr u32 kMaxTemplateNesting = 16;

struct Scanner
{
    const char* s;
    u32 n;
    u32 pos;
    u32 line;
    Arena& arena;

    bool sawNewline; // pending "a newline preceded the next token"

    // Template-literal interpolation tracking. Each open `${` pushes a
    // frame holding the running `{`/`}` balance of the interpolation
    // body, so a `}` that closes a nested object literal does not end
    // the interpolation prematurely. tmplDepth == 0 means "not inside an
    // interpolation": a `}` then is a plain RBrace.
    u32 tmplBrace[kMaxTemplateNesting];
    u32 tmplDepth;

    bool Eof() const { return pos >= n; }
    char Peek(u32 o = 0) const { return (pos + o < n) ? s[pos + o] : '\0'; }
    char Adv() { return s[pos++]; }
};

bool IsDigit(char c)
{
    return c >= '0' && c <= '9';
}
bool IsHex(char c)
{
    return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
bool IsIdentStart(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$';
}
bool IsIdentPart(char c)
{
    return IsIdentStart(c) || IsDigit(c);
}

int HexVal(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - 'A' + 10;
}

// Skip whitespace + comments, tracking newlines for ASI. Returns false
// only on an unterminated block comment.
bool SkipTrivia(Scanner& sc, const char*& err)
{
    for (;;)
    {
        char c = sc.Peek();
        if (c == ' ' || c == '\t' || c == '\r')
        {
            sc.Adv();
        }
        else if (c == '\n')
        {
            sc.sawNewline = true;
            sc.line++;
            sc.Adv();
        }
        else if (c == '/' && sc.Peek(1) == '/')
        {
            while (!sc.Eof() && sc.Peek() != '\n')
                sc.Adv();
        }
        else if (c == '/' && sc.Peek(1) == '*')
        {
            sc.Adv();
            sc.Adv();
            bool closed = false;
            while (!sc.Eof())
            {
                if (sc.Peek() == '*' && sc.Peek(1) == '/')
                {
                    sc.Adv();
                    sc.Adv();
                    closed = true;
                    break;
                }
                if (sc.Peek() == '\n')
                {
                    sc.sawNewline = true;
                    sc.line++;
                }
                sc.Adv();
            }
            if (!closed)
            {
                err = "unterminated block comment";
                return false;
            }
        }
        else
        {
            break;
        }
    }
    return true;
}

Tok KeywordKind(const char* p, u32 len)
{
    struct KW
    {
        const char* w;
        u32 l;
        Tok t;
    };
    static const KW table[] = {
        {"var", 3, Tok::KwVar},
        {"let", 3, Tok::KwLet},
        {"const", 5, Tok::KwConst},
        {"function", 8, Tok::KwFunction},
        {"return", 6, Tok::KwReturn},
        {"if", 2, Tok::KwIf},
        {"else", 4, Tok::KwElse},
        {"while", 5, Tok::KwWhile},
        {"for", 3, Tok::KwFor},
        {"break", 5, Tok::KwBreak},
        {"continue", 8, Tok::KwContinue},
        {"true", 4, Tok::KwTrue},
        {"false", 5, Tok::KwFalse},
        {"null", 4, Tok::KwNull},
        {"undefined", 9, Tok::KwUndefined},
        {"typeof", 6, Tok::KwTypeof},
        {"in", 2, Tok::KwIn},
        {"new", 3, Tok::KwNew},
    };
    for (const KW& k : table)
    {
        if (k.l != len)
            continue;
        bool eq = true;
        for (u32 i = 0; i < len; ++i)
            if (k.w[i] != p[i])
            {
                eq = false;
                break;
            }
        if (eq)
            return k.t;
    }
    return Tok::Ident;
}

// Parse a number starting at sc.pos. Fills the token's numeric fields.
bool ScanNumber(Scanner& sc, Token& t, const char*& err)
{
    const u32 start = sc.pos;
    // hex
    if (sc.Peek() == '0' && (sc.Peek(1) == 'x' || sc.Peek(1) == 'X'))
    {
        sc.Adv();
        sc.Adv();
        if (!IsHex(sc.Peek()))
        {
            err = "invalid hex literal";
            return false;
        }
        i64 v = 0;
        while (IsHex(sc.Peek()))
            v = v * 16 + HexVal(sc.Adv());
        t.numIsInt = true;
        t.numI = v;
        t.start = sc.s + start;
        t.len = sc.pos - start;
        return true;
    }

    bool isFloat = false;
    while (IsDigit(sc.Peek()))
        sc.Adv();
    if (sc.Peek() == '.' && IsDigit(sc.Peek(1)))
    {
        isFloat = true;
        sc.Adv();
        while (IsDigit(sc.Peek()))
            sc.Adv();
    }
    else if (sc.Peek() == '.' && start == sc.pos)
    {
        // leading-dot form ".5"
        isFloat = true;
        sc.Adv();
        while (IsDigit(sc.Peek()))
            sc.Adv();
    }
    if (sc.Peek() == 'e' || sc.Peek() == 'E')
    {
        isFloat = true;
        sc.Adv();
        if (sc.Peek() == '+' || sc.Peek() == '-')
            sc.Adv();
        if (!IsDigit(sc.Peek()))
        {
            err = "invalid exponent";
            return false;
        }
        while (IsDigit(sc.Peek()))
            sc.Adv();
    }

    t.start = sc.s + start;
    t.len = sc.pos - start;

    if (!isFloat)
    {
        // decimal integer
        i64 v = 0;
        for (u32 i = 0; i < t.len; ++i)
            v = v * 10 + (t.start[i] - '0');
        t.numIsInt = true;
        t.numI = v;
    }
    else
    {
        t.numIsInt = false; // parser converts via ParseNumberText
    }
    return true;
}

// Scan a quoted string, decoding escapes into the arena.
bool ScanString(Scanner& sc, Token& t, const char*& err)
{
    const char quote = sc.Adv(); // consume opening quote
    // Decode into a temporary growable arena buffer. We over-allocate
    // to the remaining source length (decoded is never longer).
    const u32 maxLen = sc.n - sc.pos;
    char* buf = static_cast<char*>(sc.arena.Alloc(maxLen + 1, 1));
    if (!buf)
    {
        err = "out of memory in string literal";
        return false;
    }
    u32 out = 0;
    while (!sc.Eof())
    {
        char c = sc.Peek();
        if (c == quote)
        {
            sc.Adv();
            buf[out] = '\0';
            t.strData = buf;
            t.strLen = out;
            return true;
        }
        if (c == '\n')
        {
            err = "newline in string literal";
            return false;
        }
        if (c == '\\')
        {
            sc.Adv();
            char e = sc.Adv();
            switch (e)
            {
            case 'n':
                buf[out++] = '\n';
                break;
            case 't':
                buf[out++] = '\t';
                break;
            case 'r':
                buf[out++] = '\r';
                break;
            case '0':
                buf[out++] = '\0';
                break;
            case '\\':
                buf[out++] = '\\';
                break;
            case '\'':
                buf[out++] = '\'';
                break;
            case '"':
                buf[out++] = '"';
                break;
            case 'x':
            {
                if (!IsHex(sc.Peek()) || !IsHex(sc.Peek(1)))
                {
                    err = "invalid \\x escape";
                    return false;
                }
                int hi = HexVal(sc.Adv());
                int lo = HexVal(sc.Adv());
                buf[out++] = char((hi << 4) | lo);
                break;
            }
            default:
                buf[out++] = e; // unknown escape -> literal char
                break;
            }
        }
        else
        {
            buf[out++] = sc.Adv();
        }
    }
    err = "unterminated string literal";
    return false;
}

// How a template cooked-chunk scan terminated.
enum class TmplStop : u8
{
    Backtick, // reached the closing `  — template literal is complete
    Interp,   // reached ${       — an interpolation follows
    Error,
};

// Scan one cooked chunk of a template literal starting at sc.pos (which
// sits just past the opening ` or the closing } of a prior ${ … }).
// Decodes the same escapes as a single-/double-quoted string but allows
// raw newlines (templates are multi-line). On success fills t.strData /
// t.strLen with the cooked text and reports where it stopped.
TmplStop ScanTemplateChunk(Scanner& sc, Token& t, const char*& err)
{
    const u32 maxLen = sc.n - sc.pos;
    char* buf = static_cast<char*>(sc.arena.Alloc(maxLen + 1, 1));
    if (!buf)
    {
        err = "out of memory in template literal";
        return TmplStop::Error;
    }
    u32 out = 0;
    while (!sc.Eof())
    {
        char c = sc.Peek();
        if (c == '`')
        {
            sc.Adv();
            buf[out] = '\0';
            t.strData = buf;
            t.strLen = out;
            return TmplStop::Backtick;
        }
        if (c == '$' && sc.Peek(1) == '{')
        {
            sc.Adv();
            sc.Adv();
            buf[out] = '\0';
            t.strData = buf;
            t.strLen = out;
            return TmplStop::Interp;
        }
        if (c == '\n')
        {
            sc.sawNewline = true;
            sc.line++;
            buf[out++] = sc.Adv();
            continue;
        }
        if (c == '\\')
        {
            sc.Adv();
            char e = sc.Adv();
            switch (e)
            {
            case 'n':
                buf[out++] = '\n';
                break;
            case 't':
                buf[out++] = '\t';
                break;
            case 'r':
                buf[out++] = '\r';
                break;
            case '0':
                buf[out++] = '\0';
                break;
            case '\\':
                buf[out++] = '\\';
                break;
            case '`':
                buf[out++] = '`';
                break;
            case '$':
                buf[out++] = '$';
                break;
            case '\'':
                buf[out++] = '\'';
                break;
            case '"':
                buf[out++] = '"';
                break;
            case 'x':
            {
                if (!IsHex(sc.Peek()) || !IsHex(sc.Peek(1)))
                {
                    err = "invalid \\x escape";
                    return TmplStop::Error;
                }
                int hi = HexVal(sc.Adv());
                int lo = HexVal(sc.Adv());
                buf[out++] = char((hi << 4) | lo);
                break;
            }
            default:
                buf[out++] = e; // unknown escape -> literal char
                break;
            }
        }
        else
        {
            buf[out++] = sc.Adv();
        }
    }
    err = "unterminated template literal";
    return TmplStop::Error;
}

// Emit one operator/punctuation token, advancing past it.
Tok ScanOperator(Scanner& sc)
{
    char c = sc.Adv();
    char d = sc.Peek();
    switch (c)
    {
    case '(':
        return Tok::LParen;
    case ')':
        return Tok::RParen;
    case '{':
        return Tok::LBrace;
    case '}':
        return Tok::RBrace;
    case '[':
        return Tok::LBracket;
    case ']':
        return Tok::RBracket;
    case ',':
        return Tok::Comma;
    case ';':
        return Tok::Semicolon;
    case ':':
        return Tok::Colon;
    case '.':
        return Tok::Dot;
    case '?':
        return Tok::Question;
    case '+':
        if (d == '=')
        {
            sc.Adv();
            return Tok::PlusEq;
        }
        return Tok::Plus;
    case '-':
        if (d == '=')
        {
            sc.Adv();
            return Tok::MinusEq;
        }
        return Tok::Minus;
    case '*':
        if (d == '=')
        {
            sc.Adv();
            return Tok::StarEq;
        }
        return Tok::Star;
    case '/':
        if (d == '=')
        {
            sc.Adv();
            return Tok::SlashEq;
        }
        return Tok::Slash;
    case '%':
        if (d == '=')
        {
            sc.Adv();
            return Tok::PercentEq;
        }
        return Tok::Percent;
    case '=':
        if (d == '=')
        {
            sc.Adv();
            if (sc.Peek() == '=')
            {
                sc.Adv();
                return Tok::EqEqEq;
            }
            return Tok::EqEq;
        }
        if (d == '>')
        {
            sc.Adv();
            return Tok::Arrow;
        }
        return Tok::Assign;
    case '!':
        if (d == '=')
        {
            sc.Adv();
            if (sc.Peek() == '=')
            {
                sc.Adv();
                return Tok::NotEqEq;
            }
            return Tok::NotEq;
        }
        return Tok::Not;
    case '<':
        if (d == '=')
        {
            sc.Adv();
            return Tok::LtEq;
        }
        return Tok::Lt;
    case '>':
        if (d == '=')
        {
            sc.Adv();
            return Tok::GtEq;
        }
        return Tok::Gt;
    case '&':
        if (d == '&')
        {
            sc.Adv();
            return Tok::AndAnd;
        }
        return Tok::Error;
    case '|':
        if (d == '|')
        {
            sc.Adv();
            return Tok::OrOr;
        }
        return Tok::Error;
    default:
        return Tok::Error;
    }
}

} // namespace

TokenStream Lex(const char* src, u32 len, Arena& arena)
{
    TokenStream ts{};
    // Each token consumes at least one source byte; +2 covers the EOF
    // token and rounding. Sizing from `len` instead of kMaxTokens keeps
    // the token buffer proportional to the script (a fixed 65536-slot
    // buffer would be megabytes and exhaust the arena on tiny inputs).
    u32 slots = len + 2;
    if (slots > kMaxTokens)
        slots = kMaxTokens;
    Token* toks = arena.NewArray<Token>(slots);
    if (!toks)
    {
        ts.ok = false;
        ts.errMsg = "out of memory allocating token buffer";
        return ts;
    }

    Scanner sc{src, len, 0, 1, arena, false, {}, 0};
    u32 count = 0;

    // Scan one template literal beginning just past the opening `.
    // Emits TemplateStr chunks and TemplateExprStart markers; for each
    // ${ it pushes a brace frame so the main loop knows the matching }
    // ends the interpolation (handled below). Returns false on a lexical
    // error (caller has already set ts.* and returns).
    auto beginTemplate = [&](auto&& emitFn) -> bool
    {
        Token chunk{};
        const char* terr = nullptr;
        TmplStop stop = ScanTemplateChunk(sc, chunk, terr);
        if (stop == TmplStop::Error)
        {
            ts.ok = false;
            ts.errMsg = terr;
            ts.errLine = sc.line;
            return false;
        }
        Token* st = emitFn(Tok::TemplateStr, chunk.strData, chunk.strLen);
        if (st)
        {
            st->strData = chunk.strData;
            st->strLen = chunk.strLen;
        }
        if (stop == TmplStop::Interp)
        {
            emitFn(Tok::TemplateExprStart, sc.s + sc.pos, 0);
            if (sc.tmplDepth < kMaxTemplateNesting)
                sc.tmplBrace[sc.tmplDepth] = 0;
            sc.tmplDepth++;
        }
        return true;
    };

    auto emit = [&](Tok kind, const char* start, u32 tlen) -> Token*
    {
        if (count >= slots)
            return nullptr;
        Token& t = toks[count++];
        t.kind = kind;
        t.start = start;
        t.len = tlen;
        t.line = sc.line;
        t.newlineBefore = sc.sawNewline;
        sc.sawNewline = false;
        return &t;
    };

    for (;;)
    {
        const char* err = nullptr;
        if (!SkipTrivia(sc, err))
        {
            ts.ok = false;
            ts.errMsg = err;
            ts.errLine = sc.line;
            return ts;
        }
        if (sc.Eof())
        {
            emit(Tok::Eof, sc.s + sc.pos, 0);
            break;
        }

        char c = sc.Peek();
        const u32 startPos = sc.pos;

        if (IsDigit(c) || (c == '.' && IsDigit(sc.Peek(1))))
        {
            Token tmp{};
            const char* nerr = nullptr;
            if (!ScanNumber(sc, tmp, nerr))
            {
                ts.ok = false;
                ts.errMsg = nerr;
                ts.errLine = sc.line;
                return ts;
            }
            Token* t = emit(Tok::Number, tmp.start, tmp.len);
            if (!t)
                break;
            t->numIsInt = tmp.numIsInt;
            t->numI = tmp.numI;
        }
        else if (c == '"' || c == '\'')
        {
            Token tmp{};
            const char* serr = nullptr;
            if (!ScanString(sc, tmp, serr))
            {
                ts.ok = false;
                ts.errMsg = serr;
                ts.errLine = sc.line;
                return ts;
            }
            Token* t = emit(Tok::String, sc.s + startPos, sc.pos - startPos);
            if (!t)
                break;
            t->strData = tmp.strData;
            t->strLen = tmp.strLen;
        }
        else if (c == '`')
        {
            sc.Adv(); // consume opening `
            if (sc.tmplDepth >= kMaxTemplateNesting)
            {
                ts.ok = false;
                ts.errMsg = "template literals nested too deeply";
                ts.errLine = sc.line;
                return ts;
            }
            if (!beginTemplate(emit))
                return ts;
        }
        else if (IsIdentStart(c))
        {
            while (IsIdentPart(sc.Peek()))
                sc.Adv();
            const char* p = sc.s + startPos;
            u32 il = sc.pos - startPos;
            emit(KeywordKind(p, il), p, il);
        }
        else
        {
            Tok op = ScanOperator(sc);
            if (op == Tok::Error)
            {
                ts.ok = false;
                ts.errMsg = "unexpected character";
                ts.errLine = sc.line;
                return ts;
            }
            // Inside a ${ … } interpolation, a `}` that balances the
            // interpolation body ends it: emit TemplateExprEnd and
            // resume scanning the following cooked chunk instead of a
            // plain RBrace. Braces from nested object literals balance
            // against tmplBrace[top] first.
            if (op == Tok::LBrace && sc.tmplDepth > 0)
            {
                sc.tmplBrace[sc.tmplDepth - 1]++;
                emit(op, sc.s + startPos, sc.pos - startPos);
            }
            else if (op == Tok::RBrace && sc.tmplDepth > 0 && sc.tmplBrace[sc.tmplDepth - 1] == 0)
            {
                emit(Tok::TemplateExprEnd, sc.s + startPos, sc.pos - startPos);
                sc.tmplDepth--;
                if (!beginTemplate(emit))
                    return ts;
            }
            else
            {
                if (op == Tok::RBrace && sc.tmplDepth > 0)
                    sc.tmplBrace[sc.tmplDepth - 1]--;
                emit(op, sc.s + startPos, sc.pos - startPos);
            }
        }
    }

    ts.tokens = toks;
    ts.count = count;
    ts.ok = true;
    return ts;
}

} // namespace duetos::web::js
