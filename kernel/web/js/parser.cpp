#include "web/js/ast.h"

#include "web/js/arena.h"
#include "web/js/interp.h"
#include "web/js/lexer.h"

/*
 * DuetOS — kernel/web/js: precedence-climbing (Pratt) parser.
 *
 * Consumes the TokenStream and builds the AST. Binary operators use a
 * binding-power table; unary/primary expressions are handled directly.
 * Statements are parsed by leading-keyword dispatch. ASI-lite: a
 * missing semicolon is tolerated when the next token starts on a new
 * line, before `}`, or at EOF.
 *
 * GAP: for-in / for-of (parsed-and-rejected), labels, switch, do-while,
 *      try/catch/throw, class, getters/setters, destructuring,
 *      spread/rest, default params, computed object keys, `new`.
 */

namespace duetos::web::js
{

namespace
{

struct Parser
{
    const Token* t;
    u32 n;
    u32 pos;
    Arena& arena;
    bool ok;
    const char* err;
    u32 errLine;

    const Token& Cur() const { return t[pos < n ? pos : n - 1]; }
    const Token& Peek(u32 o = 1) const
    {
        u32 i = pos + o;
        return t[i < n ? i : n - 1];
    }
    Tok Kind() const { return Cur().kind; }
    bool Is(Tok k) const { return Kind() == k; }
    bool AtEnd() const { return Kind() == Tok::Eof; }

    void Fail(const char* m)
    {
        if (ok)
        {
            ok = false;
            err = m;
            errLine = Cur().line;
        }
    }

    const Token& Adv() { return t[pos < n ? pos++ : n - 1]; }

    bool Accept(Tok k)
    {
        if (Is(k))
        {
            Adv();
            return true;
        }
        return false;
    }

    bool Expect(Tok k, const char* m)
    {
        if (Is(k))
        {
            Adv();
            return true;
        }
        Fail(m);
        return false;
    }

    AstNode* Node(Ast kind)
    {
        AstNode* n2 = arena.New<AstNode>();
        if (!n2)
        {
            Fail("out of memory");
            return nullptr;
        }
        n2->kind = kind;
        n2->line = Cur().line;
        return n2;
    }
};

// Forward decls.
AstNode* ParseExpr(Parser& p);
AstNode* ParseAssign(Parser& p);
AstNode* ParseStatement(Parser& p);
AstNode* ParseBlock(Parser& p);

// Binary binding powers (higher = tighter). 0 == not a binary op here.
struct BinInfo
{
    Op op;
    int bp;
};

BinInfo BinOpOf(Tok k)
{
    switch (k)
    {
    case Tok::OrOr:
        return {Op::Or, 2};
    case Tok::AndAnd:
        return {Op::And, 3};
    case Tok::EqEq:
        return {Op::EqEq, 4};
    case Tok::NotEq:
        return {Op::NotEq, 4};
    case Tok::EqEqEq:
        return {Op::StrictEq, 4};
    case Tok::NotEqEq:
        return {Op::StrictNotEq, 4};
    case Tok::Lt:
        return {Op::Lt, 5};
    case Tok::Gt:
        return {Op::Gt, 5};
    case Tok::LtEq:
        return {Op::Le, 5};
    case Tok::GtEq:
        return {Op::Ge, 5};
    case Tok::Plus:
        return {Op::Add, 6};
    case Tok::Minus:
        return {Op::Sub, 6};
    case Tok::Star:
        return {Op::Mul, 7};
    case Tok::Slash:
        return {Op::Div, 7};
    case Tok::Percent:
        return {Op::Mod, 7};
    default:
        return {Op::None, 0};
    }
}

// Collect a comma-separated list terminated by `close`. Returns the
// element nodes via the arena pointer array; count in *outCount.
AstNode** ParseExprList(Parser& p, Tok close, u32& outCount)
{
    AstNode* tmp[64];
    u32 c = 0;
    if (!p.Is(close))
    {
        for (;;)
        {
            if (c >= 64)
            {
                p.Fail("argument/element list too long");
                outCount = 0;
                return nullptr;
            }
            AstNode* e = ParseAssign(p);
            if (!p.ok)
            {
                outCount = 0;
                return nullptr;
            }
            tmp[c++] = e;
            if (!p.Accept(Tok::Comma))
                break;
        }
    }
    AstNode** out = c ? p.arena.NewArray<AstNode*>(c) : nullptr;
    if (c && !out)
    {
        p.Fail("out of memory");
        outCount = 0;
        return nullptr;
    }
    for (u32 i = 0; i < c; ++i)
        out[i] = tmp[i];
    outCount = c;
    return out;
}

// Parse the parameter name list of a function/arrow into the node.
void ParseParams(Parser& p, AstNode* fn)
{
    const char* names[32];
    u32 lens[32];
    u32 c = 0;
    if (!p.Is(Tok::RParen))
    {
        for (;;)
        {
            if (!p.Is(Tok::Ident))
            {
                p.Fail("expected parameter name");
                return;
            }
            if (c >= 32)
            {
                p.Fail("too many parameters");
                return;
            }
            names[c] = p.Cur().start;
            lens[c] = p.Cur().len;
            c++;
            p.Adv();
            if (!p.Accept(Tok::Comma))
                break;
        }
    }
    // Store params as Ident kids for uniformity.
    if (c)
    {
        fn->kids = p.arena.NewArray<AstNode*>(c);
        if (!fn->kids)
        {
            p.Fail("out of memory");
            return;
        }
        for (u32 i = 0; i < c; ++i)
        {
            AstNode* id = p.arena.New<AstNode>();
            if (!id)
            {
                p.Fail("out of memory");
                return;
            }
            id->kind = Ast::Ident;
            id->str = names[i];
            id->strLen = lens[i];
            fn->kids[i] = id;
        }
    }
    fn->kidCount = c;
}

// Object literal: { key: value, ... }  keys are ident or string.
AstNode* ParseObjectLit(Parser& p)
{
    AstNode* obj = p.Node(Ast::ObjectLit);
    if (!obj)
        return nullptr;
    p.Adv(); // {
    const char* keys[64];
    u32 keyLens[64];
    AstNode* vals[64];
    u32 c = 0;
    if (!p.Is(Tok::RBrace))
    {
        for (;;)
        {
            if (c >= 64)
            {
                p.Fail("object literal too large");
                return nullptr;
            }
            if (p.Is(Tok::Ident) || p.Is(Tok::String))
            {
                if (p.Is(Tok::String))
                {
                    keys[c] = p.Cur().strData;
                    keyLens[c] = p.Cur().strLen;
                }
                else
                {
                    keys[c] = p.Cur().start;
                    keyLens[c] = p.Cur().len;
                }
                p.Adv();
            }
            else
            {
                p.Fail("expected object key");
                return nullptr;
            }
            if (!p.Expect(Tok::Colon, "expected ':' in object literal"))
                return nullptr;
            vals[c] = ParseAssign(p);
            if (!p.ok)
                return nullptr;
            c++;
            if (!p.Accept(Tok::Comma))
                break;
        }
    }
    if (!p.Expect(Tok::RBrace, "expected '}' to close object literal"))
        return nullptr;
    if (c)
    {
        obj->kids = p.arena.NewArray<AstNode*>(c);
        obj->keys = p.arena.NewArray<const char*>(c);
        obj->keyLens = p.arena.NewArray<u32>(c);
        if (!obj->kids || !obj->keys || !obj->keyLens)
        {
            p.Fail("out of memory");
            return nullptr;
        }
        for (u32 i = 0; i < c; ++i)
        {
            obj->kids[i] = vals[i];
            obj->keys[i] = keys[i];
            obj->keyLens[i] = keyLens[i];
        }
    }
    obj->kidCount = c;
    return obj;
}

// Detect an arrow function: `( params ) =>` or `ident =>`.
bool LooksLikeArrow(Parser& p)
{
    if (p.Is(Tok::Ident) && p.Peek(1).kind == Tok::Arrow)
        return true;
    if (!p.Is(Tok::LParen))
        return false;
    // scan forward to the matching ')' then check for '=>'
    u32 depth = 0;
    for (u32 i = p.pos; i < p.n; ++i)
    {
        Tok k = p.t[i].kind;
        if (k == Tok::LParen)
            depth++;
        else if (k == Tok::RParen)
        {
            depth--;
            if (depth == 0)
                return p.t[i + 1 < p.n ? i + 1 : i].kind == Tok::Arrow;
        }
        else if (k == Tok::Eof)
            return false;
    }
    return false;
}

AstNode* ParseArrow(Parser& p)
{
    AstNode* fn = p.Node(Ast::Arrow);
    if (!fn)
        return nullptr;
    if (p.Is(Tok::Ident))
    {
        // single param without parens
        AstNode* id = p.arena.New<AstNode>();
        if (!id)
        {
            p.Fail("out of memory");
            return nullptr;
        }
        id->kind = Ast::Ident;
        id->str = p.Cur().start;
        id->strLen = p.Cur().len;
        p.Adv();
        fn->kids = p.arena.NewArray<AstNode*>(1);
        if (!fn->kids)
        {
            p.Fail("out of memory");
            return nullptr;
        }
        fn->kids[0] = id;
        fn->kidCount = 1;
    }
    else
    {
        p.Expect(Tok::LParen, "expected '('");
        ParseParams(p, fn);
        if (!p.ok)
            return nullptr;
        p.Expect(Tok::RParen, "expected ')'");
    }
    p.Expect(Tok::Arrow, "expected '=>'");
    if (!p.ok)
        return nullptr;
    if (p.Is(Tok::LBrace))
    {
        fn->a = ParseBlock(p); // block body
    }
    else
    {
        // expression body: wrap in an implicit return for the interp.
        AstNode* ret = p.Node(Ast::Return);
        if (!ret)
            return nullptr;
        ret->a = ParseAssign(p);
        fn->a = ret;
    }
    return fn;
}

AstNode* ParseFunctionExpr(Parser& p)
{
    AstNode* fn = p.Node(Ast::Function);
    if (!fn)
        return nullptr;
    p.Adv(); // 'function'
    if (p.Is(Tok::Ident))
    {
        fn->str = p.Cur().start;
        fn->strLen = p.Cur().len;
        p.Adv();
    }
    p.Expect(Tok::LParen, "expected '(' after function");
    ParseParams(p, fn);
    if (!p.ok)
        return nullptr;
    p.Expect(Tok::RParen, "expected ')'");
    fn->a = ParseBlock(p);
    return fn;
}

// Template literal: a TemplateStr head, then zero or more
// (TemplateExprStart expr TemplateExprEnd TemplateStr) groups. Folds
// into an Ast::Template node: keys[] = cooked chunks (kidCount+1 of
// them), kids[] = interpolated expressions.
AstNode* ParseTemplate(Parser& p)
{
    AstNode* tpl = p.Node(Ast::Template);
    if (!tpl)
        return nullptr;

    const char* chunks[65];
    u32 chunkLens[65];
    AstNode* exprs[64];
    u32 chunkCount = 0;
    u32 exprCount = 0;

    // head chunk
    chunks[chunkCount] = p.Cur().strData;
    chunkLens[chunkCount] = p.Cur().strLen;
    chunkCount++;
    p.Adv();

    while (p.Is(Tok::TemplateExprStart))
    {
        if (exprCount >= 64)
        {
            p.Fail("too many template interpolations");
            return nullptr;
        }
        p.Adv(); // ${
        exprs[exprCount] = ParseExpr(p);
        if (!p.ok)
            return nullptr;
        exprCount++;
        if (!p.Expect(Tok::TemplateExprEnd, "expected '}' to close template interpolation"))
            return nullptr;
        if (!p.Is(Tok::TemplateStr))
        {
            p.Fail("expected template chunk after interpolation");
            return nullptr;
        }
        chunks[chunkCount] = p.Cur().strData;
        chunkLens[chunkCount] = p.Cur().strLen;
        chunkCount++;
        p.Adv();
    }

    if (exprCount)
    {
        tpl->kids = p.arena.NewArray<AstNode*>(exprCount);
        if (!tpl->kids)
        {
            p.Fail("out of memory");
            return nullptr;
        }
        for (u32 i = 0; i < exprCount; ++i)
            tpl->kids[i] = exprs[i];
    }
    tpl->kidCount = exprCount;

    tpl->keys = p.arena.NewArray<const char*>(chunkCount);
    tpl->keyLens = p.arena.NewArray<u32>(chunkCount);
    if (!tpl->keys || !tpl->keyLens)
    {
        p.Fail("out of memory");
        return nullptr;
    }
    for (u32 i = 0; i < chunkCount; ++i)
    {
        tpl->keys[i] = chunks[i];
        tpl->keyLens[i] = chunkLens[i];
    }
    return tpl;
}

AstNode* ParsePrimary(Parser& p)
{
    if (LooksLikeArrow(p))
        return ParseArrow(p);

    const Token& tk = p.Cur();
    switch (tk.kind)
    {
    case Tok::Number:
    {
        AstNode* n = p.Node(Ast::NumberLit);
        if (!n)
            return nullptr;
        if (tk.numIsInt)
        {
            n->numIsInt = true;
            n->numI = tk.numI;
        }
        else
        {
            bool isInt;
            i64 iv;
            Sf32 fv;
            if (!ParseNumberText(tk.start, tk.len, isInt, iv, fv))
            {
                p.Fail("invalid numeric literal");
                return nullptr;
            }
            n->numIsInt = isInt;
            n->numI = iv;
            n->numF = fv;
        }
        p.Adv();
        return n;
    }
    case Tok::String:
    {
        AstNode* n = p.Node(Ast::StringLit);
        if (!n)
            return nullptr;
        n->str = tk.strData;
        n->strLen = tk.strLen;
        p.Adv();
        return n;
    }
    case Tok::Regex:
    {
        AstNode* n = p.Node(Ast::RegexLit);
        if (!n)
            return nullptr;
        n->str = tk.strData;
        n->strLen = tk.strLen;
        n->reFlags = tk.reFlags;
        n->reFlagsLen = tk.reFlagsLen;
        p.Adv();
        return n;
    }
    case Tok::KwTrue:
    case Tok::KwFalse:
    {
        AstNode* n = p.Node(Ast::BoolLit);
        if (!n)
            return nullptr;
        n->boolVal = (tk.kind == Tok::KwTrue);
        p.Adv();
        return n;
    }
    case Tok::KwNull:
    {
        AstNode* n = p.Node(Ast::NullLit);
        p.Adv();
        return n;
    }
    case Tok::KwUndefined:
    {
        AstNode* n = p.Node(Ast::UndefinedLit);
        p.Adv();
        return n;
    }
    case Tok::Ident:
    {
        AstNode* n = p.Node(Ast::Ident);
        if (!n)
            return nullptr;
        n->str = tk.start;
        n->strLen = tk.len;
        p.Adv();
        return n;
    }
    case Tok::TemplateStr:
        return ParseTemplate(p);
    case Tok::KwFunction:
        return ParseFunctionExpr(p);
    case Tok::LParen:
    {
        p.Adv();
        AstNode* e = ParseExpr(p);
        p.Expect(Tok::RParen, "expected ')'");
        return e;
    }
    case Tok::LBracket:
    {
        AstNode* arr = p.Node(Ast::ArrayLit);
        if (!arr)
            return nullptr;
        p.Adv();
        arr->kids = ParseExprList(p, Tok::RBracket, arr->kidCount);
        p.Expect(Tok::RBracket, "expected ']'");
        return arr;
    }
    case Tok::LBrace:
        return ParseObjectLit(p);
    default:
        p.Fail("unexpected token in expression");
        return nullptr;
    }
}

// Member access, indexing, and calls (left-associative postfix).
AstNode* ParsePostfix(Parser& p)
{
    AstNode* e = ParsePrimary(p);
    if (!p.ok)
        return nullptr;
    for (;;)
    {
        if (p.Is(Tok::Dot))
        {
            p.Adv();
            if (!p.Is(Tok::Ident))
            {
                p.Fail("expected property name after '.'");
                return nullptr;
            }
            AstNode* m = p.Node(Ast::Member);
            if (!m)
                return nullptr;
            m->a = e;
            m->str = p.Cur().start;
            m->strLen = p.Cur().len;
            p.Adv();
            e = m;
        }
        else if (p.Is(Tok::LBracket))
        {
            p.Adv();
            AstNode* idx = p.Node(Ast::Index);
            if (!idx)
                return nullptr;
            idx->a = e;
            idx->b = ParseExpr(p);
            p.Expect(Tok::RBracket, "expected ']'");
            e = idx;
        }
        else if (p.Is(Tok::LParen))
        {
            p.Adv();
            AstNode* call = p.Node(Ast::Call);
            if (!call)
                return nullptr;
            call->a = e;
            call->kids = ParseExprList(p, Tok::RParen, call->kidCount);
            p.Expect(Tok::RParen, "expected ')'");
            e = call;
        }
        else
        {
            break;
        }
        if (!p.ok)
            return nullptr;
    }
    return e;
}

AstNode* ParseUnary(Parser& p)
{
    Op op = Op::None;
    switch (p.Kind())
    {
    case Tok::Plus:
        op = Op::Pos;
        break;
    case Tok::Minus:
        op = Op::Neg;
        break;
    case Tok::Not:
        op = Op::NotOp;
        break;
    case Tok::KwTypeof:
        op = Op::Typeof;
        break;
    default:
        break;
    }
    if (op != Op::None)
    {
        AstNode* n = p.Node(Ast::Unary);
        if (!n)
            return nullptr;
        n->op = op;
        p.Adv();
        n->a = ParseUnary(p);
        return n;
    }
    return ParsePostfix(p);
}

AstNode* ParseBinary(Parser& p, int minBp)
{
    AstNode* lhs = ParseUnary(p);
    if (!p.ok)
        return nullptr;
    for (;;)
    {
        BinInfo bi = BinOpOf(p.Kind());
        if (bi.op == Op::None || bi.bp < minBp)
            break;
        Op op = bi.op;
        p.Adv();
        AstNode* rhs = ParseBinary(p, bi.bp + 1);
        if (!p.ok)
            return nullptr;
        bool logical = (op == Op::And || op == Op::Or);
        AstNode* n = p.arena.New<AstNode>();
        if (!n)
        {
            p.Fail("out of memory");
            return nullptr;
        }
        n->kind = logical ? Ast::Logical : Ast::Binary;
        n->op = op;
        n->a = lhs;
        n->b = rhs;
        lhs = n;
    }
    return lhs;
}

AstNode* ParseTernary(Parser& p)
{
    AstNode* cond = ParseBinary(p, 1);
    if (!p.ok)
        return nullptr;
    if (p.Is(Tok::Question))
    {
        p.Adv();
        AstNode* n = p.Node(Ast::Ternary);
        if (!n)
            return nullptr;
        n->a = cond;
        n->b = ParseAssign(p);
        p.Expect(Tok::Colon, "expected ':' in ternary");
        n->c = ParseAssign(p);
        return n;
    }
    return cond;
}

Op AssignOpOf(Tok k)
{
    switch (k)
    {
    case Tok::Assign:
        return Op::AssignPlain;
    case Tok::PlusEq:
        return Op::AssignAdd;
    case Tok::MinusEq:
        return Op::AssignSub;
    case Tok::StarEq:
        return Op::AssignMul;
    case Tok::SlashEq:
        return Op::AssignDiv;
    case Tok::PercentEq:
        return Op::AssignMod;
    default:
        return Op::None;
    }
}

AstNode* ParseAssign(Parser& p)
{
    AstNode* lhs = ParseTernary(p);
    if (!p.ok)
        return nullptr;
    Op aop = AssignOpOf(p.Kind());
    if (aop != Op::None)
    {
        if (lhs->kind != Ast::Ident && lhs->kind != Ast::Member && lhs->kind != Ast::Index)
        {
            p.Fail("invalid assignment target");
            return nullptr;
        }
        AstNode* n = p.Node(Ast::Assign);
        if (!n)
            return nullptr;
        n->op = aop;
        n->a = lhs;
        p.Adv();
        n->b = ParseAssign(p); // right-assoc
        return n;
    }
    return lhs;
}

AstNode* ParseExpr(Parser& p)
{
    // No comma-operator: expression is a single assignment expr.
    return ParseAssign(p);
}

// Statement-terminator handling (ASI-lite).
void ExpectSemi(Parser& p)
{
    if (p.Accept(Tok::Semicolon))
        return;
    // ASI: ok if next is '}', EOF, or began on a new line.
    if (p.Is(Tok::RBrace) || p.AtEnd() || p.Cur().newlineBefore)
        return;
    p.Fail("expected ';'");
}

AstNode* ParseVarDecl(Parser& p, u8 declKind)
{
    AstNode* n = p.Node(Ast::VarDecl);
    if (!n)
        return nullptr;
    n->declKind = declKind;
    p.Adv(); // var/let/const
    if (!p.Is(Tok::Ident))
    {
        p.Fail("expected variable name");
        return nullptr;
    }
    n->str = p.Cur().start;
    n->strLen = p.Cur().len;
    p.Adv();
    if (p.Accept(Tok::Assign))
    {
        n->a = ParseAssign(p);
        if (!p.ok)
            return nullptr;
    }
    ExpectSemi(p);
    return n;
}

AstNode* ParseBlock(Parser& p)
{
    AstNode* blk = p.Node(Ast::Block);
    if (!blk)
        return nullptr;
    p.Expect(Tok::LBrace, "expected '{'");
    AstNode* tmp[256];
    u32 c = 0;
    while (!p.Is(Tok::RBrace) && !p.AtEnd() && p.ok)
    {
        if (c >= 256)
        {
            p.Fail("block too large");
            return nullptr;
        }
        tmp[c++] = ParseStatement(p);
    }
    p.Expect(Tok::RBrace, "expected '}'");
    if (!p.ok)
        return nullptr;
    if (c)
    {
        blk->kids = p.arena.NewArray<AstNode*>(c);
        if (!blk->kids)
        {
            p.Fail("out of memory");
            return nullptr;
        }
        for (u32 i = 0; i < c; ++i)
            blk->kids[i] = tmp[i];
    }
    blk->kidCount = c;
    return blk;
}

AstNode* ParseIf(Parser& p)
{
    AstNode* n = p.Node(Ast::If);
    if (!n)
        return nullptr;
    p.Adv();
    p.Expect(Tok::LParen, "expected '(' after if");
    n->a = ParseExpr(p);
    p.Expect(Tok::RParen, "expected ')'");
    n->b = ParseStatement(p);
    if (p.Is(Tok::KwElse))
    {
        p.Adv();
        n->c = ParseStatement(p);
    }
    return n;
}

AstNode* ParseWhile(Parser& p)
{
    AstNode* n = p.Node(Ast::While);
    if (!n)
        return nullptr;
    p.Adv();
    p.Expect(Tok::LParen, "expected '(' after while");
    n->a = ParseExpr(p);
    p.Expect(Tok::RParen, "expected ')'");
    n->b = ParseStatement(p);
    return n;
}

AstNode* ParseFor(Parser& p)
{
    AstNode* n = p.Node(Ast::For);
    if (!n)
        return nullptr;
    p.Adv();
    p.Expect(Tok::LParen, "expected '(' after for");
    // init
    if (p.Is(Tok::Semicolon))
    {
        p.Adv();
    }
    else if (p.Is(Tok::KwVar) || p.Is(Tok::KwLet) || p.Is(Tok::KwConst))
    {
        u8 dk = p.Is(Tok::KwVar) ? 0 : (p.Is(Tok::KwLet) ? 1 : 2);
        // Peek for for-in: `for (let x in ...)` — GAP.
        if (p.Peek(1).kind == Tok::Ident && p.Peek(2).kind == Tok::KwIn)
        {
            p.Fail("for-in loops not supported (GAP)");
            return nullptr;
        }
        n->a = ParseVarDecl(p, dk); // consumes its own ';'
    }
    else
    {
        AstNode* e = ParseExpr(p);
        AstNode* es = p.Node(Ast::ExprStmt);
        if (es)
            es->a = e;
        n->a = es;
        p.Expect(Tok::Semicolon, "expected ';' in for");
    }
    // cond
    if (!p.Is(Tok::Semicolon))
        n->c = ParseExpr(p);
    p.Expect(Tok::Semicolon, "expected ';' in for");
    // update
    if (!p.Is(Tok::RParen))
        n->b = ParseExpr(p);
    p.Expect(Tok::RParen, "expected ')'");
    n->d = ParseStatement(p);
    return n;
}

AstNode* ParseFunctionDecl(Parser& p)
{
    AstNode* fn = ParseFunctionExpr(p);
    if (!p.ok || !fn)
        return fn;
    if (!fn->str)
    {
        p.Fail("function declaration requires a name");
        return nullptr;
    }
    return fn; // interp treats a top-level/Block Function with a name as a decl
}

AstNode* ParseStatement(Parser& p)
{
    switch (p.Kind())
    {
    case Tok::KwVar:
        return ParseVarDecl(p, 0);
    case Tok::KwLet:
        return ParseVarDecl(p, 1);
    case Tok::KwConst:
        return ParseVarDecl(p, 2);
    case Tok::LBrace:
        return ParseBlock(p);
    case Tok::KwIf:
        return ParseIf(p);
    case Tok::KwWhile:
        return ParseWhile(p);
    case Tok::KwFor:
        return ParseFor(p);
    case Tok::KwFunction:
        return ParseFunctionDecl(p);
    case Tok::KwReturn:
    {
        AstNode* n = p.Node(Ast::Return);
        if (!n)
            return nullptr;
        p.Adv();
        if (!p.Is(Tok::Semicolon) && !p.Is(Tok::RBrace) && !p.AtEnd() && !p.Cur().newlineBefore)
            n->a = ParseExpr(p);
        ExpectSemi(p);
        return n;
    }
    case Tok::KwBreak:
    {
        AstNode* n = p.Node(Ast::Break);
        p.Adv();
        ExpectSemi(p);
        return n;
    }
    case Tok::KwContinue:
    {
        AstNode* n = p.Node(Ast::Continue);
        p.Adv();
        ExpectSemi(p);
        return n;
    }
    case Tok::Semicolon:
    {
        // empty statement
        AstNode* n = p.Node(Ast::Block);
        p.Adv();
        return n;
    }
    default:
    {
        AstNode* n = p.Node(Ast::ExprStmt);
        if (!n)
            return nullptr;
        n->a = ParseExpr(p);
        ExpectSemi(p);
        return n;
    }
    }
}

} // namespace

ParseResult Parse(const TokenStream& toks, Arena& arena)
{
    ParseResult r{};
    Parser p{toks.tokens, toks.count, 0, arena, true, nullptr, 0};

    AstNode* prog = arena.New<AstNode>();
    if (!prog)
    {
        r.ok = false;
        r.errMsg = "out of memory";
        return r;
    }
    prog->kind = Ast::Program;

    AstNode* tmp[1024];
    u32 c = 0;
    while (!p.AtEnd() && p.ok)
    {
        if (c >= 1024)
        {
            p.Fail("program too large");
            break;
        }
        tmp[c++] = ParseStatement(p);
    }

    if (!p.ok)
    {
        r.ok = false;
        r.errMsg = p.err;
        r.errLine = p.errLine;
        return r;
    }
    if (c)
    {
        prog->kids = arena.NewArray<AstNode*>(c);
        if (!prog->kids)
        {
            r.ok = false;
            r.errMsg = "out of memory";
            return r;
        }
        for (u32 i = 0; i < c; ++i)
            prog->kids[i] = tmp[i];
    }
    prog->kidCount = c;

    r.program = prog;
    r.ok = true;
    return r;
}

} // namespace duetos::web::js
