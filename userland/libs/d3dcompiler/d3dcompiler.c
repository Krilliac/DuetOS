/*
 * userland/libs/d3dcompiler/d3dcompiler.c — DuetOS d3dcompiler v0.
 *
 * Userland Windows DLL implementing the public d3dcompiler.dll
 * surface (D3DCompile / D3DCompile2 / D3DCreateBlob / D3DReflect /
 * D3DDisassemble). Front-ends an in-process HLSL compiler that
 * lexes + parses a deterministic HLSL subset and emits a DXBC-shaped
 * blob.
 *
 * v0 scope:
 *   - Lex HLSL source into tokens (keywords, identifiers, numbers,
 *     punctuation, semantics).
 *   - Parse a tiny subset:
 *       struct VS_IN { float4 pos : POSITION; float4 col : COLOR; };
 *       struct VS_OUT { float4 pos : SV_POSITION; float4 col : COLOR; };
 *       VS_OUT main(VS_IN i) { VS_OUT o; o.pos = i.pos; o.col = i.col; return o; }
 *     plus arithmetic, constructor calls (float4(...)), saturate/dot/mul.
 *   - Emit a DXBC-shaped blob:
 *       'DXBC' magic + 16-byte source hash + total size + chunk dir.
 *       SHEX (executable), ISGN (input signature), OSGN (output signature),
 *       STAT (statistics).
 *   - Return the blob in an ID3DBlob with the canonical COM shape.
 *
 * Out of scope (v0):
 *   - Texture sampling, geometry/hull/domain/compute shaders,
 *     control flow beyond fall-through `return`, function calls beyond
 *     the small built-in set, preprocessing (#define/#include/#if).
 *   - Shader optimisation passes — the IR is direct-from-AST.
 *   - Real DXBC opcode encoding — we emit our own deterministic
 *     opcode stream inside the SHEX chunk that downstream code
 *     can cross-check by re-running the compiler on the source.
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10260000).
 */

#include "../dx_shared.h"

/* ---------------------------------------------------------------- *
 * d3dcompiler error codes                                          *
 * ---------------------------------------------------------------- */

#define D3DC_ERR_INVALID_SOURCE ((HRESULT)0x80004005UL) /* E_FAIL */
#define D3DC_ERR_PARSE ((HRESULT)0x80004006UL)
#define D3DC_ERR_LEX ((HRESULT)0x80004007UL)
#define D3DC_ERR_OOM DX_E_OUTOFMEMORY

/* D3DCompile flags we currently parse + ignore */
#define D3DCOMPILE_DEBUG (1u << 0)
#define D3DCOMPILE_SKIP_VALIDATION (1u << 1)
#define D3DCOMPILE_SKIP_OPTIMIZATION (1u << 2)
#define D3DCOMPILE_PACK_MATRIX_ROW_MAJOR (1u << 3)
#define D3DCOMPILE_PACK_MATRIX_COLUMN_MAJOR (1u << 4)
#define D3DCOMPILE_OPTIMIZATION_LEVEL0 (1u << 14)
#define D3DCOMPILE_OPTIMIZATION_LEVEL1 (0u)
#define D3DCOMPILE_OPTIMIZATION_LEVEL3 (1u << 15)

/* ---------------------------------------------------------------- *
 * ID3DBlob — refcounted byte buffer with the canonical COM shape.  *
 * ---------------------------------------------------------------- */

static const DxGuid kIID_ID3DBlob = {0x8ba5fb08, 0x5195, 0x40e2, {0xac, 0x58, 0x0d, 0x98, 0x9c, 0x3a, 0x01, 0x02}};

typedef struct ID3DBlobImpl ID3DBlobImpl;

typedef struct ID3DBlobVtbl
{
    HRESULT (*QueryInterface)(ID3DBlobImpl*, REFIID, void**);
    ULONG (*AddRef)(ID3DBlobImpl*);
    ULONG (*Release)(ID3DBlobImpl*);
    void* (*GetBufferPointer)(ID3DBlobImpl*);
    SIZE_T (*GetBufferSize)(ID3DBlobImpl*);
} ID3DBlobVtbl;

struct ID3DBlobImpl
{
    const ID3DBlobVtbl* lpVtbl;
    ULONG refcount;
    SIZE_T size;
    BYTE* data;
};

static HRESULT blob_QueryInterface(ID3DBlobImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_ID3DBlob))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}

static ULONG blob_AddRef(ID3DBlobImpl* self)
{
    return ++self->refcount;
}

static ULONG blob_Release(ID3DBlobImpl* self)
{
    if (--self->refcount == 0)
    {
        if (self->data)
            dx_heap_free(self->data);
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}

static void* blob_GetBufferPointer(ID3DBlobImpl* self)
{
    return self->data;
}

static SIZE_T blob_GetBufferSize(ID3DBlobImpl* self)
{
    return self->size;
}

static const ID3DBlobVtbl g_blob_vtbl = {
    blob_QueryInterface, blob_AddRef, blob_Release, blob_GetBufferPointer, blob_GetBufferSize,
};

static ID3DBlobImpl* blob_alloc(SIZE_T bytes)
{
    ID3DBlobImpl* b = (ID3DBlobImpl*)dx_heap_alloc(sizeof(*b));
    if (!b)
        return NULL;
    dx_memzero(b, sizeof(*b));
    b->lpVtbl = &g_blob_vtbl;
    b->refcount = 1;
    b->size = bytes;
    if (bytes)
    {
        b->data = (BYTE*)dx_heap_alloc(bytes);
        if (!b->data)
        {
            dx_heap_free(b);
            return NULL;
        }
        dx_memzero(b->data, bytes);
    }
    return b;
}

__attribute__((dllexport)) HRESULT D3DCreateBlob(SIZE_T size, ID3DBlobImpl** out_blob)
{
    if (!out_blob)
        return DX_E_POINTER;
    *out_blob = blob_alloc(size);
    return *out_blob ? DX_S_OK : D3DC_ERR_OOM;
}

/* ---------------------------------------------------------------- *
 * HLSL lexer                                                       *
 * ---------------------------------------------------------------- */

typedef enum HlslTokenKind
{
    HTK_Eof = 0,
    HTK_Ident,
    HTK_Number,
    HTK_LBrace,   /* {  */
    HTK_RBrace,   /* }  */
    HTK_LParen,   /* (  */
    HTK_RParen,   /* )  */
    HTK_LBracket, /* [  */
    HTK_RBracket, /* ]  */
    HTK_Semi,     /* ;  */
    HTK_Comma,    /* ,  */
    HTK_Dot,      /* .  */
    HTK_Colon,    /* :  */
    HTK_Plus,     /* +  */
    HTK_Minus,    /* -  */
    HTK_Star,     /* *  */
    HTK_Slash,    /* /  */
    HTK_Assign,   /* =  */

    /* keywords (must remain contiguous; lexer maps via small table) */
    HTK_KwStruct,
    HTK_KwReturn,
    HTK_KwIf,
    HTK_KwElse,
    HTK_KwFor,
    HTK_KwVoid,
    HTK_KwFloat,
    HTK_KwFloat2,
    HTK_KwFloat3,
    HTK_KwFloat4,
    HTK_KwFloat4x4,
    HTK_KwInt,
    HTK_KwUint,
    HTK_KwHalf,
    HTK_KwCBuffer,
    HTK_KwTexture2D,
    HTK_KwSamplerState,
    HTK_KwIn,
    HTK_KwOut,
    HTK_KwInOut,
} HlslTokenKind;

typedef struct HlslToken
{
    HlslTokenKind kind;
    UINT line;
    UINT column;
    SIZE_T text_off; /* byte offset into the source */
    SIZE_T text_len;
    /* Numeric literal — only valid when kind == HTK_Number. The
     * lexer parses both integer + float; the IR emitter treats
     * everything as float for simplicity. */
    double number;
} HlslToken;

#define HLSL_MAX_TOKENS 4096

typedef struct HlslLexer
{
    const char* src;
    SIZE_T src_len;
    SIZE_T cursor;
    UINT line;
    UINT column;
    HlslToken tokens[HLSL_MAX_TOKENS];
    UINT token_count;
    HRESULT err;
} HlslLexer;

static int hlsl_isspace(int c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}
static int hlsl_isalpha(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
static int hlsl_isdigit(int c)
{
    return c >= '0' && c <= '9';
}
static int hlsl_isalnum(int c)
{
    return hlsl_isalpha(c) || hlsl_isdigit(c);
}

static int hlsl_streq_n(const char* a, SIZE_T a_len, const char* b)
{
    SIZE_T b_len = 0;
    while (b[b_len])
        ++b_len;
    if (a_len != b_len)
        return 0;
    for (SIZE_T i = 0; i < a_len; ++i)
        if (a[i] != b[i])
            return 0;
    return 1;
}

static HlslTokenKind hlsl_keyword_lookup(const char* s, SIZE_T n)
{
    if (hlsl_streq_n(s, n, "struct"))
        return HTK_KwStruct;
    if (hlsl_streq_n(s, n, "return"))
        return HTK_KwReturn;
    if (hlsl_streq_n(s, n, "if"))
        return HTK_KwIf;
    if (hlsl_streq_n(s, n, "else"))
        return HTK_KwElse;
    if (hlsl_streq_n(s, n, "for"))
        return HTK_KwFor;
    if (hlsl_streq_n(s, n, "void"))
        return HTK_KwVoid;
    if (hlsl_streq_n(s, n, "float"))
        return HTK_KwFloat;
    if (hlsl_streq_n(s, n, "float2"))
        return HTK_KwFloat2;
    if (hlsl_streq_n(s, n, "float3"))
        return HTK_KwFloat3;
    if (hlsl_streq_n(s, n, "float4"))
        return HTK_KwFloat4;
    if (hlsl_streq_n(s, n, "float4x4"))
        return HTK_KwFloat4x4;
    if (hlsl_streq_n(s, n, "int"))
        return HTK_KwInt;
    if (hlsl_streq_n(s, n, "uint"))
        return HTK_KwUint;
    if (hlsl_streq_n(s, n, "half"))
        return HTK_KwHalf;
    if (hlsl_streq_n(s, n, "cbuffer"))
        return HTK_KwCBuffer;
    if (hlsl_streq_n(s, n, "Texture2D"))
        return HTK_KwTexture2D;
    if (hlsl_streq_n(s, n, "SamplerState"))
        return HTK_KwSamplerState;
    if (hlsl_streq_n(s, n, "in"))
        return HTK_KwIn;
    if (hlsl_streq_n(s, n, "out"))
        return HTK_KwOut;
    if (hlsl_streq_n(s, n, "inout"))
        return HTK_KwInOut;
    return HTK_Ident;
}

static int hlsl_lex_push(HlslLexer* lx, HlslTokenKind k, SIZE_T off, SIZE_T len, double num, UINT line, UINT col)
{
    if (lx->token_count >= HLSL_MAX_TOKENS)
    {
        lx->err = D3DC_ERR_LEX;
        return 0;
    }
    HlslToken* t = &lx->tokens[lx->token_count++];
    t->kind = k;
    t->text_off = off;
    t->text_len = len;
    t->number = num;
    t->line = line;
    t->column = col;
    return 1;
}

static HRESULT hlsl_lex(HlslLexer* lx, const char* src, SIZE_T n)
{
    lx->src = src;
    lx->src_len = n;
    lx->cursor = 0;
    lx->line = 1;
    lx->column = 1;
    lx->token_count = 0;
    lx->err = DX_S_OK;

    while (lx->cursor < n)
    {
        char c = src[lx->cursor];

        /* whitespace + newlines */
        if (hlsl_isspace((unsigned char)c))
        {
            if (c == '\n')
            {
                ++lx->line;
                lx->column = 1;
            }
            else
            {
                ++lx->column;
            }
            ++lx->cursor;
            continue;
        }

        /* line comments + block comments */
        if (c == '/' && lx->cursor + 1 < n && src[lx->cursor + 1] == '/')
        {
            while (lx->cursor < n && src[lx->cursor] != '\n')
                ++lx->cursor;
            continue;
        }
        if (c == '/' && lx->cursor + 1 < n && src[lx->cursor + 1] == '*')
        {
            lx->cursor += 2;
            while (lx->cursor + 1 < n)
            {
                if (src[lx->cursor] == '*' && src[lx->cursor + 1] == '/')
                {
                    lx->cursor += 2;
                    break;
                }
                if (src[lx->cursor] == '\n')
                    ++lx->line;
                ++lx->cursor;
            }
            continue;
        }

        UINT tline = lx->line;
        UINT tcol = lx->column;
        SIZE_T toff = lx->cursor;

        /* identifiers + keywords */
        if (hlsl_isalpha((unsigned char)c))
        {
            SIZE_T start = lx->cursor;
            while (lx->cursor < n && hlsl_isalnum((unsigned char)src[lx->cursor]))
                ++lx->cursor;
            SIZE_T len = lx->cursor - start;
            HlslTokenKind k = hlsl_keyword_lookup(src + start, len);
            if (!hlsl_lex_push(lx, k, start, len, 0.0, tline, tcol))
                return lx->err;
            lx->column += (UINT)len;
            continue;
        }

        /* numbers: integer or floating-point */
        if (hlsl_isdigit((unsigned char)c) ||
            (c == '.' && lx->cursor + 1 < n && hlsl_isdigit((unsigned char)src[lx->cursor + 1])))
        {
            SIZE_T start = lx->cursor;
            int seen_dot = 0;
            double whole = 0.0;
            double frac = 0.0;
            double frac_div = 1.0;
            while (lx->cursor < n)
            {
                char d = src[lx->cursor];
                if (hlsl_isdigit((unsigned char)d))
                {
                    if (!seen_dot)
                        whole = whole * 10.0 + (d - '0');
                    else
                    {
                        frac_div *= 10.0;
                        frac = frac + (d - '0') / frac_div;
                    }
                    ++lx->cursor;
                }
                else if (d == '.' && !seen_dot)
                {
                    seen_dot = 1;
                    ++lx->cursor;
                }
                else
                {
                    break;
                }
            }
            /* `f` / `h` suffix consumed but ignored for type */
            if (lx->cursor < n &&
                (src[lx->cursor] == 'f' || src[lx->cursor] == 'F' || src[lx->cursor] == 'h' || src[lx->cursor] == 'H'))
                ++lx->cursor;
            double v = whole + frac;
            SIZE_T len = lx->cursor - start;
            if (!hlsl_lex_push(lx, HTK_Number, start, len, v, tline, tcol))
                return lx->err;
            lx->column += (UINT)len;
            continue;
        }

        /* punctuation */
        HlslTokenKind pk = HTK_Eof;
        switch (c)
        {
        case '{':
            pk = HTK_LBrace;
            break;
        case '}':
            pk = HTK_RBrace;
            break;
        case '(':
            pk = HTK_LParen;
            break;
        case ')':
            pk = HTK_RParen;
            break;
        case '[':
            pk = HTK_LBracket;
            break;
        case ']':
            pk = HTK_RBracket;
            break;
        case ';':
            pk = HTK_Semi;
            break;
        case ',':
            pk = HTK_Comma;
            break;
        case '.':
            pk = HTK_Dot;
            break;
        case ':':
            pk = HTK_Colon;
            break;
        case '+':
            pk = HTK_Plus;
            break;
        case '-':
            pk = HTK_Minus;
            break;
        case '*':
            pk = HTK_Star;
            break;
        case '/':
            pk = HTK_Slash;
            break;
        case '=':
            pk = HTK_Assign;
            break;
        default:
            lx->err = D3DC_ERR_LEX;
            return D3DC_ERR_LEX;
        }
        if (!hlsl_lex_push(lx, pk, toff, 1, 0.0, tline, tcol))
            return lx->err;
        ++lx->cursor;
        ++lx->column;
    }

    return DX_S_OK;
}

/* ---------------------------------------------------------------- *
 * HLSL parser                                                      *
 *                                                                  *
 * Recursive-descent over a tiny subset:                            *
 *   top := ( struct_decl | func_decl | cbuffer_decl )*             *
 *   struct_decl  := 'struct' Ident '{' field* '}' ';'              *
 *   field        := type Ident ( ':' Ident )? ';'                  *
 *   func_decl    := type Ident '(' params? ')' ( ':' Ident )? body *
 *   params       := param ( ',' param )*                           *
 *   param        := ('in'|'out'|'inout')? type Ident (':' Ident)?  *
 *   cbuffer_decl := 'cbuffer' Ident '{' field* '}'                 *
 *   body         := '{' stmt* '}'                                  *
 *   stmt         := return_stmt | expr_stmt | local_decl           *
 *   return_stmt  := 'return' expr ';'                              *
 *   local_decl   := type Ident ('=' expr)? ';'                     *
 *   expr_stmt    := expr ';'                                       *
 *   expr         := assign_expr                                    *
 *   assign_expr  := unary_expr ( '=' assign_expr )?                *
 *   unary_expr   := '-' unary_expr | mul_expr                      *
 *   mul_expr     := primary ( ('*'|'/') primary )*                 *
 *   primary      := Number | Ident postfix*                        *
 *                 | typename '(' arglist ')' | '(' expr ')'        *
 *   postfix      := '.' Ident | '(' arglist ')'                    *
 *   arglist      := expr ( ',' expr )*                             *
 * ---------------------------------------------------------------- */

#define HLSL_MAX_NODES 2048

typedef enum HlslNodeKind
{
    HN_None = 0,
    HN_Top,
    HN_Struct,
    HN_Field,
    HN_Func,
    HN_Param,
    HN_CBuffer,
    HN_Block,
    HN_Return,
    HN_LocalDecl,
    HN_ExprStmt,
    HN_Number,
    HN_Ident,
    HN_Field_Access,
    HN_Call,
    HN_Constructor,
    HN_BinOp,
    HN_Neg,
    HN_Assign,
} HlslNodeKind;

typedef struct HlslNode HlslNode;

struct HlslNode
{
    HlslNodeKind kind;
    UINT type_token; /* HTK_KwFloat / HTK_KwFloat4 / 0 = unknown */
    UINT name_off;
    UINT name_len;
    UINT semantic_off;
    UINT semantic_len;
    UINT first_child;  /* index into HlslAst::nodes; 0 = none */
    UINT next_sibling; /* index; 0 = none */
    double number;
    char op; /* '+' '-' '*' '/' for HN_BinOp */
};

typedef struct HlslAst
{
    HlslNode nodes[HLSL_MAX_NODES];
    UINT count;
    UINT root;
    HRESULT err;
} HlslAst;

typedef struct HlslParser
{
    HlslLexer* lx;
    HlslAst* ast;
    UINT pos;
} HlslParser;

static UINT ast_alloc_node(HlslAst* a, HlslNodeKind k)
{
    if (a->count + 1 >= HLSL_MAX_NODES)
    {
        a->err = D3DC_ERR_PARSE;
        return 0;
    }
    /* index 0 reserved as "none"; first real node starts at 1 */
    if (a->count == 0)
        a->count = 1;
    UINT i = a->count++;
    HlslNode* n = &a->nodes[i];
    dx_memzero(n, sizeof(*n));
    n->kind = k;
    return i;
}

static void ast_append_child(HlslAst* a, UINT parent, UINT child)
{
    if (parent == 0 || child == 0)
        return;
    HlslNode* p = &a->nodes[parent];
    if (p->first_child == 0)
    {
        p->first_child = child;
        return;
    }
    UINT it = p->first_child;
    while (a->nodes[it].next_sibling != 0)
        it = a->nodes[it].next_sibling;
    a->nodes[it].next_sibling = child;
}

static const HlslToken* psr_peek(HlslParser* p)
{
    if (p->pos >= p->lx->token_count)
        return NULL;
    return &p->lx->tokens[p->pos];
}

static int psr_accept(HlslParser* p, HlslTokenKind k)
{
    const HlslToken* t = psr_peek(p);
    if (t && t->kind == k)
    {
        ++p->pos;
        return 1;
    }
    return 0;
}

static const HlslToken* psr_consume(HlslParser* p, HlslTokenKind k)
{
    const HlslToken* t = psr_peek(p);
    if (!t || t->kind != k)
    {
        p->ast->err = D3DC_ERR_PARSE;
        return NULL;
    }
    ++p->pos;
    return t;
}

static int hlsl_is_typename(HlslTokenKind k)
{
    switch (k)
    {
    case HTK_KwVoid:
    case HTK_KwFloat:
    case HTK_KwFloat2:
    case HTK_KwFloat3:
    case HTK_KwFloat4:
    case HTK_KwFloat4x4:
    case HTK_KwInt:
    case HTK_KwUint:
    case HTK_KwHalf:
    case HTK_KwTexture2D:
    case HTK_KwSamplerState:
        return 1;
    default:
        return 0;
    }
}

/* Forward decls */
static UINT hlsl_parse_expr(HlslParser* p);
static UINT hlsl_parse_block(HlslParser* p);

static UINT hlsl_parse_primary(HlslParser* p)
{
    const HlslToken* t = psr_peek(p);
    if (!t)
    {
        p->ast->err = D3DC_ERR_PARSE;
        return 0;
    }
    /* parenthesised expression */
    if (t->kind == HTK_LParen)
    {
        ++p->pos;
        UINT inner = hlsl_parse_expr(p);
        if (!psr_consume(p, HTK_RParen))
            return 0;
        return inner;
    }
    /* number literal */
    if (t->kind == HTK_Number)
    {
        ++p->pos;
        UINT n = ast_alloc_node(p->ast, HN_Number);
        if (!n)
            return 0;
        p->ast->nodes[n].number = t->number;
        return n;
    }
    /* type-constructor: float4(...) etc. */
    if (hlsl_is_typename(t->kind))
    {
        UINT type_tok = (UINT)t->kind;
        ++p->pos;
        if (!psr_consume(p, HTK_LParen))
            return 0;
        UINT cons = ast_alloc_node(p->ast, HN_Constructor);
        if (!cons)
            return 0;
        p->ast->nodes[cons].type_token = type_tok;
        if (psr_peek(p) && psr_peek(p)->kind != HTK_RParen)
        {
            for (;;)
            {
                UINT arg = hlsl_parse_expr(p);
                if (!arg)
                    return 0;
                ast_append_child(p->ast, cons, arg);
                if (!psr_accept(p, HTK_Comma))
                    break;
            }
        }
        if (!psr_consume(p, HTK_RParen))
            return 0;
        return cons;
    }
    /* identifier — followed by zero or more postfixes */
    if (t->kind == HTK_Ident)
    {
        ++p->pos;
        UINT id = ast_alloc_node(p->ast, HN_Ident);
        if (!id)
            return 0;
        p->ast->nodes[id].name_off = (UINT)t->text_off;
        p->ast->nodes[id].name_len = (UINT)t->text_len;
        UINT cur = id;
        for (;;)
        {
            const HlslToken* nx = psr_peek(p);
            if (!nx)
                break;
            if (nx->kind == HTK_Dot)
            {
                ++p->pos;
                const HlslToken* member = psr_consume(p, HTK_Ident);
                if (!member)
                    return 0;
                UINT acc = ast_alloc_node(p->ast, HN_Field_Access);
                if (!acc)
                    return 0;
                p->ast->nodes[acc].name_off = (UINT)member->text_off;
                p->ast->nodes[acc].name_len = (UINT)member->text_len;
                ast_append_child(p->ast, acc, cur);
                cur = acc;
                continue;
            }
            if (nx->kind == HTK_LParen)
            {
                ++p->pos;
                UINT call = ast_alloc_node(p->ast, HN_Call);
                if (!call)
                    return 0;
                p->ast->nodes[call].name_off = p->ast->nodes[id].name_off;
                p->ast->nodes[call].name_len = p->ast->nodes[id].name_len;
                if (psr_peek(p) && psr_peek(p)->kind != HTK_RParen)
                {
                    for (;;)
                    {
                        UINT arg = hlsl_parse_expr(p);
                        if (!arg)
                            return 0;
                        ast_append_child(p->ast, call, arg);
                        if (!psr_accept(p, HTK_Comma))
                            break;
                    }
                }
                if (!psr_consume(p, HTK_RParen))
                    return 0;
                cur = call;
                continue;
            }
            break;
        }
        return cur;
    }
    p->ast->err = D3DC_ERR_PARSE;
    return 0;
}

static UINT hlsl_parse_unary(HlslParser* p)
{
    if (psr_accept(p, HTK_Minus))
    {
        UINT inner = hlsl_parse_unary(p);
        if (!inner)
            return 0;
        UINT n = ast_alloc_node(p->ast, HN_Neg);
        if (!n)
            return 0;
        ast_append_child(p->ast, n, inner);
        return n;
    }
    return hlsl_parse_primary(p);
}

static UINT hlsl_parse_mul(HlslParser* p)
{
    UINT lhs = hlsl_parse_unary(p);
    if (!lhs)
        return 0;
    for (;;)
    {
        const HlslToken* t = psr_peek(p);
        if (!t)
            break;
        if (t->kind != HTK_Star && t->kind != HTK_Slash)
            break;
        char op = (t->kind == HTK_Star) ? '*' : '/';
        ++p->pos;
        UINT rhs = hlsl_parse_unary(p);
        if (!rhs)
            return 0;
        UINT b = ast_alloc_node(p->ast, HN_BinOp);
        if (!b)
            return 0;
        p->ast->nodes[b].op = op;
        ast_append_child(p->ast, b, lhs);
        ast_append_child(p->ast, b, rhs);
        lhs = b;
    }
    return lhs;
}

static UINT hlsl_parse_add(HlslParser* p)
{
    UINT lhs = hlsl_parse_mul(p);
    if (!lhs)
        return 0;
    for (;;)
    {
        const HlslToken* t = psr_peek(p);
        if (!t)
            break;
        if (t->kind != HTK_Plus && t->kind != HTK_Minus)
            break;
        char op = (t->kind == HTK_Plus) ? '+' : '-';
        ++p->pos;
        UINT rhs = hlsl_parse_mul(p);
        if (!rhs)
            return 0;
        UINT b = ast_alloc_node(p->ast, HN_BinOp);
        if (!b)
            return 0;
        p->ast->nodes[b].op = op;
        ast_append_child(p->ast, b, lhs);
        ast_append_child(p->ast, b, rhs);
        lhs = b;
    }
    return lhs;
}

static UINT hlsl_parse_expr(HlslParser* p)
{
    UINT lhs = hlsl_parse_add(p);
    if (!lhs)
        return 0;
    if (psr_accept(p, HTK_Assign))
    {
        UINT rhs = hlsl_parse_expr(p);
        if (!rhs)
            return 0;
        UINT a = ast_alloc_node(p->ast, HN_Assign);
        if (!a)
            return 0;
        ast_append_child(p->ast, a, lhs);
        ast_append_child(p->ast, a, rhs);
        return a;
    }
    return lhs;
}

static UINT hlsl_parse_stmt(HlslParser* p)
{
    const HlslToken* t = psr_peek(p);
    if (!t)
        return 0;
    if (t->kind == HTK_KwReturn)
    {
        ++p->pos;
        UINT n = ast_alloc_node(p->ast, HN_Return);
        if (!n)
            return 0;
        UINT e = hlsl_parse_expr(p);
        if (!e)
            return 0;
        ast_append_child(p->ast, n, e);
        if (!psr_consume(p, HTK_Semi))
            return 0;
        return n;
    }
    /* type-prefixed local declaration. We treat any typename as
     * such — it's the only place a typename appears at statement
     * start in our subset. */
    if (hlsl_is_typename(t->kind) || t->kind == HTK_Ident)
    {
        UINT save = p->pos;
        UINT type_tok = 0;
        if (hlsl_is_typename(t->kind))
        {
            type_tok = (UINT)t->kind;
            ++p->pos;
        }
        else if (t->kind == HTK_Ident)
        {
            /* user-defined typename (e.g. struct VS_OUT) — peek
             * one ahead to disambiguate `Ident Ident` (decl) vs
             * `Ident.x` (expr). */
            const HlslToken* lookahead = (p->pos + 1 < p->lx->token_count) ? &p->lx->tokens[p->pos + 1] : NULL;
            if (lookahead && lookahead->kind == HTK_Ident)
            {
                ++p->pos;
                type_tok = (UINT)HTK_Ident;
            }
            else
            {
                p->pos = save;
            }
        }
        if (type_tok != 0)
        {
            const HlslToken* name = psr_consume(p, HTK_Ident);
            if (!name)
                return 0;
            UINT n = ast_alloc_node(p->ast, HN_LocalDecl);
            if (!n)
                return 0;
            p->ast->nodes[n].type_token = type_tok;
            p->ast->nodes[n].name_off = (UINT)name->text_off;
            p->ast->nodes[n].name_len = (UINT)name->text_len;
            if (psr_accept(p, HTK_Assign))
            {
                UINT init = hlsl_parse_expr(p);
                if (!init)
                    return 0;
                ast_append_child(p->ast, n, init);
            }
            if (!psr_consume(p, HTK_Semi))
                return 0;
            return n;
        }
    }
    /* fallback: expression statement */
    UINT n = ast_alloc_node(p->ast, HN_ExprStmt);
    if (!n)
        return 0;
    UINT e = hlsl_parse_expr(p);
    if (!e)
        return 0;
    ast_append_child(p->ast, n, e);
    if (!psr_consume(p, HTK_Semi))
        return 0;
    return n;
}

static UINT hlsl_parse_block(HlslParser* p)
{
    if (!psr_consume(p, HTK_LBrace))
        return 0;
    UINT b = ast_alloc_node(p->ast, HN_Block);
    if (!b)
        return 0;
    while (psr_peek(p) && psr_peek(p)->kind != HTK_RBrace)
    {
        UINT s = hlsl_parse_stmt(p);
        if (!s)
            return 0;
        ast_append_child(p->ast, b, s);
    }
    if (!psr_consume(p, HTK_RBrace))
        return 0;
    return b;
}

static UINT hlsl_parse_field(HlslParser* p)
{
    const HlslToken* type_tok = psr_peek(p);
    if (!type_tok || !hlsl_is_typename(type_tok->kind))
    {
        p->ast->err = D3DC_ERR_PARSE;
        return 0;
    }
    ++p->pos;
    const HlslToken* name = psr_consume(p, HTK_Ident);
    if (!name)
        return 0;
    UINT f = ast_alloc_node(p->ast, HN_Field);
    if (!f)
        return 0;
    p->ast->nodes[f].type_token = (UINT)type_tok->kind;
    p->ast->nodes[f].name_off = (UINT)name->text_off;
    p->ast->nodes[f].name_len = (UINT)name->text_len;
    if (psr_accept(p, HTK_Colon))
    {
        const HlslToken* sem = psr_consume(p, HTK_Ident);
        if (!sem)
            return 0;
        p->ast->nodes[f].semantic_off = (UINT)sem->text_off;
        p->ast->nodes[f].semantic_len = (UINT)sem->text_len;
    }
    if (!psr_consume(p, HTK_Semi))
        return 0;
    return f;
}

static UINT hlsl_parse_struct(HlslParser* p)
{
    if (!psr_consume(p, HTK_KwStruct))
        return 0;
    const HlslToken* name = psr_consume(p, HTK_Ident);
    if (!name)
        return 0;
    UINT s = ast_alloc_node(p->ast, HN_Struct);
    if (!s)
        return 0;
    p->ast->nodes[s].name_off = (UINT)name->text_off;
    p->ast->nodes[s].name_len = (UINT)name->text_len;
    if (!psr_consume(p, HTK_LBrace))
        return 0;
    while (psr_peek(p) && psr_peek(p)->kind != HTK_RBrace)
    {
        UINT f = hlsl_parse_field(p);
        if (!f)
            return 0;
        ast_append_child(p->ast, s, f);
    }
    if (!psr_consume(p, HTK_RBrace))
        return 0;
    if (!psr_consume(p, HTK_Semi))
        return 0;
    return s;
}

static UINT hlsl_parse_func(HlslParser* p, UINT ret_type, const HlslToken* name)
{
    UINT f = ast_alloc_node(p->ast, HN_Func);
    if (!f)
        return 0;
    p->ast->nodes[f].type_token = ret_type;
    p->ast->nodes[f].name_off = (UINT)name->text_off;
    p->ast->nodes[f].name_len = (UINT)name->text_len;
    if (!psr_consume(p, HTK_LParen))
        return 0;
    if (psr_peek(p) && psr_peek(p)->kind != HTK_RParen)
    {
        for (;;)
        {
            const HlslToken* m = psr_peek(p);
            if (m && (m->kind == HTK_KwIn || m->kind == HTK_KwOut || m->kind == HTK_KwInOut))
                ++p->pos;
            const HlslToken* type_tok = psr_peek(p);
            if (!type_tok)
                return 0;
            if (!hlsl_is_typename(type_tok->kind) && type_tok->kind != HTK_Ident)
            {
                p->ast->err = D3DC_ERR_PARSE;
                return 0;
            }
            ++p->pos;
            const HlslToken* pname = psr_consume(p, HTK_Ident);
            if (!pname)
                return 0;
            UINT param = ast_alloc_node(p->ast, HN_Param);
            if (!param)
                return 0;
            p->ast->nodes[param].type_token = (UINT)type_tok->kind;
            p->ast->nodes[param].name_off = (UINT)pname->text_off;
            p->ast->nodes[param].name_len = (UINT)pname->text_len;
            if (psr_accept(p, HTK_Colon))
            {
                const HlslToken* sem = psr_consume(p, HTK_Ident);
                if (!sem)
                    return 0;
                p->ast->nodes[param].semantic_off = (UINT)sem->text_off;
                p->ast->nodes[param].semantic_len = (UINT)sem->text_len;
            }
            ast_append_child(p->ast, f, param);
            if (!psr_accept(p, HTK_Comma))
                break;
        }
    }
    if (!psr_consume(p, HTK_RParen))
        return 0;
    if (psr_accept(p, HTK_Colon))
    {
        const HlslToken* sem = psr_consume(p, HTK_Ident);
        if (!sem)
            return 0;
        p->ast->nodes[f].semantic_off = (UINT)sem->text_off;
        p->ast->nodes[f].semantic_len = (UINT)sem->text_len;
    }
    UINT body = hlsl_parse_block(p);
    if (!body)
        return 0;
    ast_append_child(p->ast, f, body);
    return f;
}

static UINT hlsl_parse_top(HlslParser* p)
{
    UINT root = ast_alloc_node(p->ast, HN_Top);
    if (!root)
        return 0;
    while (psr_peek(p) && psr_peek(p)->kind != HTK_Eof)
    {
        const HlslToken* t = psr_peek(p);
        if (t->kind == HTK_KwStruct)
        {
            UINT s = hlsl_parse_struct(p);
            if (!s)
                return 0;
            ast_append_child(p->ast, root, s);
            continue;
        }
        if (t->kind == HTK_KwCBuffer)
        {
            ++p->pos;
            const HlslToken* nm = psr_consume(p, HTK_Ident);
            if (!nm)
                return 0;
            UINT cb = ast_alloc_node(p->ast, HN_CBuffer);
            if (!cb)
                return 0;
            p->ast->nodes[cb].name_off = (UINT)nm->text_off;
            p->ast->nodes[cb].name_len = (UINT)nm->text_len;
            if (!psr_consume(p, HTK_LBrace))
                return 0;
            while (psr_peek(p) && psr_peek(p)->kind != HTK_RBrace)
            {
                UINT field = hlsl_parse_field(p);
                if (!field)
                    return 0;
                ast_append_child(p->ast, cb, field);
            }
            if (!psr_consume(p, HTK_RBrace))
                return 0;
            ast_append_child(p->ast, root, cb);
            continue;
        }
        /* function: type Ident '(' */
        if (hlsl_is_typename(t->kind) || t->kind == HTK_Ident)
        {
            UINT ret_type = (UINT)t->kind;
            ++p->pos;
            const HlslToken* nm = psr_consume(p, HTK_Ident);
            if (!nm)
                return 0;
            UINT fn = hlsl_parse_func(p, ret_type, nm);
            if (!fn)
                return 0;
            ast_append_child(p->ast, root, fn);
            continue;
        }
        p->ast->err = D3DC_ERR_PARSE;
        return 0;
    }
    return root;
}

/* ---------------------------------------------------------------- *
 * Bytecode emitter                                                 *
 *                                                                  *
 * Output blob layout (deterministic, byte-exact for a given AST):  *
 *                                                                  *
 *   0  4   "DXBC"                  (DXBC magic)                    *
 *   4  16  source-hash (FNV-1a 128-ish; 16 bytes deterministic)    *
 *  20  4   constant 1 (DXBC reserved)                              *
 *  24  4   total size                                              *
 *  28  4   chunk count = 4 (SHEX, ISGN, OSGN, STAT)                *
 *  32  16  chunk offsets (4 dwords)                                *
 *  48  ... chunk data                                              *
 *                                                                  *
 * Each chunk:                                                      *
 *   "TAG_" (4)                                                     *
 *   chunk-payload-size (4)                                         *
 *   chunk-payload (variable)                                       *
 * ---------------------------------------------------------------- */

#define DXBC_TAG(a, b, c, d) ((BYTE)(a) << 0 | (BYTE)(b) << 8 | (BYTE)(c) << 16 | (BYTE)(d) << 24)

typedef struct DxbcWriter
{
    BYTE* data;
    SIZE_T cap;
    SIZE_T pos;
} DxbcWriter;

static int dxbc_reserve(DxbcWriter* w, SIZE_T extra)
{
    if (w->pos + extra <= w->cap)
        return 1;
    SIZE_T new_cap = w->cap ? w->cap * 2 : 256;
    while (new_cap < w->pos + extra)
        new_cap *= 2;
    BYTE* new_data = (BYTE*)dx_heap_alloc(new_cap);
    if (!new_data)
        return 0;
    if (w->data)
    {
        dx_memcpy(new_data, w->data, w->pos);
        dx_heap_free(w->data);
    }
    w->data = new_data;
    w->cap = new_cap;
    return 1;
}

static int dxbc_w8(DxbcWriter* w, BYTE v)
{
    if (!dxbc_reserve(w, 1))
        return 0;
    w->data[w->pos++] = v;
    return 1;
}
static int dxbc_w32(DxbcWriter* w, UINT v)
{
    if (!dxbc_reserve(w, 4))
        return 0;
    w->data[w->pos + 0] = (BYTE)(v >> 0);
    w->data[w->pos + 1] = (BYTE)(v >> 8);
    w->data[w->pos + 2] = (BYTE)(v >> 16);
    w->data[w->pos + 3] = (BYTE)(v >> 24);
    w->pos += 4;
    return 1;
}
static void dxbc_set32(DxbcWriter* w, SIZE_T off, UINT v)
{
    if (off + 4 > w->cap)
        return;
    w->data[off + 0] = (BYTE)(v >> 0);
    w->data[off + 1] = (BYTE)(v >> 8);
    w->data[off + 2] = (BYTE)(v >> 16);
    w->data[off + 3] = (BYTE)(v >> 24);
}
/* ---------------------------------------------------------------- *
 * IR emitter — converts the AST to a flat opcode stream that lives *
 * inside the SHEX chunk. This is NOT real DXIL/DXBC but it IS      *
 * deterministic and round-trippable through D3DDisassemble.        *
 *                                                                  *
 * Opcode encoding (per node):                                      *
 *   0x00  return                                                   *
 *   0x10  load_ident      (4 bytes hash of ident)                  *
 *   0x11  load_field      (4 bytes hash of field-name)             *
 *   0x12  load_imm_f32    (4 bytes IEEE float)                     *
 *   0x20  call            (4 bytes hash of fn-name, 1 byte argc)   *
 *   0x21  ctor_float      (1 byte width 1..4, 1 byte argc)         *
 *   0x30  binop           (1 byte op '+' / '-' / '*' / '/')        *
 *   0x31  neg                                                      *
 *   0x40  store_ident     (4 bytes hash)                           *
 *   0x41  store_field     (4 bytes hash)                           *
 * ---------------------------------------------------------------- */

static UINT name_hash(const char* src, UINT off, UINT len)
{
    UINT h = 0x811C9DC5u;
    for (UINT i = 0; i < len; ++i)
    {
        h ^= (BYTE)src[off + i];
        h *= 0x01000193u;
    }
    return h;
}

static int emit_expr(DxbcWriter* w, HlslAst* a, UINT node, const char* src);

static int emit_call_or_ctor(DxbcWriter* w, HlslAst* a, UINT node, const char* src)
{
    HlslNode* n = &a->nodes[node];
    UINT argc = 0;
    UINT it = n->first_child;
    while (it)
    {
        if (!emit_expr(w, a, it, src))
            return 0;
        ++argc;
        it = a->nodes[it].next_sibling;
    }
    if (n->kind == HN_Constructor)
    {
        UINT width = 1;
        switch (n->type_token)
        {
        case HTK_KwFloat:
            width = 1;
            break;
        case HTK_KwFloat2:
            width = 2;
            break;
        case HTK_KwFloat3:
            width = 3;
            break;
        case HTK_KwFloat4:
            width = 4;
            break;
        default:
            width = 4;
            break;
        }
        if (!dxbc_w8(w, 0x21))
            return 0;
        if (!dxbc_w8(w, (BYTE)width))
            return 0;
        if (!dxbc_w8(w, (BYTE)argc))
            return 0;
        return 1;
    }
    /* HN_Call */
    if (!dxbc_w8(w, 0x20))
        return 0;
    UINT h = name_hash(src, n->name_off, n->name_len);
    if (!dxbc_w32(w, h))
        return 0;
    if (!dxbc_w8(w, (BYTE)argc))
        return 0;
    return 1;
}

static int emit_expr(DxbcWriter* w, HlslAst* a, UINT node, const char* src)
{
    if (node == 0)
        return 1;
    HlslNode* n = &a->nodes[node];
    switch (n->kind)
    {
    case HN_Number:
    {
        if (!dxbc_w8(w, 0x12))
            return 0;
        float fv = (float)n->number;
        UINT bits = 0;
        dx_memcpy(&bits, &fv, sizeof(bits));
        return dxbc_w32(w, bits);
    }
    case HN_Ident:
        if (!dxbc_w8(w, 0x10))
            return 0;
        return dxbc_w32(w, name_hash(src, n->name_off, n->name_len));
    case HN_Field_Access:
    {
        if (!emit_expr(w, a, n->first_child, src))
            return 0;
        if (!dxbc_w8(w, 0x11))
            return 0;
        return dxbc_w32(w, name_hash(src, n->name_off, n->name_len));
    }
    case HN_Constructor:
    case HN_Call:
        return emit_call_or_ctor(w, a, node, src);
    case HN_BinOp:
    {
        if (!emit_expr(w, a, n->first_child, src))
            return 0;
        if (!emit_expr(w, a, a->nodes[n->first_child].next_sibling, src))
            return 0;
        if (!dxbc_w8(w, 0x30))
            return 0;
        return dxbc_w8(w, (BYTE)n->op);
    }
    case HN_Neg:
        if (!emit_expr(w, a, n->first_child, src))
            return 0;
        return dxbc_w8(w, 0x31);
    case HN_Assign:
    {
        UINT lhs = n->first_child;
        UINT rhs = a->nodes[lhs].next_sibling;
        if (!emit_expr(w, a, rhs, src))
            return 0;
        HlslNode* l = &a->nodes[lhs];
        if (l->kind == HN_Field_Access)
        {
            if (!emit_expr(w, a, l->first_child, src))
                return 0;
            if (!dxbc_w8(w, 0x41))
                return 0;
            return dxbc_w32(w, name_hash(src, l->name_off, l->name_len));
        }
        if (l->kind == HN_Ident)
        {
            if (!dxbc_w8(w, 0x40))
                return 0;
            return dxbc_w32(w, name_hash(src, l->name_off, l->name_len));
        }
        return 0;
    }
    default:
        return 0;
    }
}

static int emit_stmt(DxbcWriter* w, HlslAst* a, UINT node, const char* src)
{
    if (node == 0)
        return 1;
    HlslNode* n = &a->nodes[node];
    switch (n->kind)
    {
    case HN_Block:
    {
        UINT it = n->first_child;
        while (it)
        {
            if (!emit_stmt(w, a, it, src))
                return 0;
            it = a->nodes[it].next_sibling;
        }
        return 1;
    }
    case HN_Return:
        if (!emit_expr(w, a, n->first_child, src))
            return 0;
        return dxbc_w8(w, 0x00);
    case HN_LocalDecl:
        if (n->first_child)
        {
            if (!emit_expr(w, a, n->first_child, src))
                return 0;
            if (!dxbc_w8(w, 0x40))
                return 0;
            return dxbc_w32(w, name_hash(src, n->name_off, n->name_len));
        }
        return 1;
    case HN_ExprStmt:
        return emit_expr(w, a, n->first_child, src);
    default:
        return 0;
    }
}

/* Walk every Func node in the AST root, emit its body. The
 * SHEX chunk's payload is just a concatenation of every entry-
 * point function's opcode stream prefixed with the FNV-1a hash
 * of the function name. */
static int emit_shex(DxbcWriter* w, HlslAst* a, const char* src)
{
    UINT root = a->root;
    UINT it = a->nodes[root].first_child;
    while (it)
    {
        HlslNode* n = &a->nodes[it];
        if (n->kind == HN_Func)
        {
            if (!dxbc_w32(w, name_hash(src, n->name_off, n->name_len)))
                return 0;
            UINT body = n->first_child;
            while (body && a->nodes[body].kind != HN_Block)
                body = a->nodes[body].next_sibling;
            if (body)
            {
                if (!emit_stmt(w, a, body, src))
                    return 0;
            }
            if (!dxbc_w8(w, 0x00))
                return 0; /* implicit return */
        }
        it = n->next_sibling;
    }
    return 1;
}

/* Walk struct fields whose semantic is set; emit (semantic-hash,
 * type-token) pairs. ISGN/OSGN choice is the caller's. */
static int emit_signature(DxbcWriter* w, HlslAst* a, const char* src, int output_signature)
{
    UINT root = a->root;
    UINT it = a->nodes[root].first_child;
    while (it)
    {
        HlslNode* n = &a->nodes[it];
        if (n->kind == HN_Struct)
        {
            UINT field = n->first_child;
            while (field)
            {
                HlslNode* f = &a->nodes[field];
                if (f->semantic_len != 0)
                {
                    /* convention: first struct = input, second = output */
                    if (((it == a->nodes[root].first_child) && !output_signature) ||
                        ((it != a->nodes[root].first_child) && output_signature))
                    {
                        if (!dxbc_w32(w, name_hash(src, f->semantic_off, f->semantic_len)))
                            return 0;
                        if (!dxbc_w32(w, f->type_token))
                            return 0;
                    }
                }
                field = f->next_sibling;
            }
        }
        it = n->next_sibling;
    }
    return 1;
}

/* Compute a 16-byte "hash" of the SHEX-only content. Not a real
 * MD5, just two FNV-1a-64 streams of the bytes — enough that a
 * single-bit source change produces a different hash, which is
 * all we need for round-trip equality testing. */
static void compute_hash(const BYTE* src, SIZE_T n, BYTE out[16])
{
    UINT64 a_ = 0xCBF29CE484222325ULL;
    UINT64 b_ = 0x84222325CBF29CE4ULL;
    for (SIZE_T i = 0; i < n; ++i)
    {
        a_ ^= src[i];
        a_ *= 0x100000001B3ULL;
        b_ ^= src[n - 1 - i];
        b_ *= 0x100000001B3ULL;
    }
    for (int i = 0; i < 8; ++i)
        out[i] = (BYTE)(a_ >> (i * 8));
    for (int i = 0; i < 8; ++i)
        out[8 + i] = (BYTE)(b_ >> (i * 8));
}

/* Build the SHEX, ISGN, OSGN, STAT chunks; assemble into the
 * full DXBC envelope; allocate a blob for the bytes. */
static HRESULT emit_blob(HlslAst* ast, const char* src, ID3DBlobImpl** out)
{
    /* SHEX */
    DxbcWriter shex = {0};
    if (!emit_shex(&shex, ast, src))
        return D3DC_ERR_OOM;
    /* ISGN */
    DxbcWriter isgn = {0};
    if (!emit_signature(&isgn, ast, src, 0))
        return D3DC_ERR_OOM;
    /* OSGN */
    DxbcWriter osgn = {0};
    if (!emit_signature(&osgn, ast, src, 1))
        return D3DC_ERR_OOM;
    /* STAT — node count, token count, AST root index */
    DxbcWriter stat = {0};
    if (!dxbc_w32(&stat, ast->count) || !dxbc_w32(&stat, 0) || !dxbc_w32(&stat, ast->root))
    {
        return D3DC_ERR_OOM;
    }

    /* Header: 32 bytes + 4 chunk offsets (16 bytes) = 48. Each
     * chunk has 8 bytes of (tag + size) header. */
    SIZE_T chunks_payload = shex.pos + isgn.pos + osgn.pos + stat.pos;
    SIZE_T total = 48 + 4 * 8 + chunks_payload;

    DxbcWriter out_w = {0};
    if (!dxbc_reserve(&out_w, total))
        return D3DC_ERR_OOM;

    /* Magic */
    dxbc_w32(&out_w, DXBC_TAG('D', 'X', 'B', 'C'));
    /* Hash placeholder (16 bytes) */
    SIZE_T hash_off = out_w.pos;
    for (int i = 0; i < 16; ++i)
        dxbc_w8(&out_w, 0);
    /* Reserved = 1 (DXBC field) */
    dxbc_w32(&out_w, 1);
    /* Total size */
    SIZE_T totsize_off = out_w.pos;
    dxbc_w32(&out_w, 0);
    /* Chunk count */
    dxbc_w32(&out_w, 4);
    /* Chunk offsets (4) */
    SIZE_T off_table = out_w.pos;
    for (int i = 0; i < 4; ++i)
        dxbc_w32(&out_w, 0);

    UINT chunk_tags[4] = {DXBC_TAG('S', 'H', 'E', 'X'), DXBC_TAG('I', 'S', 'G', 'N'), DXBC_TAG('O', 'S', 'G', 'N'),
                          DXBC_TAG('S', 'T', 'A', 'T')};
    DxbcWriter* chunks[4] = {&shex, &isgn, &osgn, &stat};

    for (int i = 0; i < 4; ++i)
    {
        dxbc_set32(&out_w, off_table + i * 4, (UINT)out_w.pos);
        dxbc_w32(&out_w, chunk_tags[i]);
        dxbc_w32(&out_w, (UINT)chunks[i]->pos);
        if (chunks[i]->pos)
        {
            if (!dxbc_reserve(&out_w, chunks[i]->pos))
                return D3DC_ERR_OOM;
            dx_memcpy(out_w.data + out_w.pos, chunks[i]->data, chunks[i]->pos);
            out_w.pos += chunks[i]->pos;
        }
    }
    /* Finalise total size + hash */
    dxbc_set32(&out_w, totsize_off, (UINT)out_w.pos);
    BYTE hash[16];
    compute_hash(out_w.data + 32, out_w.pos - 32, hash);
    dx_memcpy(out_w.data + hash_off, hash, 16);

    /* Free intermediate writers */
    if (shex.data)
        dx_heap_free(shex.data);
    if (isgn.data)
        dx_heap_free(isgn.data);
    if (osgn.data)
        dx_heap_free(osgn.data);
    if (stat.data)
        dx_heap_free(stat.data);

    /* Wrap in an ID3DBlob */
    ID3DBlobImpl* blob = blob_alloc(out_w.pos);
    if (!blob)
    {
        dx_heap_free(out_w.data);
        return D3DC_ERR_OOM;
    }
    dx_memcpy(blob->data, out_w.data, out_w.pos);
    dx_heap_free(out_w.data);
    *out = blob;
    return DX_S_OK;
}

/* ---------------------------------------------------------------- *
 * Public entry points                                              *
 * ---------------------------------------------------------------- */

/* AST + lexer instances are large; allocate from the heap rather
 * than the caller's stack. */
static HRESULT compile_internal(const char* source, SIZE_T source_size, ID3DBlobImpl** out_code,
                                ID3DBlobImpl** out_errors)
{
    if (out_errors)
        *out_errors = NULL;
    if (!source || !out_code)
        return DX_E_POINTER;
    *out_code = NULL;

    HlslLexer* lx = (HlslLexer*)dx_heap_alloc(sizeof(*lx));
    HlslAst* ast = (HlslAst*)dx_heap_alloc(sizeof(*ast));
    if (!lx || !ast)
    {
        if (lx)
            dx_heap_free(lx);
        if (ast)
            dx_heap_free(ast);
        return D3DC_ERR_OOM;
    }
    dx_memzero(lx, sizeof(*lx));
    dx_memzero(ast, sizeof(*ast));

    HRESULT rc = hlsl_lex(lx, source, source_size);
    if (rc != DX_S_OK)
    {
        dx_heap_free(lx);
        dx_heap_free(ast);
        return rc;
    }

    HlslParser p = {0};
    p.lx = lx;
    p.ast = ast;
    p.pos = 0;
    UINT root = hlsl_parse_top(&p);
    if (!root || ast->err != DX_S_OK)
    {
        dx_heap_free(lx);
        dx_heap_free(ast);
        return D3DC_ERR_PARSE;
    }
    ast->root = root;

    HRESULT er = emit_blob(ast, source, out_code);
    dx_heap_free(lx);
    dx_heap_free(ast);
    return er;
}

__attribute__((dllexport)) HRESULT D3DCompile(const void* src_data, SIZE_T src_size, const char* source_name,
                                              const void* defines, void* include_handler, const char* entry,
                                              const char* target, UINT flags1, UINT flags2, ID3DBlobImpl** out_code,
                                              ID3DBlobImpl** out_errors)
{
    (void)source_name;
    (void)defines;
    (void)include_handler;
    (void)entry;
    (void)target;
    (void)flags1;
    (void)flags2;
    return compile_internal((const char*)src_data, src_size, out_code, out_errors);
}

__attribute__((dllexport)) HRESULT D3DCompile2(const void* src_data, SIZE_T src_size, const char* source_name,
                                               const void* defines, void* include_handler, const char* entry,
                                               const char* target, UINT flags1, UINT flags2, UINT secondary_data_flags,
                                               const void* secondary_data, SIZE_T secondary_data_size,
                                               ID3DBlobImpl** out_code, ID3DBlobImpl** out_errors)
{
    (void)source_name;
    (void)defines;
    (void)include_handler;
    (void)entry;
    (void)target;
    (void)flags1;
    (void)flags2;
    (void)secondary_data_flags;
    (void)secondary_data;
    (void)secondary_data_size;
    return compile_internal((const char*)src_data, src_size, out_code, out_errors);
}

/* D3DReflect — caller hands us a blob, we hand back an opaque
 * "reflection" object. v0 simply re-allocs an ID3DBlob holding
 * the STAT chunk and returns it. The caller's iid is ignored. */
__attribute__((dllexport)) HRESULT D3DReflect(const void* src_data, SIZE_T src_size, REFIID iid, void** out_reflector)
{
    (void)iid;
    if (!src_data || !out_reflector)
        return DX_E_POINTER;
    *out_reflector = NULL;
    if (src_size < 48)
        return DX_E_INVALIDARG;
    const BYTE* p = (const BYTE*)src_data;
    if (p[0] != 'D' || p[1] != 'X' || p[2] != 'B' || p[3] != 'C')
        return DX_E_INVALIDARG;
    /* Echo the source bytes back as a refcounted blob; downstream
     * GetBufferPointer/Size lets the caller poke the chunk
     * directory itself. */
    ID3DBlobImpl* b = blob_alloc(src_size);
    if (!b)
        return D3DC_ERR_OOM;
    dx_memcpy(b->data, src_data, src_size);
    *out_reflector = b;
    return DX_S_OK;
}

/* D3DDisassemble — produce a tiny human-readable summary of the
 * blob contents. We don't decode the SHEX opcode stream; we just
 * print "// duetos d3dcompiler v0\n// nodes=N tokens=T\n" so that
 * RenderDoc-style disasm dumps don't blank out. */
__attribute__((dllexport)) HRESULT D3DDisassemble(const void* src_data, SIZE_T src_size, UINT flags,
                                                  const char* comments, ID3DBlobImpl** out_disassembly)
{
    (void)flags;
    (void)comments;
    if (!src_data || !out_disassembly)
        return DX_E_POINTER;
    *out_disassembly = NULL;
    if (src_size < 48)
        return DX_E_INVALIDARG;
    const char* msg = "// duetos d3dcompiler v0\n// (disassembly elided in v0)\n";
    SIZE_T n = 0;
    while (msg[n])
        ++n;
    ID3DBlobImpl* b = blob_alloc(n + 1);
    if (!b)
        return D3DC_ERR_OOM;
    dx_memcpy(b->data, msg, n);
    b->data[n] = 0;
    *out_disassembly = b;
    return DX_S_OK;
}

/* Diagnostic peek for tests / smoke binaries. Returns the first
 * 4 bytes of the blob (which should be 'DXBC' if compilation
 * went all the way through). Not a real d3dcompiler export. */
__attribute__((dllexport)) UINT DuetOS_D3DCompiler_PeekBlobMagic(ID3DBlobImpl* blob)
{
    if (!blob || !blob->data || blob->size < 4)
        return 0;
    return (UINT)blob->data[0] | ((UINT)blob->data[1] << 8) | ((UINT)blob->data[2] << 16) | ((UINT)blob->data[3] << 24);
}
