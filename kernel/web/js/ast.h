#pragma once

#include "util/types.h"
#include "web/js/value.h"

/*
 * DuetOS — kernel/web/js: AST node model + parser entry point.
 *
 * One tagged AstNode struct covers every node kind (a discriminated
 * union over child pointers). Nodes are arena-allocated; children are
 * pointers into the same arena. The tree-walking interpreter
 * (interp.cpp) consumes it directly.
 */

namespace duetos::web::js
{

class Arena;

enum class Ast : u8
{
    // expressions
    NumberLit,
    StringLit,
    RegexLit, // /pattern/flags — str/strLen = pattern, reFlags/reFlagsLen = flags
    BoolLit,
    NullLit,
    UndefinedLit,
    Ident,
    ArrayLit,  // a[] = children list
    ObjectLit, // keys[] / children[] pairs
    Unary,     // op + operand   (+ - ! typeof)
    Update,    // ++ / -- : a=lvalue operand, op=Add/Sub, boolVal=prefix?
    Binary,    // op + lhs + rhs (arith/compare/equality)
    Logical,   // && ||  (short-circuit)
    Assign,    // op + target(lhs) + value(rhs)
    Ternary,   // cond ? a : b
    Member,    // obj.prop          (lhs=obj, name=prop)
    Index,     // obj[expr]         (lhs=obj, rhs=expr)
    Template,  // `a${x}b`: keys[]=cooked chunks, kids[]=interp exprs
               //   (kidCount interps, kidCount+1 chunks)
    Call,      // callee + args[]
    Function,  // function expr/decl: params[] + body block
    Arrow,     // arrow: params[] + body (block OR expression)

    // statements
    VarDecl,  // kind (var/let/const) + name + init(optional)
    ExprStmt, // expression statement
    Block,    // children[] = statements
    If,       // cond + thenS + elseS(optional)
    While,    // cond + body
    For,      // init + cond + update + body
    Return,   // arg(optional)
    Break,
    Continue,
    Program, // top-level: children[] = statements
};

// Operator tag shared by Unary/Binary/Logical/Assign.
enum class Op : u8
{
    None,
    // unary
    Pos,
    Neg,
    NotOp,
    Typeof,
    // binary arith
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    // compare
    Lt,
    Gt,
    Le,
    Ge,
    // equality
    EqEq,
    NotEq,
    StrictEq,
    StrictNotEq,
    // logical
    And,
    Or,
    // assign flavours
    AssignPlain,
    AssignAdd,
    AssignSub,
    AssignMul,
    AssignDiv,
    AssignMod,
};

struct AstNode
{
    Ast kind;
    Op op;
    u32 line;

    // literal payloads
    bool numIsInt;
    i64 numI;
    Sf32 numF;
    bool boolVal;
    const char* str; // ident name / string-lit value / object key text / regex pattern
    u32 strLen;

    // RegexLit: the trailing flag characters (g/i/m).
    const char* reFlags;
    u32 reFlagsLen;

    // child links (reused per node kind — see comments above)
    AstNode* a; // lhs / cond / callee / obj / operand / init / target
    AstNode* b; // rhs / then / value / index-expr / update
    AstNode* c; // else / for-cond
    AstNode* d; // for-body

    // variadic children (statements, args, array elems, params)
    AstNode** kids;
    u32 kidCount;

    // object literal: parallel key arrays alongside kids[] = values
    const char** keys;
    u32* keyLens;

    // VarDecl flavour: 0 var, 1 let, 2 const
    u8 declKind;
};

// Parse a token stream into a Program node. On error, returns nullptr
// and fills *errMsg/*errLine.
struct ParseResult
{
    AstNode* program;
    bool ok;
    const char* errMsg;
    u32 errLine;
};

ParseResult Parse(const struct TokenStream& toks, Arena& arena);

} // namespace duetos::web::js
