#pragma once

#include "util/types.h"

/*
 * DuetOS — kernel/web/js: lexer / tokenizer.
 *
 * Hand-written scanner producing a flat token stream the Pratt parser
 * consumes. Handles:
 *   - numbers: decimal int/float (1, 3.14, .5, 1e3), hex (0xFF)
 *   - strings: single/double quoted with \n \t \r \\ \' \" \0 \xHH
 *   - identifiers + keywords
 *   - operators / punctuation (full set the parser needs)
 *   - // line and /-* block comments *-/
 *   - ASI-lite: each token records whether a newline preceded it, so
 *     the parser can insert semicolons at statement boundaries.
 *
 * Template literals (backtick) are supported: `text${expr}more` lexes
 * into TemplateStr / TemplateExprStart / TemplateExprEnd pieces the
 * parser folds into a string-concat tree. GAP: tagged templates and
 * raw-string (String.raw) access are not supported.
 * GAP: full Unicode identifiers — ASCII + `_`/`$` only.
 * Regex literals (`/pattern/flags`) ARE lexed: a `/` starts a regex only
 * where an expression is expected (statement start, or after `(` `,` `=`
 * `:` `[` `{` `;` `return` `typeof`, an operator, etc.) — NOT after an
 * identifier / number / `)` / `]`, where `/` is the division operator.
 * GAP: full ASI restartable-production rules — we only insert before
 *      `}` , at EOF, and after a newline when the next token can't
 *      continue the current expression (a pragmatic subset).
 */

namespace duetos::web::js
{

enum class Tok : u8
{
    Eof = 0,
    Error,

    Number,
    String,
    Ident,
    Regex, // /pattern/flags — strData/strLen = pattern, reFlags/reFlagsLen = flags

    // Template-literal pieces. A `…${…}…` literal lexes to:
    //   TemplateStr (head, cooked) [ TemplateExprStart <expr tokens>
    //   TemplateExprEnd TemplateStr (middle/tail, cooked) ]*
    // The parser folds the chunks + interpolations into a string-concat
    // tree. A plain `…` (no interpolation) is a single TemplateStr.
    TemplateStr,       // cooked literal chunk (strData/strLen)
    TemplateExprStart, // begins a ${ … } interpolation
    TemplateExprEnd,   // ends a ${ … } interpolation

    // keywords
    KwVar,
    KwLet,
    KwConst,
    KwFunction,
    KwReturn,
    KwIf,
    KwElse,
    KwWhile,
    KwFor,
    KwBreak,
    KwContinue,
    KwTrue,
    KwFalse,
    KwNull,
    KwUndefined,
    KwTypeof,
    KwIn,
    KwNew, // `new Ctor(args)` — native ctors (Date); see ParseUnary

    // punctuation / operators
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semicolon,
    Colon,
    Dot,
    Question, // ?
    Arrow,    // =>

    Assign,    // =
    PlusEq,    // +=
    MinusEq,   // -=
    StarEq,    // *=
    SlashEq,   // /=
    PercentEq, // %=

    Plus,
    Minus,
    Star,
    Slash,
    Percent,

    PlusPlus,   // ++
    MinusMinus, // --

    EqEq,    // ==
    NotEq,   // !=
    EqEqEq,  // ===
    NotEqEq, // !==
    Lt,
    Gt,
    LtEq,
    GtEq,

    AndAnd, // &&
    OrOr,   // ||
    Not,    // !
};

struct Token
{
    Tok kind;
    // Source slice [start, start+len) — for idents/strings/numbers the
    // raw text; strings carry the DECODED value separately below.
    const char* start;
    u32 len;
    u32 line;
    bool newlineBefore; // for ASI

    // For Number: pre-parsed payload (lexer does the numeric parse).
    bool numIsInt;
    i64 numI;
    // fractional numbers carry the decoded text; the parser converts
    // through the soft-float path. We keep the raw slice in start/len.

    // For String: decoded (unescaped) text lives in `start`/`len` is
    // re-pointed to the arena copy; see Lexer.
    // For Regex: strData/strLen carry the raw pattern body (between the
    // delimiting slashes), reFlags/reFlagsLen the trailing flag chars.
    const char* strData;
    u32 strLen;

    const char* reFlags; // Regex: flag characters (g/i/m), arena-owned
    u32 reFlagsLen;
};

// Tokenize the whole source up-front into an arena-backed array. The
// parser then walks `tokens[0..count)`. Returns false (and sets an
// error token) on a lexical error; the parser surfaces it.
class Arena;

struct TokenStream
{
    Token* tokens;
    u32 count;
    bool ok;
    const char* errMsg;
    u32 errLine;
};

TokenStream Lex(const char* src, u32 len, Arena& arena);

} // namespace duetos::web::js
