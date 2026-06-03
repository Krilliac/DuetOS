#pragma once

#include "util/result.h"
#include "util/types.h"
#include "web/js/arena.h"

/*
 * DuetOS — kernel/web/js: a bounded, SAFE regular-expression engine.
 *
 * Real-page scripts use regexes constantly, but a naive recursive
 * backtracking matcher is a kernel-security hazard: the interpreter runs
 * on the kernel's 64 KiB stack and a hostile page could craft a pattern
 * (e.g. `(a+)+$`) that drives unbounded C++ recursion and smashes the
 * guard page. So this engine is bounded BY CONSTRUCTION:
 *
 *   1. The pattern is COMPILED to a flat bytecode program (no AST, no
 *      tree-walk at match time). Compilation is bounded: the program-
 *      instruction count is capped (kMaxProgram) and a pattern that
 *      would exceed it fails to compile.
 *   2. Matching runs a bytecode VM with an EXPLICIT, arena-allocated
 *      backtracking stack (kMaxBacktrack frames) — NOT C++ recursion.
 *      The VM is a single non-recursive loop; no matcher frame nests a
 *      native call. Stack overflow is therefore impossible.
 *   3. Every VM step decrements a step budget (seeded from the
 *      interpreter's remaining budget). Catastrophic backtracking
 *      exhausts the budget and the match returns "no match" instead of
 *      hanging the boot.
 *   4. The scanned input length is capped (kMaxInput).
 *
 * SUBSET implemented (deliberately NOT full ES regex):
 *   literals; char classes `[...]` / negated `[^...]`; `.`; quantifiers
 *   `*` `+` `?` `{n}` `{n,}` `{n,m}` (greedy and lazy `?`-suffixed);
 *   anchors `^` `$`; word-boundary `\b` / `\B`; escapes `\d \D \w \W
 *   \s \S` and literal escapes (`\.` `\/` `\n` `\t` …); alternation `|`;
 *   capturing groups `(...)` and non-capturing `(?:...)`. Flags: `g`
 *   (global), `i` (case-insensitive ASCII), `m` (multiline `^`/`$`).
 *
 * GAP: lookahead/lookbehind, backreferences, named groups, the `s`
 *      (dotAll), `u` (unicode), `y` (sticky) flags, and `{` as a literal
 *      when not a valid quantifier are all unsupported. Matching is
 *      byte-oriented (ASCII) — no UTF-16/Unicode awareness. `i` folds
 *      ASCII A-Z/a-z only.
 *
 * Context: kernel, single-threaded per eval. All allocation is arena.
 */

namespace duetos::web::js
{

using duetos::core::ErrorCode;
using duetos::core::Result;

// ---- bounds (all enforced; a pattern/input past a bound is rejected) ----
//
// kReMaxBacktrack * sizeof(ReThread) is allocated from the eval arena per
// match attempt, so these are sized to stay well within the default
// 512 KiB engine arena: a ReThread is 8 + 2*kReMaxGroups*4 bytes, so at
// kReMaxGroups=16 / kReMaxBacktrack=512 the stack is ~70 KiB. A pattern
// needing more live forks than the cap degrades to a possible missed
// match (safety valve), never a hang or an over-allocation.
inline constexpr u32 kReMaxProgram = 2048;        // compiled instruction cap
inline constexpr u32 kReMaxClasses = 256;         // distinct char-class tables
inline constexpr u32 kReMaxBacktrack = 512;       // explicit backtrack frames
inline constexpr u32 kReMaxGroups = 16;           // capturing groups (incl. group 0)
inline constexpr u32 kReMaxInput = 1u << 20;      // 1 MiB scanned-input cap
inline constexpr u64 kReDefaultSteps = 2'000'000; // VM step budget per match

// Bytecode opcodes for the matcher VM. The program is a flat array of
// ReInst; control flow is by absolute instruction index.
enum class ReOp : u8
{
    Char,           // match one specific byte (arg.ch), advance
    Any,            // match any byte except '\n', advance
    Class,          // match a byte against class table [arg.classIdx]
    Match,          // accept: whole pattern matched
    Jmp,            // unconditional jump to arg.x
    Split,          // try arg.x first; on backtrack try arg.y (the "fork")
    Save,           // record current input pos into capture slot arg.n
    AssertBol,      // assert beginning-of-line (^)
    AssertEol,      // assert end-of-line ($)
    AssertWordB,    // assert \b
    AssertNotWordB, // assert \B
};

// One compiled instruction. A small tagged record; trivially copyable
// (arena-friendly, zero-fill-valid).
struct ReInst
{
    ReOp op;
    char ch; // Char: the literal byte
    u32 x;   // Jmp/Split: primary target; Save: (unused)
    u32 y;   // Split: secondary target
    u32 n;   // Save: capture slot index; Class: class-table index
};

// A character-class membership test, compiled from `[...]`. Stored as a
// 256-bit bitmap (one bit per byte) so a class match is O(1) and never
// recurses. `negated` is folded into the bitmap at compile time, so the
// VM just tests the bit.
struct ReClass
{
    u8 bits[32]; // 256 bits, one per possible byte value
};

// A fully compiled regex program: instructions + class tables + the
// capture count + flag bits.
struct ReProgram
{
    ReInst* code;
    u32 codeLen;
    ReClass* classes;
    u32 classCount;
    u32 groupCount;  // number of capturing groups, including group 0
    bool global;     // 'g'
    bool ignoreCase; // 'i'
    bool multiline;  // 'm'
};

// Compile `pattern` (length `patLen`) with `flags` (length `flagLen`)
// into an arena-allocated ReProgram. Returns InvalidArgument on a
// malformed/unsupported pattern or flag, OutOfMemory on arena
// exhaustion, Overflow if the program would exceed kReMaxProgram.
Result<ReProgram*> ReCompile(Arena& arena, const char* pattern, u32 patLen, const char* flags, u32 flagLen);

// The outcome of a single match attempt. `matched` false means no match
// (this includes the budget-exhausted "give up" case — a hostile
// pattern degrades to no-match, never a hang). On a match, `caps` holds
// 2*groupCount slots: caps[2k] = start, caps[2k+1] = end of group k, or
// kReNoCap for an unmatched group.
inline constexpr u32 kReNoCap = 0xFFFFFFFFu;

struct ReMatch
{
    bool matched;
    u32 start;                  // overall match start (group 0)
    u32 end;                    // overall match end (group 0)
    u32 caps[2 * kReMaxGroups]; // capture starts/ends
};

// A RegExp instance's runtime payload, hung off JsObject::regexp. Carries
// the compiled program plus the original source/flags text (for `.source`
// / `.flags` / toString) and the stateful `lastIndex` the `g` flag uses.
struct JsRegExp
{
    ReProgram* prog;
    const char* source; // arena-owned, NUL-terminated original pattern
    u32 sourceLen;
    const char* flags; // arena-owned, NUL-terminated flag string
    u32 flagsLen;
    u32 lastIndex; // mutable; advanced by g-flag exec/test
};

// Run `prog` against `input[startAt..len)`, finding the leftmost match
// at or after `startAt`. `stepBudget` bounds total VM steps; when it
// hits zero the search returns no-match. The arena is used for the
// explicit backtracking stack. Never recurses; never overflows the
// kernel stack.
ReMatch ReExec(Arena& arena, const ReProgram* prog, const char* input, u32 len, u32 startAt, u64 stepBudget);

} // namespace duetos::web::js
