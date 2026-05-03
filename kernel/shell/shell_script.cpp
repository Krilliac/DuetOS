/*
 * DuetOS — kernel shell: scripting language v0.
 *
 * Sibling TU of shell.cpp. Implements POSIX-shell-flavoured control
 * flow on top of the existing Dispatch() pipeline. The interpreter
 * is line-indexed: ScriptSplitLines() turns a file body into an
 * array of fixed-length strings, then ScriptExecute() walks that
 * array, recursing into block bodies via index ranges.
 *
 * Block matching is depth-tracking — `if`/`while`/`for` push, the
 * paired `fi`/`done` pop. Inner blocks of the same kind nest cleanly
 * because the executor only matches a closer when the depth has
 * dropped back to its caller's level.
 *
 * Branch / loop conditions read $? after dispatching their CMD:
 * $? == 0 means true (POSIX flavour). The `for` loop iterates over
 * a whitespace-split word list, writing each iteration's value into
 * the env table under the loop variable name.
 *
 * Scope limits are documented in shell_internal.h. The convention
 * for parse errors: print a one-line diagnostic, set $? to 2 (misuse
 * of shell builtin), and return — the caller (CmdSource) decides
 * whether to keep going.
 */

#include "shell/shell_internal.h"

#include "drivers/video/console.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "shell/shell.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// True iff `s` begins with `prefix` followed by either NUL or one
// of the recognised separator characters (' ', '\t', ';'). Catches
// `if `, `if(` not at all, but does match `if`+EOL (rare but legal
// for the trailing `fi` form). Using a separator check (rather than
// just StrStartsWith) prevents false positives like `iffy` matching
// `if`.
bool LineStartsWithKeyword(const char* s, const char* kw)
{
    u32 i = 0;
    for (; kw[i] != '\0'; ++i)
    {
        if (s[i] != kw[i])
            return false;
    }
    const char c = s[i];
    return c == '\0' || c == ' ' || c == '\t' || c == ';';
}

// Skip leading whitespace and return a pointer into `s`. Used to
// normalise the start of every script line so leading indent doesn't
// confuse the keyword check.
const char* SkipWs(const char* s)
{
    while (*s == ' ' || *s == '\t')
        ++s;
    return s;
}

// Find the index of the matching closer for the block opener at
// `open_idx`. `lines[open_idx]` must start with one of the three
// opener keywords (`if`, `while`, `for`). Returns the closer's
// index, or `n` if no matching closer was found (caller treats this
// as a parse error). Tracks depth: any nested `if`/`while`/`for`
// pushes, any matching `fi`/`done` pops.
u32 FindMatchingCloser(char (*lines)[kScriptLineMax], u32 n, u32 open_idx)
{
    const char* opener = SkipWs(lines[open_idx]);
    const char* close_kw = nullptr;
    if (LineStartsWithKeyword(opener, "if"))
        close_kw = "fi";
    else if (LineStartsWithKeyword(opener, "while") || LineStartsWithKeyword(opener, "for"))
        close_kw = "done";
    else
        return n;

    u32 depth = 1;
    for (u32 i = open_idx + 1; i < n; ++i)
    {
        const char* L = SkipWs(lines[i]);
        if (LineStartsWithKeyword(L, "if") || LineStartsWithKeyword(L, "while") || LineStartsWithKeyword(L, "for"))
        {
            ++depth;
            continue;
        }
        if (LineStartsWithKeyword(L, close_kw) && depth == 1)
        {
            return i;
        }
        if (LineStartsWithKeyword(L, "fi") || LineStartsWithKeyword(L, "done"))
        {
            --depth;
            if (depth == 0)
                return n; // wrong closer at our level
        }
    }
    return n;
}

// At top-level (depth 0) of the if-body between `from` and `to`,
// find the index of the next `elif` or `else` keyword. Returns `to`
// if neither is found at this level. Used by ExecuteIfBlock to
// split the body into branches without false-matching nested ifs.
u32 FindIfBranchPoint(char (*lines)[kScriptLineMax], u32 from, u32 to)
{
    u32 depth = 0;
    for (u32 i = from; i < to; ++i)
    {
        const char* L = SkipWs(lines[i]);
        if (LineStartsWithKeyword(L, "if") || LineStartsWithKeyword(L, "while") || LineStartsWithKeyword(L, "for"))
        {
            ++depth;
            continue;
        }
        if (LineStartsWithKeyword(L, "fi") || LineStartsWithKeyword(L, "done"))
        {
            if (depth > 0)
                --depth;
            continue;
        }
        if (depth == 0 && (LineStartsWithKeyword(L, "elif") || LineStartsWithKeyword(L, "else")))
        {
            return i;
        }
    }
    return to;
}

// Strip the leading keyword + trailing `; then` / `; do` clause off
// a header line and copy the bare condition into `out`. e.g.
// "if cmd1 ; then" -> "cmd1". Returns true on success; false (with
// out[0] = '\0') if the trailing clause is missing.
bool ExtractCondition(const char* line, const char* keyword, const char* tail_kw, char* out, u32 cap)
{
    out[0] = '\0';
    line = SkipWs(line);
    u32 i = 0;
    while (keyword[i] != '\0')
    {
        if (line[i] != keyword[i])
            return false;
        ++i;
    }
    // Skip mandatory whitespace after the keyword.
    if (line[i] != ' ' && line[i] != '\t')
        return false;
    while (line[i] == ' ' || line[i] == '\t')
        ++i;
    // Locate the `;` that introduces the tail clause.
    i32 semi = -1;
    for (u32 j = i; line[j] != '\0'; ++j)
    {
        if (line[j] == ';')
        {
            semi = static_cast<i32>(j);
            break;
        }
    }
    if (semi < 0)
        return false;
    // Confirm the post-semi text matches `tail_kw` (after ws).
    const char* after = SkipWs(line + semi + 1);
    u32 k = 0;
    for (; tail_kw[k] != '\0'; ++k)
    {
        if (after[k] != tail_kw[k])
            return false;
    }
    if (after[k] != '\0' && after[k] != ' ' && after[k] != '\t')
        return false;
    // Copy the condition (between i and semi-1, trimmed).
    u32 end = static_cast<u32>(semi);
    while (end > i && (line[end - 1] == ' ' || line[end - 1] == '\t'))
        --end;
    u32 o = 0;
    for (u32 p = i; p < end && o + 1 < cap; ++p)
        out[o++] = line[p];
    out[o] = '\0';
    return true;
}

// Forward declarations — the block executors recurse into the
// top-level walker and call each other through the same surface.
void ExecuteRange(char (*lines)[kScriptLineMax], u32 from, u32 to);
u32 ExecuteIfBlock(char (*lines)[kScriptLineMax], u32 n, u32 idx);
u32 ExecuteWhileBlock(char (*lines)[kScriptLineMax], u32 n, u32 idx);
u32 ExecuteForBlock(char (*lines)[kScriptLineMax], u32 n, u32 idx);

void ExecuteOneCommand(const char* src)
{
    // Dispatch needs a writable buffer (it tokenises in place).
    char buf[kScriptLineMax];
    u32 i = 0;
    for (; i + 1 < sizeof(buf) && src[i] != '\0'; ++i)
        buf[i] = src[i];
    buf[i] = '\0';
    Dispatch(buf);
}

void ExecuteRange(char (*lines)[kScriptLineMax], u32 from, u32 to)
{
    u32 i = from;
    while (i < to)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return;
        }
        const char* L = SkipWs(lines[i]);
        if (L[0] == '\0' || L[0] == '#')
        {
            ++i;
            continue;
        }
        if (LineStartsWithKeyword(L, "if"))
        {
            i = ExecuteIfBlock(lines, to, i);
            continue;
        }
        if (LineStartsWithKeyword(L, "while"))
        {
            i = ExecuteWhileBlock(lines, to, i);
            continue;
        }
        if (LineStartsWithKeyword(L, "for"))
        {
            i = ExecuteForBlock(lines, to, i);
            continue;
        }
        // Plain command — dispatch via the public pipeline so
        // alias / $VAR / pipe / redirect handling all apply.
        ExecuteOneCommand(L);
        ++i;
    }
}

u32 ExecuteIfBlock(char (*lines)[kScriptLineMax], u32 n, u32 idx)
{
    const u32 fi = FindMatchingCloser(lines, n, idx);
    if (fi >= n)
    {
        ShellSetExit(2);
        ConsoleWriteln("SCRIPT: 'if' WITHOUT MATCHING 'fi'");
        return n;
    }
    // Walk through if + elif chain until one branch fires (or fall
    // into else / past the closer with no body run). `clause_start`
    // is the index of the current clause-header line (`if` or
    // `elif`). The body of each clause runs from clause_start+1 to
    // the next branch-point at depth 0.
    u32 clause_start = idx;
    while (clause_start < fi)
    {
        const char* header = SkipWs(lines[clause_start]);
        if (LineStartsWithKeyword(header, "else"))
        {
            // Default arm — execute body and stop.
            ExecuteRange(lines, clause_start + 1, fi);
            return fi + 1;
        }
        const char* kw = LineStartsWithKeyword(header, "if") ? "if" : "elif";
        char cond[kScriptLineMax];
        if (!ExtractCondition(header, kw, "then", cond, sizeof(cond)))
        {
            ShellSetExit(2);
            ConsoleWrite("SCRIPT: BAD HEADER (missing '; then'): ");
            ConsoleWriteln(header);
            return fi + 1;
        }
        ExecuteOneCommand(cond);
        const bool truthy = (ShellLastExit() == 0);
        const u32 next = FindIfBranchPoint(lines, clause_start + 1, fi);
        if (truthy)
        {
            ExecuteRange(lines, clause_start + 1, next);
            return fi + 1;
        }
        clause_start = next;
    }
    return fi + 1;
}

u32 ExecuteWhileBlock(char (*lines)[kScriptLineMax], u32 n, u32 idx)
{
    const u32 done = FindMatchingCloser(lines, n, idx);
    if (done >= n)
    {
        ShellSetExit(2);
        ConsoleWriteln("SCRIPT: 'while' WITHOUT MATCHING 'done'");
        return n;
    }
    char cond[kScriptLineMax];
    if (!ExtractCondition(SkipWs(lines[idx]), "while", "do", cond, sizeof(cond)))
    {
        ShellSetExit(2);
        ConsoleWriteln("SCRIPT: BAD 'while' HEADER (missing '; do')");
        return done + 1;
    }
    // Cap iterations to keep a runaway loop from wedging the box.
    constexpr u32 kIterCap = 10000;
    for (u32 it = 0; it < kIterCap; ++it)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return done + 1;
        }
        ExecuteOneCommand(cond);
        if (ShellLastExit() != 0)
            break;
        ExecuteRange(lines, idx + 1, done);
    }
    return done + 1;
}

u32 ExecuteForBlock(char (*lines)[kScriptLineMax], u32 n, u32 idx)
{
    const u32 done = FindMatchingCloser(lines, n, idx);
    if (done >= n)
    {
        ShellSetExit(2);
        ConsoleWriteln("SCRIPT: 'for' WITHOUT MATCHING 'done'");
        return n;
    }
    // Header shape: `for VAR in W1 W2 W3 ; do`. ExtractCondition
    // hands us back "VAR in W1 W2 W3" — split that into varname +
    // word list ourselves.
    char tail[kScriptLineMax];
    if (!ExtractCondition(SkipWs(lines[idx]), "for", "do", tail, sizeof(tail)))
    {
        ShellSetExit(2);
        ConsoleWriteln("SCRIPT: BAD 'for' HEADER (missing '; do')");
        return done + 1;
    }
    // Pull the variable name (up to first whitespace).
    const char* p = tail;
    while (*p == ' ' || *p == '\t')
        ++p;
    char varname[kEnvNameMax];
    u32 vn = 0;
    while (*p != '\0' && *p != ' ' && *p != '\t' && vn + 1 < sizeof(varname))
        varname[vn++] = *p++;
    varname[vn] = '\0';
    if (vn == 0)
    {
        ShellSetExit(2);
        ConsoleWriteln("SCRIPT: BAD 'for' HEADER (missing VAR)");
        return done + 1;
    }
    // Skip whitespace + the literal "in" keyword.
    while (*p == ' ' || *p == '\t')
        ++p;
    if (!(p[0] == 'i' && p[1] == 'n' && (p[2] == ' ' || p[2] == '\t' || p[2] == '\0')))
    {
        ShellSetExit(2);
        ConsoleWriteln("SCRIPT: BAD 'for' HEADER (missing 'in')");
        return done + 1;
    }
    p += 2;
    // Iterate over whitespace-split words. Per iteration: write the
    // env slot, execute the body. EnvSet returns false only on a
    // full table; handle that as a soft warning so the loop still
    // terminates.
    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t')
            ++p;
        if (*p == '\0')
            break;
        char word[kEnvValueMax];
        u32 wn = 0;
        while (*p != '\0' && *p != ' ' && *p != '\t' && wn + 1 < sizeof(word))
            word[wn++] = *p++;
        word[wn] = '\0';
        if (!EnvSet(varname, word))
        {
            ConsoleWriteln("SCRIPT: ENV TABLE FULL (for-loop)");
            return done + 1;
        }
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return done + 1;
        }
        ExecuteRange(lines, idx + 1, done);
    }
    return done + 1;
}

} // namespace

void ScriptExecute(char (*body_lines)[kScriptLineMax], u32 body_n)
{
    ExecuteRange(body_lines, 0, body_n);
}

u32 ScriptSplitLines(const char* scratch, u32 n, char (*out_lines)[kScriptLineMax], u32 cap)
{
    u32 lc = 0;
    u32 i = 0;
    while (i < n && lc < cap)
    {
        u32 j = 0;
        while (i < n && scratch[i] != '\n' && j + 1 < kScriptLineMax)
        {
            out_lines[lc][j++] = scratch[i++];
        }
        bool truncated = false;
        while (i < n && scratch[i] != '\n')
        {
            ++i;
            truncated = true;
        }
        if (i < n)
            ++i; // consume '\n'
        // Trim trailing whitespace.
        while (j > 0 && (out_lines[lc][j - 1] == ' ' || out_lines[lc][j - 1] == '\t' || out_lines[lc][j - 1] == '\r'))
        {
            --j;
        }
        out_lines[lc][j] = '\0';
        if (truncated)
        {
            duetos::core::Log(duetos::core::LogLevel::Warn, "shell/script", "line truncated to fit buffer");
        }
        ++lc;
    }
    return lc;
}

} // namespace duetos::core::shell::internal
