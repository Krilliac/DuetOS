#include "web/js/regexp.h"

/*
 * DuetOS — kernel/web/js: the bounded regex matcher VM.
 *
 * Split out of regexp.cpp (which holds the compiler) so each translation
 * unit is one coherent job. This is the SECURITY-CRITICAL half: it runs
 * attacker-controlled patterns against attacker-controlled input on the
 * kernel's 64 KiB stack, so it MUST be hard-bounded.
 *
 * Design (all three bounds are load-bearing):
 *   1. NON-RECURSIVE. A backtracking matcher is classically written with
 *      C++ recursion; that would let `(a+)+$` smash the kernel stack. Here
 *      the matcher is a single flat loop. On a Split it pushes the
 *      secondary branch (with a capture snapshot) onto an EXPLICIT
 *      arena-allocated stack and follows the primary; a dead end pops and
 *      resumes. No matcher frame nests a call; stack overflow is
 *      impossible by construction.
 *   2. STEP-BOUNDED. Every VM step decrements `steps` (seeded from the
 *      interpreter's remaining budget by the caller). Catastrophic
 *      backtracking exhausts it and the match returns no-match — never a
 *      hang.
 *   3. SPACE-BOUNDED. The backtrack stack is hard-capped at
 *      kReMaxBacktrack; on overflow the current anchor is abandoned
 *      (degrades to a possible missed match, marked GAP) rather than
 *      growing memory.
 */

namespace duetos::web::js
{

namespace
{

bool VmWordChar(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

bool ClassMatch(const ReClass* cls, u8 b)
{
    return (cls->bits[b >> 3] >> (b & 7)) & 1;
}

bool WordCharAt(const char* in, u32 len, u32 pos)
{
    if (pos >= len)
        return false;
    return VmWordChar(in[pos]);
}

// A saved backtrack frame: where to resume (pc/sp) plus the capture state
// at the fork. Captures are copied by value so a failed branch can't leak
// its partial captures into the alternative.
struct ReThread
{
    u32 pc;
    u32 sp;
    u32 caps[2 * kReMaxGroups];
};

} // namespace

ReMatch ReExec(Arena& arena, const ReProgram* prog, const char* input, u32 len, u32 startAt, u64 stepBudget)
{
    ReMatch result{};
    result.matched = false;

    if (len > kReMaxInput)
        len = kReMaxInput; // GAP: input past 1 MiB is truncated for scanning.

    const u32 ncap = 2 * (prog->groupCount ? prog->groupCount : 1);

    // Explicit backtracking stack (arena-allocated, hard-capped).
    ReThread* stack = arena.NewArray<ReThread>(kReMaxBacktrack);
    if (!stack)
        return result; // OOM -> no match (safe degrade)

    u64 steps = stepBudget;

    // Try each start position startAt..len (leftmost match). The whole
    // search shares one step budget so a pathological pattern across many
    // start positions still terminates.
    for (u32 anchor = startAt; anchor <= len; ++anchor)
    {
        u32 stackTop = 0;
        ReThread cur{};
        cur.pc = 0;
        cur.sp = anchor;
        for (u32 i = 0; i < ncap; ++i)
            cur.caps[i] = kReNoCap;
        cur.caps[0] = anchor; // group-0 start

        bool advanceAnchor = false;
        for (;;)
        {
            if (steps == 0)
            {
                // Budget exhausted: give up entirely (no-match). This is the
                // catastrophic-backtracking safety valve.
                return result;
            }
            --steps;

            const ReInst& in = prog->code[cur.pc];
            bool fail = false;

            switch (in.op)
            {
            case ReOp::Char:
                if (cur.sp < len && input[cur.sp] == in.ch)
                {
                    cur.sp++;
                    cur.pc++;
                }
                else
                    fail = true;
                break;
            case ReOp::Any:
                // Without dotAll, `.` matches any byte except '\n' (current
                // behavior preserved). With the `s` flag, `.` matches line
                // terminators too.
                if (cur.sp < len && (prog->dotAll || input[cur.sp] != '\n'))
                {
                    cur.sp++;
                    cur.pc++;
                }
                else
                    fail = true;
                break;
            case ReOp::Class:
                if (cur.sp < len && ClassMatch(&prog->classes[in.n], u8(input[cur.sp])))
                {
                    cur.sp++;
                    cur.pc++;
                }
                else
                    fail = true;
                break;
            case ReOp::Save:
                if (in.n < ncap)
                    cur.caps[in.n] = cur.sp;
                cur.pc++;
                break;
            case ReOp::Jmp:
                cur.pc = in.x;
                break;
            case ReOp::Split:
                // Follow x; push y to try on backtrack. The pushed thread
                // copies the current caps so the alternative is isolated.
                if (stackTop >= kReMaxBacktrack)
                {
                    // Backtrack stack full: bail this anchor (no-match here).
                    // GAP: a pattern needing > kReMaxBacktrack live forks at
                    // one position may miss a match it would otherwise find.
                    fail = true;
                    advanceAnchor = true;
                    break;
                }
                {
                    ReThread& t = stack[stackTop++];
                    t.pc = in.y;
                    t.sp = cur.sp;
                    for (u32 i = 0; i < ncap; ++i)
                        t.caps[i] = cur.caps[i];
                }
                cur.pc = in.x;
                break;
            case ReOp::AssertBol:
                if (cur.sp == 0 || (prog->multiline && input[cur.sp - 1] == '\n'))
                    cur.pc++;
                else
                    fail = true;
                break;
            case ReOp::AssertEol:
                if (cur.sp == len || (prog->multiline && input[cur.sp] == '\n'))
                    cur.pc++;
                else
                    fail = true;
                break;
            case ReOp::AssertWordB:
            {
                bool before = (cur.sp > 0) && WordCharAt(input, len, cur.sp - 1);
                bool after = WordCharAt(input, len, cur.sp);
                if (before != after)
                    cur.pc++;
                else
                    fail = true;
                break;
            }
            case ReOp::AssertNotWordB:
            {
                bool before = (cur.sp > 0) && WordCharAt(input, len, cur.sp - 1);
                bool after = WordCharAt(input, len, cur.sp);
                if (before == after)
                    cur.pc++;
                else
                    fail = true;
                break;
            }
            case ReOp::Match:
                result.matched = true;
                result.start = cur.caps[0];
                result.end = cur.sp;
                cur.caps[1] = cur.sp; // group-0 end
                for (u32 i = 0; i < ncap; ++i)
                    result.caps[i] = cur.caps[i];
                return result;
            }

            if (fail)
            {
                if (advanceAnchor || stackTop == 0)
                    break; // no live alternative: try the next anchor
                // Pop the most recent fork and resume.
                ReThread& t = stack[--stackTop];
                cur.pc = t.pc;
                cur.sp = t.sp;
                for (u32 i = 0; i < ncap; ++i)
                    cur.caps[i] = t.caps[i];
            }
        }
    }

    return result;
}

} // namespace duetos::web::js
