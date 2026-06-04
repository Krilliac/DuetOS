#include "apps/browser/assistant_backend.h"

#include "util/string.h"

/*
 * DuetOS browser — Assistant dock backend, LocalHeuristic (Phase 2b §7 Part B).
 *
 * Deliberately minimal: a small fixed intent set + a graceful catch-all. NOT an
 * NLU. The contract (assistant_backend.h) is that AssistantRespond always
 * produces a NUL-terminated reply that fits in `cap` and always returns true.
 *
 * Intent table:
 *   null / empty / "help"     -> capability summary line
 *   "open <url>"              -> "navigate:<url>"  (a dock-host intent)
 *   "status" / "arm?"         -> "status:requested"
 *   anything else             -> fixed fallback ("try `help`")
 *
 * All writes are bounded by `cap` via core::AppendStr, which never writes index
 * cap-1 or beyond — so the trailing NUL the caller relies on always fits.
 */

namespace duetos::apps::browser
{
namespace
{
using duetos::core::AppendStr;
using duetos::core::StrEqual;

// True if `s` begins with the NUL-terminated `prefix`. NULL-safe on `s`.
bool StartsWith(const char* s, const char* prefix)
{
    if (s == nullptr)
    {
        return false;
    }
    while (*prefix != '\0')
    {
        if (*s != *prefix)
        {
            return false;
        }
        ++s;
        ++prefix;
    }
    return true;
}

// Write a NUL-terminated literal/string into `out`, bounded by `cap`.
void WriteReply(char* out, duetos::u32 cap, const char* reply)
{
    duetos::u32 pos = 0;
    AppendStr(out, &pos, cap, reply);
    out[pos] = '\0';
}

} // namespace

bool AssistantRespond(const char* userMsg, char* out, duetos::u32 cap)
{
    // Degenerate caller buffer: nothing safe to write.
    if (out == nullptr || cap == 0)
    {
        return true;
    }

    // help / empty / null -> capability summary.
    if (userMsg == nullptr || userMsg[0] == '\0' || StrEqual(userMsg, "help"))
    {
        WriteReply(out, cap, "I can: open <url>, report page status. (local mode — no LLM yet)");
        return true;
    }

    // "open <url>" -> a navigate intent the dock host acts on. The URL is
    // everything after the "open " prefix (5 chars), passed through verbatim.
    if (StartsWith(userMsg, "open "))
    {
        const char* url = userMsg + 5;
        duetos::u32 pos = 0;
        AppendStr(out, &pos, cap, "navigate:");
        AppendStr(out, &pos, cap, url);
        out[pos] = '\0';
        return true;
    }

    // page / arm status query.
    if (StrEqual(userMsg, "status") || StrEqual(userMsg, "arm?"))
    {
        WriteReply(out, cap, "status:requested");
        return true;
    }

    // Catch-all fallback — the contract's "always a reply" guarantee.
    WriteReply(out, cap, "I can't do that locally yet. Try `help`.");
    return true;
}

} // namespace duetos::apps::browser
