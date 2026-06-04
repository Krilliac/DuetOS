#include "apps/browser/assistant_backend.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "util/string.h"

/*
 * Assistant dock backend — LocalHeuristic self-test (Phase 2b §7/§8 Part B).
 *
 * Drives AssistantRespond for each fixed intent into a stack buffer and asserts
 * the reply carries the expected marker substring. Pure heuristic — no live
 * net/proc stack needed. Mirrors the priv-chrome self-test idiom: a `fail`
 * lambda emits a grep-able FAIL line + fires kBootSelftestFail, and a single
 * structural PASS sentinel is written via the raw serial path on all-pass.
 */

namespace duetos::apps::browser
{
namespace
{
using duetos::core::StrLen;

// True if `needle` occurs anywhere in `hay` (both NUL-terminated).
bool Contains(const char* hay, const char* needle)
{
    if (hay == nullptr || needle == nullptr)
    {
        return false;
    }
    const duetos::usize nlen = StrLen(needle);
    if (nlen == 0)
    {
        return true;
    }
    for (duetos::usize i = 0; hay[i] != '\0'; ++i)
    {
        duetos::usize j = 0;
        while (j < nlen && hay[i + j] == needle[j])
        {
            ++j;
        }
        if (j == nlen)
        {
            return true;
        }
    }
    return false;
}

} // namespace

void AssistantHeuristicSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[assistant-heuristic-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    char buf[128];

    // 1: help -> capability summary.
    AssistantRespond("help", buf, sizeof(buf));
    if (!Contains(buf, "open <url>") || !Contains(buf, "local mode"))
    {
        fail(1);
        return;
    }

    // 2: empty string -> same capability summary (help-equivalent).
    AssistantRespond("", buf, sizeof(buf));
    if (!Contains(buf, "open <url>"))
    {
        fail(2);
        return;
    }

    // 3: null message -> capability summary (null-safe fallback).
    AssistantRespond(nullptr, buf, sizeof(buf));
    if (!Contains(buf, "open <url>"))
    {
        fail(3);
        return;
    }

    // 4: "open <url>" -> navigate intent carrying the verbatim URL.
    AssistantRespond("open https://claude.ai/code", buf, sizeof(buf));
    if (!Contains(buf, "navigate:https://claude.ai/code"))
    {
        fail(4);
        return;
    }

    // 5: "status" -> status request intent.
    AssistantRespond("status", buf, sizeof(buf));
    if (!Contains(buf, "status:requested"))
    {
        fail(5);
        return;
    }

    // 6: "arm?" -> status request intent (alias).
    AssistantRespond("arm?", buf, sizeof(buf));
    if (!Contains(buf, "status:requested"))
    {
        fail(6);
        return;
    }

    // 7: unknown input -> fixed fallback pointing back at `help`.
    AssistantRespond("brew me a coffee", buf, sizeof(buf));
    if (!Contains(buf, "Try `help`"))
    {
        fail(7);
        return;
    }

    arch::SerialWrite("[assistant-heuristic-selftest] PASS (help/empty/null summary, open->navigate intent, "
                      "status/arm?->status:requested, unknown->fallback)\n");
}

} // namespace duetos::apps::browser
