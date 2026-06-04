#include "apps/browser/privileged/origin_predicate.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::apps::browser::priv
{
void OriginPredicateSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[priv-origin-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    // A pin that matches the build-embedded one (all 0xA5).
    SpkiPin good{};
    for (duetos::u32 i = 0; i < 32; ++i)
        good.sha256[i] = 0xA5;
    SpkiPin bad{}; // all zero — must NOT match.

    auto base = [&](const char* sc, const char* h, const char* p, bool redir, const SpkiPin* pin)
    { return OriginCheck{sc, h, p, redir, pin}; };

    // 1: the exact privileged origin, direct load, good pin → true.
    if (!IsPrivilegedOrigin(base("https", "claude.ai", "/code/x", false, &good)))
    {
        fail(1);
        return;
    }
    // 2: http (not https) → false.
    if (IsPrivilegedOrigin(base("http", "claude.ai", "/code", false, &good)))
    {
        fail(2);
        return;
    }
    // 3: a different host → false.
    if (IsPrivilegedOrigin(base("https", "evil.com", "/code", false, &good)))
    {
        fail(3);
        return;
    }
    // 4: a subdomain of claude.ai → false (exact host only).
    if (IsPrivilegedOrigin(base("https", "app.claude.ai", "/code", false, &good)))
    {
        fail(4);
        return;
    }
    // 5: a path outside /code → false.
    if (IsPrivilegedOrigin(base("https", "claude.ai", "/login", false, &good)))
    {
        fail(5);
        return;
    }
    // 6: reached via a redirect → false.
    if (IsPrivilegedOrigin(base("https", "claude.ai", "/code", true, &good)))
    {
        fail(6);
        return;
    }
    // 7: a wrong / null pin → false (fail closed).
    if (IsPrivilegedOrigin(base("https", "claude.ai", "/code", false, &bad)))
    {
        fail(7);
        return;
    }
    if (IsPrivilegedOrigin(base("https", "claude.ai", "/code", false, nullptr)))
    {
        fail(8);
        return;
    }

    arch::SerialWrite("[priv-origin-selftest] PASS (exact-origin + https + /code + no-redirect + SPKI pin; 6 negatives "
                      "fail closed)\n");
}

} // namespace duetos::apps::browser::priv
