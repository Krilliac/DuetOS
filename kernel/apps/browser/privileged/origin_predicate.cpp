#include "apps/browser/privileged/origin_predicate.h"

namespace duetos::apps::browser::priv
{
using duetos::u32;
using duetos::u8;

namespace
{
// GAP: v0 placeholder pin. The real claude.ai server-leaf SPKI SHA-256 is
// filled in when the feature is enabled for production; pin rotation /
// secondary-pin handling is a follow-up. A mismatch fails closed (never arms).
constexpr u8 kEmbeddedPin[32] = {
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
};

bool StrEq(const char* a, const char* b)
{
    u32 i = 0;
    for (; a[i] != '\0' && b[i] != '\0'; ++i)
        if (a[i] != b[i])
            return false;
    return a[i] == b[i];
}

bool StartsWith(const char* s, const char* prefix)
{
    for (u32 i = 0; prefix[i] != '\0'; ++i)
        if (s[i] != prefix[i]) // s shorter than prefix => s[i]=='\0' != prefix[i]
            return false;
    return true;
}
} // namespace

bool LeafPinMatches(const SpkiPin& leaf)
{
    u8 diff = 0;
    for (u32 i = 0; i < 32; ++i)
        diff |= static_cast<u8>(leaf.sha256[i] ^ kEmbeddedPin[i]);
    return diff == 0; // constant-time over the 32 bytes
}

bool IsPrivilegedOrigin(const OriginCheck& c)
{
    if (c.scheme == nullptr || c.host == nullptr || c.path == nullptr)
        return false;
    if (!StrEq(c.scheme, "https"))
        return false;
    if (!StrEq(c.host, "claude.ai")) // exact — no subdomain, no other host
        return false;
    if (!StartsWith(c.path, "/code"))
        return false;
    if (c.reachedViaRedirect)
        return false;
    if (c.leafPin == nullptr || !LeafPinMatches(*c.leafPin))
        return false;
    return true;
}

} // namespace duetos::apps::browser::priv
