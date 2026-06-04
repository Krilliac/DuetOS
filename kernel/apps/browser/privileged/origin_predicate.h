#pragma once

#include "util/types.h"

/*
 * DuetOS browser — Privileged-Origin Mode (spec §13): the privileged-origin
 * predicate. ALL conditions must hold for the live navigation before a tab
 * may be armed for claude.ai/code system access:
 *   scheme=="https" · host=="claude.ai" (exact, no subdomain) ·
 *   path begins "/code" · NOT reached via any redirect ·
 *   server-leaf SPKI matches the embedded pin.
 *
 * Pure — boot-self-tested. The predicate is evaluated by kernel-owned
 * browser chrome, never by the page.
 */

namespace duetos::apps::browser::priv
{
// SHA-256 of the server-leaf SubjectPublicKeyInfo (the SPKI pin).
struct SpkiPin
{
    duetos::u8 sha256[32];
};

struct OriginCheck
{
    const char* scheme;      // e.g. "https"
    const char* host;        // post-IDNA, ASCII-folded (e.g. "claude.ai")
    const char* path;        // e.g. "/code/abc"
    bool reachedViaRedirect; // true if any 3xx / client redirect was observed
    const SpkiPin* leafPin;  // server-leaf SPKI hash (null => fail closed)
};

// Constant-time compare of `leaf` against the build-embedded claude.ai pin.
bool LeafPinMatches(const SpkiPin& leaf);

// The full predicate (all conditions ANDed).
bool IsPrivilegedOrigin(const OriginCheck& c);

void OriginPredicateSelfTest();

} // namespace duetos::apps::browser::priv
