#pragma once

#include "security/privilege/arm_state.h"
#include "security/privilege/scope.h"
#include "util/types.h"

/*
 * DuetOS browser — Privileged-Origin Mode (spec §13.7/§13.8): the broker
 * request VALIDATOR — the pure heart of enforcement. It decides yes/no
 * WITHOUT executing. Every privileged call (from any Privilege Engine client)
 * passes here first; on a yes the caller invokes the matching cap-gated
 * kernel syscall (the kernel re-checks independently — belt and suspenders).
 *
 * The validator's assertions are the security contract the execution path
 * must never weaken.
 */

namespace duetos::security::privilege
{
// Upper bound on a single privileged write (spec §13.8 bounds-check).
constexpr duetos::u32 kMaxPrivWriteBytes = 16u * 1024u * 1024u;

struct PrivRequest
{
    Cap cap;
    const char* path = nullptr; // required for fs caps; spawn target for ProcSpawn
    duetos::u32 byteLen = 0;    // for fs.write
    const char* url = nullptr;  // required for Net (fetch target)
};

struct Verdict
{
    bool ok;
    const char* error; // "" when ok; else "EPERM: …" / "EINVAL: …"
};

// armed? · cap in the armed scope? · (fs caps) path canonicalises + contains? ·
// bounds ok? On a yes, writes the canonical path into canonOut[cap]. Fail-closed.
Verdict ValidateRequest(const PrivTab& tab, const Roots& roots, const PrivRequest& r, char* canonOut, duetos::u32 cap);

void BrokerSelfTest();

} // namespace duetos::security::privilege
