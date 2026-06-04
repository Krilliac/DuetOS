#pragma once

#include "util/types.h"

/*
 * DuetOS browser — Privileged-Origin Mode (spec §13.8): the audit-entry
 * formatter + sink. ONE unified audit trail for the whole Privilege Engine;
 * every entry tags the originating CLIENT identity (browser / headless) so
 * incident response can grep "everything client X did in window Y" (per the
 * "one engine, many clients" architecture). The formatter is pure (self-tested);
 * the fs sink is wired in the broker-execution task.
 */

namespace duetos::apps::browser::priv
{
struct AuditEntry
{
    const char* iso8601;     // caller stamps the timestamp (tests pass a fixed value)
    const char* client;      // "browser" / "headless" — originating client identity
    const char* origin;      // "https://claude.ai/code"
    duetos::u32 tab;         // tab / session id
    const char* cap;         // "fs.write"
    const char* argsSummary; // bounded/redacted: "path=/home/user/x bytes=412" (no payloads)
    bool ok;                 // allow vs deny
};

// Format one append-only JSON line into out[cap]; returns bytes written.
// String values are JSON-escaped; control bytes are dropped.
duetos::u32 FormatAuditLine(const AuditEntry& e, char* out, duetos::u32 cap);

// Emit one audit entry. v0 mirrors to serial (a security audit must ALWAYS be
// visible). GAP: the cap-gated fs append to audit.log lands with broker
// execution (audit.log is excluded from the fs scope).
void AuditAppend(const AuditEntry& e);

void AuditSelfTest();

} // namespace duetos::apps::browser::priv
