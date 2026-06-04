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

namespace duetos::security::privilege
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

// Emit one audit entry. Mirrors to serial (a security audit must ALWAYS be
// visible) AND appends the formatted line to the engine's own /AUDIT.LOG via a
// direct fat32 call (audit.log is excluded from the fs scope, so it is
// unreachable by page JS). No-ops gracefully if no FAT32 volume is mounted.
void AuditAppend(const AuditEntry& e);

void AuditSelfTest();

} // namespace duetos::security::privilege
