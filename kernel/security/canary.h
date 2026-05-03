#pragma once

#include "util/types.h"

/*
 * DuetOS — file-canary self-defense, v0.
 *
 * Companion wall to the FS write-rate guard
 * (kernel/proc/process.h). The rate guard says "any process
 * that writes too much, too fast, dies." This wall says "any
 * process that touches a sensitive path AT ALL dies — no
 * thresholds, no math."
 *
 * Why both: an attacker who reads our open-source threshold
 * constants can stay just under the rate cap by pacing their
 * writes (15 MiB/s indefinitely; or 16 MiB then sleep). Canaries
 * are immune to that strategy because they don't measure rate;
 * touching the path once is the trip. The ransomware's encrypt-
 * loop has no way to know which files are canaries without
 * decoding kernel symbols (and even then we can rotate at boot).
 *
 * v0 scope
 * --------
 * - Static path list: a small set of names + path prefixes
 *   compiled into the kernel. Operators extend by editing the
 *   array; a runtime-registration syscall is reserved for v1.
 * - Two matchers: exact path/leaf compare (for known canaries),
 *   and suspicious-extension compare (for "any new file with a
 *   ransomware-typical extension is hostile"). Both are
 *   case-insensitive ASCII.
 * - Trip-on-first-touch: a single match is enough to flag the
 *   calling task for kill. No threshold counters.
 * - Wired into every path-bearing FS-mutation syscall site
 *   (create, write to existing, unlink, rename). The hooks are
 *   path-string based — no filesystem support needed for the
 *   canary "files" to exist on disk.
 *
 * Threat model
 * ------------
 * Closes the "low-and-slow" rate-limit-evasion attack a
 * sophisticated open-source-aware ransomware can mount: pacing
 * writes under the cap. The canary wall trips on the first byte
 * landing on the wrong path, regardless of pace. It does NOT
 * close determined-stealthy attackers who know the canary list
 * (compile-time-leaked symbol) and steer around it; for that we
 * want randomized per-boot canary names + decoy file planting,
 * which is reserved for v1.
 *
 * Context: kernel. All matchers are read-only walks of constexpr
 * data; safe from any context (IRQ, NMI, task). The Trip path
 * calls FlagCurrentForKill, which itself is no-op-when-no-task,
 * so calling Trip from a kernel-only context is safe (just
 * doesn't kill anything).
 */

namespace duetos::security
{

/// Returns true if `path` (full path or basename) matches a
/// registered canary entry. Walks the canary list once; the
/// match is case-insensitive ASCII against either:
///   - the full string equals a registered exact path, OR
///   - the leaf basename equals a registered name, OR
///   - the path begins with a registered prefix.
///
/// Empty / null path is never a match.
bool CanaryMatchesPath(const char* path);

/// Returns true if `path`'s extension matches a known
/// ransomware-typical suffix (`.locked`, `.encrypted`,
/// `.crypto`, `.crypt`, `.ransom`, `.enc`, `.crypted`, etc).
/// Case-insensitive. The intent is "if a process is creating a
/// new file with this extension, it is almost certainly the
/// encrypted-output side of a ransomware loop" — a defense
/// independent of which files the kernel registered as
/// canaries.
bool CanaryMatchesSuspiciousExtension(const char* path);

/// Trip handler. Called when CanaryMatchesPath /
/// CanaryMatchesSuspiciousExtension returns true at a syscall
/// site. Logs the event, bumps the global trip counter +
/// `CanaryFileTouched` HealthIssue, and flags the current task
/// for kill via `KillReason::CanaryFileTouched`. Idempotent —
/// repeated calls bump counters but the kill flag is itself
/// idempotent.
///
/// `op` is a short string identifying the syscall ("create",
/// "write", "unlink", "rename", ...) used in the log line.
void CanaryTrip(const char* path, const char* op);

/// Aggregate stats for operator-facing diagnostics. Lifetime-
/// since-boot counts; reset only by reboot.
struct CanaryStats
{
    u64 trips_total;
    u64 trips_path;       // matched a registered canary path
    u64 trips_suspicious; // matched a suspicious extension
};

/// Read-only stats accessor. Safe from any context.
const CanaryStats& CanaryStatsRead();

/// Combined helper — runs both matchers and trips on the first
/// hit. Returns true if a trip happened (caller may want to
/// bail early; the kill itself is enacted by Trip). `op` is
/// passed straight to Trip on match.
///
/// Convenience for syscall sites that don't care which kind of
/// match fired — they just need "is this access forbidden?"
bool CanaryCheck(const char* path, const char* op);

} // namespace duetos::security
