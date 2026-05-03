#pragma once

#include "util/types.h"

/*
 * DuetOS — filesystem self-defense walls, v1.
 *
 * Three layered walls sit between userland and on-disk state.
 * Each catches a different attacker strategy; the rate guard
 * (kernel/proc/process.h) handles the volume axis, this TU
 * handles the location axis:
 *
 *   1. Canary path wall — first touch of a registered canary or
 *      suspicious-extension path = kill. Includes a per-boot
 *      randomized salt so the attacker can't pre-compute the
 *      canary list from kernel symbols.
 *   2. Persistence-drop detector — writes to autostart-
 *      equivalent paths (/etc/init.d/, /.duetos/autostart/,
 *      registry Run keys) raise the `PersistenceDropDetected`
 *      health flag. Mode-dependent: Advisory logs, Deny kills.
 *
 * Threat model
 * ------------
 * - Open-source-aware attacker who reads the canary list:
 *   covered by the per-boot salt entries (CanaryInit randomizes
 *   four extra registry slots from kernel entropy).
 * - "Encrypt-and-stay-resident" malware that drops a service
 *   so it survives reboot: covered by the persistence detector.
 * - "Encrypt-in-place" ransomware that stays under the rate
 *   cap and never touches a registered canary: NOT covered by
 *   this TU — the rate guard's sustained / long-tail tiers
 *   catch it instead.
 *
 * Context: kernel. All matchers are read-only walks of (mostly)
 * constexpr data; safe from any context (IRQ, NMI, task). The
 * Trip / Note paths call FlagCurrentForKill, which itself is
 * no-op-when-no-task, so calling them from a kernel-only
 * context is safe (just doesn't kill anything).
 */

namespace duetos::security
{

// ===================================================================
// Canary path wall.
// ===================================================================

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

/// Boot-time init. Pulls 8 bytes from the kernel entropy pool
/// (kernel/util/random.h `RandomU64`) and folds them into four
/// dynamic canary names like `DUETOS_HONEY_<8-hex-chars>.DAT`.
/// Subsequent `CanaryMatchesPath` calls test against both the
/// static `kCanaryPaths[]` list AND the per-boot dynamic
/// names. Result: a kernel binary leaked to an attacker no
/// longer hands them a canary registry — they have to guess
/// 64 bits of randomness per boot or scrape the live memory
/// for the names.
///
/// Safe single-init. MUST be called after `RandomInit`.
void CanaryInit();

// ===================================================================
// Persistence-drop detector.
// ===================================================================
//
// Most malware that wants to survive reboot drops a file in an
// autostart-equivalent path: a Linux init script, a Windows
// "Run" registry key value, a DuetOS startup config. Catching
// THESE writes specifically — separate from the volume / location
// rate signals — means even a single quiet write that didn't
// trip any other wall surfaces as a `PersistenceDropDetected`
// event.
//
// Mode discipline:
//   - Advisory (default): log + bump counter; legitimate
//     installers writing here are common, killing them is too
//     aggressive for v0.
//   - Deny: kill the writer. The guard subsystem escalates
//     into Deny on any security-critical kernel finding (IDT
//     hijack, syscall MSR drift, etc.) — at that point we no
//     longer trust ANY process to be writing autostart paths.

enum class PersistenceMode : u8
{
    Advisory = 0, // log + counter; the writer keeps running
    Deny,         // log + counter + kill the writer
};

/// Returns true if `path` lives under (or equals) one of the
/// registered persistence-equivalent paths. Same matcher rules
/// as CanaryMatchesPath: full-string equal, basename equal, or
/// path begins with a registered prefix.
bool PersistenceMatchesPath(const char* path);

/// Note that `path` is being mutated by an op tagged `op`
/// ("create", "write", "unlink", "rename-src", "rename-dst").
/// In Advisory mode just bumps the counter + logs. In Deny
/// mode also flags the calling task for kill via
/// `KillReason::PersistenceDrop`. Returns true if the caller
/// should short-circuit (Deny mode). Idempotent; safe from any
/// context.
bool PersistenceNote(const char* path, const char* op);

/// Combined helper — does the path match? if so, route through
/// PersistenceNote. Returns true if the caller should bail
/// (Deny mode and a match). Mirrors CanaryCheck's shape so the
/// syscall sites can call both walls back-to-back.
bool PersistenceCheck(const char* path, const char* op);

/// Read / set the persistence detector's response mode.
PersistenceMode PersistenceModeRead();
void PersistenceSetMode(PersistenceMode m);

struct PersistenceStats
{
    u64 notes_total;    // every match, regardless of mode
    u64 notes_advisory; // matches that DIDN'T kill (Advisory)
    u64 notes_denied;   // matches that DID kill (Deny)
};
const PersistenceStats& PersistenceStatsRead();

} // namespace duetos::security
