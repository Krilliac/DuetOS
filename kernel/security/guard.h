#pragma once

#include "../core/types.h"

/*
 * CustomOS security guard — v0 (advisory mode).
 *
 * Every loadable image — native ELF, Windows PE, kernel thread,
 * user thread — passes through `Gate()` before it gets to run.
 * The guard applies a small, explicit set of heuristics, produces
 * a Verdict, and (in Enforce mode) prompts the user to allow/deny
 * if the result is Warn or Deny.
 *
 * Not a signature-verification / code-signing subsystem yet —
 * the hash denylist is a hook for the future "known-bad SHA-256"
 * catalogue. The heuristics are what a user-mode AV would call
 * "static analysis": W+X segments, suspicious import names,
 * entropy-based packer detection, name-based policy.
 *
 * Modes:
 *   Off        guard disabled; Gate() always returns Allow.
 *   Advisory   scan every image, log findings, always allow.
 *              DEFAULT at boot.
 *   Enforce    scan every image, prompt on Warn/Deny, default-deny
 *              on timeout or closed prompt channel.
 *
 * Advisory is the default so a new heuristic that over-flags
 * cannot brick the boot path — operators flip to Enforce via the
 * `guard enforce` shell command once the boot-log is clean.
 *
 * Context: kernel. Gate() may block for user input (serial prompt
 * today, GUI modal in the next slice). Do NOT call from IRQ /
 * softirq context; task-context only.
 */

namespace customos::security
{

enum class ImageKind : u8
{
    NativeElf,    // our own ELF binary
    WindowsPE,    // PE/COFF executable or DLL
    KernelThread, // scheduler-created in-kernel task
    UserThread,   // user-mode task (entry in user AddressSpace)
};

enum class Verdict : u8
{
    Allow, // nothing found, or only benign findings
    Warn,  // suspicious — Enforce mode prompts user
    Deny,  // outright block — Enforce mode refuses unless overridden
};

enum class Mode : u8
{
    Off,
    Advisory,
    Enforce,
};

/// Compact, stable finding codes. Shell / log lines reference them
/// so operators can grep for a specific heuristic fire.
enum FindingCode : u32
{
    kFindingNone = 0,
    kFindingHashDeny = 1,     // SHA-256 match against the deny list
    kFindingNameDeny = 2,     // filename match against the deny list
    kFindingPeInjection = 3,  // PE imports BOTH CreateRemoteThread + WriteProcessMemory
    kFindingPeSuspicious = 4, // PE imports 2+ from the suspicious-API family
    kFindingElfWx = 5,        // ELF has a PT_LOAD segment that is both W and X
    kFindingHighEntropy = 6,  // image contains a region with Shannon entropy > 7.0
    kFindingPeNoImports = 7,  // PE with zero import descriptors (classic packer signature)
};

inline constexpr u32 kMaxFindings = 8;

struct Finding
{
    u32 code;           // FindingCode
    const char* detail; // string literal lifetime — safe to store
};

struct Report
{
    Verdict verdict;
    u32 finding_count;
    Finding findings[kMaxFindings];
};

struct ImageDescriptor
{
    ImageKind kind;
    const char* name; // never null; caller uses "(unnamed)" when the path is unknown
    const u8* bytes;  // may be null for KernelThread / UserThread
    u64 size;
};

/// Scan an image and produce a Report. Pure function — no side
/// effects, no prompts, no state changes. Always safe to call
/// regardless of mode (Inspect runs even in Off mode if callers
/// want to know what the guard WOULD flag).
Report Inspect(const ImageDescriptor& desc);

/// Full gate: runs Inspect, logs findings, and (in Enforce mode
/// on Warn/Deny) prompts the user. Returns true to let the caller
/// proceed, false to block.
///
/// In Advisory mode, always returns true even on Deny — findings
/// are logged at Warn level so operators can see what the guard
/// would have done.
bool Gate(const ImageDescriptor& desc);

/// Mode control. `SetGuardMode` logs the transition.
Mode GuardMode();
void SetGuardMode(Mode m);
const char* GuardModeName(Mode m);

/// Counters + last-report accessor for the shell `guard` command.
/// Thread-unsafe read (values can tear), but Good Enough for a
/// status line — no-one makes policy decisions off these.
u64 GuardScanCount();
u64 GuardAllowCount();
u64 GuardWarnCount();
u64 GuardDenyCount();
const Report* GuardLastReport();

/// Boot-time init: zero counters, seed the allow/deny tables,
/// drop into the default mode (Advisory). Safe to call twice;
/// second call is a no-op with a Warn log.
void GuardInit();

/// Boot-time self-test: synthesise a few fake images (clean ELF,
/// packed-PE-mimic, suspect-name) and verify the Inspect verdicts.
/// Prints PASS/FAIL to COM1.
void GuardSelfTest();

} // namespace customos::security
