#pragma once

#include "util/types.h"

/*
 * DuetOS security guard — v0 (advisory mode).
 *
 * Every loadable image — native ELF, Windows PE, kernel thread,
 * user thread — passes through `Gate()` before it gets to run.
 * The guard applies a small, explicit set of heuristics, produces
 * a Verdict, and (in Enforce mode) prompts the user to allow once,
 * allow always (adding a persistent exception), or deny if the
 * result is Warn or Deny. Images matching an existing exception
 * skip the heuristics entirely.
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

namespace duetos::security
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

/// Quick-path gate for thread creation. Bytes/size are null (a
/// thread is a function pointer, not an image), so only the
/// name-based deny list applies. Separate entry so callers don't
/// have to construct an ImageDescriptor.
bool GateThread(ImageKind kind, const char* name);

// -------------------------------------------------------------
// Operator exceptions.
//
// An exception is scoped to the SHA-256 digest of the image, never
// to its path — see `security/exception_id.h` for why, and
// `wiki/security/Security-Exceptions.md` for the operator-facing
// story. Three ways in, all of them explicit:
//
//   1. Answer `a` ("always") at an Enforce-mode prompt.
//   2. `guard except add <sha256>` from the kernel shell (root /
//      kCapSecurity — a guest PE has no route to either).
//   3. `guard-allow=<sha256>[,<sha256>...]` on the boot cmdline,
//      for unattended boots and CI. Repeatable. NOT a blanket
//      allow: unknown images still hit the full heuristic path,
//      and an unmatched Warn image is still denied on timeout.
//
// Storage: RamVol (`/run/guard-allowed`) is the immediate in-memory
// backing store, live for the duration of the boot.  Persistent
// storage across reboots uses `GUARD.DAT` on the DuetOS-owned FAT32
// volume (identified by `Fat32VolumeIsDuetOsOwned`).  The disk file
// is loaded by `GuardLoadDiskExceptions()` (called after FAT32 is
// probed) and updated on every `GuardRememberAllow` /
// `GuardForgetException`.  The boot cmdline (`guard-allow=`) remains
// the override channel for CI / unattended boots.
// -------------------------------------------------------------

/// Load the stored exception list (one 64-char hex SHA-256 digest
/// per line). Called from GuardInit. Safe if the file is absent —
/// that just means no exceptions. Lines that are not exactly a
/// 64-char digest are skipped rather than partially parsed.
void GuardLoadAllowlist();

/// Add a digest (SHA-256, 32 raw bytes) to the exception list and
/// store it. Called when the operator answers "always" at a prompt
/// and by the shell's `guard except add`. Idempotent.
void GuardRememberAllow(const u8 hash[32]);

/// Parse `guard-allow=` tokens out of `cmdline` and install them.
/// Called from GuardInit with the cached boot cmdline. A nullptr
/// cmdline installs nothing. Logs loudly when anything is seeded.
void GuardSeedExceptionsFromCmdline(const char* cmdline);

/// Exception-list accessors for the shell `guard except` surface.
/// `GuardCmdlineSeededCount` is how many of them came from the boot
/// cmdline — non-zero means this boot ran pre-authorised.
u32 GuardExceptionCount();
u32 GuardCmdlineSeededCount();
bool GuardExceptionGet(u32 index, u8 out[32]);

/// Drop the exception at `index` and rewrite the store. Returns
/// false if the index is out of range.
bool GuardForgetException(u32 index);

/// Load exceptions from the DuetOS-owned FAT32 volume's GUARD.DAT
/// file. Called from boot_bringup AFTER FAT32 volumes are probed
/// and mounted — GuardInit runs before FAT32 is available, so this
/// is a deferred second pass. Idempotent: digests already in the
/// in-memory list (from RamVol or cmdline) are not duplicated.
/// Safe if no DuetOS volume exists or the file is absent.
void GuardLoadDiskExceptions();

/// Boot-time init: zero counters, seed the allow/deny tables,
/// load the stored exception list, apply `guard-allow=` cmdline
/// seeds, drop into Advisory mode. Safe to call twice; second call
/// is a no-op with a Warn log.
void GuardInit();

/// Boot-time self-test: synthesise a few fake images (clean ELF,
/// packed-PE-mimic, suspect-name) and verify the Inspect verdicts.
/// Prints PASS/FAIL to COM1.
void GuardSelfTest();

/// True iff a `PromptUser` modal is currently up. The desktop
/// compositor (`drivers::video::DesktopCompose`) short-circuits
/// when this returns true so the prompt's directly-painted pixels
/// (the guard modal bypasses BeginCompose / EndCompose because it
/// runs synchronously on the kboot/loader thread, not on the ui-
/// ticker) are not overwritten by an in-flight desktop redraw.
/// Mirrors the `LoginIsActive()` short-circuit pattern.
///
/// Safe to call from any context — single-byte read, no locks.
bool GuardPromptActive();

} // namespace duetos::security
