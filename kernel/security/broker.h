#pragma once

#include "proc/process.h"
#include "security/rbac.h"
#include "util/types.h"

/*
 * DuetOS — elevation broker, v0.
 *
 * The broker is the kernel-owned authority that turns "this caller
 * doesn't hold cap X right now" into "they typed the password, the
 * role table says they may, so grant X for the configured grace
 * window." It is the only path that adds capabilities to a running
 * `Process` after spawn — the cap gate (`SyscallGate`) is otherwise
 * a closed door.
 *
 * The broker NEVER:
 *   - mutates published capability storage directly. It installs a
 *     generation-tagged, positive-duration Process lease through the
 *     locked capability helpers, subject to the monotonic ceiling.
 *   - trusts user-mode to draw the prompt UI or capture keystrokes.
 *     The prompt is drawn by `BrokerPrompt`, which reads keys
 *     directly from `Ps2KeyboardReadEvent` (same input ring the
 *     login gate uses).
 *   - elevates an account past the cap mask its role grants. Even
 *     "type the right password" does not grant a cap the account's
 *     role does not list. See wiki/security/RBAC-and-Elevation.md
 *     for the full design.
 *
 * Context: kernel. Called from shell-command dispatch (synchronous
 * — the dispatch thread blocks on `Ps2KeyboardReadEvent` inside the
 * broker until the user finishes typing). Cap-gate denial-path
 * callers are out of scope for v0 (would require async continuation
 * support that doesn't exist yet); see Roadmap for the v1 plan.
 */

namespace duetos::security
{

enum class BrokerOutcome : u8
{
    Granted = 0,    ///< Authority already effective or a bounded lease was installed.
    Denied,         ///< Role table refused (no role grants this cap).
    BadPassword,    ///< Verify failed N times; broker gives up.
    Cancelled,      ///< User pressed Escape.
    NotInteractive, ///< No keyboard ready (e.g. headless boot smoke).
    NoSession,      ///< No user is currently logged in.
    InvalidCap,     ///< Bad cap argument (kCapNone, out of range).
    NoLease,        ///< Zero-grace policy cannot back an ambient grant.
    CeilingDenied,  ///< Process permanently removed this capability.
};

struct BrokerRequest
{
    duetos::core::Process* proc; ///< Target process to receive the cap on Granted.
    duetos::core::Cap cap;       ///< Capability to elevate to.
    const char* reason;          ///< Short string shown in the prompt ("FILE WRITE", etc.).
};

/// Durable authority and live cached leases return immediately.
/// Otherwise the broker resolves the role, rejects zero grace, prompts
/// through the trusted input path, and installs a bounded Process lease.
/// A permanently lowered Process ceiling always wins.
BrokerOutcome BrokerRequestElevation(const BrokerRequest& req);

/// Diagnostic helper: convert a BrokerOutcome to a short string.
const char* BrokerOutcomeName(BrokerOutcome o);

/// Per-attempt password-prompt budget. Three tries, then BadPassword.
constexpr u32 kBrokerMaxAttempts = 3;

/// Boot self-test — exercises the role-table integration without
/// actually prompting (calls a hook that injects a fake-password
/// path). Verifies that the cache + role gate behave correctly when
/// the prompt is short-circuited. Panics on regression.
void BrokerSelfTest();

/// Test hook: install a function the prompt path calls instead of
/// reading from the keyboard. Used by `BrokerSelfTest`. nullptr
/// restores the real prompt. Callers outside the self-test should
/// leave this alone.
using BrokerPromptHook = bool (*)(const char* reason, char* out_pw, u32 out_pw_cap);
void BrokerSetPromptHook(BrokerPromptHook hook);

// --------------------------------------------------------------------
// Deferred-prompt mechanism.
//
// `Ps2KeyboardReadEvent` is single-consumer by contract — two
// concurrent readers race for bytes. A shell-driven elevation works
// because the shell IS the kbd-reader thread (the dispatcher runs
// inline on it), so the direct-read in `BrokerRequestElevation` is
// safe. A Win32 PE syscall (or any future user-mode broker request)
// runs in a different task and would race the shell.
//
// The deferred path closes that gap: the broker, on detecting that
// it is NOT running on the kbd-reader thread, posts the request to
// a single-slot mailbox, injects a wakeup event so the kbd reader
// notices, and blocks on a wait queue. The kbd reader, on each
// loop iteration, calls `BrokerKbdReaderPumpDeferred()`; on a
// pending request it runs the prompt UI itself (safe — the kbd
// reader IS the legal Ps2KeyboardReadEvent consumer) and wakes the
// blocked broker task.
//
// v0 is single-flight: a second concurrent deferred request returns
// false immediately. The shell `elevate` path still uses the
// direct-read fast path (no mailbox traversal).
// --------------------------------------------------------------------

/// Record the kbd-reader task ID so the broker can pick fast-path
/// vs deferred-path. Called once from the kbd-reader bring-up in
/// `kernel/core/main.cpp`. A zero `tid` disables the fast path —
/// every broker request becomes deferred (this is the configured
/// state until the kbd reader registers itself).
void BrokerSetKbdReaderTid(u64 tid);

/// Run any pending deferred prompt from the kbd-reader thread. No-op
/// when no request is pending. Called by the kbd-reader loop after
/// each `Ps2KeyboardReadEvent` returns. Returns true if a prompt
/// was actually handled (so the caller can skip its usual routing
/// for the synthetic wake-up event that arrived alongside).
bool BrokerKbdReaderPumpDeferred();

} // namespace duetos::security
