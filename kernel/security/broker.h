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
 *   - mutates kernel state without going through the cap-gate
 *     contract (it adds bits to `proc->caps` for the grant window,
 *     which is the explicit kCap* surface).
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
    Granted = 0,    ///< Password verified, grant cached, cap added to proc.
    Denied,         ///< Role table refused (no role grants this cap).
    BadPassword,    ///< Verify failed N times; broker gives up.
    Cancelled,      ///< User pressed Escape.
    NotInteractive, ///< No keyboard ready (e.g. headless boot smoke).
    NoSession,      ///< No user is currently logged in.
    InvalidCap,     ///< Bad cap argument (kCapNone, out of range).
};

struct BrokerRequest
{
    duetos::core::Process* proc; ///< Target process to receive the cap on Granted.
    duetos::core::Cap cap;       ///< Capability to elevate to.
    const char* reason;          ///< Short string shown in the prompt ("FILE WRITE", etc.).
};

/// Try to grant `cap` to `req.proc`. Implements:
///   1. Cache lookup. Hit → Granted (no prompt).
///   2. Role resolution. Miss → Denied.
///   3. Prompt (kernel-trusted). Cancel/Bad → Cancelled/BadPassword.
///   4. Cache insert (skip if role's grace override is kRbacNoGrace).
///   5. Add cap bit to `req.proc->caps`. Publishes an EventRing entry.
///
/// On any non-Granted return the caller's caps are not modified.
/// Synchronous — blocks on keyboard input until the prompt resolves.
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

} // namespace duetos::security
