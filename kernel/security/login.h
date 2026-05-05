#pragma once

#include "util/types.h"

/*
 * DuetOS — login gate (terminal + GUI), v0.
 *
 * Sits between boot-time subsystem bring-up and the interactive
 * shell. While the gate is active, the kbd-reader thread routes
 * every keystroke to `LoginFeedKey` instead of the shell. On
 * successful authentication the gate deactivates, triggers a
 * repaint (so the login background is replaced with the desktop
 * or TTY shell), and the shell resumes normal input handling.
 *
 * Two UI flavours, selected at activation time:
 *
 *   LoginMode::Tty     — simple `username:` / `password:` prompt
 *                        drawn into the framebuffer console.
 *                        Password echo is masked.
 *
 *   LoginMode::Gui     — full-screen welcome panel (winlogon-
 *                        flavour) with centered login box, mock
 *                        user avatar, Tab-navigated fields.
 *                        Drawn directly to the framebuffer.
 *
 * Scope limits:
 *   - Single concurrent session (see auth.h). `LoginStart` after
 *     another session is active simply replaces it.
 *   - No lockout after N failed attempts; v0 just re-prompts.
 *   - No reboot / shutdown buttons on the GUI — those are shell
 *     commands today (`reboot`, `halt`).
 *   - TTY login doesn't hide the echo of "username:" input; only
 *     the password field is masked.
 *
 * Context: kernel. Activation from main.cpp after the compositor
 * + console are up; mutation from the kbd-reader thread under
 * the compositor lock (same discipline as every GUI call).
 */

namespace duetos::core
{

enum class LoginMode : u8
{
    Tty = 0,
    Gui = 1,
};

/// Activate the login gate in the chosen mode and paint the
/// initial UI. After this returns the gate is "up" — the kbd
/// reader should route keys to LoginFeedKey instead of the
/// shell. Must be called with the compositor lock held.
void LoginStart(LoginMode mode);

/// True iff the gate is currently blocking input (no user
/// authenticated yet OR explicitly reactivated by `logout`).
bool LoginIsActive();

/// Which UI flavour is currently active. Meaningless when
/// !LoginIsActive().
LoginMode LoginCurrentMode();

/// Feed one keystroke to the login gate. `code` is the PS/2
/// key-event code (same enum the main kbd reader uses —
/// printable ASCII for regular chars, kKeyEnter / kKeyBackspace
/// / kKeyTab / kKeyEscape for special keys). Returns true if
/// the login gate is still active after processing, false if
/// the keystroke completed authentication and the gate
/// deactivated. Must be called with the compositor lock held;
/// performs its own framebuffer drawing for the updated field
/// state.
bool LoginFeedKey(u16 code);

/// Re-paint the login UI from scratch (call after any
/// framebuffer state change that might have clobbered the
/// background — screen mode flip, window drag, etc.). No-op
/// when !LoginIsActive(). Caller holds the compositor lock.
void LoginRepaint();

/// External trigger for `logout` to re-open the gate. Clears
/// the session, drops back to the mode last shown (or Gui if
/// called before the first activation), re-paints.
void LoginReopen();

/// Lock the screen: re-engage the gate WITHOUT clearing the
/// auth session. Captures the active user at lock time and
/// rejects unlock attempts with any other username — Windows-
/// style "only the same user can unlock". A different user
/// must explicitly log out (the existing `logout` shell
/// command, or LoginReopen) to clear the lock policy and
/// reach a fresh login. Differs from LoginReopen by skipping
/// AuthLogout.
/// GAP: on-screen "switch user" affordance distinct from
/// logout deferred to a follow-up slice.
void LoginLock();

// ---------------------------------------------------------------
// Idle-timeout auto-lock.
//
// Every kbd / mouse ingest path stamps `InputActivityStamp` at
// receive time. A dedicated `idle-lock` task wakes once a second,
// computes `now - last_activity`, and if the gap exceeds the
// configured threshold and a session is currently active, calls
// `LoginLock()` so the box re-prompts when the operator returns.
// Threshold defaults to 600 s (10 minutes) and is overridable via
// the kernel cmdline `idlelock=<seconds>` token (set to 0 to
// disable auto-lock entirely).
//
// Stamping is deliberately Cli-bracketed in the input drivers so
// the value is observed atomically; reads use a single 64-bit
// load (which is naturally atomic on x86_64 for aligned 8-byte
// memory). No lock is needed for the read path.
// ---------------------------------------------------------------

/// Note an input event for the idle-lock heuristic. Cheap —
/// stores the current tick into a global. Safe to call from
/// any context.
void InputActivityStamp();

/// Last-activity timestamp in scheduler ticks. Initialised at
/// boot to NowTicks() so the first idle window is the full
/// threshold rather than "since 1970".
u64 InputLastActivityTicks();

/// Configure the idle-lock threshold. Seconds of input idleness
/// after which `LoginLock` fires. 0 disables auto-lock entirely.
void IdleLockSetThresholdSeconds(u32 seconds);
u32 IdleLockThresholdSeconds();

/// Spawn the periodic `idle-lock` watcher task. Idempotent —
/// subsequent calls are no-ops. Wired from `kernel/core/main.cpp`
/// after the scheduler is online.
void IdleLockTaskStart();

/// Cooperative one-shot check used by tests + the watcher loop.
/// Returns true if it triggered a LoginLock call. The caller
/// must hold no compositor lock — the helper takes it itself
/// when locking.
bool IdleLockCheckOnce();

/// Boot self-test: verifies the threshold accessor, the
/// activity stamp ordering, and that `IdleLockCheckOnce`
/// triggers when the synthetic clock crosses the threshold
/// without firing for sub-threshold gaps. Does NOT actually
/// lock the screen — the test runs before any session opens.
void IdleLockSelfTest();

} // namespace duetos::core
