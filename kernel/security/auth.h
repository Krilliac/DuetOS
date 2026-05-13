#pragma once

#include "util/types.h"

/*
 * DuetOS — user accounts + authentication, v1.
 *
 * Fixed-size in-memory account table. Passwords are stored as
 * `duetos::security::PasswordHashRecord` (PBKDF2-HMAC-SHA256 over
 * a 16-byte random salt drawn from the kernel entropy pool, with
 * the default iteration count locked in `password_hash.h`). The
 * record is the same 56-byte shape that will eventually serialise
 * to disk once a persistent user table lands — at that point this
 * file's only change is to read the records from disk instead of
 * deriving them at boot. Every verify path runs a full PBKDF2
 * derivation (against either the stored record or a decoy) so the
 * wall-clock bound is uniform across "user not found", "user found
 * with wrong password", "user found with right password", and
 * "user found but locked out".
 *
 * Each account row carries metadata alongside the hash:
 *   - created_ns      — MonotonicNs at AuthAddUser / AuthInit time
 *   - last_login_ns   — MonotonicNs of most recent successful auth
 *   - last_attempt_ns — MonotonicNs of most recent verify (any leaf)
 *   - failed_attempts — consecutive bad-password count since last
 *                       success or unlock
 *   - total_logins    — lifetime count of successful logins
 *   - locked_until_ns — 0 if unlocked; otherwise the MonotonicNs at
 *                       which the lockout expires
 *
 * Brute-force lockout: after `kAuthLockoutThreshold` consecutive
 * failed attempts (default 5) an account is locked for
 * `kAuthLockoutDurationNs` (default 60 s). Locked accounts reject
 * AuthVerify even with the correct password until the lockout
 * expires; a successful verify resets the failed-attempt counter.
 * Admins can clear lockout immediately via AuthUnlockUser.
 *
 * Auth events publish to the security event ring (see event_ring.h):
 *   - AuthLoginSuccess     on successful AuthLogin
 *   - AuthLoginFailure     on rejected AuthVerify (any leaf)
 *   - AuthAccountLocked    when threshold crosses
 *   - AuthAccountUnlocked  when admin clears or lockout expires
 *   - AuthAccountCreated   on AuthAddUser
 *   - AuthAccountDeleted   on AuthDeleteUser
 *   - AuthPasswordChanged  on AuthChangePassword
 *
 * Session model: a single currently-logged-in user (session id +
 * username + admin flag). Terminal and GUI login both flip this
 * one slot; `logout` clears it; the shell's login gate refuses
 * to accept input when no session is active.
 *
 * Scope limits (spelled out so the next slice knows what to fix):
 *   - 16 accounts max (fits the "demo + family + admin" scale).
 *   - 31-char username cap, 63-char password cap.
 *   - No persistence. Accounts added at runtime disappear on
 *     reboot; defaults are re-seeded on every AuthInit.
 *   - No per-user home dirs, no UID/GID mapping into the VFS.
 *     Capability-gated commands use `AuthIsAdmin()` only.
 *   - Lockout policy is global; no per-account override.
 *
 * Init ordering: `AuthInit` calls `PasswordHashCreate` while
 * seeding the built-in admin account, which draws salt bytes from
 * the kernel entropy pool. `RandomInit` therefore MUST have run
 * before `AuthInit`. The boot sequence in `kernel/core/main.cpp`
 * already enforces this ordering. The security event ring storage
 * is `constinit` so AuthInit is also free to publish before the
 * event ring's own Init runs.
 *
 * Context: kernel. Mutated from the login and shell paths (both
 * in task context under the compositor lock or serialised by
 * kbd-reader sequencing). Never called from IRQ.
 */

namespace duetos::core
{

constexpr u32 kAuthMaxAccounts = 16;
constexpr u32 kAuthNameMax = 32;
constexpr u32 kAuthPasswordMax = 64;

// Brute-force lockout policy. After this many consecutive failed
// AuthVerify calls against a given account, the account is locked
// for kAuthLockoutDurationNs. A successful verify or an explicit
// AuthUnlockUser zeros the failed-attempts counter.
constexpr u32 kAuthLockoutThreshold = 5;
constexpr u64 kAuthLockoutDurationNs = 60ull * 1000ull * 1000ull * 1000ull; // 60 s

enum class AuthRole : u8
{
    Guest = 0, // login only
    User = 1,  // login + non-admin commands
    Admin = 2, // full privilege
};

struct AccountView
{
    const char* username;
    AuthRole role;
    bool has_password;
    bool locked;         // locked_until_ns is in the future
    u64 created_ns;      // when AuthAddUser / AuthInit allocated the row
    u64 last_login_ns;   // 0 if never logged in
    u64 last_attempt_ns; // 0 if never attempted
    u64 locked_until_ns; // 0 if not locked
    u32 failed_attempts; // consecutive failures since last success / unlock
    u32 total_logins;    // lifetime successful logins
};

/// Seed the account table with the two built-in accounts:
///   admin  / admin   (role=Admin)
///   guest  /         (role=Guest, empty password)
/// Idempotent — re-seeding wipes any runtime-added accounts and
/// restores the defaults. Call exactly once during boot before
/// any login gate runs.
void AuthInit();

/// True iff a session is currently active (someone is logged in).
bool AuthIsAuthenticated();

/// NUL-terminated username of the active session, or "" if none.
const char* AuthCurrentUserName();

/// Role of the active session. Returns Guest if no session.
AuthRole AuthCurrentRole();

/// Convenience: role of the active session is Admin.
bool AuthIsAdmin();

/// Verify credentials against the table without mutating session.
/// Returns true on exact username + password match against an
/// account that is not currently locked out. Internally runs a
/// full PBKDF2-HMAC-SHA256 derivation against either the stored
/// hash record or a decoy record (when the username does not
/// exist) so the wall-clock cost is independent of which leaf of
/// the lookup the caller landed on; the final compare is
/// constant-time across the digest. Updates per-account metadata
/// (last_attempt_ns, failed_attempts, locked_until_ns) and
/// publishes the matching event-ring entry.
bool AuthVerify(const char* username, const char* password);

/// Verify credentials AND set the session to the matched user.
/// Returns false (leaves session untouched) on bad credentials or
/// a locked account.
bool AuthLogin(const char* username, const char* password);

/// Clear the session slot. Idempotent — no-op when nothing is
/// active.
void AuthLogout();

/// Create a new account. Returns false if the table is full, the
/// username already exists, the name is empty, exceeds the length
/// cap, or contains a non-printable / whitespace character.
/// Caller-side policy (only Admin may call this) is enforced by
/// the shell command, not here — the kernel API is pure data.
bool AuthAddUser(const char* username, const char* password, AuthRole role);

/// Delete an account by name. Returns false if the user doesn't
/// exist or is the last admin. Deleting the currently-logged-in
/// user succeeds but also clears the session.
bool AuthDeleteUser(const char* username);

/// Change an account's password. If `old_password` is non-null,
/// it must match (self-service flow). Admins may pass nullptr
/// for `old_password` to force-reset another user's password.
/// A successful change clears any existing lockout on the account.
bool AuthChangePassword(const char* username, const char* old_password, const char* new_password);

/// Clear lockout state on an account: zeroes the failed-attempts
/// counter and lifts any active timed lockout. Returns false if
/// the user does not exist. Caller-side policy (admin-only) is
/// enforced by the shell command. Publishes AuthAccountUnlocked
/// only when the account was actually locked at call time.
bool AuthUnlockUser(const char* username);

/// True iff the named account is currently locked out (verify
/// would refuse). False for unknown users.
bool AuthIsLocked(const char* username);

/// Total number of active accounts (<= kAuthMaxAccounts).
u32 AuthAccountCount();

/// Read-only view of the `idx`-th account (0-based). `view` is
/// populated on success. Returns false on out-of-range.
bool AuthAccountAt(u32 idx, AccountView* view);

/// Look up an account by name. Populates `view` on hit. Returns
/// false on miss.
bool AuthAccountByName(const char* username, AccountView* view);

/// Boot-time self-test — verifies the seeded admin/guest accounts
/// accept their default creds and reject a wrong password,
/// exercises the lockout state machine end-to-end, and confirms
/// auth events make it onto the security event ring. Panics on
/// failure (the auth path is a security primitive; silent
/// breakage is unacceptable).
void AuthSelfTest();

// ---------------------------------------------------------------------
// Persistence bridge (wiki/security/Persistence.md).
//
// Encodes the current in-memory account table into a single
// encrypted blob via the security/persistence.h envelope
// (Argon2id KEK + ChaCha20-Poly1305 AEAD). The reverse path
// imports a previously-encoded blob, replacing the in-memory
// table on success.
//
// Today these run against caller-provided buffers — there is no
// writable system FS yet, so the kernel doesn't actually persist
// across reboots. The slice that brings up `/system/secrets/`
// will call AuthExportSnapshot after every mutation and feed the
// blob to the VFS; the boot path will call AuthImportSnapshot
// before AuthInit's hardcoded-seed fallback. The shape of those
// callers is pinned by the API here.
//
// Both calls take the encrypting password (typically the admin's
// password at the time of write / read) and Argon2id KDF params.
// They are kernel-mediated like every other auth API — no
// subsystem code calls them directly.
// ---------------------------------------------------------------------

struct AuthSnapshotParams
{
    u32 memory_kib;
    u32 time_cost;
    u32 parallelism;
};

/// Compute the maximum encoded size of the current account table.
/// Caller uses this to size the buffer passed to
/// AuthExportSnapshot. Returns 0 if the table is empty.
u32 AuthSnapshotEncodedSize();

/// Encode the current account table into `out`. On success
/// `*out_len` carries the bytes written. Returns false on
/// validation failure (null buffers, capacity too small, password
/// empty, Argon2id derive failure).
bool AuthExportSnapshot(const char* password, const AuthSnapshotParams& params, u8* out, u32 out_capacity,
                        u32* out_len);

/// Decode an envelope and replace the in-memory account table
/// with its contents. Returns false on header malformation,
/// MAC mismatch, version mismatch, or wrong password — the table
/// is NOT touched in any of those cases (the import is atomic).
/// Returns true on a successful import; the live session (if any)
/// is logged out as a side effect.
bool AuthImportSnapshot(const char* password, const u8* in, u32 in_len);

/// Boot self-test for the snapshot round-trip: exports the seeded
/// admin/guest table, mutates one slot in the live table, imports
/// the snapshot back, verifies the mutation was reverted. Panics
/// on regression.
void AuthSnapshotSelfTest();

} // namespace duetos::core
