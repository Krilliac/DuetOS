#pragma once

#include "types.h"

/*
 * CustomOS — user accounts + authentication, v0.
 *
 * Fixed-size in-memory account table. Passwords are stored as
 * salt + iterated FNV-1a 64-bit hashes — not cryptographic, but
 * an order of magnitude better than storing plaintext, and it
 * gives us a named seam to swap a real PBKDF into once kcrypto
 * lands. Every verify path pays the same iteration cost so the
 * wall-clock bound is uniform across good/bad usernames.
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
 *   - No login record / lastlog.
 *
 * Context: kernel. Mutated from the login and shell paths (both
 * in task context under the compositor lock or serialised by
 * kbd-reader sequencing). Never called from IRQ.
 */

namespace customos::core
{

constexpr u32 kAuthMaxAccounts = 16;
constexpr u32 kAuthNameMax = 32;
constexpr u32 kAuthPasswordMax = 64;

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
/// Returns true on exact username + password match. The hash
/// comparison is constant-time against the stored digest length
/// to avoid a trivial timing oracle on the password field.
bool AuthVerify(const char* username, const char* password);

/// Verify credentials AND set the session to the matched user.
/// Returns false (leaves session untouched) on bad credentials.
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
bool AuthChangePassword(const char* username, const char* old_password, const char* new_password);

/// Total number of active accounts (<= kAuthMaxAccounts).
u32 AuthAccountCount();

/// Read-only view of the `idx`-th account (0-based). `view` is
/// populated on success. Returns false on out-of-range.
bool AuthAccountAt(u32 idx, AccountView* view);

/// Look up an account by name. Populates `view` on hit. Returns
/// false on miss.
bool AuthAccountByName(const char* username, AccountView* view);

/// Boot-time self-test — verifies the seeded admin/guest accounts
/// accept their default creds and reject a wrong password. Panics
/// on failure (the auth path is a security primitive; silent
/// breakage is unacceptable).
void AuthSelfTest();

} // namespace customos::core
