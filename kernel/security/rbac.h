#pragma once

#include "proc/process.h"
#include "security/auth.h"
#include "util/types.h"

/*
 * DuetOS — Role-Based Access Control, v0.
 *
 * Roles are named bundles of `kCap*` bits with optional per-cap grace
 * duration overrides. They sit alongside `AuthRole` (`auth.h`, three
 * fixed levels: Guest / User / Admin) — `AuthRole` decides who can
 * log in and what baseline shell commands they can run; `Role`
 * decides which `kCap*` bits the elevation broker can grant to an
 * account, and for how long the grant stays cached.
 *
 * An account may be a member of multiple roles. The broker, when
 * asked to elevate to cap X, considers every role the account holds,
 * picks the FIRST one whose mask contains X, and uses that role's
 * grace override (or the default 5 min) for the cache entry.
 *
 * See wiki/security/RBAC-and-Elevation.md for the design.
 *
 * Context: kernel. Mutated only from shell commands (admin-gated) and
 * from RbacInit() at boot. Read from the broker and shell on every
 * elevation request — read paths are lock-free; the table is fixed
 * size and seeded once.
 */

namespace duetos::security
{

constexpr u32 kRbacMaxRoles = 16;
constexpr u32 kRbacRoleNameMax = 24;

/// Default grace duration in seconds when a role does not override
/// for a specific cap. 300 = 5 minutes.
constexpr u32 kRbacDefaultGraceSeconds = 300;

/// Sentinel grace value meaning "always reprompt; never cache."
/// A role policy that sets a cap's override to 0 yields no_cache
/// semantics for that cap.
constexpr u32 kRbacNoGrace = 0;

/// Maximum per-cap grace override (1 hour). Forever-allow is what a
/// role's cap-mask grants by default; it is intentionally NOT a per-
/// app knob (see CLAUDE.md design discussion).
constexpr u32 kRbacMaxGraceSeconds = 3600;

/// Stable handle into the role table. 0..kRbacMaxRoles-1 are the
/// live slots; kRbacRoleInvalid (== UINT32_MAX) is the "no match"
/// sentinel returned by lookups.
using RoleId = u32;
constexpr RoleId kRbacRoleInvalid = ~0u;

struct RolePolicy
{
    /// Cap bits this role can elevate to. A u64 bitmap, same shape
    /// as `CapSet::bits`. Bit `n` set means a member of this role
    /// can elevate to cap `n` (i.e. `kCap*` enumerator value `n`).
    u64 cap_mask;

    /// Per-cap grace override. `grace_seconds[c]` is the cache
    /// lifetime for cap `c` once elevated under this role. A value
    /// of `0xFFFF` (the sentinel) means "use kRbacDefaultGraceSeconds";
    /// `kRbacNoGrace` (== 0) means "always reprompt"; any other value
    /// is the literal cache lifetime in seconds (clamped to
    /// kRbacMaxGraceSeconds).
    static constexpr u16 kUseDefault = 0xFFFF;
    u16 grace_seconds[duetos::core::kCapCount];
};

struct Role
{
    char name[kRbacRoleNameMax];
    RolePolicy policy;
    bool in_use;
};

/// Account-to-role membership. Each account row carries a bitmap
/// indicating which roles it belongs to. We store this here (rather
/// than on `AuthAccount` in `auth.cpp`) so the RBAC slice can grow
/// independently of the auth table layout — they are joined by
/// account name, lazily, in the broker.
struct AccountMembership
{
    char username[duetos::core::kAuthNameMax];
    u32 role_mask; // bit i set => member of role with RoleId == i
    bool in_use;
};

/// Seed the built-in role table:
///   root       — every defined kCap*; no_cache on kCapNetAdmin.
///   developer  — FsRead, FsWrite, SpawnThread, Debug, SerialConsole, Input
///                (kCapFsWrite override: 30 min)
///   netop      — Net, NetAdmin, FsRead (no_cache on kCapNetAdmin)
///   auditor    — FsRead, SerialConsole, Input
///   sandbox    — empty mask (explicit deny role)
///
/// Idempotent — re-seeding wipes any runtime-added roles. Also seeds
/// default memberships: `admin` → root; `guest` → sandbox; built-in
/// `user` (if present) → developer.
///
/// Caller: kernel/core/main.cpp, after AuthInit() so the default
/// memberships have account rows to bind to.
void RbacInit();

/// Look up a role by name. Returns kRbacRoleInvalid on miss.
RoleId RbacFindRole(const char* name);

/// Read-only view of a role. Returns false on invalid id.
bool RbacGetRole(RoleId id, Role* out);

/// Register a new role. Returns the assigned RoleId, or
/// kRbacRoleInvalid if the table is full, the name duplicates an
/// existing entry, or the name is empty / over-long. Caller-side
/// admin gating is enforced by the shell command, not here.
RoleId RbacRegisterRole(const char* name, const RolePolicy& policy);

/// Add a user to a role. Returns false if the user or role doesn't
/// exist, or if the membership table is full.
bool RbacAddMembership(const char* username, RoleId role);

/// Remove a user from a role. Returns false if the user is not a
/// member. Idempotent on a clean state — removing the last role
/// leaves the user with an empty role_mask; the broker will deny
/// every elevation request.
bool RbacRemoveMembership(const char* username, RoleId role);

/// True iff the named account belongs to the role.
bool RbacIsMember(const char* username, RoleId role);

/// Lookup: which roles does this account hold? Returns the
/// role_mask; 0 means "no roles" (broker denies every request).
u32 RbacAccountRoleMask(const char* username);

/// Broker query: can this account elevate to `cap` via ANY of its
/// roles? `*out_role` receives the role that grants it (the FIRST
/// matching role in id order), and `*out_grace_seconds` receives
/// the cache lifetime that role assigns to this cap (defaulting to
/// kRbacDefaultGraceSeconds when the role doesn't override). On
/// "no role grants this cap", returns false and leaves the outputs
/// untouched.
bool RbacResolveElevation(const char* username, duetos::core::Cap cap, RoleId* out_role, u32* out_grace_seconds);

/// Total live role count.
u32 RbacRoleCount();

/// Iteration support for the `roles` shell command.
bool RbacRoleAt(u32 idx, Role* out);

/// Boot self-test — verifies the built-in roles seed correctly,
/// memberships round-trip, and the resolve path returns the
/// expected role/grace pair for representative cap requests on
/// known accounts. Panics on mismatch (cap policy is load-bearing).
void RbacSelfTest();

// ---------------------------------------------------------------------
// Persistence bridge — see wiki/security/Persistence.md.
//
// Mirrors the AuthExportSnapshot / AuthImportSnapshot shape: an RBAC
// snapshot encodes the current role table + the membership table
// into a single Argon2id-KEK + ChaCha20-Poly1305 envelope. The boot
// path's "writable-FS slice" will land both auth + RBAC snapshots in
// /system/secrets/.
//
// Account-name strings inside memberships are byte-preserved so a
// future cross-snapshot import order (RBAC before Auth) doesn't
// dangle — the memberships still bind by name, the auth slice just
// hasn't filled the matching account rows yet.
// ---------------------------------------------------------------------

struct RbacSnapshotParams
{
    u32 memory_kib;
    u32 time_cost;
    u32 parallelism;
};

/// Maximum encoded envelope size for the current role + membership
/// table. Returns 0 when both are empty. Use to size the buffer
/// passed to RbacExportSnapshot.
u32 RbacSnapshotEncodedSize();

/// Encode the live role + membership tables into `out`. The buffer
/// must be at least RbacSnapshotEncodedSize() bytes. Returns false
/// on parameter validation failure or KEK-derivation failure.
bool RbacExportSnapshot(const char* password, const RbacSnapshotParams& params, u8* out, u32 out_capacity,
                        u32* out_len);

/// Decode an envelope and atomically replace the live role +
/// membership tables. Returns false on malformed header, MAC
/// mismatch, version mismatch, or wrong password.
bool RbacImportSnapshot(const char* password, const u8* in, u32 in_len);

/// Boot self-test for the RBAC snapshot round-trip: exports the
/// seeded role table + memberships, mutates one row, imports back,
/// verifies the mutation was reverted. Panics on regression.
void RbacSnapshotSelfTest();

} // namespace duetos::security
