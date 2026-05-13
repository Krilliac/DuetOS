# Authentication and Login

> **Audience:** Security reviewers, operators, anyone running DuetOS on
> hardware where multiple humans share the same console
>
> **Execution context:** Kernel — auth code runs in process context; the
> login surface runs as a kernel UI app
>
> **Maturity:** v0 — TTY + GUI login; PBKDF2/Argon2id-hashed accounts; idle
> lock; in-memory account table with persistence-envelope sidecar

## Overview

DuetOS gates the desktop on a **login**. The model is single-tier (no
guest / multi-user-switching yet) but multi-account: every account is a
named entry in the kernel account table with its own password hash and
role bundle. From the first boot's "create initial account" prompt
through every subsequent unlock, the auth path goes through one set of
APIs.

The pieces:

- [`kernel/security/auth.h`](../../kernel/security/auth.h) — account
  table, login state, session ownership.
- [`kernel/security/login.h`](../../kernel/security/login.h) — TTY + GUI
  login surface, idle lock.
- [`kernel/security/password_hash.h`](../../kernel/security/password_hash.h) —
  V1 PBKDF2 + V2 Argon2id password hashing.
- [`kernel/security/rbac.h`](../../kernel/security/rbac.h) — role → cap
  mask resolution.
- [`kernel/security/broker.h`](../../kernel/security/broker.h) +
  [`grace.h`](../../kernel/security/grace.h) — elevation flow + grace
  cache.
- [`kernel/security/event_ring.h`](../../kernel/security/event_ring.h) —
  AuthLoginSuccess / Failure / AccountLocked events.
- [`kernel/security/persistence.h`](../../kernel/security/persistence.h) —
  ChaCha20-Poly1305-sealed account table at rest. See
  [Persistence](Persistence.md).

## Login Flow

```
   power on
       |
   boot self-tests + auth init
       |
   LoginStart()                    (kernel/security/login.cpp)
       |
   prompt for username + password
       |
   AuthLogin(name, password)       (kernel/security/auth.cpp)
       |
       ├-- lookup account
       ├-- PasswordVerify(stored_hash, candidate)  (kernel/security/password_hash.cpp)
       │                                            ├-- detects V1 vs V2 by tag
       │                                            ├-- V1: PBKDF2-HMAC-SHA256
       │                                            └-- V2: Argon2id
       ├-- on success: install session, log AuthLoginSuccess
       └-- on failure: bump fail counter, log AuthLoginFailure
              after N consecutive failures: account locked
       |
   session active → desktop / shell available
       |
   idle for `idlelock=<seconds>` (default 600)
       |
   LoginLock() → blank screen, re-prompt
```

Logging out (`logout`) tears the session down and re-prompts.

Switching users (`su <name>`) requires the target account's password
and replaces the current session. The grace cache (below) is dropped
on `su` — elevations belong to the previous session.

## Password Hashing — V1 and V2

Two on-disk schemes coexist:

| Version | Algorithm | Iterations / Cost | Use when |
|---------|-----------|-------------------|----------|
| V1 | PBKDF2-HMAC-SHA256 | 100,000 (emulator boot) / 600,000 (bare metal) | Legacy accounts, accounts created before V2 landed |
| V2 | Argon2id (RFC 9106) | per-record params (memory 8–1024 KiB, t ≥ 1, p ≥ 1) | New accounts |

Format on disk (per account record, ASCII for V1, tagged for V2):

```
v1$<salt_hex>$<digest_hex>
v2$argon2id$m=<KiB>,t=<iters>,p=<lanes>$<salt_b64>$<digest_b64>
```

On a successful login against a V1 record, the kernel **lazily
upgrades** the on-disk hash to V2 — the user supplied the plaintext,
the new V2 hash gets written before the session is handed off. That
means an account is upgraded the first time the user logs in after V2
ships; no operator action required.

The bare-metal vs emulator iteration counts differ because PBKDF2 has
no parameter that scales with memory — on QEMU, 600 k iters at the
HPET cadence is slow enough to annoy the boot smoke profile. The
runtime detects the hypervisor flag and picks the right count. V2
Argon2id avoids the problem because its parameters are stored in the
record itself.

## Account Table

The account table lives in kernel memory while running and is sealed
to disk under ChaCha20-Poly1305 (see [Persistence](Persistence.md)).
Per-entry fields:

- Account name (≤ 32 UTF-8 chars)
- Password hash record
- Role bundle name (resolved through `rbac.h`)
- Fail counter + lockout timestamp
- Last-success timestamp
- Per-account flags (must-change-password-on-login, disabled)

The persistence envelope's key is derived via Argon2id from a
device-bound secret — see the Persistence page for the KEK derivation
recipe.

## Role-Based Access Control

[`rbac.h`](../../kernel/security/rbac.h) resolves a role bundle name
to a `kCap*` mask. The built-in bundles:

| Role | Caps |
|------|------|
| **root** | all caps; `kCapNetAdmin` flagged `no_cache` so grace doesn't suppress prompts |
| **developer** | `kCapFsRead`, `kCapFsWrite`, `kCapSpawnThread`, `kCapDebug`, `kCapSerialConsole`, `kCapInput`; 30-minute grace on `kCapFsWrite` |
| **netop** | `kCapNet`, `kCapNetAdmin`, `kCapFsRead`; `no_cache` on `kCapNetAdmin` |
| **auditor** | `kCapFsRead`, `kCapSerialConsole`, `kCapInput` |
| **sandbox** | none; explicit deny — for processes spawned into a hard sandbox |

`RbacResolveElevation(account, requested_cap)` is the entry point the
broker calls when an elevation prompt fires.

See [RBAC and Elevation](RBAC-and-Elevation.md) for the policy
discussion and how to add a new role.

## Elevation and Grace Cache

The broker ([`broker.h`](../../kernel/security/broker.h)) handles
"this process needs cap X but doesn't currently hold it":

1. The kernel sees a cap-gate denial in a syscall path.
2. The broker is invoked with `(pid, cap)`. The grace cache
   ([`grace.h`](../../kernel/security/grace.h)) is consulted first; if
   `(pid, cap)` is present and the deadline hasn't expired, the cap is
   granted silently and the syscall retried.
3. On a cache miss, the broker prompts the user for the account
   password (up to 3 attempts).
4. On success, the cap is granted to the process and an entry is
   added to the grace cache for the role's grace window (default 5
   minutes; per-cap override available).
5. On failure, the syscall returns `ErrorCode::Forbidden`.

The grace cache is in-memory only — 64 slots, linear scan, evict
earliest-deadline on full. Cleared on process exit.

Shell command: `elevate <cap>` prompts for elevation up-front (used
when an operator wants to acquire the cap before running a sequence
of commands). `elevations` lists currently-active grants.

## Shell Surface

| Command | Purpose | Cap |
|---------|---------|-----|
| `users` | list accounts | open |
| `useradd <name>` | create new account (prompts for password + role) | `kCapUserAdmin` |
| `userdel <name>` | delete account | `kCapUserAdmin` |
| `passwd [<name>]` | change password (self by default) | self: open; other: `kCapUserAdmin` |
| `logout` | end current session | open |
| `su <name>` | switch to another account | open (prompts for target's password) |
| `login` | re-launch login surface (mostly used via lock) | open |
| `elevate <cap>` | acquire cap for the grace window | broker prompt |
| `elevations` | list current grants | open |
| `roles`, `roleadd`, `roledel` | role bundle management | `kCapUserAdmin` |
| `secevents` | dump security event ring (filtered) | `kCapAudit` |
| `caplog` | dump recent cap denials | `kCapAudit` |
| `idlelock` | configure / trigger idle lock | self: open; settings: `kCapUserAdmin` |

## Event Ring

Every login / unlock / lock / failure / lockout / password change /
elevation prompt fires a structured event into the security event ring
([`event_ring.h`](../../kernel/security/event_ring.h)):

- `AuthLoginSuccess` — account, session id
- `AuthLoginFailure` — account (or "<unknown>"), failed-attempt count
- `AuthAccountLocked` — account, lockout duration
- `AuthAccountUnlocked` — account
- `AuthPasswordChanged` — account
- `BrokerElevationGranted` — pid, cap, role
- `BrokerElevationDenied` — pid, cap, reason

`secevents` filters by kind for an operator dashboard.

## Idle Lock

The login surface watches the input router. When no event has occurred
in `idlelock=<seconds>` (kernel cmdline; default 600 = 10 minutes), the
desktop is hidden behind the lock prompt. Unlock follows the same path
as initial login — only the current account is allowed.

## Threading and Locking

- The account table is guarded by a single spinlock. Reads (lookups by
  name during login attempt) are fast enough that no read-side
  optimisation is warranted.
- Password verification is **slow on purpose** (Argon2id memory-hard).
  It runs outside the lock so a parallel login attempt isn't blocked.
- The event ring is lock-free (single writer per direction).
- The grace cache is guarded by a spinlock; lookup is linear over 64
  slots so the lock is held for sub-microsecond windows.

## Boot Self-Test

The auth subsystem's boot self-test:

- Creates a temporary account, hashes a password (both V1 and V2),
  verifies, fails-on-wrong-password, asserts the failure counter
  increments.
- Asserts the lockout triggers after the configured fail count.
- Asserts the persistence envelope round-trips the table cleanly.

A failure fires `kBootSelftestFail`.

## Known Limits / GAPs

- **Single-tier model.** No `sudo`-without-su; broker is the elevation
  primitive.
- **No guest account / no fast-user-switching.** v0.
- **No PAM-style plugin chain.** Auth is hard-coded to local password.
- **No 2FA.** TOTP / WebAuthn / FIDO2 — Roadmap.
- **No Kerberos / domain login.** Local accounts only.
- **Grace cache is global per pid.** Per-thread or per-syscall-class
  granularity not modelled.
- **Lockout duration is fixed.** Adaptive (exponential) backoff is a
  Roadmap entry.

## Related Pages

- [Capabilities](Capabilities.md) — `kCap*` table the roles map to
- [RBAC and Elevation](RBAC-and-Elevation.md) — role policy
- [Persistence](Persistence.md) — sealed account table on disk
- [Crypto Primitives](../kernel/Crypto.md) — Argon2id, PBKDF2,
  ChaCha20-Poly1305
- [Sandboxing](Sandboxing.md) — `sandbox` role
- [Driver Domains](Driver-Domains.md) — driver isolation runs
  independently of auth
- [Shell Commands](../reference/Shell-Commands.md) — full command grid
