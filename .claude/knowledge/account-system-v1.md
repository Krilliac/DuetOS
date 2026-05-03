# Account system v1 — metadata + brute-force lockout + event publish

_Type: Decision + Pattern + Observation._
_Status: Active._
_Last updated: 2026-05-03._

## What landed

Builds on the v0 PBKDF2-HMAC-SHA256 swap (see
`crypto-os-core-and-password-hash-v0.md`). The crypto layer is
unchanged — every account still stores a `PasswordHashRecord` and
every verify path still runs PBKDF2-HMAC-SHA256 + constant-time
compare. v1 redesigns the account row, the verify path, and the
shell around three additions:

1. **Per-account metadata** — `created_ns`, `last_login_ns`,
   `last_attempt_ns`, `failed_attempts`, `total_logins`,
   `locked_until_ns` carried alongside the hash record. Visible
   to admins through `AccountView` and the `users` shell command.

2. **Brute-force lockout** — after `kAuthLockoutThreshold = 5`
   consecutive failed `AuthVerify` calls, the account is locked
   for `kAuthLockoutDurationNs = 60s`. Locked accounts reject
   verify even with the correct password until the lockout
   expires. A successful verify (or admin `AuthUnlockUser`) zeros
   the failure counter. `AccountIsLocked` auto-thaws expired
   lockouts on entry, so no separate sweeper is needed.

3. **Auth event publication** — every auth-relevant transition
   publishes to the security event ring (`event_ring.h`):
   - `AuthLoginSuccess` on successful `AuthLogin`
   - `AuthLoginFailure` on rejected `AuthVerify` (any leaf —
     unknown user, wrong password, locked account)
   - `AuthAccountLocked` when threshold crosses (aux1 = failure
     count, aux2 = lockout duration)
   - `AuthAccountUnlocked` when admin clears or lockout expires
   - `AuthAccountCreated`, `AuthAccountDeleted`,
     `AuthPasswordChanged` on the corresponding API call

   The event ring's storage is `constinit` so AuthInit is free
   to publish even though `EventRingInit` runs later in boot.

### Files touched

- `kernel/security/auth.{h,cpp}` — Account struct extended with
  metadata; `AccountView` likewise. New `AuthUnlockUser` and
  `AuthIsLocked` API. `AuthVerify` updates metadata + publishes
  events; lockout thaw is inline. `AuthSelfTest` exercises the
  full lockout state machine (probe account → drive 5 failures →
  assert locked → assert correct-pw rejected while locked →
  unlock → assert correct-pw accepted → cleanup).
- `kernel/security/password_hash.h` — preamble doc updated; the
  old "future replacement" wording was stale once `auth.cpp`
  became the actual consumer in v0.
- `kernel/security/event_ring.{h,cpp}` — 7 new `EventKind` values
  + matching name-table entries.
- `kernel/security/ir_runbook.cpp` — proper IR runbook entries
  for the two attack-signal events (`AuthLoginFailure`,
  `AuthAccountLocked`); the bookkeeping events
  (`AuthLoginSuccess`, `AuthAccountUnlocked`,
  `AuthAccountCreated`, `AuthAccountDeleted`,
  `AuthPasswordChanged`) are opted out.
- `kernel/shell/shell_security.cpp` — `users` extended to show
  `LOCKED`, `fails=N`, `logins=N`. New `CmdUnlock` admin command.
- `kernel/shell/shell_internal.h` + `kernel/shell/shell_dispatch.cpp`
  — register `unlock`.

## Why this shape

- **Lockout in the kernel, not the login UI.** The v0 login.h
  preamble already noted "No lockout after N failed attempts; v0
  just re-prompts" as a scope limit. Putting the lockout at the
  `AuthVerify` boundary covers every caller (terminal login,
  GUI login, shell `su`, shell `login`) without each having to
  re-implement the policy. Locked accounts also burn an
  equivalent PBKDF2 cycle against the decoy record so the wall
  clock doesn't betray the lock state.
- **Auto-thaw on entry**, not via a sweeper task. The kernel has
  enough background work; another timer wakeup for ~5 accounts
  is overkill. `AccountIsLocked` checks the wall clock on every
  call into `AuthVerify` / `AuthIsLocked` and clears the
  lockout if it has expired, publishing `AuthAccountUnlocked`.
- **Event ring instead of klog.** Lockout / login activity is
  exactly the kind of structured signal `event_ring` exists for —
  a forensic walk wants `kind == AuthLoginFailure` filtered, not
  a regex over klog. klog still gets the audit trail (`KLOG_INFO`
  / `KLOG_WARN`) for human readers.
- **IR runbook coverage on the attack-signal events only.** Real
  malware signal: a burst of `AuthLoginFailure` and the
  `AuthAccountLocked` that follows. The bookkeeping events
  (admin actions, successful logins) are opted out — emitting
  an investigation runbook for "operator created an account" is
  noise.

## Verification

- **Boot self-test (QEMU TCG, 300 s budget)**:
  - `[I] auth : self-test OK`
  - `[W] auth : account locked (consecutive failures)` — the
    deliberate trip from the probe drive
  - `[secevents] self-test PASS (events walked=3)`
  - `[ir] self-test PASS (entries=22)`  — 22 = 16 prior + 2 new
- **Build flavors**: `x86_64-release` and `x86_64-debug` clean
  with zero warnings (the pre-existing `gzip.cpp` unused-const
  warning is unrelated).

## Out of scope (intentional)

- **Persistence** — accounts still vanish on reboot. The shape
  of `Account` (now 56-byte `PasswordHashRecord` + ~32 bytes of
  metadata + a 32-byte name) is still small; user-table-on-disk
  remains the next bounded slice and now has more state to
  serialise.
- **Per-account lockout policy override** — single global
  `kAuthLockoutThreshold` / `kAuthLockoutDurationNs`. A real
  admin would want per-account or per-role policy; that's a
  follow-on once a configuration surface exists for it.
- **Argon2id / scrypt** — still pending. The
  `PasswordAlgorithm::Argon2id` enum slot is reserved but
  unimplemented.
