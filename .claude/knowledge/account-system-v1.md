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

### Adversarial probe — `AuthBruteForceProbe`

`kernel/security/auth_pentest.{h,cpp}` runs at boot under
`DUETOS_BOOT_SELFTEST` immediately after `AuthSelfTest`. The
probe hammers the seeded admin account with random wrong
passwords drawn from `RandomU64`, then prints structured
results to COM1. Reviewable serial log (one boot, captured
2026-05-03):

```
[auth-pentest] phase1 attempts         = 0x08    (8 wrong-password attempts)
[auth-pentest] phase1 successes        = 0x00    (zero leaked through)
[auth-pentest] phase1 lockout-fired-at = 0x05    (exactly kAuthLockoutThreshold)
[auth-pentest] admin failed_attempts   = 0x05
[auth-pentest] admin locked            = 0x01
[auth-pentest] phase2 correct-pw-while-locked accepted = 0x00
[auth-pentest] phase3 successes        = 0x00    (3 more attempts, all refused)
[auth-pentest] phase3 admin still locked = 0x01
[auth-pentest] phase4 legit-after-unlock = 0x01  (real user not stranded)
[auth-pentest] events: AuthLoginFailure   = 0x0c (12 = 8 + 1 + 3 attempts)
[auth-pentest] events: AuthAccountLocked  = 0x01
[auth-pentest] events: AuthAccountUnlocked= 0x01
[auth-pentest] events: AuthLoginSuccess   = 0x01
```

Cost: ~12 PBKDF2 derivations at the 100 000-iteration default
≈ 30 s on QEMU TCG, ≈ 3 s on a modern x86 core. Phase counts
sized so the entire probe + the rest of the boot completes
well inside a 400 s smoke-test budget.

If a future change ever lets the lockout leak (correct password
accepted while armed, or threshold drifts past 5), the probe
catches it on every boot — phase 2 prints a loud
`!!! REGRESSION !!!` banner.

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
