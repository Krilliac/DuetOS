# RBAC and Elevation

> **Audience:** Kernel hackers, shell-command authors, Win32 thunk authors
>
> **Execution context:** Kernel — broker runs in the calling task's context,
> prompts under the compositor lock
>
> **Maturity:** v0 — broker + CLI prompt + grace cache shipping; GUI overlay
> path reserved; Argon2id alongside PBKDF2; persistence pending

## What problem this solves

Before this slice: every privileged action is either "your `AuthRole` is
Admin (allow)" or "it isn't (DENY)." There is no path between those — a
non-admin who needs to install a package must log out, log in as admin,
run the command, log out, log back in. That friction is the same
friction that makes desktop Linux feel hostile, and it produces the
exact UX pressure that gets users to disable security entirely.

This page documents the elevation broker (the in-session "prompt me for
my password to do this one thing") and the RBAC roles model (named
bundles of `kCap*` bits — what each role gets by default, what each
role can elevate to).

## Two orthogonal axes

Pre-existing — DO NOT confuse:

- **`AuthRole`** (`kernel/security/auth.h`) is a fixed 3-level enum:
  `Guest` / `User` / `Admin`. Decided at login. The account row carries
  it. Determines who can *log in* and what their *baseline* shell
  command set is.
- **`CapSet`** (`kernel/proc/process.h`) is a u64 bitmask on the
  `Process` struct. The cap gate (`SyscallGate` /
  `kSyscallCapTable`) reads it on every privileged syscall.

This slice adds:

- **`Role`** (`kernel/security/rbac.h`) — a named bundle of `kCap*`
  bits with an optional per-cap grace duration override. A row in
  the role table, not a field on the account. An `AuthRole::User`
  can be a member of multiple `Role`s; the broker decides which one
  to elevate to based on the cap requested.

| Concept     | Owned by               | Set when?            | Used for?                          |
|-------------|------------------------|----------------------|------------------------------------|
| `AuthRole`  | account row            | account create       | who can log in, baseline shell auth|
| `CapSet`    | `Process` struct       | process spawn        | every privileged syscall           |
| `Role`      | global role table      | role registration    | broker: "which caps does X grant?" |

## Decisions (from the design discussion)

1. **Identity model:** multi-user-with-named-roles **data model** ships
   now; UX defaults to single-user (one account, no login prompt past
   first boot). Multi-user is a config flip. *Avoids the cost of
   retrofitting uid/role fields later.*
2. **Grace cache:** per-process, 5 min default, **per-cap override**
   in the role policy. `kCapNetAdmin = no_cache` is the canonical
   "always reprompt" example; `kCapFsWrite = 30 min` is the
   canonical "long grace" example.
3. **CLI trusted path:** reuse `LoginFeedKey`. Add `LoginMode::Elevate`
   alongside `Tty` / `Gui` — kernel-trusted keystroke routing already
   exists, no new input path needed.
4. **GUI trusted path:** small modal drawn under the compositor lock.
   Same discipline as `LoginStart` (compositor lock + framebuffer
   primitives). No Secure Attention Key yet — reserved as future work
   when a real attack model demands it (see *Future work* below).
5. **Win32 UAC mapping:** pure facade. `NtAdjustPrivilegesToken` etc.
   return `STATUS_SUCCESS` and flip no real bit. The actual gate is
   the `kCap` check the underlying syscall already runs, which now
   calls the broker on miss. UAC consent dialog is cosmetic.
6. **Password hashing:** Argon2id (memory-hard, 64 MiB / t=3 / p=1)
   alongside PBKDF2. New password sets use Argon2id; PBKDF2 records
   migrate lazily on next successful verify.
7. **Per-binary always-allow ("never ask for `git push` again"):
   NO.** Only per-cap grace duration is overridable. Forever-allow
   is what a role grants by default, not a one-off knob.

## Flow: cap miss → broker → grant

```
SYS_FILE_WRITE
  → SyscallGate(num, proc)             (kernel/syscall/cap_gate.cpp)
     missing kCapFsWrite
  → SyscallGate returns Err{PermissionDenied}
     dispatcher does NOT bail yet — first calls:
  → BrokerRequest(proc, kCapFsWrite)   (kernel/security/broker.cpp)
     ├─ GraceCacheLookup(pid, kCapFsWrite)
     │    hit  → return Granted
     │    miss → fall through
     ├─ RolePolicyAllows(account, kCapFsWrite)
     │    no  → return Denied (role can't elevate to this cap)
     │    yes → fall through
     ├─ PromptForPassword(account, "SYS_FILE_WRITE")
     │    LoginMode::Elevate — reuses LoginFeedKey
     │    bad / cancel / timeout → return Denied
     │    good → fall through
     ├─ GraceCacheInsert(pid, kCapFsWrite, role_grace_for(cap))
     ├─ EventRingPublish(BrokerElevationGranted, ...)
     └─ return Granted
  → if Granted: dispatcher proceeds to handler
     if Denied:  dispatcher returns -1 (existing behaviour)
```

## What's wired up today (v0.1)

| Surface                    | State                                                          |
|----------------------------|----------------------------------------------------------------|
| Broker prompt loop (TTY)   | REAL — reads from `Ps2KeyboardReadEvent` directly              |
| Broker prompt loop (GUI)   | REAL — kernel-drawn modal under the compositor lock            |
| Grace cache                | REAL — per-process, per-cap, role-policy lifetime              |
| Role table + memberships   | REAL — in-memory; `admin`→`root`, `guest`→`sandbox` seeded     |
| `elevate <cap>`            | REAL — single-cap prompt + grant                               |
| `elevate role <name>`      | REAL — one prompt, grants every cap in the role bundle         |
| `elevate off`              | REAL — drops every active grant on the shell pseudo-process    |
| `roles` / `roles me`       | REAL — list all roles / list the active user's memberships     |
| `roleadd` / `roledel`      | REAL — admin-gated membership management                       |
| `elevations`               | REAL — dump live grace-cache rows                              |
| `RequireAdmin` integration | REAL — passes if you're admin OR (root-role member AND elevated)|
| Win32 `NtAdjustPrivilegesToken` routing | REAL — enable-but-not-held routes to broker via deferred prompt |
| Argon2id KDF               | DEFERRED — see Roadmap                                         |
| Persistence                | DEFERRED — needs writable system FS                            |

## Deferred-prompt mechanism (v0.2)

`Ps2KeyboardReadEvent` is single-consumer by contract — concurrent
readers race for bytes. A shell-driven `elevate` works because the
shell IS the kbd-reader thread, so the inline prompt loop in
`BrokerRequestElevation` is safe. A Win32 PE syscall runs in a
different task and would race the shell.

The broker resolves this by picking the path at call time:

1. `BrokerSetKbdReaderTid(tid)` records the kbd-reader's TaskId at
   bring-up (`kernel/core/main.cpp` after `SchedCreate`).
2. `RunPrompt` checks `CurrentTaskId() == g_kbd_reader_tid`. Match
   → inline TTY/GUI prompt (same as v0). Mismatch → deferred path.
3. The deferred path posts a request to a single-slot global
   `DeferredSlot`, injects a synthetic `kKeyNone` event to wake the
   kbd reader, and blocks on a `WaitQueue`.
4. The kbd-reader loop calls `BrokerKbdReaderPumpDeferred()` at the
   top of every iteration. On a pending slot it runs the prompt UI
   (safe — the kbd reader IS the legal `Ps2KeyboardReadEvent`
   consumer), stores the password in the slot, sets `completed`,
   and wakes the waiter.

State is guarded by `arch::Cli/Sti` only (no spinlock), mirroring
the existing `Process::StdinRing` discipline. Single-flight for v0:
a second concurrent deferred request returns `false` immediately
and the caller falls through to the legacy denial branch
(`NOT_ALL_ASSIGNED` for Win32 callers).

## File layout

| File                              | Owns                                              |
|-----------------------------------|---------------------------------------------------|
| `kernel/security/rbac.h`          | `Role`, `RolePolicy`, `RoleId`, registry API      |
| `kernel/security/rbac.cpp`        | Built-in role definitions, lookup                 |
| `kernel/security/broker.h`        | `BrokerRequest`, `BrokerOutcome`, prompt hooks    |
| `kernel/security/broker.cpp`      | Cache + role check + prompt orchestration         |
| `kernel/security/grace.h`         | `GraceCacheLookup` / `Insert` / `Expire`          |
| `kernel/security/grace.cpp`       | Fixed-size `(pid,cap)→deadline` table             |
| `kernel/security/login.{h,cpp}`   | **extended** with `LoginMode::Elevate`            |
| `kernel/syscall/cap_gate.cpp`     | **extended** to call broker on denial             |
| `kernel/security/password_hash.*` | **extended** with Argon2id variant                |
| `kernel/shell/shell_security.cpp` | **extended** with `elevate` / `roles` commands    |

## Built-in roles (v0)

| Role          | Cap bundle                                                       | Grace override            |
|---------------|------------------------------------------------------------------|---------------------------|
| `root`        | every `kCap*` bit                                                | `kCapNetAdmin = 0` (none) |
| `developer`   | FsRead, FsWrite, SpawnThread, Debug, SerialConsole, Input        | `kCapFsWrite = 30 min`    |
| `netop`       | Net, NetAdmin, FsRead                                            | `kCapNetAdmin = 0` (none) |
| `auditor`     | FsRead, SerialConsole, Input                                     | default 5 min             |
| `sandbox`     | none — explicit deny role for untrusted PEs                      | n/a                       |

The role table is in-memory v0; persistence is a follow-up tied to a
writable system filesystem (see *Persistence* below). Adding a role
at runtime: `RoleRegister(name, cap_mask, grace_overrides)` —
admin-only via shell.

## Anti-spoofing — CLI v0

The CLI prompt is safe by construction because the keyboard reader
demultiplexes keystrokes at the input ring level
(`kernel/core/main.cpp` kbd-reader loop). When `LoginIsActive()`
returns true (because the broker called `LoginStartElevate()`), every
keystroke routes through `LoginFeedKey` directly. No user-mode process
sees the password — the path is keyboard driver → input ring → reader
thread → login gate (in-kernel). The same path the boot login uses.

A malicious PE *could* draw a fake prompt to the framebuffer, but
nothing it does can read the keystrokes when the gate is active.
Worst case: the PE prints "Enter your password" and waits forever for
input that never arrives, because the kernel ate the bytes.

## Anti-spoofing — GUI v1 (this slice)

The GUI elevation modal is drawn by the broker under the compositor
lock, same discipline as the boot login screen. Other windows cannot
paint over it (the broker raises a `kElevationOverlay` z-layer above
every app window). Keystrokes still demultiplex through `LoginFeedKey`.

## Anti-spoofing — GUI v2 (deferred)

A future hardening: bind a Secure Attention Key (Ctrl+Alt+Del at the
PS/2 driver level) that *always* shows the kernel-drawn broker prompt,
so a paranoid user can force a known-good prompt rather than trusting
that the current one is the broker's. The keycode and the
broker-prompt syscall shape are reserved now so the future SAK
implementation has the seams to plug into.

## Win32 facade routing

`userland/libs/ntdll/`:

- `NtAdjustPrivilegesToken` — calls `BrokerRequest` for each requested
  privilege that maps to a `kCap*`, returns `STATUS_SUCCESS` regardless
  (probe-satisfying) but only adds the cap to the calling process's
  `CapSet` when the broker granted it.
- `RtlAdjustPrivilege` — same.
- `OpenProcessToken` / `LookupPrivilegeValue` — pure facade, no
  broker call. They return believable handles; the actual gate fires
  at the next privileged NT syscall.

A PE that calls `RequestExecutionState(...)` to "run as administrator"
triggers a real broker prompt drawn by the broker (not the PE's UI),
with the calling account's password. If granted, the PE inherits the
elevated caps for the grace window only; once the cache entry expires,
the next privileged syscall reprompts.

## Persistence

Out of scope for this slice — gated on a writable system filesystem.
Today the role table and account table both seed from
`AuthInit()` / `RbacInit()` at boot. A follow-up will add
`/system/secrets/` (encrypted at rest, TPM-sealed once the TPM driver
lands) and an installer-driven first-boot flow that replaces the
hardcoded seeding.

Tracked as a GAP marker in `kernel/security/rbac.cpp` and a row in
[`wiki/reference/Roadmap.md`](../reference/Roadmap.md).

## Argon2id rollout

`password_hash.h` grows a tagged-union record:

```
struct PasswordHashRecord {
    enum Kind : u8 { Pbkdf2 = 0, Argon2id = 1 } kind;
    union {
        Pbkdf2Record   pbkdf2;
        Argon2idRecord argon2id;
    };
};
```

- `AuthAddUser`, `AuthChangePassword` always write Argon2id.
- `AuthVerify` reads the kind tag and runs the matching KDF. On a
  successful PBKDF2 verify, it re-hashes the supplied plaintext with
  Argon2id and overwrites the record in place (lazy migration).
- Wall-clock uniformity is preserved: both code paths run a full
  derivation; the verify wall-clock no longer reveals which KDF a
  given account holds because both timings are within the
  password-derivation envelope the existing decoy path already
  smooths.

## Related pages

- [Capabilities](Capabilities.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Process Model](../kernel/Process-Model.md)
- [Sandboxing](Sandboxing.md)
