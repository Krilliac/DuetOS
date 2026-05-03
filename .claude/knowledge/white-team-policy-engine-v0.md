# White team — policy engine v0

**Type:** Decision + Pattern
**Status:** Active — landed in commit bb13b98 on
`claude/improve-os-security-T74TX`
**Last updated:** 2026-05-03

## What it is

A single set of operator-facing profiles that composes every
per-subsystem security mode into a coherent posture. Today the
operator has to flip ~3 independent switches — image guard mode,
persistence-drop mode, blockguard write mode — and there is no
atomic way to say "be production-strict" or "be lab-permissive".

The policy engine fixes that. One command:

```
policy set production
```

flips every per-subsystem switch to its production-coherent
value in a single operation, publishes a `PolicyChanged` event
+ per-subsystem `*ModeChanged` events, and updates the recorded
profile.

## API (as shipped)

```cpp
namespace duetos::security {

enum class PolicyProfile : u16
{
    Default = 0, // bytewise no-op snapshot of whatever each subsystem
                 // chose for itself; existence prevents a "no profile"
                 // inconsistent state.
    Lab,         // permissive: Advisory everywhere
    Production,  // strict default: Enforce / Deny everywhere
    Forensic,    // maximum: every wall enforces; same shape as Production
                 // today, but kept distinct so future runbook-driven knobs
                 // (verbose logging, every-trip event publication) can
                 // attach without reshuffling.
    Count,
};

struct PolicySnapshot
{
    PolicyProfile profile;
    Mode guard_mode;
    PersistenceMode persistence_mode;
    drivers::storage::WriteGuardMode write_guard_mode;
    u64 applied_at_uptime_ns;
    u32 applied_by_pid;       // 0 = boot init / kernel
};

PolicySnapshot PolicyCurrent();
void           PolicySet(PolicyProfile, u32 actor_pid);
PolicyProfile  PolicyCurrentProfileHint();
PolicySnapshot PolicyResolve(PolicyProfile profile);
const char*    PolicyProfileName(PolicyProfile);
void           PolicyInit();
void           PolicySelfTest();

} // namespace
```

## Profile composition matrix (as shipped)

| Subsystem mode | Default | Lab | Production | Forensic |
|---|---|---|---|---|
| Guard image-load | (sampled) | Advisory | Enforce | Enforce |
| Persistence drops | (sampled) | Advisory | Deny | Deny |
| Blockguard | (sampled) | Advisory | Deny | Deny |

Default = "snapshot whatever each subsystem chose for itself" —
a bytewise no-op so the policy engine is optional. Operators
who never call `policy set` see no change.

## Why these three subsystems and not others

Three knobs are settable today:
- `SetGuardMode(Mode)` — Off / Advisory / Enforce
- `PersistenceSetMode(PersistenceMode)` — Advisory / Deny
- `BlockWriteGuardSetMode(WriteGuardMode)` — Off / Advisory / Deny

Other knobs the design doc considered but punted on:
- **Sandbox-denial threshold** (`kSandboxDenialKillThreshold`)
  is `inline constexpr u64 = 100` — not runtime-settable. Adding
  a setter is a future enhancement.
- **FsWrite-rate caps** are constexpr per-window thresholds in
  process.cpp — same story.
- **FaultReact floor** is internal logic in `FaultReactPolicyFloor`,
  not exposed as a settable mode.

Once any of those gain runtime setters, the policy table is the
right place to add columns.

## Wiring

- `PolicyInit()` runs at boot in `core::main` after Guard/Canary
  init but before AP bring-up. Reads each subsystem's chosen
  mode and stores the Default snapshot.
- `PolicySet(profile, actor_pid)` walks the resolved profile,
  calls each subsystem's setter for fields that actually
  differ, publishes `PolicyChanged` + per-subsystem
  `*ModeChanged` events, refreshes the snapshot.
- `PolicySelfTest` cycles through Lab / Production / Forensic,
  asserts every per-subsystem mode matches expectation, then
  restores the original modes + snapshots Default.

## Shell command

```
policy show              — print current profile + per-subsystem modes
policy set <profile>     — flip profile (default | lab | production | prod | forensic); admin-gated
policy diff <profile>    — placeholder; routes through COM1 in v0
```

## What this does NOT do

- It does NOT decide policy autonomously. The runbook recommends;
  the operator (or a future "auto-escalate on confirmed compromise"
  hook) decides.
- It does NOT persist across reboots. Profile resets to Default
  every boot. Adding kernel-cmdline `policy=production` is a
  cheap follow-up.
- It does NOT remove the per-subsystem shell commands
  (`guard enforce`, `persistence deny`, etc.). Those still work
  and silently leave the profile name pointing at the prior
  selection — a future enhancement could flip to `Custom`.

## Future extensions

- **Per-process profile overrides** — pin a known-suspicious
  binary to Forensic posture even when system policy is Lab.
- **Time-bound policy** — `policy set forensic until <uptime>`
  with auto-revert.
- **Auto-escalate on confirmed compromise** — when
  IdtModified / KernelTextModified / SyscallMsrHijacked fires
  twice in a row across Heal cycles, automatically
  `policy set forensic` and emit a runbook step.
