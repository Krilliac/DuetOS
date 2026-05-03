# White team — policy engine v0

**Type:** Decision + Pattern
**Status:** Active
**Last updated:** 2026-05-03

## What it is

A single set of operator-facing profiles that composes every
per-subsystem security mode into a coherent posture. Today the
operator has to flip ~6 independent switches — image guard mode,
persistence-drop mode, blockguard mode, sandbox-denial threshold,
canary-kill enabled/disabled, FaultReact policy floor — and there
is no atomic way to say "be production-strict" or "be lab-permissive".

The policy engine fixes that. One command:

```
policy set production
```

flips every per-subsystem switch to its production-coherent value
in a single operation, publishes a `PolicyChanged` event, and
records the chosen profile in a kernel-readable variable so
boot-time subsystems can query "what posture am I in?" before
deciding their own defaults.

## API shape

```cpp
namespace duetos::security {

enum class PolicyProfile : u16
{
    Default = 0,    // matches today's behaviour exactly — bytewise no-op for
                    //   a freshly booted system. Existence prevents
                    //   accidentally regressing to a "no policy chosen" state.
    Lab,            // Permissive: image guard Advisory, persistence Advisory,
                    //   blockguard Audit, sandbox-denial threshold 1000 (10x),
                    //   canary-kill on, FaultReact floor Continue.
    Production,     // Strict default: image guard Enforce, persistence Deny,
                    //   blockguard Block, sandbox-denial threshold 100,
                    //   canary-kill on, FaultReact floor RetryThenKill.
    Forensic,       // Maximum: every wall enforces; FaultReact floor Halt
                    //   (any unhandled fault panics for crashdump);
                    //   every wall trip publishes runbook + freezes process.
                    //   Used after a confirmed incident.
};

struct PolicySnapshot
{
    PolicyProfile     profile;
    GuardMode         guard_mode;          // from existing guard.h
    PersistenceMode   persistence_mode;    // from existing canary.h
    BlockguardMode    blockguard_mode;     // from existing fs/blockguard.h
    u32               sandbox_denial_threshold;
    bool              canary_kill_enabled;
    FaultReactPolicy  fault_react_floor;
    u64               applied_at_uptime_ns;
    u32               applied_by_pid;       // 0 = boot init
};

PolicySnapshot PolicyCurrent();

// Apply a profile atomically — sets every per-subsystem mode in one critical
// section and publishes a PolicyChanged event.
core::Result<void, core::ErrorCode> PolicySet(PolicyProfile profile, u32 actor_pid);

// Subsystems that want to make boot-time decisions (e.g. "should I enable
// extra logging?") can read this. NOT a security gate — the per-subsystem
// modes are the gates; this is just a hint for ergonomics / verbosity.
PolicyProfile PolicyCurrentProfileHint();

// Boot-time init — sets profile to Default. The boot path may opt to upgrade
// to Production after init via a kernel cmdline `policy=production`.
void PolicyInit();

const char* PolicyProfileName(PolicyProfile p);

// Self-test: applies each profile in sequence, reads back via PolicyCurrent,
// asserts every per-subsystem mode is what the profile demands, then restores
// the original profile. Runs at boot iff DUETOS_DEBUG.
void PolicySelfTest();

} // namespace duetos::security
```

## Profile composition matrix

| Subsystem mode | Default | Lab | Production | Forensic |
|---|---|---|---|---|
| Guard image-load | Advisory | Advisory | Enforce | Enforce |
| Persistence drops | Advisory | Advisory | Deny | Deny |
| Blockguard | Audit | Audit | Block | Block |
| Sandbox-denial threshold | 100 | 1000 | 100 | 50 |
| Canary kill | on | on | on | on |
| FaultReact floor | Continue | Continue | RetryThenKill | Halt |
| Runbook publish on trip | on | off (verbose ↘ noise) | on | on |
| Event ring on every klog Warn | off | off | off | on |

## Wiring (boot)

`PolicyInit()` is called from `core::main` **after** every per-
subsystem default is established (so profile application can
safely read-then-overwrite each mode), but **before** ring-3 is
launched. Kernel cmdline `policy=<name>` can override.

## Shell command

```
policy show              — print current profile + the resolved per-subsystem modes
policy set <name>        — flip profile (lab / production / forensic / default)
policy diff <name>       — show what would change if you set <name>; doesn't apply
```

## Why "Default" exists

Without an explicit Default value, the boot path would either:

1. Boot with no profile applied → operator runs `policy show` and
   gets an inconsistent picture (some modes set, some not),
2. Or boot with Production → forces operators to explicitly opt out
   for a "I'm hacking on a bring-up driver" workflow.

`Default = no-op snapshot of whatever each subsystem chose for
itself` keeps the policy engine optional. Operators who never
touch it see no change. Operators who type `policy set production`
get one-flip strict mode.

## Future extensions (out of scope for v0)

- **Per-process profile overrides** — pin a known-malicious binary
  to Forensic posture even when system policy is Lab.
- **Time-bound policy** — `policy set forensic until 2026-05-04T18:00`
  with auto-revert.
- **Policy diff as runbook** — when a wall keeps tripping under
  Lab, the IR runbook can suggest "Production would have blocked
  this earlier — `policy diff production` to see the delta".
