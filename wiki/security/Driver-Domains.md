# Driver and Fault Domains

> **Audience:** Driver authors, runtime-resilience reviewers
>
> **Execution context:** Kernel — domain registry runs at boot; restart
> happens from the heartbeat thread or from a trap handler
>
> **Maturity:** v0 — registry + manual restart wired; trap-handler
> auto-restart on next slice

## Overview

DuetOS's "**fault domain**" is a small contract every restartable
subsystem signs:

- "Here is my **init** function."
- "Here is my **teardown** function."
- "I am safe to bring down + bring back up without rebooting the kernel."

The kernel keeps a registry of these contracts. When a driver faults,
the recovery taxonomy
([Runtime Recovery](Runtime-Recovery.md)) can classify the fault as
Class B (driver restart) and the runtime calls into the registry to
do exactly that — teardown, init, optional state reload. The rest of
the kernel keeps running.

Sources:

- [`fault_domain.h`](../../kernel/security/fault_domain.h) — generic
  registry + watchdog
- [`driver_domain.h`](../../kernel/security/driver_domain.h) — thin
  wrapper for drivers
- [`broker.h`](../../kernel/security/broker.h) /
  [`grace.h`](../../kernel/security/grace.h) — adjacent topic, lives
  here because elevation grants flow through similar lifecycle hooks
- [`canary.h`](../../kernel/security/canary.h) /
  [`persistence.h`](../../kernel/security/persistence.h) — adjacent
  topic — see below

The unifying principle: **graceful restart is a first-class kernel
operation**, not an "implementation detail of each driver." Every
driver is restartable through one common API and one common
event-stream.

## The Domain Registry

The registry is a fixed-size table of `FaultDomain` entries
([`fault_domain.h`](../../kernel/security/fault_domain.h)).

```cpp
struct FaultDomain {
    const char* name;
    InitFn      init;
    TeardownFn  teardown;
    DomainState state;             // Down | Up | Restarting | Stopped
    u32         restart_count;
    u64         last_restart_ns;
    void*       user_data;
};

FaultDomainHandle FaultDomainRegister(FaultDomain spec);
Result<void>      FaultDomainRestart(FaultDomainHandle);
void              FaultDomainTick();          // called from heartbeat
void              FaultDomainMarkRestart(FaultDomainHandle);  // trap-safe
```

Capacity: 48 domains. Each driver class (audio, MEI, virtio,
wireless, networking, …) registers one or more. The init + teardown
functions are stable callbacks supplied by the driver at boot.

## Rate Throttle

A driver that immediately faults again after restart isn't restartable
in any useful sense — restarting it in a tight loop just spins CPU
on a known-bad path. The registry tracks `restart_count` in a sliding
window:

- **Default policy**: 5 restarts within 60 s → transition the domain
  to `Stopped`. Subsequent `FaultDomainRestart` calls return
  `ErrorCode::Refused`. The operator must explicitly clear via
  `driver clear <name>` to re-enable.
- The window slides — once `last_restart_ns + 60 s` has passed since
  the earliest restart in the window, the count rolls off.

The threshold is per-domain configurable; the default is a sensible
"we tried, it kept failing, stop trying." A different driver class can
override (e.g. a network NIC might want a tighter window because
network failures cascade).

## Driver Wrapper

[`driver_domain.h`](../../kernel/security/driver_domain.h) is the thin
convenience wrapper drivers use:

```cpp
RegisterDriverDomain("audio.hda", &HdaInit, &HdaTeardown);
```

Under the hood it forwards to `FaultDomainRegister` with a uniform
diagnostic tag (`"driver-domain"`) so the shell `domains` command can
filter to just driver-side entries.

The driver's responsibilities:

- `Init()` must be idempotent — calling it twice on a stopped domain
  must produce the same end state as calling it once on an unregistered
  domain.
- `Teardown()` must release every resource the driver acquired during
  `Init()`. Failure here is logged but does not block restart — the
  fault domain framework assumes "best effort" teardown.

## Manual vs Automatic Restart

v0 supports **manual** restart through the shell:

```
driver list                 # list every registered domain
driver restart audio.hda    # call teardown then init
driver clear  audio.hda     # un-stop a rate-throttled domain
driver stop   audio.hda     # take a domain down manually
```

Automatic restart on a trap is the next-slice work. The current trap
handler already has the hook (`FaultDomainMarkRestart` is **trap-safe**
— sets a flag in the per-domain entry), but the deferred drain
(`FaultDomainTick` on the heartbeat) does not yet auto-execute the
restart for marked entries. Wiring that is the gate to "driver crash
during boot → kernel keeps running, surfaces a notification, restarts
on the next heartbeat."

## Driver Trust Surfaces

Domains are the **isolation primitive**. They aren't a security
boundary — a driver runs in the kernel's address space and can in
principle scribble anywhere. The domain primitive isolates *failure*,
not *trust*.

For trust, two adjacent primitives complement domains:

- **`guard.h`** — image loading gate. Inspects native ELF and Windows
  PE images for suspicious patterns (W+X sections, name-denylist,
  packer-no-imports). Modes: `Advisory` (default, scans and logs),
  `Enforce` (prompts Warn / Deny).
- **`canary.h`** — filesystem self-defense walls. Registered canary
  paths + per-boot randomised honeypot file names. Touches fire
  `CanaryTouch` events into the security event ring. The
  ransomware-detection signal.
- **`persistence.h`** — autostart-path drop detector. Files dropped
  into known persistence paths (`/Startup/`, registry Run keys) fire
  `PersistenceDrop` events. Default mode: Advisory.

All three live in `kernel/security/` and feed the same security event
ring as auth.

## Event Stream

Every domain state transition fires a structured event:

- `domain.transition` — `(name, from_state, to_state)`
- `domain.restart` — `(name, restart_count, reason)`
- `domain.rate_throttled` — `(name, count, window_ns)`
- `domain.cleared` — `(name)`

The shell's `secevents` command can filter to `domain.*`.

## Boot Self-Test

The fault-domain self-test:

- Registers a known-good toy domain (init/teardown succeed)
- Calls `FaultDomainRestart` and asserts the count increments
- Calls restart 6 times in 60 s, asserts the 6th transitions to
  `Stopped`
- Calls `driver clear`, asserts the domain returns to `Up`
- Registers a domain whose `Init()` returns `Err` — asserts the
  domain stays `Down`

A failure fires `kBootSelftestFail`.

## Threading and Locking

- The registry is guarded by a spinlock. Mutations are rare (boot init,
  manual restart, rate-throttle decision).
- Restart itself runs on the **heartbeat thread**, not in the trap
  handler — a trap handler calls `FaultDomainMarkRestart` and returns;
  the heartbeat picks up the mark on its next tick.
- Init / teardown callbacks run with the registry lock released — they
  can do whatever they need (allocate, sleep, IPC) without lockdep
  complaints from the registry itself.

## Known Limits / GAPs

- **Automatic trap-driven restart** is not yet wired — manual only.
- **No per-domain dependencies.** If `pci` is restarted, dependent
  drivers (`virtio`, `nvme`, …) don't currently get a notification.
  Cascade restart is a Roadmap entry.
- **No state reload.** A restarted driver loses any in-memory
  state. For drivers that need to survive restart (e.g. a queued
  packet), the state has to be parked in a structure that outlives
  the domain — typically the network stack itself.
- **Rate-throttle window** is fixed at 60 s and 5 restarts. Adaptive
  thresholds based on observed MTTF are a future enhancement.
- **No live driver upgrade.** Restart = teardown + init of the same
  code. Replacing the code itself goes through
  [Live Updates](../tooling/Live-Updates.md).

## Related Pages

- [Runtime Recovery](Runtime-Recovery.md) — taxonomy that picks Class
  B driver-restart
- [Diagnostics](../kernel/Diagnostics.md) — fault_react dispatcher
  that classifies the recovery
- [Auth and Login](Auth-and-Login.md) — broker / grace cache live in
  the same tree
- [Live Updates](../tooling/Live-Updates.md) — replacing the code
  rather than restarting it
- [Driver Overview](../drivers/Driver-Overview.md) — what gets
  registered as a domain
- [Capabilities](Capabilities.md) — gates on `driver` shell commands
