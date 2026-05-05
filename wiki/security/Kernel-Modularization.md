# Kernel Modularization

The DuetOS kernel is structured as a set of **fault domains** —
named subsystems that can be started, stopped, restarted, and
crash-dumped independently of the rest of the kernel. The goal:
when one driver scribbles a bad pointer or trips an internal
invariant, only that subsystem's state is torn down and (typically)
re-initialised; the kernel and every other driver keep running.

This page is the design doc for the operator-visible side of
that story. The synchronous trap path that catches faults is
covered separately in [Runtime-Recovery](Runtime-Recovery.md).

## What's a module

A "module" is a `core::FaultDomain` in `kernel/security/fault_domain.h` —
a registry row carrying a `(name, init, teardown)` triple, a
restart counter, and a lifecycle state. Modules are registered
via `RegisterDriverDomain` (or `core::FaultDomainRegister` for
non-driver subsystems).

Today the registry has capacity for **48 modules**. About 20 are
registered at boot in `kernel/core/main.cpp`; the rest is
headroom for follow-up migrations.

## Lifecycle states

Three states, written to the operator-visible `ModuleState` field
in the registry. Transient `Starting` / `Stopping` are not
modeled because `init` / `teardown` are non-yielding under the
single-writer registry — they're never observable to a reader.

```
   ┌──────────┐  ModuleStart       ┌─────────┐
   │ Stopped  │ ─────────────────▶ │ Running │
   └──────────┘                    └────┬────┘
        ▲                               │
        │ teardown ok                   │ ModuleStop
        │                               ▼
        │                          ┌─────────┐
        └──── ModuleStart ──────── │ Stopped │
                                   └─────────┘

   ┌─────────┐  trap → MarkRestart ┌─────────┐
   │ Running │ ─────────────────▶ │ Crashed │
   └─────────┘  (heartbeat tick)   └────┬────┘
        ▲                               │ FaultDomainRestart
        │                               │ (teardown + init ok)
        └───────────────────────────────┘
```

- **Stopped** — operator stopped the module, or init failed.
  No teardown work pending; a subsequent `module start` re-runs
  init.
- **Running** — init has succeeded; subsystem is live.
- **Crashed** — a trap landed inside an `EXTABLE_BIND` region
  for this domain. The watchdog hasn't drained the restart yet
  (~ one heartbeat tick away). Operators see this state after a
  fault for a brief window before the heartbeat restores
  Running.

The trap path writes `restart_pending` (single-bit, trap-safe);
the heartbeat-side `FaultDomainTick` projects that onto
`ModuleState::Crashed` before draining. Operator-driven
transitions go through `ModuleStart` / `ModuleStop` /
`ModuleRestart` in `kernel/security/module.h`.

Every state flip fires the `kModuleStateChange` probe — set
`b duetos::debug::ProbeFire` in GDB to break on every transition.

## Per-domain crash dump

When a fault domain trips, `FaultReactDrainPending` (running on
the heartbeat thread, ~1 ms after the trap) emits a structured
record on serial **and** stores a copy in an in-kernel
recent-dumps ring (last 8 records, replayable via `module dumps
<name>`).

The record format mirrors `core::BeginCrashDump`'s schema markers
so host-side tooling can grep both:

```
=== DUETOS DOMAIN DUMP BEGIN ===
  version       : 0x0000000000000001
  domain        : drivers/net
  state         : crashed
  restart_count : 0x0000000000000003 (3)
  alive         : false
  fault_kind    : internal-invariant
  faulting_rip  : 0xffffffff80a4321b drivers/net::Tx+0x4b
  --- trap frame ---
  vector        : 0x000000000000000e
  ...
  --- klog tail (filtered by area) ---
  [W] drivers/net : tx queue stalled
  ...
=== DUETOS DOMAIN DUMP END ===
```

The dump is **non-fatal**: serial output goes through a normal
spinlock (no panic-mode), no NMI broadcast, no halt. The
heartbeat carries on, drains the restart, and the module
returns to Running on the next tick.

Operators can also fire a dump on demand from a Running module:
`module dump drivers/net` emits a snapshot record without
disturbing the subsystem.

## Foundation vs restartable

Not every kernel area is a module. Tearing down paging or the
heap mid-flight isn't recovery — it's "rewrite the kernel mid-
boot." Foundational pieces stay non-restartable; their faults
go through `core::Panic` instead.

| Area | Classification | Why |
|------|----------------|-----|
| `arch/x86_64/` (paging, GDT, IDT, traps, APIC) | Foundational | The very state needed to recover. |
| `core/` (entry, panic, init) | Foundational | The recovery code itself. |
| `cpu/` (per-CPU data) | Foundational | Hosts `current_task`. |
| `mm/` (frame allocator, paging, slab, kheap) | Foundational | Tearing down heap leaks every prior alloc. |
| `sched/` (scheduler core) | Foundational | Restart orphans every kernel thread. |
| `sync/` (spinlock, RW, RCU) | Foundational | Pure code; no state to restart. |
| `syscall/` (gate + native syscalls) | Foundational | Gate is part of CPU MSR state. |
| `log/` (klog) | Foundational | The dump path uses it. |
| `ipc/` (handle table, KMutex, KEvent, …) | Foundational | Userland holds handles by index. |
| `proc/` (process model) | Foundational | Restart = murder every process. |
| `time/` HPET + tick | Foundational | Tick drives the heartbeat that drains restarts. |
| `time/` NMI watchdog | Restartable | Already a domain (`nmi-watchdog`). |
| `acpi/` AML parser | Restartable | Already a domain (`acpi/aml`). |
| `fs/` VFS root | Foundational | Mediates every other FS module. |
| `fs/` ramfs / fat32 / ext4 / NTFS / exFAT | Restartable | Per-backend. |
| `loader/` (ELF, PE, DLL, firmware) | Restartable | Pure code + parse caches. |
| `net/` Layer 3+ stack | Restartable | TCP / IP / ARP. |
| `drivers/*/` | Restartable | The whole point. |
| `subsystems/win32/`, `subsystems/linux/` | Restartable | Pure thunks; in-kernel side small. |
| `subsystems/graphics/`, `subsystems/audio/` | Restartable | |
| `security/` auth + pentest + attack_sim | Restartable | |
| `security/` fault_domain itself | Foundational | Recovery infrastructure. |
| `shell/` | Restartable | Kernel app. |
| `apps/` | Restartable | Kernel apps. |
| `debug/` extable | Foundational | Trap recovery table. |
| `debug/` breakpoints, probes | Restartable | |
| `diag/` (most) | Restartable | |
| `power/` reboot, shutdown | Restartable but pointless | One-shot ops; no live state. |

Roughly 14 foundational, 30+ restartable.

## Shell verbs

Operator surface, all gated by `RequireAdmin("MODULE")`:

```
shell> module list
shell> module status <name>
shell> module start <name>
shell> module stop <name>
shell> module restart <name>
shell> module dump <name>
shell> module dumps <name>
```

`module list` enumerates every registered domain with its state
and restart count. `module status <name>` shows the same fields
plus how many records the domain currently has in the recent-
dumps ring. `module dump` emits a fresh snapshot; `module dumps`
replays every stored record.

The legacy `domain` verb (`domain list`, `domain restart <name>`)
remains as a deprecated alias — a one-line warning is logged on
each invocation. The alias will be removed in a future slice.

## EXTABLE_BIND — wiring driver code into auto-restart

A trap that lands in a driver's address range turns into a
domain restart only if the kernel exception table maps that
range to the driver's domain id. The `EXTABLE_BIND` family of
macros in `kernel/debug/extable_bind.h` is the convenience
wrapper:

```cpp
namespace
{
::duetos::core::FaultDomainId g_dom = ::duetos::core::kFaultDomainInvalid;
[[gnu::noinline]] u64 SafePathFixup() { return 0; }
}

void DriverEntry(...)
{
    EXTABLE_BIND_BEGIN(driver_main_region);
    // ... body that may dereference a stale device pointer ...
    EXTABLE_BIND_END(driver_main_region);
}

void DriverInit()
{
    g_dom = duetos::security::RegisterDriverDomain(
        "drivers/foo", &Init, &Teardown);
    EXTABLE_BIND_REGISTER(driver_main_region, g_dom,
                          reinterpret_cast<u64>(&SafePathFixup),
                          "drivers/foo.region");
}
```

A kernel-mode #PF / #GP whose RIP lands inside `[BEGIN, END)`
is rewritten by the trap dispatcher to `SafePathFixup`'s
address, the iretq returns into the fixup, and
`FaultDomainMarkRestart(g_dom)` is queued for the heartbeat to
drain.

Today **only mm/CopyFromUser and mm/CopyToUser** have extable
rows in production. Wiring more drivers requires per-driver
fault models — what's the right fixup return value, what's
held when the fault trips, what state needs cleanup. That's
slice-by-slice work.

## Synthetic fault injection (build-flag-gated)

`kernel/test/inject_domain_fault.cpp`, behind `-DDUETOS_INJECT_DOMAIN_FAULT=1`,
registers a synthetic domain `selftest.inject` and exposes
`InjectDomainFault()` which deliberately dereferences a known-
bad address inside an `EXTABLE_BIND` region. End-to-end proof
of the recovery chain without a real driver bug.

Not enabled in default builds. Once the smoke harness has a
shell-driven hook (`fault-inject` is the proposed verb), CI
can opt in to verify the chain on every PR.

## Supervisor — restart-rate throttle

A buggy driver that crashes every few milliseconds shouldn't
loop forever in the watchdog → restart → crash cycle. Each
domain keeps a rolling history of its last
`kRestartHistoryDepth` (= 5) restart timestamps; when that many
restarts land inside `kRestartThrottleWindowTicks` (≈ 60 s at
the 100 Hz tick rate), the watchdog **refuses** the next
restart and parks the domain in `Stopped`. An operator must
explicitly `module start <name>` once they've decided the
underlying issue is fixed.

Throttle hits are counted on each domain (`restart_throttle_count`)
and globally (`FaultDomainThrottleCount()`) so an audit can
spot misbehaving subsystems across boots. The throttle is the
kernel-owned escalation rule a buggy driver can never demote.

## Cross-domain dependency cascade

Drivers can declare dependencies via
`FaultDomainAddDependency(parent, dependent)`. After a
successful restart of `parent`, every registered dependent is
`MarkRestart`-ed and drained on the same heartbeat tick. The
cascade is one level deep — a dependent that is itself a
parent fires its own dependents on its own restart, propagating
the cascade through the graph without explicit recursion.

Edge capacity is fixed (`kMaxFaultDomainDeps = 64`); self-deps
are refused; cycles are not detected (the cascade is naturally
fixed-depth: a domain can be in `Crashed` once per beat).

## /proc/dumps — userland-visible dump records

The in-kernel recent-dumps ring is mirrored to `/proc/dumps`
in ramfs, refreshed every heartbeat tick. Userland tools can
`cat /proc/dumps` (or read it through the VFS) to see the same
serialised records the shell emits via `module dumps`. Updates
are bounded: at most ~10 ms stale (one heartbeat at the 100 Hz
default tick rate). Buffer is 32 KiB — enough for ~16 records
of average size; the formatter truncates oversized records.

Disk persistence (writing dumps to a partition that survives
reboot) remains out of scope: the FS module needed to host the
file is itself a managed module, and the bootstrap ordering
problem isn't worth solving until a real disk-installer story
lands.

## Wave-1 KERNEL_INITCALL migration — pattern + status

The fault-domain registry started life as inline
`RegisterDriverDomain(...)` calls in `kernel/core/main.cpp`.
The `KERNEL_INITCALL(Drivers, "<name>.module", fn)` macro lets
each driver self-register from its own TU; `RunPhase(Drivers)`
in kernel_main fires every registered callback.

**Migrated so far:**
- `fs/ramfs` (kernel/fs/ramfs.cpp:RegisterRamfsModule)

**Pattern for follow-up migrations** (each driver TU):

```cpp
namespace
{
::duetos::core::Result<void> RegisterFooModule()
{
    ::duetos::security::RegisterDriverDomain(
        "drivers/foo",
        []() -> ::duetos::core::Result<void> { FooInit(); return {}; },
        []() -> ::duetos::core::Result<void> { return FooShutdown(); });
    return {};
}
} // namespace

KERNEL_INITCALL(Drivers, "drivers/foo.module", RegisterFooModule)
```

Then delete the matching inline block in
`kernel/core/main.cpp:1100..1300` for early drivers, or after
`RunPhase(Drivers)` in the late driver block (≈ line 2600+).

**Pending wave-1 migrations:** drivers/net, drivers/gpu,
drivers/storage/nvme, drivers/audio, fs/fat32. Each is a small
edit (move ~10 lines of registration code into the driver TU)
but has subtle ordering implications because their inline
registrations run AFTER `RunPhase(Drivers)`. A clean migration
adds a second `RunPhase(Drivers)` invocation after the late-
driver Init block, or moves the late drivers' Init into their
KERNEL_INITCALL constructors. Slice-by-slice work; the
infrastructure is ready.

## Out of scope (deferred — large enough to be their own slices)

- **Per-domain memory arenas / heap partitions.** Real
  isolation needs a per-domain frame ledger + slab allocator
  routing through it. A driver that scribbles past its own
  slab still corrupts kernel-shared heap today. Phase-C work;
  blocked on the broader memory-management slab redesign.
- **Hot upgrade / live patch.** Loading new code under a
  running kernel is a different problem class — module
  restart only re-runs the same code. Needs symbol versioning,
  text patching, and a careful kABI definition. Not on the
  near-term roadmap.
- **Rust subsystem port.** The toolchain and FFI shape are
  documented in `wiki/reference/Roadmap.md`. Modularization
  works for C++ today; Rust is orthogonal and waits for the
  rust-toolchain.toml + ABI-translation slice.
- **Userland-driven module supervisor (PID 1).** A long-term
  goal is for `init` to own module lifecycle policy (start
  order, dependencies, restart strategies) the way systemd /
  launchd does. Today the kernel registry is the only
  surface. Blocked on userland bringup.
- **Per-CPU domain isolation.** Restarts serialise on the BSP
  today via the heartbeat thread. SMP runqueues + per-CPU
  restart paths would let a domain's teardown run on the CPU
  that tripped its fault. Blocked on SMP runqueue work.
- **Disk persistence of dump records.** Covered by the
  /proc/dumps section above — needs a writable FS module
  before it's solvable.
