# System Environment View

> **Maturity:** v0, slice 2 of 3 — boot-time aggregation + canonical banner + query API + the `env-monitor` runtime poller (cached state is live, policy transitions are logged + probed). The ACPI SCI/GPE power-event path (slice 3) is pending; see [Roadmap](../reference/Roadmap.md).

## What this is

DuetOS already *detects* its environment, but the facts were scattered across half a dozen subsystems and read ad-hoc (every consumer re-derived state and re-checked `IsEmulator()` itself). `kernel/env/environment.{h,cpp}` is a **read-only aggregator**: it composes one authoritative `SystemEnvironment` snapshot at boot, derives a coarse power policy, prints one canonical banner, and exposes cached query accessors.

It **never re-detects anything** — the owning subsystems remain the single source of truth for every field. `env` only reads them:

| Field | Source |
|---|---|
| `hv_kind`, `platform` | `arch::HypervisorInfoGet()` / `arch::IsBareMetal()` |
| `cpu_total` | `acpi::CpuCount()` (MADT LAPIC census) |
| `cpu_online` | `arch::SmpCpusOnline()` |
| `cpu_hybrid` | `cpu::TopologyForCpu()` `core_class` scan |
| `ram_bytes` | `mm::TotalFrames() * mm::kPageSize` |
| `numa`, `numa_nodes` | `acpi::srat::SratPresent()` / `SratNodeCount()` |
| `form_factor` | SMBIOS chassis (`PowerSnapshot.chassis_is_laptop`) + core-count heuristic |
| `ac`, `battery_*`, `lid_*`, temps, throttle | `drivers::power::PowerSnapshotRead()` |

## Canonical banner

`EnvironmentInit()` emits exactly one line via raw `arch::SerialWrite` — a structural sentinel (like `[smoke] …`) that survives klog level demotion so `tools/test/boot-log-analyze.sh` can grep it:

```
[env] platform=QEMU/TCG cpu=1/4 ram=510MiB mem=UMA form=desktop pwr=online batt=n/a temp=n/a policy=balanced
```

`platform=` prints `bare-metal` on real hardware, otherwise the hypervisor name. `cpu=online/total` (with `(hybrid)` appended on P/E parts). `mem=UMA` or `NUMA(nN)`. `batt=n/a` when no battery; `temp=n/a` when MSR thermal is unavailable (QEMU TCG).

## Power-policy derivation

`EnvironmentDerivePolicy()` is a pure function (no side effects, no caching) so slice 2's monitor can recompute it identically on every poll. The order is:

1. **Thermal throttle hit** → `PowerSave` (trumps everything).
2. **On battery** (`ac == kAcOffline`) → `PowerSave`.
3. **Virtualized / emulated** → `Balanced` (the host owns real power management; avoid spin-heavy perf assumptions on a contended host).
4. **Bare-metal laptop on AC** → `Balanced` (thermals/fan noise still matter).
5. **Bare-metal server/desktop on AC** → `Performance`.

Today the policy is constant after boot. Slice 2 makes it react; slice 2's idle-path consumer reads `EnvironmentPowerPolicy()`.

## Query API

```cpp
void EnvironmentInit();                          // compose + banner + publish (boot, once)
SystemEnvironment EnvironmentGet();              // snapshot-by-value under publish lock, any context
EnvPowerPolicy EnvironmentPowerPolicy();         // derived-policy accessor (locked)
EnvPowerPolicy EnvironmentDerivePolicy(const SystemEnvironment&); // pure
bool EnvironmentRecompose();                     // re-read + republish; true iff changed
void EnvironmentMonitorStart();                  // spawn the env-monitor task
const char* EnvPlatformName/EnvFormFactorName/EnvPowerPolicyName(...);
void EnvironmentSelfTest();                       // [env-selftest] PASS; panics on regression
```

`EnvironmentGet()` returns **by value under a spinlock** (`g_env_lock`) — once the monitor is running the snapshot is mutated concurrently, so a reference would tear. `EnvironmentDerivePolicy()` stays pure (no lock, no side effects) so the monitor and the self-test recompute identically.

## Runtime monitor (slice 2)

`EnvironmentMonitorStart()` spawns the `env-monitor` kernel thread (same shape as the reaper: a `SchedCreate`'d worker). Every `kEnvMonitorIntervalTicks` (200 ticks ≈ 2 s at the 100 Hz scheduler clock) it:

1. `EnvironmentRecompose()` — re-reads every source (`PowerSnapshotRead` re-samples the thermal MSRs and re-polls ACPI), recomputes the policy, and atomically publishes the new snapshot under `g_env_lock`.
2. If an observable field changed: one `KLOG_INFO` summary + `KLOG_DEBUG_V` detail (AC / temp / battery). **INFO, not WARN** — a power-source change is a legitimate normal event; a WARN would flood on every unplug (CLAUDE.md "log-level abuse").
3. If the *policy* transitioned: additionally fire the `env.policy_change` probe (`ProbeId::kEnvPolicyChange`, `ArmedLog`, packed `prev<<8 | new`). A clean steady boot never changes policy, so the log stays quiet; a real AC→battery / thermal-throttle transition leaves a sentinel line and a GDB-breakable frame.

The reactive payoff of slice 2 is that **cached state is live, not frozen at boot** — the banner is the boot snapshot, but every later reader (`EnvironmentGet`, `EnvironmentPowerPolicy`, the shell, slice 3) sees current state.

### Idle-path reaction is deferred to slice 3 (deliberate)

The plan floated biasing the scheduler's MWAIT/HLT idle path on `PowerSave`. On inspection there is **no safe real lever today**: `IdleMain` already uses MWAIT-C1 whenever available, documented as *"at least as deep as a bare HLT and lower-power on most parts"* with identical wake semantics. The only deeper lever (the MWAIT EAX C-state hint / deep C-states) is explicitly deferred — *"no profile evidence and no consumer yet"*. Wiring a policy read into the hot idle loop that changes nothing would be a probe-satisfying facade (CLAUDE.md-forbidden). The idle C-state reaction lands with slice 3, where a real lever and a consumer arrive together. See Design-Decisions 2026-05-18.

## Boot wiring

`EnvironmentInit()` runs inside `BootBringupDevices()` immediately after `drivers::power::PowerInit()` — so AC/battery/thermal are live — and after SMP AP bring-up, so the online census is final. `EnvironmentMonitorStart()` is called immediately after (scheduler is online by the devices phase, and the first snapshot is published). The self-test is `DUETOS_BOOT_SELFTEST`-gated (debug/self-test builds only); it asserts the cached==derived invariant, exercises the full derivation matrix against synthetic snapshots, and round-trips `EnvironmentRecompose()`.

## Forward plan

- **Slice 3:** expose the already-parsed FADT GPE0/GPE1 + PM1 event block, install the ACPI SCI handler (`IoApicRoute` + `arch::IrqInstall`), extend `kernel/acpi/ec.cpp` with `_Qxx` query dispatch, turn power-button / lid / AC-change into real interrupt-driven events that wake the monitor instantly (instead of only on its 2 s poll), and add the now-meaningful idle-path C-state reaction.
