# System Environment View

> **Maturity:** v0, slice 1 of 3 — boot-time aggregation + canonical banner + query API. The runtime monitor task (slice 2) and the ACPI SCI/GPE power-event path (slice 3) are pending; see [Roadmap](../reference/Roadmap.md).

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
void EnvironmentInit();                          // compose + banner + cache (boot, once)
const SystemEnvironment& EnvironmentGet();       // cached read, any context
EnvPowerPolicy EnvironmentPowerPolicy();         // cheap derived-policy accessor
EnvPowerPolicy EnvironmentDerivePolicy(const SystemEnvironment&); // pure
const char* EnvPlatformName/EnvFormFactorName/EnvPowerPolicyName(...);
void EnvironmentSelfTest();                       // [env-selftest] PASS; panics on regression
```

## Boot wiring

`EnvironmentInit()` runs inside `BootBringupDevices()` immediately after `drivers::power::PowerInit()` — so AC/battery/thermal are live — and after SMP AP bring-up, so the online census is final. The self-test is `DUETOS_BOOT_SELFTEST`-gated (debug/self-test builds only); it asserts the cached policy equals the pure derivation of the live snapshot — the invariant slice 2's monitor depends on.

## Forward plan

- **Slice 2:** an `env-monitor` kernel thread (reaper pattern) re-composes the snapshot on a timed poll, emits a gated `KLOG_WARN` sentinel + `KBP_PROBE` on policy transitions, and biases the existing MWAIT/HLT idle path on `PowerSave`. No tickless / no timeslice change.
- **Slice 3:** expose the already-parsed FADT GPE0/GPE1 + PM1 event block, install the ACPI SCI handler (`IoApicRoute` + `arch::IrqInstall`), extend `kernel/acpi/ec.cpp` with `_Qxx` query dispatch, and turn power-button / lid / AC-change into real interrupt-driven events that wake the monitor instantly.
