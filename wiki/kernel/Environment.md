# System Environment View

> **Maturity:** v0, slices 1–3 complete — boot-time aggregation + canonical banner + query API + the `env-monitor` runtime poller + the ACPI SCI power-event path (power button → graceful shutdown, SCI-driven monitor wake). Known limits below: GPE `_Qxx` (lid/AC via EC) is acked but not yet evaluated, and the idle-path C-state reaction stays deferred (no safe lever exists yet). See [Roadmap](../reference/Roadmap.md).

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

## ACPI SCI power events (slice 3)

`kernel/acpi/acpi_sci.{h,cpp}` owns the System Control Interrupt. `EnvMonitorMain` calls `AcpiSciInit(&g_env_wq)` on entry; it:

1. latches the FADT PM1 event / GPE / SMI_CMD ports (new `acpi.h` accessors fed by the FADT parse in `acpi.cpp`);
2. hands ACPI ownership SMM→OS if needed (`SMI_CMD`←`ACPI_ENABLE`, bounded poll on `PM1_CNT.SCI_EN`; QEMU/SeaBIOS already did this so it's a no-op there);
3. clears stale `PWRBTN_STS` and arms `PWRBTN_EN`;
4. `IoApicRoute` + `arch::IrqInstall` the SCI vector (`0x20 + SCI_INT`, MADT override honoured) and emits the raw `[acpi/sci] armed` milestone.

The handler runs in **IRQ context** — no AML, no allocation: it read-/write-1-clears PM1 + GPE status, latches what fired into `SciPending`, and `WaitQueueWakeOne(&g_env_wq)`. The `env-monitor` task blocks on that WaitQueue (`WaitQueueBlockTimeout`, 2 s fallback); on wake it `AcpiSciTakePending()`, and on `power_button` it logs the raw `[env/sci]` sentinels and calls `acpi::AcpiShutdown()` (legal in task context). AC/lid/thermal still come through `EnvironmentRecompose()`.

**GAP — GPE `_Qxx` not evaluated.** GPE status is acked (so a level-triggered SCI can't stay asserted) and the GPE is masked, but the per-GPE `_Qxx` AML query method is *not* run — that needs the AML interpreter in process context plus an EC `_Qxx` path that does not exist (`ec.h`). Power-button (the event QEMU can exercise) is fully handled; lid/AC via EC `_Qxx` remain a documented limit tracked by the "Battery + ACPI suspend" roadmap entry.

### Idle-path C-state reaction: still deferred (honest status)

Slices 1–2 said the idle reaction would land "with slice 3, where a real lever and a consumer arrive together." That framing was optimistic: **slice 3 added the SCI event path, not deep C-states.** There is still no safe non-speculative idle lever — `IdleMain` already uses MWAIT-C1 (equal-or-lower power than HLT, identical wake), and the only deeper knob (MWAIT EAX C-state hint / a cpuidle governor) remains explicitly deferred with "no profile evidence and no consumer yet." Wiring a policy read into the hot idle loop that changes nothing is still a facade. The substantive slice-3 reactivity is **event-driven** (instant power-button shutdown; SCI-driven monitor wake), which fulfils "reactive of its environment" without the facade. The C-state lever lands if/when deep C-states are implemented for their own reasons. See Design-Decisions 2026-05-18 (slice 3 entry).

### Live-test caveat (QEMU)

The full power-button → S5 chain could **not** be observed live on the available QEMU targets, and the script says so rather than claiming success. The `env-monitor` is a Normal-priority task that only gets CPU after the boot task winds down — ~coincident with a **pre-existing ~17 s automatic ACPI poweroff** in the headless CI boot (verified identical on the slice-2 build, so *not* a slice-3 regression). The SCI therefore arms just as the box powers itself off, leaving no window to land a QMP button press first. `tools/test/env-powerbtn-smoke.sh` gates on `[acpi/sci] armed`, presses the button, and reports **PASS** only on the `[env/sci] PWRBTN_STS latched` sentinel, **SKIP** when the pre-existing auto-shutdown races it, and **FAIL** only on a panic or an armed-but-ignored button. Correctness up to the hardware boundary is proven by `[acpi/sci-selftest] PASS` (synthetic PM1 decode + latch round-trip), the `[acpi/sci] armed` milestone, and a clean analyzer verdict.

## Boot wiring

`EnvironmentInit()` runs inside `BootBringupDevices()` immediately after `drivers::power::PowerInit()` — so AC/battery/thermal are live — and after SMP AP bring-up, so the online census is final. `EnvironmentMonitorStart()` is called immediately after (scheduler is online by the devices phase, and the first snapshot is published); the monitor task then runs `AcpiSciInit`. The self-test is `DUETOS_BOOT_SELFTEST`-gated (debug/self-test builds only); `AcpiSciSelfTest` (`[acpi/sci-selftest] PASS`) runs in the ACPI bring-up block, `EnvironmentSelfTest` (`[env-selftest] PASS`) in the devices block.
