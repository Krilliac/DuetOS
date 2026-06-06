# Power Management

> **Audience:** Driver authors, ACPI consumers, anyone wiring an
> operator-facing shutdown / reboot
>
> **Execution context:** Kernel — boot-time inventory + terminal
> shutdown/reboot path
>
> **Maturity:** v0 — static inventory and shutdown/reboot wired; live
> battery telemetry deferred until AML runtime lands

## Overview

DuetOS power management splits across two thin trees:

- [`kernel/drivers/power/`](../../kernel/drivers/power/) — boot-time
  power snapshot (AC state, battery presence, thermal MSRs, chassis
  type from SMBIOS).
- [`kernel/power/`](../../kernel/power/) — terminal control paths:
  `KernelReboot()` and `KernelHalt()`.

The split is by lifecycle: the driver-side runs once at boot to build
an inventory, then becomes read-only data the rest of the kernel
consults. The kernel-side is what's called when the user clicks
"shutdown" or the IR runbook decides to bring the system down.

True dynamic power management — battery percentage that updates while
the system runs, suspend/resume, CPU P-state selection — needs an AML
runtime to call `_BST`, `_BIF`, `_PSV`, EC region reads. That is the
gating slice; see [ACPI](../kernel/ACPI.md) for the deferred work.

## File Layout

| File | Purpose |
|------|---------|
| [`drivers/power/power.h`](../../kernel/drivers/power/power.h) / `.cpp` | Boot snapshot: AC, battery presence, thermal, chassis type |
| [`power/reboot.h`](../../kernel/power/reboot.h) / `reboot.cpp` | `KernelReboot()` + `KernelHalt()` — terminal paths |

## Boot Snapshot

`PowerInit()` runs once during boot. It composes its snapshot from
three sources:

1. **SMBIOS** — [`arch::Smbios*`](../../kernel/arch/x86_64/smbios.cpp)
   provides the chassis type ID. The driver maps it to a
   user-facing string (`Desktop` / `Laptop` / `Server` / `Other`)
   and sets the `is_laptop` flag if chassis ∈ {Notebook, Hand Held,
   Sub Notebook, Portable}.
2. **MSR thermal** — `arch::ThermalRead()` reads
   `IA32_THERM_STATUS` / `IA32_PACKAGE_THERM_STATUS` for current vs
   target temperature deltas, plus the throttle flag.
3. **ACPI namespace lookup** — `acpi::AmlContainsName("BAT0")` and
   `acpi::AmlContainsName("BAT1")` tell us whether the firmware
   declares one or two batteries. This is presence-only — actual
   capacity / charge is `_BST` territory and not yet evaluable.

The resulting `PowerSnapshot` struct is read-only after boot. Public
accessors:

```cpp
const PowerSnapshot& power::Snapshot();
bool                 power::IsLaptop();
bool                 power::HasBattery();
int                  power::ThermalThrottleFlag();
```

Consumers:

- The `about` and `sysmon` apps display the snapshot.
- The `settings` app uses `IsLaptop()` to choose between "laptop"
  and "desktop" preset behaviour for sleep / lid actions (currently
  decorative — the actions themselves aren't wired).
- The IR runbook reads thermal throttle as one input to a "system is
  in distress" classifier.

## Terminal Paths: Reboot and Halt

[`power/reboot.h`](../../kernel/power/reboot.h) declares two
`[[noreturn]]` functions. They are the **only** way out of the kernel
once boot finishes.

### `KernelReboot()`

The reboot path tries four strategies, in order, until one succeeds:

1. **ACPI reset register**. If the FADT's RESET_REG block is populated
   and the FADT flags say it's usable, write the configured byte to
   the configured address space (memory / I/O).
2. **PCH reset port `0xCF9`**. Write `0x06` (full reset / hard reset).
   Works on most Intel chipsets even when ACPI's RESET_REG is absent.
3. **8042 keyboard controller**. Pulse pin 0xFE (system reset) on the
   keyboard controller — the historical x86 reset path.
4. **Triple-fault**. Load a null IDTR and `int3`. The CPU faults; the
   processor cannot deliver a vector with a null IDT, so it triple-faults
   and the platform resets.

Each strategy is wrapped in a small busy-wait window so the firmware
has a chance to act before the next strategy tries. The triple-fault
is the last-resort fallback — it always works, but cleaner paths are
preferred because they let the firmware execute its own reset
choreography.

### `KernelHalt()`

The halt path aims for ACPI S5 (soft-off) and falls back to "park the
boot CPU":

1. **ACPI S5 via AML**. The `_S5_` package (decoded by
   [`acpi::AmlReadS5`](../../kernel/acpi/aml.h)) gives the `SLP_TYPa`
   and `SLP_TYPb` values; the driver writes them to PM1a/PM1b control
   port with `SLP_EN` set.
2. **QEMU ports**. If the firmware doesn't expose `_S5_`, fall back to
   QEMU's `0x604`/`0xB004` legacy shutdown ports — useful in CI.
3. **HLT-park**. If neither worked, mask all IRQs, raise CPL=0, `cli`,
   and `hlt` in a loop. Other CPUs, if SMP is online, get an INIT IPI
   first to stop them from running anything past the halt.

`KernelHalt()` is also the path the panic handler converges on after
writing its post-mortem; see
[Runtime Recovery](../security/Runtime-Recovery.md) for the panic →
halt flow.

## Operator Surface

The shell exposes:

- `reboot` — calls `KernelReboot()`.
- `shutdown` — calls `KernelHalt()` (the name aligns with Unix-side
  expectations; the ACPI literature would call this S5).

Both commands are gated on `kCapPower` (a coarse "may control
machine power state" capability — see
[Capabilities](../security/Capabilities.md)). The default user does
not hold this capability; an operator must elevate first.

## Threading and Locking

- `PowerInit()` runs single-threaded during boot.
- Read accessors are pure reads of immutable snapshot data — no locks
  needed.
- Reboot / halt are terminal. No teardown ordering races to worry
  about, but the implementations explicitly mask interrupts before
  the final write so an IRQ doesn't trample the reset sequence
  mid-flight.

## Thermal Throttle Probe

The thermal throttle flag is sampled at boot and exposed via
`power::ThermalThrottleFlag()`. The runtime checker
([Diagnostics](../kernel/Diagnostics.md)) does **not** currently sample
it post-boot — adding a periodic thermal poll to the heartbeat is a
small, well-bounded next step once the operator surface needs it.

## RAPL Power Telemetry (read-only)

`kernel/arch/x86_64/rapl.{h,cpp}` reads the RAPL (Running Average Power
Limit) energy + power-info MSRs and decodes them into joules / watts /
the TDP envelope. It is **read-only** — it never writes a RAPL MSR.
Raising a power limit (`MSR_PKG_POWER_LIMIT`) without adequate cooling
can overheat the package, so per the
[Hardware-Safety contract](../security/Hardware-Safety.md) RAPL is
read-only telemetry by default; a future limit-*setting* surface must
sit behind a kernel capability + an explicit cooling-aware tune mode.

- **Intel** (architectural since Sandy Bridge): `MSR_RAPL_POWER_UNIT`
  (0x606) for the unit exponents, `MSR_PKG_POWER_INFO` (0x614) for the
  TDP / min / max envelope, `MSR_PKG_ENERGY_STATUS` (0x611) and
  `MSR_DRAM_ENERGY_STATUS` (0x619) for cumulative energy.
- **AMD** (family 17h+): `MSR_AMD_RAPL_PWR_UNIT` (0xC0010299) +
  `MSR_AMD_PKG_ENERGY_STAT` (0xC001029B); no `PKG_POWER_INFO`, so TDP
  reads "unknown".
- **Gating** mirrors the thermal probe exactly: reads issue only when
  `CpuHas(kCpuFeatMsr)` AND the vendor is recognised AND we are not
  under a hypervisor (`IsEmulator()`) — KVM/TCG do not reliably expose
  RAPL, and an unimplemented-MSR `rdmsr` would `#GP`. On those paths
  `RaplRead()` returns `valid=false` and the boot probe logs "no data".
- **Surface:** `RaplRead()` (one-shot), `RaplSamplePackagePowerMw(ms)`
  (busy-waits a window for a live spot reading), `RaplProbe()` (boot
  one-liner), and `RaplSelfTest()` (pure-math unit-decode test, gates
  CI). The `hwmon` shell command shows the package energy / TDP / live
  draw alongside thermal + battery.

## CPU Frequency Telemetry (read-only)

`kernel/arch/x86_64/cpufreq.{h,cpp}` reads the architectural
frequency-reporting MSRs and decodes them to MHz. Like RAPL it is
**read-only** — it never writes a P-state / voltage MSR (`IA32_PERF_CTL`,
the OC mailbox, HWP request); driving frequency or voltage from software
is a physical-damage surface, so frequency is telemetry only.

- **Intel:** `MSR_PLATFORM_INFO` (0xCE) for the base + max-efficiency
  ratios, `IA32_PERF_STATUS` (0x198) for the current operating ratio,
  `IA32_MPERF`/`IA32_APERF` (0xE7/0xE8) for the effective frequency under
  load (`base * dAPERF / dMPERF`). The reference clock is taken as
  100 MHz (Nehalem+/Zen BCLK).
- **AMD:** MPERF/APERF work (effective frequency); the static base/min
  ratios live in P-state-def MSRs and read "unknown" in v0.
- **Gating** is identical to thermal/RAPL (`CpuHas(kCpuFeatMsr)` &&
  vendor && `!IsEmulator()`), so it reports `valid=false` under QEMU.
- **Surface:** `CpuFreqRead()`, `CpuFreqSampleEffectiveMhz(ms)`,
  `CpuFreqProbe()` (boot one-liner), `CpuFreqSelfTest()` (pure-math
  ratio→MHz + effective-freq test, gates CI). Shown by `hwmon`.

## Known Limits / GAPs

- **RAPL is read-only.** Energy / power / TDP readout only; setting a
  power limit is deliberately not implemented (Hardware-Safety
  pre-landing row "RAPL power-limit raise").
- **CPU frequency is read-only.** Current/base/min + effective-frequency
  readout only; no P-state / HWP / voltage writes (Hardware-Safety
  pre-landing row "MSR voltage / Vcore offset").
- **No `_BST` / `_BIF` evaluation.** Battery presence yes, charge /
  capacity / discharge rate no.
- **No EC region reads.** Most laptop sensors (lid switch, fan RPM,
  ambient temp) hang off the embedded controller; v0 leaves it
  untouched.
- **No suspend / resume.** S3 / S4 not modelled.
- **No CPU P-state / C-state selection.** Frequency / idle stays at
  firmware default.
- **No SCI handler.** Power button, lid, AC-plug events are dropped.
- **Thermal MSR is read once.** Periodic resample lands when the
  operator surface needs it.

## Related Pages

- [ACPI](../kernel/ACPI.md) — the parsing layer this driver consumes
- [Runtime Recovery](../security/Runtime-Recovery.md) — terminal halt
  on panic
- [Capabilities](../security/Capabilities.md) — `kCapPower` gate
- [Driver Overview](Driver-Overview.md) — how this driver fits the
  family
- [Diagnostics](../kernel/Diagnostics.md) — thermal as a runtime signal
- [Roadmap](../reference/Roadmap.md) — battery telemetry, suspend / resume
