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
2. **CPU temperature** — `arch::ThermalRead()`. Two vendor paths: Intel
   `IA32_THERM_STATUS` / `IA32_PACKAGE_THERM_STATUS` for current vs
   target temperature deltas plus the throttle flag, and AMD Zen via
   the SMN aperture (see [CPU Temperature](#cpu-temperature) below).
   `PowerSnapshot` carries explicit `cpu_temp_valid` /
   `package_temp_valid` / `tj_max_valid` flags — 0 C is a legal
   reading, so a zero-sentinel could not express "no sensor".
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

## Safe MSR access

Every MSR read on this page goes through
[`arch::ReadMsrSafe`](../../kernel/arch/x86_64/msr_safe.h), an
extable-guarded `rdmsr` mirroring the pre-existing `WriteMsrSafe`
template. A `#GP` from an MSR the part does not implement is redirected
to a fixup that returns `false` with the destination untouched.

Why it matters here: before it existed, a bad `rdmsr` was
unrecoverable, so every consumer on this page defended with a static
"recognised vendor AND not under a hypervisor" gate. That gate was a
prediction, and it was wrong in both directions — it suppressed
frequency telemetry on hypervisors that do expose the counters, and it
was the reason an AMD dev box reported no CPU temperature at all. The
consumers now ASK the hardware and report exactly what came back.

A `false` return means **unsupported**, deliberately a different fact
from a successful read of `0`. Each consumer caches its probe result: a
declined probe costs a trap plus one `[extable] recovered kernel trap`
line, which is diagnostic once and a flood if repeated.

`MsrSafeSelfTest()` gates both extable rows plus a live read of
`IA32_APIC_BASE`. Registration happens in the boot extable block, and
the three sensor probes now run after it.

## CPU Temperature

Intel and AMD do not put the sensor in the same place, so
`arch/x86_64/thermal.{h,cpp}` carries two paths and reports which one
answered in `ThermalReading::source`.

- **Intel** — MSRs. `IA32_THERM_STATUS` (0x19C) bits 22:16 are the
  distance below TJMax; `MSR_TEMPERATURE_TARGET` (0x1A2) supplies
  TJMax, with `tj_max_valid` distinguishing a measured limit from the
  100 C architectural fallback. `IA32_PACKAGE_THERM_STATUS` (0x1B1) is
  the package figure.
- **AMD** — **not an MSR.** Zen reports core temperature through the
  System Management Network: `THM_TCON_CUR_TMP` at SMN address
  `0x00059800`, reached by writing the address to PCI config `0x60` and
  reading `0x64` on device `0:0.0`. Bits 31:21 are an 11-bit count at
  0.125 C/LSB; bit 19 selects the -49..206 C range. The decoded figure
  is Tctl.
- **Family gate** — 17h / 19h / 1Ah only. Pre-Zen AMD parts have a
  thermal register at a different PCI function with a different layout,
  so an unrecognised family reports **unsupported** rather than
  decoding into a confident wrong number.
- **Cross-vendor safety** — the SMN index write is refused unless the
  host bridge answers vendor `0x1022`. On an Intel MCH that offset is a
  DRAM-configuration register, so we never touch it. The index/data
  pair is a two-step non-atomic sequence and takes its own spinlock
  (lockdep class `smn`, ordered above `pci-config`).
- **Decode testing** — the arithmetic lives in the freestanding
  [`cpu_sensor_math.h`](../../kernel/arch/x86_64/cpu_sensor_math.h) and
  is covered by `tests/host/test_cpu_sensor_math.cpp`. This split is
  load-bearing: QEMU models no SMN aperture, so a boot can only prove
  the plumbing does not fault — it can never prove the decode. The
  arithmetic is where a wrong shift silently turns 61 C into 488 C.

**Validation status:** the AMD path is implemented but **not validated
on hardware**. A bare-metal boot on a Zen part would print
`[thermal] source=amd-smn core=<n>C`; under QEMU the correct output is
`[thermal] source=none temp=unsupported`.

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
- **Gating** mirrors the thermal probe exactly: reads issue when
  `CpuHas(kCpuFeatMsr)` AND the vendor is recognised, through
  `ReadMsrSafe`. Presence is then decided by `POWER_UNIT` answering
  something other than 0 or all-ones, which was always the right test.
  There is no "bail under any hypervisor" gate any more — one that
  exposes RAPL yields real numbers, one that does not yields
  `valid=false`.
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
- **AMD (family 17h+):** `MSR_PSTATE_DEF` (0xC0010064 + n) carries
  FID/DID per P-state; `CoreCOF = FID / DID * 200 MHz`. P0 is the base
  frequency and the lowest enabled state is the max-efficiency point.
  `MSR_PSTATE_STATUS` (0xC0010063) names the live state, which is how
  `current_mhz` is obtained on AMD — `IA32_PERF_STATUS` is Intel-only.
  Zen-family-gated for the same reason as the thermal path.
- **APERF/MPERF** additionally require the CPUID advertisement (Intel
  leaf 6 ECX bit 0, AMD `0x80000007` EDX bit 10 `EffFreqRO`) as well as
  a successful read. Without that, QEMU TCG answering 0 for unknown
  MSRs would let us claim counters frozen at zero.
- **Gating**: `CpuHas(kCpuFeatMsr)` && recognised vendor, then per-MSR
  probing through `ReadMsrSafe`. No hypervisor gate.
- **Honesty**: `CpuFreqReading` splits `valid` into `current_valid`,
  `ratios_valid` and `counters_valid`, because a part can publish its
  static base ratio while declining a live operating point. An
  unsupported reading returns entirely empty, so a caller that only
  checks `valid` cannot pick a plausible zero out of the record.
  `TelemetryCpuInfo` propagates `current_mhz_valid` / `base_mhz_valid`
  rather than collapsing them.
- **Surface:** `CpuFreqRead()`, `CpuFreqSampleEffectiveMhz(ms)`,
  `CpuFreqProbe()` (boot one-liner), `CpuFreqSelfTest()` (pure-math
  ratio→MHz + Zen P-state + effective-freq test plus the
  unsupported-vs-zero invariant, gates CI). Shown by `hwmon`.

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
- **Thermal is read once at boot for the snapshot.** `ThermalRead()`
  itself resamples on every call; periodic polling into the heartbeat
  lands when the operator surface needs it.
- **AMD thermal is unvalidated on hardware.** QEMU emulates no SMN
  aperture, so only the decode math and the "reports unsupported"
  behaviour are proven. See the validation note above.
- **AMD reports Tctl, not Tdie.** First/second-generation Threadripper
  and the X-suffix Ryzen 1000/2000 parts bias Tctl above Tdie by a
  fixed +10..+27 C; the bias table is keyed off the brand string and is
  not carried.
- **AMD has no package temperature and no junction limit** on this
  path — the SMN register carries neither, and per-CCD sensors sit at
  family-dependent addresses. Both report unsupported/unknown, never 0.

## Related Pages

- [ACPI](../kernel/ACPI.md) — the parsing layer this driver consumes
- [Runtime Recovery](../security/Runtime-Recovery.md) — terminal halt
  on panic
- [Capabilities](../security/Capabilities.md) — `kCapPower` gate
- [Driver Overview](Driver-Overview.md) — how this driver fits the
  family
- [Diagnostics](../kernel/Diagnostics.md) — thermal as a runtime signal
- [Roadmap](../reference/Roadmap.md) — battery telemetry, suspend / resume
