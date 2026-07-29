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

## CPU Frequency Telemetry

`kernel/arch/x86_64/cpufreq.{h,cpp}` reads the architectural
frequency-reporting MSRs and decodes them to MHz. The read half is
unconditional; the *control* half is default-inert and described in the
next section.

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

## CPU P-state Control (default-inert, operator-unlocked)

Landed 2026-07-29. Until then cpufreq was read-only because
[Hardware-Safety](../security/Hardware-Safety.md) forbade writing
`IA32_PERF_CTL` / HWP at all; the project owner approved P-state
*selection* on 2026-07-29 and that row was amended in the same commit.
**Voltage did not open and is not planned to.**

**Three gates, all required before a single MSR is written:**

1. **Tune mode.** `cpufreq=tune` on the boot cmdline. Off by default —
   without it `CpuFreqSetTarget` returns `TuneModeOff` before reading
   anything, so a normal boot leaves no trace on the hardware.
   `CpuFreqTuneEnable()` is called once from `BootBringupKernelServices`
   and logs `[cpufreq] tune=enabled`.
2. **Capability.** `kCapPowerTune` (`kernel/proc/process.h`). The only
   caller is the shell's `cpufreq set`, which takes it through the
   normal `RequireCap` / elevation-broker path. `arch` has no view of
   the process model, so the cap check is the *caller's* obligation and
   is documented as such on `CpuFreqSetTarget`.
3. **Platform-advertised window.** The request is admitted only if it
   lies inside a window read out of this part's own registers on this
   call. Out-of-window is **refused, not clamped** — clamping would
   apply a number nobody chose with no error to notice
   (`cpu_sensor_math::RatioAdmit`).

**Mechanisms**, preferred in this order:

- **Intel HWP** (`IA32_HWP_REQUEST`, 0x774) when `CPUID.06H:EAX[7]` says
  HWP exists *and* `IA32_PM_ENABLE` bit 0 says firmware already turned
  it on. Window from `IA32_HWP_CAPABILITIES` (0x771) lowest..highest.
  Sets min == max == desired to pin the point; EPP, the activity window
  and the package-control bit are preserved, never chosen by us. Note
  the unit here is an abstract *performance* value, not architecturally
  a bus ratio — it is 1:1 with the ratio on every shipping part, but
  `cpufreq` labels it as such rather than rendering it as MHz.
- **Intel legacy** (`IA32_PERF_CTL`, 0x199) otherwise. Window floor is
  `IA32_PLATFORM_INFO` bits 47:40 (max-efficiency ratio), ceiling is
  `MSR_TURBO_RATIO_LIMIT` (0x1AD) bits 7:0 where the part exposes it,
  else the max non-turbo ratio — never a guessed headroom.
  Read-modify-write preserves bit 32 (IDA/turbo disengage).
- **AMD** (`MSR_PSTATE_CTL`, 0xC0010062) selects an **index** into the
  platform's own `MSR_PSTATE_DEF` table. A lower index is a higher
  frequency. Only indices the platform actually enabled are admitted —
  window membership alone is not enough, since the table can have holes.

**What is never written:** `MSR_PSTATE_DEF` itself (its `CpuVid` field
would couple a voltage to the ratio — the whole reason AMD control is
index selection), the OC mailbox `0x150`, RAPL power limits, and
PROCHOT / thermal-throttle bits. DuetOS also never *enables* HWP:
`IA32_PM_ENABLE` bit 0 is write-once until reset and switching the
platform into hardware-managed P-states is a larger commitment than
setting one operating point.

**Safety of the write itself.** Every write goes through
`WriteMsrSafe`, so a `#GP` on a part that declines the MSR is a
recovered fault and a `WriteFailed` status rather than a dead box. Every
write is then read back from the same register and compared; a
disagreement is `NotVerified`, not silence.

**No guest reach.** No syscall exposes any of this, so no Win32 or Linux
thunk can request a frequency change regardless of the caps the guest
holds. That is deliberate on two counts: an unattended thermal load, and
the fact that a workload able to modulate the clock has a
cross-isolation signalling channel and a Hertzbleed-class timing
amplifier.

**Surface:** `CpuFreqControlRead()` (window + mechanism + current, safe
on any boot), `CpuFreqSetTarget(value)`, `CpuFreqTuneEnabled()`,
`CpuFreqSetStatusName()`. Operator command: `cpufreq` shows the window,
`cpufreq set <n>` applies one and then reports a 200 ms APERF/MPERF
*delivered* frequency, which is a different claim from "the request
register holds what we wrote."

**Boot log:** `[cpufreq] ... control=<hwp|perf_ctl|amd_pstate|none>
window=<lo>..<hi> tune=<on|off>` on every boot;
`[cpufreq] set mechanism=… old=… new=…` at WARN on each transition.

## Known Limits / GAPs

- **RAPL is read-only.** Energy / power / TDP readout only; setting a
  power limit is deliberately not implemented (Hardware-Safety
  pre-landing row "RAPL power-limit raise").
- **CPU P-state control is silicon-unverified.** The gating, the
  admission math and the read path are proven (host tests + boot
  self-test + clean boot under TCG and KVM). The *write* path is not:
  QEMU answers none of the frequency MSRs under either accelerator, so
  no boot has ever executed a `wrmsr` to `IA32_PERF_CTL` /
  `IA32_HWP_REQUEST` / `MSR_PSTATE_CTL`, and QEMU models no real
  P-states, so even a write that returned without faulting would prove
  nothing about delivered frequency. First-boot-on-real-hardware should
  check `cpufreq` reports a plausible window, then `cpufreq set` and
  confirm the reported APERF/MPERF *delivered* MHz moved.
- **No EPP / energy-performance preference control.** The HWP path
  preserves whatever EPP firmware set and never chooses one. An EPP
  hint is a separate policy knob (Roadmap: EPP + idle governors).
- **HWP is never enabled by DuetOS.** On a part where firmware left
  `IA32_PM_ENABLE` bit 0 clear, control falls back to legacy
  `IA32_PERF_CTL`. Enabling HWP is write-once until reset; the decision
  belongs with the EPP / idle-governor work.
- **Per-CPU, not system-wide.** `CpuFreqSetTarget` writes the MSR on the
  CPU that runs it. On Intel HWP and on parts with per-core P-states,
  other cores keep their previous operating point; there is no
  broadcast-to-all-CPUs path yet.
- **No idle governor / C-state selection.** Idle stays at firmware
  default.
- **RAPL is still read-only.** Raising a power limit is a separate,
  unapproved surface — the P-state slice did not open it.
- **No `_BST` / `_BIF` evaluation.** Battery presence yes, charge /
  capacity / discharge rate no.
- **No EC region reads.** Most laptop sensors (lid switch, fan RPM,
  ambient temp) hang off the embedded controller; v0 leaves it
  untouched.
- **S3 suspend/resume: core landed, gated.** The wake trampoline, the
  CPU architectural save/restore, the FACS waking-vector handshake and
  the per-driver Suspend/Resume + veto contract are in tree (see
  "Suspend-to-RAM (S3)" below). It is REFUSED on any machine that has
  probed NVMe / AHCI / a NIC, on SMP, and under firmware that declines
  the waking vector. S4 is not modelled at all.
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

## Suspend-to-RAM (S3)

Landed 2026-07-29. Three pieces:

| Piece | File | Job |
|---|---|---|
| ACPI plumbing | `kernel/acpi/acpi.cpp`, `aml.cpp` | `FacsAddress`, `AcpiSetWakingVector`, `AcpiSleepTypeFor`, `AcpiSleepWriteControl`, generic `AmlReadSleepPackage` |
| Wake trampoline + context | `kernel/arch/x86_64/acpi_wakeup.{S,cpp,h}` | real -> protected -> long mode blob at physical `0x9000`; `AcpiSuspendEnter` / `AcpiWakeResume64` save/restore pair |
| Orchestration | `kernel/power/suspend.{h,cpp}` | participant + veto registry, refusal outcomes, self-test |

### The refusal contract

`PowerSuspendToRam` returns a `SuspendOutcome`; only `Cycled` means the
machine slept. The other five each name a distinct reason
(`no-acpi-s3-package`, `no-waking-vector`, `device-refused`,
`multiple-cpus-online`, `platform-declined`). Nothing collapses into a
falsy value: `SLP_TYP == 0` is a legal encoding, so "firmware declares
no `\_S3`" is carried by a bool return, never by a zero.

Drivers opt in with `PowerSuspendRegister(name, prepare, resume)` or
opt out with `PowerSuspendVeto(name, reason)`. Today:

| Driver | Status |
|---|---|
| serial (16550) | participant — `SerialInit` on resume |
| PS/2 keyboard, PS/2 mouse | participants — `Ps2KeyboardResume` / `Ps2MouseResume` re-run the 8042 bring-up and re-route the IOAPIC pin |
| block storage (NVMe / AHCI) | **veto** — no controller re-init after platform reset |
| NIC | **veto** — no controller re-init after platform reset |

Because the vetoes are registered at the drivers' attach site, S3 is
available only in the boot window before storage and networking come
up. That window is where the live self-test runs.

### Proving it

`tools/test/s3-cycle-smoke.sh` boots with `s3test=1`, waits for
`[suspend] entering S3`, confirms QEMU's run-state is `suspended`,
delivers a QMP `system_wakeup` (`tools/qemu/qmp.sh wakeup`), then
requires the resume sentinel, continued log output, and no fault
signature afterwards.

Two QEMU-specific notes, both learned the hard way:

- **`-no-reboot` breaks S3.** Waking goes THROUGH a platform reset, so
  `-no-reboot` turns a healthy resume into a shutdown before the guest
  executes an instruction. `DUETOS_ALLOW_REBOOT=1` drops the flag.
- **SeaBIOS resumes, OVMF does not.** Under `DUETOS_LEGACY=1` the
  firmware re-enters the waking vector and the cycle completes. Under
  OVMF the trampoline's first real-mode breadcrumb never appears, so
  the firmware is not honouring the vector. UEFI S3 resume is therefore
  unproven.

### Known limits

- `ResumePlatform` re-maps MMIO as well as re-programming the LAPIC /
  IOAPIC / HPET. The MMIO arena is a bump allocator with no free, so
  each cycle leaks arena; an `s3test=1` boot faults later in the VirtIO
  probe. Tracked as Roadmap item 23.
- No AP park/resume, so `PowerSuspendCheck` refuses on SMP.
- S0ix untouched.
