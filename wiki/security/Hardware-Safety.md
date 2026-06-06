# Hardware Safety — the default-inert contract

> **Audience:** Driver authors, kernel hackers, security / threat modellers, anyone wiring a new controller into the boot path
>
> **Execution context:** Spans kernel boot bring-up, driver probe, and the storage/FS write paths — wherever DuetOS touches *persistent* or *physical* hardware state
>
> **Maturity:** Living contract. The "current posture" table reflects an audit as of 2026-06-06; the "pre-landing preconditions" table is forward-looking and binds work that is **not yet in tree**.

## The principle

DuetOS boots on **real commodity hardware** — a laptop or desktop that
very likely already holds a Windows or Linux install and the owner's
data. Unlike a hobby OS that only ever runs in QEMU against a scratch
image, every persistent or physical effect DuetOS has on that machine
is real and frequently **irreversible**: a clobbered partition table,
a filled NVRAM store, an over-volted CPU, a stopped fan.

The governing rule, established by the incident below and binding on
every subsystem that follows:

> **Default to inert.** A path that mutates persistent storage, firmware
> / NVRAM, or any physical-state register (voltage, power, thermal, fan,
> RF transmit power, display timings) must be **closed by default** and
> open **only** after a *positive* proof of DuetOS ownership *and* an
> explicit operator-authorized action. The absence of a guard is not a
> licence to act — it is the signal to stay inert.

Four corollaries, each grep-able into existence:

1. **Positive ownership, never default-to-act.** Adopt / write only when
   a DuetOS-owned signature is present (a GPT type GUID, a FAT
   `kDuetOsVolumeId`, an exFAT `kDuetOsVolumeSerial`, a region-sanity
   bounds check). No marker ⇒ not ours ⇒ hands off. "Fall back to the
   first writable thing" is the bug class, not the feature.
2. **The gate is kernel-owned.** Per the [Subsystem
   Isolation](../kernel/Subsystem-Isolation.md) rules, a Win32 or Linux
   guest can never flip a physical-state capability. These mutators sit
   behind a kernel capability that only an operator-authorized native
   action sets.
3. **Honor safety signals; never suppress them.** Thermal throttle /
   PROCHOT, regulatory TX-power clamp, IOMMU faults, EC-owned fan floors
   are *obeyed*. Code that disables a protection mechanism is presumed
   wrong.
4. **One ownership predicate, not N call-site checks.** The incident
   happened because ownership was checked per-call-site and one site was
   missed. The durable form is a single predicate every persistent-write
   primitive routes through (see *Cross-cutting structural gates*).

## The incident anchor (commit 7bb94062)

Two boot-time paths could corrupt a disk DuetOS was merely *running on*,
because both defaulted to acting in the absence of a guard:

- **Vector A — crash-dump persist wrote the physical disk tail.**
  `NvmeDumpReservedLba` / `AhciDumpReservedLba` fell back to
  `sector_count - kReservedSectors` (the last 4 MiB) when no DuetOS
  crash-dump partition existed — landing on the backup GPT header and a
  WinRE partition. `DiskPersistSelfTest` fired the write on *every*
  boot. **Fix:** return 0 (skip) unless `GptFindCrashDumpRegion` finds a
  `kDuetCrashDumpTypeGuid` partition that passes `GptCrashDumpRegionSane`.
- **Vector B — any FAT volume was adopted as the system volume.**
  `Fat32Probe` registered every probed FAT volume, so a Windows EFI
  System Partition could become `Fat32Volume(0)` — the volume ~120 call
  sites write to. **Fix:** adopt only volumes carrying both
  `kDuetOsVolumeId` + `kDuetOsVolumeLabel` (`Fat32VolumeIsDuetOsOwned`).

Both fixes inverted the default from *act* to *inert*. This page
generalizes that inversion to every hardware surface, current and
future.

## Current posture — what the 2026-06-06 audit confirmed safe

A five-domain audit (storage/FS, CPU/power/firmware, memory/DMA/MMIO,
GPU/display/NIC/audio, plus a web-sourced damage checklist) found the
tree already follows the contract everywhere except one latent gap
(exFAT, since fixed). Confirmed-safe state, so a future change that
*regresses* one of these is a contract violation:

| Surface | Posture today | Guard |
|---------|---------------|-------|
| **FAT32 adoption** | Inert-by-default | `Fat32VolumeIsDuetOsOwned` — foreign FAT (Windows ESP, USB) never registered |
| **exFAT adoption** | Inert-by-default | `ExfatVolumeIsDuetOsOwned` (`kDuetOsVolumeSerial`) — landed 2026-06-06; foreign exFAT not registered |
| **Crash-dump persist** | Inert-by-default | `GptFindCrashDumpRegion` + `GptCrashDumpRegionSane` bounds (excludes primary + backup GPT) |
| **NTFS / ext4** | Read-only tier | No write API compiled in; selftests write only RAM disks |
| **FAT32 / exFAT write** | Bounded tier | In-place / append / create / delete / rename; no cluster-chain growth past envelope |
| **TRIM (`fstrim`)** | Owned-only | Routes through `Fat32Volume(idx)` → only owned volumes; discards free clusters within the partition |
| **CPU MSRs** | No physical-state writes | No Vcore/`0x150`, no RAPL `PKG_POWER_LIMIT`, no thermal-throttle/PROCHOT disable. SYSCALL/EFER/CET writes panic-on-fault by design |
| **RAPL telemetry** | Read-only (landed 2026-06-06) | `arch/x86_64/rapl.cpp` reads energy/power/TDP MSRs only; never writes a limit. Vendor + hypervisor gated like thermal. See [Power-Management](../drivers/Power-Management.md) |
| **CPU frequency telemetry** | Read-only (landed 2026-06-06) | `arch/x86_64/cpufreq.cpp` reads current/base/min + effective (MPERF/APERF) frequency only; never writes `IA32_PERF_CTL`/HWP/voltage. Same vendor + hypervisor gating |
| **UEFI NVRAM** | No writes | No `SetVariable` / capsule / `UpdateCapsule` path exists |
| **SPI flash / microcode** | No writes | None; **ME/PSP guard** actively refuses PCI config writes to coprocessor BDFs (`me_psp_guard`) |
| **CMOS / RTC** | Bounded | `RtcWrite` bounds-checked, freeze/unfreeze, touches only time bytes 0x00–0x09 |
| **ACPI** | Read-only inputs | Tables not mutated; only spec-mandated FADT-sourced handshakes (ACPI_ENABLE, S5, RESET_REG) |
| **EC** | ACPI-mediated only | Writes only via AML region handler with timeouts; no EC-firmware flash, no raw register pokes |
| **DMA** | Owned-buffer only | NVMe PRP / AHCI PRDT point only at kernel-owned staging buffers; zone-clamped with panic-on-violation |
| **PCI BARs** | Firmware-assigned | Size-probe writes restored; no permanent BAR reprogram |
| **GPU / display / NIC / audio** | Volatile-only | No clock/voltage/fan/VBIOS/EEPROM/MAC/TX-power writes; modeset uses readback-verify; HDA gain hardcoded mid-range |
| **IOMMU** | Present, **OFF by default** | VT-d discovery→enable implemented but gated off; AMD-Vi parse-only. See *pre-landing* below |

## Pre-landing preconditions — bind these BEFORE the owning driver lands

Most of the high-severity damage classes correspond to controllers
DuetOS **has not implemented yet**. The safest state for an unwritten
risky writer is *non-existence* — and when one is written, it must ship
its safety gate in the same slice, not as a follow-up. Each row is the
acceptance criterion the implementing slice must satisfy; the owning
roadmap section links back here.

Severity: **BRICK** (permanent, no software recovery) > **PHYS-DMG**
(hardware degradation) > **DATA-LOSS** (user/other-OS data) >
**RECOVERABLE** (a tool can repair).

| Controller (unimplemented) | Severity | Damage if unguarded | Mandatory gate before it lands |
|----------------------------|----------|---------------------|--------------------------------|
| **UEFI variable writes** (boot-entry install, OS-indications) | BRICK | Wiping/corrupting NVRAM bricks non-conformant boards; `BootOrder` edits lock the user out of Windows | Read-only by default; **append-only** to your own `Boot####` + vendor-GUID namespace; never delete/reorder existing entries; back up `BootOrder` first; explicit "install bootloader" action |
| **UEFI capsule / firmware update** | BRICK | A bad/unsigned capsule bricks the board | Do not implement. If ever added: signed capsules verified against firmware keys, Secure-Boot-aware, multi-confirm operator gate |
| **SPI flash / BIOS ROM writes** | BRICK | Partial/incorrect write bricks the platform | Do not write platform SPI flash. Respect hardware WP / flash-descriptor lockdown. Keep the `me_psp_guard` fence |
| **EC firmware flash / raw EC register writes** | BRICK / PHYS-DMG | EC owns fan, battery, thermal, power sequencing — misprogramming permanently overheats the machine | EC access stays ACPI/AML-mediated only; no EC-firmware flashing; no undocumented register pokes |
| **GPU VBIOS / EEPROM flashing** | BRICK | A power-loss mid-flash, or wrong image, bricks the card | Do not flash GPU ROM. No code path writes the card's EEPROM |
| **NIC EEPROM / NVM / MAC writes** | BRICK | Corrupting EEPROM/MAC/calibration permanently disables the adapter | NIC NVM read-only; load vendor RF firmware to RAM only, never write it |
| **MSR voltage / Vcore offset** (`0x150`, OC mailbox) | PHYS-DMG | Undervolt faults silicon (Plundervolt); overvolt degrades the die | Forbid voltage MSR writes by default; OC-lock stance. Behind a kernel-cap tuning mode only, never a guest |
| **RAPL power-limit raise** (`MSR_PKG_POWER_LIMIT`) | PHYS-DMG | Raising PL1/PL2 without cooling overheats the package | RAPL is read-only telemetry by default; raising limits requires an explicit cooling-aware tune mode |
| **Thermal-throttle / PROCHOT / TCC disable** | PHYS-DMG | Last line of defence against silicon cook-off | Never disable. Honor throttle signals; no code clears thermal-control bits |
| **Fan PWM / RPM control** (EC fan, GPU fan curve) | PHYS-DMG | A stuck-at-0% fan thermally kills CPU/GPU | Never command below the hardware safety floor; if DuetOS doesn't run a thermal feedback loop, leave fans to EC/firmware (inert) |
| **GPU clock / voltage tables** (pp_table, SMU/SMC) | PHYS-DMG | Overvolt degrades/destabilizes the GPU | Ship stock clocks/voltages only; no OC by default |
| **Display modeset / PLL programming** | PHYS-DMG | Driving a panel out of spec can electrically stress aging hardware | Drive only EDID-advertised modes; if EDID is absent/invalid, fall back to a guaranteed-safe low mode (640×480@60 / 1024×768@60), never a guessed high-rate mode |
| **Wi-Fi TX power** | PHYS-DMG (+ legal) | Exceeding limits overheats the PA/PHY and is illegal | Clamp to lesser of regulatory limit and EEPROM-calibrated max; default to the most-restrictive ("world") domain until a country is set. See [Wireless-Regulatory](../drivers/Wireless-Regulatory.md) |
| **Battery charge thresholds** (charger IC / EC) | PHYS-DMG | Misprogrammed charge voltage/current is a fire/thermal hazard | Leave battery management to EC/firmware; no charge-limit writes without a validated EC-mediated API |
| **ATA Secure-Erase / NVMe Sanitize / Format-NVM** | DATA-LOSS | Wipes the *entire* drive, unrecoverably | Never in a default/boot path; explicit operator command; select the device **by serial, not enumeration index** |
| **TRIM on a new range / non-owned volume** | DATA-LOSS | Discarded blocks are unrecoverable | Never auto-TRIM outside an owned partition (today's `fstrim` already satisfies this — keep it owned-only) |
| **DMA without IOMMU** (any new bus-master driver) | DATA-LOSS | A bad descriptor scribbles firmware / other-OS memory | Enable + enforce the IOMMU before bus-master DMA; map only driver-owned buffers; validate descriptor targets (the NVMe/AHCI staging-buffer pattern) |
| **Partition / GPT writes** (installer, partitioner) | DATA-LOSS | Clobbering primary/backup GPT or a foreign partition destroys another OS | Partition-relative LBA with hardcoded bounds; never touch protective MBR / primary GPT / **backup GPT at the last LBA** except in an explicit, consented partition op; validate primary↔backup agreement first |
| **New foreign-FS write tier** (NTFS write, ext4 write, foreign-FAT RW) | DATA-LOSS | Corrupts another OS's data + journal | Enforce the documented read-only/bounded tiers at the VFS boundary; a write into a read-only backend must hard-fail, not fall through; require an ownership signature + explicit consent for RW |

## Cross-cutting structural gates

Three structural moves convert "remember to check at each call site" (the
class-of-bug that caused the incident) into enforced properties:

1. **One ownership predicate, one chokepoint.** A single
   `DiskRegionIsOwned(lba, len)` / `VolumeIsOwnedByDuetOS(vol)` that
   *every* persistent-write primitive routes through — no write primitive
   callable without it. The block layer's optional `BlockWriteGuard`
   (Off / Advisory / Deny) is a good defense-in-depth start; promoting an
   ownership predicate to a *mandatory* gate on the write primitive itself
   is the durable fix. (This is the [Roadmap](../reference/Roadmap.md)
   "ownership write-chokepoint" item.) Matches the
   [CLAUDE.md](../../CLAUDE.md) "whitelist incompleteness" class-of-bug
   guidance — convert per-call-site allow-lists into a property test.
2. **Default-inert capability.** Every physical-state mutator (voltage /
   RAPL / thermal, fan PWM, TX power, out-of-EDID timings, TRIM / erase,
   any firmware / NVRAM write) compiles behind a kernel capability that is
   **off** unless an explicit operator install/tune step set it. Per
   [Subsystem Isolation](../kernel/Subsystem-Isolation.md), a guest
   PE/ELF can never flip it.
3. **Device selection by serial, never by index.** Whole-device
   destructive ops (erase / sanitize / format / partition) identify the
   target by serial number, so an enumeration-order change can't redirect
   the operation onto the wrong drive.

## Re-running the audit

This contract was derived by a five-way parallel audit. To re-run it
after a hardware slice lands (or on a cadence):

- **Fan-out by domain** — storage/FS write paths; CPU/power/firmware
  MSR + port writes; memory/DMA/MMIO; GPU/display/NIC/audio device state.
  For each, the question is literally: *"Could a default boot, or a
  malicious/buggy PE/ELF guest, reach this mutation without an ownership
  check and an explicit enable?"*
- **Greps that bound the surface** (every hit is a review target):
  ```
  git grep -nE '\bwrmsr\b|SetVariable|UpdateCapsule|spi.?flash'
  git grep -niE '\b(trim|blkdiscard|secure.?erase|sanitize|format.?nvm)\b'
  git grep -niE 'fan.?(pwm|speed|curve)|txpower|tx_power|charge.?(limit|voltage)|vbios|eeprom.?write'
  git grep -nE '0xCF9|outb?\(0x64|Outw?\(g_pm1|wrmsr.*0x150'
  ```
- **The self-tests are the regression anchors.** `Fat32OwnershipSelfTest`,
  `ExfatSelfTest` (foreign-reject leg), and the `GptCrashDumpRegionSane`
  math test panic-on-fail and gate CI. A new ownership gate should land
  with a matching foreign-reject self-test.

## Sources

External damage taxonomy and mitigations behind the pre-landing table:

- [LWN — Bricking systems using rm](https://lwn.net/Articles/674940/) (UEFI NVRAM brick)
- [rodsbooks — Repairing GPT disks](https://www.rodsbooks.com/gdisk/repairing.html) (backup GPT at last LBA)
- [fwupd — uefi-capsule plugin](https://github.com/fwupd/fwupd/blob/main/plugins/uefi-capsule/README.md) (capsule / BootOrder hazards)
- [Plundervolt](https://www.techtarget.com/searchsecurity/definition/Plundervolt) + [intel-undervolt MSR warning](https://github.com/kitsunyan/intel-undervolt) (voltage MSR damage)
- [Intel Community — Disabling Thermal Throttling](https://community.intel.com/t5/Processors/Disabling-Thermal-Throttling/td-p/1238985) (PROCHOT/TCC)
- [Chromium EC — write protection / fan / battery](https://chromium.googlesource.com/chromiumos/platform/ec/+/HEAD/docs/write_protection.md) (EC-owned thermal/power)
- [Overclock.net — how flashing a GPU BIOS bricks](https://www.overclock.net/threads/so-how-does-flashing-a-gpu-bios-actually-brick-the-card.1796252/) (VBIOS)
- [KTC — damage from forcing higher refresh](https://us.ktcplay.com/blogs/support-tips/damage-monitor-forcing-higher-refresh-rate) (out-of-spec modeset)
- [Wolph — max Wi-Fi TX power per country](https://w.wol.ph/2015/08/28/maximum-wifi-transmission-power-country/) (regulatory)
- [Attingo — TRIM data loss](https://www.attingo.com/blog/trim-command-with-solid-state-drives/) + [ata.wiki — ATA Secure Erase](https://ata.wiki.kernel.org/index.php/ATA_Secure_Erase) (irreversible discard/erase)
- [Intel — Using IOMMU for DMA Protection in UEFI (PDF)](https://www.intel.com/content/dam/develop/external/us/en/documents/intel-whitepaper-using-iommu-for-dma-protection-in-uefi-820238.pdf) + [CERT VU#382314](https://kb.cert.org/vuls/id/382314) (DMA / IOMMU)

## See also

- [Subsystem Isolation](../kernel/Subsystem-Isolation.md) — why a guest can never flip a physical-state capability
- [IOMMU (VT-d + AMD-Vi)](../drivers/IOMMU.md) — DMA-remapping driver (present, off by default)
- [ME / PSP Mitigation](ME-PSP-Mitigation.md) — the coprocessor config-write fence
- [Wireless-Regulatory](../drivers/Wireless-Regulatory.md) — TX-power clamp domain
- [Roadmap → Hardware safety](../reference/Roadmap.md) — the open work items this page anchors
