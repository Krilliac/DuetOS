# Intel ME / AMD PSP Mitigation

> **Audience:** Security reviewers, operators evaluating platform posture,
> driver authors who touch low-level MMIO or DMA
>
> **Execution context:** Kernel — fence is installed at boot before any
> non-kernel code executes
>
> **Maturity:** v0 — host-side MMIO fence + AMT network blocks online;
> IOMMU DMA fence deferred until VT-d / AMD-Vi land

## What this is

Intel's **Management Engine** (ME, marketed as CSME / TXE / GSC depending
on platform) and AMD's **Platform Security Processor** (PSP, including
the Cryptographic Co-Processor and System Management Unit mailbox) are
independent coprocessors that sit inside the chipset / SoC. Each runs
its own firmware on dedicated silicon, has full DMA reach into host RAM,
and on platforms that support Intel AMT or AMD DASH can transparently
intercept network traffic through the integrated Ethernet PHY.

The host OS cannot turn them off. Their power, firmware, and lifetime
are owned by the platform vendor and survive reboots, S3 / S5, and even
the host CPU being held in reset.

What the host OS *can* do — and what this module does — is fence the
host-visible interfaces the coprocessors expose, so a compromised host
cannot help them and a remote operator cannot reach AMT through the
normal network stack. This page documents what DuetOS fences, what it
does not, and how to verify the posture on a given platform.

## Threat model

| Attack | Mitigated by DuetOS? | How |
|---|---|---|
| Userland process re-maps the MEI / PSP MMIO BAR and pokes at it | **Yes** | MapMmio deny-list, registered by the kernel-internal probe |
| Compromised in-tree driver opportunistically `ioremap`s the management interface | **Yes** | Same MapMmio deny-list — kernel internals share the gate |
| Win32 / Linux subsystem mediates access to the BAR | **Yes** | Subsystems never reach the BAR; they call kernel APIs that go through the same gate |
| Remote attacker connects to AMT web UI / RAS over the host network stack | **Yes** | Kernel firewall drops AMT / vPro / IPMI ports in both directions |
| ME / PSP itself snoops host RAM via DMA | **No, v0** | Needs IOMMU. Deferred — see "Deferred" below |
| ME / PSP receives traffic delivered to it below the OS (transparent NIC interception) | **No** | Architecturally impossible at OS level — the coprocessor sees the wire before the host stack does |
| ME firmware compromised at flash (vendor compromise, BadUSB-style flash attack) | **No** | Out of scope — the OS only sees what the platform exposes |

The honest summary: this module shrinks the OS-visible attack surface to
zero, but cannot fix the architectural fact that the coprocessor sits
below the OS. For platforms that need stronger guarantees, the
established options are physical disabling at flash time
(`me_cleaner` for Intel chipsets that honour the HAP bit) or choosing
hardware without these coprocessors (e.g. Talos II / Raptor POWER9,
some RISC-V dev boards).

## What DuetOS does

### 1. MMIO deny-list

[`kernel/security/me_psp_guard.{h,cpp}`](../../kernel/security/me_psp_guard.h)
holds a small table of fenced devices. Each entry records the BAR
physical range, the BDF, and the coprocessor kind. The table is
populated at boot by the MEI probe ([`kernel/drivers/mei/mei.cpp`](../../kernel/drivers/mei/mei.cpp))
and the PSP probe ([`kernel/drivers/psp/psp.cpp`](../../kernel/drivers/psp/psp.cpp))
*after* each probe has done its own single mapping. From that point on,
`mm::MapMmio(phys, bytes)` consults the table on every call; an overlap
returns `nullptr` and logs `[me-psp] WARN MapMmio refused phys=…` at
WARN level.

Why "register after own map" rather than "block everything always":
the kernel-internal probe needs to see the BAR exists (size probe, role
classification). It maps once, registers, and never re-maps. The
registration happens before any non-kernel code executes, so the
"one legitimate map" is provably the only one.

### 2. AMT / vPro / IPMI network blocks

`MePspGuardActivate()` installs firewall rules covering the canonical
AMT and IPMI management ports, in both Ingress and Egress directions:

| Proto | Port | Service |
|-------|------|---------|
| TCP | 16992 | AMT web UI (HTTP) |
| TCP | 16993 | AMT web UI (HTTPS) |
| TCP | 16994 | AMT redirection (SOL / IDE-R) |
| TCP | 16995 | AMT redirection over TLS |
| TCP/UDP | 623 | IPMI / RMCP (ASF) |
| TCP/UDP | 664 | RMCP+ (IPMI 2.0 secure) |

Egress rules matter too — they stop an OS-side actor (a misbehaving
driver, a Win32 PE riding the network stack) from initiating an AMT
dial-home through the host stack. They do *not* stop the coprocessor
from talking directly through the NIC below the host stack: that
traffic never crosses the firewall hook. The rule set is install-once
and idempotent.

Not blocked by default:

- **TCP 5900 (VNC)** — Intel AMT KVM Remote Control rides on 5900 on
  some configurations, but 5900 is also the standard VNC port for
  unrelated legitimate workloads. Blocking it would break those. An
  operator who never uses VNC can add the rule manually via the
  `firewall` shell command.
- **TCP 9971 (Intel Mesh Commander)** — niche; surface here so an
  operator who never uses it can add the rule manually.

### 3. Boot-log evidence + selftest

Every fenced device produces a `[me-psp] WARN fence registered …` line
in the boot log. After activation, a single `[me-psp] activated
fenced=N fw_rules_new=M` summary line lands, followed by
`[me-psp-selftest] PASS (fenced=N refused=K)`. The selftest exercises
the deny path with a synthetic fenced range so it is meaningful even
on platforms with no real ME / PSP device.

Boot-log signal to verify (no coprocessor present is fine — the
selftest still passes):

```
[boot] Arming Intel ME / AMD PSP fence.
[boot] Detecting Intel MEI/HECI devices.
[mei] selftest pass
[boot] Detecting AMD PSP / SMU devices.
[psp] selftest pass
…
[boot] Activating ME/PSP guard (AMT / vPro firewall blocks).
[me-psp] activated fenced=<N> fw_rules_new=<16>
[me-psp] fenced=<N> devices …
[me-psp-selftest] PASS (fenced=<N> refused=0)
```

### 4. Runtime status — `mepsp` shell command

The kernel shell exposes `mepsp` (alias `vpro`, `amt`). It prints:

- Every fenced device with its BDF and physical range.
- Lifetime count of refused `MapMmio` calls (any non-zero value is a
  signal — log who tried and why).
- Active AMT firewall rule count and total lifetime hits (hits are an
  intrusion signal — something on the wire is trying to reach AMT).
- A reminder that IOMMU DMA fencing is not yet active.

## Deferred

These are real gaps. They are out of scope for v0 because the
prerequisites are not in the tree yet, not because they are unimportant.

- **IOMMU DMA fencing.** The strongest available mitigation: use
  VT-d (Intel) or AMD-Vi to deny DMA from the ME / PSP BDFs into kernel
  and user RAM. Requires DMAR / IVRS ACPI table parsing and an IOMMU
  domain manager — neither exists in `kernel/` yet. When they land, the
  guard grows a `MePspGuardDmaQuarantine(bdf)` call and every fenced
  device's `dma_quarantine` field becomes meaningful.
- **HAP (Intel "High Assurance Platform") bit detection.** The HAP
  bit lives in the ME firmware region on SPI flash; it tells the ME
  to halt after BRINGUP. We cannot toggle it (it is set with
  `me_cleaner` or `flashrom`), but we can *observe* it indirectly via
  the HFS register on the MEI BAR — if the ME reports the "HAP
  acknowledged" state, the operator has a vendor-independent attestation
  that an external pre-OS step disabled it. Adding this needs the
  existing MEI map to read HFS, which is mechanically cheap.
- **PSP fuses / fTPM disable.** AMD fuses are platform-final and set
  by AGESA before the OS ever runs. The OS can only observe what was
  fused. Out of scope.
- **SPI flash protection.** A future slice could refuse to map the SPI
  controller's BAR for write access, raising the bar for an OS-side
  flash-rewrite attack on the ME / PSP firmware region.

## Verifying on a real platform

1. Boot with serial logging enabled (`tools/qemu/run.sh` does this by
   default).
2. `grep -E '^\[me-psp\]|\[mei\]|\[psp\]|me-psp-selftest' <log>`
3. From the kernel shell: `mepsp` — should show the same device count
   as the boot log, zero `MapMmio refused`, sixteen active AMT rules.
4. From the shell, attempt a connection to AMT: `nc 127.0.0.1 16992`.
   The firewall denial counter should tick up; `firewall log` will
   record the deny.
5. Force-trip the MMIO guard from a debug shell command (planned —
   currently exercised only by the selftest). The refusal counter
   should increment and a WARN line should land on the serial console.

## See also

- [Capabilities](Capabilities.md) — how kernel privilege gates are
  organised; ME/PSP guard is a peer to the cap-system, not built on it
- [Driver Domains](Driver-Domains.md) — the surrounding restartability
  contract; the guard itself is not restartable (it is boot-only state)
- [Firewall Roadmap](../networking/Firewall-Roadmap.md) — the rule
  evaluation engine the AMT blocks plug into
- [`kernel/security/me_psp_guard.h`](../../kernel/security/me_psp_guard.h)
  — public API
- [`kernel/drivers/mei/mei.h`](../../kernel/drivers/mei/mei.h),
  [`kernel/drivers/psp/psp.h`](../../kernel/drivers/psp/psp.h) —
  per-vendor probes
