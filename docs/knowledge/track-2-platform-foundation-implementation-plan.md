# Track 2 Deep Dive — Platform Foundation Implementation Plan

_Last updated: 2026-04-20_

## Design Intent

Track 2 is the platform stabilization track that unlocks everything else. The design principle is:

- keep the earliest boot path deterministic,
- move complexity behind validated interfaces,
- avoid hidden ordering dependencies.

If this track is weak, later subsystems (VFS, drivers, compositor, Win32) become unstable and expensive to debug.

---

## Scope

This plan covers:

1. UEFI handoff contract.
2. ACPI table ingestion and validation.
3. SMP AP bring-up and per-CPU lifecycle.
4. PCIe discovery and resource assignment.
5. Early diagnostics and crash visibility.

---

## Architecture Choices

### 1) BootInfo Contract (single immutable handoff object)

Create a single versioned `BootInfo` blob passed from bootloader to kernel with:

- memory map descriptors,
- framebuffer descriptor,
- ACPI RSDP pointer,
- SMBIOS pointer (if present),
- EFI runtime map snapshot metadata,
- boot device identification,
- command line and boot flags.

**Why:** avoids ad-hoc global variables and ordering bugs.

**Tradeoff:** strict schema versioning work up front, but dramatically better long-term compatibility.

---

### 2) ACPI Parser Strategy (strict + defensive)

Implement ACPI parsing as a standalone module with:

- checksum validation on all used tables,
- signature/length bounds checks,
- support for: RSDP → XSDT/RSDT → MADT/MCFG/FADT/HPET,
- explicit “table present/not present” typed result.

**Why:** malformed firmware data is common in real hardware.

**Maintenance burden:** medium; table-specific quirks must be documented by DMI signature where needed.

---

### 3) SMP Bring-up Contract

Define AP state machine:

- `Offline` → `InitSent` → `StartupSent` → `TrampolineEntered` → `PerCpuInit` → `SchedulerReady` → `Online`.

Per-CPU structure must include:

- CPU id and APIC id,
- kernel stack pointer,
- scheduler runqueue pointer,
- interrupt nesting/lock counters,
- per-CPU stats pointers.

**Why:** explicit states reduce deadlock and half-online CPU classes of bugs.

---

### 4) PCIe Enumeration Model

Implement bus walk with stable device identity:

`segment:bus:device.function` + vendor/device IDs + class/subclass/prog-if.

Resource pipeline:

1. Read BAR shape,
2. size probe,
3. allocate window,
4. write final BAR,
5. enable bus mastering only after driver attach decision.

**Why:** enforces security and correctness around DMA-capable devices.

---

### 5) Early Diagnostics

Hard requirement: every fatal boot-stage failure emits:

- stage identifier,
- error code,
- minimal context (CPU id, pointer/value),
- sink to serial and framebuffer.

**Why:** without this, real-machine bring-up is near impossible at scale.

---

## Implementation Breakdown (ordered work items)

## T2-01 BootInfo v1 Finalization

**Tasks**

- define packed + validated schema with version field,
- loader fills all known fields, kernel validates version and size,
- reject mismatched schema with explicit panic code.

**Acceptance tests**

- valid handoff boots,
- invalid version rejected with deterministic panic code,
- missing optional fields handled gracefully.

---

## T2-02 ACPI Discovery + Validation

**Tasks**

- locate RSDP from boot info,
- parse XSDT (fallback RSDT),
- validate and index required table pointers,
- expose typed query API for MADT/MCFG/FADT/HPET.

**Acceptance tests**

- malformed checksum table is rejected,
- missing table path does not crash kernel,
- known QEMU ACPI layout parses consistently.

---

## T2-03 AP Trampoline + Secondary CPU Entry

**Tasks**

- install trampoline page,
- issue INIT/SIPI sequence using LAPIC,
- AP enters long mode and jumps into shared secondary entry,
- AP completes per-CPU init and reports online.

**Acceptance tests**

- N-core VM brings all APs online,
- timeout path logs failing APIC id,
- AP failure does not corrupt BSP scheduler.

---

## T2-04 Per-CPU Runtime Structures

**Tasks**

- allocate per-CPU blocks,
- wire GS-base or equivalent per-CPU access primitive,
- move scheduler counters/timers to per-CPU storage,
- enforce no shared mutable global fallback.

**Acceptance tests**

- scheduler tick/accounting correct on multi-core,
- lock contention stats per-CPU visible,
- no race warnings in stress harness.

---

## T2-05 PCIe Core Enumerator

**Tasks**

- MCFG-backed MMIO config access,
- enumerate all functions,
- store canonical device descriptors,
- expose match API for drivers.

**Acceptance tests**

- detected device count stable across boots,
- class/vendor parsing valid for QEMU + one real machine,
- malformed config read handled without panic.

---

## T2-06 BAR Allocation + Security Guardrails

**Tasks**

- centralized PCI resource allocator,
- BAR mapping into controlled MMIO region,
- default deny bus-mastering until bound driver authorizes,
- audit log for all DMA-capable enable operations.

**Acceptance tests**

- overlapping BAR assignment impossible,
- unauthorized driver cannot enable bus mastering,
- MMIO mapping always non-executable.

---

## T2-07 Boot Diagnostics Framework

**Tasks**

- stage-based boot logger,
- panic code registry,
- serial + framebuffer mirror sinks,
- boot failure summary persisted for next boot retrieval.

**Acceptance tests**

- induced failures emit deterministic stage + code,
- logs visible on both sinks,
- summary retrieval works after reboot.

---

## Security Requirements Embedded in Track 2

1. ACPI and firmware data is untrusted input; always validate.
2. No executable mappings for firmware/PCI MMIO regions.
3. DMA enable must be explicit and audited.
4. AP startup timeout/abort paths must be bounded and non-blocking.
5. Diagnostic output must avoid leaking secrets in release mode.

---

## Threading/Execution Context Notes

- AP bring-up code runs in low-level startup context (not scheduler-safe).
- ACPI table parsing is boot-time single-threaded.
- PCI enumeration initially boot-time single-threaded, later async-safe once lock policy exists.
- Diagnostic sinks must be IRQ-safe for panic path use.

---

## Known Risks

- Firmware quirks may require DMI-specific compatibility paths.
- AP startup sequences can be timing-sensitive on some hardware.
- Incorrect BAR handling can cause silent device malfunction or memory corruption.

Mitigation: strict staged tests, defensive defaults, and exhaustive telemetry early.

---

## Deliverables to Produce Next (from this plan)

1. `docs/architecture/bootinfo-v1.md`
2. `docs/architecture/acpi-parser-contract.md`
3. `docs/architecture/smp-bringup-state-machine.md`
4. `docs/architecture/pci-resource-security.md`
5. `docs/testing/track2-validation-matrix.md`

