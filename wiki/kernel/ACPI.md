# ACPI

> **Audience:** Kernel hackers, driver authors, BIOS / firmware hackers
>
> **Execution context:** Kernel — table parse at init; AML **method**
> evaluation (`AmlEvaluate`) runs in process context on demand
>
> **Maturity:** v0 — RSDP/XSDT/MADT/HPET/MCFG/SRAT parsed; namespace
> walker + field/region index + v0 tree-walking method interpreter;
> full ACPICA parity (CreateField, Mutex object semantics, GPIO/
> GenericSerialBus regions) still deferred

## Overview

ACPI on DuetOS is two things:

1. **Boot-time table parser** — RSDP discovery, XSDT walk, per-table
   structured decode. This is what makes the kernel SMP-aware, find IOAPICs,
   route legacy ISA IRQs, and find power-management ports.
2. **AML namespace walker + field/region index** — a DSDT/SSDT
   bytecode walker that records every Name / Method / OperationRegion /
   FieldUnit by canonical path, with constant region offsets/lengths
   decoded so FieldUnits resolve to a backing address. The recursive
   TermList byte parse — the firmware-controlled-input attack surface —
   lives in the memory-safe no_std `duetos_aml` Rust crate
   (`kernel/acpi/aml_rust/`); `aml.cpp` is a thin FFI caller that owns
   the namespace-table storage + accessors and the offset slicers
   (`AmlMethodBody` / `AmlNameValue` / `AmlReadS5`) the evaluator drives.
   It is continuously fuzzed by `tests/fuzz/fuzz_aml`.
3. **AML method interpreter** (`kernel/acpi/aml_eval.{h,cpp}`) — a v0
   recursive tree-walker that actually *executes* a method body:
   operands (Arg/Local/constants/Buffer/Package), arithmetic / bitwise
   / logical ops, If/Else/While/Return/Break/Continue, Store /
   Index / SizeOf / DerefOf, nested method invocation, Sleep/Stall,
   and FieldUnit read/write through SystemIO / SystemMemory directly
   or a registered handler for EmbeddedControl / SMBus / PCI_Config.
   Entry points: `AmlEvaluate(path, args, argc, &out)` /
   `AmlEvaluateInteger(...)`. A boot self-test
   (`AmlEvalSelfTest`) drives synthetic bytecode and emits
   `[acpi/aml-eval] selftest PASS`.

Full ACPICA parity (CreateField/CreateByteField, real Mutex object
semantics, GPIO / GenericSerialBus / IPMI region spaces, computed
OperationRegion bounds, >256-byte Buffers) is **not** in scope for v0
— these are the marked `// GAP:` boundaries in `aml_eval.cpp`. The
EC driver registers an EmbeddedControl region handler via
`AmlRegisterRegionHandler` so `_BIF` / `_BST` / `_Qxx` can run.

Sources:

- [`kernel/acpi/acpi.h`](../../kernel/acpi/acpi.h) +
  [`acpi.cpp`](../../kernel/acpi/acpi.cpp) — table discovery + decode
- [`kernel/acpi/aml.h`](../../kernel/acpi/aml.h) +
  [`aml.cpp`](../../kernel/acpi/aml.cpp) — namespace-table storage,
  accessors, and the FFI bridge to the Rust walker
- [`kernel/acpi/aml_rust/`](../../kernel/acpi/aml_rust/) — memory-safe
  no_std AML TermList walker (the recursive byte parser)
- [`kernel/acpi/aml_eval.h`](../../kernel/acpi/aml_eval.h) +
  [`aml_eval.cpp`](../../kernel/acpi/aml_eval.cpp) — v0 method interpreter
- [`kernel/acpi/ec.h`](../../kernel/acpi/ec.h) +
  [`ec.cpp`](../../kernel/acpi/ec.cpp) — Embedded Controller driver +
  EmbeddedControl region handler
- [`kernel/acpi/acpi_sci.h`](../../kernel/acpi/acpi_sci.h) +
  [`acpi_sci.cpp`](../../kernel/acpi/acpi_sci.cpp) — System Control
  Interrupt handler (power button, PM1/GPE status); see
  [Environment](Environment.md#acpi-sci-power-events-slice-3)
- [`kernel/acpi/acpi_power.h`](../../kernel/acpi/acpi_power.h) +
  [`acpi_power.cpp`](../../kernel/acpi/acpi_power.cpp) — battery / AC /
  lid / backlight method evaluators (consumed by `drivers/power`)
- [`kernel/acpi/srat.h`](../../kernel/acpi/srat.h) — NUMA topology
- [`kernel/acpi/acpi_rust/`](../../kernel/acpi/acpi_rust/) — Rust crate
  for tightly-bounded decoders (see [Rust Subsystems](../tooling/Rust-Subsystems.md))

## Table Discovery

`AcpiInit()` runs in the early boot phase. It:

1. Looks for the RSDP in the EBDA (`0x9FC00..0xA0000`) and BIOS ROM
   (`0xE0000..0x100000`) using the canonical 8-byte signature `RSD PTR `.
2. Uses the RSDP revision to pick XSDT (v2+) over RSDT (v1).
3. Walks the SDT pointer array, checksums each table, and dispatches by
   4-byte signature: `APIC` → MADT, `HPET` → HPET, `MCFG` → MCFG, `SRAT`
   → SRAT, `DSDT`/`SSDT` cached for `aml.cpp` to walk later.

A table that fails its checksum fires the `kAcpiMcfgTruncated` probe (or
the per-table equivalent) and is skipped — the kernel keeps booting on
the tables that did checksum.

## Public Read APIs

```cpp
acpi::LocalApicAddress();                  // u64 phys
acpi::IoApicCount();                       // u32
acpi::IoApicRecords();                     // span<IoApicRecord>
acpi::CpuCount();                          // u32, from MADT LAPIC entries
acpi::IsaIrqToGsi(u8 isa_irq, ...);        // resolves ISA → GSI overrides
acpi::Pm1aControlPort();                   // u16 I/O port for shutdown
acpi::Pm1bControlPort();                   // u16
acpi::HpetAddress();                       // PhysAddr or 0
acpi::McfgAddress();                       // PhysAddr or 0 (ECAM base)
acpi::DsdtAddress() / .DsdtLength();       // for AML walker
acpi::SsdtAddress(i) / .SsdtLength(i);     // per-SSDT
acpi::AcpiReset();                         // writes RESET_REG if present
acpi::AcpiShutdown();                      // S5: _PTS(5)/_GTS(5) then PM1 SLP_TYP
```

All accessors are read-only and IRQ-safe after `AcpiInit()` returns.

## MADT — SMP Topology

The MADT (Multiple APIC Description Table) is the source of truth for:

- CPU count (one local APIC entry per logical CPU)
- IOAPIC base + GSI base per IOAPIC
- ISA → GSI overrides (the classic "IRQ 0 is actually GSI 2" PIT remap)
- NMI source list

The scheduler reads `CpuCount()` to size its per-CPU array
([`kernel/cpu/percpu.cpp`](../../kernel/cpu/percpu.cpp)). The interrupt
router reads `IoApicRecords()` to know which IOAPIC owns which GSI range.

See [CPU Topology](CPU-Topology.md) for the consumer side.

## HPET, MCFG, SRAT

- **HPET** — the HPET base address feeds the
  [time](Time.md#clocksource-selection) clocksource layer. If
  `HpetAddress()` returns 0 the kernel boots on calibrated TSC; if
  neither is available the boot panics.
- **MCFG** — the PCI Express Enhanced Configuration Access Mechanism
  base. [`kernel/drivers/pci/pci.cpp`](../../kernel/drivers/pci/pci.cpp)
  uses it to do MMIO config-space reads instead of falling back to
  CF8/CFC port I/O. See [PCIe Enumeration](../drivers/PCIe-Enumeration.md).
- **SRAT** — System Resource Affinity Table. NUMA memory ranges parsed
  by [`srat.cpp`](../../kernel/acpi/srat.cpp). Currently advisory; the
  frame allocator does not yet honour NUMA-local preference.

## AML Namespace Walker

[`aml.cpp`](../../kernel/acpi/aml.cpp) is **structural** only: it builds
a name → bytecode-offset index from DSDT + every SSDT and answers
questions like "does `\_SB.PCI0.BAT0` exist?" or "what bytes follow the
`_S5_` Package opcode?"

Public surface:

```cpp
bool aml::AmlContainsName(const char* qualified_name);
size_t aml::AmlNamespaceBuild();   // returns entry count
size_t aml::AmlNamespaceCount();
const char* aml::AmlObjectKindName(AmlObjectKind k);
ResultStruct aml::AmlReadS5();     // extracts the SLP_TYPx values from _S5_
```

The walker recognises a handful of opcodes (Name, Scope, Method, Device,
Package, the `_HID` / `_UID` / `_STA` short-form helpers) and treats
everything else as opaque bytes. That is enough to:

- Detect `BAT0` for the power UI
- Find `_S5_` for clean shutdown
- Count Device blocks under `\_SB.PCI0` to cross-check PCI enumeration

The walker itself is **not** enough to execute `_BST` or to evaluate an
EC region read — that is the job of the AML method interpreter
([`aml_eval.cpp`](../../kernel/acpi/aml_eval.cpp), `AmlEvaluate` /
`AmlEvaluateInteger`), which runs over the index this walker builds.

The interpreter is hardened against malformed firmware tables (a crafted
DSDT/SSDT delivered via modified firmware or a hostile VM): `EvalTermArg`
carries a recursion-depth guard (in addition to the existing per-method
`InvokeMethod` cap) so deeply nested operand expressions can't overflow the
kernel stack (ML-04, CWE-674), and `Package` element slots are reserved
contiguously before evaluation so a nested-`Package` element no longer
mis-resolves into a neighbour's arena slot (ML-08, CWE-682). Both are
covered by the `[acpi/aml-eval]` boot self-test (incl. a nested-package
case). (Security audit, 2026-06-07.)

## Rust Decoders

[`kernel/acpi/acpi_rust/`](../../kernel/acpi/acpi_rust/) is a small Rust
crate that exposes byte-stream decoders for the fixed-shape tables
(RSDP / RSDT / XSDT / MADT headers). The C++ side calls into it through
a thin C wrapper. The choice was made because table-bytes-from-firmware
is exactly the call-site profile where memory safety matters more than
C++ ergonomics. See [Rust Subsystems](../tooling/Rust-Subsystems.md).

## Threading and Locking

- All discovery and parsing happens once in `AcpiInit()` during early
  boot, single CPU, IRQs masked. No locking needed at that point.
- Post-init, the public accessors return cached snapshots. They take no
  locks and are safe from any context including IRQ tails.
- `AcpiReset()` / `AcpiShutdown()` are terminal — they take the system
  down, so no concurrency concerns.

## Capability Gates

ACPI itself has no `kCap*` gate — the tables are read once and the
accessors are public. Operations that consume ACPI data (e.g. shutting
down the machine via the shell `shutdown` command) carry their own
gates; see [Capabilities](../security/Capabilities.md).

## Known Limits / GAPs

- **No computed OperationRegion bounds.** The namespace walker decodes
  constant region offsets/lengths only; a region whose base or length
  is a computed expression is not resolved
  ([`aml.cpp:622`](../../kernel/acpi/aml.cpp)).
- **No >1 GiB SystemMemory region.** The AML interpreter's
  SystemMemory FieldUnit read/write path caps the backing region size
  ([`aml_eval.cpp:246`](../../kernel/acpi/aml_eval.cpp)) — revisit if a
  real DSDT needs a larger region.
- **No NUMA-aware allocation.** SRAT is parsed but the frame allocator
  is a single global pool; per-node pools land when SMP scaling
  demands them.
- **No ACPICA-style namespace mutation.** Object lookup is read-only;
  there is no `_INI` walker, no GPE binding.

## Related Pages

- [Boot Path](Boot.md) — when ACPI parsing happens
- [CPU Topology](CPU-Topology.md) — MADT consumer
- [PCIe Enumeration](../drivers/PCIe-Enumeration.md) — MCFG consumer
- [Time](Time.md) — HPET consumer
- [Power Management](../drivers/Power-Management.md) — `_S5_` shutdown,
  battery detection
- [Rust Subsystems](../tooling/Rust-Subsystems.md) — `acpi_rust` crate
