# Boot Path

> **Audience:** Kernel hackers
>
> **Execution context:** Kernel — boot CPU, IRQ-disabled until APIC online
>
> **Maturity:** Active

## Overview

The boot path takes the system from UEFI firmware (or legacy BIOS via
GRUB) to a fully-initialised kernel running the scheduler with drivers
probed. The order is intentionally strict — partially-live subsystems
must not be exposed before their dependencies are alive.

## Boot path (x86_64)

```
UEFI firmware
   -> boot/uefi/BOOTX64.EFI (PE32+ stub)
   -> loads kernel as ELF with a thin stub
   -> kernel entry in long mode
   -> per-CPU bringup
   -> init process
```

Today the canonical boot path is **Multiboot2 + GRUB**. The hybrid ISO
boots both SeaBIOS (legacy CSM) and UEFI (OVMF in QEMU; native firmware
on real hardware) from a single image. See
[`.claude/knowledge/uefi-hybrid-iso-v0.md`](../../.claude/knowledge/uefi-hybrid-iso-v0.md)
for the ISO-build details.

## Kernel execution order at boot

```
Early console
   -> physmem map ingest
   -> paging on (4-level + higher-half mappings)
   -> heap (kheap)
   -> IDT/GDT
   -> APIC + LAPIC timer (PIT-calibrated, 100 Hz)
   -> SMP AP bringup
   -> scheduler online
   -> drivers (PCIe -> NVMe -> graphics -> input)
   -> VFS
   -> init
```

### Bring-up dependency chain

```
MMU before scheduler context switches
-> scheduler before user threads
-> PCI enumeration before device-class probes
-> block / network / input before higher services
-> core services before Win32 translator workloads
```

## Boot stack high-VMA alias

The boot stack is mapped twice during early boot — once at the
identity-mapped low address used by the AP entry trampoline and once at
the higher-half VMA the kernel actually runs at. Without the alias,
the first task switch out of the boot context double-faults on the
first user CR3 load. See
[`.claude/knowledge/boot-stack-high-vma-fix.md`](../../.claude/knowledge/boot-stack-high-vma-fix.md).

## Verification

The end-to-end "did it boot" gate is `tools/test/ctest-boot-smoke.sh`.
A clean boot prints the "ProductName=DuetOS" smoke line, runs through
the registry / fopen test, and exits with rc 0x1234 from the
`reg_fopen_test` process. See [QEMU Smoke Tests](../tooling/QEMU-Smoke.md).

## Related Pages

- [Memory Management](Memory-Management.md) — paging, frame allocator, kheap
- [Scheduler](Scheduler.md) — when the scheduler comes online
- [PCIe Enumeration](../drivers/PCIe-Enumeration.md) — first driver step
- [SMP AP Bringup Scope](../advanced/SMP-AP-Bringup-Scope.md)
