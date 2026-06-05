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
on real hardware) from a single image: `tools/build/iso/grub.cfg`
declares both `multiboot2` and `chainloader` paths, and `grub-mkrescue`
embeds the El-Torito boot record alongside the EFI System Partition.

The native `boot/uefi/BOOTX64.EFI` exists today through Phase B.1.
Phase A locked the toolchain (the firmware accepts the image and
`efi_main` prints a banner via `ConOut` + COM1); **Phase B.1** then
added the file-system probe and ELF header validation — it walks
`LoadedImage → SimpleFileSystem → \duetos-kernel.elf`, reads and
validates the `Elf64_Ehdr` (magic / class / `EM_X86_64` / `e_phnum`),
logs `e_entry`, and halts. It does **not** yet load the PT_LOAD
segments or hand off (Phase B.2 / B.3, pending), so the GRUB path
remains canonical. See [`UEFI-Loader.md`](UEFI-Loader.md) for the
full phase breakdown.

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
first user CR3 load (the in-flight stack pointer dereferences a
no-longer-mapped low VA).

## A/B kernel slots

DuetOS supports redundant A/B kernel images on the ESP so a botched
kernel update can't brick the box. The installer
(`kernel/fs/installer.cpp`) writes two `menuentry` blocks into
`/boot/grub/grub.cfg`, one per slot, and seeds `/boot/duetos-slot.cfg`
with a small key=value file:

```
active=a
pending=?
tries_remaining=3
last_healthy=a
```

GRUB reads `/boot/duetos-slot.cfg` at boot and selects the kernel
image (`/boot/duetos-kernel-${active}.elf`) accordingly. The
running kernel calls `boot_slot::MarkHealthyNow()` from the first
heartbeat tick (`kernel/diag/heartbeat.cpp`) — proving the boot path
reached steady state — and persists the updated state back to the
ESP via FAT32. If the kernel never reaches that point (panic during
boot, hung scheduler), the state file stays as-is, GRUB decrements
`tries_remaining` on the next attempt, and after `tries_remaining=0`
falls back to `last_healthy`.

### Inspecting + administering slots

The kernel shell exposes:

- `slotinfo` — print the in-RAM `CurrentState` (active, pending,
  last_healthy, tries_remaining).
- `bootslot install <a|b> <kernel-path>` — flip `pending` to
  the named slot (caller stages the ELF beforehand). Requires admin.
- `bootslot rollback` — force `Rollback`: restore `last_healthy`,
  clear `pending`. Requires admin.
- `bootslot force-fail` — test-only: write `tries_remaining=0`
  and reboot. Useful for verifying the bootloader's rollback path
  from inside a running system. Requires admin.

### Source map

| File | Purpose |
|---|---|
| `kernel/fs/boot_slot.{h,cpp}` | State machine, serialise / parse, `LoadVia` / `SaveVia` callback ABI, self-test. |
| `kernel/diag/heartbeat.cpp`   | `PersistBootSlotState()` writes the post-`MarkHealthyNow` state to FAT32. |
| `kernel/shell/shell_bootslot.cpp` | `slotinfo` + `bootslot` shell commands. |
| `kernel/fs/installer.cpp`     | Emits the A/B `grub.cfg` and seeds `/boot/duetos-slot.cfg` at install time. |
| `boot/grub/grub.cfg`          | Dev-build (ISO) grub.cfg — appended static slot-a / slot-b entries for QEMU exercises. |

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
