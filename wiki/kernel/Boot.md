# Boot Path

> **Audience:** Kernel hackers
>
> **Execution context:** Kernel — boot CPU, IRQ-disabled until APIC online
>
> **Maturity:** Active

## Overview

The supported release boot path takes the system from either BIOS or UEFI
firmware through GRUB's Multiboot2 handoff to a fully-initialised kernel
running the scheduler with drivers probed. The order is intentionally strict
— partially-live subsystems must not be exposed before their dependencies are
alive.

## Boot path (x86_64)

```
BIOS firmware -> GRUB BIOS loader --+
                                      +-> GRUB `multiboot2`
UEFI firmware -> GRUB EFI loader  ----+-> kernel entry
   -> per-CPU bringup
   -> init process
```

The required supported release path is **GRUB + Multiboot2**. The hybrid ISO
boots both SeaBIOS and UEFI firmware (OVMF in QEMU; native firmware on real
hardware) from a single image. `boot/grub/grub.cfg` selects the kernel with
`multiboot2`, while `grub-mkrescue` supplies the BIOS and EFI GRUB boot images.
"UEFI boot" in the VM and release documentation describes the firmware profile;
it does not mean the kernel was loaded by DuetOS's direct UEFI loader.

The native `boot/uefi/BOOTX64.EFI` is an **experimental** path that exists
today through Phase B.1.
Phase A locked the toolchain (the firmware accepts the image and
`efi_main` prints a banner via `ConOut` + COM1); **Phase B.1** then
added the file-system probe and ELF header validation — it walks
`LoadedImage → SimpleFileSystem → \duetos-kernel.elf`, reads and
validates the `Elf64_Ehdr` (magic / class / `EM_X86_64` / `e_phnum`),
logs `e_entry`, and halts. It does **not** yet load the `PT_LOAD` segments,
call `ExitBootServices`, construct a versioned `BootInfo`, or hand off to the
kernel. Until all four steps and their required CI gate land, GRUB +
Multiboot2 remains the supported release contract. See
[`UEFI-Loader.md`](UEFI-Loader.md) for the full phase breakdown.

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
kernel update can't brick the box. The installed-disk
`/boot/grub/grub.cfg` is **generated from the slot state**
(`boot_slot::GrubCfgGenerate`): one `menuentry` per slot (each with
the matching `slot=a` / `slot=b` cmdline arg), `set default`
pointing at the slot the state machine wants booted next
(`pending` while an install is in flight, else `active`), and
`set fallback` listing the other slot plus a legacy
system-partition entry. The state itself lives in
`/boot/duetos-slot.cfg`, a small key=value file:

```
active=a
pending=b
tries_remaining=3
last_healthy=a
```

At install time `kernel/fs/installer.cpp` stages the embedded
kernel into the inactive slot (byte-for-byte read-back validation),
flips `pending` via `BeginInstall`, and persists both files through
the shared `installer::PersistSlotState` bridge. The running kernel
learns its slot from the `slot=` cmdline arg
(`kernel/core/boot_bringup.cpp`), calls
`boot_slot::MarkHealthyNow()` from the first heartbeat tick
(`kernel/diag/heartbeat.cpp`) — proving the boot path reached
steady state — and re-persists, which regenerates the cfg so
`set default` follows the promotion. If the kernel never reaches
that point, the cfg keeps its previous default/fallback shape and a
missing/corrupt slot image degrades through the fallback chain;
GRUB itself does not decrement `tries_remaining` (see
[Boot Slots](../filesystem/Boot-Slots.md) for the limits).

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
| `kernel/fs/boot_slot.{h,cpp}` | State machine, serialise / parse, `LoadVia` / `SaveVia` callback ABI, `GrubCfgGenerate`, self-test. |
| `kernel/diag/heartbeat.cpp`   | `PersistBootSlotState()` persists the post-`MarkHealthyNow` state (shared FAT32 bridge). |
| `kernel/shell/shell_bootslot.cpp` | `slotinfo` + `bootslot` shell commands. |
| `kernel/fs/installer.cpp`     | Stages the inactive-slot kernel, `FindBootSlotVolume` + `PersistSlotState` (state file + generated `grub.cfg`). |
| `boot/grub/grub.cfg`          | Dev-build (ISO) grub.cfg — appended static slot-a / slot-b entries for QEMU exercises. |

## Verification

The end-to-end "did it boot" gate is `tools/test/ctest-boot-smoke.sh`.
It always exercises an ISO generated by `grub-mkrescue` and a Multiboot2
`grub.cfg`. Release CI runs the driver in required mode, where a missing
prerequisite, missing serial output, or timeout is a failure rather than a
skip, and separately runs the release binary's `bringup` profile through the
same GRUB + Multiboot2 handoff. A clean comprehensive boot prints the
"ProductName=DuetOS" smoke line, runs through
the registry / fopen test, and exits with rc 0x1234 from the
`reg_fopen_test` process. See [QEMU Smoke Tests](../tooling/QEMU-Smoke.md).

## Related Pages

- [Memory Management](Memory-Management.md) — paging, frame allocator, kheap
- [Scheduler](Scheduler.md) — when the scheduler comes online
- [PCIe Enumeration](../drivers/PCIe-Enumeration.md) — first driver step
- [SMP AP Bringup Scope](../advanced/SMP-AP-Bringup-Scope.md)
