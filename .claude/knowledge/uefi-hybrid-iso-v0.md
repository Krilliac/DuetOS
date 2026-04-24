# UEFI hybrid-ISO boot path — v0

**Last updated:** 2026-04-23
**Type:** Observation
**Status:** Active — same ISO boots SeaBIOS (legacy) + OVMF (UEFI)

## What landed

`grub-mkrescue` was always producing a hybrid ISO; it just needed
`grub-efi-amd64-bin` installed to actually emit the UEFI El Torito
boot record alongside the legacy one.

After `apt install grub-efi-amd64-bin`, the same ISO carries:

```
-c '/boot.catalog'
-b '/boot/grub/i386-pc/eltorito.img'    # legacy BIOS path
-eltorito-alt-boot
-e '/efi.img'                            # UEFI path
-no-emul-boot
```

ISO size doubled (~2 MiB → ~4 MiB) since the EFI image embeds an
amd64 GRUB build.

## Boot helper

`tools/qemu/run.sh` grew a `DUETOS_UEFI=1` mode that swaps in an
OVMF firmware pflash pair:

```
DUETOS_UEFI=1 tools/qemu/run.sh
```

The script makes a per-run writable copy of `OVMF_VARS_4M.fd` so a
previous boot's NVRAM (BootOrder, Boot####) can't sabotage the next
invocation. Override paths via `DUETOS_OVMF_CODE` /
`DUETOS_OVMF_VARS` if the OVMF package layout differs.

## Why this matters for real hardware

Most laptops and motherboards from ~2020 onward ship UEFI-only with
CSM disabled. The legacy `i386-pc` boot record won't be considered
at all on those machines — the firmware looks for an
`/EFI/BOOT/BOOTX64.EFI` (or an El Torito EFI image on optical
media). With the hybrid ISO we now produce, the same media works on:

- QEMU SeaBIOS (default `-bios`)
- QEMU OVMF
- Old PCs with legacy BIOS / CSM
- Modern UEFI-only PCs

## Cross-firmware portability win

Boot logs from the same ISO under both firmwares:

```
SeaBIOS:  [pci] ECAM online base=0xb0000000 buses=0x0..0xf
OVMF:     [pci] ECAM online base=0xe0000000 buses=0x0..0xf
```

OVMF places the MCFG aperture at a different physical address than
SeaBIOS (E000_0000 vs B000_0000). The kernel's MCFG parser
(`kernel/acpi/acpi.cpp::ParseMcfg`) handles the address transparently
because it reads the table; it doesn't hardcode the value. Same
post-handoff: hypervisor detected, 8 PCI devices found, hid + msc
self-tests PASS, no panics, heartbeat runs cleanly to timeout.

## What's NOT done

- **Native UEFI loader.** GRUB-x86_64-efi is a third-party
  dependency. A real `boot/uefi/BOOTX64.EFI` (PE32+ that calls
  EFI services directly, then jumps into the kernel) is still on
  the planned-not-started list. The hybrid path with GRUB is good
  enough until we want EFI Stub semantics, runtime services, or
  Secure Boot signing.
- **Secure Boot.** Unsigned kernel won't load on default-SB
  systems. Requires shim + signing key infrastructure.
- **GOP framebuffer hand-off.** GRUB still uses VBE on the legacy
  side; under UEFI it picks GOP automatically. We consume what
  Multiboot2 gives us either way.

## References

- `tools/qemu/run.sh` — boot helper.
- `kernel/CMakeLists.txt` — `duetos-iso` target, picks up
  `grub-efi-amd64-bin` automatically when present.
- `boot/grub/grub.cfg` — menuentries (unchanged across firmwares).
- `kernel/acpi/acpi.cpp::ParseMcfg` — MCFG parser that handled the
  base-address swap without code changes.
- OVMF: package `ovmf` on Debian/Ubuntu;
  `/usr/share/OVMF/OVMF_CODE_4M.fd` + `OVMF_VARS_4M.fd`.
