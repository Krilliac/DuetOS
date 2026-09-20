# Removable-Media Boot Image

> **Status:** regular-file image construction and QEMU/OVMF boot verified.
> Physical-device writing is intentionally not implemented by the repo tool.

DuetOS can produce a UEFI removable-media image without mounting, enumerating,
or modifying a host disk.  The image uses the supported GRUB + Multiboot2
kernel handoff; it does not claim that the experimental direct UEFI loader can
boot the kernel.

## Safety boundary

`tools/image/build-removable-media.sh` accepts an output **regular file**. It
rejects Linux device paths, Windows `PhysicalDrive` paths, block-device nodes,
directories, symlinks, and every other existing non-regular target even when
`--force` is present. Construction happens in a sibling temporary directory
and the completed image is renamed into place, so a failed host tool does not
leave a partial artifact at the requested path.

The tool does not:

- discover or choose disks;
- call `dd`, `diskpart`, `Clear-Disk`, `Format-Volume`, or mount a filesystem;
- require elevation;
- transfer the image to USB media;
- resize an installed operating system.

Writing an image to physical media remains a separate operator action that
must identify the exact removable target independently.

## Prerequisites

On Ubuntu/Debian the builder needs GRUB's x86_64 EFI modules, parted, and
mtools.  QEMU verification also needs QEMU and OVMF:

```bash
sudo apt-get install -y grub-efi-amd64-bin parted mtools qemu-system-x86 ovmf
```

## Build an image

Build the kernel first, then create a 128 MiB image:

```bash
cmake --build build/x86_64-debug --parallel 8
tools/image/build-removable-media.sh \
  --kernel build/x86_64-debug/kernel/duetos-kernel.elf \
  --output build/x86_64-debug/duetos-removable.img
```

The image contains one GPT FAT32 EFI System Partition with:

```text
/EFI/BOOT/BOOTX64.EFI
/boot/duetos-kernel.elf
```

`BOOTX64.EFI` is a GRUB standalone image with an embedded configuration.  It
searches for `/boot/duetos-kernel.elf` and starts it with the Multiboot2
`boot=desktop autologin=1 smoke=bringup` command line.

An existing regular output is refused unless `--force` is supplied.  `--force`
never relaxes the physical-device rejection.

## Verify without physical media

The contract test checks target refusal, paths containing spaces, GPT/ESP
layout, the EFI payload, and a byte-identical kernel round trip:

```bash
DUETOS_KERNEL_ELF=build/x86_64-debug/kernel/duetos-kernel.elf \
  bash tools/test/removable-media-image-contract.sh
```

The boot smoke constructs a fresh temporary image and boots it as a virtual
disk under OVMF:

```bash
DUETOS_PRESET=x86_64-debug \
  bash tools/test/removable-media-boot-smoke.sh
```

It requires `metrics bringup-complete`, rejects panic/triple-fault markers,
and runs the standard boot-log analyzer.  A successful QEMU exit without the
completion marker is still a failure.

## Secure Boot limitation

The generated standalone GRUB EFI application is not signed by a key present
in commodity firmware databases.  A machine with Secure Boot enabled will
normally refuse it.  This tool does not disable Secure Boot, alter firmware
variables, enroll keys, or claim a signed boot chain.  A production path needs
a reviewed shim/signing design; until then, real-hardware testing requires an
operator-controlled firmware configuration that permits the unsigned loader.

## Relationship to the installer

This artifact closes a host-tooling gap: DuetOS can now produce and test a
removable UEFI image without touching a disk.  It does not make
`kernel/fs/installer.cpp` self-booting.  The in-OS installer still needs to
install supported GRUB boot artifacts (or the direct UEFI loader must complete
its ELF segment load, `ExitBootServices`, versioned `BootInfo`, and kernel
handoff work).

## Related pages

- [Daily-Driver Readiness](../reference/Daily-Driver-Readiness.md)
- [UEFI Loader](../kernel/UEFI-Loader.md)
- [QEMU Smoke Tests](QEMU-Smoke.md)
- [Boot Path](../kernel/Boot.md)
