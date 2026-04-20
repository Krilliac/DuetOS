# ISO Build & End-to-End Boot Verification

**Last updated:** 2026-04-20
**Type:** Pattern
**Status:** Active

## Description

How the bootable CustomOS ISO is produced and the canonical way to verify a full boot in QEMU. First end-to-end-verified boot landed in this session: the kernel reaches long mode and writes to COM1.

## Context

Applies to `kernel/CMakeLists.txt` (ISO target), `boot/grub/grub.cfg`, `tools/qemu/run.sh`. This is third-party scaffolding — GRUB is used because our own UEFI boot loader doesn't exist yet. When `boot/uefi/` lands, the ISO helper switches to shipping our loader instead of GRUB.

## Approach

### Build the ISO

```bash
cmake --preset x86_64-debug
cmake --build build/x86_64-debug --parallel $(nproc)
```

The `customos-iso` target is declared `ALL` in `kernel/CMakeLists.txt`, so a plain build produces `build/x86_64-debug/customos.iso` alongside the kernel ELF.

If `grub-mkrescue` and `xorriso` are not installed, the target is silently skipped with a status message pointing at the apt packages required. The kernel ELF still builds.

### Required host packages (Ubuntu)

```bash
sudo apt-get install -y grub-common grub-pc-bin xorriso mtools qemu-system-x86
```

- `grub-common` — `grub-mkrescue` itself.
- `grub-pc-bin` — the i386-pc boot image that `grub-mkrescue` embeds.
- `xorriso` — the ISO-9660 writer.
- `mtools` — FAT utilities grub-mkrescue uses when producing hybrid images.
- `qemu-system-x86` — the emulator.

### Boot in QEMU

```bash
tools/qemu/run.sh                      # interactive, serial on stdio
CUSTOMOS_TIMEOUT=10 tools/qemu/run.sh  # self-terminate after 10s (useful in CI)
```

The script:
1. Uses `-cdrom build/<preset>/customos.iso -boot d` when the ISO exists.
2. Falls back to `-kernel` **with a warning** if only the ELF exists (that path won't boot today — QEMU's `-kernel` speaks Multiboot 1, not 2).
3. Passes `-display none -serial stdio -no-reboot -no-shutdown -d int,cpu_reset -D qemu.log`.

### Expected output

On a working build the serial output is exactly:

```
[boot] CustomOS kernel reached long mode.
[boot] Multiboot2 handoff verified.
[boot] Halting CPU.
```

`qemu.log` should contain **one** `CPU Reset` record (the initial power-on) and nothing after it. Any further `CPU Reset` or interrupt traces mean the kernel faulted — the IDT is intentionally absent in v0, so the next reset is almost always a triple fault.

### Pre-flight sanity checks

```bash
# Confirm the kernel header is still valid Multiboot2.
grub-file --is-x86-multiboot2 build/x86_64-debug/kernel/customos-kernel.elf

# Peek at the ISO layout.
xorriso -indev build/x86_64-debug/customos.iso -find / 2>&1 | grep -v "^xorriso"
# Expected top-level:
#   /boot/customos-kernel.elf
#   /boot/grub/grub.cfg
#   /boot/grub/i386-pc/*.mod
```

### Debugging a boot failure

1. Re-run with display on and keep QEMU alive:
   ```bash
   CUSTOMOS_DISPLAY=gtk tools/qemu/run.sh
   ```
2. Start QEMU paused with a gdb stub:
   ```bash
   tools/qemu/run.sh -s -S
   # in another terminal:
   gdb build/x86_64-debug/kernel/customos-kernel.elf \
       -ex 'target remote :1234' \
       -ex 'break _start' -ex 'continue'
   ```
3. Inspect `qemu.log` — the `int` trace shows every interrupt and reset cause, which is how triple faults are typically diagnosed when no IDT is installed.

## Notes

- The ISO is **hybrid** — the MBR includes `boot_hybrid.img`, so it also boots on real USB sticks written with `dd`. Do not remove `--compress=xz` casually; it's what keeps the image near 2.4 MiB rather than ~10 MiB.
- GRUB's `multiboot2` command (not `multiboot`) is mandatory — `multiboot` only handles the v1 protocol and will complain about our header.
- Fallback to `-kernel` in `run.sh` exists so a developer without xorriso installed still gets a non-cryptic error rather than a silent crash. It is **not** a supported boot path.
- **See also:** [kernel-bringup-v0.md](kernel-bringup-v0.md) for the kernel-side boot code this ISO hands off to; [hardware-target-matrix.md](hardware-target-matrix.md) for why we don't care about legacy BIOS long-term.
