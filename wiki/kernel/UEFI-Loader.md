# UEFI Loader

> **Audience:** Kernel hackers, anyone working on the boot path
>
> **Execution context:** Pre-kernel — runs in UEFI firmware, x86_64
> long mode, Microsoft x64 ABI, identity-mapped, Boot Services live.
>
> **Maturity:** Phase A (toolchain proof) shipped. Phase B (real
> kernel handoff) pending.

## Status

The UEFI loader lives in `boot/uefi/` and produces `BOOTX64.EFI`,
the PE32+ image a UEFI firmware loads from `EFI/BOOT/BOOTX64.EFI`
on a FAT32 ESP. It is **not yet** the canonical boot path —
today the kernel still boots via GRUB + Multiboot2 — but it is a
real binary that the firmware accepts and runs.

The loader has two phases (Phase B is itself sliced):

| Phase | Scope | Status |
| ----- | ----- | ------ |
| **A**     | Toolchain + ABI proof. `efi_main` prints a banner via `ConOut->OutputString` + COM1, calls `BootServices->Stall`, halts. No kernel handoff. | ✅ Shipped |
| **B.1**   | File-system probe + ELF header validation. Walks `image_handle → LoadedImage → DeviceHandle → SimpleFileSystem → root → \duetos-kernel.elf`, reads the 64-byte `Elf64_Ehdr`, validates magic / class / endianness / `EM_X86_64` / `e_phnum`, logs `e_entry`. Halts. No segment load yet. | ✅ Shipped |
| **B.2**   | Allocate pages, load each `PT_LOAD` segment, set up the kernel page tables (or hand the kernel its own setup), build a DuetOS-shaped boot info struct (memory map + framebuffer + cmdline). | ⏳ Pending |
| **B.3**   | `ExitBootServices`, jump to a new `entry_uefi` symbol in `boot.S` that takes the boot info struct in 64-bit long mode. | ⏳ Pending |

## Why two phases

A UEFI loader exercises a fundamentally different toolchain
than the rest of the kernel: Microsoft x64 calling convention
(RCX/RDX/R8/R9 — not the System V order kernel C++ uses),
PE/COFF output (not ELF), `lld-link` driver (not `ld.lld`),
`-fshort-wchar` so the wide-string literals in the loader
compile to UCS-2 (UEFI's CHAR16) instead of the Linux UTF-32
default.

Landing all of that plus a real kernel handoff in one slice
would conflate "did I get the toolchain right?" with "did I
get the kernel handoff right?" — two failure modes that look
identical at a serial console (silent boot). Phase A locks the
toolchain so Phase B's bring-up failures all live in one
place: the kernel-loading half.

## Build

```
cmake --preset x86_64-release
cmake --build build/x86_64-release --target duetos-uefi
ls -l build/x86_64-release/boot/uefi/BOOTX64.EFI
```

The CMake target lives in `boot/uefi/CMakeLists.txt`. It does
**not** use the kernel's freestanding-ELF toolchain file
(`cmake/toolchains/x86_64-kernel.cmake`); that pins
`--target=x86_64-unknown-none-elf`, which is wrong for UEFI.
Instead the directory drives `clang` and `lld-link` directly
via `add_custom_command` with `--target=x86_64-unknown-windows`.

The flags reflect the loader's freestanding stance — see
`boot/uefi/CMakeLists.txt` for the full list with per-flag
rationale comments.

## Smoke-testing in QEMU + OVMF

```
# One-time install (from CLAUDE.md's live-test runtime tooling)
sudo apt-get install -y qemu-system-x86 ovmf

# Stage the EFI binary on a virtual FAT32 ESP and boot it
mkdir -p /tmp/duetos-esp/EFI/BOOT
cp build/x86_64-release/boot/uefi/BOOTX64.EFI /tmp/duetos-esp/EFI/BOOT/
qemu-system-x86_64 \
  -bios /usr/share/OVMF/OVMF_CODE.fd \
  -drive format=raw,file=fat:rw:/tmp/duetos-esp \
  -nographic -serial mon:stdio -no-reboot
```

OVMF prints firmware banners, picks `EFI/BOOT/BOOTX64.EFI`
from the ESP, hands control to `efi_main`, and the loader's
banner ("`DuetOS UEFI loader v0 (Phase A: toolchain proof)`")
should appear on the OVMF console. After 2 s of `Stall` the
loader hits its `cli; hlt` loop — the firmware sees a hung
guest and the QEMU window stays at the banner.

## Anatomy

```
boot/uefi/
├── CMakeLists.txt   — clang+lld-link custom commands, MS x64 + PE32+
├── efi_types.h      — minimal hand-rolled UEFI type surface (200 LOC)
└── main.cpp         — efi_main entry, ConOut banner, halt (~80 LOC)
```

`efi_types.h` is hand-rolled rather than vendoring EDK2 / gnu-efi
headers — the freestanding project owns its include tree, and the
slice of UEFI surface needed by Phase A is small enough that
hand-rolling each protocol is cheaper than maintaining a
vendored header. Phase B will append: `EFI_LOADED_IMAGE_PROTOCOL`,
`EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`, `EFI_FILE_PROTOCOL`, `EFI_GRAPHICS_OUTPUT_PROTOCOL`,
the `GetMemoryMap` / `AllocatePages` / `ExitBootServices` boot service
prototypes.

## Phase B plan

The kernel's existing entry — `kernel/arch/x86_64/boot.S:_start` —
expects a 32-bit Multiboot2 handoff (`eax = 0x36d76289`,
`ebx = mbi struct phys addr`). UEFI hands control in 64-bit
long mode, so the loader has two viable strategies:

1. **Multiboot2 shim**: synthesize a Multiboot2 info structure
   from the UEFI memory map / GOP framebuffer / kernel cmdline,
   drop the CPU back to 32-bit protected mode, jump to `_start`.
   Pros: zero kernel-side change. Cons: the "drop back to PM"
   dance is fragile and discards the long-mode setup the firmware
   already paid for.
2. **Native UEFI handoff**: define a new kernel entry that
   accepts a DuetOS-shaped boot info structure in 64-bit long
   mode. Add an `entry_uefi` symbol to `boot.S` that branches
   in past the 32-bit setup. Pros: clean, fast, plays well with
   the firmware's identity map. Cons: requires a small kernel-side
   change (one new entry + boot-info structure shape).

Phase B will pick option 2 — the kernel change is small and the
result is the right architecture for a UEFI-first OS. See
`wiki/reference/Roadmap.md` for the slice scoping when it lands.

## Related

- [`Boot.md`](Boot.md) — full boot path including kernel-side bring-up.
- [`boot/grub/grub.cfg`](../../boot/grub/grub.cfg) — the GRUB
  configuration today's bootable ISO ships with.
- `wiki/reference/Design-Decisions.md` — entry covering the
  Phase A / Phase B split (when Phase B lands).
