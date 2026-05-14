# External References

> **Audience:** Contributors who want primary-source documentation for
> a hardware register layout, file format, or low-level protocol.
>
> **Maturity:** Curated index, not a port target.

## How to use this page

This page is a **reading list, not a dependency list**. DuetOS does not
fork or vendor any of the third-party projects listed here. The
references are useful when:

- A new slice touches an area where the canonical doc is well-known
  (e.g. enabling SMEP/SMAP, walking an NVMe submission queue, parsing a
  PE import directory) and you want to cross-check the in-tree
  implementation against the spec.
- A bug surfaces and you want to confirm whether the in-tree code is
  diverging from the canonical recipe.
- You're starting a slice in a subsystem that DuetOS does not yet have
  (e.g. AMD GPU support, Intel iGPU mode-setting) and want a v0
  register-level walk-through.

If a wiki page on this list has direct in-tree counterparts, the
relevant DuetOS subsystem page (left column) is linked alongside.

## OSDev wiki

The [OSDev wiki](https://wiki.osdev.org/) is the lingua franca for
hobby x86_64 kernel work. It is generally accurate at the
register-level / boot-sequence level and weaker on modern firmware,
GPU drivers, and Wine-style ABI compat. License is permissive
(content reusable with attribution); we do not copy text into our own
wiki.

### Boot path / arch — `boot/`, `kernel/arch/x86_64/`

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [UEFI](https://wiki.osdev.org/UEFI) | [Boot Path](../kernel/Boot.md), [UEFI Loader](../kernel/UEFI-Loader.md) | Boot services / runtime services boundary, GOP handoff |
| [GOP](https://wiki.osdev.org/GOP) | [UEFI Loader](../kernel/UEFI-Loader.md) | Linear framebuffer info structure |
| [Setting Up Long Mode](https://wiki.osdev.org/Setting_Up_Long_Mode) | [Boot Path](../kernel/Boot.md) | PML4/PAE bring-up sequence |
| [x86-64](https://wiki.osdev.org/X86-64) | [Architecture Overview](../getting-started/Architecture-Overview.md) | Register file, calling conventions, MSR table |
| [Higher Half x86 Bare Bones](https://wiki.osdev.org/Higher_Half_x86_Bare_Bones) | [Boot Path](../kernel/Boot.md) | Higher-half mapping discipline |
| [Debugging UEFI applications with GDB](https://wiki.osdev.org/Debugging_UEFI_applications_with_GDB) | [Debugger](../tooling/Debugger.md) | Symbol-aware UEFI debugging recipe |

### Memory — `kernel/mm/`

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [Paging](https://wiki.osdev.org/Paging) | [Memory Management](../kernel/Memory-Management.md) | PML4/5, NX bit, TLB shootdown |
| [Supervisor Memory Protection](https://wiki.osdev.org/Supervisor_Memory_Protection) | [W^X / NX Enforcement](../security/WX-Enforcement.md) | SMEP/SMAP CPUID + CR4 enable sequence (DuetOS implements this in `kernel/mm/paging.cpp`) |
| [Page Frame Allocation](https://wiki.osdev.org/Page_Frame_Allocation) | [Memory Management](../kernel/Memory-Management.md) | Bitmap / buddy allocator design space |
| [Brendan's Memory Management Guide](https://wiki.osdev.org/Brendan%27s_Memory_Management_Guide) | [Memory Management](../kernel/Memory-Management.md) | Higher-level MM design rationale |

### Security — `kernel/security/`

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [Security](https://wiki.osdev.org/Security) | [W^X / NX Enforcement](../security/WX-Enforcement.md), [Sandboxing](../security/Sandboxing.md) | Enumerated mitigation surface |
| [Stack Smashing Protector](https://wiki.osdev.org/Stack_Smashing_Protector) | [W^X / NX Enforcement](../security/WX-Enforcement.md) | `__stack_chk_guard` / `__stack_chk_fail` ABI |
| [CPU Bugs](https://wiki.osdev.org/CPU_Bugs) | — | Spec-v1/v2/MDS/TAA mitigation rationale (DuetOS probes via `cpu_mitigations.cpp`) |
| [System Management Mode](https://wiki.osdev.org/System_Management_Mode) | — | SMM threat model — relevant to the Malware Hard-Stop plan |

### Storage — `kernel/drivers/storage/`

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [AHCI](https://wiki.osdev.org/AHCI) | [Storage (NVMe + AHCI)](../drivers/Storage.md) | HBA register layout, command list / FIS table |
| [NVMe](https://wiki.osdev.org/NVMe) | [Storage (NVMe + AHCI)](../drivers/Storage.md) | Admin / IO submission and completion queue layout |
| [SATA](https://wiki.osdev.org/SATA) | [Storage (NVMe + AHCI)](../drivers/Storage.md) | Wire protocol context for AHCI |

### USB — `kernel/drivers/usb/`

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [eXtensible Host Controller Interface](https://wiki.osdev.org/EXtensible_Host_Controller_Interface) | [USB (xHCI + Class)](../drivers/USB.md) | Capability / operational / runtime register layout, TRB ring discipline |
| [Enhanced Host Controller Interface](https://wiki.osdev.org/Enhanced_Host_Controller_Interface) | — | Only relevant if a legacy-USB-2 fallback is added |

### Filesystems — `kernel/fs/`

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [VFS](https://wiki.osdev.org/VFS) | [VFS](../filesystem/VFS.md) | Generic VFS shape — DuetOS's is more capability-aware |
| [FAT](https://wiki.osdev.org/FAT) | [FAT32](../filesystem/FAT32.md) | Boot record, FAT entry encoding, directory entry layout |
| [ExFAT](https://wiki.osdev.org/ExFAT) | — | Boot region + cluster heap layout |
| [Ext4](https://wiki.osdev.org/Ext4) | [ext4](../filesystem/ext4.md) | Superblock, extent tree, htree directory layout |
| [Ext2](https://wiki.osdev.org/Ext2) | [ext4](../filesystem/ext4.md) | Necessary background for ext4 |
| [NTFS](https://wiki.osdev.org/NTFS) | [NTFS](../filesystem/NTFS.md) | MFT, attribute records, $Bitmap / $LogFile semantics |

### Win32 / PE — `subsystems/win32/`, `kernel/loader/`

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [PE](https://wiki.osdev.org/PE) | [PE Loader](../subsystems/PE-Loader.md), [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md) | Section table, import / export directory walk, base relocation block format |
| [COFF](https://wiki.osdev.org/COFF) | [PE Loader](../subsystems/PE-Loader.md) | Underlying object format and relocation types |
| [MZ](https://wiki.osdev.org/MZ) | [PE Loader](../subsystems/PE-Loader.md) | DOS header / `e_lfanew` PE-offset quirks |

### Audio — `kernel/drivers/audio/`

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [Intel High Definition Audio](https://wiki.osdev.org/Intel_High_Definition_Audio) | [Audio](../drivers/Audio.md) | Codec verb / response paths, BDL stream layout |
| [AC97](https://wiki.osdev.org/AC97) | [Audio](../drivers/Audio.md) | Legacy QEMU fallback only |

### Graphics — `kernel/drivers/gpu/`

DuetOS's GPU support is the weakest area in tree; these pages are
**worth opening when an Intel iGPU slice is scheduled**. AMD and
NVIDIA require primary sources outside OSDev (AMD's open GPU docs
and NVIDIA's open kernel module sources, respectively).

| OSDev page | DuetOS wiki | What's useful |
|---|---|---|
| [Native Intel graphics](https://wiki.osdev.org/Native_Intel_graphics) | [Graphics Drivers](../drivers/Graphics-Drivers.md) | i915-style mode setting, plane / pipe / DDI register layout |
| [Intel HD Graphics](https://wiki.osdev.org/Intel_HD_Graphics) | [Graphics Drivers](../drivers/Graphics-Drivers.md) | Ironlake-class primary plane registers |
| [Graphics stack](https://wiki.osdev.org/Graphics_stack) | [Graphics Drivers](../drivers/Graphics-Drivers.md) | Architectural overview only |
| [Drawing In a Linear Framebuffer](https://wiki.osdev.org/Drawing_In_Protected_Mode) | [Compositor and Window Manager](../subsystems/Compositor.md) | v0 software path background |

### What OSDev wiki does **not** cover

DuetOS has goals that the OSDev wiki does not document. For these,
use the listed primary sources, not OSDev:

| Topic | Primary source |
|---|---|
| Win32 NT subsystem semantics | Wine source (`dlls/ntdll/`), ReactOS source (reference only — not a fork target), MSDN / Microsoft Learn |
| D3D11 / D3D12 → Vulkan translation | DXVK source, vkd3d-proton source |
| AMD GPU programming | AMD's open GPU register reference manuals |
| NVIDIA GPU programming | NVIDIA's open-gpu-kernel-modules source, nouveau reverse-engineered docs |
| Modern Wi-Fi (iwlwifi, MT76, etc.) | Linux kernel source (`drivers/net/wireless/`), vendor firmware blobs |
| ACPI AML interpretation depth | ACPICA source (Intel's reference AML interpreter), ACPI specification |
| KASLR design | Linux Documentation/x86/x86_64/mm.rst, academic literature |

## Other reference projects (not dependencies)

These projects are useful **as prior art**, not as code DuetOS pulls
in:

- **Wine** — canonical Win32 / NT user-mode reimplementation. Read
  for ABI shape; never link.
- **ReactOS** — Win32 + NT kernel reimplementation. Read for
  semantics; never fork.
- **smoltcp** — pure-Rust TCP stack. DuetOS has its own in-kernel
  TCP (`kernel/net/tcp.cpp`); a second stack would violate the
  "one source of truth per resource" rule.
- **EuraliOS** — hobby Rust kernel; useful as a journal-style
  reading list of "the order subsystems usually need to land".
  Architecture is microkernel-leaning and incompatible with DuetOS's
  hybrid model.
- **SerenityOS** (BSD-2-Clause) — full POSIX hobby OS in C++.
  Highest-value reading: LibGfx image codecs (PNG/JPEG/BMP/GIF/ICO
  parser shapes), the WindowServer/LibGUI compositor/toolkit split,
  pledge/unveil per-process capability scoping (parallel to our
  `kCap*` bits). Caveats: everything depends on AK (their STL
  replacement) which is threaded through every library, so
  single-component extraction is expensive. POSIX-evangelist
  userland — copy designs, not code.
- **ToaruOS** (NCSA / BSD-style) — **the closest architectural
  cousin** in the references list: hybrid kernel (Misaka), x86_64 +
  ARMv8, UEFI-first, SMP, ACPI. Plain C with no AK-equivalent
  stdlib threaded through it, which makes single-component reading
  much easier than Serenity. Highest-value reading: Yutani
  compositor architecture (alternate design to ours — Yutani is
  userland, ours is in-kernel; useful to see the trade-offs),
  terminal emulator's VT/ANSI escape parser + character-cell grid
  + glyph-cache shape, audio-server / mixer routing between the
  per-app `winmm`-equivalent and the kernel HDA driver. Caveats:
  POSIX-ish userland, PTY-shaped shell hosting, no PE/Win32 — all
  of which require re-imagining inside DuetOS's capability-gated
  model.
- **Linux kernel** (GPLv2) — **read-only reference for protocol
  shapes only**. The license is incompatible with MIT; do not copy
  code. Useful for driver register layouts, iwlwifi firmware
  protocols, Wi-Fi standards, ACPI/AML edge cases. Always
  re-derive from public specs where possible to keep the audit
  trail clean.

See [Toaru Port Plan](../advanced/Toaru-Port-Plan.md) for the
clean-room methodology and slice plan for the ongoing ToaruOS
prior-art port.

## Related Pages

- [Project Pillars](../getting-started/Project-Pillars.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Roadmap](Roadmap.md)
- [Win32 / DirectX Surface Status](Win32-Surface-Status.md)
