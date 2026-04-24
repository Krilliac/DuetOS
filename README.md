# CustomOS

A general-purpose operating system, written from scratch, that runs
Windows PE executables natively — not via a VM, not via Wine, not as an
emulator bolted onto another host OS. The PE loader, the NT syscall
surface, the full set of user-mode DLLs (`kernel32`, `ntdll`, `user32`,
`gdi32`, `ucrtbase`, `msvcp140`, …) all live in this repo, co-equal with
the native ABI.

Currently runs x86_64. UEFI boot on commodity hardware. 33 slices of
development and one live-verified fact:

```
Windows Kill 1.1.4 | Windows Kill Library 3.1.3
Not enough argument. Use -h for help.
```

That's a real MSVC-built third-party Windows PE printing to our serial
console after going through our PE loader, our 29 userland DLLs, our
scheduler, and our syscalls. Bits as shipped, running on CustomOS.

---

## What's here

- **Kernel** (`kernel/`) — Multiboot2 boot, 4-level paging, per-process
  address spaces, SMP-aware round-robin scheduler, W^X + SMEP/SMAP +
  ASLR + stack canaries + retpoline, capability-based IPC,
  `int 0x80` native syscall ABI (~57 numbered calls). PCIe, NVMe,
  AHCI, xHCI/USB, PS/2, HDA, e1000. HPET-calibrated LAPIC timer.
  Kernel-mode breakpoint subsystem with hardware DR gates. Live crash
  dump with inline symbol resolution.
- **PE loader** (`kernel/core/pe_loader.cpp`, `pe_exports.cpp`,
  `dll_loader.cpp`) — validates DOS + NT + PE32+ headers, maps
  sections with characteristic-driven flags, applies DIR64 base
  relocations, walks the Export Address Table, resolves imports
  against preloaded DLLs with forwarder chasing, falls through to a
  legacy stubs path for anything not yet ported.
- **Win32 translator DLLs** (`userland/libs/`) — 29 userland DLLs
  totalling ~760 exports. `kernel32` (155), `ntdll` (114), `ucrtbase`
  (72), `user32` (73), `gdi32` (44), `kernelbase` (44 forwarders),
  plus `msvcrt`, `msvcp140`, `vcruntime140`, `dbghelp`, `advapi32`,
  `shell32`, `shlwapi`, `ole32`, `oleaut32`, `winmm`, `bcrypt`,
  `psapi`, `crypt32`, `comctl32`, `comdlg32`, `version`, `setupapi`,
  `iphlpapi`, `userenv`, `wtsapi32`, `dwmapi`, `uxtheme`, `secur32`,
  `ws2_32`, `wininet`, `winhttp`, `d3d9`/`11`/`12`, `dxgi`.
- **Real implementations** — registry, `fopen`/`fread`/`fseek`/`fgets`,
  `printf` formatting, `getenv`, heap (`malloc`/`HeapAlloc`), atomics,
  critical sections, SRW locks, InitOnce, time, threads, mutexes,
  events, semaphores, TLS slots.
- **Inspect tooling** (`kernel/debug/inspect.h`) — shell-driven
  disassembly and reverse-engineering surface that predates the PE
  loader. First-byte opcode histograms, syscall-site recovery, spawn-
  time image scanning.

---

## The layering, in one diagram

```
Windows PE applications
        ↓ imports
Win32 translator DLLs  (userland/libs/, 29 DLLs)
        ↓ int 0x80
Native CustomOS kernel
        ↓
Kernel-mode drivers (PCIe, NVMe, AHCI, USB, NIC, GPU, audio, input)
```

The Win32 DLLs are **translators**, not parallel subsystems. There is
one TCP stack in the kernel, one compositor, one VFS, one registry —
each reachable from two entry ABIs (native and Win32). See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full picture,
including how `ws2_32!send` reaches the e1000 transmit ring.

---

## Build + run

```bash
# Configure (x86_64-debug or x86_64-release)
cmake --preset x86_64-debug

# Build kernel + all userland DLLs + ISO
cmake --build build/x86_64-debug --parallel $(nproc)

# Boot in QEMU — watches the serial log on stdout
CUSTOMOS_TIMEOUT=30 tools/qemu/run.sh build/x86_64-debug/customos.iso
```

Tools required for the ISO path:
`qemu-system-x86`, `ovmf`, `grub-common`, `grub-pc-bin`,
`grub-efi-amd64-bin`, `xorriso`, `mtools`. Compiler baseline:
Clang 18+ (used as both the freestanding kernel compiler and the
host cross-compiler for the userland Windows PE toolchain).

A healthy boot ends with something like:

```
[ring3] registered 0x26 DLL(s) pid=0x13
[reg-fopen-test] ProductName="CustomOS" (type=1, size=9)
[reg-fopen-test] /bin/hello.exe first two bytes: 0x4d 0x5a
[reg-fopen-test] all checks passed
Windows Kill 1.1.4 | Windows Kill Library 3.1.3
Not enough argument. Use -h for help.
[I] sys : exit rc val=0x1234
```

---

## What works today

Freestanding Win32 PEs (no CRT, direct `int 0x80`) — since early
development. Console programs with CRT, threads, mutexes, events,
atomics, `printf`, file I/O, registry queries — current. Real
third-party Windows binary (`windows-kill.exe`) — running end-to-end
through the DLL surface.

## What doesn't work (yet)

Windowed programs — `user32!CreateWindowExW` returns NULL; there is
no window manager and no GDI renderer. Networking — `ws2_32!socket`
returns `INVALID_SOCKET`; the kernel net stack is a skeleton.
DirectX — returns `E_NOTIMPL`; no Vulkan ICD yet. COM — returns
`CLASS_E_CLASSNOTAVAILABLE`. Each of those is its own multi-slice
implementation track; the DLL surface is the scaffolding that makes
them possible.

See [`docs/HISTORY.md`](docs/HISTORY.md) for how the project got to
this point and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
current layering model. [`CLAUDE.md`](CLAUDE.md) is the authoritative
development guide — coding standards, anti-bloat guidelines, and the
full architectural statement.

---

## Non-goals

- Not a Linux distribution. No Linux kernel, no GNU userland base.
- Not a Wine fork. Wine is useful prior art; this repo does not vendor
  it or link against it.
- Not a ReactOS rewrite.
- Not a research microkernel. Pragmatism over academic purity.
- Not aiming at binary compatibility with specific Windows DLL
  versions — we aim at *executable* compatibility (run the `.exe`).

---

## Layout

```
boot/          UEFI loader + boot protocol
kernel/
  arch/x86_64/ bootstrap, paging, GDT/IDT, traps, APIC, context switch
  core/        entry, pe_loader, dll_loader, scheduler helpers, syscalls
  debug/       breakpoints, inspect, syscall-site scanner
  drivers/     pci, storage/, usb/, net/, gpu/, audio/, input/, video/
  fs/          VFS, ramfs, FAT32, NTFS (read-only), GPT
  mm/          frame allocator, paging, kheap, kstack, address_space
  net/         protocol stacks (skeleton)
  sched/       scheduler + blocking primitives
  security/    guards, pentest probes
  subsystems/
    graphics/  compositor + Vulkan ICD (skeleton)
    linux/     Linux-ABI syscall bridge
    translation/ NT → Linux syscall translator
    win32/     flat-stubs page (legacy fallback), syscall handlers
  sync/        spinlock, waitqueue primitives
userland/
  apps/        test fixtures (hello_pe, hello_winapi, windows-kill,
               thread_stress, syscall_stress, customdll_test,
               reg_fopen_test, …)
  libs/        29 userland DLLs shipped into every Win32-imports PE
tools/         build helpers, QEMU launcher, embed-blob, gen-symbols
docs/          architecture, history, ABI matrix, design notes
tests/         hosted + on-target tests
.claude/       working notes kept from development
```

---

## License

See [`LICENSE`](LICENSE).
