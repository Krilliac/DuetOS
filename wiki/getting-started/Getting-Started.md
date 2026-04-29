# Getting Started with DuetOS

> **Audience:** Anyone new to the codebase
>
> **Execution context:** Host (Linux dev machine + QEMU)
>
> **Maturity:** Active

## Overview

DuetOS is a from-scratch x86_64 operating system that runs Windows PE
executables natively. This page walks you from a fresh clone to a booted
kernel printing on a serial console.

## Prerequisites

DuetOS targets a Linux dev host. The compiler/build baseline is:

- **Clang 18+** (used as both the freestanding kernel compiler and the
  cross-compiler for the userland Windows PE toolchain)
- **CMake 3.25+**
- **lld** (preferred kernel linker; `clang -fuse-ld=lld`)
- **GNU assembler** via clang for `.S` files (Intel syntax)
- **NASM 2.16+** is reserved for hand-written boot ASM if/when it lands; not
  required today

For the ISO build and live boot (install on demand — see CLAUDE.md
"Live-test runtime tooling — install on demand"):

```bash
sudo apt-get update
sudo apt-get install -y \
    qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin \
    xorriso mtools ovmf
```

## Build

```bash
# Configure (pick one)
cmake --preset x86_64-debug       # Kernel + userland, debug
cmake --preset x86_64-release     # Kernel + userland, release

# Build kernel + all userland DLLs + ISO
cmake --build build/x86_64-debug --parallel $(nproc)
```

Output:
- `build/x86_64-debug/kernel/duetos-kernel.elf`
- `build/x86_64-debug/duetos.iso`

## Boot in QEMU

```bash
DUETOS_TIMEOUT=30 tools/qemu/run.sh build/x86_64-debug/duetos.iso
```

A healthy boot ends with something like:

```
[ring3] registered 0x26 DLL(s) pid=0x13
[reg-fopen-test] ProductName="DuetOS" (type=1, size=7)
[reg-fopen-test] /bin/hello.exe first two bytes: 0x4d 0x5a
[reg-fopen-test] all checks passed
Windows Kill 1.1.4 | Windows Kill Library 3.1.3
Not enough argument. Use -h for help.
[I] sys : exit rc val=0x1234
```

That last block is a real MSVC-built third-party Windows PE
(`windows-kill.exe`) printing to our serial console after going through
our PE loader, our 29 userland DLLs, our scheduler, and our syscalls.

## Run the Hosted Tests

```bash
cd build/x86_64-debug && ctest --output-on-failure && cd -
```

Hosted unit tests live under `tests/`. The on-target self-tests run
during the QEMU smoke boot.

## Reproduce the Screenshots

See [README.md > Screenshots](../../README.md#screenshots) for the exact
`screenshot-theme.sh` invocations used to capture each screenshot in
`docs/screenshots/`.

## Next Steps

- **New to the codebase**: read [Architecture Overview](Architecture-Overview.md)
  then [Project Pillars](Project-Pillars.md), then [History](History.md) for
  how the system arrived at its current shape.
- **Working on the kernel**: [Boot Path](../kernel/Boot.md), then
  [Memory Management](../kernel/Memory-Management.md) and
  [Subsystem Isolation](../kernel/Subsystem-Isolation.md).
- **Working on the Win32 surface**: [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md)
  and [PE Loader](../subsystems/PE-Loader.md).
- **Contributing**: [Coding Standards](../tooling/Coding-Standards.md) and
  [Contributing](../advanced/Contributing.md).

## Related Pages

- [Architecture Overview](Architecture-Overview.md)
- [Build System](../tooling/Build-System.md)
- [QEMU Smoke Tests](../tooling/QEMU-Smoke.md)
- [Troubleshooting](../advanced/Troubleshooting.md)
