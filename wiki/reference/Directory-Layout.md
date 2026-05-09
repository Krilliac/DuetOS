# Directory Layout

> **Audience:** All contributors
>
> **Execution context:** N/A
>
> **Maturity:** Active — directories appear as work does

## Overview

The directory tree below is **aspirational where marked, live where
not**. Do not create a directory until the first file legitimately
belongs in it.

## Top Level

```
boot/                 UEFI loader (x86_64), legacy BIOS stub (later), boot protocol
kernel/               (see breakdown below)
drivers/              (planned out-of-tree driver area; today drivers live in kernel/drivers/)
subsystems/           (planned out-of-tree subsystem area; today they live in kernel/subsystems/)
userland/
  libc/               our libc (freestanding + hosted) — planned
  init/               PID 1, service supervisor — planned
  shell/              command shell — planned
  tools/              native userland utilities — planned
  apps/               sample/test apps (native + PE)
  libs/               29 userland Win32 DLLs shipped into every Win32-imports PE
third_party/          vendored dependencies (compiler-rt fragments, zlib, etc.)
tools/
  build/              build helpers, image builders, initrd packer
  qemu/               QEMU launch scripts, debug helpers
  debug/              symbol resolution, panic decode, disasm scripts
  test/               integration test harnesses
  cleanroom/          cleanroom trace tooling
  security/           pentest helpers
  win32-compat/       Win32 compatibility tooling
  linux-compat/       Linux ABI tooling
tests/                unit tests (hosted) + kernel self-tests (on-target)
docs/                 boot-log examples, ABI matrix, theme prototypes,
                      sync-wiki.sh, screenshots
wiki/                 canonical documentation home (you are here)
.github/              CI workflows, repo templates
cmake/                CMake helpers
```

## Kernel Internals (`kernel/`)

```
acpi/                 ACPI tables (RSDP, MADT, FADT) + AML parser
apps/                 in-kernel native apps (calculator, clock, gfxdemo, files, ...)
arch/x86_64/          bootstrap, paging, GDT/IDT, trap frames, APIC, context switch
arch/aarch64/         (later) ARM64 equivalents
core/                 entry (main.cpp), panic, early init
cpu/                  per-CPU data structures
debug/                breakpoints, probes, syscall scan, exception tables
diag/                 kdbg, crprobe, runtime checker, hexdump, recovery, crash dump
drivers/              in-kernel device drivers (see Driver Overview)
fs/                   VFS, path resolution, FAT32, exFAT, ext4, NTFS, ramfs, GPT
ipc/                  (planned) capability-based IPC, ports, shared memory
loader/               ELF + PE loaders, DLL loader, firmware loader
log/                  klog (kernel log ring + sinks)
mm/                   physical frame allocator, paging, slab/heap, kstack, address spaces
net/                  protocol stacks (TCP/IP, UDP, ICMP, ARP, Wi-Fi)
power/                reboot / shutdown
proc/                 process model (process.cpp, ring3 smoke)
sched/                scheduler, runqueues, threads, context switch
security/             auth/login, stack canary, fault domains, attack sim, pentest, image guard
shell/                kernel shell (split across shell_*.cpp TUs)
subsystems/           Linux ABI, Win32 ABI, graphics, ABI translation
sync/                 spinlocks, mutexes, RW locks, RCU-lite
syscall/              native syscall dispatch + cap_table.def
test/                 in-kernel tests (run during boot smoke)
time/                 (planned) HPET/TSC/APIC timer, clocksource, scheduler tick
util/                 Result<T,E>, string helpers, types, symbols, random
```

## Drivers (`kernel/drivers/`)

```
audio/                Intel HDA
gpu/                  virtio-gpu, Intel/AMD/NVIDIA discovery
input/                PS/2 keyboard/mouse
net/                  Intel e1000, wireless shells (iwlwifi/rtl/bcm)
pci/                  PCIe enumeration
power/                shutdown / reboot helpers
storage/              NVMe, AHCI/SATA
usb/                  xHCI host + class (HID, MSC, CDC-ECM, RNDIS)
video/                framebuffer, compositor primitives, theme tokens, widget
```

## Subsystems (`kernel/subsystems/`)

```
graphics/             compositor + Vulkan ICD (skeleton)
linux/                Linux-ABI syscall bridge
translation/          NT -> Linux syscall translator (and friends)
win32/                flat-stubs page (legacy fallback), Win32 syscall handlers
```

## Userland DLLs (`userland/libs/`)

29 DLLs as of writing — see [Win32 DLLs](../subsystems/Win32-DLLs.md)
for the full inventory.

## Build Output Layout

```
build/<preset>/
  kernel/duetos-kernel.elf       kernel ELF
  userland/libs/<dll>/<dll>.dll  per-DLL build artifact
  kernel/smoke-pes/<app>/<app>.exe  generated per-app PE
  duetos.iso                     hybrid ISO bootable on SeaBIOS + UEFI
```

## Related Pages

- [Architecture Overview](../getting-started/Architecture-Overview.md)
- [Driver Overview](../drivers/Driver-Overview.md)
- [Win32 DLLs](../subsystems/Win32-DLLs.md)
- [Build System](../tooling/Build-System.md)
