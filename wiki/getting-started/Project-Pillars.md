# Project Pillars

> **Audience:** Mixed
>
> **Execution context:** N/A (design doctrine)
>
> **Maturity:** Stable — these pillars define what "drift" looks like

## Overview

This page captures the non-negotiable design tenets every patch must
respect. They are restated from `CLAUDE.md` so contributors can find them
without reading the whole agent context file.

## The Two Defining Goals

1. **Run Windows PE executables natively.** A first-class Win32/NT
   subsystem — not a VM, not an emulator layer on top of another host
   OS. The PE loader, NT syscall surface, and Win32 user-mode DLLs are
   part of the base system, co-equal with the native DuetOS ABI.
2. **Run on typical commodity PC hardware.** x86_64 from day one
   (Intel/AMD), with first-class driver support for commodity GPUs
   (Intel iGPU, AMD Radeon, NVIDIA GeForce). ARM64 is a planned second
   tier.

## Pillars (do not drift from these)

- **Kernel**: Hybrid (microkernel-style IPC, monolithic-style in-kernel
  drivers for hot paths). Preemptive, SMP-aware, per-CPU runqueues.
- **Boot**: UEFI-first (x86_64), with a secondary legacy-BIOS path only
  if/when a target machine demands it. No MBR-only code paths in new
  work.
- **Memory**: 4-level paging (x86_64), NX, SMEP/SMAP, KASLR, per-process
  address spaces. Physical frame allocator + slab/buddy hybrid.
- **Scheduler**: MLFQ + per-CPU runqueues, affinity, work-stealing.
  Real-time class reserved, not the default.
- **Filesystem**: VFS abstraction. First backend: a native FS tuned for
  the project's needs. FAT32/exFAT/NTFS read-only tier for
  interoperability; ext4 read-only tier for Linux data partitions.
- **Executable formats**: Native ELF-like format **and** full PE/COFF.
  The PE subsystem is a peer, not a shim.
- **Win32 subsystem**: NT syscall layer -> user-mode `ntdll`,
  `kernel32`, `user32`, `gdi32`, `d3d*`, `dxgi`, `winmm`, `xaudio2`
  reimplementations. Not a Wine fork — studied as prior art, not taken
  as a dependency.
- **Graphics**: Direct GPU drivers for Intel/AMD/NVIDIA. Kernel-mode
  DRM-style layer + user-mode API (Vulkan-first, D3D11/D3D12 translation
  on top for the Win32 subsystem).
- **Drivers**: PCIe enumeration, NVMe, AHCI/SATA, xHCI/USB, Intel
  HDA/AC'97, e1000/iwlwifi/rtl8169 NICs. Audio and networking user-mode
  stacks.
- **Security**: W^X enforced, ASLR, stack canaries, control-flow
  integrity. No setuid; capability-based IPC.

## What DuetOS is *not*

- Not a Linux distribution. No Linux kernel, no GNU userland as a base.
- Not a Wine project. Wine's userland reimplementation is useful prior
  art; we are writing ours.
- Not a research microkernel (L4, seL4). Pragmatism over academic
  purity.
- Not a rewrite of ReactOS. ReactOS is useful as a reference for Win32
  semantics; we are not forking it.
- Not aiming at binary compatibility with specific Windows DLL versions
  — we aim at *executable* compatibility (run the `.exe`).

## Project Pillars in One Line Each

- PE executables run as a **native ABI**, not through an emulator shell.
- Kernel is a **hybrid** (microkernel IPC shape, monolithic hot paths).
- **Direct GPU drivers** for Intel / AMD / NVIDIA; Vulkan is the primary
  user-mode API.
- **Capability-based IPC**; no setuid.
- **W^X, ASLR, SMEP/SMAP, KASLR, CFI** enforced from day one.

## Related Pages

- [Architecture Overview](Architecture-Overview.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Sandboxing](../security/Sandboxing.md)
- [Anti-Bloat Guidelines](../tooling/Anti-Bloat-Guidelines.md)
