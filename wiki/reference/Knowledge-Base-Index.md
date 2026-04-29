# Knowledge Base Index

> **Audience:** Contributors looking for deeper context
>
> **Execution context:** N/A
>
> **Maturity:** Companion to `.claude/index.md`

## Overview

The wiki you are reading is the **public-facing**, structured digest
of DuetOS. The full development working notes — issue postmortems,
optimisation observations, plan files, deferred-task batches —
live in `.claude/knowledge/` and are indexed by `.claude/index.md`.

This page maps wiki sections to the deeper notes that back them.

## Why Two Layers?

- **Wiki**: structured, audience-tagged, versioned with the code,
  human-onboarding-friendly.
- **`.claude/knowledge/`**: terse, slice-numbered, AI-session memory.
  Captures "we tried X, it broke Y, the canary is Z." Useful for
  resuming work across sessions and for understanding *why* a wiki
  page reads the way it does.

The wiki is the source of truth for **what is**. The knowledge base
is the source of truth for **why and how**. Both are maintained in
the same repo.

## Mapping

### Kernel core

| Wiki page | Knowledge entries |
|-----------|-------------------|
| [Boot Path](../kernel/Boot.md) | `kernel-bringup-v0.md`, `boot-verification-v0.md`, `iso-build-and-boot.md`, `uefi-hybrid-iso-v0.md` |
| [Memory Management](../kernel/Memory-Management.md) | `frame-allocator-v0.md`, `kernel-heap-v0.md`, `paging-v0.md`, `higher-half-kernel-v0.md`, `kernel-stack-guard-v0.md`, `boot-stack-high-vma-fix.md`, `per-process-address-space-v0.md`, `kmalloc-zero-init-pattern.md` |
| [Scheduler](../kernel/Scheduler.md) | `scheduler-v0.md`, `sched-blocking-primitives-v0.md`, `lapic-timer-v0.md`, `acpi-madt-v0.md`, `ioapic-v0.md`, `gdt-idt-v0.md` |
| [Syscalls](../kernel/Syscalls.md) | `result-type-v0.md` |
| [Process Model](../kernel/Process-Model.md) | `process-capabilities-v0.md` |
| [Subsystem Isolation](../kernel/Subsystem-Isolation.md) | `subsystem-isolation-decision-v0.md` (audit checklist) |
| [Logging and Tracing](../kernel/Logging-And-Tracing.md) | `klog-overhaul.md`, `crash-dump-v0.md`, `cleanroom-trace-boot-survey-v0.md` |

### Drivers

| Wiki page | Knowledge entries |
|-----------|-------------------|
| [Driver Overview](../drivers/Driver-Overview.md) | `driver-shells-v0.md`, `hardware-target-matrix.md` |
| [PCIe Enumeration](../drivers/PCIe-Enumeration.md) | `pci-enum-v0.md` |
| [Storage (NVMe + AHCI)](../drivers/Storage.md) | `nvme-driver-v0.md`, `gpt-parser-v0.md`, `storage-and-filesystem-roadmap.md` |
| [USB (xHCI + Class)](../drivers/USB.md) | `xhci-enumeration-v0.md`, `xhci-hid-keyboard-v0.md`, `usb-cdc-ecm-driver-v0.md`, `usb-rndis-driver-v0.md` |
| [Networking Drivers](../drivers/Networking-Drivers.md) | `e1000-driver-v0.md`, `wireless-drivers-v0.md`, `network-shell-commands-v0.md`, `network-flyout-panel-v0.md` |
| [Graphics Drivers](../drivers/Graphics-Drivers.md) | `gpu-discovery-v0.md`, `render-drivers-v6.md`, `desktop-chrome-polish-v0.md`, `gfxdemo-multimode-v0.md`, `rasterizer-compositor-shell-plan.md` |
| [Input](../drivers/Input.md) | `ps2-keyboard-v0.md`, `xhci-hid-keyboard-v0.md` |

### Subsystems

| Wiki page | Knowledge entries |
|-----------|-------------------|
| [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md) | `subsystems-status.md`, `win32-thunks-compat-note.md` |
| [PE Loader](../subsystems/PE-Loader.md) | `subsystems-status.md` |
| [Win32 DLLs](../subsystems/Win32-DLLs.md) | `subsystems-status.md` |
| [Compositor](../subsystems/Compositor.md) | `desktop-chrome-polish-v0.md`, `native-apps-v0.md`, `network-flyout-panel-v0.md` |
| [DirectX v0 Path](../subsystems/DirectX.md) | `directx-v0.md` (per README) |

### Filesystem

| Wiki page | Knowledge entries |
|-----------|-------------------|
| [VFS](../filesystem/VFS.md) | `vfs-namespace-v0.md` |
| [GPT](../filesystem/GPT.md) | `gpt-parser-v0.md` |
| [FAT32](../filesystem/FAT32.md), [ext4](../filesystem/ext4.md) | `deferred-task-batch-2026-04-25.md` |

### Networking

| Wiki page | Knowledge entries |
|-----------|-------------------|
| [Network Stack](../networking/Network-Stack.md) | `network-shell-commands-v0.md` |
| [Live Internet Verification](../networking/Live-Internet.md) | `live-internet-connectivity-v0.md` |

### Security

| Wiki page | Knowledge entries |
|-----------|-------------------|
| [Sandboxing](../security/Sandboxing.md) | `sandbox-overview-v0.md`, `kernel-isolation-v0.md`, `detour-hook-hardening-v0.md` |
| [Capabilities](../security/Capabilities.md) | `process-capabilities-v0.md` |
| [W^X / NX](../security/WX-Enforcement.md) | `dep-nx-v0.md`, `kpti-meltdown-investigation-v0.md` |
| [Attack Simulation](../security/Attack-Simulation.md) | `attack-sim-kernel-v1.md`, `pentest-ring3-adversarial-v0.md`, `pentest-gui-findings-v0.md`, `redteam-coverage-matrix-v0.md`, `security-guard.md`, `runtime-invariant-checker-v0.md` |
| [Runtime Recovery Strategy](../security/Runtime-Recovery.md) | `runtime-recovery-strategy.md` (verbatim source) |
| [Malware Hard-Stop Plan](../security/Malware-Hard-Stop-Plan.md) | `security-malware-hard-stop-plan.md` (verbatim source) |

### Tooling

| Wiki page | Knowledge entries |
|-----------|-------------------|
| [Build System](../tooling/Build-System.md) | `build-optimizations.md`, `clang-format.md`, `iso-build-and-boot.md`, `rust-bringup-plan.md` |
| [Coding Standards](../tooling/Coding-Standards.md) | `result-type-v0.md`, `ai-bloat-pattern.md`, `kmalloc-zero-init-pattern.md` |
| [Anti-Bloat Guidelines](../tooling/Anti-Bloat-Guidelines.md) | `ai-bloat-pattern.md`, `workflow-patterns.md` |
| [Git Workflow](../tooling/Git-Workflow.md) | `git-rebase-conflicts.md`, `github-api-pr-checks.md` |
| [Debugging](../tooling/Debugging.md) | `debug-tooling-symbol-disasm.md`, `breakpoints-v0.md`, `inspect-umbrella-v0.md`, `runtime-invariant-checker-v0.md`, `crash-dump-v0.md`, `kernel-debug-recommendations-plan.md`, `post-debug-recommendations-plan.md` |
| [QEMU Smoke Tests](../tooling/QEMU-Smoke.md) | `qemu-smoke-profile-matrix-v0.md`, `boot-verification-v0.md` |

### Plans (multi-session work files)

`.claude/knowledge/` also holds **plan files** that span multiple
sessions. Plans currently active:

- `post-debug-recommendations-plan.md` — graduated large items from
  the closed kernel-debug-recommendations plan (B2 SMP, KPTI/CET
  enable, per-zone allocator, slab+KASAN, ABI handle migration, GDB
  stub completion, more driver fault-domain registrations).
- `storage-and-filesystem-roadmap.md` — block layer -> NVMe/AHCI
  -> GPT -> FS plan (stages 1-2, 4 landed; rest deferred).
- `rust-bringup-plan.md` — trigger, layout, toolchain, CI for first
  Rust subsystem.
- `wireless-drivers-v0.md` (decisions section) — wireless data plane
  bringup roadmap.

## Maintenance

- The wiki is **regenerated** by `docs/sync-wiki.sh sync` (auto
  sections only; the prose is human-authored).
- The knowledge base is **append-only** during development. Old
  notes are kept for historical context; supersession is handled by
  cross-linking.
- Both are committed alongside code changes — see
  [Git Workflow > Pre-commit Checks](../tooling/Git-Workflow.md#pre-commit-checks).

## Related Pages

- [Design Decisions Log](Design-Decisions.md)
- [Directory Layout](Directory-Layout.md)
- See `.claude/index.md` for the live knowledge-base index
