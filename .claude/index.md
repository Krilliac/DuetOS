# Persistence Context — Index

_Read this at every session start (after git sync). Each row links to a detailed knowledge file._

## Knowledge Index

| Topic | File | Type | Status | Last Updated |
|-------|------|------|--------|--------------|
| AI bloat pattern and countermeasures | [knowledge/ai-bloat-pattern.md](knowledge/ai-bloat-pattern.md) | Observation | Active | 2026-04-20 |
| clang-format — CI-matching invocation | [knowledge/clang-format.md](knowledge/clang-format.md) | Pattern | Active | 2026-04-20 |
| Git rebase conflict resolution | [knowledge/git-rebase-conflicts.md](knowledge/git-rebase-conflicts.md) | Pattern | Active | 2026-04-20 |
| GitHub API / PR checks diagnosis | [knowledge/github-api-pr-checks.md](knowledge/github-api-pr-checks.md) | Pattern | Active | 2026-04-20 |
| Build and CI workflow speedups | [knowledge/build-optimizations.md](knowledge/build-optimizations.md) | Optimization | Active | 2026-04-20 |
| Effective dev workflows | [knowledge/workflow-patterns.md](knowledge/workflow-patterns.md) | Pattern | Active | 2026-04-20 |
| Win32/NT subsystem architecture | [knowledge/win32-subsystem-design.md](knowledge/win32-subsystem-design.md) | Decision | Active | 2026-04-20 |
| PE subsystem v0 — freestanding hello.exe + real-world PE diagnostic | [knowledge/pe-subsystem-v0.md](knowledge/pe-subsystem-v0.md) | Observation | Active | 2026-04-21 |
| PE base-relocation support v0 — walk + apply, zero-delta in v0 | [knowledge/pe-base-reloc-v0.md](knowledge/pe-base-reloc-v0.md) | Observation | Active | 2026-04-21 |
| Win32 subsystem v0 — import resolution + kernel32.ExitProcess stub | [knowledge/win32-subsystem-v0.md](knowledge/win32-subsystem-v0.md) | Observation | Active | 2026-04-21 |
| PE EAT parser + DLL loader skeleton (stage 2 slice 1) | [knowledge/pe-eat-dll-loader-v0.md](knowledge/pe-eat-dll-loader-v0.md) | Observation | Active | 2026-04-24 |
| Win32 windowing — current state (through v1.4) | [knowledge/win32-windowing-v1.4.md](knowledge/win32-windowing-v1.4.md) | Observation + Decision | Active | 2026-04-25 |
| Win32 heap — real HeapSize + HeapReAlloc / realloc (batch 14) | [knowledge/win32-subsystem-v0.md#batch-14--real-heapsize--heaprealloc](knowledge/win32-subsystem-v0.md) | Observation | Active | 2026-04-21 |
| Real-world PE execution — winkill CRT entry + argc/argv + five loader gaps | [knowledge/pe-real-world-run.md](knowledge/pe-real-world-run.md) | Observation | Active | 2026-04-22 |
| Win32 stubs — callee-saved rdi/rsi ABI bug + fix pattern | [knowledge/win32-stubs-rdi-rsi-abi.md](knowledge/win32-stubs-rdi-rsi-abi.md) | Issue + Pattern | Active | 2026-04-22 |
| Win32 stubs.{h,cpp} renamed to thunks.{h,cpp} — terminology + bytecode rationale | [knowledge/win32-thunks-rename.md](knowledge/win32-thunks-rename.md) | Decision | Active | 2026-04-25 |
| Kernel breakpoint subsystem v0 + phase 2a (per-task DR, syscall, kCapDebug) + phase 3 (suspend/inspect/resume/step) + phase 4 (static KBP_PROBE macros) | [knowledge/breakpoints-v0.md](knowledge/breakpoints-v0.md) | Observation | Active | 2026-04-23 |
| Hardware target matrix (CPU/GPU/IO tiers) | [knowledge/hardware-target-matrix.md](knowledge/hardware-target-matrix.md) | Decision | Active | 2026-04-20 |
| UEFI hybrid-ISO boot path — same ISO boots SeaBIOS + OVMF | [knowledge/uefi-hybrid-iso-v0.md](knowledge/uefi-hybrid-iso-v0.md) | Observation | Active | 2026-04-23 |
| Result<T, E> — kernel exception-handling primitive (software side) | [knowledge/result-type-v0.md](knowledge/result-type-v0.md) | Decision + Pattern | Active | 2026-04-23 |
| Kernel-stack guard pages v0 — unmapped low-edge page per task | [knowledge/kernel-stack-guard-v0.md](knowledge/kernel-stack-guard-v0.md) | Observation + Decision | Active | 2026-04-23 |
| Kernel isolation v0 — extable + fault domains | [knowledge/kernel-isolation-v0.md](knowledge/kernel-isolation-v0.md) | Decision + Pattern | Active | 2026-04-23 |
| Rust bring-up plan — trigger, layout, toolchain, CI | [knowledge/rust-bringup-plan.md](knowledge/rust-bringup-plan.md) | Decision | Active | 2026-04-21 |
| Storage + Filesystem roadmap — block layer → NVMe/AHCI → GPT → FS | [knowledge/storage-and-filesystem-roadmap.md](knowledge/storage-and-filesystem-roadmap.md) | Decision | Active (stages 1–2, 4 landed) | 2026-04-21 |
| NVMe driver v0 — polling admin + I/O queue, marker self-test | [knowledge/nvme-driver-v0.md](knowledge/nvme-driver-v0.md) | Observation | Active | 2026-04-21 |
| GPT parser v0 — PMBR + primary header + entries, CRC-validated | [knowledge/gpt-parser-v0.md](knowledge/gpt-parser-v0.md) | Observation | Active | 2026-04-21 |
| klog overhaul — Trace + scopes + metrics + sinks + colour | [knowledge/klog-overhaul.md](knowledge/klog-overhaul.md) | Observation | Active | 2026-04-21 |
| Security guard — image-load protection | [knowledge/security-guard.md](knowledge/security-guard.md) | Decision | Active | 2026-04-21 |
| Linux-ABI syscall subsystem | [knowledge/linux-abi-subsystem.md](knowledge/linux-abi-subsystem.md) | Observation | Active | 2026-04-22 |
| Linux syscall batches 55-56 + NT→Linux translator (SYS_NT_INVOKE) | [knowledge/linux-syscall-batch-55.md](knowledge/linux-syscall-batch-55.md) | Observation | Active | 2026-04-23 |
| `inspect` umbrella v0 — `syscalls` / `opcodes` / `arm` subcommands | [knowledge/inspect-umbrella-v0.md](knowledge/inspect-umbrella-v0.md) | Observation | Active | 2026-04-23 |
| ABI translation unit (Linux gap-fill) | [knowledge/abi-translation-unit.md](knowledge/abi-translation-unit.md) | Observation | Active | 2026-04-22 |
| Native DuetOS apps v0 — pattern for in-kernel applications | [knowledge/native-apps-v0.md](knowledge/native-apps-v0.md) | Pattern | Active | 2026-04-21 |
| gfxdemo multi-mode v0 — six animated effects (plasma/mandelbrot/cube/particles/starfield/fire) + key dispatch + self-tests | [knowledge/gfxdemo-multimode-v0.md](knowledge/gfxdemo-multimode-v0.md) | Observation + Pattern | Active | 2026-04-26 |
| Kernel bring-up v0 (Multiboot2 → long mode → `kernel_main`) | [knowledge/kernel-bringup-v0.md](knowledge/kernel-bringup-v0.md) | Observation | Active | 2026-04-20 |
| ISO build & end-to-end boot verification | [knowledge/iso-build-and-boot.md](knowledge/iso-build-and-boot.md) | Pattern | Active | 2026-04-20 |
| GDT + IDT v0 — canonical descriptors and trap path | [knowledge/gdt-idt-v0.md](knowledge/gdt-idt-v0.md) | Observation | Active | 2026-04-20 |
| Physical frame allocator v0 — bitmap over Multiboot2 map | [knowledge/frame-allocator-v0.md](knowledge/frame-allocator-v0.md) | Observation | Active | 2026-04-20 |
| Higher-half kernel move v0 — `0xFFFFFFFF80000000` | [knowledge/higher-half-kernel-v0.md](knowledge/higher-half-kernel-v0.md) | Observation | Active | 2026-04-20 |
| Boot stack high-VMA alias — fixes #DF on first boot→user CR3 switch under load | [knowledge/boot-stack-high-vma-fix.md](knowledge/boot-stack-high-vma-fix.md) | Issue + Pattern | Active | 2026-04-26 |
| Debug tooling — `addr2sym` shell command + `tools/debug/disasm-at.sh` + `tools/debug/decode-panic.sh` | [knowledge/debug-tooling-symbol-disasm.md](knowledge/debug-tooling-symbol-disasm.md) | Pattern | Active | 2026-04-26 |
| Kernel heap v0 — first-fit + coalescing over direct map | [knowledge/kernel-heap-v0.md](knowledge/kernel-heap-v0.md) | Observation | Active | 2026-04-20 |
| Managed page-table API v0 — 4-level walker over boot PML4 | [knowledge/paging-v0.md](knowledge/paging-v0.md) | Observation | Active | 2026-04-20 |
| LAPIC + periodic timer v0 — PIT-calibrated 100 Hz tick | [knowledge/lapic-timer-v0.md](knowledge/lapic-timer-v0.md) | Observation | Active | 2026-04-20 |
| Scheduler v0 — round-robin kernel threads with preemption | [knowledge/scheduler-v0.md](knowledge/scheduler-v0.md) | Observation | Active | 2026-04-20 |
| Scheduler blocking primitives v0 — sleep, wait queues, mutex | [knowledge/sched-blocking-primitives-v0.md](knowledge/sched-blocking-primitives-v0.md) | Observation | Active | 2026-04-20 |
| ACPI MADT discovery v0 — RSDP → XSDT/RSDT → APIC table | [knowledge/acpi-madt-v0.md](knowledge/acpi-madt-v0.md) | Observation | Active | 2026-04-20 |
| IOAPIC driver v0 — MMIO redirection table + ACPI override routing | [knowledge/ioapic-v0.md](knowledge/ioapic-v0.md) | Observation | Active | 2026-04-20 |
| PS/2 keyboard v0 — first end-to-end IRQ-driven driver | [knowledge/ps2-keyboard-v0.md](knowledge/ps2-keyboard-v0.md) | Observation | Active | 2026-04-20 |
| Boot verification v0 — end-to-end QEMU boot baseline | [knowledge/boot-verification-v0.md](knowledge/boot-verification-v0.md) | Observation | Active | 2026-04-20 |
| Per-process address space v0 — `mm::AddressSpace`, per-task PML4, isolation | [knowledge/per-process-address-space-v0.md](knowledge/per-process-address-space-v0.md) | Observation | Active | 2026-04-20 |
| Process + capability model v0 — `core::Process`, `CapSet`, cap-gated syscalls | [knowledge/process-capabilities-v0.md](knowledge/process-capabilities-v0.md) | Observation | Active | 2026-04-20 |
| VFS namespace + per-process root v0 — ramfs + `Process::root` + SYS_STAT | [knowledge/vfs-namespace-v0.md](knowledge/vfs-namespace-v0.md) | Observation | Active | 2026-04-20 |
| Sandboxing overview v0 — consolidated 5-wall story across AS/caps/VFS/W^X/budget | [knowledge/sandbox-overview-v0.md](knowledge/sandbox-overview-v0.md) | Decision | Active | 2026-04-20 |
| DEP / NX / W^X v0 — EFER.NXE, map-time gate, kernel-image split, live probes | [knowledge/dep-nx-v0.md](knowledge/dep-nx-v0.md) | Observation | Active | 2026-04-20 |
| Detour / hook hardening v0 — threat-model table + every wall mapped | [knowledge/detour-hook-hardening-v0.md](knowledge/detour-hook-hardening-v0.md) | Decision | Active | 2026-04-20 |
| SMP foundations v0 — spinlocks + per-CPU data | [knowledge/smp-foundations-v0.md](knowledge/smp-foundations-v0.md) | Observation | Active | 2026-04-20 |
| Runtime recovery strategy — halt/restart/retry/reject taxonomy | [../docs/knowledge/runtime-recovery-strategy.md](../docs/knowledge/runtime-recovery-strategy.md) | Decision | Active | 2026-04-20 |
| PCI enumeration v0 — legacy port-IO walk | [knowledge/pci-enum-v0.md](knowledge/pci-enum-v0.md) | Observation | Active | 2026-04-20 |
| GPU discovery v0 — PCI classification + BAR map | [knowledge/gpu-discovery-v0.md](knowledge/gpu-discovery-v0.md) | Observation | Active | 2026-04-22 |
| Driver shells v0 — net / usb / audio / gpu-probes | [knowledge/driver-shells-v0.md](knowledge/driver-shells-v0.md) | Observation | Active | 2026-04-22 |
| Render / drivers — current state (through v6) | [knowledge/render-drivers-v6.md](knowledge/render-drivers-v6.md) | Observation + Decision | Active | 2026-04-25 |
| DirectX v0 — real COM-vtable d3d9/d3d11/d3d12/dxgi DLLs | [knowledge/directx-v0.md](knowledge/directx-v0.md) | Observation + Decision | Active | 2026-04-24 |
| xHCI enumeration v0 — Address Device + GET_DESCRIPTOR(Device) | [knowledge/xhci-enumeration-v0.md](knowledge/xhci-enumeration-v0.md) | Observation | Active | 2026-04-23 |
| xHCI HID boot keyboard — end-to-end USB keyboard input | [knowledge/xhci-hid-keyboard-v0.md](knowledge/xhci-hid-keyboard-v0.md) | Observation | Active | 2026-04-23 |
| Intel e1000 NIC driver — real packet I/O on commodity wired gigabit | [knowledge/e1000-driver-v0.md](knowledge/e1000-driver-v0.md) | Observation | Active | 2026-04-23 |
| Network shell commands — ifconfig / dhcp / route / netscan / net | [knowledge/network-shell-commands-v0.md](knowledge/network-shell-commands-v0.md) | Observation | Active | 2026-04-25 |
| Network flyout panel — bottom-right Wi-Fi-style popup with hover preview | [knowledge/network-flyout-panel-v0.md](knowledge/network-flyout-panel-v0.md) | Observation + Decision | Active | 2026-04-25 |
| Wireless driver shells v0 — iwlwifi / rtl88xx / bcm43xx chip-id bring-up | [knowledge/wireless-drivers-v0.md](knowledge/wireless-drivers-v0.md) | Observation + Decision | Active | 2026-04-25 |
| Live Internet connectivity v0 — DuetOS reaches Google over real DNS + TCP | [knowledge/live-internet-connectivity-v0.md](knowledge/live-internet-connectivity-v0.md) | Observation + Pattern | Active | 2026-04-25 |
| USB CDC-ECM driver + xHCI bulk-transfer API v0 | [knowledge/usb-cdc-ecm-driver-v0.md](knowledge/usb-cdc-ecm-driver-v0.md) | Observation + Decision | Active (probe not auto-called) | 2026-04-25 |
| USB RNDIS driver + bulk-poll serialization v0 | [knowledge/usb-rndis-driver-v0.md](knowledge/usb-rndis-driver-v0.md) | Observation + Decision | Active (control plane works; bulk concurrency gap) | 2026-04-25 |
| Kernel entropy pool — RDSEED/RDRAND/splitmix tier | [knowledge/kernel-entropy-v0.md](knowledge/kernel-entropy-v0.md) | Observation | Active | 2026-04-22 |
| Runtime invariant checker — heap/frames/sched/CRx/canary/stack-overflow | [knowledge/runtime-invariant-checker-v0.md](knowledge/runtime-invariant-checker-v0.md) | Observation | Active | 2026-04-22 |
| Crash dump v0 — embedded symbol table + bracketed dump file (+ register-bit decoders + GPR symbolization + readable uptime/task labels + tree-wide hex log readability pass: PCI/NVMe/AHCI/xHCI/USB/PE/GPT/ext4/FAT32/Linux-signals/Win32-NTSTATUS + VA-region tags on cr2/rsp/rbp/rip + boot-time mm-map anchor + peer-CPU NMI snapshots + per-CPU held-locks dump) | [knowledge/crash-dump-v0.md](knowledge/crash-dump-v0.md) | Observation | Active | 2026-04-25 |
| Ring 3 first slice — GDT user segments + iretq entry + smoke task | [knowledge/ring3-first-slice-v0.md](knowledge/ring3-first-slice-v0.md) | Observation | Active | 2026-04-20 |
| Ring-3 adversarial test suite — jail / nx / priv / badint / kread probes | [knowledge/pentest-ring3-adversarial-v0.md](knowledge/pentest-ring3-adversarial-v0.md) | Pattern | Active | 2026-04-21 |
| GUI pentest runner v0 — live login + shell attack findings | [knowledge/pentest-gui-findings-v0.md](knowledge/pentest-gui-findings-v0.md) | Observation | Active | 2026-04-24 |
| Kernel attacker simulation suite v1 — 9 active attacks (bootkit, IDT, GDT, LSTAR, CR0.WP, SMEP, SMAP, NXE, .text patch) + deferred catalogue | [knowledge/attack-sim-kernel-v1.md](knowledge/attack-sim-kernel-v1.md) | Observation + Pattern | Active | 2026-04-26 |
| Cleanroom-trace boot survey v0 — first live read of the trace ring buffer | [knowledge/cleanroom-trace-boot-survey-v0.md](knowledge/cleanroom-trace-boot-survey-v0.md) | Observation | Active | 2026-04-25 |
| Deferred-task batches (2026-04-25 + 2026-04-26 follow-up) — PE ordinal forwarders + by-ord IAT + binary-search EAT, ext4 multi-block dirs, ext4 depth>0 extent tree walk, GDI ellipse fill/outline parity, RNDIS multi-record RX, FAT32 LFN-checksum, window-DC SetTextColor explicit-black | [knowledge/deferred-task-batch-2026-04-25.md](knowledge/deferred-task-batch-2026-04-25.md) | Observation | Active | 2026-04-26 |
| Win32 custom diagnostics + safety extensions v0 — flight recorder, handle provenance, error provenance, heap quarantine, deadlock detect, contention profile, async-paint policy, pixel isolation, input replay, strict-RWX, strict-handle-inherit (all opt-in) | [knowledge/win32-custom-extensions-v0.md](knowledge/win32-custom-extensions-v0.md) | Observation + Decision | Active | 2026-04-25 |

## Quick Reference

### Current Project State (2026-04-25)

The system boots end-to-end on QEMU `-vga virtio` and exercises every
landed subsystem on its way to the desktop. Headline capabilities:

- **PE / Win32**: Real-world MSVC PEs (e.g. `windows-kill.exe`, ~80 KB,
  52 imports across 6 DLLs, SEH + TLS + resources) load and exit
  cleanly. Stage-2 PE loader chases forwarders (name + ordinal) through
  the per-process DLL table; ordinal-form `Dll.#N` forwarders are
  parsed; by-ordinal IAT entries resolve against preloaded EATs;
  `PeExportLookupName` is binary-search.
- **Win32 windowing**: `windowed_hello` paints with GDI primitives,
  pumps `WM_TIMER`s, dispatches `WM_PAINT` through a user-registered
  WndProc, round-trips `SendMessage`, queries focus / styles / palette,
  exits cleanly. `text_color_set` flag honors explicit-black
  `SetTextColor`. Filled-ellipse compositor prim parity between
  window-HDC and memDC paths.
- **Storage / FS**: NVMe + GPT + FAT32 + ext4 read paths. FAT32 LFN
  walker validates the per-fragment checksum against the trailing SFN
  (orphaned LFN runs fall back to the 8.3 name). ext4 root-dir walk
  iterates every leaf-extent block; depth>0 still deferred.
- **Net**: e1000 wired NIC + USB CDC-ECM + USB RNDIS for live
  Internet. RNDIS RX delivers every `RNDIS_PACKET_MSG` per bulk
  transfer (was: only the first).
- **Render**: virtio-gpu 2D scanout cycle as the kernel framebuffer;
  Classic-theme system palette; 8×8 font.
- **Security**: SMEP / SMAP / NX / W^X / KASLR / CFI all on; image-load
  guard; per-process address spaces; sandbox 5-wall story.

Branch convention: each Claude-driven slice runs on its own
`claude/<slug>` feature branch. Merge target is `main`. The active
branch for any given session is whatever the harness checked out;
session-start git sync rebases on `origin/main` first.

- **Default branch**: `main`.
- **Platforms**: x86_64 first (Multiboot2 → long mode + UEFI hybrid
  ISO). ARM64 planned, not started.
- **Toolchain**: clang 18.1.3, lld 18, cmake 3.28, GNU assembler via
  clang (`.S` files with Intel syntax). NASM not required yet.
- **Build**: `cmake --preset x86_64-debug` / `x86_64-release`. Output:
  `build/<preset>/kernel/duetos-kernel.elf`.
- **Live-test tooling on demand**: `qemu-system-x86_64`, `ovmf`,
  `grub-mkrescue`, `xorriso`, `mtools` are NOT pre-installed on the
  dev host. CLAUDE.md → "Live-test runtime tooling — install on
  demand" lists when to install (runtime-behaviour deltas, not pure
  refactors) and the apt line.
- **CI**: not yet wired. When it lands, mirror locally with the
  commands in CLAUDE.md → "Pre-commit checks".

### Project Pillars (one-liners)

- PE executables run as a **native ABI**, not through an emulator shell.
- Kernel is a **hybrid** (microkernel IPC shape, monolithic hot paths).
- **Direct GPU drivers** for Intel / AMD / NVIDIA; Vulkan is the primary user-mode API.
- **Capability-based IPC**; no setuid.
- **W^X, ASLR, SMEP/SMAP, KASLR, CFI** enforced from day one.

### Before Writing Code

1. Check file size — if over 500 lines (`.cpp`/`.c`/`.rs`) or 300 lines (`.h`/`.hpp`), consider splitting.
2. Search for existing implementations before adding new ones — especially low-level primitives (spinlocks, allocators, list helpers).
3. Be explicit about kernel vs. user space. Kernel has no `malloc`, no `printf`, no exceptions.
4. Run `clang-format -i` on modified files before committing.
5. If adding a syscall number, remember: **once published, it's ABI forever.**

### CI Quick Reference

- Once CI is online, treat `check-format` as the canonical formatter check. Mirror it locally using the full command in `.claude/knowledge/clang-format.md`.
- Use GitHub MCP tools in this environment (not `gh`) for PR polling. See `.claude/knowledge/github-api-pr-checks.md`.
- Pre-push order: format → configure → build → tests → QEMU smoke.

---

_To add a new entry: create a file in `knowledge/`, add a row to the table above, then commit both. Delete completed single-shot session logs — the code is in the repo and the history is in git._
