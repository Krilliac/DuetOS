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
| Win32 windowing v0 — user32 → SYS_WIN_* → compositor | [knowledge/win32-windowing-v0.md](knowledge/win32-windowing-v0.md) | Observation + Decision | Active | 2026-04-24 |
| Win32 windowing v1 — per-window msg queues + GDI + input + reaper | [knowledge/win32-windowing-v1.md](knowledge/win32-windowing-v1.md) | Observation + Decision | Active | 2026-04-24 |
| Win32 windowing v1.2 — lifecycle msgs + timers + GDI prims + async input + capture + clipboard | [knowledge/win32-windowing-v1.2.md](knowledge/win32-windowing-v1.2.md) | Observation + Decision | Active | 2026-04-24 |
| Win32 windowing v1.3 — WndProc dispatch + WM_PAINT + longs + metrics + cross-proc + enum/find | [knowledge/win32-windowing-v1.3.md](knowledge/win32-windowing-v1.3.md) | Observation + Decision | Active | 2026-04-24 |
| Win32 windowing v1.4 — SendMessage + styles + parent/focus + caret + beep + MessageBox types | [knowledge/win32-windowing-v1.4.md](knowledge/win32-windowing-v1.4.md) | Observation + Decision | Active | 2026-04-24 |
| Win32 heap — real HeapSize + HeapReAlloc / realloc (batch 14) | [knowledge/win32-subsystem-v0.md#batch-14--real-heapsize--heaprealloc](knowledge/win32-subsystem-v0.md) | Observation | Active | 2026-04-21 |
| Real-world PE execution — winkill CRT entry + argc/argv + five loader gaps | [knowledge/pe-real-world-run.md](knowledge/pe-real-world-run.md) | Observation | Active | 2026-04-22 |
| Win32 stubs — callee-saved rdi/rsi ABI bug + fix pattern | [knowledge/win32-stubs-rdi-rsi-abi.md](knowledge/win32-stubs-rdi-rsi-abi.md) | Issue + Pattern | Active | 2026-04-22 |
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
| Kernel bring-up v0 (Multiboot2 → long mode → `kernel_main`) | [knowledge/kernel-bringup-v0.md](knowledge/kernel-bringup-v0.md) | Observation | Active | 2026-04-20 |
| ISO build & end-to-end boot verification | [knowledge/iso-build-and-boot.md](knowledge/iso-build-and-boot.md) | Pattern | Active | 2026-04-20 |
| GDT + IDT v0 — canonical descriptors and trap path | [knowledge/gdt-idt-v0.md](knowledge/gdt-idt-v0.md) | Observation | Active | 2026-04-20 |
| Physical frame allocator v0 — bitmap over Multiboot2 map | [knowledge/frame-allocator-v0.md](knowledge/frame-allocator-v0.md) | Observation | Active | 2026-04-20 |
| Higher-half kernel move v0 — `0xFFFFFFFF80000000` | [knowledge/higher-half-kernel-v0.md](knowledge/higher-half-kernel-v0.md) | Observation | Active | 2026-04-20 |
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
| render/drivers v1 — virtio-gpu bring-up + D3D IAT routing + vendor MMIO reads | [knowledge/render-drivers-v1.md](knowledge/render-drivers-v1.md) | Observation + Pattern | Active | 2026-04-24 |
| render/drivers v2 — virtio-gpu 2D cycle + SYS_GDI_BITBLT + real paint IAT | [knowledge/render-drivers-v2.md](knowledge/render-drivers-v2.md) | Observation + Pattern | Active | 2026-04-24 |
| render/drivers v3 — virtio-gpu kernel FB + TextOutA + GDI object table + real BitBlt | [knowledge/render-drivers-v3.md](knowledge/render-drivers-v3.md) | Observation + Decision | Active | 2026-04-24 |
| render/drivers v4 — memDC painting + DC colour state + StretchBlt | [knowledge/render-drivers-v4.md](knowledge/render-drivers-v4.md) | Observation | Active | 2026-04-24 |
| render/drivers v5 — Rectangle/Ellipse/SetPixel IAT + pen state + MoveToEx/LineTo + DrawTextA | [knowledge/render-drivers-v5.md](knowledge/render-drivers-v5.md) | Observation | Active | 2026-04-24 |
| render/drivers v6 — message loop + filled primitives + UTF-16 text + sys palette | [knowledge/render-drivers-v6.md](knowledge/render-drivers-v6.md) | Observation + Decision | Active | 2026-04-24 |
| DirectX v0 — real COM-vtable d3d9/d3d11/d3d12/dxgi DLLs | [knowledge/directx-v0.md](knowledge/directx-v0.md) | Observation + Decision | Active | 2026-04-24 |
| xHCI enumeration v0 — Address Device + GET_DESCRIPTOR(Device) | [knowledge/xhci-enumeration-v0.md](knowledge/xhci-enumeration-v0.md) | Observation | Active | 2026-04-23 |
| xHCI HID boot keyboard — end-to-end USB keyboard input | [knowledge/xhci-hid-keyboard-v0.md](knowledge/xhci-hid-keyboard-v0.md) | Observation | Active | 2026-04-23 |
| Intel e1000 NIC driver — real packet I/O on commodity wired gigabit | [knowledge/e1000-driver-v0.md](knowledge/e1000-driver-v0.md) | Observation | Active | 2026-04-23 |
| Network shell commands — ifconfig / dhcp / route / netscan / net | [knowledge/network-shell-commands-v0.md](knowledge/network-shell-commands-v0.md) | Observation | Active | 2026-04-25 |
| Network flyout panel — bottom-right Wi-Fi-style popup with hover preview | [knowledge/network-flyout-panel-v0.md](knowledge/network-flyout-panel-v0.md) | Observation + Decision | Active | 2026-04-25 |
| Kernel entropy pool — RDSEED/RDRAND/splitmix tier | [knowledge/kernel-entropy-v0.md](knowledge/kernel-entropy-v0.md) | Observation | Active | 2026-04-22 |
| Runtime invariant checker — heap/frames/sched/CRx/canary/stack-overflow | [knowledge/runtime-invariant-checker-v0.md](knowledge/runtime-invariant-checker-v0.md) | Observation | Active | 2026-04-22 |
| Crash dump v0 — embedded symbol table + bracketed dump file | [knowledge/crash-dump-v0.md](knowledge/crash-dump-v0.md) | Observation | Active | 2026-04-20 |
| Ring 3 first slice — GDT user segments + iretq entry + smoke task | [knowledge/ring3-first-slice-v0.md](knowledge/ring3-first-slice-v0.md) | Observation | Active | 2026-04-20 |
| Ring-3 adversarial test suite — jail / nx / priv / badint / kread probes | [knowledge/pentest-ring3-adversarial-v0.md](knowledge/pentest-ring3-adversarial-v0.md) | Pattern | Active | 2026-04-21 |
| GUI pentest runner v0 — live login + shell attack findings | [knowledge/pentest-gui-findings-v0.md](knowledge/pentest-gui-findings-v0.md) | Observation | Active | 2026-04-24 |

## Quick Reference

### Current Project State (2026-04-22)

**Milestone (2026-04-22)**: `windows-kill.exe` — a real-world 80 KB MSVC
PE with 8 sections, 52 imports across 6 DLLs, SEH, TLS, and a resource
directory — runs end-to-end as a ring-3 process on DuetOS and exits
via `SYS_EXIT(0)`. No #PF, no #GP, no panic, no task-kill. The CRT's
`__p___argc` / `__p___argv` now return pointers into a per-process
proc-env page; unresolved data imports (e.g. `std::cout`) route to a
fake-object pad so MSVC's virtual-dispatch idiom walks mapped zeros
instead of code bytes; the miss-logger decoder skips indirect-call
patterns rather than fabricating `<unmapped>` entries. Programs don't
yet PRINT (std::cout no-ops), but the full PE execution path is clean.

### Prior Project State (2026-04-20)

- **Repository**: kernel runs at `0xFFFFFFFF80000000` (higher-half), brings up GDT + IDT (vectors 0..47 + LAPIC spurious 0xFF), parses the Multiboot2 memory map, runs a bitmap-backed physical frame allocator with single + contiguous-run allocation, brings up a 2 MiB first-fit + coalescing kernel heap (`KMalloc`/`KFree`) over the higher-half direct map, adopts the boot PML4 with a 4-level managed paging API (`MapPage`/`UnmapPage`/`MapMmio` into a 512 MiB MMIO arena at `0xFFFFFFFFC0000000`, EFER.NXE on), masks the legacy 8259 PIC, brings up the BSP LAPIC, arms a PIT-calibrated periodic LAPIC timer at 100 Hz on vector 0x20, and runs a round-robin preemptive scheduler with kernel threads (`SchedCreate` / `SchedYield` / `SchedExit`) whose time slices are driven by the timer IRQ. Blocking primitives are online: `SchedSleepTicks` (tick-driven sleep queue), `WaitQueue` (event-driven FIFO), and `Mutex` with FIFO hand-off (built on `WaitQueue`). ACPI MADT is parsed at boot (RSDP → XSDT/RSDT → APIC) and the IOAPIC driver consumes it to map every controller's MMIO window, read the version register, and mask every pin; `IoApicRoute(gsi, vector, lapic_id, isa_irq)` / `IoApicMask` / `IoApicUnmask` are ready for drivers to program. MPS polarity + trigger flags from MADT overrides are honoured on ISA routes. PS/2 keyboard is online as the first real end-to-end IRQ-driven driver: ACPI → IOAPIC → IDT → dispatcher → driver → SPSC ring buffer → `WaitQueue` → scheduler — raw scan codes come out as `[kbd] scan=0xNN` on COM1. Both the panic path and the CPU-exception trap dispatcher now emit a bracketed, self-describing crash dump record (`=== DUETOS CRASH DUMP BEGIN/END ===`) with every code address annotated inline by an embedded, build-time-generated function symbol table (`function+offset (file:line)`); trap dumps also carry all GPRs from the hardware TrapFrame. `tools/test-panic.sh` and `tools/test-trap.sh` extract each record into `build/<preset>/crash-dumps/<timestamp>.dump` and `<timestamp>-trap.dump` respectively, asserting the shape of each path. Design decisions are now tracked in a living log (`docs/knowledge/design-decisions-log.md`) with rationale + "revisit when" markers per slice. The GDT has been extended with DPL=3 user-code/user-data descriptors (slots 5–6); the BSP TSS gained a runtime-settable RSP0 slot that the scheduler now auto-publishes on every switch-in to a task with a kernel stack. `arch::EnterUserMode(rip, rsp)` builds an iretq frame into ring 3. The syscall ABI v0 is online via `int 0x80` (DPL=3 gate): `SYS_EXIT = 0`, `SYS_GETPID = 1`, `SYS_WRITE = 2`, `SYS_YIELD = 3`. SMEP + SMAP are enabled in `PagingInit` (CPUID-gated CR4 flips); `mm::CopyFromUser` / `mm::CopyToUser` validate pointers against the canonical low half, walk the PT to confirm every touched page is `Present | User`, and bracket the copy with stac/clac. Per-task user-VM regions are registered via `sched::RegisterUserVmRegion` and reaped (UnmapPage + FreeFrame) on task death, so nothing leaks across task boundaries. A `ring3-smoke` scheduler thread maps one code + one stack page with the U/S bit set, drops a 38-byte payload (pause; pause; SYS_WRITE("Hello from ring 3!\n"); SYS_YIELD; SYS_EXIT) into ring 3, registers both pages for reaper-driven cleanup, and is reaped cleanly by the kernel-side reaper after SYS_EXIT — the user pages are unmapped and the backing frames returned to the physical allocator. Boot ends with three worker threads contending on a demo mutex, a `kbd-reader` thread blocked on keyboard input, the BSP driving its idle task via `sti; hlt`, and APs halted in their trampoline. All self-tests pass. Next bites: SMP scheduler join (APs actually running), USB HID / xHCI (real-hardware input path), `__copy_user_fault_fixup` for copy-from-user #PF recovery, or per-process address spaces (unblocks a second ring-3 task without a VA collision).
- **Default branch**: `main`.
- **Active dev branch**: `claude/port-sparkengine-components-f38iH` (Claude-driven bootstrapping).
- **Platforms**: x86_64 first (Multiboot2 → long mode). ARM64 planned, not started. UEFI path planned, not started.
- **Toolchain in use**: clang 18.1.3, lld 18, cmake 3.28, GNU assembler via clang (`.S` files with Intel syntax). NASM not required yet.
- **Build system**: `cmake --preset x86_64-debug` / `x86_64-release`. Produces `build/<preset>/kernel/duetos-kernel.elf`.
- **Runtime tooling not yet installed on dev host**: `qemu-system-x86_64`, `ovmf`, `grub-mkrescue`, `xorriso`. `tools/qemu/run.sh` documents the install step and will work as soon as those are present, once the Multiboot2 ISO build helper lands.
- **CI**: not yet wired. When it lands, mirror locally with the commands in `CLAUDE.md` → "Pre-commit checks".

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
