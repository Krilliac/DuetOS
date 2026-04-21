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
| Win32 heap — real HeapSize + HeapReAlloc / realloc (batch 14) | [knowledge/win32-subsystem-v0.md#batch-14--real-heapsize--heaprealloc](knowledge/win32-subsystem-v0.md) | Observation | Active | 2026-04-21 |
| Hardware target matrix (CPU/GPU/IO tiers) | [knowledge/hardware-target-matrix.md](knowledge/hardware-target-matrix.md) | Decision | Active | 2026-04-20 |
| Rust bring-up plan — trigger, layout, toolchain, CI | [knowledge/rust-bringup-plan.md](knowledge/rust-bringup-plan.md) | Decision | Active | 2026-04-21 |
| Storage + Filesystem roadmap — block layer → NVMe/AHCI → GPT → FS | [knowledge/storage-and-filesystem-roadmap.md](knowledge/storage-and-filesystem-roadmap.md) | Decision | Active (stages 1–2, 4 landed) | 2026-04-21 |
| NVMe driver v0 — polling admin + I/O queue, marker self-test | [knowledge/nvme-driver-v0.md](knowledge/nvme-driver-v0.md) | Observation | Active | 2026-04-21 |
| GPT parser v0 — PMBR + primary header + entries, CRC-validated | [knowledge/gpt-parser-v0.md](knowledge/gpt-parser-v0.md) | Observation | Active | 2026-04-21 |
| Native CustomOS apps v0 — pattern for in-kernel applications | [knowledge/native-apps-v0.md](knowledge/native-apps-v0.md) | Pattern | Active | 2026-04-21 |
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
| Crash dump v0 — embedded symbol table + bracketed dump file | [knowledge/crash-dump-v0.md](knowledge/crash-dump-v0.md) | Observation | Active | 2026-04-20 |
| Ring 3 first slice — GDT user segments + iretq entry + smoke task | [knowledge/ring3-first-slice-v0.md](knowledge/ring3-first-slice-v0.md) | Observation | Active | 2026-04-20 |
| Ring-3 adversarial test suite — jail / nx / priv / badint / kread probes | [knowledge/pentest-ring3-adversarial-v0.md](knowledge/pentest-ring3-adversarial-v0.md) | Pattern | Active | 2026-04-21 |

## Quick Reference

### Current Project State (2026-04-20)

- **Repository**: kernel runs at `0xFFFFFFFF80000000` (higher-half), brings up GDT + IDT (vectors 0..47 + LAPIC spurious 0xFF), parses the Multiboot2 memory map, runs a bitmap-backed physical frame allocator with single + contiguous-run allocation, brings up a 2 MiB first-fit + coalescing kernel heap (`KMalloc`/`KFree`) over the higher-half direct map, adopts the boot PML4 with a 4-level managed paging API (`MapPage`/`UnmapPage`/`MapMmio` into a 512 MiB MMIO arena at `0xFFFFFFFFC0000000`, EFER.NXE on), masks the legacy 8259 PIC, brings up the BSP LAPIC, arms a PIT-calibrated periodic LAPIC timer at 100 Hz on vector 0x20, and runs a round-robin preemptive scheduler with kernel threads (`SchedCreate` / `SchedYield` / `SchedExit`) whose time slices are driven by the timer IRQ. Blocking primitives are online: `SchedSleepTicks` (tick-driven sleep queue), `WaitQueue` (event-driven FIFO), and `Mutex` with FIFO hand-off (built on `WaitQueue`). ACPI MADT is parsed at boot (RSDP → XSDT/RSDT → APIC) and the IOAPIC driver consumes it to map every controller's MMIO window, read the version register, and mask every pin; `IoApicRoute(gsi, vector, lapic_id, isa_irq)` / `IoApicMask` / `IoApicUnmask` are ready for drivers to program. MPS polarity + trigger flags from MADT overrides are honoured on ISA routes. PS/2 keyboard is online as the first real end-to-end IRQ-driven driver: ACPI → IOAPIC → IDT → dispatcher → driver → SPSC ring buffer → `WaitQueue` → scheduler — raw scan codes come out as `[kbd] scan=0xNN` on COM1. Both the panic path and the CPU-exception trap dispatcher now emit a bracketed, self-describing crash dump record (`=== CUSTOMOS CRASH DUMP BEGIN/END ===`) with every code address annotated inline by an embedded, build-time-generated function symbol table (`function+offset (file:line)`); trap dumps also carry all GPRs from the hardware TrapFrame. `tools/test-panic.sh` and `tools/test-trap.sh` extract each record into `build/<preset>/crash-dumps/<timestamp>.dump` and `<timestamp>-trap.dump` respectively, asserting the shape of each path. Design decisions are now tracked in a living log (`docs/knowledge/design-decisions-log.md`) with rationale + "revisit when" markers per slice. The GDT has been extended with DPL=3 user-code/user-data descriptors (slots 5–6); the BSP TSS gained a runtime-settable RSP0 slot that the scheduler now auto-publishes on every switch-in to a task with a kernel stack. `arch::EnterUserMode(rip, rsp)` builds an iretq frame into ring 3. The syscall ABI v0 is online via `int 0x80` (DPL=3 gate): `SYS_EXIT = 0`, `SYS_GETPID = 1`, `SYS_WRITE = 2`, `SYS_YIELD = 3`. SMEP + SMAP are enabled in `PagingInit` (CPUID-gated CR4 flips); `mm::CopyFromUser` / `mm::CopyToUser` validate pointers against the canonical low half, walk the PT to confirm every touched page is `Present | User`, and bracket the copy with stac/clac. Per-task user-VM regions are registered via `sched::RegisterUserVmRegion` and reaped (UnmapPage + FreeFrame) on task death, so nothing leaks across task boundaries. A `ring3-smoke` scheduler thread maps one code + one stack page with the U/S bit set, drops a 38-byte payload (pause; pause; SYS_WRITE("Hello from ring 3!\n"); SYS_YIELD; SYS_EXIT) into ring 3, registers both pages for reaper-driven cleanup, and is reaped cleanly by the kernel-side reaper after SYS_EXIT — the user pages are unmapped and the backing frames returned to the physical allocator. Boot ends with three worker threads contending on a demo mutex, a `kbd-reader` thread blocked on keyboard input, the BSP driving its idle task via `sti; hlt`, and APs halted in their trampoline. All self-tests pass. Next bites: SMP scheduler join (APs actually running), USB HID / xHCI (real-hardware input path), `__copy_user_fault_fixup` for copy-from-user #PF recovery, or per-process address spaces (unblocks a second ring-3 task without a VA collision).
- **Default branch**: `main`.
- **Active dev branch**: `claude/port-sparkengine-components-f38iH` (Claude-driven bootstrapping).
- **Platforms**: x86_64 first (Multiboot2 → long mode). ARM64 planned, not started. UEFI path planned, not started.
- **Toolchain in use**: clang 18.1.3, lld 18, cmake 3.28, GNU assembler via clang (`.S` files with Intel syntax). NASM not required yet.
- **Build system**: `cmake --preset x86_64-debug` / `x86_64-release`. Produces `build/<preset>/kernel/customos-kernel.elf`.
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
