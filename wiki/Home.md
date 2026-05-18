# DuetOS Wiki

**DuetOS** is a from-scratch, general-purpose operating system written in C++23,
Rust, and x86_64 assembly. It is designed around two co-equal goals:

1. **Run Windows PE executables natively** as a first-class ABI — not via VM,
   not via Wine, not as an emulator on another host. The PE loader, NT syscall
   surface, and full set of user-mode DLLs (`kernel32`, `ntdll`, `user32`,
   `gdi32`, `d3d*`, `dxgi`, `winmm`, …) live in this repo as part of the base
   system, peer to the native ABI.
2. **Run on commodity PC hardware** — x86_64 from day one (Intel + AMD), with
   first-class driver support for commodity GPUs (Intel iGPU, AMD Radeon,
   NVIDIA GeForce). ARM64 is a planned second tier.

> **One kernel, two ABI faces.** Native DuetOS programs and Windows PE
> executables both converge through the same `int 0x80` syscall gate into the
> same kernel subsystems. There is one TCP stack, one VFS, one registry, one
> compositor — each reachable from two ABI front-ends. Win32 and Linux are
> *facades for executing PE/ELF binaries*; they never drive DuetOS, they call
> the kernel like everyone else.

## Where to Start

| Role | Recommended reading order |
|------|---------------------------|
| **New to DuetOS** | [Getting Started](getting-started/Getting-Started.md) -> [Architecture Overview](getting-started/Architecture-Overview.md) -> [History](getting-started/History.md) |
| **Kernel hacker** | [Architecture Overview](getting-started/Architecture-Overview.md) -> [Boot Path](kernel/Boot.md) -> [Memory Management](kernel/Memory-Management.md) -> [Scheduler](kernel/Scheduler.md) -> [Subsystem Isolation](kernel/Subsystem-Isolation.md) |
| **Driver author** | [Driver Overview](drivers/Driver-Overview.md) -> [PCIe Enumeration](drivers/PCIe-Enumeration.md) -> the device-class page (storage / USB / net / GPU) |
| **PE / Win32 dev** | [Win32 PE Subsystem](subsystems/Win32-PE-Subsystem.md) -> [PE Loader](subsystems/PE-Loader.md) -> [Win32 DLLs](subsystems/Win32-DLLs.md) |
| **Linux ABI dev** | [Linux ABI](subsystems/Linux-ABI.md) |
| **Security / threat modeller** | [Sandboxing](security/Sandboxing.md) -> [Capabilities](security/Capabilities.md) -> [W^X / NX](security/WX-Enforcement.md) -> [Attack Simulation](security/Attack-Simulation.md) |
| **ABI consumer** | [Syscall ABI](specifications/Syscall-ABI.md) |
| **Contributor** | [Coding Standards](tooling/Coding-Standards.md) -> [Anti-Bloat Guidelines](tooling/Anti-Bloat-Guidelines.md) -> [Git Workflow](tooling/Git-Workflow.md) -> [Contributing](advanced/Contributing.md) |

## Wiki Navigation

`wiki/_Sidebar.md` is the canonical table of contents for every wiki page and
category.

- [Browse the full sidebar](./_Sidebar.md)
- [Syscall ABI reference](specifications/Syscall-ABI.md)
- [Roadmap](reference/Roadmap.md)
- [Design decisions log](reference/Design-Decisions.md)
- [Project history](getting-started/History.md)

## Live Verification (current state)

The kernel boots end-to-end on QEMU `-vga virtio` and exercises every landed
subsystem on its way to the desktop. Headline capabilities:

- **PE / Win32**: Real-world MSVC PEs (e.g. `windows-kill.exe`, ~80 KB,
  52 imports across 6 DLLs, SEH + TLS + resources) load and exit cleanly.
- **Win32 windowing**: `windowed_hello` paints with GDI primitives, dispatches
  `WM_PAINT` / `WM_TIMER` through a user-registered WndProc, exits cleanly.
- **Storage / FS**: NVMe + GPT + FAT32 + ext4 read paths.
- **Net**: e1000 wired NIC + USB CDC-ECM + USB RNDIS reach Google over real DNS + TCP.
- **Render**: virtio-gpu 2D scanout cycle as the kernel framebuffer.
- **Security**: SMEP / SMAP / NX / W^X / KASLR / CFI all on.

See [Getting Started](getting-started/Getting-Started.md) for build + run
instructions and [History](getting-started/History.md) for how the system
arrived at its current shape.

## Code Quality

DuetOS enforces code quality at the repo level:

- **clang-format** enforced in CI on every PR (Allman braces, 120-col, 4-space
  indent — see `.clang-format`)
- **clang-tidy** static analysis (see `.clang-tidy`)
- **Sanitizers**: KASAN-equivalent for kernel, ASan/UBSan/LSan for hosted tests
- **Boot smoke** test gate via `tools/test/ctest-boot-smoke.sh`

See [Contributing](advanced/Contributing.md) for the full pre-commit checklist
and [Coding Standards](tooling/Coding-Standards.md) for the conventions every
file must satisfy.

## License

DuetOS is licensed under the terms in [`LICENSE`](../LICENSE).

## Project Statistics

<!-- AUTO:stats -->
| Metric | Count |
|--------|-------|
| Header files | 425 |
| Source files | 777 |
| Syscalls (numbered) | 168 |
| Capability bits | 13 |
| Kernel drivers | 12 |
| Userland DLLs | 59 |
| DLL exports (approx) | 0 |
| Test files | 19 |
| STUB markers | 33 |
| GAP markers | 66 |
| Wiki pages | 111 |
| *Last synced* | *2026-05-18 12:25* |
<!-- /AUTO:stats -->

_Run `docs/sync-wiki.sh sync` to refresh this block from the live tree._
