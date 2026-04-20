# CustomOS

A general-purpose operating system, written from scratch, with two defining goals:

1. **Run Windows PE executables natively.** A first-class Win32 / NT subsystem — not a VM, not an emulator bolted onto another host OS. The PE loader, NT syscall surface, and user-mode `ntdll` / `kernel32` / `user32` / `gdi32` / `d3d*` live in this repo, co-equal with the native ABI.
2. **Run on typical commodity PC hardware.** x86_64 from day one (Intel and AMD), with first-party GPU drivers for Intel iGPU, AMD Radeon, and NVIDIA GeForce. ARM64 is a planned second tier.

CustomOS is greenfield. There is no legacy to work around yet — which means the quality of decisions made now compounds.

---

## Status

Early bootstrapping. The repo currently holds:

- `CLAUDE.md` — the authoritative project context for AI-assisted development.
- `AGENTS.md` — one-page session bootstrap for agents.
- `.claude/` — persistent knowledge base (read `.claude/index.md` first).
- Coding-style dotfiles (`.clang-format`, `.clang-tidy`, `.editorconfig`).

No kernel source yet. That starts once the boot and toolchain plan settles.

---

## Project pillars

| Pillar | Stance |
|--------|--------|
| **Kernel** | Hybrid — microkernel-style IPC, monolithic-style in-kernel drivers for hot paths. Preemptive, SMP-aware, per-CPU runqueues. |
| **Boot** | UEFI-first (x86_64). No MBR-only paths in new work. |
| **Memory** | 4-level paging, NX, SMEP/SMAP, KASLR, per-process address spaces. Slab + buddy allocator hybrid. |
| **Executables** | Native ELF-like format *and* full PE/COFF. The PE subsystem is a peer, not a shim. |
| **Win32 subsystem** | NT syscall layer in the kernel + reimplemented user-mode DLLs. Not a Wine fork. |
| **Graphics** | First-party kernel drivers for Intel / AMD / NVIDIA. Vulkan is the primary user-mode API. D3D11/D3D12 translate onto it. |
| **Drivers** | PCIe, NVMe, AHCI, xHCI/USB, Intel HDA, e1000 / rtl8169. |
| **Security** | W^X, ASLR, stack canaries, CFI. No setuid; capability-based IPC. |

See `CLAUDE.md` for the full architectural statement, non-goals, and the planned directory layout.

---

## Non-goals

- Not a Linux distribution. No Linux kernel, no GNU userland base.
- Not a Wine fork. Wine is useful prior art; we write our own.
- Not a ReactOS rewrite. ReactOS is a reference, not a base.
- Not a research microkernel. Pragmatism over academic purity.

---

## Repository layout (planned)

```
boot/          UEFI loader, boot protocol
kernel/        arch/, core/, mm/, sched/, fs/, net/, sync/, time/, ipc/, syscall/
drivers/       pci/, storage/, usb/, net/, gpu/, audio/, input/
subsystems/    win32/ (loader, ntdll, kernel32, user32, gdi32, d3d*, dxgi, winmm)
               graphics/ (compositor, WM, Vulkan ICD)
               audio/
               posix/     (later)
userland/      libc/, init/, shell/, tools/, apps/
tools/         build/, qemu/, test/
tests/         hosted unit tests + on-target kernel self-tests
docs/          architecture, ABI, design notes
third_party/   vendored deps (compiler-rt fragments, etc.)
.claude/       persistent AI context (read index.md first)
```

Directories appear as the work does. Do not create a directory until the first file legitimately belongs in it.

---

## Contributing

The active development branch for Claude-driven bootstrapping work is
`claude/port-sparkengine-components-f38iH`. All commits for that work land there
until the base repo layout is settled.

Before writing code, read:

- `CLAUDE.md` — project rules, anti-bloat guidelines, coding standards, the full pre-commit checklist.
- `.claude/index.md` — persistent knowledge base, session-start workflow.

Everything else flows from those two files.
