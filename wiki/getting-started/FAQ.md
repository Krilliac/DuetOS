# Frequently Asked Questions

> **Audience:** Newcomers, evaluators, the curious
>
> **Execution context:** N/A
>
> **Maturity:** Active

## Project Identity

### Is this a Linux distribution?

No. There is no Linux kernel anywhere in this tree. The kernel under
`kernel/` is written from scratch and booted directly by GRUB/UEFI into
long mode; nothing else runs below it. `kernel/subsystems/linux/` is a
**guest ABI translator** — the same shape as `kernel/subsystems/win32/`,
a second entry ABI into our kernel so a Linux ELF binary can call
`syscall` and hit a DuetOS syscall via the translation unit.

### Is this Wine?

No. Wine is useful prior art and is studied as a reference, but we do
not vendor it or link against it. The Win32 user-mode DLLs in
`userland/libs/` (44 production DLLs, ~1100 exports) are
reimplementations.

### Is this ReactOS?

No. ReactOS is useful for understanding Win32 semantics; we do not fork
it. DuetOS is a from-scratch kernel with a direct PE-loader path into
ring 3.

### Is this a research microkernel?

No. Pragmatism over academic purity. The kernel is hybrid:
microkernel-style IPC shape, monolithic-style in-kernel drivers for hot
paths.

### What does "natively" mean for PE executables?

It means the PE binary's bytes — as shipped, MSVC-built, with all the
SEH / TLS / resource baggage of a real Windows executable — are mapped
into a fresh address space, relocated, IAT-patched against preloaded
DuetOS userland DLLs, and entered at its `AddressOfEntryPoint`. The
binary then makes Win32 calls into our DLLs which marshal to `int 0x80`
and trap into our kernel. No VM, no emulator, no host OS underneath.

## Build & Run

### What compiler do I need?

Clang 18+, used as both the freestanding kernel compiler and the
host cross-compiler for the userland Windows PE toolchain.

### Why isn't the build system building?

If you see "command not found" for `qemu-system-x86_64`, `grub-mkrescue`,
`xorriso`, `mtools`, or `ovmf` — those aren't pre-installed on the dev
host. Install them only when a task legitimately requires a live-boot
smoke test (see CLAUDE.md "Live-test runtime tooling — install on
demand"). Pure refactors and docs changes can stop at compile-clean.

### Can I run DuetOS on real hardware?

x86_64 + UEFI is the target. The build produces a hybrid ISO that
boots both SeaBIOS (legacy CSM) and UEFI (OVMF in QEMU; firmware on
real hardware). See [QEMU Smoke Tests](../tooling/QEMU-Smoke.md). Bare
metal validation cadence is informal — most live testing happens in
QEMU + OVMF.

### What about ARM64?

Planned, not started. The kernel is structured to make ARM64 a second
tier — `kernel/arch/x86_64/` is the only arch directory today.

## Architecture

### Why one kernel with two ABI faces?

Because shipping two parallel TCP stacks, two VFSes, two compositors,
two registries is how OSes rot. DuetOS has **one** of each, reachable
from two ABI front-ends (native + Win32). See
[Architecture Overview](Architecture-Overview.md) and
[Subsystem Isolation](../kernel/Subsystem-Isolation.md).

### How does a Win32 program reach the network?

`PE.text: call [__imp_send]` ->
`ws2_32!send` (translator DLL in `userland/libs/ws2_32/`) ->
`SYS_SOCK_SEND` marshal -> `int 0x80` ->
kernel syscall dispatch -> kernel net stack -> e1000 TX ring ->
packet on wire. Same kernel send backend that native sockets use.

### Where do Win32 privileges (SeDebugPrivilege, ACLs, integrity levels) actually gate?

They don't. Those Win32 surfaces are facades that satisfy probes — the
real authorization is the kernel's `kCap*` capability set on the
`Process` struct. See [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
and [Capabilities](../security/Capabilities.md).

## Status

### What works today?

- Freestanding Win32 PEs (no CRT, direct `int 0x80`) — since Phase 1
- MSVC console PEs with CRT, threads, mutexes, events, atomics, printf,
  file I/O, registry queries — current
- `windows-kill.exe` (a real shipped third-party Windows binary) —
  end-to-end on every boot
- Windowed Win32 PEs (`windowed_hello`) — end-to-end on every boot
- Live Internet (DNS + TCP to a real Internet host) — current

### What still doesn't work?

- Cross-process COM/RPC, monikers, structured storage, and full native file dialogs
- DirectX rendering beyond `Clear` + `Present` (D3D vtables exist but
  real `Draw*` returns `E_NOTIMPL`)
- Modal dialogs, menus, common controls, scroll bars, outline fonts,
  multi-threaded message queues
- Most of `winsock2`'s asynchronous surface (synchronous BSD-socket
  subset works)
- Arbitrary file writes through the FS write paths (read paths are live;
  write is the next FS slice)

See [History > Phase 6](History.md#phase-6--windowed-win32--live-network)
for the latest status and what each missing track requires.

## Related Pages

- [Architecture Overview](Architecture-Overview.md)
- [History](History.md)
- [Project Pillars](Project-Pillars.md)
- [Win32 PE Subsystem](../subsystems/Win32-PE-Subsystem.md)
