# Win32 / NT Subsystem — Architectural Decisions

**Last updated:** 2026-04-20
**Type:** Decision
**Status:** Active

## Description

Running Windows PE executables natively is one of CustomOS's two defining goals. This entry records the **high-level architectural decisions** about how the Win32/NT subsystem fits into the OS. Implementation details belong in headers and per-subsystem READMEs once they exist — this entry is the contract everything else has to honor.

## Context

Applies to everything under `subsystems/win32/` (planned), the PE/COFF loader, the NT syscall layer, and any driver surface (GDI, DirectX) that Windows binaries expect. Also constrains how the **native** CustomOS ABI evolves — the two must stay peers, not one layered on top of the other.

---

## Details

### Decision 1 — The Win32 subsystem is a peer, not a shim

The NT syscall interface is implemented **directly in the kernel**, alongside the native CustomOS syscall interface. Both dispatch tables live in `kernel/syscall/` and both are first-class.

Rationale:
- A shim-over-native design (the "Wine model" of translating every Win32 call into host calls) is slower and leaks semantics that are hard to match without kernel cooperation (reparse points, async I/O, APCs, structured exceptions).
- Kernel-level implementation lets us honor NT semantics exactly where they matter most — object handles, wait semantics, I/O completion ports, thread suspension/resume — instead of approximating them in user space.

Constraint: the native CustomOS syscall ABI must not be defined in a way that prevents the NT ABI from being peer-equal. No accidental "the real ABI is ours and Win32 is second-class."

### Decision 2 — User-mode Windows DLLs are reimplementations, not imports

`ntdll.dll`, `kernel32.dll`, `user32.dll`, `gdi32.dll`, `dxgi.dll`, `d3d11.dll`, `d3d12.dll`, `winmm.dll`, `xaudio2*.dll` are **reimplemented in this repo** under `subsystems/win32/<dll>/`.

Rationale:
- Binary compatibility with real Windows DLLs is not achievable and not the goal — we want *executable compatibility* (run the `.exe`), not *DLL compatibility* (run the shipping `kernel32.dll`).
- Reimplementing lets us own the bug budget. No "just upgrade Wine" moments when a Windows update regresses something.
- Wine and ReactOS are valuable **prior art and reference** for NT semantics. We read their source, we do not link against them or fork them.

### Decision 3 — PE loader lives in the kernel

The PE/COFF loader (parsing headers, mapping sections, applying relocations, resolving imports, running TLS callbacks, setting up SEH records) lives in `kernel/` (or a kernel-callable helper in `subsystems/win32/loader/`).

Rationale:
- The loader must run before `ntdll` is mapped in (import resolution chains through it).
- Some sections need kernel-level primitives (image-backed VMAs, copy-on-write for writable sections, SEH unwind metadata).
- It doubles as the native loader for our own ELF-like format — shared code path, specialized parsers per format.

### Decision 4 — DirectX rides on Vulkan

`d3d11.dll` and `d3d12.dll` translate to Vulkan (via a first-party translation layer, **not** DXVK / VKD3D as dependencies). DXGI presents through the native compositor.

Rationale:
- Maintaining two real driver stacks (a D3D one and a Vulkan one) per GPU vendor is untenable for a small team.
- Vulkan is our primary user-mode graphics API for native apps anyway — translating D3D onto it gives us one driver path to maintain per vendor instead of two.
- Studying DXVK / VKD3D as prior art is explicitly encouraged. Taking a dependency on them is not.

### Decision 5 — No setuid, capability-based IPC

The NT handle model (explicitly-granted, revocable, duplicatable) maps cleanly onto a capability-based IPC system. We lean into that rather than emulating Unix-style ambient authority.

Rationale:
- NT's handle model is more amenable to modern sandboxing than POSIX's. Embracing it for **both** the Win32 and native ABIs removes an entire class of privilege-escalation bugs.
- POSIX compatibility (if we add it, later, under `subsystems/posix/`) will layer on top of capabilities, not replace them.

### Decision 6 — Compatibility is measured in "does the .exe run," not percentages

We don't ship a "97% compatible" marketing number. A binary either runs end-to-end on CustomOS or it doesn't. The test suite is a set of real applications (a game, a compiler, a shell, a well-known benchmark) with pass/fail per binary.

Rationale:
- Partial compatibility numbers drive effort toward "pad the metric," not "fix the next real user-visible bug."
- A focused list of "must run" applications gives every subsystem a concrete forcing function.

### Decision 7 — Win32 subsystem processes run in the target process's address space

All Win32 user-mode code (`ntdll`, `kernel32`, `user32`, etc.) runs in the **target process's** address space, not in a separate Win32 server process.

Rationale:
- Crosses a kernel boundary only where the NT semantics demand it (real syscalls, object manager operations).
- Avoids a per-call RPC tax that would kill performance for GDI/USER32-heavy workloads.
- Shared state between processes goes through explicit IPC ports, not shared-memory hacks.

---

## Non-goals (call these out explicitly)

- **Not a Wine fork.** Wine is prior art. We do not vendor it, link against it, or track its releases.
- **Not a ReactOS rewrite.** ReactOS is a reference for NT semantics. We do not fork it.
- **Not a Linux compatibility layer.** POSIX support, if added, is a separate subsystem with its own plan.
- **No guarantee of driver compatibility.** A Windows `.sys` driver will not run on CustomOS. Hardware support comes from our own kernel drivers.
- **No Windows Store / UWP / WinRT support in v1.** Classic Win32 first, everything else later (if at all).

---

## Implications for other subsystems

| Area | Implication |
|------|-------------|
| Scheduler | Must support NT thread semantics — priority boosts on I/O completion, suspend/resume counts, APCs. |
| Memory manager | Must support image-backed VMAs with copy-on-write on writable sections (PE characteristic bits). |
| VFS | Must support NT path semantics (`\Device\HarddiskVolume1\…`), case-insensitive matching, 8.3 aliases where needed. |
| IPC | Must support NT object handles with access masks and duplication — not just a Unix-style file descriptor table. |
| Graphics | Compositor must understand DXGI swap chains, HWND-equivalent surfaces, multi-monitor `MONITORINFO`. |
| Security | No setuid; capabilities are the default; Win32 `AccessCheck()` resolves against the same capability set. |

---

## Notes

- This entry is a **decision**, not a tutorial. When a subsystem question comes up ("should this call go through NT or through our native ABI?"), re-read the decisions above.
- Update this entry when a decision is revised. Do **not** silently diverge in code — if code contradicts a decision here, either the code is wrong or the decision should be revised (and this entry updated).
- **See also:** [hardware-target-matrix.md](hardware-target-matrix.md) for the GPU/CPU tiers the Win32 subsystem can assume.
