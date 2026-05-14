# Win32 PE Subsystem

> **Audience:** PE/Win32 devs, kernel hackers
>
> **Execution context:** Userland (PE process) -> int 0x80 -> kernel
>
> **Maturity:** Real third-party MSVC PEs run end-to-end

## Overview

DuetOS executes Windows PE binaries as a **first-class native ABI**.
The bytes of an MSVC-built `.exe` are mapped into a fresh address
space, relocated, IAT-patched against preloaded DuetOS userland DLLs,
and entered at the PE `EntryPoint`. The PE issues calls to the Win32
DLLs which marshal to `int 0x80` and trap into the kernel. No VM, no
emulator, no host OS underneath.

## The Layering

```
Windows PE applications
        |  imports
Win32 translator DLLs       userland/libs/   (44 production DLLs, ~1100 exports)
        |  int 0x80
Native DuetOS kernel
        |
Kernel-mode drivers (PCIe, NVMe, AHCI, USB, NIC, GPU, audio, input)
```

The Win32 DLLs are **translators**, not parallel subsystems. There is
one TCP stack in the kernel, one compositor, one VFS, one registry —
each reachable from two entry ABIs (native + Win32). See
[Subsystem Isolation](../kernel/Subsystem-Isolation.md).

## Live Verification

The serial log on every boot includes:

```
Windows Kill 1.1.4 | Windows Kill Library 3.1.3
Not enough argument. Use -h for help.
```

That is `windows-kill.exe` — a real third-party 80 KB MSVC PE with 52
imports across 6 DLLs (SEH + TLS + resources) — printing through our
PE loader, our 44 production userland DLLs (38 preloaded), our
scheduler, and our syscalls.

## End-to-end Call Flow Example: `ws2_32!send`

```
PE .text:  call [__imp_send]
   -> ws2_32!send                     (translator DLL: userland/libs/ws2_32/)
   -> Win32 calling convention -> SYS_SOCK_SEND marshal
   -> int 0x80
   -> kernel syscall dispatch          kernel/syscall/syscall.cpp
   -> net stack send path              kernel/net/
   -> e1000 TX ring programming        kernel/drivers/net/e1000/
   -> packet on wire
```

The same kernel send backend is used by native sockets and Win32
sockets.

## Components

| Layer | Path | Notes |
|-------|------|-------|
| PE loader (stage 1+2) | `kernel/loader/pe_loader.cpp` | DOS + NT + PE32+ headers, sections, DIR64 reloc, IAT walk |
| EAT parser | `kernel/loader/pe_exports.cpp` | `IMAGE_EXPORT_DIRECTORY`, binary-search lookup |
| DLL loader | `kernel/loader/dll_loader.cpp` | Maps a DLL into a process, applies relocs, parses EAT |
| Win32 syscall handlers | `kernel/subsystems/win32/` | `SYS_WIN_*`, `SYS_GDI_*`, `SYS_FILE_*`, `SYS_HEAP_*` etc. |
| Translator DLLs | `userland/libs/{kernel32,ntdll,user32,gdi32,...}` | 44 production DLLs, ~1100 exports |
| Flat-stubs page (legacy) | `kernel/subsystems/win32/` | Fallback for anything not yet ported to a real DLL |

## Per-process Bringup

When a PE spawns:

1. PE bytes validated; `PeReport` summarises every directory.
2. New `mm::AddressSpace` allocated.
3. **Preload set of 38 userland DLLs** (out of 44 production DLLs in
   `userland/libs/`) mapped into the new AS. The remaining DLLs load
   on demand via `LoadLibraryA/W` -> `DllLoad`.
4. PE sections mapped with characteristic-driven flags (W^X enforced).
5. DIR64 base relocations applied.
6. Imports walked: each `(dll, name)` resolved against the preloaded
   set's EATs, IAT slots patched. Forwarders chase recursively
   (name-form + ordinal-form `Dll.#N`). By-ordinal IAT entries
   resolve against preloaded EATs.
7. Process + thread state created, heap bootstrapped.
8. First user thread enters at `ImageBase + AddressOfEntryPoint`.

Per-process cost: ~96 frames for the preloaded DLL set.

## What Works Today

- **Freestanding Win32 PEs** (no CRT, direct `int 0x80`) — since
  Phase 1.
- **MSVC console PEs with CRT**: threads, mutexes, events, atomics,
  printf, file I/O, registry queries — since Phase 4 / 5.
- **`windows-kill.exe`** (real shipped third-party Windows binary) —
  since the end of Phase 3.
- **`unity_engine.exe`** (real Unity 2022 LTS standalone launcher,
  vendored from NSMB-MarioVsLuigi v2.1.1.0). 72 imports across
  KERNEL32.dll + UnityPlayer.dll resolve cleanly; CRT bootstrap
  walks PEB + PEB_LDR_DATA (set up by the PE loader's TEB
  scaffolding); `UnityMain2` returns through the catch-all NO-OP;
  process exits with `rc=0`. The boot transcript carries a
  `[ring3] pe spawn name="ring3-unity"` line followed by
  `[I] sys : exit rc val=0x0 (0)` and `[proc] destroy
  ring3-unity` — no #PF, no task-kill. See
  [`userland/apps/unity_engine/README.md`](../../userland/apps/unity_engine/README.md)
  for the per-import inventory and the three loader fixes that
  unlocked it.
- **Windowed Win32 PEs** (`windowed_hello`) — Phase 6, end-to-end on
  every boot.
- **Live Internet** (DNS + TCP to a real Internet host) — Phase 6.

See [History](../getting-started/History.md) for the full evolution.

## What Doesn't Work (Yet)

- **COM apartments**, real `CoInitialize` / `CoCreateInstance`.
- **DirectX rendering** beyond Clear + Present (`Draw*` returns
  `E_NOTIMPL`).
- **Modal dialogs, menus, common controls, scroll bars, outline
  fonts, multi-threaded message queues**.
- **Most of `winsock2`'s asynchronous surface** (synchronous BSD
  socket subset works).
- **Arbitrary file writes** through the FS write paths.

## Related Pages

- [PE Loader](PE-Loader.md)
- [Win32 DLLs](Win32-DLLs.md)
- [DirectX v0 Path](DirectX.md)
- [Compositor and Window Manager](Compositor.md)
- [Linux ABI](Linux-ABI.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Win32 Thunks Compat Note](../advanced/Win32-Thunks-Compat-Note.md)
