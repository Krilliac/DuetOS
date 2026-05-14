# unity_engine.exe — real-world Unity-built PE test vector

`unity_engine.exe` is a verbatim copy of `NSMB-MarioVsLuigi.exe`
(MIT-licensed) from the v2.1.1.0 Windows-64 release of
[NSMB-MarioVsLuigi](https://github.com/ipodtouch0218/NSMB-MarioVsLuigi),
which is built with the Unity 2022 LTS standalone-player toolchain.

It is vendored as a **measurement vector for the PE loader's
import-resolution path against the canonical Unity engine launcher
pattern**, in the same vein as
[`windows_kill/windows-kill.exe`](../windows_kill/README.md) is
vendored for the `PeReport` diagnostic path.

## What it exercises

Every Unity-built Windows standalone ships a tiny launcher .exe
(usually a few hundred KB) whose only real job is to load
`UnityPlayer.dll` and hand control to `UnityMain2`. The launcher
itself is the smallest representation of "running Unity" we can
embed without dragging in the 35 MB `UnityPlayer.dll`, the 8 MB
Mono runtime, the managed assemblies, and the `_Data` asset
folder.

Two import DLLs, ~72 imports total:

- `UnityPlayer.dll!UnityMain2` — single import. **Cannot resolve**
  on DuetOS — UnityPlayer.dll itself isn't present and there is
  no plausible "v0 Unity engine" we can substitute. Falls through
  to the catch-all NO-OP thunk: the IAT slot gets pointed at a
  miss-logger thunk that records the call and returns 0. The
  Unity launcher CRT then calls into it, prints nothing, and
  exits.
- `KERNEL32.dll` — ~71 imports. The usual VC++ runtime bootstrap:
  `Tls*`, `LoadLibraryExW`, `GetProcAddress`, `Heap*`,
  critical-section / SList primitives, exception-unwind plumbing
  (`RtlCaptureContext`, `RtlLookupFunctionEntry`,
  `RtlVirtualUnwind`, `RtlPcToFileHeader`), `Get*Time*`,
  `WriteConsoleW`, `WriteFile`, `IsProcessorFeaturePresent`. Most
  of these are already real or noop-pinned in
  `kernel/subsystems/win32/` and `userland/libs/kernel32/`. The
  ones that aren't will show up as `[pe-resolve] unknown import
  -> catch-all NO-OP` lines in the boot transcript — that's the
  gap inventory this fixture produces.

## Expected boot signature (as of the slice that vendored this fixture)

The kernel's `SpawnPeFile` runs `PeReport` (logging the import
inventory), `PeLoad` (which maps sections, applies relocations,
resolves imports through the catch-all), then jumps to the entry
point. The launcher's CRT does its initial bootstrap (including
the PEB / PEB_LDR_DATA walk), calls `UnityMain2` — a NO-OP thunk —
and exits cleanly via `ExitProcess(0)`. The serial transcript
contains, in order:

    [ring3] pe spawn name="ring3-unity" pid=... entry=... image_base=...
    [pe-resolve] unresolved import UnityPlayer.dll!UnityMain2 -> catch-all NO-OP
    [pe-resolve] ... (~71 KERNEL32 lines; most via-DLL or via-thunk-table hits)
    [pe-resolve] total imports resolved val=0x48 (72)
    [t=...] win32/tls : DoTlsAlloc: granted slot val=0x0
    [t=...] win32/tls : DoTlsAlloc: granted slot val=0x1
    [win32-miss] slot=... called fn="<unmapped>"   (= UnityMain2 NO-OP)
    [I] sys : exit rc val=0x0 (0)
    [proc] destroy ring3-unity

The clean exit is the deliverable: the launcher's CRT bootstrap
walked far enough to discover an empty loader-data list (set up
by the PE loader's TEB / PEB / PEB_LDR_DATA scaffolding), call
into the Unity main entry, take the NO-OP return path, and exit
through ExitProcess(0). No #PF, no task-kill, no minidump.

History of the failures fixed to reach this state:

1. **cr2=0x20 / rip=image_base+0x7a6d** — `RtlPcToFileHeader`
   resolved through the catch-all that leaves `*BaseOfImage`
   uninitialised. Fixed by pinning the import to
   `kOffPcToFileHeaderNull` which writes `*BaseOfImage = NULL`
   before returning 0 (see `subsystems/win32/thunks.cpp`).
2. **cr2=0x20 / rip=image_base+0x7a6d (re-occurrence)** — the
   MSVC CRT bootstrap reads `gs:[0x60]` for the PEB pointer,
   which was left zero in the 64-bit TEB-setup path. Fixed by
   writing the PEB VA at TEB offset 0x60 (see `loader/pe_loader.cpp`).
3. **cr2=0x08 / rip=image_base+0x7a71** — once the PEB pointer
   was non-NULL, the next instruction reads `PEB.Ldr` and
   dereferences it. Fixed by laying out a minimal
   `PEB_LDR_DATA` (Length=0x58, Initialized=1, three
   circular-empty LIST_ENTRY heads) inside the TEB page at
   offset 0x200, and pointing `PEB.Ldr` at it.

## Provenance

Downloaded once from the project's GitHub release page:

    https://github.com/ipodtouch0218/NSMB-MarioVsLuigi/releases/download/v2.1.1.0/MarioVsLuigi-Win64-v2.1.1.0.zip

Repackaged: only the launcher `.exe` is kept here. The 35 MB
`UnityPlayer.dll`, the 8 MB Mono runtime, the D3D12 redistributable,
and the managed-assembly folder are not vendored — they would
balloon the kernel ELF by ~95 MB without changing what the
loader's import path measures.

Size: 667 648 bytes.
SHA-256: `d5e3d7b99e5765cece99d5aa049ed70cddf48381a5f1ad84d375a5851831c56c`.

## Why this file, specifically?

The user's prompt: "download unity engine (slim as possible since
it's large) and try to run the exe. Fix failures/issues till it'll
run." This is the slimmest real Unity engine artifact that:

1. Is an actual Unity-2022-LTS-built standalone (the toolchain
   stamps the canonical CRT bootstrap + the
   `UnityPlayer.dll!UnityMain2` import — that's what makes it
   "Unity" at the binary level).
2. Has a non-trivial import surface (~72 imports across two
   DLLs) so the catch-all NO-OP resolver and the Win32 thunks
   table both get real exercise.
3. Has an open-source upstream license (MIT) that allows
   verbatim redistribution as a test vector.
4. Fits inside the kernel ELF (~650 KB) without ballooning it.

`UnityCrashHandler64.exe` from the same archive is the obvious
fallback (Unity-built, 1.5 MB, more diverse imports — user32,
shell32, dbghelp, bcrypt, wininet, gdi32, advapi32, ole32). If
this launcher fixture proves out, the crash handler is the
natural next-larger-bite to vendor for a second-tier
measurement.

## Not for execution as a real game

This file is loaded by the PE loader, its imports are resolved
through the catch-all stub forest, and its entry point is jumped
to. It will NOT render Mario vs. Luigi, will NOT initialise a
Unity scene, will NOT contact Photon, will NOT do anything a real
Unity game does — there is no `UnityPlayer.dll`, no D3D11 device,
no Mono runtime, no asset folder. The PE process load itself IS
the contribution.

Treat the serial transcript as the deliverable; don't read game
behaviour into a launcher with all-NO-OP `UnityMain2`.
