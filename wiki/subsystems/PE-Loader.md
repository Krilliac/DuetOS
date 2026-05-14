# PE Loader

> **Audience:** Kernel hackers, PE/Win32 devs, security folks
>
> **Execution context:** Kernel — process context during spawn
>
> **Maturity:** Stage 2 — real-world MSVC PEs load and run

## Overview

The PE loader takes a PE32+ image (validated DOS + NT headers, section
table, data directories) and produces a runnable user process. Stage 2
closed the gaps that prevented real third-party Windows binaries from
loading: forwarder chasing (name-form and ordinal-form), by-ordinal IAT
resolution, binary-search EAT lookup.

## Files

- `kernel/loader/pe_loader.cpp` — main load path
- `kernel/loader/pe_exports.cpp` — `IMAGE_EXPORT_DIRECTORY` parser,
  binary-search export lookup
- `kernel/loader/dll_loader.cpp` — DLL load + per-process DLL table
  (IAT walker + forwarder chase live in this TU and `pe_loader.cpp`)

## Load Sequence

1. **Validate**: DOS magic `MZ`, e_lfanew bounds, NT magic `PE\0\0`,
   PE32+ optional-header size, machine = `0x8664`.
2. **`PeReport`**: walks every data directory, prints section table,
   lists every imported DLL and function, counts base-relocation
   blocks, counts TLS callbacks. Run for *every* spawn including ones
   that will be rejected — this is the diagnostic that drove the
   loader's evolution.
3. **Address space**: allocate `mm::AddressSpace`, mirror kernel half.
4. **Preload set**: register every userland DLL into the per-process
   DLL table (`Process::dll_images[]`). 38 DLLs preloaded out of the
   44 production DLLs in `userland/libs/` (the rest load on demand);
   ~1100 exports total. Per-DLL status lives in
   [`Win32-Surface-Status`](../reference/Win32-Surface-Status.md).
5. **Map sections**: each PE section mapped at `ImageBase + VA` with
   flags from `Characteristics` (`MEM_EXECUTE`, `MEM_WRITE`,
   `MEM_READ`). W^X is enforced — a section requesting both write +
   execute is rejected at map time.
6. **Apply relocations**: DIR64-style base relocations (only `IMAGE_REL_BASED_DIR64`
   is honoured; others are inert in PE32+).
7. **Walk imports**: for each `(dll_name, func_name | ordinal)`:
   - Look up `dll_name` in the per-process DLL table.
   - Resolve the export by name (binary search) or by ordinal
     (direct EAT index).
   - **If the export is a forwarder** (`Dll.Func` or `Dll.#N`),
     recurse through the per-process DLL table. Bounded depth.
   - Patch the IAT slot with the absolute VA of the resolved entry.
8. **Bootstrap heap + main thread**.
9. **Entry**: schedule first user task at
   `ImageBase + AddressOfEntryPoint`.

## Forwarder Chasing

A forwarder export looks like `kernel32.GetProcAddress` or
`kernelbase.#0042`. The IAT-patch step resolves it recursively against
the preloaded set. Both name-form and ordinal-form are supported.
Bounded depth prevents pathological loops.

This was a stage-2 closer — without it, `kernelbase` (44 forwarders to
`kernel32`) couldn't be mapped.

## By-ordinal IAT Resolution

PE imports can reference an export by ordinal rather than name:
`IMAGE_IMPORT_BY_NAME` vs `IMAGE_ORDINAL_FLAG`. The loader handles
both — by-ordinal lookups index directly into the preloaded EAT.

Stage 2 closer; before this, MSVC binaries that import by ordinal
would fail at the IAT-patch step.

## EAT Binary Search

`PeExportLookupName` is binary-search (the EAT's name-pointer table is
sorted lexicographically). For DLLs with hundreds of exports
(`kernel32` has 155, `ntdll` has 114) this matters at spawn time.

## Stub Markers

Anywhere the loader takes a "good enough for v0" shortcut is marked
with `// STUB:` or `// GAP:`. See
[Logging and Tracing](../kernel/Logging-And-Tracing.md) for the
convention.

## Known Limits / GAPs

- **No SEH unwinding by the loader**. SEH tables are mapped (so the
  `__C_specific_handler` finds them) but DuetOS does not unwind on
  exception — exceptions inside a PE produce a process kill.
- **TLS image-level callbacks**: a non-empty `IMAGE_DIRECTORY_ENTRY_TLS`
  callback array causes the PE load to fail with
  `TlsCallbacksUnsupported` (`pe_loader.cpp:1805`). Empty callback
  arrays — common because the MSVC CRT reserves the directory
  unconditionally — are accepted. A future slice will inject a
  per-process x64 thunk that walks the array with
  `(rcx=image_base, rdx=DLL_PROCESS_ATTACH, r8=nullptr)` before
  jumping to the real entry. Per-thread TLS init via the CRT works.
- **No PE delay-load** (`__delayLoadHelper2`). Anything imported by
  delay-load is treated as eager-import.
- **Bound imports**: the `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` directory
  is silently ignored. Bound imports are an optimisation that
  embeds resolved addresses for a specific DLL build; safe to skip
  because the eager-import walk re-resolves them, but the loader
  does not validate that the bound timestamps still match.
- **Subsystem field**: the optional header `Subsystem` field
  (`IMAGE_SUBSYSTEM_WINDOWS_GUI` / `_CUI` / `_NATIVE`) is not
  inspected. Both GUI and console binaries are loaded identically;
  `user32`/`kernel32` thunks decide their own behaviour. Native
  subsystem PEs (`smss.exe`-class) are out of scope for v0.
- **`IMAGE_DLLCHARACTERISTICS_NX_COMPAT` bit**: not consulted —
  W^X is enforced unconditionally for every PE regardless of the
  bit. This is stricter than Windows; PEs that incorrectly omit
  the bit still get NX. Recorded for the audit trail, not as a
  fix target.
- **CFG (Control Flow Guard)**: `__security_cookie` is seeded
  (`SeedSecurityCookie` at `pe_loader.cpp:773`) but the
  `GuardCFFunctionTable` is not loaded — indirect calls land
  without CFG validation.
- **Resource section**: mapped read-only but not interpreted — the
  resource APIs (`FindResource`, `LoadIcon`, etc.) walk the section
  themselves.
- **PEB / PEB_LDR_DATA**: the loader populates a minimal v0
  scaffolding inside the TEB page (`pe_loader.cpp` step 4b for
  PE32+) — `gs:[0x60]` -> PEB at TEB+0x100, `PEB.Ldr` at
  PEB+0x20 -> PEB_LDR_DATA at TEB+0x200 with `Length=0x58`,
  `Initialized=1`, and three circular-empty
  `LIST_ENTRY` heads. This is what every loader-walking
  helper stamped by MSVC actually reads (the Unity launcher's
  `mov gs:0x60, %rax; mov 0x20(%rax), %rcx; cmp ebx, 0x8(%rcx)`
  pattern faulted at cr2=0x20 / 0x08 before this landed).
  Real `ImageBaseAddress`, `ProcessParameters`, and the loaded-
  module list itself are NOT populated — anything that iterates
  the list immediately wraps back to the head, the documented
  "no DLLs loaded" state. Adding a non-empty module list is a
  follow-on when a PE that needs `GetModuleHandle` walks for
  itself surfaces.

See [History](../getting-started/History.md) Phases 4-6 for the loader's
evolution.

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md)
- [Win32 DLLs](Win32-DLLs.md)
- [Memory Management](../kernel/Memory-Management.md) — `AddressSpace`
- [Process Model](../kernel/Process-Model.md)
- [W^X / NX Enforcement](../security/WX-Enforcement.md)
