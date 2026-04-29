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
   DLL table (`Process::dll_images[]`). 29 DLLs at present, ~760
   exports total.
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
- **TLS callbacks**: dispatched only at thread create. Per-thread TLS
  init by the CRT works; image-level callbacks for module load are
  fired on first map only.
- **No PE delay-load** (`__delayLoadHelper2`). Anything imported by
  delay-load is treated as eager-import.
- **Resource section**: mapped read-only but not interpreted — the
  resource APIs (`FindResource`, `LoadIcon`, etc.) walk the section
  themselves.

See [History](../getting-started/History.md) Phases 4-6 for the loader's
evolution.

## Related Pages

- [Win32 PE Subsystem](Win32-PE-Subsystem.md)
- [Win32 DLLs](Win32-DLLs.md)
- [Memory Management](../kernel/Memory-Management.md) — `AddressSpace`
- [Process Model](../kernel/Process-Model.md)
- [W^X / NX Enforcement](../security/WX-Enforcement.md)
