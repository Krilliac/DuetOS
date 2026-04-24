# PE EAT parser + DLL loader — stage 2 kickoff

**Type:** Observation · **Status:** Active (stage-2 slices 1 + 2 landed) · **Last updated:** 2026-04-24

## Context

Stage 1 of the Win32 subsystem (see
[`pe-subsystem-v0.md`](pe-subsystem-v0.md) and
[`win32-subsystem-v0.md`](win32-subsystem-v0.md)) ran PE
executables by mapping a single kernel-hosted stubs page per
process and patching the IAT directly from a flat
`{dll, func} -> offset` table in `kernel/subsystems/win32/stubs.cpp`.
That design has ~122 Win32 functions resolved across 14 DLL
names and carried us through real-world PEs like
`windows-kill.exe`. It stops cold the moment a PE calls
`LoadLibraryW` / `GetProcAddress` to resolve something dynamically:
we have no DLL to walk, no EAT to index into.

Stage 2 is the path to real DLLs: load an on-disk DLL's bytes
into the process's address space, parse its Export Directory,
and let `GetProcAddress` become a real index operation instead
of a static table lookup.

This entry documents the **first slice of stage 2**: the EAT
parser and DLL-loader skeleton. No existing call sites change
behavior — this is pure new surface that later slices will wire
into `GetProcAddress` and eventually into the import resolver.

## What landed

Three new translation units:

| File | Role |
|------|------|
| `kernel/core/pe_exports.h` / `.cpp` | Standalone EAT parser. Given a PE file buffer, validates `IMAGE_EXPORT_DIRECTORY` and exposes name / ordinal lookup + forwarder detection. No allocations, no AS dependency. |
| `kernel/core/dll_loader.h` / `.cpp` | DLL-loader skeleton. `DllLoad(file, len, as, aslr_delta)` validates the DLL-kind bit, maps every section into `as`, applies base relocations, and parses the EAT. Returns a `DllImage` + parsed `PeExports`. |
| `kernel/core/pe_loader.cpp` | One-line extension: `PeReport` now calls `PeExportsReport` on every PE it scans so the boot log dumps the EAT whenever one is present. |

## EAT parser API (pe_exports.h)

```cpp
struct PeExports {
    const u8* file;      // borrowed
    u64 file_len;
    u32 base_ordinal;    // IMAGE_EXPORT_DIRECTORY.Base
    u32 num_funcs;       // EAT size
    u32 num_names;       // ENT/EOT size
    u64 funcs_file_off;  // file offset of EAT (u32[num_funcs])
    u64 names_file_off;  // file offset of ENT (u32[num_names])
    u64 ords_file_off;   // file offset of EOT (u16[num_names])
    u64 name_file_off;   // file offset of the DLL name string
    u32 export_dir_lo;   // RVA range that identifies a forwarder
    u32 export_dir_hi;
};

PeExportStatus PeParseExports(file, file_len, out);
bool PeExportAt(exp, idx, out);                  // iterate by EAT index
bool PeExportLookupOrdinal(exp, ordinal, out);   // absolute ordinal lookup
bool PeExportLookupName(exp, name, out);         // case-sensitive name lookup
const char* PeExportsDllName(exp);               // DLL's own name
void PeExportsReport(exp);                       // serial log dump
```

`PeExport` result carries `{name, ordinal, rva}` OR
`{is_forwarder=true, forwarder="Dll.Func"}`. Forwarder
detection uses the classic PE rule: a function-entry RVA that
lies within the Export Directory's RVA range is a forwarder
string, not a code entry point.

## DLL loader API (dll_loader.h)

```cpp
DllLoadResult DllLoad(file, file_len, as, aslr_delta);
u64 DllResolveExport(dll, name);      // absolute VA or 0
u64 DllResolveOrdinal(dll, ordinal);  // absolute VA or 0
```

DllLoad walks the same steps `PeLoad` does for an EXE, minus
the user stack / TEB / proc-env / Win32 stubs page setup:

1. Parse + validate PE headers.
2. Reject if `IMAGE_FILE_DLL` bit is clear in
   `FileHeader.Characteristics` (0x2000).
3. Map the first `SizeOfHeaders` bytes RO+NX at `base_va` (so
   `__ImageBase` lookups work, just like EXE loading).
4. Map every section at `base_va + VirtualAddress` with
   PE-derived flags (R/W/X).
5. Apply `IMAGE_REL_BASED_DIR64` base relocations using
   `aslr_delta` as the shift from the preferred ImageBase.
6. `PeParseExports` → populate `DllImage.exports`.

On success the returned `DllImage` carries everything a caller
needs to turn a `(name | ordinal)` into an absolute VA via
`DllResolveExport` / `DllResolveOrdinal`.

## What is explicitly NOT in scope yet

Deferred to stage 2 slice 2+:

- **DLL-of-DLL imports.** If the loaded DLL has its own
  `IMAGE_DIRECTORY_ENTRY_IMPORT`, we do not walk it. The
  `DllImage` is returned with an unresolved IAT. Tackling this
  requires a per-process DLL cache so `kernel32.dll` isn't
  loaded twice when two DLLs import from it.
- **DllMain dispatch.** Real Windows calls the DLL entry with
  `DLL_PROCESS_ATTACH` before any caller touches exports. v0
  skeleton skips the call — fine as long as nothing the DLL
  exports depends on DllMain having run.
- **TLS callbacks** in the DLL. Same rejection gate as
  `PeLoad`: non-empty callback array fails. Empty array
  (MSVC's placeholder `.tls`) passes through untouched.
- **DLL refcounting / shared cache.** One DLL image per AS per
  call. Two `DllLoad` calls on the same DLL duplicate the
  mapping.
- **Unload path.** No `DllUnload` yet. AS release tears the
  mapping down when the process exits.
- **LoadLibrary / GetProcAddress wiring.** The v0 stubs for
  these still return 0/NULL. A future slice routes them through
  `DllLoad` + a per-process DLL table.
- **Real DLL test fixture.** No embedded DLL blob yet. The EAT
  parser has been exercised on every existing ramfs PE (they
  all hit `NoExportDirectory` cleanly). A later slice will
  add a purpose-built test DLL (mirror of
  `tools/build-hello-winapi.sh`) so the name / ordinal lookup
  and forwarder paths get real coverage on boot.

## Design decisions

### Why keep pe_exports.cpp standalone, with its own PE-header helpers?

`pe_loader.cpp` already has `LeU16`/`LeU32`/`LeU64`/`RvaToFile`
in its anon namespace. The EAT parser reimplements a minimal
shape of these rather than exposing the loader's internals.

Two reasons:

1. **Freestanding.** `PeExportsReport` needs to be callable
   from `PeReport` *and* from any future unit test that hands
   in a synthetic byte buffer. Pulling in the loader's
   `PagingInit`-aware bits (the guard include, the stubs
   namespace) would couple the parser to the whole Win32
   subsystem.
2. **Stage 2 refactor target.** When the DLL loader gains
   import resolution (stage 2b/2c), the three files will share
   enough PE-header plumbing that a `pe_common.h` makes sense.
   Doing that refactor now — before the shape of "DLL-specific
   vs EXE-specific" has been exercised — would be premature.
   Duplicated helpers are cheap; the wrong abstraction is
   expensive.

### Why reject non-DLL PEs in DllLoad instead of repurposing PeLoad?

PeLoad sets up a user stack, TEB, proc-env page, Win32 stubs
page, and calls ResolveImports. A DLL needs none of these at
load time — imports are resolved lazily (or via a later
slice's recursive loader), the stack belongs to the calling
process, and there's no "entry point" to transfer control to.

Making PeLoad branch on DLL vs EXE would have doubled its
surface. A separate `DllLoad` keeps each function's scope
obvious and keeps the DLL-specific failure modes
(`NotADll`, `ExportParseFailed`) isolated from PeLoad's gate
set.

### Why is `DllResolveExport` a tight wrapper over `PeExportLookupName`?

The resolver is the narrow contract callers actually want —
"give me a VA or nullptr." Exposing `PeExportLookupName`
directly would leak the forwarder handling into every caller
that just wants "the function to jump to." `DllResolveExport`
returns 0 on a forwarder; the caller can decide whether to
chase it (which requires a DLL cache they own) or treat it as
an unresolved symbol.

## Slice 2 — real test DLL + boot-time smoke test

Slice 1 delivered the parser + loader but had no purpose-built
fixture: every PE in ramfs is an EXE with no exports, so the
parser only saw the `NoExportDirectory` path. Slice 2 closes
that gap.

New test surface:

| File | Role |
|------|------|
| `userland/libs/customdll/customdll.c` | Three-function freestanding DLL source: `CustomAdd`, `CustomMul`, `CustomVersion`. `__declspec(dllexport)` on each. No CRT, no imports, no DllMain. |
| `tools/build-customdll.sh` | Host build script. `clang --target=x86_64-pc-windows-msvc -c` → object, then `lld-link /dll /noentry /nodefaultlib /base:0x10000000 /export:... /out:customdll.dll` → 2 KiB DLL. Runs `embed-blob.py` to produce `generated_customdll.h`. |
| `kernel/core/dll_loader_selftest.cpp` | `DllLoaderSelfTest()` parses the embedded bytes, loads them into a scratch `AddressSpace`, and asserts name + ordinal lookups resolve to VAs inside the mapped image. |
| `kernel/CMakeLists.txt` | `add_custom_command` fires the DLL build whenever the C source or the script changes, and the generated header is folded into the kernel's shared source list so both stages pick it up. |
| `kernel/core/main.cpp` | One-line call into `DllLoaderSelfTest()` right after `Win32LogNtCoverage` — same spot as the other subsystem scoreboards. |

### Expected boot log

```
[dll-test] begin customdll.dll bytes=0x800
  exports: dll="customdll.dll" base=0x1 nfunc=0x3 nname=0x3
    [0x1] CustomAdd      -> rva=0x1000
    [0x2] CustomMul      -> rva=0x1010
    [0x3] CustomVersion  -> rva=0x1020
[dll-test] EAT parse OK — CustomAdd rva=0x1000 CustomMul rva=0x1010 CustomVersion rva=0x1020
[dll-load] begin base_va=0x10000000 size=0x3000 sections=0x2 chars=0x2022
[dll-load] relocs blocks=0x1 applied=0x0 delta=0x0
[dll-load] OK entry_rva=0x0 has_exports=0x1
[dll-test] DllLoad OK base_va=0x10000000 CustomAdd VA=0x10001000
```

The `PeExportsReport` block comes from the diagnostic path
(PeReport now calls it); the `[dll-test]` / `[dll-load]` lines
come from `DllLoaderSelfTest` itself.

### Why `lld-link /dll /noentry`?

DLLs built through the default path want a `_DllMainCRTStartup`
reference, which pulls in the MSVC CRT. We don't have one.
`/noentry` tells lld-link to skip the entry-point reference
entirely. The kernel's DLL loader currently does not dispatch
DllMain anyway (see "Deferred" below), so the missing entry is
inconsequential for now.

### Why three exports, not one?

One export would verify `PeExportLookupName` and
`PeExportLookupOrdinal` in isolation, but wouldn't catch two
common bugs:

1. **Off-by-one in the ENT / EOT walk.** A single-export DLL
   has the name table at offset 0 and the ordinal table at
   offset 0; any sign-extension or stride error would happen
   to land on the right slot. Three exports exercise a
   non-trivial stride.
2. **Alphabetical ordering assumption in EOT.** lld-link emits
   names sorted alphabetically (ENT must be sorted per PE
   spec), with EOT entries pointing back into the EAT. A
   single export has EOT = [0] regardless. With three sorted
   exports (CustomAdd, CustomMul, CustomVersion), EOT values
   diverge from their ENT indices only if the parser honours
   the EOT indirection correctly.

## Boot-time visibility

`PeReport` now appends an `exports:` block to the diagnostic it
already emits for every PE in ramfs. All the existing PEs
(`hello.exe`, `hello_winapi.exe`, `synxtest.exe`,
`syscall_stress.exe`, `thread_stress.exe`, `windows-kill.exe`)
are executables without exports, so the block reports
`NoExportDirectory` and stays silent — correct and cheap. The
first real DLL embedded in ramfs will light up the full dump:

```
  exports: dll="customdll.dll" base=0x1 nfunc=0x3 nname=0x3
    [0x0001] CustomAdd  -> rva=0x1020
    [0x0002] CustomMul  -> rva=0x1040
    [0x0003] CustomName -> forwarder="KERNEL32.GetCommandLineA"
```

## What's next (stage 2 slice 3+)

1. ~~Real test DLL.~~ **Landed in slice 2** —
   `userland/libs/customdll/`, boot-time `DllLoaderSelfTest`.
2. **Per-process DLL table.** `Process::dll_images[]` with a
   fixed cap; `DllLoad` registers into it, `DllResolveExport`
   walks it first for dependency resolution.
3. **Recursive import resolution.** Walk the DLL's own Import
   Directory, look up each target DLL in the table (load if
   absent, detect circular dependencies), then patch the DLL's
   IAT through the EAT. Replaces the flat `kStubsTable` for
   the DLLs we can supply end-to-end.
4. **`GetProcAddress` / `LoadLibraryW` rewrite.** The v0 stubs
   return 0 today; promote them to real trampolines that call
   into the new DLL layer. Gated on (1) + (2).
5. **DllMain dispatch + forwarder chasing.** Required before we
   can replace `kernel32.dll`'s stub batch with a real DLL —
   several kernel32 entry points depend on it.

## Related entries

- [`pe-subsystem-v0.md`](pe-subsystem-v0.md) — the PE
  executable loader this sits next to.
- [`win32-subsystem-v0.md`](win32-subsystem-v0.md) — the stage-1
  flat-stubs design this is the successor to.
- [`win32-subsystem-design.md`](win32-subsystem-design.md) —
  decisions 2 + 3: DLLs are our own reimplementations, PE
  loader lives in the kernel. The DLL loader honours both.
