# PE EAT parser + DLL loader — stage 2 kickoff

**Type:** Observation · **Status:** Active (stage-2 slices 1-29 landed; 15 userland DLLs shipped, ~317 flat-stub rows retired) · **Last updated:** 2026-04-24

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

## Slice 3 — per-process DLL table

Slice 2 left `DllLoad` standing alone: it returned a
`DllImage` that callers had to hold themselves. Slice 3 wires
the image into the per-process state so a future
`GetProcAddress` / import-resolver rewrite can walk all DLLs
registered on the caller's `Process` without a separate
out-of-band table.

New surface in `kernel/core/process.{h,cpp}`:

```cpp
struct Process {
    // ... existing fields ...

    static constexpr u64 kDllImageCap = 16;
    DllImage dll_images[kDllImageCap];
    u64      dll_image_count;
};

bool ProcessRegisterDllImage(Process* proc, const DllImage& image);
u64  ProcessResolveDllExport(const Process* proc,
                             const char* dll_name, const char* func_name);
```

`ProcessRegisterDllImage` copies the image into the next free
slot and bumps the count. Returns false when the table is full
— a hard cap of 16 DLLs per process (ample for the Win32
closure that `windows-kill.exe` touches: ntdll + kernel32 +
user32 + advapi32 + msvcp140 + vcruntime140 + ~7 UCRT
apisets).

`ProcessResolveDllExport` walks the registered images and
returns the absolute VA on the first name hit, or 0 on miss.
Key behaviours:

- **DLL-name filter.** `dll_name == nullptr` searches every
  registered DLL. A non-null `dll_name` restricts to the
  matching DLL (case-insensitive on the DLL's own Export
  Directory name — Win32 convention).
- **Function-name match is case-sensitive** — delegates to
  `PeExportLookupName`, which mirrors `GetProcAddress` on
  real Windows.
- **Forwarder exports return 0.** Caller must chase
  forwarders through logic it controls; the v0 DLL cache
  doesn't yet have the cross-DLL bookkeeping required.

`ProcessCreate` zero-initialises the table. No other Win32
tables (mutexes, events, threads, …) needed changes — the DLL
table lives next to them and follows the same slot-reuse
pattern the rest of the Process uses.

### Self-test extension

`DllLoaderSelfTest` now covers the table end-to-end: it
`KMalloc`s a scratch `Process`, zeroes it, registers the
loaded `DllImage`, and runs five resolve probes:

| Probe | Intent |
|-------|--------|
| `resolve via proc (exact dll match)` | `dll="customdll.dll"` hits the slot and returns CustomAdd's VA. |
| `resolve via proc (ci dll match)`     | `dll="CUSTOMDLL.DLL"` hits despite case mismatch — verifies the `DllNameEq` path. |
| `resolve via proc (any dll)`          | `dll=nullptr` still finds the function because every DLL is searched. |
| `resolve via proc (wrong dll)`        | `dll="kernel32.dll"` misses even though `CustomAdd` would otherwise match — DLL filter honoured. |
| `resolve via proc (wrong func)`       | Valid DLL, bogus function name → clean 0 return. |

### Why keep the Process zeroed manually instead of ProcessCreate?

`ProcessCreate` takes ownership of an `AddressSpace`, a root
`RamfsNode`, caps, etc. The selftest only exercises the DLL
table fields; pushing everything else through the real
construction path would pull in KPI surface (root nodes,
caps) unrelated to what we're verifying. `KMalloc` + manual
zero-init is the narrowest possible test setup and matches
the style used by `FrameAllocatorSelfTest` /
`KernelHeapSelfTest` for their own scratch state.

## Slice 4 — real `GetProcAddress` → `SYS_DLL_PROC_ADDRESS`

Slice 3 made the per-process DLL table callable from kernel
code. Slice 4 plumbs a user-mode entry point through it: the
Win32 `GetProcAddress` stub, which has been stuck at
`kOffReturnZero` since batch 25, now trampolines into a real
kernel syscall that walks `Process::dll_images[]`.

### New syscall

```text
SYS_DLL_PROC_ADDRESS = 57
  rdi = HMODULE (DLL load-base VA; 0 = "any registered DLL")
  rsi = user ptr to NUL-terminated ASCII function name
  returns: absolute VA of the export on hit, 0 on miss
```

Handler in `kernel/core/syscall.cpp`:
- `CurrentProcess()` — no `proc` → return 0.
- `CopyFromUser` the function name into a 257-byte kernel-
  stack bounce buffer (256 chars + hard NUL). Bounded so a
  hostile caller can't make us walk off the page.
- Delegates to `ProcessResolveDllExportByBase(proc, hmod, name)`.

### New Process helper

`ProcessResolveDllExportByBase(proc, base_va, func_name)`
sits alongside the slice-3 `ProcessResolveDllExport(proc,
dll_name, func_name)`. Difference:

| Caller shape | Helper | Match by |
|---|---|---|
| GetProcAddress(HMODULE, LPCSTR) | `ByBase` | DLL's own `base_va` |
| in-kernel `(dll_name, func_name)` resolution | `ProcessResolveDllExport` | DLL's embedded name (case-insensitive) |

Both helpers hard-reject forwarder exports for now (return
0). Forwarder chasing needs a cross-DLL resolver that stage-2
will bring online once multiple DLLs are actually registered.

### New stub bytecode (18 bytes at offset 0xC7F)

```asm
0xC7F  push rdi
0xC80  push rsi
0xC81  mov rdi, rcx              ; hModule
0xC84  mov rsi, rdx              ; LPCSTR name
0xC87  mov eax, 57               ; SYS_DLL_PROC_ADDRESS
0xC8C  int 0x80
0xC8E  pop rsi
0xC8F  pop rdi
0xC90  ret
```

`kStubsBytes` grows from 0xC7F to 0xC91 bytes. The
`{"kernel32.dll", "GetProcAddress", kOffReturnZero}` entry
becomes `kOffGetProcAddressReal`. Every other
`kOffReturnZero` consumer is unaffected.

Miss contract is identical to the prior stub: 0 back to the
caller. Existing PEs that `GetProcAddress` an optional API
and NULL-check gracefully fall back either way, so slice 4
is a drop-in — no existing ramfs PE regresses.

### Why not wire into ResolveImports yet?

The import resolver currently runs inside `PeLoad`, which is
invoked from `SpawnPeFile` BEFORE `ProcessCreate`. At that
point there's no `Process*` to register DLLs on. Teaching
ResolveImports to consult the DLL table would require either
(a) two-pass load — create the Process first, then DllLoad
every needed DLL, then resolve — or (b) a loader-local DLL
cache that the resolver consults and which is later handed
to the Process. Both are larger slices than slice 4 warrants,
so this one stays narrow: it makes **explicit**
`GetProcAddress` calls real, and leaves the **implicit** IAT
patching to a future slice.

### Self-test extension

`DllLoaderSelfTest` gets three new assertions for the
HMODULE path (`ProcessResolveDllExportByBase`):

| Probe | Intent |
|-------|--------|
| `ByBase(base_va, CustomAdd)` | Matches exactly on load-base — the Win32-natural path. |
| `ByBase(0, CustomMul)` | Fallthrough — HMODULE=0 searches every registered DLL. |
| `ByBase(0xDEADBEEF, CustomAdd)` | Bogus HMODULE → clean 0 back (miss). |

The syscall handler itself isn't callable from kernel_main
(no ring-3 context), so the in-kernel test stops one layer
below `int 0x80`. The pathology would be a stub-bytecode
error; that's caught by a manual ring-3 PE test when the
first PE that calls `GetProcAddress` against a registered
DLL lands. For now: `windows-kill.exe` still calls
GetProcAddress but all DLLs are empty, so the result is 0 —
same as before slice 4.

## Slice 5 — pre-load `customdll.dll` into every Win32-imports PE

Slice 4 made the `SYS_DLL_PROC_ADDRESS` syscall real, but no
process yet had any DLL registered — so every call still
returned 0, just through a different code path. Slice 5 closes
that gap for the test fixture: `SpawnPeFile` now calls
`DllLoad` + `ProcessRegisterDllImage` on `customdll.dll`
immediately after `Win32HeapInit`, inside the existing
`r.imports_resolved` gate.

### Where it hooks

`kernel/core/ring3_smoke.cpp::SpawnPeFile` — right after the
Win32 heap stands up for a PE that had imports. Reuses the
same gate: freestanding PEs (e.g. `hello.exe`) neither get a
heap nor a DLL, keeping their frame footprint unchanged.

```cpp
if (r.imports_resolved) {
    Win32HeapInit(proc);
    DllLoad(kBinCustomDllBytes, len, as, /*aslr_delta=*/0);
    ProcessRegisterDllImage(proc, dll.image);
    // [ring3] pre-loaded customdll.dll base=0x10000000 pid=0xN
}
```

### Behavioural delta

- **Every Win32-imports PE now has `customdll.dll` mapped at
  VA `0x10000000`** (three pages: headers, `.text`, `.rdata`).
  No collision with existing fixed VAs (win32 heap at
  `0x50000000`, stubs at `0x60000000`, proc-env at
  `0x65000000`, TEB at `0x70000000`, stack ending at
  `0x80000000`, typical PE ImageBase `0x140000000+ASLR`).
- **No existing PE changes behaviour.** None of
  `hello_winapi`, `thread_stress`, `syscall_stress`, or
  `windows-kill` imports anything from `customdll.dll`, so
  the IAT is unaffected and their code paths are identical.
- **`GetProcAddress(hmod=<customdll_base>, "CustomAdd")` now
  resolves.** This is the first end-to-end proof that the
  stage-2 pipeline works from user mode all the way through
  the kernel DLL table to the mapped export.

### Why preload into EVERY Win32-imports process, not opt-in?

- **Regression canary.** Every spawn that has imports exercises
  `DllLoad` + register + AS mapping. A frame-allocator
  regression, a paging bug, or an AS-region-bookkeeping drift
  would surface on the next boot.
- **No per-PE metadata to read.** An opt-in design needs
  either a CMake-side flag per PE fixture or a "needs
  customdll" marker in the PE itself. Neither is cheaper
  than the 3 frames a preload costs.
- **Non-fatal on failure.** If `DllLoad` fails (e.g. frame
  budget tight for a specific workload), we log loudly but
  let the spawn proceed. Promote to fatal the first time a
  real PE depends on the DLL being loaded.

### Boot-log shape

For every Win32-imports PE:

```
[ring3] pe spawn name="ring3-hello-winapi" pid=0xN ...
[dll-load] begin base_va=0x10000000 size=0x3000 sections=0x2 chars=0x2022
[dll-load] OK entry_rva=0x0 has_exports=0x1
[ring3] pre-loaded customdll.dll base=0x10000000 pid=0xN
```

Freestanding PEs (`hello.exe`) emit no `[dll-load]` /
`[ring3] pre-loaded` lines — the `r.imports_resolved` gate
keeps them untouched.

## Slice 6 — `ResolveImports` consults the DLL table

Slice 5 registered the DLL on `Process` AFTER `PeLoad` finished,
so the IAT walk inside `ResolveImports` never saw it. Slice 6
turns the order around: `SpawnPeFile` now `DllLoad`s
`customdll.dll` BEFORE `PeLoad` and threads the resulting
`DllImage` array through to `ResolveImports`, which consults
the DLL table BEFORE falling through to the flat
`Win32StubsLookup` / catch-all path.

On hit, the IAT slot is patched with the DLL's export VA
directly. No trampoline page. No `int 0x80` round-trip. The
PE's indirect call lands straight in the DLL's code.

### New PeLoad signature

```cpp
PeLoadResult PeLoad(const u8* file, u64 file_len, AddressSpace* as,
                    const char* program_name, u64 aslr_delta,
                    const DllImage* preloaded_dlls = nullptr,
                    u64 preloaded_dll_count = 0);
```

The defaulted tail keeps every prior call site source-
compatible: only `SpawnPeFile` passes a real array today.

### New helper in pe_loader.cpp (anon namespace)

```cpp
bool TryResolveViaPreloadedDlls(const char* dll_name, const char* fn_name,
                                const DllImage* dlls, u64 count, u64* out_va);
```

Walks the array, matches the import's `dll_name` case-insensitively
against each DLL's embedded Export Directory name, looks up
`fn_name` via `PeExportLookupName`. Returns the absolute VA on
hit (= `base_va + export.rva`), `false` on miss.
Forwarder exports: skipped silently, falls through to the
flat stubs — forwarder chasing still deferred.

### ResolveImports walk — new order

```text
for each import {dll, fn}:
    stub_va = 0
    if TryResolveViaPreloadedDlls(dll, fn, ...):
        # Direct-to-DLL path (slice 6).
        # [pe-resolve] via-dll customdll.dll!CustomAdd -> 0x10001000
    elif Win32StubsLookupKind(dll, fn, ...):
        # Flat stubs path — existing batches 0-65.
    else:
        # Catch-all: miss-logger trampoline or data landing pad.
    patch IAT slot at (image_base + first_thunk + fn_idx*8) = stub_va
```

A DLL-resolved import is never a no-op shim, so the familiar
`[pe-resolve] import resolved to NO-OP stub` Warn line stays
quiet for those slots.

### SpawnPeFile order-of-operations (before → after slice 6)

| Step | Before slice 6 | After slice 6 |
|---|---|---|
| AddressSpaceCreate | 1 | 1 |
| DllLoad customdll | — (or: 7, post-ProcessCreate in slice 5) | 2 (pre-PeLoad) |
| PeLoad | 2 | 3 (now carries the DLL array) |
| ProcessCreate | 3 | 4 |
| Win32HeapInit | 4 | 5 |
| ProcessRegisterDllImage | 5 (slice 5) | 6 (copies the slice-2 stack local) |

The DllImage lives on SpawnPeFile's stack frame for the
duration of the call; `ProcessRegisterDllImage` copies the
struct into the Process's permanent `dll_images[]` slot, so
the stack local can go out of scope safely on return.

### Why only customdll.dll today?

The order-of-operations plumbing is generic — `preloaded_dlls`
is an array, not a single DLL. Slice 6 only populates one
entry because that's all we have a blob for. Adding more
fixtures is purely a build-system task: drop a new
`userland/libs/X/` + `tools/build-X.sh` + `CMake` entry, then
extend the pre-PeLoad block in `SpawnPeFile` to DllLoad
every blob before building the array.

### Behavioural delta on existing PEs

None. `customdll.dll` exports `CustomAdd` / `CustomMul` /
`CustomVersion`; no existing ramfs PE (hello_winapi,
thread_stress, syscall_stress, windows-kill) imports from
`customdll.dll`, so `TryResolveViaPreloadedDlls` misses for
every import and the flat-stubs path runs exactly as before.

The path is provably live: add a PE that imports
`CustomAdd`, watch the boot log for:

```
[pe-resolve] via-dll customdll.dll!CustomAdd -> 0x10001000
```

### Next slice candidates

- **Retire kernel32-via-DLL**: write a real `userland/libs/kernel32/`
  that provides a handful of entry points (e.g. `GetTickCount`,
  `Sleep`) as native code. When lld-linked as a DLL, PEs that
  import those names will resolve via the DLL path instead of
  the flat stubs page — the first genuine retirement of
  `kStubsTable` entries.
- **Forwarder chasing**: populate the `forwarder` branch of
  `TryResolveViaPreloadedDlls` — when an entry is a forwarder,
  parse `"Dll.Func"`, look up that DLL in the array, recurse.

## Slice 7 — `customdll_test.exe` end-to-end fixture

Slice 6 made the via-DLL path live in the loader but kept it
dormant: no existing ramfs PE imports from `customdll.dll`, so
`TryResolveViaPreloadedDlls` missed for every call. Slice 7
ships the first fixture that actually exercises the path:
a tiny PE that imports `CustomAdd` / `CustomMul` /
`CustomVersion` from `customdll.dll` plus `ExitProcess` from
`kernel32.dll`.

### New fixture

| File | Role |
|------|------|
| `userland/apps/customdll_test/hello.c` | `_start` calls each of the three DLL exports, cross-checks their return values, and `ExitProcess`es with `0x1234` on success / `0xBAD0` on mismatch. Freestanding, no CRT, no SSE. |
| `userland/apps/customdll_test/customdll.def` | Declares the three DLL exports for `llvm-dlltool`. |
| `userland/apps/customdll_test/kernel32.def` | `ExitProcess` only — tight `.def` to keep the produced PE small. |
| `tools/build-customdll-test.sh` | Host-side: two `.lib`s via `llvm-dlltool`, one `.obj` via `clang`, one PE via `lld-link /subsystem:console /entry:_start /base:0x140000000`. Embeds bytes as `generated_customdll_test.h`. |
| `kernel/CMakeLists.txt` | `add_custom_command` fires the build whenever source/scripts change; header folded into both kernel stages. |
| `kernel/fs/ramfs.cpp` | `/bin/customdll_test.exe` node added to the trusted bin listing. |
| `kernel/core/ring3_smoke.cpp` | Fifth `SpawnPeFile` call in the autoboot list — runs after `syscall_stress`, before `winkill` diagnostic. |

### Expected boot-log signature

```
[ring3] pe report name="ring3-customdll-test"
  image_base=0x140000000 entry_rva=0x1000 image_size=0x3000
  imports: rva=0x2030 size=0x...
    needs customdll.dll: CustomAdd, CustomMul, CustomVersion
    needs kernel32.dll:  ExitProcess
[ring3] pre-loaded customdll.dll base=0x10000000 (pre-PeLoad — visible to ResolveImports)
[pe-resolve] via-dll customdll.dll!CustomAdd     -> 0x10001000
[pe-resolve] via-dll customdll.dll!CustomMul     -> 0x10001010
[pe-resolve] via-dll customdll.dll!CustomVersion -> 0x10001020
[pe-resolve] ...import resolved... ExitProcess (flat-stubs path)
[ring3] pe spawn name="ring3-customdll-test" pid=0xN entry=0x140001000 ...
[ring3] registered customdll.dll pid=0xN
...
[I] sys : exit rc val=0x1234
```

If `exit rc` reports `0xBAD0`, at least one of the three DLL
exports returned the wrong value — regression signal.

### Why these particular operands?

- `CustomAdd(0x1000, 0x0234)` → `0x1234` (success signature
  memorable in the serial log, distinct from `0x2a`/`0xABCDE`/
  `0xCAFE` used by other fixtures).
- `CustomMul(3, 4)` → `12` — smallest arguments that produce
  a non-trivial result.
- `CustomVersion()` → `0x200` — matches the marker constant
  baked into `customdll.c` since slice 2.

All three results are checked inline; only a clean
three-way match produces the `0x1234` exit code.

### Why the fixture has no IAT miss-logger entries

Every import resolves either via-DLL (three of them) or via
the flat stubs path (`ExitProcess`). No import hits
`Win32StubsLookupCatchAll`, so the per-process
`win32_iat_misses[]` table stays empty and no
`[win32-miss]` log lines appear for this PE.

## Slice 8 — forwarder chasing

Slice 6 detected forwarder exports but skipped them (fell
through to the flat stubs). Real Windows PEs forward heavily
(`msvcp140` → `ucrtbase`, `kernel32` → `kernelbase`, `ucrt` →
`api-ms-win-crt-*`), so resolving forwarders is non-optional
for a production DLL surface. Slice 8 adds the chase.

### What changed in `TryResolveViaPreloadedDlls`

A new `ParseForwarder(fwd, out_dll, out_func)` helper in the
pe_loader anon namespace splits a PE forwarder string
(`"DllBase.TargetFunc"`) into its two halves:

- Locates the first `'.'` — the split point per PE spec.
- Copies the pre-`.` segment into `out_dll`; appends `".dll"`
  if the source didn't already carry that suffix (real PEs
  sometimes do, sometimes don't).
- Rejects ordinal-form forwarders (`"Dll.#N"`) — deferred
  until something real needs them. The current customdll-only
  test pool has no such forwarders.

The resolver becomes `TryResolveViaPreloadedDllsImpl(... depth)`
and recurses on a forwarder hit with `depth+1`. A compile-time
ceiling `kMaxForwarderDepth = 4` bounds the chase against
pathological cycles — 4 is enough for real multi-hop chains
(kernel32→kernelbase→ntdll is typically 2 hops).

On a successful chase, the boot log now emits:

```
[pe-resolve] via-dll-fwd customdll.dll!CustomAddFwd \
    -> customdll.CustomAdd -> 0x10001000
```

Distinguishing the forwarder path from the direct via-DLL
path (`via-dll` vs `via-dll-fwd`) makes the chain visible
for regression diagnosis.

### DLL-side change (`tools/build-customdll.sh`)

One extra `lld-link` flag:

```
/export:CustomAddFwd=customdll.CustomAdd
```

`lld-link` emits a fourth export whose EAT slot points back
inside the Export Directory to the string
`customdll.CustomAdd`. `llvm-readobj --coff-exports` confirms
the shape:

```
Export {
  Ordinal: 2
  Name: CustomAddFwd
  ForwardedTo: customdll.CustomAdd
}
```

### Test-PE extension (`customdll_test.exe`)

Imports `CustomAddFwd` via `customdll.def`, calls it with
`(0x1100, 0x0133)` = `0x1233`. The success check now
requires all four results (direct + forwarded + mul + ver)
to match — any regression in either the direct or the
forwarder path produces `0xBAD0` as the exit code.

### Boot-log signature on success (slice 8)

```
[pe-resolve] via-dll     customdll.dll!CustomAdd     -> 0x10001000
[pe-resolve] via-dll-fwd customdll.dll!CustomAddFwd \
             -> customdll.CustomAdd -> 0x10001000
[pe-resolve] via-dll     customdll.dll!CustomMul     -> 0x10001010
[pe-resolve] via-dll     customdll.dll!CustomVersion -> 0x10001020
...
[I] sys : exit rc val=0x1234
```

Both `via-dll` and `via-dll-fwd` paths land on the same
`0x10001000` — `CustomAddFwd`'s IAT slot ends up with the
same VA as `CustomAdd`'s. The chase runs exactly once at
load time; runtime calls are indistinguishable.

## Slice 9 — multi-DLL preload

Slices 5–8 all ran with exactly one pre-loaded DLL
(`customdll.dll`). The array parameter to `PeLoad` was
plumbed but only ever held one entry. Slice 9 generalises the
preload slot to N DLLs and ships a second test DLL
(`customdll2.dll`) with a disjoint export set so every lookup
path gets a real walk-past-the-first-DLL exercise.

### What changed in `SpawnPeFile`

A single-entry DllImage local becomes a 4-slot stack array +
a mirrored table of source blobs:

```cpp
struct PreloadDllEntry { const char* label; const u8* bytes; u64 len; };
const PreloadDllEntry preload_set[] = {
    {"customdll.dll",  kBinCustomDllBytes,  kBinCustomDllBytes_len},
    {"customdll2.dll", kBinCustomDll2Bytes, kBinCustomDll2Bytes_len},
};
DllImage preloaded_dlls[kPreloadSlotCap];  // kPreloadSlotCap = 4
u64      preloaded_count = 0;
for each entry:
    DllLoad(... into `as` ...);
    preloaded_dlls[preloaded_count++] = dll.image;
PeLoad(... preloaded_dlls, preloaded_count ...);
// post-ProcessCreate: loop ProcessRegisterDllImage
```

Adding a third DLL is a one-line append to `preload_set[]`
once the blob is embedded via CMake.

### Why the array is NOT zero-initialised

Plain `DllImage arr[4]{}` value-initialises ~400 bytes; clang
lowers that to `memset`, which the kernel doesn't link. The
array stays uninitialised; we only read indices
`[0..preloaded_count)` and every such slot is fully assigned
before the increment — no uninitialised-read hazard.

### New fixture — `customdll2.dll`

| File | Role |
|------|------|
| `userland/libs/customdll2/customdll2.c` | `__declspec(dllexport) int CustomDouble(int n) { return n*2; }`. One function, disjoint from customdll.dll. |
| `tools/build-customdll2.sh` | `clang --target=...msvc -c` → `.obj`, `lld-link /dll /noentry /base:0x10010000 /export:CustomDouble` → DLL. Embed as `generated_customdll2.h`. |
| `kernel/CMakeLists.txt` | `add_custom_command` for the new blob; header folded into both stages. |

Load base `0x10010000` = 1 MiB above `customdll.dll`'s
`0x10000000` — plenty of headroom for customdll's 3 pages;
no VA collision.

### Test PE update — `customdll_test.exe`

- Extra `.def` (`customdll_test/customdll2.def`) tells
  llvm-dlltool to produce a `customdll2.lib` so lld-link can
  resolve `__imp_CustomDouble`.
- `hello.c` imports + calls `CustomDouble(0x55)` = `0xAA` and
  cross-checks. Success gate now requires FIVE values to
  line up: `CustomAdd` (direct), `CustomAddFwd` (forwarded),
  `CustomMul` + `CustomVersion` (direct), `CustomDouble`
  (from second DLL).

`llvm-readobj` confirms the PE's Import Directory carries
three DLLs: customdll.dll (4 imports), customdll2.dll (1
import), kernel32.dll (ExitProcess).

### Boot-log signature on success

```
[ring3] pre-loaded customdll.dll  base=0x10000000 (pre-PeLoad — visible to ResolveImports)
[ring3] pre-loaded customdll2.dll base=0x10010000 (pre-PeLoad — visible to ResolveImports)
[pe-resolve] via-dll     customdll.dll!CustomAdd         -> 0x10001000
[pe-resolve] via-dll-fwd customdll.dll!CustomAddFwd -> customdll.CustomAdd -> 0x10001000
[pe-resolve] via-dll     customdll.dll!CustomMul         -> 0x10001010
[pe-resolve] via-dll     customdll.dll!CustomVersion     -> 0x10001020
[pe-resolve] via-dll     customdll2.dll!CustomDouble     -> 0x10011000
[ring3] registered 0x2 DLL(s) pid=0xN
...
[I] sys : exit rc val=0x1234
```

The `[ring3] registered 0x2` line confirms the
`ProcessRegisterDllImage` loop ran for both DLLs — the DLL
table is populated for `GetProcAddress` even though the
PE's IAT lookups happen at load time.

## Slice 10 — first stub retirement into real userland `kernel32.dll`

Slices 1-9 built the full infrastructure for loading DLLs and
resolving imports through them, but every DLL so far was a
test fixture (`customdll.dll`, `customdll2.dll`). Slice 10
kicks off the retirement of flat-stubs-page entries into
real userland code: a shipped `kernel32.dll` whose exports
replace the hand-assembled trampolines in
`kernel/subsystems/win32/stubs.cpp`.

### Slice 10 scope — exactly one export

`GetCurrentProcessId`. Chosen as the first retirement because:

- **Trivially equivalent to the existing flat stub**. Both
  are 8 bytes: `mov eax, 8; int 0x80; ret`. Verified via
  `llvm-objdump`:

  ```
  10021000 <GetCurrentProcessId>:
  10021000:  movl $0x8, %eax
  10021005:  int  $0x80
  10021007:  retq
  ```

  Byte-identical to the stub at `0x60000048`. Zero chance
  of register-clobber regression.

- **DLL matches the import name**. PEs reference this
  function as `kernel32.dll!GetCurrentProcessId`; our DLL's
  Export Directory also names itself `kernel32.dll` (via the
  `/out:kernel32.dll` lld-link flag). Slice 6's via-DLL path
  matches on CI DLL name, so the IAT is patched to the DLL
  address BEFORE `Win32StubsLookupKind` is consulted.

### Effect on existing PEs

Any PE that imports `kernel32.dll!GetCurrentProcessId`
(hello_winapi.exe, windows-kill.exe, ...) now has its IAT
slot patched to `0x10021000` (the DLL's entry) instead of
`0x60000048` (the stub). The boot log emits:

```
[pe-resolve] via-dll kernel32.dll!GetCurrentProcessId -> 0x10021000
```

At ring-3 call time, the PE's indirect call through the IAT
lands in the DLL's 8-byte function, which issues the same
`int 0x80` SYS_GETPROCID as the stub. The stub at
`kOffGetCurrentProcessId` is now dead code — still present
in `kStubsBytes` and still registered in `kStubsTable`, but
unreachable for this specific `{dll, func}` pair.

### Why keep the flat stub around as dead code?

Two reasons:

1. **Fallback safety**. If a future slice breaks the DLL
   preload path (frame shortage, cycle, CMake drift), the
   flat stub still works — slice 6's via-DLL path misses
   and `Win32StubsLookupKind` runs. Existing PEs keep
   working during the transition.
2. **Narrow slice discipline**. Removing the stub now would
   couple "retire into DLL" with "delete dead code" — two
   orthogonal changes. A later sweep-slice deletes all dead
   kStubsTable entries once the retirement train has
   stabilised.

### Per-spawn frame cost

Three DLLs now preloaded per Win32-imports spawn:
`customdll.dll` (3 pages) + `customdll2.dll` (3 pages) +
`kernel32.dll` (3 pages) = 9 frames per process. Comfortably
within the kFrameBudgetTrusted envelope (256 frames); real
production workloads will push this much higher, at which
point the preload set becomes per-PE or per-image-descriptor
instead of the current global-constant list.

### Retirement roadmap

Each future slice should retire functions in
ABI-compatible groups — e.g. "all Interlocked*" in one
slice, "string intrinsics (strlen/strcmp/strcpy)" in
another. The stubs.cpp header comment listing the ~122
current entries becomes the retirement backlog.

For rough order-of-magnitude: `kStubsTable` has ~122 entries
across ~14 DLL names. Retiring everything into shipped DLLs
is ~30-100 slices of this granularity, most of them simple
syscall trampolines or return-constant shims.

## Slices 11-17 — retirement wave (consolidated)

After slice 10 proved the first retirement, slices 11-17
ramped up the pace dramatically. Total flat-stub coverage by
the end of slice 17: **~85 of ~122 rows retired (~70%)**
across **6 userland DLLs**.

### DLLs shipped

| DLL | Base VA | Exports | Slice intro | Notes |
|-----|---------|---------|-------------|-------|
| `customdll.dll` | `0x10000000` | 4 | slice 2 | Test fixture (Add/Mul/Version + forwarder) |
| `customdll2.dll` | `0x10010000` | 1 | slice 9 | Test fixture (CustomDouble) |
| `kernel32.dll` | `0x10020000` | 47 | slice 10 | Process/thread, Interlocked*, Sleep, Console, Wow64, SList, … |
| `vcruntime140.dll` | `0x10030000` | 3 | slice 13 | memset/memcpy/memmove |
| `msvcrt.dll` | `0x10040000` | 8 | slice 14 | strlen/strcmp/strcpy/strchr + wide variants |
| `ucrtbase.dll` | `0x10050000` | 25 | slice 15 + 17 | malloc/free/exit + CRT startup + atoi/strtol + terminate |

Per-spawn frame cost: 6 DLLs × ~3 pages = ~18 frames per
Win32-imports process. Comfortable headroom in
`kFrameBudgetTrusted` (256).

### What landed in each slice

- **Slice 11** — kernel32 trampoline batch (11 funcs):
  GetCurrentThreadId, GetLastError, SetLastError,
  GetCurrentProcess/Thread (pseudo-handles), ExitProcess,
  TerminateProcess (noreturn), IsDebuggerPresent,
  IsProcessorFeaturePresent, SetConsoleCtrlHandler,
  GetStdHandle.
- **Slice 12** — Sleep/SwitchToThread/GetTickCount(64) +
  full Interlocked* family (8 × 32-bit + 8 × 64-bit = 16
  atomic intrinsics via clang's `__atomic_*`).
- **Slice 13** — vcruntime140.dll: memset/memcpy/memmove
  (byte-loop with `__attribute__((no_builtin))` to stop
  clang from calling itself).
- **Slice 14** — msvcrt.dll: 4 narrow + 4 wide string
  intrinsics.
- **Slice 15** — ucrtbase.dll: heap (malloc/free/calloc/
  realloc/_aligned_*), exit/_exit, CRT startup shims
  (_initterm/_set_app_type/_cexit/...), string intrinsics
  duplicated from msvcrt.
- **Slice 16** — kernel32 console/wow64/drives/SList batch
  (15 funcs): GetConsoleMode/CP/OutputCP, GetLogicalDrives,
  GetDriveTypeA/W, IsWow64Process/2, GetModuleHandleExW/A,
  FreeLibrary, InterlockedPushEntrySList/Pop/Flush,
  InitializeSListHead.
- **Slice 17** — ucrtbase conversions: atoi, atol, strtol,
  strtoul + C++ runtime terminators (terminate,
  _invalid_parameter_noinfo_noreturn).

### Key build-system findings during the wave

- **Clang emits `memset` / `memcpy` for large stack zero-
  inits**. `DllImage[4]{}` (~400 bytes) and `static const
  PreloadDllEntry preload_set[]` (~150 bytes) both tripped
  the kernel link with `undefined symbol: memset/memcpy`.
  Fixes: drop the `{}` (we only read assigned slots) and
  mark large initialised arrays `static const` (lands in
  `.rodata` instead of being a runtime template copy).
- **Win32 LLP64 type sizes**. `unsigned long` is 32 bits
  under MSVC ABI; using it for HANDLE casts triggers
  `int-to-void-pointer-cast` warnings. Use a 64-bit
  `UINT_PTR` typedef.
- **clang `no_builtin` attribute is selective**. It
  recognises some str* names but not all wcs* names
  (`wcscpy`/`wcschr` aren't in its list). `-fno-builtin-X`
  flags cover the rest at the command-line level.
- **`/dll /noentry` is the right invocation** for
  freestanding DLLs without a `_DllMainCRTStartup`. Lets
  lld-link skip the default entry-point reference.

## Slices 18-23 — final retirement wave (consolidated)

Slices 11-17 took us to ~70%. Slices 18-23 pushed to ~99% of
retirable flat-stub rows.

### Added to `kernel32.dll` (slices 18-23)

- **Slice 18** — VirtualAlloc/Free/Protect (+Ex), lstrlenA/W,
  lstrcmpA/W, lstrcmpiA/W, lstrcpyA/W.
- **Slice 19** — WriteFile, WriteConsoleA, WriteConsoleW,
  CloseHandle, CreateFileW, ReadFile, SetFilePointerEx,
  GetFileSizeEx, GetFileSize.
- **Slice 20** — GetSystemTimeAsFileTime, QueryPerformanceCounter,
  QueryPerformanceFrequency, GetProcessHeap, HeapAlloc, HeapFree,
  HeapSize, HeapReAlloc, HeapCreate, HeapDestroy, GetACP,
  GetOEMCP, IsValidCodePage, MultiByteToWideChar,
  WideCharToMultiByte.
- **Slice 21** — TlsAlloc/Free/GetValue/SetValue, CreateMutexW/A,
  ReleaseMutex, CreateEventW/A, SetEvent, ResetEvent,
  CreateSemaphoreW/A, ReleaseSemaphore, WaitForSingleObject,
  WaitForSingleObjectEx.
- **Slice 22** — InitializeCriticalSection (+Ex, +AndSpinCount),
  DeleteCriticalSection, Enter/Leave/TryEnterCriticalSection,
  InitializeSRWLock, Acquire/Release/TryAcquireSRWLockExclusive,
  Acquire/Release/TryAcquireSRWLockShared, InitOnceExecuteOnce.
- **Slice 23** — CreateThread, ResumeThread, GetExitCodeThread,
  ExitThread, GetExitCodeProcess.

### Final DLL inventory

| DLL | Exports | Notes |
|-----|---------|-------|
| `customdll.dll` | 4 | Test fixture |
| `customdll2.dll` | 1 | Test fixture |
| `kernel32.dll` | **123** | Process/thread, sync, I/O, VM, locale, time, Interlocked*, CS/SRW, InitOnce |
| `vcruntime140.dll` | 3 | memset/memcpy/memmove |
| `msvcrt.dll` | 8 | String + wide string intrinsics |
| `ucrtbase.dll` | 25 | Heap, exit, CRT startup, string, conversions, terminators |

**Total: 164 exports across 6 DLLs.**

### Build-system findings (new ones from slices 18-23)

- **`/wcs*/` in C block comments is a trap.** The `*/`
  inside terminates the block. Already tripped us twice
  (slice 14 + slice 18). Write `str / wcs intrinsics`
  instead.
- **Caller-owned CAS targets**. `__atomic_compare_exchange_n`
  on a `long long volatile*` produced directly from the user
  pointer works cleanly; clang emits a `lock cmpxchg`.
- **`(long long)` casts everywhere** — MSVC's LLP64 means
  `long` = 32 bits; any syscall arg that's a pointer or a
  size needs `long long`. The inline-asm constraints `"a"`,
  `"D"`, `"S"`, `"d"` all require matching operand widths.

### What's still on the flat stubs

The deliberately-deferred set (stateful / complex / very
specialised):

- **SEH helpers** — `__C_specific_handler`, `__CxxFrameHandler3`,
  `_CxxThrowException`, `RtlCaptureContext`, `RtlVirtualUnwind`,
  `RtlLookupFunctionEntry`. Need real `.pdata` / `.xdata`
  unwind-table walking.
- **C++ std runtime** — `?_Xbad_alloc@std@@YAXXZ` etc.
  Hundreds of mangled throw helpers in msvcp140.
- **dbghelp** — `SymInitialize`, `SymCleanup`, `SymFromAddr`.
  Debug-info parsing.
- **ntdll Rtl\*** — some forwarded aliases.
- **Miscellaneous** — CreateToolhelp32Snapshot,
  Process32FirstW, CreateRemoteThread, OpenProcess,
  GenerateConsoleCtrlEvent, SetUnhandledExceptionFilter /
  UnhandledExceptionFilter (already upgraded to `Real`
  variants in the flat stubs; not a no-op).

A real `msvcp140.dll` + `dbghelp.dll` would take another few
slices. SEH is a multi-slice undertaking on its own.

## Slices 24-29 — extend to 15 userland DLLs

The retirement wave continued past kernel32 + CRT into the
full Win32 userland surface. By slice 29 the preload set
covers 24 DLL slots (some are fixtures / forwarders).

### Full DLL inventory (15 userland DLLs)

| Slice | DLL | Base VA | Exports | Role |
|-------|-----|---------|---------|------|
| 10-23 | kernel32.dll | `0x10020000` | 123 | Process/thread/sync/I/O/VM/locale/time/Interlocked/CS/SRW/InitOnce |
| 13 | vcruntime140.dll | `0x10030000` | 3 | memset/memcpy/memmove |
| 14 | msvcrt.dll | `0x10040000` | 8 | strlen/strcmp/strcpy/strchr + wide |
| 15 | ucrtbase.dll | `0x10050000` | 25 | Heap, exit, CRT startup, conversions |
| 24 | ntdll.dll | `0x10060000` | 108 | Nt\* + Zw\* + Rtl\* + Ldr\* + __chkstk |
| 25 | dbghelp.dll | `0x10070000` | 11 | Sym\*, StackWalk, MiniDumpWriteDump |
| 26 | msvcp140.dll | `0x10080000` | 17 | C++ std throw + ostream helpers |
| 27 | kernelbase.dll | `0x10090000` | 44 | Forwarders to kernel32 |
| 27 | advapi32.dll | `0x100A0000` | 25 | Reg\* / token / GetUserName / RtlGenRandom |
| 28 | shlwapi.dll | `0x100B0000` | 16 | Path\* / Str\* string helpers |
| 28 | shell32.dll | `0x100C0000` | 13 | Shell/CommandLine/Extract/Open |
| 28 | ole32.dll | `0x100D0000` | 15 | CoInit + CoTaskMem heap aliases |
| 28 | oleaut32.dll | `0x100E0000` | 5 | BSTR (real) + VARIANT zeroing |
| 28 | winmm.dll | `0x100F0000` | 8 | Timer + audio stubs |
| 28 | bcrypt.dll | `0x10100000` | 8 | CNG stubs + deterministic RNG |
| 28 | psapi.dll | `0x10110000` | 7 | Process/module enumeration |
| 29 | d3d9/11/12.dll | `0x10120/130/140` | 2/2/3 | DirectX — E_NOTIMPL |
| 29 | dxgi.dll | `0x10150000` | 3 | DXGI factory — E_NOTIMPL |
| 29 | user32.dll | `0x10160000` | 73 | Window manager — no-op stubs |
| 29 | gdi32.dll | `0x10180000` | 44 | GDI — no-op stubs |

**Total: ~560 exports across 15 userland DLLs.** Plus the 2
test fixtures (customdll.dll, customdll2.dll).

Per-spawn frame cost: ~72 frames per Win32-imports PE — well
within `kFrameBudgetTrusted`'s 256.

### New patterns from slices 24-29

- **Cross-DLL forwarders** (slice 27 kernelbase.dll) —
  proved the slice-8 chaser works on real 44-entry forwarder
  tables. `.def` syntax `Name = targetdll.TargetName`
  generates forwarder RVAs pointing back into the export
  directory.
- **Mangled C++ name exports** (slice 26 msvcp140.dll) — use
  `.def` file with `Exported = InternalName` aliasing so the
  C source carries plain identifiers; lld-link puts the
  mangled name in the export table.
- **Same-DLL forwarders** (slice 24 ntdll.dll Zw* aliases) —
  `/export:ZwXxx=NtXxx` on the lld-link cmdline. One function,
  two export names.
- **Centralised NOT_IMPL sink** — a single `NtReturnNotImpl`
  function with ~42 exports aliasing to it. Cheap way to
  retire big STATUS_NOT_IMPLEMENTED batches without writing
  42 copies.
- **Generic stub-DLL builder** (`tools/build-stub-dll.sh`) —
  takes (name, base VA, comma-separated exports) + a
  per-DLL C source. Slices 28-29 shipped 13 DLLs through
  this one helper.

### What remains on the flat stubs

After slice 29, `kStubsTable` still has rows for:

- **SEH unwind** — `__C_specific_handler`, `__CxxFrameHandler3`,
  `_CxxThrowException`, `RtlCaptureContext`, `RtlVirtualUnwind`,
  `RtlLookupFunctionEntry`. Real .pdata / .xdata traversal
  work; multi-slice undertaking.
- **Process32First/Next, CreateRemoteThread, OpenProcess,
  GenerateConsoleCtrlEvent** — a handful in kernel32 that
  need new kernel syscalls to implement meaningfully.
- **Real \_initterm / \_cexit etc.** that iterate function-
  pointer tables — current stub + DLL both no-op rather
  than actually calling; need the recursive-DLL-load work.

Everything else is covered.

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

## What's next (stage 2 slice 6+)

1. ~~Real test DLL.~~ **Landed in slice 2** —
   `userland/libs/customdll/`, boot-time `DllLoaderSelfTest`.
2. ~~Per-process DLL table.~~ **Landed in slice 3** —
   `Process::dll_images[]`, `ProcessRegisterDllImage`,
   `ProcessResolveDllExport`.
3. ~~Real GetProcAddress.~~ **Landed in slice 4** —
   `SYS_DLL_PROC_ADDRESS` (57), `ProcessResolveDllExportByBase`,
   real stub at `kOffGetProcAddressReal`.
4. ~~Preload customdll.dll.~~ **Landed in slice 5** —
   every Win32-imports spawn maps + registers the DLL.
5. ~~ResolveImports consults DLL table.~~ **Landed in slice 6** —
   PeLoad accepts a DllImage array; SpawnPeFile loads
   customdll pre-PeLoad; direct-to-DLL IAT patching.
6. ~~End-to-end fixture.~~ **Landed in slice 7** —
   `customdll_test.exe` imports CustomAdd/Mul/Version,
   boot log shows `[pe-resolve] via-dll ...`, exits `0x1234`.
7. ~~Forwarder chasing.~~ **Landed in slice 8** —
   `ParseForwarder` + bounded recursion in
   `TryResolveViaPreloadedDlls`. `CustomAddFwd` forwarder
   exercises the chase end-to-end.
8. ~~Multi-DLL preload.~~ **Landed in slice 9** —
   N-entry preload array in SpawnPeFile; second test DLL
   `customdll2.dll` with a disjoint `CustomDouble` export
   exercises the walk-past-first-DLL path.
9. ~~First stub retirement into real `kernel32.dll`.~~
   **Landed in slice 10** — `GetCurrentProcessId` now
   resolves to ring-3 code in `userland/libs/kernel32/`
   via the slice-6 preload path. Stub stays as dead-code
   fallback.
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
