# Image Loaders

> **Audience:** Kernel hackers, ABI implementors
>
> **Execution context:** Kernel — task context (loader runs on behalf of
> a process being constructed)
>
> **Maturity:** PE/COFF loader v0 stable; ELF loader parser-only; DLL loader
> active; firmware loader active

## Overview

DuetOS loads four distinct kinds of binary out of the same
[`kernel/loader/`](../../kernel/loader/) tree:

1. **PE/COFF** — Windows executables (`.exe`) and DLLs. Documented in
   detail at [PE Loader](../subsystems/PE-Loader.md).
2. **ELF64** — native DuetOS executables and userland native apps.
   Documented here.
3. **DLL** — Windows dynamic libraries (PE/COFF with the DLL bit set);
   parsed as PE, then bound through the DLL loader's name → export
   resolver.
4. **Firmware** — opaque binary blobs handed to a device driver
   (iwlwifi ucode, Intel GSC, AMDGPU firmware, etc.). Loaded through
   a separate path so file-layout assumptions can't bleed.

Each loader has the same shape: a `Validate()` pass over the header, a
`Load()` pass that issues `mm::*` calls to map the image, and a
`Entry()` query that returns the entry point for the spawn path to jump
to. None of them executes code on its own — they construct an
`AddressSpace`, populate it, and return.

## File Layout

| File | Purpose |
|------|---------|
| [`pe_loader.h`](../../kernel/loader/pe_loader.h) / `.cpp` | Windows PE/COFF — see [PE Loader](../subsystems/PE-Loader.md) |
| [`pe_exports.h`](../../kernel/loader/pe_exports.h) | PE export table walker (used by both DLL resolution and runtime `GetProcAddress` thunks) |
| [`elf_loader.h`](../../kernel/loader/elf_loader.h) / `.cpp` | ELF64 parser; segment load deferred |
| [`dll_loader.h`](../../kernel/loader/dll_loader.h) / `.cpp` | DLL loader + export resolver |
| `dll_loader_selftest.cpp` | KAT-style boot test of name + ordinal resolution |
| [`firmware_loader.h`](../../kernel/loader/firmware_loader.h) / `.cpp` | Firmware blob loader + trace ring |
| [`firmware_package.h`](../../kernel/loader/firmware_package.h) / `.cpp` | Firmware package format parser |
| [`compat_shim.h`](../../kernel/loader/compat_shim.h) / `.cpp` | Per-image compat policies (e.g. "this PE expects a 1 MiB stack guarantee", "ignore debugger checks") |
| [`exec_meta_rust/`](../../kernel/loader/exec_meta_rust/) | Rust crate — common image header decoders (see [Rust Subsystems](../tooling/Rust-Subsystems.md)) |

## ELF64 Loader

`elf_loader.h` answers structural questions about an ELF64 image:

```cpp
loader::Result<void> ElfValidate(span<const u8> file);
loader::Result<u64>  ElfEntry(span<const u8> file);
loader::Result<loader::ElfProgramHeaderInfo> ElfProgramHeaderInfo(span<const u8> file);
```

Today the loader **parses** but does not yet spawn — the PT_LOAD segment
walker that calls into `mm::AddressSpace` is the next slice. Until that
lands the loader is wired in to:

- Validate the ELF magic + class + machine on any binary handed to it
- Reject anything that isn't `ET_EXEC` x86_64 little-endian, version 1
- Provide the entry-RIP for `inspect`-style tools

Native-app loading uses this header validator today; the actual segment
mapping path is shared with the PE loader's `MapSegments` helper once
the slice lands.

## DLL Loader

`dll_loader.h` is the PE loader's companion for resolved imports and
explicit `LoadLibrary` calls:

```cpp
struct DllImage { /* base, exports table cache, ref count */ };

loader::Result<void*> DllResolveExport(const DllImage& img, const char* name);
loader::Result<void*> DllResolveOrdinal(const DllImage& img, u16 ordinal);
```

Resolution paths:

1. **Implicit imports** — PE loader walks the `IMAGE_DIRECTORY_ENTRY_IMPORT`
   on load, asks the DLL loader to resolve each name against the named
   DLL's export table. Misses fire `kWin32StubMiss` and route through
   the [thunk table](../subsystems/Win32-DLLs.md) for known stubs.
2. **Explicit imports** — `GetProcAddress` thunks call back into
   `DllResolveExport` at runtime. The cache lives on each `DllImage`
   so repeated calls are O(1) after the first miss.

The DLL loader does **not** synthesise a fake DLL for missing names —
that's the job of the Win32 thunk table. The loader either resolves to
a real export in a real DLL, or returns `Err{ErrorCode::NotFound}` and
lets the PE loader decide how loud to be.

`dll_loader_selftest.cpp` runs at boot: load a known DLL, resolve a
known export by name and by ordinal, assert the addresses match. A
failure here is a clear "imports are broken" signal long before any PE
binary is in flight.

## Firmware Loader

Firmware is a different beast: opaque blobs from a vendor that drivers
hand the device. The loader exists to enforce three things:

- **Source policy** — `FwSetSourcePolicy()` controls whether firmware is
  loaded from a built-in package, the FAT32 `/FIRMWARE/` directory, or
  not at all. See [Wireless Firmware](../drivers/Wireless-Firmware.md)
  for the trust model.
- **Trace ring** — every firmware load (request, hit, miss) leaves a
  one-liner in the firmware trace ring, readable with the shell `fw`
  command. The cleanroom-trace exercise in
  [`kernel/diag/crprobe.cpp`](../../kernel/diag/crprobe.cpp) deliberately
  asks for a missing blob to keep the miss path warm.
- **Package format** — `firmware_package.h` parses the
  multi-blob package format that bundles per-device firmware variants
  with a manifest. `FwPackageHasFlag` / `FwPackageLooksLike` answer
  the driver's "does this package contain the variant my device wants?"
  questions before mapping the bytes.

```cpp
loader::Result<span<const u8>> FwLoad(const char* name);
void FwSetSourcePolicy(FwSourcePolicy);
void FwTraceRead(span<FwTraceEntry> out);
```

## Compat Shims

`compat_shim.h` keeps the small list of per-image compat tweaks the
loader honours. v0 entries:

- **Stack-size sidecar** — some PEs expect a 1 MiB stack even though
  the header says 64 KiB. The sidecar lists which image basenames get
  the bump.
- **Debugger-bypass** — PEs that probe `IsDebuggerPresent` and refuse
  to run get a sidecar-controlled "always return FALSE" promise.
- **ETW bypass** — same shape, for Event Tracing for Windows hooks
  that the v0 thunk table doesn't service.

```cpp
void ApplySidecar(loader::LoadedImage&);   // adjust stack / heap before spawn
void ApplyBuffer(span<const u8>&);         // patch known-bad header bytes
bool ShouldIgnoreDebugger(const LoadedImage&);
```

The sidecar table is human-maintained, small, and reviewed alongside
every new PE that needs an entry. Anything that grows to >32 rows is a
sign the underlying ABI surface needs a real fix rather than another
sidecar.

## PE Exports Helper

`pe_exports.h` is the shared walker over a PE's `IMAGE_DIRECTORY_ENTRY_EXPORT`:

```cpp
loader::Result<void*> PeExportFind(const PeImage& img, const char* name);
loader::Result<void*> PeExportFindByOrdinal(const PeImage& img, u16 ordinal);
```

Both `DllResolveExport` and the runtime `GetProcAddress` thunk are thin
wrappers over it. Keeping the walker in one place means
forward-style hint validation and ordinal-vs-name resolution differ
in exactly one TU.

## Capability Gates

Image loading itself is not user-facing — the spawn path is. The
loader assumes the caller has already passed `kCapSpawnExec` (for the
syscalls that spawn a process) and concerns itself only with the bytes.

## Threading and Locking

- The loader is **per-image stateless**: every call takes the image's
  bytes and a fresh `AddressSpace` to populate. No global mutable state.
- Firmware loader trace ring is lock-free (`KEvent`-bounded ring).
- DLL image cache is per-process, kept in the process's `LoadedDlls`
  table.

## Known Limits / GAPs

- **ELF segment load not wired.** `ElfValidate` is in production use;
  the segment-mapping path that calls `mm::AddressSpace::MapRegion` is
  on the next slice.
- **No PE forwarder chains.** A DLL export that forwards to another
  DLL's export resolves to one hop; multi-hop chains fail and need to
  be detected in the parser.
- **DLL TLS is parsed but not initialised.** The PE loader builds the
  TLS template; the per-thread allocator + callback dispatch are still
  on the v0 happy path (see Roadmap).
- **No relocation streaming.** Whole-image relocation runs in one pass
  before the image is handed back. Lazy relocation is not planned.

## Related Pages

- [PE Loader](../subsystems/PE-Loader.md) — PE/COFF detail
- [Win32 DLLs](../subsystems/Win32-DLLs.md) — what the loader resolves
  imports against
- [Win32 Surface Status](../reference/Win32-Surface-Status.md) — per-export
  REAL / STUB / MISSING inventory
- [Wireless Firmware](../drivers/Wireless-Firmware.md) — firmware loader
  consumer
- [Rust Subsystems](../tooling/Rust-Subsystems.md) — `exec_meta_rust`
  crate
- [Memory Management](Memory-Management.md) — where loaders place their
  segments
