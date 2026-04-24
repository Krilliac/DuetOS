#pragma once

#include "dll_loader.h"
#include "types.h"

namespace customos::mm
{
struct AddressSpace;
}

namespace customos::core
{
struct Process;
}

/*
 * CustomOS PE/COFF loader — v0.
 *
 * Pillar #1 of the project is "run Windows PE executables
 * natively." This is the v0 slice of that: enough of the loader
 * to bring up a freestanding PE produced by clang + lld-link,
 * with no imports, no base relocations, no TLS callbacks, no
 * exception directory, no delay-load. Such a PE is purely a
 * container for mapped bytes and an entry point — precisely
 * what a first loader should target.
 *
 * Scope (explicit):
 *
 *   - DOS stub header ("MZ") recognition + e_lfanew redirect.
 *   - NT Headers: PE\0\0 signature, FileHeader.Machine ==
 *     IMAGE_FILE_MACHINE_AMD64.
 *   - Optional Header (PE32+): ImageBase, AddressOfEntryPoint,
 *     SectionAlignment, FileAlignment, SizeOfImage,
 *     SizeOfHeaders.
 *   - Section Table: for each section, map SizeOfRawData bytes
 *     from file[PointerToRawData ..] into
 *     [ImageBase + VirtualAddress ..] with flags derived from
 *     IMAGE_SCN_MEM_{EXECUTE,READ,WRITE}.
 *
 * Non-scope (v0 rejects these):
 *
 *   - Import Directory with any descriptors — we require an
 *     empty IAT. Delay-load likewise.
 *   - Base Relocations — we require ImageBase to be usable
 *     verbatim. SizeOfImage must fit at ImageBase.
 *   - TLS, exception handlers, bound imports, COM descriptor.
 *   - Non-page-aligned SectionAlignment / FileAlignment — the
 *     build toolchain passes /align:4096 /filealign:4096 so
 *     every raw offset equals the RVA. A future slice will
 *     handle real filealign=0x200 PEs with cross-page copies.
 *
 * Stack handling mirrors ElfLoad: one writable, NX ring-3 page
 * mapped at kV0StackVa (0x7FFFE000). v0 does not honour the
 * Optional Header's SizeOfStackReserve / SizeOfStackCommit.
 *
 * Context: kernel task. Safe from any caller that can hold the
 * AS creation lock.
 */

namespace customos::core
{

enum class PeStatus : u8
{
    Ok = 0,
    TooSmall,                // Buffer can't hold a DOS stub.
    BadDosMagic,             // First two bytes are not "MZ".
    BadLfanewBounds,         // e_lfanew points past end-of-file.
    BadNtSignature,          // Not "PE\0\0".
    BadMachine,              // Not IMAGE_FILE_MACHINE_AMD64.
    NotPe32Plus,             // OptionalHeader.Magic != 0x20B.
    SectionAlignUnsup,       // SectionAlignment != 4096.
    FileAlignUnsup,          // FileAlignment not a power-of-2 in [512, 4096].
    SectionCountZero,        // No sections to load.
    OptHeaderOutOfBounds,    // SizeOfOptionalHeader shorter than required.
    SectionOutOfBounds,      // Section raw data extends past end-of-file.
    ImportsPresent,          // Imports non-empty AND at least one unresolved stub.
    RelocsNonEmpty,          // Base Reloc Directory is non-empty (v0 unsupported).
    TlsPresent,              // TLS Directory is non-empty. Callback array may be
                             // empty (MSVC's placeholder .tls section) or carry
                             // actual process-startup callbacks. PeLoad tolerates
                             // the former and rejects the latter via
                             // `TlsCallbacksUnsupported` below.
    TlsCallbacksUnsupported, // TLS Directory has >= 1 non-null callback VA in
                             // its callbacks array. v0 does not execute them
                             // (the ring-3 thunk that'd call each callback
                             // before entry is a separate slice). Failing the
                             // load beats silently skipping init a real
                             // Windows PE's main() might depend on.
    StubsPageAllocFail,      // Could not allocate the Win32 stubs page during load.
};

const char* PeStatusName(PeStatus s);

/// Validate enough of the PE to be confident v0 can load it.
/// Does not allocate. Returns PeStatus::Ok iff PeLoad will
/// succeed on the same buffer.
PeStatus PeValidate(const u8* file, u64 file_len);

/// Dump a human-readable diagnostic report of the PE image to
/// the serial console: DOS + NT header summary, section table,
/// import directory (every DLL + function name), base-reloc
/// summary, TLS summary. Intended for the "we can't load this
/// yet, but here's exactly what's missing" path — called before
/// PeValidate in the spawn path so the log shows the full gap
/// even when the load is rejected. Safe to call on any
/// well-enough-formed PE; bails out silently on malformed
/// bytes.
void PeReport(const u8* file, u64 file_len);

struct PeLoadResult
{
    bool ok;
    bool imports_resolved; // true iff this PE had imports the resolver patched
                           // — SpawnPeFile uses this flag to decide whether to
                           // stand up the per-process Win32 heap. Freestanding
                           // PEs (hello.exe) get ok=true, imports_resolved=false
                           // and skip heap init to keep their frame footprint
                           // down.
    u64 entry_va;          // ImageBase + AddressOfEntryPoint
    u64 stack_va;          // Lowest VA of the stack page.
    u64 stack_top;         // rsp at ring-3 entry (stack_va + kPageSize).
    u64 image_base;
    u64 image_size;
    u64 teb_va; // VA of the per-task TEB page (0 if PE has no
                // imports — the freestanding hello.exe path).
                // Non-zero value is the GSBASE to load before
                // ring-3 entry.
};

/// Load a validated PE into `as`. On failure, the AS may hold
/// partial mappings — caller must AddressSpaceRelease. Mirror
/// of ElfLoad in shape so SpawnPeFile can drop straight into
/// the existing ring3 spawn plumbing.
///
/// `program_name` is copied into the proc-env page as argv[0]
/// when the PE has imports (see `Win32ProcEnvPopulate`). Pass
/// the caller-facing name (`/bin/winkill.exe`, the
/// SpawnRing3Task name, …); PeLoad will truncate to
/// `kProcEnvStringBudget - 1` bytes. Null or empty falls back
/// to "a.exe" — the conventional Windows "no name recorded"
/// placeholder.
///
/// `aslr_delta` is added to the PE's preferred ImageBase before
/// any section is mapped. Must be 64 KiB aligned (Win32 convention
/// + our own page granularity). Passing 0 disables ASLR and loads
/// at the preferred base (the v0 behaviour). The caller is
/// responsible for not picking a delta that pushes the image into
/// reserved VA regions (stack at 0x7FFF0000, win32 heap at
/// 0x50000000, etc.).
///
/// Stage-2 slice 6 — `preloaded_dlls` / `preloaded_dll_count`:
/// optional array of DLL images the caller has ALREADY loaded
/// into `as` via `DllLoad`. ResolveImports consults this array
/// BEFORE the flat `Win32StubsLookup` table: for every
/// {dll_name, fn_name} import, if a preloaded DLL matches the
/// import's dll_name (case-insensitive) and exports fn_name,
/// the IAT slot is patched with the DLL's export VA directly —
/// bypassing the trampoline page. Misses fall through to
/// Win32StubsLookup so existing PEs are unaffected. Pass
/// nullptr / 0 to disable (the pre-slice-6 behaviour).
PeLoadResult PeLoad(const u8* file, u64 file_len, customos::mm::AddressSpace* as, const char* program_name,
                    u64 aslr_delta, const DllImage* preloaded_dlls = nullptr, u64 preloaded_dll_count = 0);

/// Transfer any (IAT-slot-VA, function-name) pairs the loader
/// staged for catch-all imports during the most recent PeLoad
/// into `proc->win32_iat_misses`. Call once right after
/// ProcessCreate. Idempotent: drains the staging buffer to empty.
void PeLoadDrainIatMisses(customos::core::Process* proc);

// IMAGE_SCN_* bits exposed for any caller that wants to decode
// section flags on its own (readelf-style tools later).
inline constexpr u32 kScnCntCode = 0x00000020;
inline constexpr u32 kScnMemExecute = 0x20000000;
inline constexpr u32 kScnMemRead = 0x40000000;
inline constexpr u32 kScnMemWrite = 0x80000000;

} // namespace customos::core
