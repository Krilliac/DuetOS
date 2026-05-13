#pragma once

#include "loader/dll_loader.h"
#include "util/types.h"

namespace duetos::mm
{
struct AddressSpace;
}

namespace duetos::core
{
struct Process;
}

/*
 * DuetOS PE/COFF loader — v0.
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

namespace duetos::core
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
    ImageBaseOutOfRange,     // ImageBase or ImageBase+SizeOfImage lands outside the canonical
                             // user low half (>0x00007FFFFFFFFFFF). A malicious PE with a
                             // kernel-half ImageBase would otherwise drive AddressSpaceMapUserPage
                             // into PanicAs and DoS the kernel from any execve-style spawn path.
    Pe32ExecutionNotReady,   // OptionalHeader.Magic == 0x10B (PE32 / i386). The image parses
                             // and PeReport can walk it (diagnostic-load), but actual MapAndRun
                             // is gated until the 32-bit user-CS, syscall-ABI, and i386 DLL
                             // set land. Distinct from NotPe32Plus so callers can tell "rejected
                             // because of format" (NotPe32Plus, malformed magic) apart from
                             // "rejected because of policy" (this).
};

const char* PeStatusName(PeStatus s);

/// Validate enough of the PE to be confident v0 can load it.
/// Does not allocate. Returns PeStatus::Ok iff PeLoad will
/// succeed on the same buffer.
PeStatus PeValidate(const u8* file, u64 file_len);

/// True iff the PE's Optional Header DllCharacteristics field
/// has IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE (bit 0x0040)
/// set. Spawn paths gate per-image ASLR on this flag — Win32's
/// contract is that PEs without `/DYNAMICBASE` load at their
/// preferred base. Returns false on malformed input rather
/// than throwing.
bool PeIsDynamicBase(const u8* file, u64 file_len);

/// Read the optional-header `ImageBase` (preferred base VA) +
/// `SizeOfImage` from `file`. Returns 0 on parse failure so the
/// caller can fall back to a default. Used by pre-load loops to
/// reserve non-overlapping regions BEFORE calling DllLoad — the
/// alternative is to map pages, detect a collision, and rewind,
/// which is far more expensive than parsing the header.
u64 PePreferredBaseOf(const u8* file, u64 file_len);
u64 PeImageSizeOf(const u8* file, u64 file_len);

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

/// Materialise a short PE summary (header counts, image base,
/// entry RVA, image size, section count, parse status) into a
/// caller-supplied writer. Mirrors the first ~10 lines of
/// `PeReport` but emits via a callback instead of the serial
/// port — used by /sys/inspect/<basename> to populate a static
/// ramfs file at boot. The full disasm + import dump in
/// PeReport stays serial-only; the summary is what fits into
/// a few-KiB inspect buffer.
using PeReportFn = void (*)(const char* chunk);
void PeQuickSummaryTo(PeReportFn writer, const u8* file, u64 file_len);

struct PeLoadResult
{
    bool ok;
    bool imports_resolved; // true iff this PE had imports the resolver patched
                           // — SpawnPeFile uses this flag to decide whether to
                           // stand up the per-process Win32 heap. Freestanding
                           // PEs (hello.exe) get ok=true, imports_resolved=false
                           // and skip heap init to keep their frame footprint
                           // down.
    bool is_pe32;          // true for PE32 (i386), false for PE32+ (AMD64).
                           // Drives the ring-3 entry-mode pick downstream:
                           // PE32 enters via EnterUserMode32 (compat mode,
                           // CS=0x3B), PE32+ via EnterUserModeWithGs.
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
/// `preloaded_dlls` / `preloaded_dll_count`:
/// optional array of DLL images the caller has ALREADY loaded
/// into `as` via `DllLoad`. ResolveImports consults this array
/// BEFORE the flat `Win32ThunksLookup` table: for every
/// {dll_name, fn_name} import, if a preloaded DLL matches the
/// import's dll_name (case-insensitive) and exports fn_name,
/// the IAT slot is patched with the DLL's export VA directly —
/// bypassing the trampoline page. Misses fall through to
/// Win32ThunksLookup so existing PEs are unaffected. Pass
/// nullptr / 0 to disable (the pre-DLL-loader behaviour).
PeLoadResult PeLoad(const u8* file, u64 file_len, duetos::mm::AddressSpace* as, const char* program_name,
                    u64 aslr_delta, const DllImage* preloaded_dlls = nullptr, u64 preloaded_dll_count = 0);

/// Transfer any (IAT-slot-VA, function-name) pairs the loader
/// staged for catch-all imports during the most recent PeLoad
/// into `proc->win32_iat_misses`. Call once right after
/// ProcessCreate. Idempotent: drains the staging buffer to empty.
void PeLoadDrainIatMisses(duetos::core::Process* proc);

/// Resolve `dll_name!fn_name` against an array of preloaded DLL
/// images. Walks each image's EAT and chases forwarder exports
/// recursively (both name-form "Dll.Func" and ordinal-form
/// "Dll.#N"), bounded against forwarder cycles. Returns true and
/// writes the absolute target VA on success; returns false if
/// the DLL isn't in the array, the function isn't exported, or
/// a forwarder chain leaves the array.
///
/// Used both by PeLoad's IAT resolver and by the per-process
/// GetProcAddress path so user-mode lookups see the same
/// forwarder behaviour as kernel-mode imports.
bool PeResolveViaDlls(const char* dll_name, const char* fn_name, const DllImage* dlls, u64 count, u64* out_va);

// IMAGE_SCN_* bits exposed for any caller that wants to decode
// section flags on its own (readelf-style tools later).
inline constexpr u32 kScnCntCode = 0x00000020;
inline constexpr u32 kScnMemExecute = 0x20000000;
inline constexpr u32 kScnMemRead = 0x40000000;
inline constexpr u32 kScnMemWrite = 0x80000000;

} // namespace duetos::core
