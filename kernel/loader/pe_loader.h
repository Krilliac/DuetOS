#pragma once

#include "loader/dll_loader.h"
#include "mm/address_space.h"
#include "proc/user_stack.h"
#include "util/types.h"

namespace duetos::core
{
struct Process;
}

/*
 * DuetOS PE/COFF loader.
 *
 * Pillar #1 of the project is "run Windows PE executables
 * natively." This is the loader half of that: it turns an
 * untrusted PE image into a mapped, fixed-up, ring-3-ready
 * address space.
 *
 * Handled:
 *
 *   - DOS stub header ("MZ") recognition + e_lfanew redirect.
 *   - NT Headers: the four-byte "PE" + two NUL signature, and
 *     FileHeader.Machine. PE32+
 *     (AMD64) runs; PE32 (i386) parses and maps but its ring-3
 *     entry is gated (PeStatus::Pe32ExecutionNotReady).
 *   - Optional Header: ImageBase, AddressOfEntryPoint,
 *     SectionAlignment, FileAlignment, SizeOfImage, SizeOfHeaders,
 *     DllCharacteristics (per-image ASLR opt-in).
 *   - Section Table: SizeOfRawData bytes copied from
 *     file[PointerToRawData ..] to [load_base + VirtualAddress ..]
 *     with flags derived from IMAGE_SCN_MEM_{EXECUTE,READ,WRITE},
 *     W^X enforced.
 *   - Base Relocations (directory 5) — the image is relocatable, so
 *     spawn can apply an ASLR delta.
 *   - Imports (directory 1) — every IAT slot bound against the
 *     preloaded DLL export tables, the api-set contract table, and
 *     the kernel thunk page.
 *   - Delay-load imports (directory 13) — bound EAGERLY through the
 *     same ladder, so the image's own __delayLoadHelper2 never
 *     runs. See wiki/reference/Design-Decisions.md.
 *   - TLS (directory 9) — .tls template copied per-thread,
 *     TEB.ThreadLocalStoragePointer + _tls_index wired, and the
 *     AddressOfCallBacks array invoked in ring 3 via a generated
 *     trampoline before the entry point.
 *   - Load Config (directory 10) — the /GS `__security_cookie` is
 *     seeded per-image from the kernel RNG.
 *
 * Not handled:
 *
 *   - Bound imports (directory 11) and the delay-load bound IAT:
 *     both are prebind caches, ignored in favour of a real bind.
 *   - COM descriptor (directory 14) — no managed images.
 *   - The VC6 absolute-VA delay-load descriptor form (dlattrRva
 *     clear); those descriptors are skipped, not bound.
 *
 * Stack handling honours the Optional Header: the image's
 * SizeOfStackReserve / SizeOfStackCommit (both clamped) lay out a
 * demand-grown reservation ending at core::kUserStackTopVa, of
 * which only the top is committed at load. The #PF handler grows
 * it a page at a time and a guard page below the reservation
 * keeps a runaway fatal — see kernel/proc/user_stack.h.
 *
 * Context: kernel task. Safe from any caller that can hold the
 * AS creation lock.
 */

namespace duetos::core
{

enum class PeStatus : u8
{
    Ok = 0,
    TooSmall,              // Buffer can't hold a DOS stub.
    BadDosMagic,           // First two bytes are not "MZ".
    BadLfanewBounds,       // e_lfanew points past end-of-file.
    BadNtSignature,        // Not "PE\0\0".
    BadMachine,            // Not IMAGE_FILE_MACHINE_AMD64.
    NotPe32Plus,           // OptionalHeader.Magic != 0x20B.
    SectionAlignUnsup,     // SectionAlignment != 4096.
    FileAlignUnsup,        // FileAlignment not a power-of-2 in [512, 4096].
    SectionCountZero,      // No sections to load.
    OptHeaderOutOfBounds,  // SizeOfOptionalHeader shorter than required.
    SectionOutOfBounds,    // Section raw data extends past end-of-file.
    ImportsPresent,        // Imports non-empty AND at least one unresolved stub.
    RelocsNonEmpty,        // Base Reloc Directory is non-empty (v0 unsupported).
    TlsPresent,            // TLS Directory is non-empty. Not a reject reason:
                           // PeLoad copies the .tls template, wires
                           // TEB.ThreadLocalStoragePointer, writes _tls_index,
                           // and runs AddressOfCallBacks through a generated
                           // ring-3 trampoline before the entry point.
    StubsPageAllocFail,    // Could not allocate the Win32 stubs page during load.
    ImageBaseOutOfRange,   // ImageBase or ImageBase+SizeOfImage lands outside the canonical
                           // user low half (>0x00007FFFFFFFFFFF). A malicious PE with a
                           // kernel-half ImageBase would otherwise drive AddressSpaceMapUserPage
                           // into PanicAs and DoS the kernel from any execve-style spawn path.
    Pe32ExecutionNotReady, // OptionalHeader.Magic == 0x10B (PE32 / i386). The image parses
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

/// True iff the PE bytes parse as a PE32 (i386) image — OptHdrMagic
/// == 0x10B. False for PE32+ (AMD64, OptHdrMagic == 0x20B) and for
/// malformed inputs. Lets SpawnPeFile pick the bitness-correct
/// preload set BEFORE running the full PeLoad parser. Cheap: just
/// the DOS stub + COFF header walk that PeValidate's prefix path
/// already does.
bool PeIsPe32(const u8* file, u64 file_len);

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

/// Walk an already-mapped PE / DLL's import directory and
/// patch each IAT slot in place. Used by `DllLoad` consumers
/// to resolve a vendored DLL's own imports against the same
/// preloaded DLL set the main PE sees — without this call,
/// the DLL is loaded but its own IAT contains the on-disk
/// (zero / placeholder) values and any export that calls one
/// of its imports crashes on the first indirect call.
///
/// Returns true iff every import resolved. Returns false on a
/// header parse failure or an unresolvable import that had no
/// catch-all fallback. The pattern matches `PeLoad`'s
/// internal import-walk; this is the same code reused on a
/// loaded-DLL basis.
bool PeResolveImportsForLoadedImage(const u8* file, u64 file_len, duetos::mm::AddressSpace* as,
                                    const DllImage* preloaded_dlls, u64 preloaded_dll_count);

/// True iff `dll_name` is a Windows API-set contract name —
/// "api-ms-win-..." or "ext-ms-win-..." (case-insensitive). These
/// are not real DLLs: they are name contracts whose implementation
/// lives in one of the base DLLs the loader already preloads
/// (kernel32 / kernelbase / ntdll / ...). mingw's import libs
/// (e.g. -lsynchronization) emit imports against these contract
/// names for modern APIs (WaitOnAddress, condition variables, ...),
/// and Chrome links the same way.
///
/// Exposed because every code path that might otherwise go looking
/// for a FILE by that name must not — no filesystem, here or on
/// Windows, has one.
bool IsApiSetContract(const char* dll_name);

/// Callback for `PeEnumImportDlls`. `dll_name` is a bounds-checked
/// pointer INTO the caller's file buffer (never null, always NUL
/// terminated inside the buffer) and is only valid for the duration
/// of the call. Return false to stop the walk early.
using PeImportDllFn = bool (*)(const char* dll_name, void* ctx);

/// Enumerate the DLL names in a PE's import directory without
/// touching an address space. Every RVA is validated against
/// `file_len` before it is dereferenced, so a hostile / truncated
/// image stops the walk instead of reading out of bounds.
///
/// Returns the number of descriptors visited. A PE with no import
/// directory returns 0 — that is not an error.
///
/// The side-by-side DLL resolver (`loader/sxs_dll.h`) uses this to
/// learn WHICH DLLs an image wants before deciding what to read off
/// the volume; the import binder itself still walks the directory
/// again inside `ResolveImports`.
u32 PeEnumImportDlls(const u8* file, u64 file_len, PeImportDllFn fn, void* ctx);

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
    u64 stack_va;          // Lowest COMMITTED VA of the ring-3 stack.
    u64 stack_top;         // One-past-last byte of the reservation; rsp at
                           // ring-3 entry is derived from it by the spawn path.
    // Full reservation descriptor (top / reserve_lo / commit_lo /
    // guard_lo). SpawnPeFile transfers this and the capability below
    // to the private primary Task before scheduler publication; the #PF
    // handler accepts only that current Task's pair. See user_stack.h.
    UserStackRange stack;
    // Exact AS-scoped capability reserved before the first stack page was
    // committed. Spawn transfers it to the private primary Task; loader or
    // spawn failure destroys/releases it without ever publishing a raw VA
    // window as ownership.
    duetos::mm::AddressSpaceReservationToken stack_reservation;
    u64 image_base;
    u64 image_size;
    u64 teb_va; // VA of the per-task TEB page (0 if PE has no
                // imports — the freestanding hello.exe path).
                // Non-zero value is the GSBASE to load before
                // ring-3 entry.

    // Static-TLS template descriptor (T6-01). Filled by
    // SetupStaticTls when the image has a TLS directory; copied
    // onto Process by the spawn path so SYS_THREAD_CREATE can
    // replicate per-thread TEB + TLS block + DLL_THREAD_ATTACH.
    bool tls_present;
    u64 tls_tmpl_src_va;   // mapped (relocated) template start
    u64 tls_tmpl_raw;      // bytes to copy
    u64 tls_tmpl_zerofill; // zero tail bytes
    u64 tls_index_va;      // *_tls_index VA (already 0 for v0)
    u32 tls_cb_count;
    u64 tls_callbacks[16]; // absolute (relocated) callback VAs
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
