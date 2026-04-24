#pragma once

#include "pe_exports.h"
#include "types.h"

namespace customos::mm
{
struct AddressSpace;
}

namespace customos::core
{

/*
 * CustomOS DLL loader — stage 2 skeleton.
 *
 * Builds on the EAT parser (`pe_exports.h`) to turn a PE/COFF
 * DLL buffer into a mapped image + parsed export table. The
 * eventual stage-2 goal is:
 *
 *   - A real `LoadLibraryW` that maps ntdll / kernel32 / user32
 *     per-process from on-disk DLLs and lets the IAT resolver
 *     patch via the DLL's EAT, retiring the flat `kStubsTable`
 *     lookup currently done by `Win32StubsLookup`.
 *
 * This header delivers only the first slice of that: **parse +
 * map + parse EAT**. Import resolution of the DLL itself (which
 * may require recursive DLL loads for forwarders) is intentionally
 * deferred to a later slice and will live in the same header.
 *
 * Scope of v0 DllLoad:
 *   - Reject non-DLL PEs (Characteristics bit
 *     IMAGE_FILE_DLL must be set).
 *   - Map every section into `as` at `ImageBase + VirtualAddress`
 *     with PE-derived flags (R/W/X).
 *   - Map the header page RO+NX at ImageBase so `__ImageBase`
 *     lookups work from ring 3.
 *   - Apply base relocations with the caller-supplied delta.
 *     DLLs almost always need this — the preferred base
 *     routinely collides across two DLLs and ASLR is required
 *     to avoid it.
 *   - Parse the Export Directory via `PeParseExports` and
 *     populate `DllImage.exports`.
 *
 * Not in scope yet (deferred):
 *   - DLL imports (walking the DLL's own IAT).
 *   - DllMain dispatch (DLL_PROCESS_ATTACH).
 *   - TLS callbacks in the DLL.
 *   - Refcounted DLL cache (one DLL shared across processes).
 *   - Freeing / unmapping a DLL from an AS.
 *
 * Context: kernel task. Mirrors `PeLoad`'s thread-safety
 * contract — safe from any caller that can hold the AS
 * creation lock.
 */

enum class DllLoadStatus : u8
{
    Ok = 0,
    HeaderParseFailed,  // PE headers are malformed
    NotADll,            // IMAGE_FILE_DLL bit clear in FileHeader.Characteristics
    BadMachine,         // Machine != AMD64
    SectionAlignUnsup,  // SectionAlignment != 4096
    SectionOutOfBounds, // Section raw data past EOF
    MapFailed,          // AddressSpaceMapUserPage refused a page
    RelocFailed,        // Base reloc directory is malformed
    ExportParseFailed,  // EAT parse reported a Bad* status (we let
                        // NoExportDirectory through — a DLL with zero
                        // exports is legal, just not useful)
};

const char* DllLoadStatusName(DllLoadStatus s);

/// A loaded DLL image. Held by the per-process DLL table (not
/// yet implemented; stage-2 follow-up). Borrows ownership of
/// the input file buffer — keep that alive for the lifetime of
/// the image.
struct DllImage
{
    const u8* file; // borrowed source bytes
    u64 file_len;   // bytes
    u64 base_va;    // final base VA (preferred base + aslr_delta)
    u64 size;       // SizeOfImage after alignment
    u32 entry_rva;  // DllMain RVA (0 if no entry; not yet dispatched)

    PeExports exports; // parsed export table
    bool has_exports;
};

struct DllLoadResult
{
    DllLoadStatus status;
    DllImage image;
};

/// Load a DLL into `as`:
///   1. Parse + validate headers.
///   2. Confirm IMAGE_FILE_DLL bit is set.
///   3. Map headers + every section.
///   4. Apply base relocations using `aslr_delta` as the delta
///      from the preferred ImageBase.
///   5. Parse the Export Directory and populate exports.
///
/// On failure, `as` may hold partial mappings — the caller is
/// responsible for releasing the AS (mirrors `PeLoad`'s
/// contract). On success, the IAT for the DLL's OWN imports is
/// still unresolved; a later slice will recursively resolve them.
DllLoadResult DllLoad(const u8* file, u64 file_len, customos::mm::AddressSpace* as, u64 aslr_delta);

/// Look up an export by name in a loaded DLL image and return
/// the absolute VA to jump to. Returns 0 on miss or on a
/// forwarder (the caller must chase forwarders through a DLL
/// cache it controls — not yet implemented).
u64 DllResolveExport(const DllImage& dll, const char* name);

/// As above, but by ordinal.
u64 DllResolveOrdinal(const DllImage& dll, u32 ordinal);

/// Boot-time smoke test for the EAT parser + DLL loader.
/// Exercises a purpose-built 2 KiB DLL embedded in the kernel
/// (`generated_customdll.h`): parses its EAT directly, loads it
/// into a scratch AddressSpace, and verifies name + ordinal
/// lookups all return VAs inside the mapped image range. Emits
/// `[dll-test] ...` lines to the serial log. Failure prints
/// `[dll-test] FAIL <step>` but does not panic — the boot log
/// is the diagnostic surface.
void DllLoaderSelfTest();

} // namespace customos::core
