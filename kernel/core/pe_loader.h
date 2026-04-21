#pragma once

#include "types.h"

namespace customos::mm
{
struct AddressSpace;
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
    TooSmall,             // Buffer can't hold a DOS stub.
    BadDosMagic,          // First two bytes are not "MZ".
    BadLfanewBounds,      // e_lfanew points past end-of-file.
    BadNtSignature,       // Not "PE\0\0".
    BadMachine,           // Not IMAGE_FILE_MACHINE_AMD64.
    NotPe32Plus,          // OptionalHeader.Magic != 0x20B.
    SectionAlignUnsup,    // SectionAlignment != 4096.
    FileAlignUnsup,       // FileAlignment != 4096.
    SectionCountZero,     // No sections to load.
    OptHeaderOutOfBounds, // SizeOfOptionalHeader shorter than required.
    SectionOutOfBounds,   // Section raw data extends past end-of-file.
    ImportsPresent,       // Import Directory is non-empty (v0 unsupported).
    RelocsNonEmpty,       // Base Reloc Directory is non-empty (v0 unsupported).
    TlsPresent,           // TLS Directory is non-empty (v0 unsupported).
};

const char* PeStatusName(PeStatus s);

/// Validate enough of the PE to be confident v0 can load it.
/// Does not allocate. Returns PeStatus::Ok iff PeLoad will
/// succeed on the same buffer.
PeStatus PeValidate(const u8* file, u64 file_len);

struct PeLoadResult
{
    bool ok;
    u64 entry_va;  // ImageBase + AddressOfEntryPoint
    u64 stack_va;  // Lowest VA of the stack page.
    u64 stack_top; // rsp at ring-3 entry (stack_va + kPageSize).
    u64 image_base;
    u64 image_size;
};

/// Load a validated PE into `as`. On failure, the AS may hold
/// partial mappings — caller must AddressSpaceRelease. Mirror
/// of ElfLoad in shape so SpawnPeFile can drop straight into
/// the existing ring3 spawn plumbing.
PeLoadResult PeLoad(const u8* file, u64 file_len, customos::mm::AddressSpace* as);

// IMAGE_SCN_* bits exposed for any caller that wants to decode
// section flags on its own (readelf-style tools later).
inline constexpr u32 kScnCntCode = 0x00000020;
inline constexpr u32 kScnMemExecute = 0x20000000;
inline constexpr u32 kScnMemRead = 0x40000000;
inline constexpr u32 kScnMemWrite = 0x80000000;

} // namespace customos::core
