#pragma once

#include "util/types.h"

// Forward-declare mm::AddressSpace — ElfLoad takes one without
// pulling address_space.h into every consumer of this header.
namespace duetos::mm
{
struct AddressSpace;
}

/*
 * DuetOS ELF64 loader — v0.
 *
 * Parses and (eventually) loads x86_64 little-endian ELF64
 * files. v0 scope is "validate + enumerate PT_LOAD segments";
 * actual ring-3 spawn via ElfLoad is the next slice when the
 * user toolchain lands.
 *
 * Every function is purely a byte-buffer walker — no memory
 * allocation, no MMU calls. The buffer must outlive the
 * callback invocations. Shell commands (`readelf`, `exec`)
 * are the current consumers.
 *
 * Context: kernel. Safe from any task-level caller.
 */

namespace duetos::core
{

enum class ElfStatus : u8
{
    Ok = 0,
    TooSmall,           // Buffer smaller than the 64-byte header.
    BadMagic,           // Not "\x7FELF".
    NotElf64,           // ei_class != ELFCLASS64.
    NotLittleEndian,    // ei_data != ELFDATA2LSB.
    BadVersion,         // ei_version != EV_CURRENT.
    BadMachine,         // e_machine != EM_X86_64.
    NoProgramHeaders,   // e_phoff==0 or e_phnum==0.
    HeaderOutOfBounds,  // Program header table past end-of-file.
    SegmentOutOfBounds, // PT_LOAD p_offset + p_filesz past end-of-file.
    UnalignedSegment,   // p_offset % p_align != p_vaddr % p_align.
};

const char* ElfStatusName(ElfStatus s);

/// Validate an ELF file's header + program-header table. Does
/// NOT touch segment contents. Returns ElfStatus::Ok if the
/// file is well-formed enough to iterate segments.
ElfStatus ElfValidate(const u8* file, u64 file_len);

/// Read `e_entry` from a validated ELF. Undefined behaviour if
/// the buffer isn't valid per ElfValidate.
u64 ElfEntry(const u8* file);

/// Read `e_phnum` / `e_phentsize` / `e_phoff` into out-params.
void ElfProgramHeaderInfo(const u8* file, u64* phoff_out, u16* phnum_out, u16* phentsize_out);

/// One PT_LOAD segment as the caller needs to process it.
struct ElfSegment
{
    u64 file_offset; // byte offset of segment data inside `file`
    u64 vaddr;       // virtual address the segment wants to land at
    u64 filesz;      // bytes to copy from `file[file_offset]`
    u64 memsz;       // total bytes in memory (zero-fill memsz - filesz)
    u64 align;       // p_align
    u8 flags;        // PF_R (4) | PF_W (2) | PF_X (1), bitwise OR
    u8 _pad[7];
};

/// Walk the PT_LOAD program headers. `cb` is invoked once per
/// segment. Non-PT_LOAD entries (NOTE, GNU_STACK, etc.) are
/// skipped. Returns the number of PT_LOAD segments visited.
using ElfSegmentCb = void (*)(const ElfSegment& seg, void* cookie);
u32 ElfForEachPtLoad(const u8* file, u64 file_len, ElfSegmentCb cb, void* cookie);

// PF_* flag bits exposed so callers can decode ElfSegment::flags
// without rolling their own masks.
inline constexpr u8 kElfPfX = 0x1;
inline constexpr u8 kElfPfW = 0x2;
inline constexpr u8 kElfPfR = 0x4;

// ---------------------------------------------------------------
// ElfLoad — populate an AddressSpace from a validated ELF.
//
// For each PT_LOAD segment, allocates one frame per 4 KiB page in
// [vaddr & ~0xFFF, (vaddr + memsz + 0xFFF) & ~0xFFF), copies the
// relevant slice of file[p_offset..p_offset+p_filesz) into it
// (zero-padding bytes in the memsz-but-not-filesz tail), and
// installs the mapping into `as` with flags derived from
// p_flags (R/W/X → kPageWritable / !kPageNoExecute; the U bit is
// forced on by AddressSpaceMapUserPage).
//
// Also allocates + maps one stack page at a fixed v0 VA
// (0x7FFFE000, top of canonical low half minus a guard). Future:
// per-process stack base, growable stacks.
//
// On any failure (invalid ELF, AllocateFrame OOM) returns
// {ok=false}; partial mappings are NOT rolled back — caller must
// AddressSpaceRelease the AS to free anything that got installed.
// ---------------------------------------------------------------

struct ElfLoadResult
{
    bool ok;
    u64 entry_va;  // where to set rip (= e_entry from the ELF)
    u64 stack_va;  // lowest VA of the stack page
    u64 stack_top; // rsp at ring-3 entry (= stack_va + kPageSize)
};

/// Load a validated ELF image into `as`. Returns {ok=true, ...} on
/// success. On failure, the AddressSpace may contain partial state
/// — caller should AddressSpaceRelease it.
ElfLoadResult ElfLoad(const u8* file, u64 file_len, duetos::mm::AddressSpace* as);

} // namespace duetos::core
