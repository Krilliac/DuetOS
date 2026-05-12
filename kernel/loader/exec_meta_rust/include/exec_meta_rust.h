// DuetOS executable-image metadata C FFI — hand-written. Mirrors
// kernel/loader/exec_meta_rust/src/lib.rs.
//
// Two validators, both bounds-checked slice traversal in Rust.
// The C++ loaders keep the mapping logic; this layer answers only
// "is the header well-formed enough to map?"

#pragma once

#include "util/types.h"

namespace duetos::loader::exec_meta
{

// Layouts pinned by the matching Rust #[repr(C)] structs. The C++
// wrappers do a field-by-field copy on the way out so layout drift
// can't silently break the loaders.
struct DuetosPePrefix
{
    u32 nt_base;       // file offset of "PE\0\0"
    u16 section_count; // FileHeader.NumberOfSections
    u16 _pad;
};

struct DuetosPeImage
{
    u32 nt_base;
    u16 section_count;
    u16 opt_header_size;
    u32 opt_base;
    u32 image_size;
    u32 entry_rva;
    u32 _pad1;
    u64 image_base;
    u32 section_base;
    u32 _pad2;
};

extern "C"
{
    /// Validate an ELF64 file (header + PT_LOAD bounds). Returns a
    /// `u32` value that maps 1:1 onto `duetos::core::ElfStatus`
    /// (0 = Ok, 1 = TooSmall, …, 10 = UnalignedSegment). The C++
    /// caller `static_cast`s it back.
    u32 duetos_exec_meta_elf_validate(const u8* buf, usize len);

    /// Validate the PE/COFF prefix: DOS stub, e_lfanew bounds, PE
    /// signature, FileHeader.Machine == AMD64. On success the
    /// `*out_prefix` struct carries the NT-base file offset and
    /// the section count; on failure `*out_status` carries one of
    /// the first six PeStatus enumerators (0 = Ok, 1 = TooSmall,
    /// 2 = BadDosMagic, 3 = BadLfanewBounds, 4 = BadNtSignature,
    /// 5 = BadMachine).
    ///
    /// The deeper optional-header / section-table / data-directory
    /// validation continues to live in
    /// kernel/loader/pe_loader.cpp::ParseHeaders; the prefix check
    /// here just gates the early "is this an AMD64 PE/COFF image
    /// at all?" decision.
    bool duetos_exec_meta_pe_validate_prefix(const u8* buf, usize len, DuetosPePrefix* out_prefix, u32* out_status);

    /// Validate everything the PE prefix walker checks, plus the
    /// optional-header magic (PE32+), section + file alignment,
    /// image base + size in canonical low half, section-table
    /// bounds, and per-section raw extent fit.
    ///
    /// On success, `*out_image` carries the data the loader needs
    /// to map the image: `nt_base`, `section_count`,
    /// `opt_header_size`, `opt_base`, `image_size`, `entry_rva`,
    /// `image_base`, `section_base`. On failure, `*out_status`
    /// carries one of the PeStatus enumerators
    /// (byte-identical to the C++ `duetos::core::PeStatus` enum:
    /// 0..5 are the prefix codes, 6 = NotPe32Plus,
    /// 7 = SectionAlignUnsup, 8 = FileAlignUnsup,
    /// 9 = SectionCountZero, 10 = OptHeaderOutOfBounds,
    /// 11 = SectionOutOfBounds, 17 = ImageBaseOutOfRange).
    ///
    /// The deeper data-directory walks (Imports / BaseReloc / TLS)
    /// still live in `kernel/loader/pe_loader.cpp` for now.
    bool duetos_exec_meta_pe_validate_image(const u8* buf, usize len, DuetosPeImage* out_image, u32* out_status);
}

} // namespace duetos::loader::exec_meta
