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

// Layout pinned by the matching Rust #[repr(C)] struct. The C++
// wrappers do a field-by-field copy on the way out so layout drift
// can't silently break the loaders.
struct DuetosPePrefix
{
    u32 nt_base;       // file offset of "PE\0\0"
    u16 section_count; // FileHeader.NumberOfSections
    u16 _pad;
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
}

} // namespace duetos::loader::exec_meta
