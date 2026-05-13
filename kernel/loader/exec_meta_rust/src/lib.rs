//! DuetOS executable-image metadata validators.
//!
//! Two byte-walkers: a full ELF64 header / PT_LOAD validator
//! that the C++ loader can call instead of its own `ElfValidate`,
//! and a PE prefix validator that covers the early "is this an
//! AMD64 PE/COFF image at all?" gate.
//!
//! Every walker uses bounds-checked slice indexing + `checked_add`
//! for offset arithmetic so attacker-crafted offsets cannot wrap
//! into a false success.

#![no_std]

use core::{ptr, slice};

// ---------- shared status codes ----------

/// Mirrored on the C++ side as the `duetos::core::ElfStatus` enum
/// (kernel/loader/elf_loader.h). Values are byte-identical so a
/// `u8` round-trips cleanly through the FFI.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DuetosElfStatus {
    Ok = 0,
    TooSmall = 1,
    BadMagic = 2,
    NotElf64 = 3,
    NotLittleEndian = 4,
    BadVersion = 5,
    BadMachine = 6,
    NoProgramHeaders = 7,
    HeaderOutOfBounds = 8,
    SegmentOutOfBounds = 9,
    UnalignedSegment = 10,
}

/// Mirrored on the C++ side as the first six values of
/// `duetos::core::PeStatus`. Values are byte-identical.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DuetosPePrefixStatus {
    Ok = 0,
    TooSmall = 1,
    BadDosMagic = 2,
    BadLfanewBounds = 3,
    BadNtSignature = 4,
    BadMachine = 5,
}

/// Extension of DuetosPePrefixStatus: values 6..11 + 17 of the C++
/// `duetos::core::PeStatus` enum. Returned by
/// `duetos_exec_meta_pe_validate_image`. Values 12..16 are NOT
/// emitted here (they cover data-directory checks / OOM, which
/// still live in the C++ loader for now).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DuetosPeImageStatus {
    Ok = 0,
    TooSmall = 1,
    BadDosMagic = 2,
    BadLfanewBounds = 3,
    BadNtSignature = 4,
    BadMachine = 5,
    NotPe32Plus = 6,
    SectionAlignUnsup = 7,
    FileAlignUnsup = 8,
    SectionCountZero = 9,
    OptHeaderOutOfBounds = 10,
    SectionOutOfBounds = 11,
    ImageBaseOutOfRange = 17,
}

// ---------- helpers ----------

fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `ptr` as valid for `len` bytes when
    // non-null. We never store the slice past the call.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

fn write_status_pe(out: *mut u32, value: DuetosPePrefixStatus) {
    if out.is_null() {
        return;
    }
    // SAFETY: FFI contract pins `out` as a writable u32-sized region;
    // we never retain the pointer past the call.
    unsafe { ptr::write(out, value as u32) };
}

/// Write a `DuetosPePrefix` through the out-pointer if non-null.
/// Concentrates the only raw-pointer dereference the PE prefix
/// FFI entry performs so the `pub extern "C"` fn stays clippy-clean
/// (`not_unsafe_ptr_arg_deref`).
fn write_pe_prefix(out: *mut DuetosPePrefix, value: DuetosPePrefix) {
    if out.is_null() {
        return;
    }
    // SAFETY: FFI contract pins `out` as a writable
    // `DuetosPePrefix`-sized region; we never retain the pointer.
    unsafe { ptr::write(out, value) };
}

#[inline]
fn load_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn load_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn load_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

// ---------- ELF ----------

const ELF_HEADER_SIZE: usize = 64;
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const EI_CLASS_64: u8 = 2;
const EI_DATA_LSB: u8 = 1;
const EI_VERSION_CURRENT: u8 = 1;
const EM_X86_64: u16 = 0x3E;
const PT_LOAD: u32 = 1;
/// Canonical low-half ceiling on x86_64 user VAs. A PT_LOAD
/// requesting a VA above this gates out before the loader's
/// AddressSpaceMapUserPage helper would panic on a kernel-half
/// address.
const ELF_USER_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

fn elf_validate(buf: &[u8]) -> DuetosElfStatus {
    if buf.len() < ELF_HEADER_SIZE {
        return DuetosElfStatus::TooSmall;
    }
    if buf[..4] != ELF_MAGIC {
        return DuetosElfStatus::BadMagic;
    }
    if buf[4] != EI_CLASS_64 {
        return DuetosElfStatus::NotElf64;
    }
    if buf[5] != EI_DATA_LSB {
        return DuetosElfStatus::NotLittleEndian;
    }
    if buf[6] != EI_VERSION_CURRENT {
        return DuetosElfStatus::BadVersion;
    }
    let e_machine = load_u16_le(buf, 18);
    if e_machine != EM_X86_64 {
        return DuetosElfStatus::BadMachine;
    }
    let e_phoff = load_u64_le(buf, 32);
    let e_phentsize = load_u16_le(buf, 54);
    let e_phnum = load_u16_le(buf, 56);
    if e_phoff == 0 || e_phnum == 0 || e_phentsize < 56 {
        return DuetosElfStatus::NoProgramHeaders;
    }
    let file_len = buf.len() as u64;
    let phtbl_bytes = (e_phnum as u64).saturating_mul(e_phentsize as u64);
    // Overflow-safe bounds: e_phoff near U64_MAX must not wrap.
    if e_phoff > file_len || phtbl_bytes > file_len - e_phoff {
        return DuetosElfStatus::HeaderOutOfBounds;
    }
    for i in 0..e_phnum {
        let off = e_phoff + (i as u64) * (e_phentsize as u64);
        // The table-bounds check above guarantees off + 56 <= file_len.
        let p = off as usize;
        let p_type = load_u32_le(buf, p);
        if p_type != PT_LOAD {
            continue;
        }
        let p_offset = load_u64_le(buf, p + 8);
        let p_vaddr = load_u64_le(buf, p + 16);
        let p_filesz = load_u64_le(buf, p + 32);
        let p_memsz = load_u64_le(buf, p + 40);
        let p_align = load_u64_le(buf, p + 48);
        // Overflow-safe bounds — refuse a crafted p_offset near
        // U64_MAX that would wrap when added to p_filesz.
        if p_offset > file_len || p_filesz > file_len - p_offset {
            return DuetosElfStatus::SegmentOutOfBounds;
        }
        if p_memsz < p_filesz {
            return DuetosElfStatus::SegmentOutOfBounds;
        }
        if p_vaddr > ELF_USER_MAX {
            return DuetosElfStatus::SegmentOutOfBounds;
        }
        if p_memsz > 0 && (p_memsz - 1) > (ELF_USER_MAX - p_vaddr) {
            return DuetosElfStatus::SegmentOutOfBounds;
        }
        if p_align > 1 && (p_offset % p_align) != (p_vaddr % p_align) {
            return DuetosElfStatus::UnalignedSegment;
        }
    }
    DuetosElfStatus::Ok
}

/// FFI: validate an ELF64 file. Returns the matching ElfStatus
/// value cast to `u32`; the C++ caller casts back to the enum.
#[no_mangle]
pub extern "C" fn duetos_exec_meta_elf_validate(buf: *const u8, len: usize) -> u32 {
    let Some(slice) = slice_from_raw(buf, len) else {
        return DuetosElfStatus::TooSmall as u32;
    };
    elf_validate(slice) as u32
}

// ---------- PE/COFF prefix ----------

const DOS_MAGIC: u16 = 0x5A4D; // 'M','Z' in LE
const PE_SIGNATURE: u32 = 0x0000_4550; // 'P','E',0,0 in LE
const PE_MACHINE_AMD64: u16 = 0x8664;
const PE_MACHINE_I386: u16 = 0x014C;
/// FileHeader (COFF) is 20 bytes immediately after the PE signature.
const PE_FILE_HEADER_SIZE: usize = 20;
/// e_lfanew is at offset 0x3C in the DOS stub.
const PE_LFANEW_OFFSET: usize = 0x3C;

/// Result of a successful prefix validation: file-offset of the PE
/// signature ("PE\0\0") and the section count read from
/// FileHeader.NumberOfSections. The C++ side reuses these in its
/// follow-up optional-header / section-table parsing.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosPePrefix {
    pub nt_base: u32,
    pub section_count: u16,
    pub _pad: u16,
}

fn pe_validate_prefix(buf: &[u8], out: &mut DuetosPePrefix) -> DuetosPePrefixStatus {
    *out = DuetosPePrefix::default();
    // DOS stub: need at least e_lfanew (offset 0x3C + 4 bytes).
    if buf.len() < PE_LFANEW_OFFSET + 4 {
        return DuetosPePrefixStatus::TooSmall;
    }
    let dos_magic = load_u16_le(buf, 0);
    if dos_magic != DOS_MAGIC {
        return DuetosPePrefixStatus::BadDosMagic;
    }
    let e_lfanew = load_u32_le(buf, PE_LFANEW_OFFSET);
    // NT header = 4 bytes sig + 20 FileHeader. We don't read the
    // optional header here; the C++ side does that.
    let need = (e_lfanew as u64).saturating_add(4 + PE_FILE_HEADER_SIZE as u64);
    if need > buf.len() as u64 {
        return DuetosPePrefixStatus::BadLfanewBounds;
    }
    let nt_base = e_lfanew as usize;
    let sig = load_u32_le(buf, nt_base);
    if sig != PE_SIGNATURE {
        return DuetosPePrefixStatus::BadNtSignature;
    }
    let file_hdr = nt_base + 4;
    let machine = load_u16_le(buf, file_hdr);
    if machine != PE_MACHINE_AMD64 && machine != PE_MACHINE_I386 {
        return DuetosPePrefixStatus::BadMachine;
    }
    out.nt_base = e_lfanew;
    out.section_count = load_u16_le(buf, file_hdr + 2);
    DuetosPePrefixStatus::Ok
}

/// FFI: validate a PE prefix. Writes the matching status into
/// `*out_status` and, on Ok, fills `*out_prefix` with the NT-base
/// file offset + section count. Returns true on Ok.
#[no_mangle]
pub extern "C" fn duetos_exec_meta_pe_validate_prefix(
    buf: *const u8,
    len: usize,
    out_prefix: *mut DuetosPePrefix,
    out_status: *mut u32,
) -> bool {
    let mut prefix = DuetosPePrefix::default();
    let status = match slice_from_raw(buf, len) {
        Some(slice) => pe_validate_prefix(slice, &mut prefix),
        None => DuetosPePrefixStatus::TooSmall,
    };
    write_status_pe(out_status, status);
    write_pe_prefix(out_prefix, prefix);
    status == DuetosPePrefixStatus::Ok
}

// ---------- PE/COFF image (deeper validation) ----------
//
// Picks up where the prefix walker stopped: optional-header magic
// (PE32+ only), section / file alignment, image base + size in
// canonical low half, section-table bounds + per-section raw extent
// fit. Stops before the data-directory walks (Imports / BaseReloc /
// TLS) — those still live in the C++ loader because their fix-up
// paths are tightly tied to address-space mapping.

/// Offset of FileHeader.SizeOfOptionalHeader within FileHeader.
const PE_FILEHDR_OFF_SIZE_OF_OPT_HEADER: usize = 16;
/// Optional-header magic for the two PE variants we accept.
const PE_OPT_MAGIC_PE32_PLUS: u16 = 0x020B;
const PE_OPT_MAGIC_PE32: u16 = 0x010B;
/// Optional-header offsets common to PE32 and PE32+ (the layout
/// matches through offset 32 because BaseOfData (PE32 only, u32 at
/// 24) lines up with the upper half of ImageBase (u64 at 24 in
/// PE32+)).
const PE_OPT_OFF_ADDRESS_OF_ENTRY_POINT: usize = 16;
const PE_OPT_OFF_SECTION_ALIGNMENT: usize = 32;
const PE_OPT_OFF_FILE_ALIGNMENT: usize = 36;
const PE_OPT_OFF_SIZE_OF_IMAGE: usize = 56;
/// ImageBase: u64 at offset 24 in PE32+; u32 at offset 28 in PE32.
const PE_OPT_OFF_IMAGE_BASE_PE32_PLUS: usize = 24;
const PE_OPT_OFF_IMAGE_BASE_PE32: usize = 28;
/// NumberOfRvaAndSizes (and the data directories that follow it)
/// land at different offsets because the four stack/heap reserve/
/// commit slots are u32 in PE32 (16 bytes total) and u64 in PE32+
/// (32 bytes total).
const PE_OPT_OFF_NUMBER_OF_RVA_AND_SIZES_PE32_PLUS: usize = 108;
const PE_OPT_OFF_NUMBER_OF_RVA_AND_SIZES_PE32: usize = 92;
const PE_OPT_OFF_DATA_DIRECTORIES_PE32_PLUS: usize = 112;
const PE_OPT_OFF_DATA_DIRECTORIES_PE32: usize = 96;
/// Section-header bytes.
const PE_SECTION_HEADER_SIZE: usize = 40;
const PE_SECTION_OFF_POINTER_TO_RAW_DATA: usize = 20;
const PE_SECTION_OFF_SIZE_OF_RAW_DATA: usize = 16;
/// Page alignment we enforce on SectionAlignment.
const PE_PAGE_ALIGN: u32 = 4096;
/// Canonical low-half user VA ceiling.
const PE_USER_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Deeper PE image-validation output. Superset of `DuetosPePrefix`.
///
/// `is_pe32` is 1 for a PE32 (i386) image, 0 for PE32+ (AMD64). PE32
/// images pass the validator for diagnostic load (PeReport can walk
/// imports / relocs / TLS) but the C++ loader rejects the actual
/// MapAndRun path until the 32-bit user-CS + syscall-ABI layers
/// (kernel/arch/x86_64/{gdt,syscall}.cpp) land.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosPeImage {
    pub nt_base: u32,
    pub section_count: u16,
    pub opt_header_size: u16,
    pub opt_base: u32,
    pub image_size: u32,
    pub entry_rva: u32,
    pub is_pe32: u8,
    pub _pad1a: u8,
    pub _pad1b: u16,
    pub image_base: u64,
    pub section_base: u32,
    pub data_dir_offset: u32,
    pub number_of_rva_and_sizes: u32,
    pub _pad2: u32,
}

fn pe_validate_image(buf: &[u8], out: &mut DuetosPeImage) -> DuetosPeImageStatus {
    *out = DuetosPeImage::default();
    // Run the prefix walker first to share the bounds-check logic.
    let mut prefix = DuetosPePrefix::default();
    match pe_validate_prefix(buf, &mut prefix) {
        DuetosPePrefixStatus::Ok => {}
        DuetosPePrefixStatus::TooSmall => return DuetosPeImageStatus::TooSmall,
        DuetosPePrefixStatus::BadDosMagic => return DuetosPeImageStatus::BadDosMagic,
        DuetosPePrefixStatus::BadLfanewBounds => return DuetosPeImageStatus::BadLfanewBounds,
        DuetosPePrefixStatus::BadNtSignature => return DuetosPeImageStatus::BadNtSignature,
        DuetosPePrefixStatus::BadMachine => return DuetosPeImageStatus::BadMachine,
    }
    out.nt_base = prefix.nt_base;
    out.section_count = prefix.section_count;
    if out.section_count == 0 {
        return DuetosPeImageStatus::SectionCountZero;
    }
    // FileHeader.SizeOfOptionalHeader.
    let file_hdr = out.nt_base as usize + 4;
    out.opt_header_size = load_u16_le(buf, file_hdr + PE_FILEHDR_OFF_SIZE_OF_OPT_HEADER);
    out.opt_base = out.nt_base + 4 + PE_FILE_HEADER_SIZE as u32;
    // OptionalHeader.Magic at offset 0 picks the variant. We need to
    // peek it before knowing how big the optional header should be.
    let min_opt_for_magic = 2u16;
    if out.opt_header_size < min_opt_for_magic {
        return DuetosPeImageStatus::OptHeaderOutOfBounds;
    }
    let opt_end_peek = (out.opt_base as u64) + (min_opt_for_magic as u64);
    if opt_end_peek > buf.len() as u64 {
        return DuetosPeImageStatus::OptHeaderOutOfBounds;
    }
    let opt = out.opt_base as usize;
    let opt_magic = load_u16_le(buf, opt);
    let (is_pe32, image_base_off, n_rva_off, dd_off) = if opt_magic == PE_OPT_MAGIC_PE32_PLUS {
        (
            false,
            PE_OPT_OFF_IMAGE_BASE_PE32_PLUS,
            PE_OPT_OFF_NUMBER_OF_RVA_AND_SIZES_PE32_PLUS,
            PE_OPT_OFF_DATA_DIRECTORIES_PE32_PLUS,
        )
    } else if opt_magic == PE_OPT_MAGIC_PE32 {
        (
            true,
            PE_OPT_OFF_IMAGE_BASE_PE32,
            PE_OPT_OFF_NUMBER_OF_RVA_AND_SIZES_PE32,
            PE_OPT_OFF_DATA_DIRECTORIES_PE32,
        )
    } else {
        return DuetosPeImageStatus::NotPe32Plus;
    };
    out.is_pe32 = if is_pe32 { 1 } else { 0 };
    out.data_dir_offset = dd_off as u32;
    // Need enough optional-header bytes to reach NumberOfRvaAndSizes
    // (the deepest u32 we touch before the data-directory array).
    let min_opt = (n_rva_off + 4) as u16;
    if out.opt_header_size < min_opt {
        return DuetosPeImageStatus::OptHeaderOutOfBounds;
    }
    let opt_end = (out.opt_base as u64) + (out.opt_header_size as u64);
    if opt_end > buf.len() as u64 {
        return DuetosPeImageStatus::OptHeaderOutOfBounds;
    }
    // SectionAlignment must equal page size — the loader maps each
    // section at (ImageBase + VirtualAddress), and a sub-page
    // SectionAlignment would mean two sections share a page with
    // conflicting protections.
    let section_alignment = load_u32_le(buf, opt + PE_OPT_OFF_SECTION_ALIGNMENT);
    if section_alignment != PE_PAGE_ALIGN {
        return DuetosPeImageStatus::SectionAlignUnsup;
    }
    let file_alignment = load_u32_le(buf, opt + PE_OPT_OFF_FILE_ALIGNMENT);
    if file_alignment != 512 && file_alignment != 1024 && file_alignment != 2048 && file_alignment != 4096 {
        return DuetosPeImageStatus::FileAlignUnsup;
    }
    out.image_base = if is_pe32 {
        // PE32 stores ImageBase as a 32-bit zero-extended value.
        load_u32_le(buf, opt + image_base_off) as u64
    } else {
        load_u64_le(buf, opt + image_base_off)
    };
    out.entry_rva = load_u32_le(buf, opt + PE_OPT_OFF_ADDRESS_OF_ENTRY_POINT);
    out.image_size = load_u32_le(buf, opt + PE_OPT_OFF_SIZE_OF_IMAGE);
    out.number_of_rva_and_sizes = load_u32_le(buf, opt + n_rva_off);
    // ImageBase + SizeOfImage must fit in canonical low half — a
    // malicious PE with a kernel-half ImageBase would otherwise
    // drive AddressSpaceMapUserPage into PanicAs and DoS the kernel.
    if out.image_base > PE_USER_MAX {
        return DuetosPeImageStatus::ImageBaseOutOfRange;
    }
    if out.image_size > 0 && (out.image_size as u64 - 1) > (PE_USER_MAX - out.image_base) {
        return DuetosPeImageStatus::ImageBaseOutOfRange;
    }
    // Section table follows the optional header.
    out.section_base = out.opt_base + out.opt_header_size as u32;
    let section_table_bytes = (out.section_count as u64).saturating_mul(PE_SECTION_HEADER_SIZE as u64);
    let section_table_end = (out.section_base as u64).saturating_add(section_table_bytes);
    if section_table_end > buf.len() as u64 {
        return DuetosPeImageStatus::SectionOutOfBounds;
    }
    // Cross-check every section's raw extent fits in the file.
    for i in 0..out.section_count {
        let sec = out.section_base as usize + (i as usize) * PE_SECTION_HEADER_SIZE;
        let raw_off = load_u32_le(buf, sec + PE_SECTION_OFF_POINTER_TO_RAW_DATA);
        let raw_sz = load_u32_le(buf, sec + PE_SECTION_OFF_SIZE_OF_RAW_DATA);
        let raw_end = (raw_off as u64).saturating_add(raw_sz as u64);
        if raw_end > buf.len() as u64 {
            return DuetosPeImageStatus::SectionOutOfBounds;
        }
    }
    DuetosPeImageStatus::Ok
}

/// Helper concentrating the only raw-pointer dereference the image
/// FFI entry performs. Keeps clippy's `not_unsafe_ptr_arg_deref`
/// quiet.
fn write_pe_image(out: *mut DuetosPeImage, value: DuetosPeImage) {
    if out.is_null() {
        return;
    }
    // SAFETY: FFI contract pins `out` as a writable
    // `DuetosPeImage`-sized region; we never retain the pointer.
    unsafe { ptr::write(out, value) };
}

/// FFI: validate everything up to (but not including) the data
/// directories. On Ok, `*out_image` carries nt_base / section_count
/// / opt_header_size / opt_base / image_base / entry_rva /
/// image_size / section_base. On failure, `*out_status` carries one
/// of the PeStatus enumerators (byte-identical to the C++ enum:
/// 0/1/2/3/4/5 = prefix codes, 6 = NotPe32Plus, 7 = SectionAlignUnsup,
/// 8 = FileAlignUnsup, 9 = SectionCountZero, 10 = OptHeaderOutOfBounds,
/// 11 = SectionOutOfBounds, 17 = ImageBaseOutOfRange).
#[no_mangle]
pub extern "C" fn duetos_exec_meta_pe_validate_image(
    buf: *const u8,
    len: usize,
    out_image: *mut DuetosPeImage,
    out_status: *mut u32,
) -> bool {
    let mut image = DuetosPeImage::default();
    let status = match slice_from_raw(buf, len) {
        Some(slice) => pe_validate_image(slice, &mut image),
        None => DuetosPeImageStatus::TooSmall,
    };
    write_status_pe_image(out_status, status);
    write_pe_image(out_image, image);
    status == DuetosPeImageStatus::Ok
}

/// Like `write_status_pe` but for the image-validator's wider enum.
fn write_status_pe_image(out: *mut u32, value: DuetosPeImageStatus) {
    if out.is_null() {
        return;
    }
    // SAFETY: FFI contract pins `out` as a writable u32-sized
    // region; we never retain the pointer past the call.
    unsafe { ptr::write(out, value as u32) };
}

// ---------- hosted tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_min_elf64() -> [u8; ELF_HEADER_SIZE] {
        let mut buf = [0u8; ELF_HEADER_SIZE];
        buf[..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = EI_CLASS_64;
        buf[5] = EI_DATA_LSB;
        buf[6] = EI_VERSION_CURRENT;
        buf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        // e_phoff at byte 32 — point past the header at byte 64
        // (= file_len after we extend).
        buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        buf
    }

    fn append_pt_load(file_with_header: &mut alloc::vec::Vec<u8>, vaddr: u64, filesz: u64, align: u64, off: u64) {
        let mut ph = [0u8; 56];
        ph[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        ph[8..16].copy_from_slice(&off.to_le_bytes());
        ph[16..24].copy_from_slice(&vaddr.to_le_bytes());
        ph[32..40].copy_from_slice(&filesz.to_le_bytes());
        ph[40..48].copy_from_slice(&filesz.to_le_bytes());
        ph[48..56].copy_from_slice(&align.to_le_bytes());
        file_with_header.extend_from_slice(&ph);
    }

    // --- ELF ---

    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn elf_valid_header_no_phdrs_fails() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&make_min_elf64());
        // Header says e_phnum=1 but we never appended a PT_LOAD;
        // the phtbl-bounds check should reject.
        assert_eq!(elf_validate(&buf), DuetosElfStatus::HeaderOutOfBounds);
    }

    #[test]
    fn elf_valid_pt_load_passes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&make_min_elf64());
        append_pt_load(&mut buf, 0x400_000, 0x1000, 0x1000, 0x1000);
        // Extend file to contain the segment bytes the PT_LOAD claims.
        buf.resize(0x1000 + 0x1000, 0);
        assert_eq!(elf_validate(&buf), DuetosElfStatus::Ok);
    }

    #[test]
    fn elf_bad_magic_rejects() {
        let mut buf = make_min_elf64();
        buf[1] = b'X';
        assert_eq!(elf_validate(&buf), DuetosElfStatus::BadMagic);
    }

    #[test]
    fn elf_not_64bit_rejects() {
        let mut buf = make_min_elf64();
        buf[4] = 1; // ELFCLASS32
        assert_eq!(elf_validate(&buf), DuetosElfStatus::NotElf64);
    }

    #[test]
    fn elf_big_endian_rejects() {
        let mut buf = make_min_elf64();
        buf[5] = 2; // ELFDATA2MSB
        assert_eq!(elf_validate(&buf), DuetosElfStatus::NotLittleEndian);
    }

    #[test]
    fn elf_bad_machine_rejects() {
        let mut buf = make_min_elf64();
        buf[18..20].copy_from_slice(&0xB7u16.to_le_bytes()); // aarch64
        assert_eq!(elf_validate(&buf), DuetosElfStatus::BadMachine);
    }

    #[test]
    fn elf_overflow_in_phoff_rejects() {
        let mut buf = make_min_elf64();
        buf[32..40].copy_from_slice(&u64::MAX.to_le_bytes()); // e_phoff
        assert_eq!(elf_validate(&buf), DuetosElfStatus::HeaderOutOfBounds);
    }

    #[test]
    fn elf_too_small_rejects() {
        let buf = [0u8; 10];
        assert_eq!(elf_validate(&buf), DuetosElfStatus::TooSmall);
    }

    #[test]
    fn elf_unaligned_segment_rejects() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&make_min_elf64());
        // p_offset % p_align must equal p_vaddr % p_align.
        // Force a mismatch: offset=0x1000 (≡ 0 mod 0x1000) but
        // vaddr=0x400_001 (≡ 1 mod 0x1000).
        append_pt_load(&mut buf, 0x400_001, 0x1000, 0x1000, 0x1000);
        buf.resize(0x1000 + 0x1000, 0);
        assert_eq!(elf_validate(&buf), DuetosElfStatus::UnalignedSegment);
    }

    #[test]
    fn elf_kernel_half_vaddr_rejects() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&make_min_elf64());
        // p_vaddr in the canonical high half — DuetOS bans this.
        append_pt_load(&mut buf, 0xFFFF_FFFF_8000_0000, 0x1000, 0x1000, 0x1000);
        buf.resize(0x1000 + 0x1000, 0);
        assert_eq!(elf_validate(&buf), DuetosElfStatus::SegmentOutOfBounds);
    }

    // --- PE ---

    fn make_min_pe() -> [u8; 0x80] {
        let mut buf = [0u8; 0x80];
        // DOS magic.
        buf[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
        // e_lfanew at 0x3C points to 0x40 (one byte past 0x3C+4).
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // PE signature at 0x40.
        buf[0x40..0x44].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        // FileHeader at 0x44: Machine (LE u16), NumberOfSections (LE u16), ...
        buf[0x44..0x46].copy_from_slice(&PE_MACHINE_AMD64.to_le_bytes());
        buf[0x46..0x48].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
        buf
    }

    #[test]
    fn pe_prefix_minimal_passes() {
        let buf = make_min_pe();
        let mut prefix = DuetosPePrefix::default();
        assert_eq!(pe_validate_prefix(&buf, &mut prefix), DuetosPePrefixStatus::Ok);
        assert_eq!(prefix.nt_base, 0x40);
        assert_eq!(prefix.section_count, 3);
    }

    #[test]
    fn pe_bad_dos_magic_rejects() {
        let mut buf = make_min_pe();
        buf[0] = b'Z';
        let mut prefix = DuetosPePrefix::default();
        assert_eq!(pe_validate_prefix(&buf, &mut prefix), DuetosPePrefixStatus::BadDosMagic);
    }

    #[test]
    fn pe_bad_lfanew_rejects() {
        let mut buf = make_min_pe();
        // Point e_lfanew past end of file.
        buf[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let mut prefix = DuetosPePrefix::default();
        assert_eq!(
            pe_validate_prefix(&buf, &mut prefix),
            DuetosPePrefixStatus::BadLfanewBounds
        );
    }

    #[test]
    fn pe_bad_signature_rejects() {
        let mut buf = make_min_pe();
        buf[0x40] = b'X';
        let mut prefix = DuetosPePrefix::default();
        assert_eq!(
            pe_validate_prefix(&buf, &mut prefix),
            DuetosPePrefixStatus::BadNtSignature
        );
    }

    #[test]
    fn pe_bad_machine_rejects() {
        let mut buf = make_min_pe();
        buf[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
        let mut prefix = DuetosPePrefix::default();
        assert_eq!(pe_validate_prefix(&buf, &mut prefix), DuetosPePrefixStatus::BadMachine);
    }

    #[test]
    fn pe_too_small_rejects() {
        let buf = [0u8; 10];
        let mut prefix = DuetosPePrefix::default();
        assert_eq!(pe_validate_prefix(&buf, &mut prefix), DuetosPePrefixStatus::TooSmall);
    }

    // --- PE deeper image validation ---

    fn make_min_pe_image() -> Vec<u8> {
        // Build a minimal PE32+ image with one zero-extent section.
        // Layout: DOS stub (0x40) + PE sig (4) + FileHeader (20) +
        // OptionalHeader (112) + 1 SectionHeader (40) = 0xDC bytes.
        let nt_base: u32 = 0x40;
        let opt_size: u16 = 112;
        let mut buf = Vec::new();
        buf.resize(0x40, 0);
        buf[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
        buf[0x3C..0x40].copy_from_slice(&nt_base.to_le_bytes());
        // PE signature.
        buf.extend_from_slice(&PE_SIGNATURE.to_le_bytes());
        // FileHeader: Machine, NumberOfSections, TimeDateStamp,
        // PointerToSymbolTable, NumberOfSymbols,
        // SizeOfOptionalHeader, Characteristics.
        buf.extend_from_slice(&PE_MACHINE_AMD64.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // 1 section
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&opt_size.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        // OptionalHeader (PE32+, 112 bytes — minimum that reaches
        // NumberOfRvaAndSizes at offset 108).
        let mut opt = vec![0u8; opt_size as usize];
        opt[0..2].copy_from_slice(&PE_OPT_MAGIC_PE32_PLUS.to_le_bytes());
        // AddressOfEntryPoint at +16, ImageBase at +24, SectionAlignment at +32,
        // FileAlignment at +36, SizeOfImage at +56.
        opt[16..20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry_rva
        opt[24..32].copy_from_slice(&0x0040_0000u64.to_le_bytes()); // ImageBase
        opt[32..36].copy_from_slice(&PE_PAGE_ALIGN.to_le_bytes()); // SectionAlignment
        opt[36..40].copy_from_slice(&512u32.to_le_bytes()); // FileAlignment
        opt[56..60].copy_from_slice(&0x1000u32.to_le_bytes()); // SizeOfImage
                                                               // NumberOfRvaAndSizes at +108.
        opt[108..112].copy_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&opt);
        // One section header — 40 bytes, all zero (raw_off + raw_sz = 0, fits trivially).
        buf.resize(buf.len() + 40, 0);
        buf
    }

    #[test]
    fn pe_image_minimal_passes() {
        let buf = make_min_pe_image();
        let mut image = DuetosPeImage::default();
        assert_eq!(pe_validate_image(&buf, &mut image), DuetosPeImageStatus::Ok);
        assert_eq!(image.section_count, 1);
        assert_eq!(image.image_base, 0x0040_0000);
        assert_eq!(image.entry_rva, 0x1000);
        assert_eq!(image.image_size, 0x1000);
    }

    #[test]
    fn pe_image_zero_sections_rejects() {
        let mut buf = make_min_pe_image();
        // FileHeader.NumberOfSections at nt_base+4+2 = 0x46.
        buf[0x46..0x48].copy_from_slice(&0u16.to_le_bytes());
        let mut image = DuetosPeImage::default();
        assert_eq!(
            pe_validate_image(&buf, &mut image),
            DuetosPeImageStatus::SectionCountZero
        );
    }

    #[test]
    fn pe_image_pe32_not_plus_rejects() {
        let mut buf = make_min_pe_image();
        // OptionalHeader.Magic at opt_base = nt_base + 24 = 0x58.
        // PE32 (not PE32+) magic is 0x010B.
        buf[0x58..0x5A].copy_from_slice(&0x010Bu16.to_le_bytes());
        let mut image = DuetosPeImage::default();
        assert_eq!(pe_validate_image(&buf, &mut image), DuetosPeImageStatus::NotPe32Plus);
    }

    #[test]
    fn pe_image_bad_section_alignment_rejects() {
        let mut buf = make_min_pe_image();
        // SectionAlignment at opt_base + 32 = 0x78.
        buf[0x78..0x7C].copy_from_slice(&0x200u32.to_le_bytes()); // 512, not 4096
        let mut image = DuetosPeImage::default();
        assert_eq!(
            pe_validate_image(&buf, &mut image),
            DuetosPeImageStatus::SectionAlignUnsup
        );
    }

    #[test]
    fn pe_image_bad_file_alignment_rejects() {
        let mut buf = make_min_pe_image();
        // FileAlignment at opt_base + 36 = 0x7C. Spec allows
        // 512..4096; 256 is illegal.
        buf[0x7C..0x80].copy_from_slice(&256u32.to_le_bytes());
        let mut image = DuetosPeImage::default();
        assert_eq!(pe_validate_image(&buf, &mut image), DuetosPeImageStatus::FileAlignUnsup);
    }

    #[test]
    fn pe_image_kernel_half_image_base_rejects() {
        let mut buf = make_min_pe_image();
        // ImageBase at opt_base + 24 = 0x70. Set to a kernel-half VA.
        buf[0x70..0x78].copy_from_slice(&0xFFFF_FFFF_8000_0000u64.to_le_bytes());
        let mut image = DuetosPeImage::default();
        assert_eq!(
            pe_validate_image(&buf, &mut image),
            DuetosPeImageStatus::ImageBaseOutOfRange
        );
    }

    #[test]
    fn pe_image_image_base_plus_size_overflow_rejects() {
        let mut buf = make_min_pe_image();
        // ImageBase near the top of low-half + SizeOfImage = 16 MiB
        // → fits inside `PE_USER_MAX - image_base = 0xFFFF` only if
        // size <= 0x10000, so a 16-MiB SizeOfImage should reject
        // with `ImageBaseOutOfRange`. Offsets within the optional
        // header: ImageBase at opt_base+24, SizeOfImage at +56.
        buf[0x70..0x78].copy_from_slice(&0x0000_7FFF_FFFF_0000u64.to_le_bytes()); // ImageBase
        buf[0x90..0x94].copy_from_slice(&0x0100_0000u32.to_le_bytes()); // SizeOfImage = 16 MiB
        let mut image = DuetosPeImage::default();
        assert_eq!(
            pe_validate_image(&buf, &mut image),
            DuetosPeImageStatus::ImageBaseOutOfRange
        );
    }

    #[test]
    fn pe_image_truncated_optional_header_rejects() {
        let mut buf = make_min_pe_image();
        // SizeOfOptionalHeader at nt_base+4+16 = 0x54. Force <
        // NumberOfRvaAndSizes_offset+4 = 112.
        buf[0x54..0x56].copy_from_slice(&100u16.to_le_bytes());
        let mut image = DuetosPeImage::default();
        assert_eq!(
            pe_validate_image(&buf, &mut image),
            DuetosPeImageStatus::OptHeaderOutOfBounds
        );
    }

    #[test]
    fn pe_image_section_raw_extent_overflows_rejects() {
        let mut buf = make_min_pe_image();
        // SectionHeader starts at opt_base + opt_header_size =
        // 0x58 + 112 = 0xC8. PointerToRawData at +20, SizeOfRawData
        // at +16. Stuff in u32::MAX values that would overflow when
        // added.
        let sec_base = 0xC8usize;
        buf[sec_base + PE_SECTION_OFF_POINTER_TO_RAW_DATA..sec_base + PE_SECTION_OFF_POINTER_TO_RAW_DATA + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        buf[sec_base + PE_SECTION_OFF_SIZE_OF_RAW_DATA..sec_base + PE_SECTION_OFF_SIZE_OF_RAW_DATA + 4]
            .copy_from_slice(&0x10u32.to_le_bytes());
        let mut image = DuetosPeImage::default();
        assert_eq!(
            pe_validate_image(&buf, &mut image),
            DuetosPeImageStatus::SectionOutOfBounds
        );
    }

    #[test]
    fn pe_image_short_input_returns_too_small() {
        let buf = [0u8; 10];
        let mut image = DuetosPeImage::default();
        assert_eq!(pe_validate_image(&buf, &mut image), DuetosPeImageStatus::TooSmall);
    }
}
