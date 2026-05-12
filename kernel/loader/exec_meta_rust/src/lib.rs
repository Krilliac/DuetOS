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
    if machine != PE_MACHINE_AMD64 {
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
}
