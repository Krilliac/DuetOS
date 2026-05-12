//! DuetOS USB MSC SCSI response parsers.
//!
//! Five small walkers, all bounds-checked slice traversal of
//! attacker-supplied bytes. The C++ MSC driver lives in
//! `kernel/drivers/usb/msc_scsi.cpp`; this crate is its parser
//! half, called through `#[repr(C)]` out-structs that mirror
//! the C++ ones one-for-one.
//!
//! Every helper:
//!   - validates input length first;
//!   - zero-initialises the out-struct so a partial parse can't
//!     return uninitialised bytes to the C++ caller;
//!   - reads via slice indexing only — no raw pointer arithmetic.

#![no_std]

use core::{ptr, slice};

// ---------- C-ABI out-structs (mirror msc_scsi.h) ----------

// FFI out-structs. Each is a separate Rust type from the C++
// counterpart (the C++ wrapper does field-by-field copy on the way
// out) so layout drift between the two halves can't silently break
// callers. Default impls are used to zero-fill before parse and on
// any failure path.

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMscInquiryData {
    pub peripheral_type: u8,
    pub removable: u8,
    pub version: u8,
    pub vendor_id: [u8; 9],
    pub product_id: [u8; 17],
    pub product_rev: [u8; 5],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMscReadCapacity10 {
    pub last_lba: u32,
    pub block_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMscGetConfigHeader {
    pub data_length: u32,
    pub current_profile: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMscReadTocHeader {
    pub toc_data_length: u16,
    pub first_track: u8,
    pub last_track: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMscDiscInformation {
    pub length: u16,
    pub disc_status: u8,
    pub state_of_last_sess: u8,
    pub erasable: u8,
    pub first_track_on_disc: u8,
    pub num_sessions_lsb: u8,
    pub first_track_in_last_session_lsb: u8,
    pub last_track_in_last_session_lsb: u8,
    pub disc_type: u8,
}

// ---------- helpers ----------
//
// All raw-pointer dereferences live here so the `pub extern "C"`
// entry points are clippy-clean (`not_unsafe_ptr_arg_deref`) and a
// future "no unsafe outside the FFI wall" audit only has to look
// at this section.

/// Reconstruct a slice from a `(ptr, len)` FFI pair, returning
/// `None` on a null pointer.
fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller's FFI contract is that `ptr` is valid for `len`
    // bytes when non-null. We never store the slice past the call.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Read a big-endian u32 from `buf[off..off+4]`. Caller must have
/// already bounds-checked.
#[inline]
fn read_be_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a big-endian u16 from `buf[off..off+2]`. Caller must have
/// already bounds-checked.
#[inline]
fn read_be_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

/// Copy `src` (up to `dst.len() - 1` bytes) into `dst`, trimming
/// trailing spaces and forcing a trailing NUL. Mirrors the C++
/// `CopyTrimmed(out, in, max)` helper in msc_scsi.cpp.
fn copy_trimmed(dst: &mut [u8], src: &[u8]) {
    if dst.is_empty() {
        return;
    }
    let max = dst.len() - 1;
    let take = core::cmp::min(max, src.len());
    // Find trailing-space cutoff in `src[..take]`.
    let mut end = take;
    while end > 0 && src[end - 1] == b' ' {
        end -= 1;
    }
    dst[..end].copy_from_slice(&src[..end]);
    dst[end] = 0;
    // Zero the rest of dst so callers don't see uninit bytes.
    for b in &mut dst[end + 1..] {
        *b = 0;
    }
}

/// Write a zeroed `T` into the out-pointer. Returns `Some(&mut T)`
/// if `out` is non-null (and the value was initialised), or `None`.
/// Consolidates the only raw-pointer dereference any FFI entry
/// point performs.
fn out_init<'a, T: Default + Copy>(out: *mut T) -> Option<&'a mut T> {
    if out.is_null() {
        return None;
    }
    // SAFETY: caller's FFI contract is that `out` is non-null +
    // writable for `T`. We never retain the pointer past the call.
    unsafe {
        ptr::write(out, T::default());
        Some(&mut *out)
    }
}

// ---------- parsers ----------

fn parse_inquiry(buf: &[u8], out: &mut DuetosMscInquiryData) -> bool {
    if buf.len() < 36 {
        return false;
    }
    *out = DuetosMscInquiryData::default();
    out.peripheral_type = buf[0] & 0x1F;
    out.removable = if buf[1] & 0x80 != 0 { 1 } else { 0 };
    out.version = buf[2] & 0x07;
    copy_trimmed(&mut out.vendor_id, &buf[8..16]);
    copy_trimmed(&mut out.product_id, &buf[16..32]);
    copy_trimmed(&mut out.product_rev, &buf[32..36]);
    true
}

fn parse_read_capacity_10(buf: &[u8], out: &mut DuetosMscReadCapacity10) -> bool {
    if buf.len() < 8 {
        return false;
    }
    out.last_lba = read_be_u32(buf, 0);
    out.block_size = read_be_u32(buf, 4);
    true
}

fn parse_get_config_header(buf: &[u8], out: &mut DuetosMscGetConfigHeader) -> bool {
    *out = DuetosMscGetConfigHeader::default();
    if buf.len() < 8 {
        return false;
    }
    out.data_length = read_be_u32(buf, 0);
    out.current_profile = read_be_u16(buf, 6);
    true
}

fn parse_read_toc_header(buf: &[u8], out: &mut DuetosMscReadTocHeader) -> bool {
    *out = DuetosMscReadTocHeader::default();
    if buf.len() < 4 {
        return false;
    }
    out.toc_data_length = read_be_u16(buf, 0);
    out.first_track = buf[2];
    out.last_track = buf[3];
    true
}

fn parse_disc_information(buf: &[u8], out: &mut DuetosMscDiscInformation) -> bool {
    *out = DuetosMscDiscInformation::default();
    if buf.len() < 12 {
        return false;
    }
    out.length = read_be_u16(buf, 0);
    let b2 = buf[2];
    out.disc_status = b2 & 0x03;
    out.state_of_last_sess = (b2 >> 2) & 0x03;
    out.erasable = if b2 & 0x10 != 0 { 1 } else { 0 };
    out.first_track_on_disc = buf[3];
    out.num_sessions_lsb = buf[4];
    out.first_track_in_last_session_lsb = buf[5];
    out.last_track_in_last_session_lsb = buf[6];
    out.disc_type = buf[8];
    true
}

// ---------- FFI exports ----------

#[no_mangle]
pub extern "C" fn duetos_msc_parse_inquiry(buf: *const u8, len: usize, out: *mut DuetosMscInquiryData) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_inquiry(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_msc_parse_read_capacity_10(
    buf: *const u8,
    len: usize,
    out: *mut DuetosMscReadCapacity10,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_read_capacity_10(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_msc_parse_get_config_header(
    buf: *const u8,
    len: usize,
    out: *mut DuetosMscGetConfigHeader,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_get_config_header(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_msc_parse_read_toc_header(
    buf: *const u8,
    len: usize,
    out: *mut DuetosMscReadTocHeader,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_read_toc_header(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_msc_parse_disc_information(
    buf: *const u8,
    len: usize,
    out: *mut DuetosMscDiscInformation,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_disc_information(slice, dst)
}

// ---------- hosted tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn ascii(s: &[u8], pad_to: usize) -> [u8; 36] {
        let mut out = [b' '; 36];
        out[..s.len().min(36)].copy_from_slice(&s[..s.len().min(36)]);
        // Right-pad the relevant SCSI string region with spaces.
        let _ = pad_to;
        out
    }

    #[test]
    fn inquiry_parses_qemu_usb_disk() {
        // Synthetic INQUIRY data shaped like QEMU usb-storage.
        let mut buf = [0u8; 36];
        buf[0] = 0; // peripheral type = direct-access disk
        buf[1] = 0x80; // RMB bit set => removable
        buf[2] = 0x06; // SPC-4
        let vendor = b"QEMU    "; // 8 bytes, space-padded
        let product = b"USB-DISK        "; // 16 bytes
        let rev = b"0.01"; // 4 bytes
        buf[8..16].copy_from_slice(vendor);
        buf[16..32].copy_from_slice(product);
        buf[32..36].copy_from_slice(rev);

        let mut out = DuetosMscInquiryData::default();
        assert!(parse_inquiry(&buf, &mut out));
        assert_eq!(out.peripheral_type, 0);
        assert_eq!(out.removable, 1);
        assert_eq!(out.version, 6);
        assert_eq!(&out.vendor_id[..4], b"QEMU");
        assert_eq!(out.vendor_id[4], 0);
        assert_eq!(&out.product_id[..8], b"USB-DISK");
        assert_eq!(out.product_id[8], 0);
        assert_eq!(&out.product_rev[..4], b"0.01");
        assert_eq!(out.product_rev[4], 0);
    }

    #[test]
    fn inquiry_short_returns_false() {
        let buf = [0u8; 35];
        let mut out = DuetosMscInquiryData::default();
        assert!(!parse_inquiry(&buf, &mut out));
    }

    #[test]
    fn inquiry_overlong_vendor_truncates() {
        // 32-character "vendor" (overflows the 8-byte SCSI slot,
        // but our parser only reads 8 bytes so it can't escape).
        let mut buf = [b'A'; 36];
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        let mut out = DuetosMscInquiryData::default();
        assert!(parse_inquiry(&buf, &mut out));
        // 8 A's + NUL terminator.
        assert_eq!(&out.vendor_id[..8], b"AAAAAAAA");
        assert_eq!(out.vendor_id[8], 0);
    }

    #[test]
    fn read_capacity_10_parses() {
        // last_lba = 0x00112233, block_size = 512.
        let buf = [0x00, 0x11, 0x22, 0x33, 0x00, 0x00, 0x02, 0x00];
        let mut out = DuetosMscReadCapacity10::default();
        assert!(parse_read_capacity_10(&buf, &mut out));
        assert_eq!(out.last_lba, 0x0011_2233);
        assert_eq!(out.block_size, 512);
    }

    #[test]
    fn read_capacity_10_short_returns_false() {
        let buf = [0u8; 7];
        let mut out = DuetosMscReadCapacity10::default();
        assert!(!parse_read_capacity_10(&buf, &mut out));
    }

    #[test]
    fn get_config_header_parses() {
        // data_length=0x100, current_profile=0x0008 (CD-ROM).
        let buf = [0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08];
        let mut out = DuetosMscGetConfigHeader::default();
        assert!(parse_get_config_header(&buf, &mut out));
        assert_eq!(out.data_length, 0x100);
        assert_eq!(out.current_profile, 0x0008);
    }

    #[test]
    fn read_toc_header_parses() {
        let buf = [0x00, 0x12, 1, 3];
        let mut out = DuetosMscReadTocHeader::default();
        assert!(parse_read_toc_header(&buf, &mut out));
        assert_eq!(out.toc_data_length, 0x12);
        assert_eq!(out.first_track, 1);
        assert_eq!(out.last_track, 3);
    }

    #[test]
    fn disc_information_parses_finalized() {
        // length=0x20, byte 2 = 0b00001110 = state=11(complete) status=10(finalized) erasable=0
        // (Pack via bits: bits 0..1 disc_status, bits 2..3 state_of_last_sess, bit 4 erasable)
        // Want disc_status=0b10=2 (finalized), state=0b11=3 (complete), erasable=0.
        let b2 = (3 << 2) | 2;
        let buf = [0x00, 0x20, b2, 1, 2, 3, 4, 0, 0x10, 0, 0, 0];
        let mut out = DuetosMscDiscInformation::default();
        assert!(parse_disc_information(&buf, &mut out));
        assert_eq!(out.length, 0x20);
        assert_eq!(out.disc_status, 2);
        assert_eq!(out.state_of_last_sess, 3);
        assert_eq!(out.erasable, 0);
        assert_eq!(out.first_track_on_disc, 1);
        assert_eq!(out.num_sessions_lsb, 2);
        assert_eq!(out.disc_type, 0x10);
    }

    #[test]
    fn disc_information_erasable_bit_set() {
        // bit 4 of byte 2 = erasable.
        let b2 = 0x10;
        let buf = [0, 0, b2, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut out = DuetosMscDiscInformation::default();
        assert!(parse_disc_information(&buf, &mut out));
        assert_eq!(out.erasable, 1);
    }

    #[test]
    fn all_zero_inputs_are_rejected_when_short() {
        let empty: &[u8] = &[];
        let mut ic = DuetosMscInquiryData::default();
        let mut rc = DuetosMscReadCapacity10::default();
        let mut gc = DuetosMscGetConfigHeader::default();
        let mut th = DuetosMscReadTocHeader::default();
        let mut di = DuetosMscDiscInformation::default();
        assert!(!parse_inquiry(empty, &mut ic));
        assert!(!parse_read_capacity_10(empty, &mut rc));
        assert!(!parse_get_config_header(empty, &mut gc));
        assert!(!parse_read_toc_header(empty, &mut th));
        assert!(!parse_disc_information(empty, &mut di));
    }

    // Sanity: the synthetic INQUIRY in the C++ self-test ends up
    // with the same trimmed strings as the C++ side.
    #[test]
    fn cpp_self_test_synthetic_inquiry_matches() {
        // Replicate the buffer the C++ self-test constructs and
        // verify our parser produces the same fields.
        let _ = ascii(b"unused", 0); // keep the helper from being dead
        let mut buf = [b' '; 36];
        buf[0] = 0;
        buf[1] = 0x80;
        buf[2] = 0x06;
        buf[8..16].copy_from_slice(b"QEMU    ");
        buf[16..32].copy_from_slice(b"USB-DISK        ");
        buf[32..36].copy_from_slice(b"0.01");
        let mut out = DuetosMscInquiryData::default();
        assert!(parse_inquiry(&buf, &mut out));
        assert_eq!(&out.vendor_id[..4], b"QEMU");
        assert_eq!(&out.product_id[..8], b"USB-DISK");
        assert_eq!(&out.product_rev[..4], b"0.01");
    }
}
