//! DuetOS Bluetooth HCI walker.
//!
//! Production crate. HCI event-packet header + body decoders for
//! Command Complete, Command Status, Disconnection Complete, LE
//! Meta event header, Read_Local_Version, and Read_BD_ADDR. The
//! C++ side at `kernel/net/bluetooth/hci.cpp` calls into this
//! crate for byte parsing; transport rings, HCI command builders,
//! and the `HciEventHeader` cache layer stay in C++.

#![no_std]

use core::{ptr, slice};

/// HCI packet types (Bluetooth Core 5.4, Vol 4 §2.1).
pub const HCI_PACKET_TYPE_COMMAND: u8 = 0x01;
pub const HCI_PACKET_TYPE_ACL_DATA: u8 = 0x02;
pub const HCI_PACKET_TYPE_SCO_DATA: u8 = 0x03;
pub const HCI_PACKET_TYPE_EVENT: u8 = 0x04;
pub const HCI_PACKET_TYPE_ISO_DATA: u8 = 0x05;

/// HCI event codes (subset).
pub const HCI_EVT_DISCONNECTION_COMPLETE: u8 = 0x05;
pub const HCI_EVT_COMMAND_COMPLETE: u8 = 0x0E;
pub const HCI_EVT_COMMAND_STATUS: u8 = 0x0F;
pub const HCI_EVT_NUMBER_OF_COMPLETED_PACKETS: u8 = 0x13;
pub const HCI_EVT_LE_META_EVENT: u8 = 0x3E;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosHciEvent {
    pub event_code: u8,
    pub param_total_length: u8,
    pub param_off: u16,
    pub ok: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosHciCommandComplete {
    pub num_hci_command_packets: u8,
    pub _pad0: u8,
    pub command_opcode: u16,
    pub return_parameters_off: u16,
    pub return_parameters_size: u16,
    pub ok: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosHciCommandStatus {
    pub status: u8,
    pub num_hci_command_packets: u8,
    pub command_opcode: u16,
    pub ok: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosHciDisconnectionComplete {
    pub status: u8,
    pub _pad0: u8,
    pub connection_handle: u16,
    pub reason: u8,
    pub _pad1: u8,
    pub ok: u8,
    pub _pad2: [u8; 5],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosHciLeMeta {
    pub subevent_code: u8,
    pub _pad0: u8,
    pub param_off: u16,
    pub param_size: u16,
    pub ok: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosHciReadLocalVersion {
    pub status: u8,
    pub hci_version: u8,
    pub hci_revision: u16,
    pub lmp_version: u8,
    pub _pad0: u8,
    pub manufacturer_name: u16,
    pub lmp_subversion: u16,
    pub ok: u8,
    pub _pad: [u8; 5],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosHciReadBdAddr {
    pub status: u8,
    pub _pad0: u8,
    pub bd_addr: [u8; 6],
    pub ok: u8,
    pub _pad: [u8; 7],
}

const HCI_EVENT_HEADER_SIZE: usize = 3; // packet_type + event_code + param_total_length

fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `ptr` as valid for `len` bytes.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

fn out_init<'a, T: Default + Copy>(out: *mut T) -> Option<&'a mut T> {
    if out.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `out` as a writable T-sized region.
    unsafe {
        ptr::write(out, T::default());
        Some(&mut *out)
    }
}

#[inline]
fn load_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Parse an HCI event packet header. `buf` is the full packet
/// including the 1-byte packet-type prefix the host stack peels off
/// the wire.
fn parse_event_packet(buf: &[u8], out: &mut DuetosHciEvent) -> bool {
    if buf.len() < HCI_EVENT_HEADER_SIZE {
        return false;
    }
    if buf[0] != HCI_PACKET_TYPE_EVENT {
        return false;
    }
    out.event_code = buf[1];
    out.param_total_length = buf[2];
    out.param_off = HCI_EVENT_HEADER_SIZE as u16;
    if (out.param_total_length as usize) > buf.len() - HCI_EVENT_HEADER_SIZE {
        return false;
    }
    out.ok = 1;
    true
}

/// Parse the body of an HCI event whose header has already been
/// validated, OR a raw header-included buffer. The function is
/// strict about the "byte 0 is packet type 0x04" prefix so passing
/// raw transport buffers is supported.
fn parse_command_complete(buf: &[u8], out: &mut DuetosHciCommandComplete) -> bool {
    let mut hdr = DuetosHciEvent::default();
    if !parse_event_packet(buf, &mut hdr) {
        return false;
    }
    if hdr.event_code != HCI_EVT_COMMAND_COMPLETE {
        return false;
    }
    if hdr.param_total_length < 3 {
        return false;
    }
    let body_off = hdr.param_off as usize;
    out.num_hci_command_packets = buf[body_off];
    out.command_opcode = load_u16_le(buf, body_off + 1);
    out.return_parameters_off = (body_off + 3) as u16;
    out.return_parameters_size = (hdr.param_total_length - 3) as u16;
    out.ok = 1;
    true
}

fn parse_command_status(buf: &[u8], out: &mut DuetosHciCommandStatus) -> bool {
    let mut hdr = DuetosHciEvent::default();
    if !parse_event_packet(buf, &mut hdr) {
        return false;
    }
    if hdr.event_code != HCI_EVT_COMMAND_STATUS {
        return false;
    }
    if hdr.param_total_length != 4 {
        return false;
    }
    let body_off = hdr.param_off as usize;
    out.status = buf[body_off];
    out.num_hci_command_packets = buf[body_off + 1];
    out.command_opcode = load_u16_le(buf, body_off + 2);
    out.ok = 1;
    true
}

fn parse_disconnection_complete(buf: &[u8], out: &mut DuetosHciDisconnectionComplete) -> bool {
    let mut hdr = DuetosHciEvent::default();
    if !parse_event_packet(buf, &mut hdr) {
        return false;
    }
    if hdr.event_code != HCI_EVT_DISCONNECTION_COMPLETE {
        return false;
    }
    if hdr.param_total_length != 4 {
        return false;
    }
    let body_off = hdr.param_off as usize;
    out.status = buf[body_off];
    out.connection_handle = load_u16_le(buf, body_off + 1);
    out.reason = buf[body_off + 3];
    out.ok = 1;
    true
}

fn parse_le_meta(buf: &[u8], out: &mut DuetosHciLeMeta) -> bool {
    let mut hdr = DuetosHciEvent::default();
    if !parse_event_packet(buf, &mut hdr) {
        return false;
    }
    if hdr.event_code != HCI_EVT_LE_META_EVENT {
        return false;
    }
    if hdr.param_total_length < 1 {
        return false;
    }
    let body_off = hdr.param_off as usize;
    out.subevent_code = buf[body_off];
    out.param_off = (body_off + 1) as u16;
    out.param_size = (hdr.param_total_length - 1) as u16;
    out.ok = 1;
    true
}

/// Parse a HCI_Read_Local_Version_Information return-parameter
/// block. The caller is responsible for stripping the
/// Command_Complete envelope and handing us the 9-byte rparams.
fn parse_read_local_version(buf: &[u8], out: &mut DuetosHciReadLocalVersion) -> bool {
    if buf.len() < 9 {
        return false;
    }
    out.status = buf[0];
    out.hci_version = buf[1];
    out.hci_revision = load_u16_le(buf, 2);
    out.lmp_version = buf[4];
    out.manufacturer_name = load_u16_le(buf, 5);
    out.lmp_subversion = load_u16_le(buf, 7);
    out.ok = 1;
    true
}

/// Parse a HCI_Read_BD_ADDR return-parameter block (7 bytes).
fn parse_read_bd_addr(buf: &[u8], out: &mut DuetosHciReadBdAddr) -> bool {
    if buf.len() < 7 {
        return false;
    }
    out.status = buf[0];
    out.bd_addr.copy_from_slice(&buf[1..7]);
    out.ok = 1;
    true
}

// ---------- FFI ----------

#[no_mangle]
pub extern "C" fn duetos_hci_parse_event_packet(buf: *const u8, len: usize, out: *mut DuetosHciEvent) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_event_packet(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_hci_parse_command_complete(
    buf: *const u8,
    len: usize,
    out: *mut DuetosHciCommandComplete,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_command_complete(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_hci_parse_command_status(
    buf: *const u8,
    len: usize,
    out: *mut DuetosHciCommandStatus,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_command_status(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_hci_parse_disconnection_complete(
    buf: *const u8,
    len: usize,
    out: *mut DuetosHciDisconnectionComplete,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_disconnection_complete(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_hci_parse_le_meta(buf: *const u8, len: usize, out: *mut DuetosHciLeMeta) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_le_meta(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_hci_parse_read_local_version(
    buf: *const u8,
    len: usize,
    out: *mut DuetosHciReadLocalVersion,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_read_local_version(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_hci_parse_read_bd_addr(buf: *const u8, len: usize, out: *mut DuetosHciReadBdAddr) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_read_bd_addr(slice, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hci_event_command_complete_passes() {
        let buf = [0x04u8, 0x0E, 4, 1, 0x03, 0x0C, 0x00];
        let mut out = DuetosHciEvent::default();
        assert!(parse_event_packet(&buf, &mut out));
        assert_eq!(out.event_code, 0x0E);
        assert_eq!(out.param_total_length, 4);
        assert_eq!(out.param_off, 3);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn hci_wrong_packet_type_rejects() {
        let buf = [0x01u8, 0x0E, 0];
        let mut out = DuetosHciEvent::default();
        assert!(!parse_event_packet(&buf, &mut out));
    }

    #[test]
    fn hci_truncated_params_rejects() {
        let buf = [0x04u8, 0x0E, 10, 1, 2, 3];
        let mut out = DuetosHciEvent::default();
        assert!(!parse_event_packet(&buf, &mut out));
    }

    #[test]
    fn hci_zero_param_length_passes() {
        let buf = [0x04u8, 0x10, 0];
        let mut out = DuetosHciEvent::default();
        assert!(parse_event_packet(&buf, &mut out));
        assert_eq!(out.param_total_length, 0);
    }

    #[test]
    fn hci_too_short_rejects() {
        let buf = [0x04u8];
        let mut out = DuetosHciEvent::default();
        assert!(!parse_event_packet(&buf, &mut out));
    }

    // ---- Command_Complete body ----

    #[test]
    fn command_complete_decodes() {
        let buf = [
            0x04u8,
            HCI_EVT_COMMAND_COMPLETE,
            7,
            1,
            0x03,
            0x0C,
            0x00,
            0xAA,
            0xBB,
            0xCC,
        ];
        let mut cc = DuetosHciCommandComplete::default();
        assert!(parse_command_complete(&buf, &mut cc));
        assert_eq!(cc.num_hci_command_packets, 1);
        assert_eq!(cc.command_opcode, 0x0C03);
        assert_eq!(cc.return_parameters_off, 6);
        assert_eq!(cc.return_parameters_size, 4);
        assert_eq!(cc.ok, 1);
    }

    #[test]
    fn command_complete_wrong_event_rejects() {
        let buf = [0x04u8, 0x10, 4, 0, 0, 0, 0];
        let mut cc = DuetosHciCommandComplete::default();
        assert!(!parse_command_complete(&buf, &mut cc));
    }

    #[test]
    fn command_complete_too_short_body_rejects() {
        let buf = [0x04u8, HCI_EVT_COMMAND_COMPLETE, 2, 1, 0];
        let mut cc = DuetosHciCommandComplete::default();
        assert!(!parse_command_complete(&buf, &mut cc));
    }

    // ---- Command_Status body ----

    #[test]
    fn command_status_decodes() {
        let buf = [0x04u8, HCI_EVT_COMMAND_STATUS, 4, 0, 1, 0x06, 0x04];
        let mut cs = DuetosHciCommandStatus::default();
        assert!(parse_command_status(&buf, &mut cs));
        assert_eq!(cs.status, 0);
        assert_eq!(cs.num_hci_command_packets, 1);
        assert_eq!(cs.command_opcode, 0x0406);
    }

    #[test]
    fn command_status_wrong_len_rejects() {
        let buf = [0x04u8, HCI_EVT_COMMAND_STATUS, 5, 0, 1, 0x06, 0x04, 0xAA];
        let mut cs = DuetosHciCommandStatus::default();
        assert!(!parse_command_status(&buf, &mut cs));
    }

    // ---- Disconnection_Complete ----

    #[test]
    fn disconnection_complete_decodes() {
        let buf = [0x04u8, HCI_EVT_DISCONNECTION_COMPLETE, 4, 0, 0x40, 0x00, 0x13];
        let mut dc = DuetosHciDisconnectionComplete::default();
        assert!(parse_disconnection_complete(&buf, &mut dc));
        assert_eq!(dc.status, 0);
        assert_eq!(dc.connection_handle, 0x40);
        assert_eq!(dc.reason, 0x13);
    }

    // ---- LE Meta ----

    #[test]
    fn le_meta_decodes() {
        let buf = [0x04u8, HCI_EVT_LE_META_EVENT, 3, 0x02, 0xAA, 0xBB];
        let mut le = DuetosHciLeMeta::default();
        assert!(parse_le_meta(&buf, &mut le));
        assert_eq!(le.subevent_code, 0x02);
        assert_eq!(le.param_off, 4);
        assert_eq!(le.param_size, 2);
    }

    #[test]
    fn le_meta_zero_plen_rejects() {
        let buf = [0x04u8, HCI_EVT_LE_META_EVENT, 0];
        let mut le = DuetosHciLeMeta::default();
        assert!(!parse_le_meta(&buf, &mut le));
    }

    // ---- Read_Local_Version + Read_BD_ADDR rparams ----

    #[test]
    fn read_local_version_decodes() {
        let rp = [0x00u8, 0x0C, 0x34, 0x12, 0x0C, 0x0F, 0x00, 0x16, 0x61];
        let mut v = DuetosHciReadLocalVersion::default();
        assert!(parse_read_local_version(&rp, &mut v));
        assert_eq!(v.hci_version, 0x0C);
        assert_eq!(v.hci_revision, 0x1234);
        assert_eq!(v.manufacturer_name, 0x000F);
        assert_eq!(v.lmp_subversion, 0x6116);
    }

    #[test]
    fn read_local_version_too_short_rejects() {
        let rp = [0u8; 5];
        let mut v = DuetosHciReadLocalVersion::default();
        assert!(!parse_read_local_version(&rp, &mut v));
    }

    #[test]
    fn read_bd_addr_decodes() {
        let rp = [0u8, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let mut a = DuetosHciReadBdAddr::default();
        assert!(parse_read_bd_addr(&rp, &mut a));
        assert_eq!(a.bd_addr, [0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
    }
}
