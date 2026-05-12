//! DuetOS Bluetooth HCI walker — **skeleton**.
//!
//! Foundation for moving Bluetooth Host Controller Interface
//! parsing into safe Rust slice traversal. v0 covers only the
//! HCI packet-type byte and the HCI event header (event-code +
//! parameter length); body decoders for Command Complete,
//! Command Status, Connection Complete, LE Meta events, etc.
//! are next-slice work, tracked in `wiki/networking/Bluetooth.md`.
//!
//! No current C++ caller — the existing `kernel/net/bluetooth/`
//! code keeps its parsers.

#![no_std]

use core::{ptr, slice};

/// HCI packet types (Bluetooth Core 5.4, Vol 4 §2.1).
pub const HCI_PACKET_TYPE_COMMAND: u8 = 0x01;
pub const HCI_PACKET_TYPE_ACL_DATA: u8 = 0x02;
pub const HCI_PACKET_TYPE_SCO_DATA: u8 = 0x03;
pub const HCI_PACKET_TYPE_EVENT: u8 = 0x04;
pub const HCI_PACKET_TYPE_ISO_DATA: u8 = 0x05;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosHciEvent {
    pub event_code: u8,
    pub param_total_length: u8,
    pub param_off: u16,
    pub ok: u8,
    pub _pad: [u8; 3],
}

const HCI_EVENT_HEADER_SIZE: usize = 3; // packet_type (1) + event_code (1) + param_total_length (1)

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

fn parse_event_packet(buf: &[u8], out: &mut DuetosHciEvent) -> bool {
    // HCI event packet layout (Vol 4 §5.4.4):
    //   [0]  Packet type (must be 0x04 = Event)
    //   [1]  Event code
    //   [2]  Parameter total length (u8)
    //   [3..] Parameters
    if buf.len() < HCI_EVENT_HEADER_SIZE {
        return false;
    }
    if buf[0] != HCI_PACKET_TYPE_EVENT {
        return false;
    }
    out.event_code = buf[1];
    out.param_total_length = buf[2];
    out.param_off = HCI_EVENT_HEADER_SIZE as u16;
    // Parameters must fit in the remaining buffer.
    if (out.param_total_length as usize) > buf.len() - HCI_EVENT_HEADER_SIZE {
        return false;
    }
    out.ok = 1;
    true
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hci_event_command_complete_passes() {
        // Packet type 0x04, Event 0x0E (Command Complete),
        // ParameterTotalLength = 4, body = (num_hci_command_packets,
        // opcode-lo, opcode-hi, status).
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
        let buf = [0x01u8, 0x0E, 0]; // 0x01 = Command, not Event
        let mut out = DuetosHciEvent::default();
        assert!(!parse_event_packet(&buf, &mut out));
    }

    #[test]
    fn hci_truncated_params_rejects() {
        // Claims 10 param bytes but only 3 follow.
        let buf = [0x04u8, 0x0E, 10, 1, 2, 3];
        let mut out = DuetosHciEvent::default();
        assert!(!parse_event_packet(&buf, &mut out));
    }

    #[test]
    fn hci_zero_param_length_passes() {
        let buf = [0x04u8, 0x10, 0]; // Hardware Error w/ no params
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
}
