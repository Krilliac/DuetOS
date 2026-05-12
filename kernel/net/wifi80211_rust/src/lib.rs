//! DuetOS IEEE 802.11 management-frame walker — **skeleton**.
//!
//! Foundation for moving Wi-Fi management-frame parsing into safe
//! Rust slice traversal. v0 covers only the frame-control byte
//! decode + MAC-address extraction; the IE (Information Element)
//! list walker, Beacon body decoder, Probe Response, Auth /
//! Assoc / Reassoc frame bodies, and EAPOL-Key 4-way handshake
//! are next-slice work, tracked in `wiki/networking/Wireless.md`.
//!
//! No current C++ caller — the existing MLME code in
//! `kernel/net/wireless/mlme.cpp` keeps its parsers.

#![no_std]

use core::{ptr, slice};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosWifiFrameHeader {
    /// Type: 0 = Management, 1 = Control, 2 = Data, 3 = Extension.
    pub frame_type: u8,
    /// Subtype within the type. For Management frames:
    ///   0 = Assoc Request, 1 = Assoc Response, 4 = Probe Request,
    ///   5 = Probe Response, 8 = Beacon, 11 = Auth, 12 = Deauth, …
    pub frame_subtype: u8,
    pub flags: u8,
    pub _pad: u8,
    pub duration_id: u16,
    pub _pad2: u16,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub sequence_control: u16,
    pub ok: u8,
    pub _pad3: u8,
}

/// 802.11 frame minimum (data + management): 24 bytes (3 MAC
/// addresses + duration/ID + sequence control). 4-address data
/// frames are 30 bytes; the skeleton walker only handles the
/// 3-address case.
const WIFI_FRAME_MIN: usize = 24;

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

fn parse_frame_header(buf: &[u8], out: &mut DuetosWifiFrameHeader) -> bool {
    if buf.len() < WIFI_FRAME_MIN {
        return false;
    }
    // Frame control field is 2 bytes, little-endian on the wire.
    // Bits 2-3 of byte 0 = Type; bits 4-7 = Subtype; byte 1 = flags.
    let fc0 = buf[0];
    let flags = buf[1];
    out.frame_type = (fc0 >> 2) & 0x3;
    out.frame_subtype = (fc0 >> 4) & 0xF;
    out.flags = flags;
    out.duration_id = load_u16_le(buf, 2);
    out.addr1.copy_from_slice(&buf[4..10]);
    out.addr2.copy_from_slice(&buf[10..16]);
    out.addr3.copy_from_slice(&buf[16..22]);
    out.sequence_control = load_u16_le(buf, 22);
    // Reserved frame type 3 (Extension) is post-802.11ax; reject
    // for the v0 skeleton so a future caller has to opt in
    // explicitly when extension frames matter.
    if out.frame_type == 3 {
        return false;
    }
    out.ok = 1;
    true
}

#[no_mangle]
pub extern "C" fn duetos_wifi80211_parse_frame_header(
    buf: *const u8,
    len: usize,
    out: *mut DuetosWifiFrameHeader,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_frame_header(slice, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_management_beacon() -> [u8; 24] {
        let mut buf = [0u8; 24];
        // Frame Control byte 0: protocol_version=0, type=0 (mgmt),
        // subtype=8 (Beacon).
        //   bits 0-1: protocol version (0)
        //   bits 2-3: type (0 → mgmt)
        //   bits 4-7: subtype (8 → beacon)
        // → 8 << 4 | 0 << 2 | 0 = 0x80.
        buf[0] = 0x80;
        buf[1] = 0; // flags
        buf[2..4].copy_from_slice(&0u16.to_le_bytes()); // duration
        buf[4..10].copy_from_slice(&[0xFF; 6]); // dst = broadcast
        buf[10..16].copy_from_slice(&[0x02; 6]); // src
        buf[16..22].copy_from_slice(&[0x02; 6]); // BSSID
        buf[22..24].copy_from_slice(&0u16.to_le_bytes()); // seq
        buf
    }

    #[test]
    fn wifi_beacon_parses() {
        let buf = make_management_beacon();
        let mut out = DuetosWifiFrameHeader::default();
        assert!(parse_frame_header(&buf, &mut out));
        assert_eq!(out.frame_type, 0);
        assert_eq!(out.frame_subtype, 8);
        assert_eq!(out.addr1, [0xFF; 6]);
        assert_eq!(out.addr2, [0x02; 6]);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn wifi_data_frame_parses() {
        let mut buf = make_management_beacon();
        // type=2 (data), subtype=0 → fc0 = 0 << 4 | 2 << 2 = 0x08.
        buf[0] = 0x08;
        let mut out = DuetosWifiFrameHeader::default();
        assert!(parse_frame_header(&buf, &mut out));
        assert_eq!(out.frame_type, 2);
        assert_eq!(out.frame_subtype, 0);
    }

    #[test]
    fn wifi_extension_frame_rejects() {
        let mut buf = make_management_beacon();
        // type=3 (Extension) — bits 2-3 set to 11.
        buf[0] = 0b0000_1100;
        let mut out = DuetosWifiFrameHeader::default();
        assert!(!parse_frame_header(&buf, &mut out));
    }

    #[test]
    fn wifi_too_short_rejects() {
        let buf = [0u8; 10];
        let mut out = DuetosWifiFrameHeader::default();
        assert!(!parse_frame_header(&buf, &mut out));
    }
}
