//! DuetOS IEEE 802.11 management-frame walker.
//!
//! Production crate. Covers the frame-control + 3-address header
//! decode, the Information-Element list walker, the Beacon /
//! Probe Response fixed body prefix decoder, and the EAPOL-Key
//! (4-way handshake) frame header. The C++ MLME at
//! `kernel/net/wireless/` calls into this crate via the
//! `duetos_wifi80211_*` FFI symbols.

#![no_std]

use core::{ptr, slice};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosWifiFrameHeader {
    pub frame_type: u8,
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

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosWifiIe {
    pub id: u8,
    pub len: u8,
    pub _pad: u16,
    /// Byte offset within the frame where the IE payload starts.
    pub payload_offset: u32,
    pub ok: u8,
    pub _pad2: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosWifiBeaconBody {
    pub timestamp: u64,
    pub beacon_interval: u16,
    pub capability_info: u16,
    /// Byte offset where the IE list starts (mac header + 12).
    pub ie_list_offset: u32,
    pub ok: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosWifiEapolKey {
    pub key_descriptor_type: u8,
    pub _pad0: u8,
    pub key_info: u16,
    pub key_length: u16,
    pub _pad1: u16,
    pub replay_counter: u64,
    pub key_nonce: [u8; 32],
    pub key_iv: [u8; 16],
    pub key_rsc: [u8; 8],
    pub key_reserved: [u8; 8],
    pub key_mic: [u8; 16],
    pub key_data_length: u16,
    pub _pad2: u16,
    /// Byte offset within the buffer where the KeyData blob starts.
    pub key_data_offset: u32,
    pub ok: u8,
    pub _pad3: [u8; 7],
}

/// 802.11d Country Information Element §9.4.2.10. Triplets are
/// stored inline (capped at 16) so the parser is allocation-free.
/// Operating-triplet form (first_channel >= 201) is parsed but
/// not stored — `IntersectWithCountryIe` only consumes sub-band
/// triplets, and ignoring the operating-class form keeps the
/// safety property "a beacon can only narrow the allowed set."
pub const COUNTRY_IE_MAX_TRIPLETS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosWifiCountryIeTriplet {
    pub first_channel: u8,
    pub num_channels: u8,
    pub max_tx_dbm: i8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DuetosWifiCountryIe {
    pub alpha2: [u8; 2],
    pub environment: u8,
    pub n_triplets: u8,
    pub triplets: [DuetosWifiCountryIeTriplet; COUNTRY_IE_MAX_TRIPLETS],
    pub ok: u8,
    pub _pad: [u8; 3],
}

impl Default for DuetosWifiCountryIe {
    fn default() -> Self {
        Self {
            alpha2: [0; 2],
            environment: 0,
            n_triplets: 0,
            triplets: [DuetosWifiCountryIeTriplet::default(); COUNTRY_IE_MAX_TRIPLETS],
            ok: 0,
            _pad: [0; 3],
        }
    }
}

const WIFI_FRAME_MIN: usize = 24;
const BEACON_FIXED_BODY_BYTES: usize = 12;
/// EAPOL-Key body lives below a 4-byte EAPOL header (IEEE 802.1X-2010 §11.4).
const EAPOL_HEADER_BYTES: usize = 4;
/// Minimum EAPOL-Key body before the variable-length KeyData blob:
/// 1 (desc_type) + 2 (key_info) + 2 (key_len) + 8 (replay) + 32 (nonce)
/// + 16 (iv) + 8 (rsc) + 8 (reserved) + 16 (mic) + 2 (key_data_len) = 95.
const EAPOL_KEY_FIXED_BYTES: usize = 95;

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

#[inline]
fn load_u16_be(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
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

#[inline]
fn load_u64_be(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
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

fn parse_frame_header(buf: &[u8], out: &mut DuetosWifiFrameHeader) -> bool {
    if buf.len() < WIFI_FRAME_MIN {
        return false;
    }
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
    if out.frame_type == 3 {
        return false;
    }
    out.ok = 1;
    true
}

fn parse_beacon_body(buf: &[u8], out: &mut DuetosWifiBeaconBody) -> bool {
    // Beacon / Probe Response body starts immediately after the
    // 24-byte MAC header. Fixed prefix is 12 bytes (8 timestamp +
    // 2 interval + 2 capability), then IE list.
    let body_start = WIFI_FRAME_MIN;
    if buf.len() < body_start + BEACON_FIXED_BODY_BYTES {
        return false;
    }
    out.timestamp = load_u64_le(buf, body_start);
    out.beacon_interval = load_u16_le(buf, body_start + 8);
    out.capability_info = load_u16_le(buf, body_start + 10);
    out.ie_list_offset = (body_start + BEACON_FIXED_BODY_BYTES) as u32;
    out.ok = 1;
    true
}

/// Decode one Information Element starting at `off`. Returns
/// `false` on a hard parse error (truncated tag).
fn parse_ie(buf: &[u8], off: usize, out: &mut DuetosWifiIe) -> bool {
    if off + 2 > buf.len() {
        return false;
    }
    let id = buf[off];
    let len = buf[off + 1];
    if off + 2 + (len as usize) > buf.len() {
        return false;
    }
    out.id = id;
    out.len = len;
    out.payload_offset = (off + 2) as u32;
    out.ok = 1;
    true
}

/// Parse a Country Information Element payload (the bytes AFTER
/// the 2-byte element-id/length header). Returns true on a
/// well-formed IE; operating-triplet entries (first_channel >=
/// 201) are skipped per the safety property documented above.
fn parse_country_ie(buf: &[u8], out: &mut DuetosWifiCountryIe) -> bool {
    // Minimum payload: 2-byte alpha2 + 1-byte environment.
    if buf.len() < 3 {
        return false;
    }
    out.alpha2[0] = buf[0];
    out.alpha2[1] = buf[1];
    out.environment = buf[2];
    out.n_triplets = 0;
    let mut i: usize = 3;
    // Cap at COUNTRY_IE_MAX_TRIPLETS to bound the stored output
    // AND at TCP_OPT_GUARD-equivalent 64 iterations so a hostile
    // 255-byte IE with 80+ triplets can't tie up the parser.
    let mut visited: u32 = 0;
    while i + 3 <= buf.len() && (out.n_triplets as usize) < COUNTRY_IE_MAX_TRIPLETS && visited < 64 {
        let first = buf[i];
        if first >= 201 {
            // Operating-triplet form: skip 3 bytes without
            // recording. The intersector only consumes sub-band
            // triplets; ignoring operating-class form keeps the
            // safety property intact.
            i = match i.checked_add(3) {
                Some(v) => v,
                None => return true, // saturated; treat as end
            };
            visited = visited.saturating_add(1);
            continue;
        }
        let slot = out.n_triplets as usize;
        out.triplets[slot].first_channel = first;
        out.triplets[slot].num_channels = buf[i + 1];
        out.triplets[slot].max_tx_dbm = buf[i + 2] as i8;
        out.n_triplets += 1;
        i = match i.checked_add(3) {
            Some(v) => v,
            None => return true,
        };
        visited = visited.saturating_add(1);
    }
    out.ok = 1;
    true
}

fn parse_eapol_key(buf: &[u8], out: &mut DuetosWifiEapolKey) -> bool {
    // IEEE 802.1X EAPOL packet header:
    //   [0]   Protocol Version (1 or 2)
    //   [1]   Packet Type (0x03 = EAPOL-Key)
    //   [2..4] Packet Body Length (big-endian)
    //   [4..] Packet Body (the EAPOL-Key descriptor)
    if buf.len() < EAPOL_HEADER_BYTES + EAPOL_KEY_FIXED_BYTES {
        return false;
    }
    if buf[1] != 0x03 {
        return false;
    }
    let body_len = load_u16_be(buf, 2) as usize;
    if EAPOL_HEADER_BYTES + body_len > buf.len() {
        return false;
    }
    if body_len < EAPOL_KEY_FIXED_BYTES {
        return false;
    }
    let body = &buf[EAPOL_HEADER_BYTES..EAPOL_HEADER_BYTES + body_len];
    out.key_descriptor_type = body[0];
    // Key Info, Key Length, Replay Counter are big-endian in the
    // 802.11 EAPOL-Key descriptor.
    out.key_info = load_u16_be(body, 1);
    out.key_length = load_u16_be(body, 3);
    out.replay_counter = load_u64_be(body, 5);
    out.key_nonce.copy_from_slice(&body[13..13 + 32]);
    out.key_iv.copy_from_slice(&body[45..45 + 16]);
    out.key_rsc.copy_from_slice(&body[61..61 + 8]);
    out.key_reserved.copy_from_slice(&body[69..69 + 8]);
    out.key_mic.copy_from_slice(&body[77..77 + 16]);
    out.key_data_length = load_u16_be(body, 93);
    if (out.key_data_length as usize) > body_len - EAPOL_KEY_FIXED_BYTES {
        return false;
    }
    out.key_data_offset = (EAPOL_HEADER_BYTES + EAPOL_KEY_FIXED_BYTES) as u32;
    out.ok = 1;
    true
}

// ---------- FFI ----------

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

#[no_mangle]
pub extern "C" fn duetos_wifi80211_parse_beacon_body(
    buf: *const u8,
    len: usize,
    out: *mut DuetosWifiBeaconBody,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_beacon_body(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_wifi80211_parse_ie(buf: *const u8, len: usize, off: usize, out: *mut DuetosWifiIe) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_ie(slice, off, dst)
}

#[no_mangle]
pub extern "C" fn duetos_wifi80211_parse_country_ie(buf: *const u8, len: usize, out: *mut DuetosWifiCountryIe) -> bool {
    // Route the raw-pointer null-check + zero-init through out_init (as the
    // sibling FFI wrappers do) so the deref lives in the private helper, not
    // this public fn — clippy::not_unsafe_ptr_arg_deref fires otherwise.
    // Zero-init via Default so a partial parse never leaks stale triplets.
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_country_ie(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_wifi80211_parse_eapol_key(buf: *const u8, len: usize, out: *mut DuetosWifiEapolKey) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_eapol_key(slice, dst)
}

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn make_management_beacon() -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0] = 0x80;
        buf[1] = 0;
        buf[2..4].copy_from_slice(&0u16.to_le_bytes());
        buf[4..10].copy_from_slice(&[0xFF; 6]);
        buf[10..16].copy_from_slice(&[0x02; 6]);
        buf[16..22].copy_from_slice(&[0x02; 6]);
        buf[22..24].copy_from_slice(&0u16.to_le_bytes());
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
        buf[0] = 0x08;
        let mut out = DuetosWifiFrameHeader::default();
        assert!(parse_frame_header(&buf, &mut out));
        assert_eq!(out.frame_type, 2);
        assert_eq!(out.frame_subtype, 0);
    }

    #[test]
    fn wifi_extension_frame_rejects() {
        let mut buf = make_management_beacon();
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

    // ---- Beacon body / IE walker ----

    fn make_beacon_with_ssid(ssid: &[u8]) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; 24 + 12 + 2 + ssid.len() + 5];
        // MAC header (subtype=Beacon).
        buf[0] = 0x80;
        // Timestamp + interval + cap.
        buf[24..32].copy_from_slice(&0x1234_5678u64.to_le_bytes());
        buf[32..34].copy_from_slice(&100u16.to_le_bytes());
        buf[34..36].copy_from_slice(&0x0011u16.to_le_bytes());
        // SSID IE (id=0).
        let ie_off = 36;
        buf[ie_off] = 0;
        buf[ie_off + 1] = ssid.len() as u8;
        buf[ie_off + 2..ie_off + 2 + ssid.len()].copy_from_slice(ssid);
        // DS Parameter Set IE (id=3, len=1, channel=6) after the SSID.
        let ds_off = ie_off + 2 + ssid.len();
        buf[ds_off] = 3;
        buf[ds_off + 1] = 1;
        buf[ds_off + 2] = 6;
        buf
    }

    #[test]
    fn beacon_body_decodes() {
        let buf = make_beacon_with_ssid(b"DUETSSID");
        let mut out = DuetosWifiBeaconBody::default();
        assert!(parse_beacon_body(&buf, &mut out));
        assert_eq!(out.timestamp, 0x1234_5678);
        assert_eq!(out.beacon_interval, 100);
        assert_eq!(out.capability_info, 0x0011);
        assert_eq!(out.ie_list_offset, 36);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn beacon_body_too_short_rejects() {
        let buf = [0u8; 30];
        let mut out = DuetosWifiBeaconBody::default();
        assert!(!parse_beacon_body(&buf, &mut out));
    }

    #[test]
    fn ie_walker_finds_ssid_and_dsparam() {
        let buf = make_beacon_with_ssid(b"NetX");
        let body = DuetosWifiBeaconBody::default();
        let mut body_mut = body;
        assert!(parse_beacon_body(&buf, &mut body_mut));
        let mut off = body_mut.ie_list_offset as usize;
        let mut ie = DuetosWifiIe::default();
        assert!(parse_ie(&buf, off, &mut ie));
        assert_eq!(ie.id, 0);
        assert_eq!(ie.len, 4);
        off = ie.payload_offset as usize + ie.len as usize;
        let mut ie2 = DuetosWifiIe::default();
        assert!(parse_ie(&buf, off, &mut ie2));
        assert_eq!(ie2.id, 3);
        assert_eq!(ie2.len, 1);
    }

    #[test]
    fn ie_walker_rejects_truncated() {
        // IE claims 10 bytes but only 3 follow the header.
        let buf = [0u8, 10, 1, 2, 3];
        let mut ie = DuetosWifiIe::default();
        assert!(!parse_ie(&buf, 0, &mut ie));
    }

    // ---- EAPOL-Key ----

    fn make_eapol_key() -> [u8; 4 + 95] {
        let mut buf = [0u8; 4 + 95];
        // EAPOL header.
        buf[0] = 2; // Version 2 (802.1X-2010)
        buf[1] = 0x03; // Type = EAPOL-Key
        buf[2..4].copy_from_slice(&95u16.to_be_bytes()); // body length
                                                         // Body.
        let body = &mut buf[4..];
        body[0] = 2; // Key Descriptor Type: RSN
        body[1..3].copy_from_slice(&0x008Au16.to_be_bytes()); // Key Info
        body[3..5].copy_from_slice(&16u16.to_be_bytes()); // Key Length = 16
        body[5..13].copy_from_slice(&1u64.to_be_bytes()); // Replay counter
                                                          // Nonce, IV, RSC, reserved, MIC stay zero for the test.
        body[93..95].copy_from_slice(&0u16.to_be_bytes()); // Key Data Length
        buf
    }

    #[test]
    fn eapol_key_decodes() {
        let buf = make_eapol_key();
        let mut out = DuetosWifiEapolKey::default();
        assert!(parse_eapol_key(&buf, &mut out));
        assert_eq!(out.key_descriptor_type, 2);
        assert_eq!(out.key_info, 0x008A);
        assert_eq!(out.key_length, 16);
        assert_eq!(out.replay_counter, 1);
        assert_eq!(out.key_data_length, 0);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn eapol_key_wrong_type_rejects() {
        let mut buf = make_eapol_key();
        buf[1] = 0x01; // EAP packet, not EAPOL-Key.
        let mut out = DuetosWifiEapolKey::default();
        assert!(!parse_eapol_key(&buf, &mut out));
    }

    #[test]
    fn eapol_key_truncated_rejects() {
        let buf = [0u8; 10];
        let mut out = DuetosWifiEapolKey::default();
        assert!(!parse_eapol_key(&buf, &mut out));
    }

    #[test]
    fn eapol_key_oversized_keydata_rejects() {
        let mut buf = make_eapol_key();
        // Claim 0xFFFF bytes of KeyData but body length is fixed.
        buf[4 + 93..4 + 95].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let mut out = DuetosWifiEapolKey::default();
        assert!(!parse_eapol_key(&buf, &mut out));
    }

    // --- Country IE ---

    #[test]
    fn country_ie_minimal_no_triplets() {
        // 2 alpha2 bytes + 1 environment.
        let buf = [b'U', b'S', b'I'];
        let mut out = DuetosWifiCountryIe::default();
        assert!(parse_country_ie(&buf, &mut out));
        assert_eq!(out.alpha2, [b'U', b'S']);
        assert_eq!(out.environment, b'I');
        assert_eq!(out.n_triplets, 0);
    }

    #[test]
    fn country_ie_subband_triplet() {
        // US indoor + one sub-band triplet (ch 1, 11 channels, 30 dBm).
        let buf = [b'U', b'S', b'I', 1, 11, 30];
        let mut out = DuetosWifiCountryIe::default();
        assert!(parse_country_ie(&buf, &mut out));
        assert_eq!(out.n_triplets, 1);
        assert_eq!(out.triplets[0].first_channel, 1);
        assert_eq!(out.triplets[0].num_channels, 11);
        assert_eq!(out.triplets[0].max_tx_dbm, 30);
    }

    #[test]
    fn country_ie_signed_dbm_negative() {
        // -1 dBm encoded as 0xFF.
        let buf = [b'J', b'P', b'I', 1, 14, 0xFF];
        let mut out = DuetosWifiCountryIe::default();
        assert!(parse_country_ie(&buf, &mut out));
        assert_eq!(out.triplets[0].max_tx_dbm, -1);
    }

    #[test]
    fn country_ie_operating_triplet_skipped() {
        // Sub-band ch1, then operating triplet (>=201), then sub-band ch36.
        let buf = [b'U', b'S', b'I', 1, 11, 30, 201, 0, 0, 36, 8, 17];
        let mut out = DuetosWifiCountryIe::default();
        assert!(parse_country_ie(&buf, &mut out));
        // 2 sub-band triplets recorded, operating one skipped.
        assert_eq!(out.n_triplets, 2);
        assert_eq!(out.triplets[0].first_channel, 1);
        assert_eq!(out.triplets[1].first_channel, 36);
    }

    #[test]
    fn country_ie_short_buffer_rejects() {
        let buf = [b'U', b'S']; // 2 bytes, need at least 3.
        let mut out = DuetosWifiCountryIe::default();
        assert!(!parse_country_ie(&buf, &mut out));
    }

    #[test]
    fn country_ie_caps_at_16_triplets() {
        // Build 20 sub-band triplets; only first 16 should be stored.
        let mut buf = vec![b'U', b'S', b'I'];
        for i in 0..20 {
            buf.extend_from_slice(&[1 + i as u8, 1, 20]);
        }
        let mut out = DuetosWifiCountryIe::default();
        assert!(parse_country_ie(&buf, &mut out));
        assert_eq!(out.n_triplets, 16);
    }

    #[test]
    fn country_ie_trailing_partial_triplet_ignored() {
        // 2 sub-band triplets + 2 trailing bytes (not enough for triplet).
        let buf = [b'U', b'S', b'I', 1, 11, 30, 36, 8, 17, 0xAA, 0xBB];
        let mut out = DuetosWifiCountryIe::default();
        assert!(parse_country_ie(&buf, &mut out));
        assert_eq!(out.n_triplets, 2);
    }

    #[test]
    fn country_ie_null_out_rejects() {
        let buf = [b'U', b'S', b'I'];
        assert!(!duetos_wifi80211_parse_country_ie(
            buf.as_ptr(),
            buf.len(),
            core::ptr::null_mut(),
        ));
    }
}
