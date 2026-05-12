// DuetOS IEEE 802.11 management-frame walker C FFI — hand-written.
// Mirrors kernel/net/wifi80211_rust/src/lib.rs.

#pragma once

#include "util/types.h"

namespace duetos::net::wifi80211
{

struct DuetosWifiFrameHeader
{
    u8 frame_type;
    u8 frame_subtype;
    u8 flags;
    u8 _pad;
    u16 duration_id;
    u16 _pad2;
    u8 addr1[6];
    u8 addr2[6];
    u8 addr3[6];
    u16 sequence_control;
    u8 ok;
    u8 _pad3;
};

struct DuetosWifiIe
{
    u8 id;
    u8 len;
    u16 _pad;
    u32 payload_offset;
    u8 ok;
    u8 _pad2[7];
};

struct DuetosWifiBeaconBody
{
    u64 timestamp;
    u16 beacon_interval;
    u16 capability_info;
    u32 ie_list_offset;
    u8 ok;
    u8 _pad[3];
};

struct DuetosWifiEapolKey
{
    u8 key_descriptor_type;
    u8 _pad0;
    u16 key_info;
    u16 key_length;
    u16 _pad1;
    u64 replay_counter;
    u8 key_nonce[32];
    u8 key_iv[16];
    u8 key_rsc[8];
    u8 key_reserved[8];
    u8 key_mic[16];
    u16 key_data_length;
    u16 _pad2;
    u32 key_data_offset;
    u8 ok;
    u8 _pad3[7];
};

extern "C"
{
    /// Decode the 24-byte 802.11 frame header (3-address case).
    /// Rejects extension frames (type=3).
    bool duetos_wifi80211_parse_frame_header(const u8* buf, usize len, DuetosWifiFrameHeader* out);

    /// Decode the fixed prefix of a Beacon / Probe Response body
    /// (timestamp + beacon_interval + capability_info) and return
    /// the byte offset where the IE list begins.
    bool duetos_wifi80211_parse_beacon_body(const u8* buf, usize len, DuetosWifiBeaconBody* out);

    /// Decode one IE (Information Element) starting at byte `off`.
    /// Returns false on a truncated tag.
    bool duetos_wifi80211_parse_ie(const u8* buf, usize len, usize off, DuetosWifiIe* out);

    /// Decode an EAPOL-Key descriptor (4-way handshake message).
    /// Validates the EAPOL header, descriptor-fixed-prefix length,
    /// and the KeyData length field.
    bool duetos_wifi80211_parse_eapol_key(const u8* buf, usize len, DuetosWifiEapolKey* out);
}

} // namespace duetos::net::wifi80211
