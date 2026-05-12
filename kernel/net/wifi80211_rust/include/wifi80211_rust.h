// DuetOS IEEE 802.11 management-frame walker C FFI — hand-written.
// Mirrors kernel/net/wifi80211_rust/src/lib.rs.
//
// Status: SKELETON. Currently no C++ caller.

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

extern "C"
{
    /// Decode the 24-byte 802.11 frame header (3-address case).
    /// Returns true with `out->ok = 1` on success; rejects
    /// extension frames (type=3) so callers explicitly opt in
    /// when extension support lands.
    bool duetos_wifi80211_parse_frame_header(const u8* buf, usize len, DuetosWifiFrameHeader* out);
}

} // namespace duetos::net::wifi80211
