// DuetOS Bluetooth HCI walker C FFI — hand-written. Mirrors
// kernel/net/hci_rust/src/lib.rs.
//
// Status: SKELETON. Currently no C++ caller.

#pragma once

#include "util/types.h"

namespace duetos::net::hci
{

inline constexpr u8 kHciPacketTypeCommand = 0x01;
inline constexpr u8 kHciPacketTypeAclData = 0x02;
inline constexpr u8 kHciPacketTypeScoData = 0x03;
inline constexpr u8 kHciPacketTypeEvent = 0x04;
inline constexpr u8 kHciPacketTypeIsoData = 0x05;

struct DuetosHciEvent
{
    u8 event_code;
    u8 param_total_length;
    u16 param_off;
    u8 ok;
    u8 _pad[3];
};

extern "C"
{
    /// Parse an HCI event packet (packet-type 0x04). Validates the
    /// packet-type byte, reads the event code + parameter total
    /// length, and confirms the parameters fit in the supplied
    /// buffer. The C++ caller indexes `buf[out.param_off ..
    /// out.param_off + out.param_total_length]` to walk the body.
    bool duetos_hci_parse_event_packet(const u8* buf, usize len, DuetosHciEvent* out);
}

} // namespace duetos::net::hci
