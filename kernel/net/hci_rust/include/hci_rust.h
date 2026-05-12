// DuetOS Bluetooth HCI walker C FFI — hand-written. Mirrors
// kernel/net/hci_rust/src/lib.rs.

#pragma once

#include "util/types.h"

namespace duetos::net::hci_rust
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

struct DuetosHciCommandComplete
{
    u8 num_hci_command_packets;
    u8 _pad0;
    u16 command_opcode;
    u16 return_parameters_off;
    u16 return_parameters_size;
    u8 ok;
    u8 _pad[3];
};

struct DuetosHciCommandStatus
{
    u8 status;
    u8 num_hci_command_packets;
    u16 command_opcode;
    u8 ok;
    u8 _pad[3];
};

struct DuetosHciDisconnectionComplete
{
    u8 status;
    u8 _pad0;
    u16 connection_handle;
    u8 reason;
    u8 _pad1;
    u8 ok;
    u8 _pad2[5];
};

struct DuetosHciLeMeta
{
    u8 subevent_code;
    u8 _pad0;
    u16 param_off;
    u16 param_size;
    u8 ok;
    u8 _pad[3];
};

struct DuetosHciReadLocalVersion
{
    u8 status;
    u8 hci_version;
    u16 hci_revision;
    u8 lmp_version;
    u8 _pad0;
    u16 manufacturer_name;
    u16 lmp_subversion;
    u8 ok;
    u8 _pad[5];
};

struct DuetosHciReadBdAddr
{
    u8 status;
    u8 _pad0;
    u8 bd_addr[6];
    u8 ok;
    u8 _pad[7];
};

extern "C"
{
    /// Parse an HCI event packet header (packet-type prefix +
    /// event code + parameter length).
    bool duetos_hci_parse_event_packet(const u8* buf, usize len, DuetosHciEvent* out);

    /// Parse a Command_Complete event (0x0E).
    bool duetos_hci_parse_command_complete(const u8* buf, usize len, DuetosHciCommandComplete* out);

    /// Parse a Command_Status event (0x0F).
    bool duetos_hci_parse_command_status(const u8* buf, usize len, DuetosHciCommandStatus* out);

    /// Parse a Disconnection_Complete event (0x05).
    bool duetos_hci_parse_disconnection_complete(const u8* buf, usize len, DuetosHciDisconnectionComplete* out);

    /// Parse an LE Meta event (0x3E) header.
    bool duetos_hci_parse_le_meta(const u8* buf, usize len, DuetosHciLeMeta* out);

    /// Parse a Read_Local_Version_Information return-parameter
    /// block (9 bytes). Caller hands us the rparams the
    /// Command_Complete envelope pointed at.
    bool duetos_hci_parse_read_local_version(const u8* buf, usize len, DuetosHciReadLocalVersion* out);

    /// Parse a Read_BD_ADDR return-parameter block (7 bytes).
    bool duetos_hci_parse_read_bd_addr(const u8* buf, usize len, DuetosHciReadBdAddr* out);
}

} // namespace duetos::net::hci_rust
