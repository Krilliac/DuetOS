#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Bluetooth Host Controller Interface (HCI) packet parser
 * + builder, v0.
 *
 * The HCI is the wire protocol the host CPU uses to talk to a
 * Bluetooth controller — across USB, UART (H4 / 3-Wire), SDIO, or
 * SPI. The packet shapes are fixed by the Bluetooth Core
 * Specification Vol 4 Part E §5.4. This module handles the four
 * packet types at the byte level:
 *
 *   - Command   (host -> controller, 3-byte header + N params)
 *   - Event     (controller -> host, 2-byte header + N params)
 *   - ACL data  (bidirectional, 4-byte header + payload)
 *   - SCO data  (bidirectional, 3-byte header + payload)
 *
 * v0 scope:
 *   - Encode Command packets: HCI_Reset, HCI_Read_Local_Version_
 *     Information, HCI_Read_BD_ADDR, HCI_LE_Set_Scan_Parameters,
 *     HCI_LE_Set_Scan_Enable.
 *   - Decode Event packets: Command_Complete, Command_Status,
 *     Disconnection_Complete, LE_Meta_Event header.
 *   - Decode the parameter payload of Command_Complete responses
 *     for HCI_Read_Local_Version_Information and HCI_Read_BD_ADDR.
 *   - Build the H4 transport-layer indicator byte that
 *     UART / SDIO transports prefix to every packet (USB transport
 *     splits packet kinds across endpoints, so it ignores the H4
 *     byte; the helper is here for both transports).
 *
 * Out of scope (deferred):
 *   - ACL / SCO data path. v0 is identification + LE scan only —
 *     the bytes that move once a connection is up are a separate
 *     slice owned by the upper-stack TUs (L2CAP / RFCOMM / GATT).
 *   - Vendor-specific opcodes (OGF=0x3F). Real chips use them for
 *     firmware patch RAM upload and PSKEY tweaks; that's a per-
 *     vendor follow-on.
 *   - Extended (LE 5.x) advertising / extended scan commands.
 *     Classic + LE 1.x scan is the v0 surface.
 *
 * Threading: pure functions. No global state. Safe from any
 * context (including IRQ if the caller has the bytes already).
 *
 * Subsystem isolation: this is a freestanding parser. It is
 * called by kernel-only callers (a future btusb driver, the boot
 * self-test). No subsystem (Win32 / Linux ABI) reaches it
 * directly.
 *
 * Reference: Bluetooth Core Specification 5.4 Vol 4 Part E §5.4
 * (HCI packet formats), §7.1 (Link Control commands), §7.4
 * (Informational parameters), §7.8 (LE Controller commands).
 */

namespace duetos::net::bluetooth
{

// H4 transport-layer packet indicator byte. UART / SDIO
// transports prefix one of these to every packet on the wire;
// USB transport doesn't need it (packet kind is implicit in
// endpoint type).
inline constexpr u8 kH4PacketCmd = 0x01;
inline constexpr u8 kH4PacketAclData = 0x02;
inline constexpr u8 kH4PacketScoData = 0x03;
inline constexpr u8 kH4PacketEvent = 0x04;
inline constexpr u8 kH4PacketIso = 0x05;

// Opcode group field values (top 6 bits of the 16-bit opcode).
inline constexpr u8 kOgfLinkControl = 0x01;
inline constexpr u8 kOgfLinkPolicy = 0x02;
inline constexpr u8 kOgfHostController = 0x03;
inline constexpr u8 kOgfInformational = 0x04;
inline constexpr u8 kOgfStatus = 0x05;
inline constexpr u8 kOgfTesting = 0x06;
inline constexpr u8 kOgfLeController = 0x08;
inline constexpr u8 kOgfVendor = 0x3F;

// Opcode command field values (low 10 bits) for the v0 commands
// we encode. Names match the Bluetooth Core Spec.
inline constexpr u16 kOcfDisconnect = 0x0006;          // OGF=link control
inline constexpr u16 kOcfReset = 0x0003;               // OGF=host controller
inline constexpr u16 kOcfReadLocalVersion = 0x0001;    // OGF=informational
inline constexpr u16 kOcfReadBdAddr = 0x0009;          // OGF=informational
inline constexpr u16 kOcfLeSetScanParameters = 0x000B; // OGF=LE controller
inline constexpr u16 kOcfLeSetScanEnable = 0x000C;     // OGF=LE controller

// Event codes (Vol 4 Part E §7.7).
inline constexpr u8 kEvtDisconnectionComplete = 0x05;
inline constexpr u8 kEvtCommandComplete = 0x0E;
inline constexpr u8 kEvtCommandStatus = 0x0F;
inline constexpr u8 kEvtNumberOfCompletedPackets = 0x13;
inline constexpr u8 kEvtLeMetaEvent = 0x3E;

// LE Meta-Event sub-events (the byte at parameter offset 0 of an
// LE meta event).
inline constexpr u8 kLeSubEvtConnectionComplete = 0x01;
inline constexpr u8 kLeSubEvtAdvertisingReport = 0x02;
inline constexpr u8 kLeSubEvtConnectionUpdateComplete = 0x03;

// LE-scan-parameters argument constants (§7.8.10).
inline constexpr u8 kLeScanTypePassive = 0x00;
inline constexpr u8 kLeScanTypeActive = 0x01;
inline constexpr u8 kLeOwnAddrTypePublic = 0x00;
inline constexpr u8 kLeOwnAddrTypeRandom = 0x01;
inline constexpr u8 kLeFilterPolicyAll = 0x00;
inline constexpr u8 kLeFilterPolicyWhitelist = 0x01;

// Packet-size envelopes.
inline constexpr u32 kHciCmdHeaderBytes = 3;
inline constexpr u32 kHciEvtHeaderBytes = 2;
inline constexpr u32 kHciCmdMaxParamLen = 255;
inline constexpr u32 kHciEvtMaxParamLen = 255;
inline constexpr u32 kHciCmdMaxBytes = kHciCmdHeaderBytes + kHciCmdMaxParamLen;

// Pack/unpack the 16-bit OPCODE field. The wire form is
// (OGF << 10) | (OCF & 0x03FF) and is transmitted little-endian.
inline constexpr u16 HciOpcode(u8 ogf, u16 ocf)
{
    return static_cast<u16>((static_cast<u16>(ogf & 0x3F) << 10) | (ocf & 0x03FF));
}

inline constexpr u8 HciOpcodeOgf(u16 op)
{
    return static_cast<u8>((op >> 10) & 0x3F);
}

inline constexpr u16 HciOpcodeOcf(u16 op)
{
    return static_cast<u16>(op & 0x03FF);
}

// Decoded HCI event header.
struct HciEventHeader
{
    u8 event_code;
    u8 parameter_total_length;
    const u8* parameters; // points into the caller's buffer
    u32 parameters_size;
};

// Decoded Command_Complete event header (excluding the per-command
// return parameters).
struct HciCommandComplete
{
    u8 num_hci_command_packets; // host's allowed in-flight count
    u16 command_opcode;
    const u8* return_parameters; // points into caller's buffer
    u32 return_parameters_size;
};

// Decoded Command_Status event.
struct HciCommandStatus
{
    u8 status; // 0 == success
    u8 num_hci_command_packets;
    u16 command_opcode;
};

// Decoded Read_Local_Version_Information return parameters.
struct HciReadLocalVersion
{
    u8 status;
    u8 hci_version;
    u16 hci_revision;
    u8 lmp_version;
    u16 manufacturer_name;
    u16 lmp_subversion;
};

// Decoded Read_BD_ADDR return parameters.
struct HciReadBdAddr
{
    u8 status;
    u8 bd_addr[6]; // little-endian on the wire; we keep wire order
};

/// Build an HCI Command packet with no parameters. Returns the
/// number of bytes written into `out`, or 0 on null/short buffer.
u32 HciBuildCmd(u8* out, u32 out_size, u8 ogf, u16 ocf);

/// Build an HCI Command packet with `params_len` parameter bytes
/// copied from `params`. Returns the byte count written, or 0 on
/// null/short buffer or `params_len > kHciCmdMaxParamLen`.
u32 HciBuildCmdWithParams(u8* out, u32 out_size, u8 ogf, u16 ocf, const u8* params, u8 params_len);

/// Build a HCI_Reset command packet (no parameters). Convenience
/// wrapper around HciBuildCmd.
u32 HciBuildCmdReset(u8* out, u32 out_size);

/// Build a HCI_LE_Set_Scan_Parameters command packet (§7.8.10).
/// `interval` and `window` are in units of 0.625 ms.
u32 HciBuildCmdLeSetScanParameters(u8* out, u32 out_size, u8 le_scan_type, u16 interval, u16 window, u8 own_addr_type,
                                   u8 filter_policy);

/// Build a HCI_LE_Set_Scan_Enable command packet (§7.8.11).
u32 HciBuildCmdLeSetScanEnable(u8* out, u32 out_size, u8 enable, u8 filter_duplicates);

/// Parse the 2-byte event header. Returns false if `len < 2` or
/// the declared parameter length runs past `len`.
bool HciParseEventHeader(const u8* buf, u32 len, HciEventHeader* out);

/// Parse the parameters of a Command_Complete event (event code
/// 0x0E). Caller passes the full event packet (header + params).
/// Returns false on a non-Command_Complete event or a short
/// parameter block.
bool HciParseCommandComplete(const u8* buf, u32 len, HciCommandComplete* out);

/// Parse the parameters of a Command_Status event (event code
/// 0x0F). Same input contract as HciParseCommandComplete.
bool HciParseCommandStatus(const u8* buf, u32 len, HciCommandStatus* out);

/// Decode the return parameters of HCI_Read_Local_Version_Information
/// (Command_Complete return parameters, 9 bytes).
bool HciParseReadLocalVersion(const u8* buf, u32 len, HciReadLocalVersion* out);

/// Decode the return parameters of HCI_Read_BD_ADDR (Command_Complete
/// return parameters, 7 bytes).
bool HciParseReadBdAddr(const u8* buf, u32 len, HciReadBdAddr* out);

/// Pretty-print a one-line summary of any event packet to the
/// kernel serial log. Idempotent / no allocation.
void HciEventLog(const HciEventHeader& evt);

/// Boot-time self-test. Round-trips the HCI_Reset, LE-scan, and
/// status/parameter encoders, then feeds canned event-bytes
/// through every parser and KASSERTs the decoded fields. Logs
/// `[bt-hci] selftest pass/fail` and panics on failure.
void HciSelfTest();

} // namespace duetos::net::bluetooth
