#pragma once

#include "util/types.h"

/*
 * DuetOS — USB CDC-ECM Ethernet driver, v0.
 *
 * USB Communications Device Class - Ethernet Networking Control
 * Model. The standard, vendor-agnostic way to expose an Ethernet
 * interface over USB. Works with:
 *   - QEMU's `-device usb-net` (CDC-ECM by default)
 *   - Most premium USB-Ethernet dongles (those that don't use
 *     vendor-specific protocols like AX88xxx or RTL8152)
 *   - iPhone USB tethering (Apple Mobile Device Ethernet uses an
 *     ECM-like layout — same bulk-IN/bulk-OUT shape; v0 only
 *     binds the RNDIS-free path)
 *
 * Scope (v0):
 *   - Probe any device whose bDeviceClass = 0x02 (Communications)
 *     and bDeviceSubClass = 0x06 (Ethernet Control Model).
 *   - GET_DESCRIPTOR(Config) → parse for:
 *       - bConfigurationValue
 *       - Data interface number + alt setting 1 (the one with
 *         bulk endpoints; alt 0 has none)
 *       - Bulk-IN + Bulk-OUT endpoint addresses + max-packet sizes
 *       - iMACAddress index from the CDC Ethernet Functional
 *         Descriptor (subtype 0x0F)
 *   - GET_DESCRIPTOR(String, iMACAddress) → parse 12-char ASCII
 *     hex MAC.
 *   - SET_CONFIGURATION + SET_INTERFACE 1.
 *   - SET_ETHERNET_PACKET_FILTER (class request 0x43) with
 *     DIRECTED | BROADCAST | ALL_MULTICAST so the device's RX
 *     path delivers everything we care about.
 *   - Configure both bulk endpoints via xHCI; spawn an
 *     `cdc-ecm-rx` poll task; register a TX trampoline; bind as
 *     `iface 1` of the kernel network stack and kick off DHCP.
 *
 * Out of scope (deferred):
 *   - The interrupt-IN management endpoint that carries
 *     CONNECTION_SPEED_CHANGE / NETWORK_CONNECTION notifications.
 *     Not required for v0 — DHCP succeeds without us listening.
 *   - CDC-NCM (NTB packet aggregation; iPhones beyond ECM mode).
 *   - RNDIS (Microsoft, what most Android phones default to).
 *   - Multi-instance — one CDC-ECM device at a time.
 */

namespace duetos::drivers::usb
{

/// Walk every xHCI-enumerated device for class 0x02 / subclass
/// 0x06 (CDC-ECM). On a match, parse its config descriptor, bring
/// it up, and bind it as iface 1 in the network stack. Idempotent —
/// second call no-ops. Returns true iff a CDC-ECM device came online.
///
/// NOT AUTO-CALLED AT BOOT in v0. See the knowledge entry
/// `usb-cdc-ecm-driver-v0.md` for the DHCP-regression issue that
/// surfaces when the probe runs during xHCI init — short version:
/// the probe's synchronous control transfers interact badly with
/// the pre-poll-task event-ring state and stall the e1000 RX path.
/// Call this manually from a shell command / kernel thread once a
/// real CDC-ECM device is attached.
bool CdcEcmProbe();

struct CdcEcmStats
{
    bool online;
    u8 mac[6];
    u8 slot_id;
    u8 bulk_in_ep;
    u8 bulk_out_ep;
    u16 bulk_in_mps;
    u16 bulk_out_mps;
    u32 rx_packets;
    u32 rx_bytes;
    u32 rx_dropped;
    u32 tx_packets;
    u32 tx_bytes;
    u32 tx_failures;
};

CdcEcmStats CdcEcmStatsRead();

} // namespace duetos::drivers::usb
