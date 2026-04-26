#pragma once

#include "util/types.h"

/*
 * DuetOS — USB RNDIS Ethernet driver, v0.
 *
 * Microsoft's "Remote NDIS" protocol: an RPC-style command channel
 * over the USB control pipe, plus a packet-aggregating framing layer
 * over bulk IN / bulk OUT. RNDIS is what:
 *   - QEMU's `-device usb-net` emulates by default (no rndis=off)
 *   - Most Android phones use for USB tethering (default)
 *   - Many Windows-compatible USB-Ethernet dongles speak natively
 *
 * Protocol shape (per Microsoft RNDIS spec rev 1.1):
 *
 *   Control channel (over EP0):
 *     SEND_ENCAPSULATED_COMMAND (bRequest=0x00, type=0x21) — host
 *       writes a RNDIS message struct; device parses + executes.
 *     GET_ENCAPSULATED_RESPONSE (bRequest=0x01, type=0xA1) — host
 *       reads the matching reply.
 *
 *   Bring-up sequence:
 *     1. INITIALIZE_MSG     → INITIALIZE_CMPLT (learn max_xfer_size)
 *     2. SET_MSG OID_GEN_CURRENT_PACKET_FILTER = directed | broadcast
 *     3. QUERY_MSG OID_802_3_PERMANENT_ADDRESS → 6-byte MAC
 *     4. Configure bulk IN + bulk OUT endpoints in the xHCI device ctx
 *
 *   Data plane (over bulk IN / bulk OUT):
 *     Each USB transfer carries one or more RNDIS_PACKET_MSG records.
 *     Each record = 44-byte header + Ethernet frame.
 *
 * Scope (v0):
 *   - Single-packet-per-transfer on TX (no aggregation).
 *   - RX accepts the first packet in each transfer; multi-packet
 *     aggregation is a follow-up (need to walk the per-transfer
 *     header chain).
 *   - No PnP messages (RNDIS_INDICATE_STATUS_MSG); we ignore
 *     incoming control-plane notifications.
 *   - No interrupt-IN notification endpoint polling — we do
 *     blocking GET_ENCAPSULATED_RESPONSE after each command.
 *   - Manual invocation only — `RndisProbe()` must be called
 *     by a kernel thread or shell command, NOT from kernel_main
 *     (same auto-probe regression as CDC-ECM; see knowledge).
 */

namespace duetos::drivers::usb
{

/// Walk every xHCI-enumerated device and try to bring up the first
/// one that responds to RNDIS INITIALIZE. Returns true iff a device
/// came online. Caller is responsible for ensuring the xHCI HID
/// poll task isn't actively draining the event ring (use
/// XhciPauseEventConsumer, now a compatibility no-op).
bool RndisProbe();

struct RndisStats
{
    bool online;
    u8 mac[6];
    u8 slot_id;
    u32 device_max_xfer;
    u32 packet_alignment;
    u32 rx_packets;
    u32 rx_bytes;
    u32 rx_dropped;
    u32 tx_packets;
    u32 tx_bytes;
    u32 tx_failures;
    u32 control_msgs;
    u32 control_failures;
};

RndisStats RndisStatsRead();

} // namespace duetos::drivers::usb
