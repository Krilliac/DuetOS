#pragma once

#include "util/types.h"

/*
 * DuetOS — USB Bluetooth (btusb) transport driver, v0.
 *
 * The producer that feeds the Bluetooth HID keyboard upper stack
 * (`net/bluetooth/hid.{h,cpp}`) real bytes. A standards-compliant
 * USB Bluetooth controller declares class 0xE0 / subclass 0x01 /
 * protocol 0x01 on its primary interface and exposes (Bluetooth
 * Core Spec Vol 4 Part B §2.1):
 *
 *   - EP0 control      — HCI Commands (class request bmRequestType
 *                        0x20, bRequest 0x00).
 *   - Interrupt IN     — HCI Events.
 *   - Bulk IN / OUT    — ACL data (the HID reports ride this once a
 *                        keyboard connection is up).
 *   - Isochronous      — SCO voice (not used by a keyboard).
 *
 * v0 transport scope (built on the real xHCI transfer surface —
 * the interrupt-IN primitive is additive: independent DeviceState
 * fields + functions, so no bulk/HID/EP0 caller is perturbed):
 *   - Find the controller (`XhciFindDeviceByClass`), parse its
 *     config descriptor for the bulk-IN / bulk-OUT (ACL) and
 *     interrupt-IN (events) endpoints, SET_CONFIGURATION, configure
 *     the bulk + interrupt-IN endpoints, register a diag adapter.
 *   - Send the HCI identity bring-up commands (Reset,
 *     Read_Local_Version, Read_BD_ADDR) over EP0 via the class
 *     request.
 *   - Spawn two RX pumps: bulk-IN → `BtHidDeliverAcl` (the real,
 *     wired keyboard data path) and interrupt-IN → HCI event
 *     processing (records to the diag ring, stamps the adapter from
 *     the Command_Complete bring-up answers, tears a HID connection
 *     down on Disconnection_Complete).
 *
 * GAPs (documented limits, not stubs):
 *   - GAP: no connection manager. v0 processes HCI events but does
 *     not yet drive LE scan/connect, SMP pairing/bonding, or GATT
 *     (HOGP) service discovery — so a real BT keyboard cannot
 *     associate on its own and call `BtHidRegisterLeKeyboard`.
 *     That layer is a deliberate separate frontier (the project
 *     defers SMP; see wiki/reference/Design-Decisions.md). Once a
 *     link is up and a keyboard registered, the full
 *     ACL→keystroke path is real and self-tested.
 *   - GAP: no SCO / isochronous path (voice — not a keyboard).
 *   - GAP: the event-endpoint Interval is a fixed 8 ms, not derived
 *     from the descriptor's bInterval (fine for HCI events).
 *
 * Wiring: like `CdcEcmProbe`, `BtusbProbe` is deliberately NOT
 * auto-called at boot. Auto-probing every enumerated device runs
 * control transfers + spawns an RX pump that races the shared xHCI
 * event-ring consumer with the HID poll task, which regresses the
 * e1000 DHCP path until the follow-up TRB-dispatch slice lands (see
 * the CdcEcmProbe note in kernel/core/main.cpp). It is invokable on
 * demand via the `bt probe` shell subcommand. The probe logic is
 * boot self-tested (`[btusb] selftest pass`).
 *
 * Subsystem isolation: kernel-owned. The ACL pump hands raw HCI
 * ACL packets to `duetos::net::bluetooth::BtHidDeliverAcl`; the
 * keyboard report reaches the input layer through the same cap-free
 * in-kernel API the xHCI HID poll task uses.
 */

namespace duetos::drivers::usb
{

// USB Bluetooth class-specific request used to push an HCI Command
// down EP0 (Vol 4 Part B §2.2.2): host→device | class | device.
inline constexpr u8 kBtusbReqTypeHciCommand = 0x20;
inline constexpr u8 kBtusbReqHciCommand = 0x00;

struct BtusbStats
{
    bool online;
    u8 slot_id;
    u8 acl_in_ep;
    u8 acl_out_ep;
    u8 event_in_ep; // HCI events drained by the event RX pump
    u64 acl_packets_rx;
    u64 acl_bytes_rx;
    u64 acl_short_drops;
    u64 hci_cmds_sent;
};

/// Probe + bring up a USB Bluetooth controller and start the ACL
/// RX pump. Returns true if a controller was found and brought up.
/// Safe to call when none is attached (returns false, no side
/// effects). Invoked on demand (shell `bt probe`), not at boot.
bool BtusbProbe();

/// Snapshot of driver state for the `bt` shell command.
BtusbStats BtusbStatsRead();

/// Boot-time self-test of the transport-framing logic: HCI command
/// class-request parameters, endpoint-role classification from a
/// synthetic Bluetooth-interface config descriptor, and the ACL
/// hand-off length clamp. Pure (no hardware). Logs `[btusb]
/// selftest pass` and panics on mismatch.
void BtusbSelfTest();

} // namespace duetos::drivers::usb
