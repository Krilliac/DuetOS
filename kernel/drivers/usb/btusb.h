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
 * v0 transport scope (built on the existing real xHCI transfer
 * surface — no changes to the working HID/event ring):
 *   - Find the controller (`XhciFindDeviceByClass`), parse its
 *     config descriptor for the bulk-IN / bulk-OUT (ACL) and
 *     interrupt-IN (events) endpoints, SET_CONFIGURATION, configure
 *     the bulk endpoints.
 *   - Send the HCI identity bring-up commands (Reset,
 *     Read_Local_Version, Read_BD_ADDR) over EP0 via the class
 *     request, and stamp the diag adapter.
 *   - Spawn an ACL RX pump: bulk-IN → `BtHidDeliverAcl`. This is
 *     the real, wired keyboard data path.
 *
 * GAPs (documented limits, not stubs):
 *   - GAP: the HCI **event** interrupt-IN endpoint is not drained
 *     in v0. The public xHCI surface exposes control + bulk only;
 *     adding a generic interrupt-IN primitive would perturb the
 *     working HID poll/event ring, which is a separate slice. Until
 *     then HCI command *responses* (Command_Complete) and async
 *     events (LE Connection Complete, Disconnection_Complete) are
 *     not consumed — so connection establishment / SMP pairing /
 *     GATT (HOGP) discovery is the next slice. The ACL→keyboard
 *     decode itself is fully real and self-tested (BtHid).
 *   - GAP: no SCO / isochronous path (voice — not a keyboard).
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
    u8 event_in_ep; // located but not yet drained (see GAP)
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
