#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Bluetooth HID keyboard input path, v0.
 *
 * The layer the hci.h / diag.h headers deferred ("ACL/SCO data
 * path … L2CAP / RFCOMM / GATT upper-stack"), scoped tightly to the
 * one workload the task needs: a Bluetooth keyboard's keystrokes
 * reaching the shell exactly like a USB or PS/2 keyboard's do.
 *
 * Wire path a keystroke travels:
 *
 *   HCI ACL packet  (transport driver IRQ → BtHidDeliverAcl)
 *     └─ per-connection fragment reassembly (PB flag)
 *        └─ L2CAP B-frame  {len, CID, payload}
 *           ├─ CID 0x0004  → ATT  (BLE HID-over-GATT / HOGP)
 *           │     Handle Value Notification → HID Input Report
 *           └─ dynamic CID → HIDP (classic Bluetooth HID profile)
 *                 DATA/Input transaction → HID Input Report
 *        └─ 8-byte boot-protocol keyboard report
 *           └─ drivers::input::HidKeyboardDiffAndInject
 *              (the SAME decoder + inject queue USB HID uses —
 *               one source of truth, CLAUDE.md rule 6)
 *
 * Subsystem isolation: this is kernel-owned. A future btusb/btuart
 * transport driver is the only producer; it calls BtHidDeliverAcl
 * from its event/ACL IRQ path. No Win32/Linux ABI reaches it. The
 * keyboard report is handed to the kernel input layer through the
 * same cap-free in-kernel API the xHCI HID poll task uses.
 *
 * v0 scope:
 *   - ACL fragment reassembly + L2CAP B-frame decode.
 *   - BLE HOGP: ATT Handle Value Notification / Indication carrying
 *     an 8-byte boot keyboard report (optionally Report-ID-prefixed).
 *   - Classic HID: HIDP DATA/Input frame carrying the same report.
 *   - Bounded connection table; register/unregister keyed on the
 *     12-bit ACL connection handle.
 *
 * GAPs (documented limits, not stubs — the happy path works):
 *   - GAP: no GATT service discovery — BtHidRegisterLeKeyboard is
 *     told the HID Report characteristic value handle by the
 *     connection-setup step; v0 has no SDP/GATT crawler.
 *   - GAP: no SMP pairing / link encryption — a production keyboard
 *     bonds first; v0 decodes the post-connection report stream and
 *     trusts the link. Bonding is a separate security slice.
 *   - GAP: non-boot HID report maps (report-descriptor-defined
 *     field layouts) are not parsed; only the 8-byte boot keyboard
 *     report (optionally one Report-ID prefix byte) is accepted.
 *
 * Threading: BtHidDeliverAcl / register / unregister take the
 * connection-table spinlock and are safe from a transport driver's
 * IRQ context. The parse helpers are pure.
 *
 * Reference: Bluetooth Core 5.4 Vol 3 Part A (L2CAP), Vol 3 Part F
 * (ATT), HID-over-GATT Profile 1.0, HID Profile 1.1 (HIDP).
 */

namespace duetos::net::bluetooth
{

inline constexpr u32 kBtHidMaxConnections = 4;
inline constexpr u32 kBtHidReasmMax = 64; // boot reports never fragment; bound is generous.

// Fixed L2CAP channel ID for the ATT protocol (BLE HOGP rides it).
inline constexpr u16 kL2capCidAtt = 0x0004;

// ATT opcodes carrying a server-pushed value (Vol 3 Part F §3.4.7).
inline constexpr u8 kAttHandleValueNotification = 0x1B;
inline constexpr u8 kAttHandleValueIndication = 0x1D;

// HIDP header for a classic-HID DATA transaction carrying an Input
// report: transaction type DATA (0xA0) | report type Input (0x01).
inline constexpr u8 kHidpHdrDataInput = 0xA1;

// ACL Packet-Boundary flag values (Vol 4 Part E §5.4.2). Only the
// continuation case needs distinguishing; everything else starts a
// fresh L2CAP PDU.
inline constexpr u8 kAclPbContinuation = 0x01;

enum class BtHidKind : u8
{
    None = 0,
    LeHogp,  // BLE: ATT Handle Value Notification on CID 0x0004
    Classic, // BR/EDR: HIDP DATA/Input on the interrupt-channel CID
};

// Decoded HCI ACL header (Vol 4 Part E §5.4.2).
struct BtHidAclHeader
{
    u16 handle; // 12-bit connection handle
    u8 pb;      // packet-boundary flag (bits 12..13)
    u8 bc;      // broadcast flag (bits 14..15)
    u16 data_len;
};

/// Initialise / reset the connection table. Idempotent; safe at
/// boot. Mirrors BluetoothDiagInit.
void BtHidInit();

/// Register a BLE HOGP keyboard once its connection is up. The
/// connection-setup step supplies the HID Report characteristic
/// value handle so notifications can be matched. Pass 0 to accept
/// any 8/9-byte ATT notification on the link (relaxed; see GAP on
/// GATT discovery). Returns AlreadyExists if the ACL handle is
/// already registered, OutOfMemory if the table is full.
::duetos::core::Result<void> BtHidRegisterLeKeyboard(u16 acl_handle, u16 att_report_handle);

/// Register a classic-Bluetooth HID keyboard once its HIDP
/// interrupt L2CAP channel is up. `interrupt_cid` is the local
/// dynamic CID HIDP Input reports arrive on.
::duetos::core::Result<void> BtHidRegisterClassicKeyboard(u16 acl_handle, u16 interrupt_cid);

/// Drop a connection (call on HCI Disconnection_Complete).
/// Idempotent.
void BtHidUnregister(u16 acl_handle);

/// Single ingress for the transport driver's ACL IRQ path: hand it
/// one raw HCI ACL data packet (header + L2CAP fragment). Performs
/// reassembly, routing, report normalisation, and — on a complete
/// boot keyboard report — feeds press/release KeyEvents into the
/// kernel input queue. Unknown handles / non-keyboard CIDs are
/// silently ignored.
void BtHidDeliverAcl(const u8* acl_pkt, u32 len);

// ---- Pure parse helpers (no state; exposed for the self-test) ----

/// Decode the 4-byte ACL header and locate its payload. Returns
/// false on a short buffer or a declared length running past `len`.
bool BtHidParseAclHeader(const u8* p, u32 len, BtHidAclHeader* out, const u8** payload, u32* payload_len);

/// Decode an L2CAP B-frame: {length:u16 LE, cid:u16 LE, payload}.
/// Returns false if `len < 4` or the declared length runs past it.
bool BtHidParseL2cap(const u8* pdu, u32 len, u16* cid, const u8** sdu, u32* sdu_len);

/// Normalise a routed L2CAP SDU into an 8-byte boot keyboard
/// report. `kind` selects ATT-notification vs HIDP framing.
/// `att_match_handle` (LE HOGP, 0 = accept any) gates which
/// notification handle is the keyboard's. Returns false if the SDU
/// isn't a keyboard Input report this v0 decodes.
bool BtHidExtractBootReport(BtHidKind kind, u16 att_match_handle, const u8* sdu, u32 sdu_len, u8 out_report[8]);

// ---- Diagnostics (used by the `bt` shell command) ----

struct BtHidConnectionInfo
{
    bool live;
    BtHidKind kind;
    u16 acl_handle;
    u16 match_id; // LE: ATT report handle; Classic: interrupt CID
    u64 reports_seen;
};

u32 BtHidConnectionCount();
BtHidConnectionInfo BtHidConnectionAt(u32 index);

/// Boot-time self-test. Drives canned ACL packets (BLE ATT
/// notification, classic HIDP, fragmented reassembly, report-ID
/// strip, release-all) end-to-end and KASSERTs the decoded reports
/// + connection state. Captures KeyEvents instead of injecting so
/// the boot input stream stays clean. Logs `[bt-hid] selftest
/// pass` and panics on mismatch.
void BtHidSelfTest();

} // namespace duetos::net::bluetooth
