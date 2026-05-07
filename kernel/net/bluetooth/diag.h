#pragma once

#include "net/bluetooth/hci.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Bluetooth diagnostic layer, v0.
 *
 * Companion to `net/bluetooth/hci.{h,cpp}`. The HCI parser is a
 * pure byte-level encoder/decoder; this module is the kernel-owned
 * inventory of attached Bluetooth adapters and a small ring of the
 * most-recent HCI events seen from each.
 *
 * Why it lives here: when a btusb/btuart transport driver lands,
 * it'll parse every IRQ-delivered event packet into an
 * `HciEventHeader` and call `BluetoothDiagRecordEvent` so:
 *   - The `bt` shell command can render adapter state without
 *     piggy-backing on the transport driver's private logs.
 *   - A future GUI Settings panel can subscribe to adapter events
 *     through one stable kernel surface.
 *   - Boot self-tests can drive synthetic events through the diag
 *     layer to exercise it end-to-end without a real adapter.
 *
 * v0 scope:
 *   - Bounded adapter inventory (`kBluetoothMaxAdapters` slots).
 *   - Bounded last-events ring per adapter (`kBluetoothEventRingSize`).
 *   - Stats counters: events_seen / cmd_complete_seen /
 *     cmd_status_seen / unknown_event / overflow.
 *   - Setter for adapter identity (BD_ADDR, manufacturer name) so
 *     a transport driver can stamp it once the chip answers
 *     Read_Local_Version + Read_BD_ADDR.
 *
 * Out of scope:
 *   - The transport drivers themselves (btusb, btuart). Coming.
 *   - L2CAP / RFCOMM / GATT upper-stack. Each is its own slice.
 *
 * Threading: every public function takes the diag spinlock. Safe
 * to call from any kernel context, including the IRQ handler of a
 * transport driver delivering events.
 */

namespace duetos::net::bluetooth
{

inline constexpr u32 kBluetoothMaxAdapters = 4;
inline constexpr u32 kBluetoothEventRingSize = 32;
inline constexpr u32 kBluetoothNameMax = 47; // DEVICE_NAME field is 248 bytes; we truncate to 47+NUL.

enum class BluetoothTransport : u8
{
    Unknown = 0,
    Usb,      // btusb — class 0xE0 / sub 0x01 / prog 0x01
    Uart,     // H4 over UART (SoCs, dev boards)
    Sdio,     // Common in laptops with WLAN+BT combo cards
    Loopback, // self-test only — no real chip
};

const char* BluetoothTransportName(BluetoothTransport t);

// One slot per attached controller.
struct BluetoothAdapter
{
    bool live;
    BluetoothTransport transport;
    u8 bd_addr[6]; // 0..0 until the controller answers Read_BD_ADDR
    bool bd_addr_valid;
    u16 manufacturer_id; // from Read_Local_Version response
    u8 hci_version;
    u8 lmp_version;
    char name[kBluetoothNameMax + 1]; // friendly name; transport driver fills

    u64 events_seen;
    u64 cmd_complete_seen;
    u64 cmd_status_seen;
    u64 disconnection_seen;
    u64 le_meta_seen;
    u64 unknown_seen;
    u64 ring_overflows;
};

// One slot in the per-adapter recent-events ring. Captures the
// HCI event-code byte + parameter total length so the shell can
// render the sequence without re-parsing the original bytes.
struct BluetoothEventRecord
{
    u64 sequence;
    u8 event_code;
    u8 parameter_total_length;
    u16 command_opcode; // populated for Command_Complete + Command_Status; 0 otherwise
    u8 le_subevent;     // populated for LE_Meta_Event; 0 otherwise
    u8 status;          // first parameter byte for Command_Status; 0 otherwise
};

/// Initialise the diag layer. Idempotent. Safe to call from boot.
void BluetoothDiagInit();

/// Register a new adapter. Returns the slot index on success or
/// `Err{ErrorCode::OutOfMemory}` if every slot is taken.
::duetos::core::Result<u32> BluetoothDiagRegisterAdapter(BluetoothTransport transport);

/// Mark an adapter slot free. Idempotent. The slot's events ring
/// is cleared.
void BluetoothDiagUnregisterAdapter(u32 slot);

/// Stamp an adapter's identity once Read_Local_Version succeeds.
void BluetoothDiagStampLocalVersion(u32 slot, const HciReadLocalVersion& v);

/// Stamp an adapter's BD_ADDR once Read_BD_ADDR succeeds.
void BluetoothDiagStampBdAddr(u32 slot, const HciReadBdAddr& a);

/// Set the adapter's friendly name. Truncates to `kBluetoothNameMax`.
void BluetoothDiagSetName(u32 slot, const char* name);

/// Record an HCI event into the adapter's ring + bump counters.
/// The transport driver's IRQ path calls this once per event.
void BluetoothDiagRecordEvent(u32 slot, const HciEventHeader& evt);

/// Synthesize events for the boot self-test. Bypasses the transport
/// path so the diag layer can be exercised before a real adapter
/// exists. Logs `[bt-diag] selftest pass/fail` and panics on
/// failure.
void BluetoothDiagSelfTest();

/// Diagnostic accessors — used by the `bt` shell command.
u32 BluetoothDiagAdapterCount();
const BluetoothAdapter& BluetoothDiagAdapter(u32 slot);
u32 BluetoothDiagEventRingFill(u32 slot);
const BluetoothEventRecord& BluetoothDiagEventRingAt(u32 slot, u32 index);

} // namespace duetos::net::bluetooth
