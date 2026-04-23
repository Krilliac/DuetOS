#pragma once

#include "../../core/result.h"
#include "../../core/types.h"

/*
 * CustomOS — xHCI USB host-controller driver, v0.
 *
 * Brings each xHCI controller found by drivers/usb/usb.cpp out of
 * reset, programs the minimum data structures the spec demands
 * (DCBAA + command ring + event ring + ERST), starts the
 * controller, and rounds-trips a single NoOp command through the
 * Cmd-ring → doorbell → Event-ring path.
 *
 * Scope (v0):
 *   - HCRST + wait for !CNR.
 *   - Allocate DCBAA (max_slots+1 × 8 B, page-aligned).
 *   - Allocate command ring (256 TRBs × 16 B = 4 KiB) with a
 *     trailing Link TRB pointing back to entry 0.
 *   - Allocate event ring (256 TRBs × 16 B) + Event Ring Segment
 *     Table (16 B, one entry).
 *   - Wire DCBAAP, CRCR (with cycle bit 1), CONFIG.MaxSlotsEn.
 *   - Wire interrupter 0: ERSTSZ=1, ERSTBA, ERDP.
 *   - USBCMD.RS=1; wait for USBSTS.HCH to clear.
 *   - Issue NoOp (TRB type 23) on the Cmd ring; ring doorbell 0;
 *     poll the event ring for a Command Completion event with our
 *     command-TRB pointer.
 *   - Scan every PORTSC, reset + Enable Slot for each connected
 *     port, stash the slot id on PortRecord.
 *   - For each enabled slot: build the Device + Input contexts
 *     (respecting HCCPARAMS1.CSZ), allocate an EP0 transfer ring,
 *     submit Address Device, then issue GET_DESCRIPTOR(Device) via
 *     a Setup/Data/Status three-TRB control transfer on EP0. Parse
 *     the 18-byte device descriptor + log VID/PID/class per port.
 *   - GET_DESCRIPTOR(Config) in two phases — 9-byte header to
 *     learn wTotalLength, then the full tree. Walk the tree for
 *     HID (class=3) / Boot (subclass=1) / Keyboard (protocol=1)
 *     interface descriptors; record the interface number, its
 *     first interrupt-IN endpoint's address, wMaxPacketSize and
 *     bInterval.
 *
 * Not in scope (this slice):
 *   - SET_CONFIGURATION, Configure Endpoint, interrupt-IN transfer
 *     ring, HID polling task, keyboard-event injection. All of
 *     those hang off the HID-keyboard fields populated here; the
 *     next slice lights them up into actual keystrokes.
 *   - Scratchpad buffers (we panic-skip if the controller asks
 *     for any; QEMU's xHCI doesn't on q35).
 *   - MSI-X interrupt completion — every command + control
 *     transfer is polled.
 *
 * Why polling: until we wire MSI-X for completion + an IRQ-driven
 * event-ring consumer, polling the event ring with a timeout keeps
 * the bring-up self-test legible without blocking on infrastructure.
 *
 * Context: kernel. Init runs once after UsbInit, before the boot-
 * time self-tests log.
 */

namespace customos::drivers::usb::xhci
{

inline constexpr u32 kMaxXhciPortsPerController = 16;

/// One slot's worth of per-port state captured at port-scan time
/// + what enumeration learned about the attached device.
struct PortRecord
{
    u8 port_num;        // 1-based xHCI port number
    bool connected;     // CCS at scan time
    bool reset_ok;      // PRESET sequence completed (PED set)
    bool slot_ok;       // Enable Slot succeeded
    bool addressed;     // Address Device succeeded
    bool descriptor_ok; // GET_DESCRIPTOR(Device) round-trip succeeded
    u8 slot_id;         // valid iff slot_ok
    u8 speed;           // PORTSC bits 13:10 (1=full, 2=low, 3=high, 4=super, 5=super+)
    u32 portsc_at_scan;
    // Device-descriptor fields populated on successful
    // GET_DESCRIPTOR(Device). Zeroed until descriptor_ok is true.
    u16 vendor_id;
    u16 product_id;
    u8 device_class;
    u8 device_subclass;
    u8 device_protocol;
    u8 max_packet_size_0;
    // Configuration-descriptor fields populated on successful
    // GET_DESCRIPTOR(Config). Walked for HID Boot Keyboard; if
    // found, hid_* fields record where the interrupt-IN endpoint
    // sits and how often it wants to be polled. The next slice
    // consumes these to submit SET_CONFIGURATION / Configure
    // Endpoint / periodic Normal TRBs.
    bool config_desc_ok;
    u16 config_desc_bytes;
    u8 hid_config_value; // bConfigurationValue from top-level Config desc
    bool hid_keyboard;
    u8 hid_interface_num;
    u8 hid_ep_addr;        // bEndpointAddress: bit 7 = IN direction
    u16 hid_ep_max_packet; // wMaxPacketSize of the HID int-IN endpoint
    u8 hid_ep_interval;    // bInterval, raw (USB units)
};

/// Per-controller stats. One slot per discovered xHCI; populated
/// during init.
struct ControllerInfo
{
    u8 bus;
    u8 device;
    u8 function;
    bool init_ok;            // controller reset + ring setup succeeded
    bool noop_ok;            // NoOp command round-tripped through the event ring
    u8 max_slots;            // HCSPARAMS1.MaxSlots
    u8 max_ports;            // HCSPARAMS1.MaxPorts
    u16 max_intrs;           // HCSPARAMS1.MaxIntrs
    u32 max_scratchpad;      // HCSPARAMS2 high|low (0 on QEMU q35 default)
    u64 dcbaa_phys;          // physical base of DCBAA
    u64 cmd_ring_phys;       // physical base of command ring
    u64 event_ring_phys;     // physical base of event ring
    u64 erst_phys;           // physical base of ERST
    u32 ports_connected;     // count of ports with a device at scan time
    u32 slots_enabled;       // count of successful Enable Slot commands
    u32 devices_addressed;   // count of successful Address Device commands
    u32 descriptors_fetched; // count of successful GET_DESCRIPTOR(Device) transfers
    u32 configs_parsed;      // count of successful GET_DESCRIPTOR(Config) + parse
    u32 hid_keyboards_found; // count of ports that resolved to a HID boot keyboard
    u32 hid_keyboards_bound; // count of ports that fully came up for HID polling
    u32 context_bytes;       // HCCPARAMS1.CSZ → 32 or 64
    PortRecord ports[kMaxXhciPortsPerController];
};

/// Walk drivers::usb::HostController() entries; for each xHCI run
/// init + NoOp round-trip; fill the per-controller record. Logs
/// pass/fail per controller. Safe exactly once at boot.
void XhciInit();

/// Quiesce every brought-up controller: USBCMD.RS=0, wait for
/// HCH=1, clear ring / DCBAA / ERST pointers so the next Init
/// starts fresh. Does NOT free allocator pages — the physical
/// frames stay held by the controller records until a subsequent
/// Init re-uses them; re-init with a clean state is cheap.
/// Returns Ok on full quiesce, BadState if any controller
/// didn't halt within the deadline.
::customos::core::Result<void> XhciShutdown();

/// Shutdown + Init round-trip. Used by the fault-domain restart
/// path and the `xhci restart` shell command.
::customos::core::Result<void> XhciRestart();

u32 XhciCount();
const ControllerInfo* XhciControllerAt(u32 i);

} // namespace customos::drivers::usb::xhci
