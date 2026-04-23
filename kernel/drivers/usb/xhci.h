#pragma once

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
 *   - Log the round-trip and the per-controller resources.
 *
 * Not in scope:
 *   - Scratchpad buffers (we panic-skip if the controller asks
 *     for any; QEMU's xHCI doesn't on q35).
 *   - Port reset / device address / descriptor fetch.
 *   - MSI-X interrupt completion (NoOp is polled).
 *   - Bulk / interrupt / isoch transfer rings.
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

/// One slot's worth of per-port state captured at port-scan time.
struct PortRecord
{
    u8 port_num;    // 1-based xHCI port number
    bool connected; // CCS at scan time
    bool reset_ok;  // PRESET sequence completed (PED set)
    bool slot_ok;   // Enable Slot succeeded
    u8 slot_id;     // valid iff slot_ok
    u8 speed;       // PORTSC bits 13:10 (1=full, 2=low, 3=high, 4=super, 5=super+)
    u32 portsc_at_scan;
};

/// Per-controller stats. One slot per discovered xHCI; populated
/// during init.
struct ControllerInfo
{
    u8 bus;
    u8 device;
    u8 function;
    bool init_ok;        // controller reset + ring setup succeeded
    bool noop_ok;        // NoOp command round-tripped through the event ring
    u8 max_slots;        // HCSPARAMS1.MaxSlots
    u8 max_ports;        // HCSPARAMS1.MaxPorts
    u16 max_intrs;       // HCSPARAMS1.MaxIntrs
    u32 max_scratchpad;  // HCSPARAMS2 high|low (0 on QEMU q35 default)
    u64 dcbaa_phys;      // physical base of DCBAA
    u64 cmd_ring_phys;   // physical base of command ring
    u64 event_ring_phys; // physical base of event ring
    u64 erst_phys;       // physical base of ERST
    u32 ports_connected; // count of ports with a device at scan time
    u32 slots_enabled;   // count of successful Enable Slot commands
    PortRecord ports[kMaxXhciPortsPerController];
};

/// Walk drivers::usb::HostController() entries; for each xHCI run
/// init + NoOp round-trip; fill the per-controller record. Logs
/// pass/fail per controller. Safe exactly once at boot.
void XhciInit();

u32 XhciCount();
const ControllerInfo* XhciControllerAt(u32 i);

} // namespace customos::drivers::usb::xhci
