#pragma once

#include "../../core/types.h"

/*
 * CustomOS — USB driver shell, v0.
 *
 * Discovery + classification for USB host controllers. Walks the
 * `pci::Device` cache for serial-bus-controller / USB entries
 * (class 0x0C, subclass 0x03) and categorises each by prog_if:
 *
 *   0x00  UHCI  — USB 1.1 (Intel). Legacy. Port-IO based.
 *   0x10  OHCI  — USB 1.1 (Compaq / IBM). MMIO based.
 *   0x20  EHCI  — USB 2.0. Every post-2005 chipset. MMIO.
 *   0x30  xHCI  — USB 3.0/3.1/3.2/4.0. Current standard. MMIO.
 *   0x80  Other — rarely seen.
 *   0xFE  Device controller (not a host) — skipped.
 *
 * Scope (v0):
 *   - HOST CONTROLLER discovery + classification only.
 *   - BAR 0 mapped as MMIO for each controller.
 *   - Class-driver hooks (HID, MSC) stubbed but not wired —
 *     they need real host-controller enumeration of the bus
 *     topology first, which is the whole-enchilada xHCI slice
 *     that's explicitly deferred (`docs/knowledge/usb-xhci-
 *     scope-estimate.md`).
 *
 * The USB stack above the host controllers is structured as:
 *
 *   host controller (xhci/ehci/...) -> bus enumeration ->
 *   devices -> class drivers (HID keyboard/mouse, MSC flash
 *   drive, printer, Wi-Fi dongle, ...).
 *
 * This slice provides the empty class-driver registration
 * surface so a future slice can fill in each class driver
 * without touching the host-controller discovery layer.
 *
 * Context: kernel. `UsbInit` runs once at boot after
 * `PciEnumerate`.
 */

namespace customos::drivers::usb
{

inline constexpr u8 kPciClassSerialBus = 0x0C;
inline constexpr u8 kPciSubclassUsb = 0x03;

// prog_if values per the USB spec.
inline constexpr u8 kProgIfUhci = 0x00;
inline constexpr u8 kProgIfOhci = 0x10;
inline constexpr u8 kProgIfEhci = 0x20;
inline constexpr u8 kProgIfXhci = 0x30;
inline constexpr u8 kProgIfOther = 0x80;
inline constexpr u8 kProgIfDevice = 0xFE;

inline constexpr u64 kMaxHostControllers = 8;

enum class HciKind : u8
{
    Unknown = 0,
    Uhci,
    Ohci,
    Ehci,
    Xhci,
    Device,
    Other,
};

const char* HciKindName(HciKind k);

struct HostControllerInfo
{
    u16 vendor_id;
    u16 device_id;
    u8 bus;
    u8 device;
    u8 function;
    u8 prog_if;
    HciKind kind;
    u64 mmio_phys;
    u64 mmio_size;
    void* mmio_virt;
};

/// Walk the PCI cache, register every USB host controller, and log
/// the result. Does not enumerate downstream USB devices.
void UsbInit();

/// Number of host controllers discovered.
u64 HostControllerCount();

/// Accessor for a discovered HC record.
const HostControllerInfo& HostController(u64 index);

// -------------------------------------------------------------------
// Class-driver registration hooks. v0: stubs that log "probe OK"
// when a matching (class, subclass, prog_if) triple is seen on the
// bus. A real slice replaces each stub with a real driver: the HID
// class driver needs report-descriptor parsing; the MSC class driver
// needs SCSI-over-USB command execution; the hub driver needs port
// state management.
//
// Class codes per USB.org:
//   0x03  HID      — keyboard, mouse, gamepad
//   0x08  MSC      — mass storage (flash drives, external HDDs)
//   0x09  Hub      — every multi-port USB topology has one
//   0x0E  Video    — UVC webcams
//   0xEF  Misc     — IAD-based composite devices
// -------------------------------------------------------------------

inline constexpr u8 kUsbClassHid = 0x03;
inline constexpr u8 kUsbClassMsc = 0x08;
inline constexpr u8 kUsbClassHub = 0x09;
inline constexpr u8 kUsbClassVideo = 0x0E;

/// Class-driver probe called once per attached device by a future
/// bus-enumeration slice. Today it's a log-only stub surfaced here
/// so the class-driver table exists.
struct UsbClassDriver
{
    u8 class_code;
    const char* name;
    // On attach: called when a device matching `class_code` is
    // enumerated. Returns true if the driver claims the device.
    // v0: always returns false (no real drivers yet).
    bool (*probe)(u8 subclass, u8 prog_if);
};

/// Enumerate the compiled-in class-driver table (HID, MSC, Hub, ...).
u64 ClassDriverCount();
const UsbClassDriver& ClassDriver(u64 index);

} // namespace customos::drivers::usb
