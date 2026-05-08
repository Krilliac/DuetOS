# USB (xHCI + Class)

> **Audience:** Driver authors
>
> **Execution context:** Kernel — IRQ + softirq + process
>
> **Maturity:** v0 host + boot-keyboard HID, CDC-ECM and RNDIS class drivers

## Overview

```
[ USB device ]
     |
[ xHCI host controller ]               kernel/drivers/usb/xhci/
     |
[ USB core ]                           kernel/drivers/usb/core/
     |
[ Class driver ]                       kernel/drivers/usb/class/{hid,msc,cdc-ecm,rndis}/
     |
[ Subsystem (input, net, fs) ]
```

## xHCI Host v0

`kernel/drivers/usb/xhci/`.

- Initializes capability + operational + runtime + doorbell register
  spaces.
- Allocates command ring + event ring + transfer rings.
- Address Device + Get Descriptor(Device) on enumeration.
- Bulk-transfer API shared with class drivers.

## Rust Descriptor Parsers

`kernel/drivers/usb/class_rust/` contains the no_std Rust configuration
descriptor walker for class-driver binding. It recognizes MSC bulk-only
interfaces, hubs, UVC control/streaming interfaces, and Bluetooth USB interfaces
and records their endpoint sets.

`kernel/drivers/usb/hid_rust/` contains the no_std Rust HID report-descriptor
parser. `kernel/drivers/usb/hid_descriptor.cpp` keeps the public C++ API and
self-tests, but the descriptor walk and mouse-layout extraction are Rust FFI
calls. These parsers validate the aggregate `/kernel/rust` staticlib model for
multiple USB-facing Rust subsystems.

USB descriptors are treated as hostile input even though they come from
"hardware": a malicious USB peripheral can return arbitrary bytes for descriptor
requests, including impossible lengths, duplicate or high-numbered report IDs,
truncated items, and deeply nested HID collections. The Rust crates keep that
byte-level walk in safe slice-based code after a narrow C ABI validates the raw
pointer/length pair.

## HID Boot Keyboard

`kernel/drivers/usb/class/hid/keyboard/`.

End-to-end USB keyboard input on boot. The boot-protocol report layout
(8-byte fixed-format report) is decoded into key events and routed
into the input subsystem. Key events feed the kernel shell + the
compositor's focused window.

## CDC-ECM

`kernel/drivers/usb/class/cdc-ecm/`.

USB Communications Device Class — Ethernet Control Model. Presents a
USB device as a netif via the kernel net stack. Used by USB Ethernet
adapters.

GAP: probe is not yet auto-called (deferred to a follow-up).

## RNDIS

`kernel/drivers/usb/class/rndis/`.

Remote Network Driver Interface Specification — Microsoft's USB
ethernet protocol. Control plane (initialize / set OID / query OID)
works. Bulk RX delivers every `RNDIS_PACKET_MSG` per bulk transfer
(was: only the first).

GAP: bulk-poll concurrency. The control plane is single-threaded, but
the bulk RX path can race with class-side teardown if a host hot-plugs
mid-poll.

## Known Limits / GAPs

- **No MSC (mass-storage class) driver yet.** USB sticks are not
  bootable as system disks today.
- **Hot-plug after boot** is not exercised; the device list is what
  the host enumerated at boot.
- **No xHCI suspend / resume.**

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [Networking Drivers](Networking-Drivers.md) — CDC-ECM and RNDIS feed
  the net stack
- [Input](Input.md) — HID boot keyboard
- [Live Internet Verification](../networking/Live-Internet.md)
