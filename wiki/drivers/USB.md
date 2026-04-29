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

See `.claude/knowledge/xhci-enumeration-v0.md`.

## HID Boot Keyboard

`kernel/drivers/usb/class/hid/keyboard/`.

End-to-end USB keyboard input on boot. The boot-protocol report layout
(8-byte fixed-format report) is decoded into key events and routed
into the input subsystem. Key events feed the kernel shell + the
compositor's focused window.

See `.claude/knowledge/xhci-hid-keyboard-v0.md`.

## CDC-ECM

`kernel/drivers/usb/class/cdc-ecm/`.

USB Communications Device Class — Ethernet Control Model. Presents a
USB device as a netif via the kernel net stack. Used by USB Ethernet
adapters.

GAP: probe is not yet auto-called (deferred to a follow-up). See
`.claude/knowledge/usb-cdc-ecm-driver-v0.md`.

## RNDIS

`kernel/drivers/usb/class/rndis/`.

Remote Network Driver Interface Specification — Microsoft's USB
ethernet protocol. Control plane (initialize / set OID / query OID)
works. Bulk RX delivers every `RNDIS_PACKET_MSG` per bulk transfer
(was: only the first).

GAP: bulk-poll concurrency. See
`.claude/knowledge/usb-rndis-driver-v0.md`.

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
