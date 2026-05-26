#!/usr/bin/env python3
# DuetOS USB class-descriptor fuzz seed generator.
#
# WHAT  Emits realistic USB configuration-descriptor byte streams
#       (the layout a kernel sees from a successful
#       GET_DESCRIPTOR(CONFIGURATION) response). Each seed walks
#       through Configuration -> Interface -> Endpoint chains
#       past the byte-0 length gate and the byte-1 type gate, so
#       the fuzzer immediately exercises:
#         - mass storage (bulk-only): MSC interface + bulk IN/OUT
#         - HID (boot mouse): HID interface + interrupt IN
#         - hub: hub interface + interrupt IN
#
# WHY   USB descriptor parsing is structurally a TLV walk where
#       each (bLength, bDescriptorType) header gates a typed
#       payload. Random mutation reaches a valid Configuration
#       wrapper roughly 1 in 65k; seeded coverage skips that.
#       Subsequent interface + endpoint chains exercise the
#       per-class flag-extraction in duetos_usbclass_parse_config.
#
# USAGE  python3 gen_usbclass_seeds.py <out_dir>

import os
import sys


# Descriptor types (USB 2.0 §9.4).
T_CONFIG = 0x02
T_INTERFACE = 0x04
T_ENDPOINT = 0x05
T_HID = 0x21


def config(total_len: int, n_iface: int, attr: int = 0x80, max_power: int = 50) -> bytes:
    # 9-byte Configuration descriptor.
    return bytes([
        0x09,                              # bLength
        T_CONFIG,                          # bDescriptorType
        total_len & 0xFF, (total_len >> 8) & 0xFF,  # wTotalLength
        n_iface,                           # bNumInterfaces
        0x01,                              # bConfigurationValue
        0x00,                              # iConfiguration
        attr,                              # bmAttributes (bus-powered)
        max_power,                         # bMaxPower (× 2 mA)
    ])


def interface(ifnum: int, n_ep: int, cls: int, sub: int, proto: int) -> bytes:
    # 9-byte Interface descriptor.
    return bytes([
        0x09, T_INTERFACE,
        ifnum,                             # bInterfaceNumber
        0x00,                              # bAlternateSetting
        n_ep,                              # bNumEndpoints
        cls, sub, proto,
        0x00,                              # iInterface
    ])


def endpoint(addr: int, attr: int, max_packet: int, interval: int) -> bytes:
    # 7-byte Endpoint descriptor.
    return bytes([
        0x07, T_ENDPOINT,
        addr,                              # bEndpointAddress (bit 7 = IN/OUT)
        attr,                              # bmAttributes (00=ctrl, 01=iso, 02=bulk, 03=intr)
        max_packet & 0xFF, (max_packet >> 8) & 0xFF,
        interval,
    ])


def hid_descriptor(report_len: int) -> bytes:
    # 9-byte HID descriptor (USB HID 1.11 §6.2.1).
    return bytes([
        0x09, T_HID,
        0x11, 0x01,                        # bcdHID 1.11
        0x00,                              # bCountryCode
        0x01,                              # bNumDescriptors
        0x22,                              # bDescriptorType (Report)
        report_len & 0xFF, (report_len >> 8) & 0xFF,
    ])


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/usbclass"
    os.makedirs(out, exist_ok=True)

    # MSC (bulk-only) — class 0x08 / subclass 0x06 / protocol 0x50.
    # One interface, two bulk endpoints (IN 0x81, OUT 0x02).
    iface_msc = interface(0, 2, 0x08, 0x06, 0x50)
    ep_in = endpoint(0x81, 0x02, 512, 0)
    ep_out = endpoint(0x02, 0x02, 512, 0)
    body = iface_msc + ep_in + ep_out
    msc = config(9 + len(body), 1) + body
    open(os.path.join(out, "msc.bin"), "wb").write(msc)

    # Hub — class 0x09 / subclass 0 / protocol 0 (full-speed) +
    # interrupt-IN endpoint for status change notifications.
    iface_hub = interface(0, 1, 0x09, 0x00, 0x00)
    ep_intr = endpoint(0x81, 0x03, 8, 0xFF)
    body = iface_hub + ep_intr
    hub = config(9 + len(body), 1) + body
    open(os.path.join(out, "hub.bin"), "wb").write(hub)

    # Boot mouse — HID class 0x03 / subclass 0x01 (boot) /
    # protocol 0x02 (mouse). Interface + HID descriptor +
    # interrupt-IN.
    iface_mouse = interface(0, 1, 0x03, 0x01, 0x02)
    hid_d = hid_descriptor(50)
    ep_mouse = endpoint(0x81, 0x03, 8, 10)
    body = iface_mouse + hid_d + ep_mouse
    mouse = config(9 + len(body), 1) + body
    open(os.path.join(out, "mouse_boot.bin"), "wb").write(mouse)

    # Composite device — two interfaces (MSC + HID).
    body = (interface(0, 2, 0x08, 0x06, 0x50) + ep_in + ep_out
            + interface(1, 1, 0x03, 0x01, 0x02) + hid_d + ep_mouse)
    composite = config(9 + len(body), 2) + body
    open(os.path.join(out, "composite.bin"), "wb").write(composite)

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
