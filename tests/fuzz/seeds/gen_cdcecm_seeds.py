#!/usr/bin/env python3
# DuetOS USB CDC-ECM fuzz seed generator.
#
# WHAT  Emits the control-IN *stream* the CDC-ECM bring-up consumes
#       in order (host_shim/usbnet_stubs.cpp feeds successive
#       GET_DESCRIPTOR / control-IN replies straight off this byte
#       stream):
#         [0..9)   GET_DESCRIPTOR(Config) 9-byte header (only
#                  wTotalLength at off 2 is read; gate: <= 1024)
#         [9..)    full Config descriptor that ParseConfigDescriptor
#                  walks: Config -> comm Interface -> CDC Ethernet
#                  Functional Descriptor (subtype 0x0F, iMACAddress)
#                  -> data Interface alt=1 -> bulk IN + bulk OUT
#         then     GET_DESCRIPTOR(String) reply ReadMacFromString
#                  parses for 12 ASCII-hex MAC chars (UTF-16LE)
#
# WHY   ParseConfigDescriptor only runs ReadMacFromString + the rest
#       of bring-up once the descriptor yields all four required
#       fields (data iface, bulk IN, bulk OUT, iMAC index). Random
#       mutation reaches a valid Config wrapper ~1 in 65k; seeding
#       past it puts the fuzzer straight on the interesting walk.
#
# USAGE  python3 gen_cdcecm_seeds.py <out_dir>

import os
import sys

T_CONFIG = 0x02
T_STRING = 0x03
T_INTERFACE = 0x04
T_ENDPOINT = 0x05
T_CS_INTERFACE = 0x24
CDC_SUBTYPE_ETHERNET = 0x0F
CLASS_CDC_COMM = 0x02
CLASS_CDC_DATA = 0x0A


def config(total_len, n_iface, config_value=0x01):
    return bytes([
        0x09, T_CONFIG,
        total_len & 0xFF, (total_len >> 8) & 0xFF,  # wTotalLength
        n_iface, config_value, 0x00, 0x80, 50,
    ])


def interface(ifnum, alt, n_ep, cls, sub, proto):
    return bytes([0x09, T_INTERFACE, ifnum, alt, n_ep, cls, sub, proto, 0x00])


def endpoint(addr, attr, max_packet, interval=0):
    return bytes([
        0x07, T_ENDPOINT, addr, attr,
        max_packet & 0xFF, (max_packet >> 8) & 0xFF, interval,
    ])


def cdc_ethernet_func(imac_idx):
    # CDC Ethernet Networking Functional Descriptor (CDC1.2 §5.2.3.2),
    # bLength=13, bDescriptorType=0x24, bDescriptorSubtype=0x0F.
    return bytes([
        0x0D, T_CS_INTERFACE, CDC_SUBTYPE_ETHERNET,
        imac_idx,                       # iMACAddress string index
        0x00, 0x00, 0x00, 0x00,         # bmEthernetStatistics
        0xEA, 0x05,                     # wMaxSegmentSize (1514)
        0x00, 0x00,                     # wNumberMCFilters
        0x00,                           # bNumberPowerFilters
    ])


def mac_string_descriptor(mac_hex="001122334455"):
    # USB string descriptor: bLength, bDescriptorType=0x03, then
    # UTF-16LE chars. ReadMacFromString takes the low byte of each.
    chars = b"".join(bytes([ord(c), 0x00]) for c in mac_hex)
    return bytes([2 + len(chars), T_STRING]) + chars


def cfg_header(total_len):
    # 9-byte GET_DESCRIPTOR(Config) header; only wTotalLength matters.
    return bytes([0x09, T_CONFIG, total_len & 0xFF, (total_len >> 8) & 0xFF, 0x01, 0x01, 0x00, 0x80, 50])


def full_cdc_config(imac_idx=1):
    body = (
        interface(0, 0, 1, CLASS_CDC_COMM, 0x06, 0x00)  # comm iface (ECM subclass)
        + cdc_ethernet_func(imac_idx)
        + interface(1, 0, 0, CLASS_CDC_DATA, 0x00, 0x00)  # data iface alt 0 (no eps)
        + interface(1, 1, 2, CLASS_CDC_DATA, 0x00, 0x00)  # data iface alt 1
        + endpoint(0x81, 0x02, 512)                       # bulk IN
        + endpoint(0x02, 0x02, 512)                       # bulk OUT
    )
    return config(9 + len(body), 2) + body


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/cdcecm"
    os.makedirs(out, exist_ok=True)

    cfg = full_cdc_config(imac_idx=1)
    canonical = cfg_header(len(cfg)) + cfg + mac_string_descriptor()
    open(os.path.join(out, "canonical.bin"), "wb").write(canonical)

    # No functional descriptor -> iMAC never found (walker still runs).
    body = (
        interface(0, 0, 1, CLASS_CDC_COMM, 0x06, 0x00)
        + interface(1, 1, 2, CLASS_CDC_DATA, 0x00, 0x00)
        + endpoint(0x81, 0x02, 512) + endpoint(0x02, 0x02, 512)
    )
    no_func = config(9 + len(body), 2) + body
    open(os.path.join(out, "no_func_desc.bin"), "wb").write(cfg_header(len(no_func)) + no_func)

    # Truncated: header claims a wTotalLength longer than the bytes.
    open(os.path.join(out, "truncated.bin"), "wb").write(cfg_header(512) + cfg[:20])

    # Boundary: wTotalLength == cap (1024) and just over (1025, rejected).
    open(os.path.join(out, "total_1024.bin"), "wb").write(cfg_header(1024) + cfg)
    open(os.path.join(out, "total_over_cap.bin"), "wb").write(cfg_header(1025) + cfg)

    # Minimal 9-byte config header only (no descriptor body).
    open(os.path.join(out, "header_only.bin"), "wb").write(cfg_header(9) + config(9, 0))

    # Zero-length / runt inputs.
    open(os.path.join(out, "empty.bin"), "wb").write(b"")
    open(os.path.join(out, "runt.bin"), "wb").write(b"\x09\x02")

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
