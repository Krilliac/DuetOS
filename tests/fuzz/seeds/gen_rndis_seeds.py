#!/usr/bin/env python3
# DuetOS USB RNDIS fuzz seed generator.
#
# WHAT  Emits the control-IN *stream* the RNDIS bring-up consumes in
#       order (host_shim/usbnet_stubs.cpp feeds successive control-IN
#       replies straight off this byte stream):
#         [0..9)   GET_DESCRIPTOR(Config) 9-byte header (wTotalLength)
#         [9..)    full Config descriptor RndisParseConfig walks:
#                  comm Interface (class 0x02/sub 0x02/proto 0xFF) +
#                  data Interface (class 0x0A) with bulk IN + bulk OUT
#         then     INITIALIZE_CMPLT  reply (52 bytes) RndisInitialize
#                  SET_CMPLT         reply (16 bytes) RndisSetU32Oid
#                  QUERY_CMPLT       reply (64 bytes) RndisQueryMac
#                  (the classic length/offset spot: MAC read at
#                  8 + InformationBufferOffset after a containment
#                  check on InformationBufferLength / Offset)
#
# WHY   Each bring-up stage gates the next: a malformed descriptor
#       stops before the control replies are parsed, and a wrong
#       message-type / non-success status stops the rest. Random
#       mutation almost never lines all the magic constants up;
#       seeding past them puts the fuzzer straight on the offset math.
#
# USAGE  python3 gen_rndis_seeds.py <out_dir>

import os
import struct
import sys

T_CONFIG = 0x02
T_INTERFACE = 0x04
T_ENDPOINT = 0x05

RNDIS_MSG_INIT_CMPLT = 0x80000002
RNDIS_MSG_SET_CMPLT = 0x80000005
RNDIS_MSG_QUERY_CMPLT = 0x80000004
RNDIS_STATUS_SUCCESS = 0x00000000


def le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def config(total_len, n_iface, config_value=0x01):
    return bytes([
        0x09, T_CONFIG,
        total_len & 0xFF, (total_len >> 8) & 0xFF,
        n_iface, config_value, 0x00, 0x80, 50,
    ])


def interface(ifnum, alt, n_ep, cls, sub, proto):
    return bytes([0x09, T_INTERFACE, ifnum, alt, n_ep, cls, sub, proto, 0x00])


def endpoint(addr, attr, max_packet, interval=0):
    return bytes([
        0x07, T_ENDPOINT, addr, attr,
        max_packet & 0xFF, (max_packet >> 8) & 0xFF, interval,
    ])


def cfg_header(total_len):
    return bytes([0x09, T_CONFIG, total_len & 0xFF, (total_len >> 8) & 0xFF, 0x02, 0x01, 0x00, 0x80, 50])


def full_rndis_config():
    body = (
        interface(0, 0, 1, 0x02, 0x02, 0xFF)   # comm/ctrl iface (RNDIS match_a)
        + endpoint(0x83, 0x03, 8, 1)           # interrupt-IN (ignored, class 0x02)
        + interface(1, 0, 2, 0x0A, 0x00, 0x00)  # data iface (class 0x0A)
        + endpoint(0x81, 0x02, 512)            # bulk IN
        + endpoint(0x02, 0x02, 512)            # bulk OUT
    )
    return config(9 + len(body), 2) + body


def init_cmplt(max_xfer=0x4000, alignment=0):
    r = bytearray(52)
    r[0:4] = le32(RNDIS_MSG_INIT_CMPLT)
    r[4:8] = le32(52)                       # MessageLength
    r[8:12] = le32(1)                       # RequestID
    r[12:16] = le32(RNDIS_STATUS_SUCCESS)   # Status
    r[16:20] = le32(1)                      # MajorVersion
    r[20:24] = le32(0)                      # MinorVersion
    r[36:40] = le32(max_xfer)               # MaxTransferSize
    r[40:44] = le32(alignment)              # PacketAlignmentFactor
    return bytes(r)


def set_cmplt():
    r = bytearray(16)
    r[0:4] = le32(RNDIS_MSG_SET_CMPLT)
    r[4:8] = le32(16)
    r[8:12] = le32(2)
    r[12:16] = le32(RNDIS_STATUS_SUCCESS)
    return bytes(r)


def query_cmplt(info_off=16, mac=b"\x00\x11\x22\x33\x44\x55"):
    # InformationBufferOffset is measured from offset 8; the MAC lands
    # at reply[8 + info_off]. The canonical 16 -> reply[24].
    r = bytearray(64)
    r[0:4] = le32(RNDIS_MSG_QUERY_CMPLT)
    r[4:8] = le32(64)
    r[8:12] = le32(3)
    r[12:16] = le32(RNDIS_STATUS_SUCCESS)
    r[16:20] = le32(len(mac))               # InformationBufferLength
    r[20:24] = le32(info_off)               # InformationBufferOffset
    abs_off = 8 + info_off
    r[abs_off:abs_off + len(mac)] = mac
    return bytes(r)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/rndis"
    os.makedirs(out, exist_ok=True)

    cfg = full_rndis_config()
    head = cfg_header(len(cfg)) + cfg

    canonical = head + init_cmplt() + set_cmplt() + query_cmplt()
    open(os.path.join(out, "canonical.bin"), "wb").write(canonical)

    # Bring-up that stops after the descriptor walk (bad INIT magic).
    open(os.path.join(out, "bad_init_magic.bin"), "wb").write(head + b"\x00" * 52)

    # Reaches QueryMac with a large-but-in-bounds InfoBufferOffset
    # (50 is the max the containment check accepts: 50 > 64-14 is false).
    open(os.path.join(out, "query_off_edge.bin"), "wb").write(
        head + init_cmplt() + set_cmplt() + query_cmplt(info_off=50))

    # Config that fails RndisParseConfig (no data iface) — walker still runs.
    body = interface(0, 0, 1, 0x02, 0x02, 0xFF) + endpoint(0x83, 0x03, 8, 1)
    no_data = config(9 + len(body), 1) + body
    open(os.path.join(out, "no_data_iface.bin"), "wb").write(cfg_header(len(no_data)) + no_data)

    # Truncated descriptor (header over-claims wTotalLength).
    open(os.path.join(out, "truncated.bin"), "wb").write(cfg_header(512) + cfg[:18])

    # Boundary: oversize wTotalLength (rejected by the > 1024 cap).
    open(os.path.join(out, "total_over_cap.bin"), "wb").write(cfg_header(1025) + cfg)

    # Runt / empty.
    open(os.path.join(out, "empty.bin"), "wb").write(b"")
    open(os.path.join(out, "runt.bin"), "wb").write(b"\x09\x02")

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
