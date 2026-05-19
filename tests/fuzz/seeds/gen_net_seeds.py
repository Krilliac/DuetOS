#!/usr/bin/env python3
# DuetOS network-ingest fuzz seed generator.
#
# WHAT  Emits well-formed Ethernet frames (ARP request, IPv4+ICMP
#       echo, IPv4+UDP, IPv4+TCP SYN) with correct IPv4 / ICMP
#       header checksums, so fuzz_net's NetStackInjectRx walks
#       past the ethertype + IPv4 sanity gates and exercises the
#       ICMP / UDP / TCP parsers (and the duetos_net_parsers Rust
#       DHCP/DNS option walkers) on mutated input.
#
# WHY   Random bytes reach ARP/IPv4 occasionally but rarely carry
#       a valid IPv4 header (version/IHL + checksum) to reach L4.
#
# USAGE  python3 gen_net_seeds.py <out_dir>

import os
import struct
import sys

ETH_HDR = 14
SRC_MAC = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
DST_MAC = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
SRC_IP = bytes([10, 0, 2, 2])
DST_IP = bytes([10, 0, 2, 15])


def inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def eth(ethertype: int) -> bytearray:
    f = bytearray()
    f += DST_MAC + SRC_MAC + struct.pack(">H", ethertype)
    return f


def ipv4(proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    ip = bytearray(20)
    ip[0] = 0x45                       # version 4, IHL 5
    struct.pack_into(">H", ip, 2, total)
    struct.pack_into(">H", ip, 4, 0x0001)   # ident
    ip[8] = 64                          # TTL
    ip[9] = proto
    ip[12:16] = SRC_IP
    ip[16:20] = DST_IP
    ck = inet_checksum(bytes(ip))
    struct.pack_into(">H", ip, 10, ck)
    return bytes(ip) + payload


def seed_arp() -> bytes:
    f = eth(0x0806)
    arp = bytearray(28)
    struct.pack_into(">H", arp, 0, 1)        # htype Ethernet
    struct.pack_into(">H", arp, 2, 0x0800)   # ptype IPv4
    arp[4] = 6                                # hlen
    arp[5] = 4                                # plen
    struct.pack_into(">H", arp, 6, 1)        # op = request
    arp[8:14] = SRC_MAC
    arp[14:18] = SRC_IP
    arp[24:28] = DST_IP
    return bytes(f + arp)


def seed_icmp() -> bytes:
    icmp = bytearray(12)
    icmp[0] = 0x08                            # echo request
    struct.pack_into(">H", icmp, 4, 1)       # id
    struct.pack_into(">H", icmp, 6, 1)       # seq
    icmp[8:12] = b"\xde\xad\xbe\xef"
    struct.pack_into(">H", icmp, 2, inet_checksum(bytes(icmp)))
    return bytes(eth(0x0800) + ipv4(1, bytes(icmp)))


def seed_udp() -> bytes:
    # UDP from :68 to :67 (DHCP-shaped) so the Rust DHCP option
    # walker is on the reachable path.
    payload = bytes(32)
    udp = bytearray(8 + len(payload))
    struct.pack_into(">H", udp, 0, 68)       # src port
    struct.pack_into(">H", udp, 2, 67)       # dst port
    struct.pack_into(">H", udp, 4, len(udp))
    udp[8:] = payload
    return bytes(eth(0x0800) + ipv4(17, bytes(udp)))


def seed_tcp() -> bytes:
    tcp = bytearray(20)
    struct.pack_into(">H", tcp, 0, 12345)    # src port
    struct.pack_into(">H", tcp, 2, 80)       # dst port
    struct.pack_into(">I", tcp, 4, 1)        # seq
    tcp[12] = 0x50                            # data offset 5
    tcp[13] = 0x02                            # SYN
    struct.pack_into(">H", tcp, 14, 1024)    # window
    return bytes(eth(0x0800) + ipv4(6, bytes(tcp)))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/net"
    os.makedirs(out, exist_ok=True)
    seeds = {
        "arp.bin": seed_arp(),
        "icmp.bin": seed_icmp(),
        "udp.bin": seed_udp(),
        "tcp.bin": seed_tcp(),
    }
    for name, data in seeds.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data)
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
