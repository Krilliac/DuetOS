#!/usr/bin/env python3
# DuetOS network-ingest fuzz seed generator.
#
# WHAT  Emits well-formed Ethernet frames (ARP request, IPv4+ICMP
#       echo, IPv4+UDP, IPv4+TCP SYN, and the IPv6 peers: IPv6+ICMPv6
#       echo, IPv6+UDP, IPv6+TCP SYN) with correct IPv4 / ICMP and
#       IPv6 upper-layer pseudo-header checksums, so fuzz_net's
#       NetStackInjectRx walks past the ethertype + L3 sanity gates
#       and exercises the ICMP(v6) / UDP / TCP parsers (and the
#       duetos_net_parsers Rust DHCP/DNS option walkers) on mutated
#       input — for both address families.
#
# WHY   Random bytes reach ARP/IPv4 occasionally but rarely carry a
#       valid IPv4/IPv6 header (version + checksum) to reach L4. The
#       ethertype-0x86DD branch (Ipv6HandleIncoming -> Ipv6HeaderParse
#       -> ICMPv6/UDP/TCP) was wired into NetStackInjectRx but had no
#       seed, so the whole IPv6 RX parse surface was effectively dark
#       under fuzzing until these three seeds landed.
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


# Link-local IPv6 addresses (fe80::/64). The exact value does not
# matter for the parser walk — these just have to form a valid v6
# header so NetStackInjectRx demuxes ethertype 0x86DD into
# Ipv6HandleIncoming -> Ipv6HeaderParse and the ICMPv6 / UDP / TCP
# sub-parsers, which were dark until this seed landed.
SRC_IP6 = bytes([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55])
DST_IP6 = bytes([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0xAA, 0xBB, 0xFF, 0xFE, 0xCC, 0xDD, 0xEE])


def ipv6(next_header: int, payload: bytes, hop_limit: int = 255) -> bytes:
    hdr = bytearray(40)
    hdr[0] = 0x60                              # version 6
    struct.pack_into(">H", hdr, 4, len(payload))  # payload length
    hdr[6] = next_header
    hdr[7] = hop_limit
    hdr[8:24] = SRC_IP6
    hdr[24:40] = DST_IP6
    return bytes(hdr) + payload


def ipv6_pseudo_checksum(next_header: int, payload: bytes) -> int:
    # RFC 8200 §8.1 upper-layer checksum: ones-complement sum over
    # {src(16) dst(16) upper_len(4) zero(3) next_header(1)} + payload,
    # with the L4 checksum field already zeroed in `payload`.
    ph = SRC_IP6 + DST_IP6 + struct.pack(">I", len(payload)) + bytes([0, 0, 0, next_header])
    return inet_checksum(ph + payload)


def seed_ipv6_icmp6() -> bytes:
    # ICMPv6 Echo Request (type 128) — checksum-validated by
    # HandleIcmpv6 before the type dispatch.
    icmp = bytearray([128, 0, 0, 0, 0x00, 0x01, 0x00, 0x02]) + b"ping"
    ck = ipv6_pseudo_checksum(58, bytes(icmp))
    struct.pack_into(">H", icmp, 2, ck)
    return bytes(eth(0x86DD) + ipv6(58, bytes(icmp)))


def seed_ipv6_udp() -> bytes:
    # UDP datagram over IPv6 — reaches NetUdpDispatch (and the
    # duetos_net_parsers DHCP/DNS option walkers on the payload).
    payload = b"\x00\x01\x02\x03"
    udp = bytearray(8) + payload
    struct.pack_into(">H", udp, 0, 5353)         # src port
    struct.pack_into(">H", udp, 2, 53)           # dst port (DNS)
    struct.pack_into(">H", udp, 4, len(udp))     # length
    ck = ipv6_pseudo_checksum(17, bytes(udp))
    struct.pack_into(">H", udp, 6, ck if ck != 0 else 0xFFFF)
    return bytes(eth(0x86DD) + ipv6(17, bytes(udp)))


def seed_ipv6_tcp() -> bytes:
    # TCP SYN over IPv6 — reaches the segment parser + ParseSackBlocks.
    tcp = bytearray(20)
    struct.pack_into(">H", tcp, 0, 12345)        # src port
    struct.pack_into(">H", tcp, 2, 80)           # dst port
    struct.pack_into(">I", tcp, 4, 1)            # seq
    tcp[12] = 0x50                               # data offset 5
    tcp[13] = 0x02                               # SYN
    struct.pack_into(">H", tcp, 14, 1024)        # window
    ck = ipv6_pseudo_checksum(6, bytes(tcp))
    struct.pack_into(">H", tcp, 16, ck)
    return bytes(eth(0x86DD) + ipv6(6, bytes(tcp)))


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
        "ipv6_icmp6.bin": seed_ipv6_icmp6(),
        "ipv6_udp.bin": seed_ipv6_udp(),
        "ipv6_tcp.bin": seed_ipv6_tcp(),
    }
    for name, data in seeds.items():
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(data)
    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
