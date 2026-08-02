#!/usr/bin/env python3
"""Structural contract for network protocol-state synchronization."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def mask_non_code(source: str) -> str:
    masked = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "line"
                continue
            if current == "/" and following == "*":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "block"
                continue
            if current in ('"', "'"):
                quote = current
                masked[index] = " "
                index += 1
                state = "literal"
                continue
        elif state == "line":
            if current == "\n":
                state = "code"
            else:
                masked[index] = " "
            index += 1
            continue
        elif state == "block":
            if current == "*" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "code"
                continue
            if current != "\n":
                masked[index] = " "
            index += 1
            continue
        else:
            if current == "\\":
                masked[index] = " "
                if index + 1 < len(source):
                    masked[index + 1] = " "
                index += 2
                continue
            masked[index] = " "
            index += 1
            if current == quote:
                state = "code"
            continue
        index += 1
    return "".join(masked)


def function_bodies(source: str, name: str) -> list[str]:
    clean = mask_non_code(source)
    bodies: list[str] = []
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", clean):
        opening = clean.find("{", match.end())
        semicolon = clean.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        depth = 0
        for position in range(opening, len(clean)):
            if clean[position] == "{":
                depth += 1
            elif clean[position] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(source[opening : position + 1])
                    break
    if not bodies:
        raise AssertionError(f"definition not found: {name}")
    return bodies


def function_body(source: str, name: str) -> str:
    return function_bodies(source, name)[0]


def ordered(body: str, *needles: str) -> None:
    position = -1
    for needle in needles:
        position = body.find(needle, position + 1)
        if position < 0:
            raise AssertionError(f"missing ordered token: {needle}")


def lock_regions(source: str, lock: str) -> list[str]:
    clean = mask_non_code(source)
    acquire = re.compile(rf"SpinLockAcquire\(\s*{re.escape(lock)}\s*\)")
    release = re.compile(rf"SpinLockRelease\(\s*{re.escape(lock)}\s*,")
    regions: list[str] = []
    for match in acquire.finditer(clean):
        end = release.search(clean, match.end())
        if end is None:
            raise AssertionError(f"{lock} acquisition has no following release")
        regions.append(clean[match.end() : end.start()])
    return regions


class NetProtocolStateSyncContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("kernel/net/stack.h")
        cls.stack = read("kernel/net/stack.cpp")
        cls.ipv6 = read("kernel/net/ipv6.cpp")
        cls.firewall_header = read("kernel/net/firewall.h")
        cls.firewall = read("kernel/net/firewall.cpp")
        cls.host_test = read("tests/host/test_net_protocol_state_smp.cpp")
        cls.host_frames = read("tests/host/net_protocol_state_smp_frames.h")

    def test_protocol_state_has_separate_irq_save_locks(self) -> None:
        for lock in (
            "g_arp_lock",
            "g_ipv4_stats_lock",
            "g_icmp_lock",
            "g_udp_lock",
            "g_dhcp_lock",
            "g_dns_lock",
            "g_ntp_lock",
        ):
            self.assertRegex(self.stack, rf"SpinLock\s+{lock}\s*=")
            self.assertTrue(lock_regions(self.stack, lock), lock)
        self.assertRegex(self.ipv6, r"SpinLock\s+g_ipv6_stats_lock\s*=")
        self.assertTrue(lock_regions(self.ipv6, "g_ipv6_stats_lock"))
        self.assertRegex(self.firewall, r"SpinLock\s+g_firewall_lock\s*=")
        self.assertTrue(lock_regions(self.firewall, "g_firewall_lock"))
        self.assertIn("deliberately NEVER", self.header)
        self.assertIn("locks are deliberately NEVER", self.header)
        self.assertIn("transaction token", self.header)
        self.assertIn("IRQ-safe", self.firewall_header)
        self.assertIn("complete snapshots", self.firewall_header)

    def test_protocol_locks_do_not_cover_callouts_or_waits(self) -> None:
        forbidden = (
            "SchedSleepTicks",
            "SocketUdpDispatch",
            "NetUdpSend",
            "IfaceTx",
            "SerialWrite",
            "InterfaceOperationAcquire",
            "InterfaceOperationGuard",
        )
        for lock in (
            "g_arp_lock",
            "g_ipv4_stats_lock",
            "g_icmp_lock",
            "g_udp_lock",
            "g_dhcp_lock",
            "g_dns_lock",
            "g_ntp_lock",
        ):
            for region in lock_regions(self.stack, lock):
                for token in forbidden:
                    self.assertNotIn(token, region, f"{token} under {lock}")

        for region in lock_regions(self.ipv6, "g_ipv6_stats_lock"):
            for token in ("DuetosNetIfaceTx", "NetUdpDispatch", "tcp::OnSegment", "InterfaceMac"):
                self.assertNotIn(token, region, f"{token} under g_ipv6_stats_lock")

        for region in lock_regions(self.firewall, "g_firewall_lock"):
            for token in ("TickCount", "NotifyShowKind", "KLOG_", "FindBootCmdline"):
                self.assertNotIn(token, region, f"{token} under g_firewall_lock")

    def test_stats_and_ping_are_snapshot_published(self) -> None:
        self.assertIn("Ipv4StatIncrement(&Ipv4Stats::", self.stack)
        self.assertIn("IcmpStatIncrement(&IcmpStats::", self.stack)
        self.assertIn("Ipv6StatIncrement(&Ipv6Stats::", self.ipv6)
        for name, lock in (
            ("Ipv4StatsRead", "g_ipv4_stats_lock"),
            ("IcmpStatsRead", "g_icmp_lock"),
            ("NetPingArm", "g_icmp_lock"),
            ("NetPingRead", "g_icmp_lock"),
        ):
            body = function_body(self.stack, name)
            ordered(body, f"SpinLockAcquire({lock})", f"SpinLockRelease({lock}")
        ordered(
            function_body(self.ipv6, "Ipv6StatsRead"),
            "SpinLockAcquire(g_ipv6_stats_lock)",
            "SpinLockRelease(g_ipv6_stats_lock",
        )
        unbind = function_body(self.stack, "NetStackUnbindInterface")
        ordered(
            unbind,
            "SpinLockRelease(g_interface_lock, flags)",
            "SpinLockAcquire(g_icmp_lock)",
            "SpinLockRelease(g_icmp_lock, flags)",
            "ArpRetireBinding(binding)",
        )

    def test_firewall_single_lock_and_deferred_notification(self) -> None:
        for token in (
            "ConntrackInsertOrRefreshLocked",
            "ConntrackLookupReverseLocked",
            "ConntrackResetLocked",
            "LogDenialLocked",
            "PrepareDenialToastLocked",
            "FwAddLocked",
        ):
            self.assertIn(token, self.firewall)
        evaluate = function_body(self.firewall, "FwEvaluate")
        ordered(
            evaluate,
            "TickCount()",
            "SpinLockAcquire(g_firewall_lock)",
            "LogDenialLocked",
            "SpinLockRelease(g_firewall_lock, flags)",
            "NotifyShowKind",
        )
        for name in (
            "ConntrackSnapshot",
            "FwLogSnapshot",
            "FwLogTotalCount",
            "FwDefaultPolicy",
            "FwStatsRead",
            "FwSnapshot",
        ):
            body = function_body(self.firewall, name)
            ordered(body, "SpinLockAcquire(g_firewall_lock)", "SpinLockRelease(g_firewall_lock")

    def test_arp_uses_copy_out_for_concurrent_callers(self) -> None:
        self.assertIn("bool ArpLookup(u32 iface_index, Ipv4Address ip, ArpEntry* out_entry)", self.header)
        self.assertIn("externally serialized", self.header)
        overloads = function_bodies(self.stack, "ArpLookup")
        copy_out = next(body for body in overloads if "out_entry == nullptr" in body)
        ordered(copy_out, "InterfaceOperationGuard", "SpinLockAcquire(g_arp_lock)", "ArpLookupLocked")
        insert = function_body(self.stack, "ArpInsert")
        ordered(insert, "InterfaceOperationGuard", "SpinLockAcquire(g_arp_lock)", "binding_generation")
        self.assertRegex(function_body(self.stack, "ArpResolveWithWait"), r"ArpLookup\([^;]*&out")
        self.assertIn("ArpResolveWithWait", function_body(self.stack, "ResolveL2Destination"))
        self.assertIn("ArpRetireBinding(binding)", function_body(self.stack, "NetStackUnbindInterface"))

    def test_udp_demux_pins_callbacks_and_drains_unlocked(self) -> None:
        binding = re.search(r"struct\s+UdpBinding\s*\{(?P<body>.*?)\};", self.stack, re.DOTALL)
        self.assertIsNotNone(binding)
        for token in ("bool closing", "u64 generation", "u64 active_calls"):
            self.assertIn(token, binding.group("body"))

        dispatch = function_body(self.stack, "NetUdpDispatch")
        ordered(dispatch, "SocketUdpDispatch", "UdpBindingAcquire", "snapshot.handler", "UdpBindingRelease")
        self.assertNotIn("SpinLockAcquire(g_udp_lock)", dispatch)

        drain = function_body(self.stack, "UdpBindingUnbindExact")
        ordered(
            drain,
            "binding.in_use = false",
            "binding.closing = true",
            "SpinLockRelease(g_udp_lock, flags)",
            "SchedSleepTicks(1)",
        )
        bind = function_body(self.stack, "UdpBindingBind")
        self.assertIn("binding.handler == handler", bind)
        self.assertIn("binding.generation", bind)

    def test_dhcp_snapshot_commit_is_generation_and_transaction_checked(self) -> None:
        state = re.search(r"struct\s+DhcpState\s*\{(?P<body>.*?)\n\};", self.stack, re.DOTALL)
        self.assertIsNotNone(state)
        self.assertIn("CommittingAck", state.group("body"))
        self.assertIn("u64 transaction", state.group("body"))

        incoming = function_body(self.stack, "DhcpOnUdp")
        ordered(
            incoming,
            "snapshot = g_dhcp[iface_index]",
            "SpinLockRelease(g_dhcp_lock, state_flags)",
            "InterfaceOperationGuard",
            "current.transaction != snapshot.transaction",
        )
        self.assertIn("current.binding_generation != snapshot.binding_generation", incoming)
        self.assertIn("DhcpState::Stage::CommittingAck", incoming)

        start = function_body(self.stack, "DhcpStart")
        ordered(start, "g_dhcp_next_transaction", "state.transaction", "SpinLockRelease(g_dhcp_lock", "DhcpSendDiscover")
        read_lease = function_bodies(self.stack, "DhcpLeaseRead")[0]
        ordered(read_lease, "snapshot = g_dhcp", "InterfaceOperationGuard", "current.transaction == snapshot.transaction")

    def test_dns_and_ntp_revalidate_exact_transactions(self) -> None:
        dns_rx = function_body(self.stack, "DnsOnUdp")
        ordered(dns_rx, "DnsStateReadLocked", "SpinLockRelease(g_dns_lock", "InterfaceOperationGuard")
        for token in (
            "current.transaction == snapshot.transaction",
            "NetInterfaceBindingEqual(current.binding, snapshot.binding)",
            "current.xid == snapshot.xid",
            "current.src_port == snapshot.src_port",
        ):
            self.assertIn(token, dns_rx)

        dns_query = function_body(self.stack, "NetDnsQueryA")
        ordered(dns_query, "g_dns_starting = true", "SpinLockRelease(g_dns_lock", "UdpBindingUnbindExact", "UdpBindingBind")
        self.assertIn("g_dns_binding_generation = operation.generation", dns_query)

        ntp_rx = function_body(self.stack, "NtpOnUdp")
        ordered(ntp_rx, "NtpStateReadLocked", "SpinLockRelease(g_ntp_lock", "InterfaceOperationGuard")
        self.assertIn("originate != snapshot.request_cookie", ntp_rx)
        self.assertIn("current.transaction == snapshot.transaction", ntp_rx)
        self.assertIn("NetInterfaceBindingEqual(current.binding, snapshot.binding)", ntp_rx)

        ntp_query = function_body(self.stack, "NetNtpQuery")
        ordered(ntp_query, "g_ntp_request_cookie = request_cookie", "SpinLockRelease(g_ntp_lock", "UdpBindingUnbindExact")
        self.assertIn("pkt[40 + i]", ntp_query)

    def test_dns_and_ntp_publish_generation_bearing_query_receipts(self) -> None:
        for token in (
            "struct DnsQueryReceipt",
            "NetInterfaceBinding binding",
            "kInvalidDnsQueryReceipt",
            "DnsQueryReceiptIsValid",
            "NetDnsResultRead(DnsQueryReceipt receipt)",
            "struct NtpQueryReceipt",
            "kInvalidNtpQueryReceipt",
            "NtpQueryReceiptIsValid",
            "NetNtpResultRead(NtpQueryReceipt receipt)",
        ):
            self.assertIn(token, self.header)

        dns_queries = function_bodies(self.stack, "NetDnsQueryA")
        exact_dns_query = next(body for body in dns_queries if "out_receipt" in body)
        ordered(
            exact_dns_query,
            "*out_receipt = kInvalidDnsQueryReceipt",
            "const u64 transaction",
            "NetUdpSend",
            "still_current",
            "DnsQueryReceipt{.binding",
        )
        dns_reads = function_bodies(self.stack, "NetDnsResultRead")
        exact_dns_read = next(body for body in dns_reads if "DnsQueryReceiptIsValid" in body)
        self.assertIn("snapshot.transaction != receipt.transaction", exact_dns_read)
        self.assertIn("NetInterfaceBindingEqual(snapshot.binding, receipt.binding)", exact_dns_read)

        ntp_queries = function_bodies(self.stack, "NetNtpQuery")
        exact_ntp_query = next(body for body in ntp_queries if "out_receipt" in body)
        ordered(
            exact_ntp_query,
            "*out_receipt = kInvalidNtpQueryReceipt",
            "const u64 transaction",
            "NetUdpSend",
            "still_current",
            "NtpQueryReceipt{.binding",
        )
        ntp_reads = function_bodies(self.stack, "NetNtpResultRead")
        exact_ntp_read = next(body for body in ntp_reads if "NtpQueryReceiptIsValid" in body)
        self.assertIn("snapshot.transaction != receipt.transaction", exact_ntp_read)
        self.assertIn("NetInterfaceBindingEqual(snapshot.binding, receipt.binding)", exact_ntp_read)

    def test_dhcp_rejects_wrong_transport_client_server_offer_and_state(self) -> None:
        incoming = function_body(self.stack, "DhcpOnUdp")
        for token in (
            "src_port != 67 || dst_port != 68",
            "buf[1] != 1",
            "buf[2] != 6",
            "buf[28 + i] != operation.mac.octets[i]",
            "!DhcpFindOption(opts, opts_len, kDhcpOptServerId",
            "snapshot.stage == DhcpState::Stage::Requesting",
            "!IpEq(server_id, snapshot.server_ip)",
            "!IpEq(yiaddr, snapshot.offered_ip)",
            "current.stage != DhcpState::Stage::Requesting",
            "!IpEq(current.server_ip, snapshot.server_ip)",
            "!IpEq(current.offered_ip, snapshot.offered_ip)",
        ):
            self.assertIn(token, incoming)

    def test_unbind_retires_state_without_nested_protocol_locks(self) -> None:
        unbind = function_body(self.stack, "NetStackUnbindInterface")
        ordered(
            unbind,
            "SpinLockRelease(g_interface_lock, flags)",
            "ArpRetireBinding(binding)",
            "SpinLockAcquire(g_dhcp_lock)",
            "SpinLockAcquire(g_dns_lock)",
            "UdpBindingUnbindExact(dns_udp_binding)",
            "SpinLockAcquire(g_ntp_lock)",
            "UdpBindingUnbindExact(ntp_udp_binding)",
            "SpinLockAcquire(g_interface_lock)",
            "ifc.retiring = false",
        )
        for lock in ("g_dhcp_lock", "g_dns_lock", "g_ntp_lock"):
            regions = lock_regions(unbind, lock)
            self.assertEqual(len(regions), 1)
            self.assertNotIn("UdpBindingUnbindExact", regions[0])

    def test_hostile_host_test_covers_contention_and_stale_generations(self) -> None:
        for token in (
            "arp_writer_a",
            "udp_binder",
            "udp_dispatcher",
            "packet_injector",
            "ping_writer",
            "firewall_admin",
            "firewall_evaluator",
            "result_reader",
            "DispatchDnsResponse(stale_dns)",
            "DispatchNtpResponse(stale_ntp)",
            "DispatchDhcpResponse(stale_dhcp)",
            "binding_generation == binding_d.generation",
            "obsolete_dns_receipt.transaction != current_dns_receipt.transaction",
            "obsolete_ntp_receipt.transaction != current_ntp_receipt.transaction",
            "NetDnsResultRead(obsolete_dns_receipt)",
            "NetNtpResultRead(obsolete_ntp_receipt)",
            "DhcpReplyFault::AckBeforeOffer",
            "DhcpReplyFault::WrongPorts",
            "DhcpReplyFault::WrongClientMac",
            "DhcpReplyFault::MissingServerIdentifier",
            "DhcpReplyFault::WrongServerIdentifier",
            "DhcpReplyFault::WrongOfferedAddress",
            "BuildIpv4IcmpEchoFrame",
            "BuildIpv6EmptyFrame",
            "FwLogSnapshot",
            "ConntrackSnapshot",
        ):
            self.assertIn(token, self.host_test)
        for token in ("BuildIpv4UdpFrame", "BuildIpv4IcmpEchoFrame", "BuildIpv6EmptyFrame"):
            self.assertIn(token, self.host_frames)
        self.assertGreaterEqual(self.host_test.count("std::thread"), 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
