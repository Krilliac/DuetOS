#!/usr/bin/env python3
"""Structural contract for generation-safe network-stack restart."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    """Return a C++ function body using a comment/string-aware scan."""
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

    clean = "".join(masked)
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
                    return source[opening : position + 1]
    raise AssertionError(f"definition not found: {name}")


def ordered(body: str, *needles: str) -> None:
    position = -1
    for needle in needles:
        next_position = body.find(needle, position + 1)
        if next_position < 0:
            raise AssertionError(f"missing ordered token: {needle}")
        position = next_position


class NetStackRestartContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("kernel/net/stack.h")
        cls.stack = read("kernel/net/stack.cpp")
        cls.tcp_header = read("kernel/net/tcp.h")
        cls.tcp_internal = read("kernel/net/tcp_internal.h")
        cls.tcp = read("kernel/net/tcp.cpp")
        cls.tcp_segment = read("kernel/net/tcp_segment.cpp")
        cls.tcp_timer = read("kernel/net/tcp_timer.cpp")
        cls.socket_header = read("kernel/net/socket.h")
        cls.socket = read("kernel/net/socket.cpp")

    def test_public_api_uses_exact_receipts_and_context_callbacks(self) -> None:
        for token in (
            "using NetTxContextFn",
            "struct NetInterfaceBinding",
            "NetStackBindInterfaceOwned",
            "NetStackUnbindInterface",
            "NetStackAcquireInterface",
            "NetStackReleaseInterface",
            "NetStackTransmit",
            "DrainTimedOut",
            "void NetStackInjectRx(NetInterfaceBinding binding",
        ):
            self.assertIn(token, self.header)
        self.assertIn("driver_context", self.header)
        self.assertIn("generation", self.header)
        self.assertIn("StaleBinding", self.header)

    def test_admission_and_pins_share_one_atomic_word(self) -> None:
        gate = re.search(r"struct\s+alignas\(8\)\s+OperationGate\s*\{(?P<body>.*?)\};", self.stack, re.DOTALL)
        self.assertIsNotNone(gate)
        self.assertRegex(gate.group("body"), r"\bu64\s+state\s*;")
        self.assertNotRegex(gate.group("body"), r"\b(bool|u\d+)\s+(open|admission|pins?)\b")

        pin = function_body(self.stack, "TryPin")
        close = function_body(self.stack, "Close")
        self.assertIn("CompareExchange", pin)
        self.assertIn("kOpen", pin)
        self.assertIn("CompareExchange", close)
        self.assertIn("observed & kPinsMask", close)

    def test_bind_publishes_identity_before_opening_admission(self) -> None:
        bind = function_body(self.stack, "BindInterfaceInternal")
        ordered(
            bind,
            "ifc.context_tx = context_tx",
            "ifc.driver_context = driver_context",
            "StoreRelease(&ifc.generation, generation)",
            "Open(ifc.operations)",
            "ifc.bound = true",
            "*out_binding = NetInterfaceBinding{iface_index, generation}",
        )
        owned = function_body(self.stack, "NetStackBindInterfaceOwned")
        ordered(owned, "*out_binding = kInvalidNetInterfaceBinding", "BindInterfaceInternal")

    def test_unbind_closes_then_drains_before_clearing_owner(self) -> None:
        unbind = function_body(self.stack, "NetStackUnbindInterface")
        ordered(
            unbind,
            "Close(ifc.operations)",
            "PinCount(ifc.operations) != 0",
            "NetInterfaceUnbindResult::DrainTimedOut",
            "tcp::RetireInterface(binding)",
            "flags = sync::SpinLockAcquire(g_interface_lock)",
            "PinCount(ifc.operations) == 0",
            "ifc.context_tx = nullptr",
            "ifc.driver_context = nullptr",
            "g_dhcp[binding.iface_index] = {}",
            "ifc.retiring = false",
        )
        retire_position = unbind.index("tcp::RetireInterface(binding)")
        final_lock_position = unbind.index("flags = sync::SpinLockAcquire(g_interface_lock)", retire_position)
        final_unlock_position = unbind.index("sync::SpinLockRelease(g_interface_lock, flags)", final_lock_position)
        self.assertNotIn("tcp::RetireInterface", unbind[final_lock_position:final_unlock_position])

        timeout = unbind[:retire_position]
        self.assertNotIn("ifc.driver_context = nullptr", timeout)

    def test_stale_rx_and_protocol_state_are_generation_scoped(self) -> None:
        exact_rx = re.search(
            r"void\s+NetStackInjectRx\(NetInterfaceBinding\s+binding[^)]*\)\s*\{(?P<body>.*?)\n\}",
            self.stack,
            re.DOTALL,
        )
        self.assertIsNotNone(exact_rx)
        self.assertIn("binding.generation", exact_rx.group("body"))
        self.assertIn("u64 binding_generation", self.stack)
        self.assertRegex(
            self.stack,
            r"e\.iface_index\s*==\s*iface_index\s*&&\s*e\.binding_generation\s*==\s*binding_generation",
        )
        self.assertIn("InterfaceGenerationIsOpen(iface_index, binding_generation)", function_body(self.stack, "ArpLookup"))
        self.assertIn("InterfaceGenerationIsOpen(iface_index, binding_generation)", function_body(self.stack, "ArpInsert"))
        for state in ("g_dhcp", "g_ping_binding_generation", "g_dns_binding_generation", "g_ntp_binding_generation"):
            self.assertIn(state, function_body(self.stack, "NetStackUnbindInterface"))

    def test_legacy_entry_points_remain_available_during_migration(self) -> None:
        self.assertIn("bool NetStackBindInterface(u32 iface_index", self.header)
        self.assertIn("void NetStackInjectRx(u32 iface_index", self.header)

    def test_tcp_objects_capture_and_match_exact_interface_identity(self) -> None:
        tcb = re.search(r"struct\s+Tcb\s*\{(?P<body>.*?)\n\};", self.tcp_internal, re.DOTALL)
        self.assertIsNotNone(tcb)
        self.assertIn("NetInterfaceBinding interface_binding", tcb.group("body"))
        self.assertIn("MacAddress local_mac", tcb.group("body"))
        self.assertNotRegex(tcb.group("body"), r"\bu32\s+iface_index\s*;")

        for name in ("Listen", "Connect"):
            body = function_body(self.tcp, name)
            ordered(body, "StackInterfacePinGuard", "interface.binding", "t.interface_binding = interface.binding")
            self.assertIn("t.local_mac = interface.mac", body)

        lookup = function_body(self.tcp, "LookupExact")
        listener = function_body(self.tcp, "LookupListener")
        bucket_hash = function_body(self.tcp, "BucketHash")
        self.assertIn("NetInterfaceBindingEqual", lookup)
        self.assertIn("NetInterfaceBindingEqual", listener)
        self.assertIn("binding.generation", bucket_hash)

    def test_tcp_send_and_rx_fail_closed_on_stale_generation(self) -> None:
        send = function_body(self.tcp_segment, "SendSegment")
        ordered(send, "t.local_mac.octets", "NetStackTransmit(t.interface_binding")
        self.assertNotIn("InterfaceMac", send)
        self.assertNotIn("DuetosNetIfaceTx", self.tcp_segment)

        incoming = function_body(self.tcp_segment, "OnSegment")
        ordered(incoming, "StackInterfacePinGuard", "LookupExact(interface.binding", "LookupListener(interface.binding")
        child = function_body(self.tcp_segment, "HandleListenSyn")
        self.assertIn("child.interface_binding = interface.binding", child)
        self.assertIn("child.local_mac = interface.mac", child)
        self.assertIn("SendSegment", self.tcp_timer)

    def test_tcp_retire_drops_exact_generation_before_rebind(self) -> None:
        self.assertIn("u32 RetireInterface(NetInterfaceBinding binding)", self.tcp_header)
        retire = function_body(self.tcp_segment, "RetireInterface")
        ordered(retire, "NetInterfaceBindingEqual", "DropTcb(i)")
        self.assertIn("SpinLockAcquire(g_tcb_lock)", retire)
        self.assertIn("SpinLockRelease(g_tcb_lock", retire)

    def test_udp_socket_send_pins_one_interface_generation(self) -> None:
        snapshot = re.search(r"struct\s+SocketSnapshot\s*\{(?P<body>.*?)\n\};", self.socket, re.DOTALL)
        self.assertIsNotNone(snapshot)
        self.assertIn("u32 iface_index", snapshot.group("body"))
        self.assertIn("out.iface_index = s.iface_index", function_body(self.socket, "SnapshotSocketLocked"))

        send = function_body(self.socket, "SocketSendDgram")
        ordered(
            send,
            "state = SnapshotSocketLocked(s)",
            "NetStackAcquireInterface(state.iface_index, &interface)",
            "DUETOS_DEFER(NetStackReleaseInterface(interface.binding))",
            "!IpEqual(state.local_ip, interface.ip)",
            "ArpLookup(interface.binding.iface_index, dst, &arp)",
            "NetUdpSend(interface.binding.iface_index",
        )
        self.assertNotIn("NicCount", send)
        self.assertNotIn("InterfaceIp", send)

    def test_stream_socket_lazily_reconciles_retired_tcb_without_lock_inversion(self) -> None:
        reconcile = function_body(self.socket, "ReconcileRetiredStreamTcb")
        ordered(
            reconcile,
            "observed = snapshot.tcb",
            "SpinLockRelease(g_sock_lock, flags)",
            "tcp::Alive(observed)",
            "flags = sync::SpinLockAcquire(g_sock_lock)",
            "current.tcb == observed",
            "current.tcb = tcp::kInvalidTcbId",
            "current.connected = false",
            "current.listening = false",
            "current.shutdown_flags |= 0x3",
        )
        for name in (
            "SocketIsListening",
            "SocketIsConnected",
            "SocketListen",
            "SocketConnect",
            "SocketAcceptNonblocking",
            "SocketSendStream",
            "SocketRecvStream",
            "SocketPollEvents",
        ):
            self.assertIn("ReconcileRetiredStreamTcb", function_body(self.socket, name), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
