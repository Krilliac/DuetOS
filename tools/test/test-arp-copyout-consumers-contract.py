#!/usr/bin/env python3
"""Guard production ARP consumers against mutable-cache pointer escape."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOCKET_CPP = (ROOT / "kernel/net/socket.cpp").read_text(encoding="utf-8")
SHELL_NETWORK_CPP = (ROOT / "kernel/shell/shell_network.cpp").read_text(encoding="utf-8")


def mask_comments_and_literals(source: str) -> str:
    """Blank C++ comments and literals while preserving offsets and newlines."""
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
            if current == "\\" and following:
                masked[index] = masked[index + 1] = " "
                index += 2
                continue
            masked[index] = " "
            index += 1
            if current == quote:
                state = "code"
            continue
        index += 1
    return "".join(masked)


def function_body(source: str, name: str) -> str:
    clean = mask_comments_and_literals(source)
    definition = re.search(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{", clean)
    if definition is None:
        raise AssertionError(f"missing function definition: {name}")
    opening = clean.find("{", definition.start())
    depth = 0
    for index in range(opening, len(clean)):
        if clean[index] == "{":
            depth += 1
        elif clean[index] == "}":
            depth -= 1
            if depth == 0:
                return clean[opening + 1 : index]
    raise AssertionError(f"unterminated function definition: {name}")


def arp_lookup_arguments(body: str) -> list[str]:
    """Return every simple ArpLookup argument list in a function body."""
    return re.findall(r"\bArpLookup\s*\(([^()]*)\)", body)


class ArpCopyoutConsumerContractTests(unittest.TestCase):
    def test_all_target_file_lookups_use_the_copyout_overload(self) -> None:
        for source in (SOCKET_CPP, SHELL_NETWORK_CPP):
            calls = arp_lookup_arguments(mask_comments_and_literals(source))
            self.assertTrue(calls)
            self.assertTrue(all(call.count(",") == 2 for call in calls))

    def test_socket_datagram_send_uses_stack_copyout(self) -> None:
        send = function_body(SOCKET_CPP, "SocketSendDgram")
        self.assertRegex(send, r"\bArpEntry\s+arp\s*\{\s*\}\s*;")
        # The contract is the copy-out shape (stack ArpEntry + &arp), not which
        # interface index the send path resolves on — SocketSendDgram now looks
        # up ARP on the socket's bound interface rather than a hardcoded 0.
        self.assertRegex(send, r"\bArpLookup\([^()]*,\s*dst,\s*&arp\)")
        self.assertIn("dst_mac = arp.mac", send)
        self.assertNotRegex(send, r"\b(?:const\s+)?ArpEntry\s*\*")
        self.assertNotIn("arp->", send)
        self.assertEqual(len(arp_lookup_arguments(send)), 1)
        self.assertEqual(arp_lookup_arguments(send)[0].count(","), 2)

    def test_route_diagnostic_uses_stack_copyout(self) -> None:
        route = function_body(SHELL_NETWORK_CPP, "CmdRoute")
        self.assertRegex(route, r"\bArpEntry\s+arp\s*\{\s*\}\s*;")
        self.assertIn("ArpLookup(0, lease.router, &arp)", route)
        self.assertIn("if (!arp_found)", route)
        self.assertIn("gateway_mac = arp.mac", route)
        self.assertNotIn("arp->", route)
        self.assertEqual(len(arp_lookup_arguments(route)), 1)
        self.assertEqual(arp_lookup_arguments(route)[0].count(","), 2)

    def test_shell_network_self_test_retries_into_the_same_local_copy(self) -> None:
        net = function_body(SHELL_NETWORK_CPP, "CmdNet")
        calls = arp_lookup_arguments(net)
        self.assertRegex(net, r"\bArpEntry\s+arp\s*\{\s*\}\s*;")
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call.count(",") == 2 for call in calls))
        self.assertEqual(net.count("ArpLookup(0, lease.router, &arp)"), 2)
        self.assertIn("arp_found = duetos::net::ArpLookup(0, lease.router, &arp)", net)
        self.assertIn("if (arp_found)", net)
        self.assertIn("gateway_mac = arp.mac", net)
        self.assertNotIn("arp->", net)


if __name__ == "__main__":
    unittest.main(verbosity=2)
