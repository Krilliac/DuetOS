#!/usr/bin/env python3
"""Guard the scheduler -> net stack -> NIC activation boot dependency."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BRINGUP_CPP = ROOT / "kernel/core/boot_bringup.cpp"
MAIN_CPP = ROOT / "kernel/core/main.cpp"


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


def unique_position(source: str, label: str, pattern: str) -> int:
    matches = list(re.finditer(pattern, source))
    if len(matches) != 1:
        raise AssertionError(f"expected one {label}, found {len(matches)}")
    return matches[0].start()


class NetStackBootOrderContractTests(unittest.TestCase):
    def test_stack_initializes_once_between_scheduler_and_driver_activation(self) -> None:
        bringup_source = BRINGUP_CPP.read_text(encoding="utf-8")
        main_source = MAIN_CPP.read_text(encoding="utf-8")
        devices = function_body(bringup_source, "BootBringupDevices")

        pci = unique_position(devices, "PCI enumeration", r"\bPciEnumerate\s*\(")
        stack = unique_position(devices, "network-stack initialization", r"\bNetStackInit\s*\(")
        virtio = unique_position(devices, "VirtIO activation", r"\bVirtioInit\s*\(")
        net = unique_position(devices, "NIC activation", r"\bdrivers::net::NetInit\s*\(")
        self.assertLess(pci, stack)
        self.assertLess(stack, virtio)
        self.assertLess(stack, net)

        boot_sources = mask_comments_and_literals(bringup_source + "\n" + main_source)
        for label, pattern in (
            ("network-stack initialization", r"\bNetStackInit\s*\("),
            ("VirtIO activation", r"\bVirtioInit\s*\("),
            ("NIC activation", r"\bdrivers::net::NetInit\s*\("),
        ):
            self.assertEqual(len(re.findall(pattern, boot_sources)), 1, f"boot must contain exactly one {label}")

        kernel_main = function_body(main_source, "kernel_main")
        services = unique_position(kernel_main, "kernel-services phase", r"\bBootBringupKernelServices\s*\(")
        devices_call = unique_position(kernel_main, "device phase", r"\bBootBringupDevices\s*\(")
        self.assertLess(services, devices_call)

        service_body = function_body(bringup_source, "BootBringupKernelServices")
        unique_position(service_body, "scheduler initialization", r"\bSchedInit\s*\(")


if __name__ == "__main__":
    unittest.main(verbosity=2)
