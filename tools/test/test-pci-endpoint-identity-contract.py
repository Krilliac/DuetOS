#!/usr/bin/env python3
"""Structural contract for endpoint-only cached PCI subsystem identity."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving braces."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for offset in range(begin, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise AssertionError("unterminated block comment")
            end += 2
            blank(index, end)
            index = end
            continue
        raw_prefix = next(
            (prefix for prefix in ('u8R"', 'uR"', 'UR"', 'LR"', 'R"') if source.startswith(prefix, index)),
            None,
        )
        if raw_prefix is not None:
            delimiter_begin = index + len(raw_prefix)
            opening = source.find("(", delimiter_begin, delimiter_begin + 17)
            if opening >= 0:
                delimiter = source[delimiter_begin:opening]
                terminator = ")" + delimiter + '"'
                end = source.find(terminator, opening + 1)
                if end < 0:
                    raise AssertionError("unterminated raw string")
                end += len(terminator)
                blank(index, end)
                index = end
                continue
        if (
            source[index] == "'"
            and index > 0
            and index + 1 < len(source)
            and source[index - 1].isalnum()
            and source[index + 1].isalnum()
        ):
            index += 1
            continue
        if source[index] in "\"'":
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            else:
                raise AssertionError("unterminated quoted literal")
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(masked)


def matching(source: str, opening: int, left: str = "{", right: str = "}") -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} region")


def function_body(source: str, name: str) -> str:
    clean = code_only(source)
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", clean):
        opening_paren = clean.find("(", match.start())
        closing_paren = matching(clean, opening_paren, "(", ")")
        opening = clean.find("{", closing_paren + 1)
        semicolon = clean.find(";", closing_paren + 1)
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        return clean[opening : matching(clean, opening) + 1]
    raise AssertionError(f"definition not found: {name}")


class PciEndpointIdentityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("kernel/drivers/pci/pci.h")
        cls.source = read("kernel/drivers/pci/pci.cpp")

    def test_device_exposes_canonical_identity_and_compatible_aliases(self) -> None:
        device = re.search(r"struct\s+Device\s*\{(?P<body>.*?)\n\};", self.header, re.DOTALL)
        self.assertIsNotNone(device)
        for field in (
            "subsystem_vendor_id",
            "subsystem_device_id",
            "programming_interface",
            "revision_id",
            "subsystem_known",
            "class_code",
            "subclass",
            "header_type",
        ):
            self.assertRegex(device.group("body"), rf"\b{field}\b")
        self.assertRegex(device.group("body"), r"\bprog_if\b")
        self.assertRegex(device.group("body"), r"\brevision\b")

    def test_decoder_owns_standard_dword_byte_layout(self) -> None:
        decoder = function_body(self.header, "DecodeDeviceIdentity")
        for assignment in (
            "vendor_device & 0xFFFFu",
            "(vendor_device >> 16) & 0xFFFFu",
            "class_revision & 0xFFu",
            "(class_revision >> 8) & 0xFFu",
            "(class_revision >> 16) & 0xFFu",
            "(class_revision >> 24) & 0xFFu",
            "(header >> 16) & 0xFFu",
        ):
            self.assertIn(assignment, decoder)
        self.assertIn("(device.header_type & 0x7Fu) == 0", decoder)
        self.assertIn("endpoint_layout && subsystem_register_read", decoder)
        self.assertIn("subsystem_vendor != 0", decoder)
        self.assertIn("subsystem_vendor != 0xFFFFu", decoder)
        self.assertIn("device.revision = device.revision_id", decoder)
        self.assertIn("device.prog_if = device.programming_interface", decoder)

    def test_probe_reads_subsystem_dword_only_inside_type_zero_branch(self) -> None:
        probe = function_body(self.source, "Probe")
        self.assertEqual(probe.count("PciConfigRead32(addr, 0x2C)"), 1)
        endpoint_branch = re.search(
            r"if\s*\(\(header_type\s*&\s*0x7Fu\)\s*==\s*0x00\)\s*\{(?P<body>.*?)\}",
            probe,
            re.DOTALL,
        )
        self.assertIsNotNone(endpoint_branch)
        self.assertIn("subsystem = PciConfigRead32(addr, 0x2C)", endpoint_branch.group("body"))
        self.assertIn("subsystem_register_read = true", endpoint_branch.group("body"))
        self.assertLess(probe.index("const u32 hdr"), probe.index("PciConfigRead32(addr, 0x2C)"))
        self.assertLess(probe.index("PciConfigRead32(addr, 0x2C)"), probe.index("CacheDevice"))

    def test_cache_uses_pure_decoder_without_parallel_field_logic(self) -> None:
        cache = function_body(self.source, "CacheDevice")
        self.assertIn("detail::DecodeDeviceIdentity", cache)
        for field in (
            "d.vendor_id =",
            "d.device_id =",
            "d.revision =",
            "d.prog_if =",
            "d.subclass =",
            "d.class_code =",
            "d.header_type =",
        ):
            self.assertNotIn(field, cache)


class ParserHostileTests(unittest.TestCase):
    def test_comments_raw_literals_and_parameter_braces_cannot_spoof_body(self) -> None:
        fixture = r'''
const char* decoy = R"tag(void Target() { FakeRaw(); })tag";
// void Target() { FakeLine(); }
/* void Target() { FakeBlock(); } */
void Target(int value = []() { return 0; }())
{
    auto separated = 0xFF'FF;
    Real(value, separated);
}
'''
        body = function_body(fixture, "Target")
        self.assertIn("Real", body)
        self.assertIn("0xFF'FF", body)
        self.assertNotIn("FakeRaw", body)
        self.assertNotIn("FakeLine", body)
        self.assertNotIn("FakeBlock", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
