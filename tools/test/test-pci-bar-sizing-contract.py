#!/usr/bin/env python3
"""Structural contract for serialized, decode-safe PCI BAR sizing."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving source offsets."""
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


class PciBarSizingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("kernel/drivers/pci/pci.h")
        cls.source = read("kernel/drivers/pci/pci.cpp")
        cls.bar = code_only(function_body(cls.source, "PciReadBar"))

    def test_all_public_config_dwords_share_the_transaction_lock(self) -> None:
        read32 = code_only(function_body(self.source, "PciConfigRead32"))
        write32 = code_only(function_body(self.source, "PciConfigWrite32"))
        for body, helper in (
            (read32, "PciConfigRead32LockHeld"),
            (write32, "PciConfigWrite32LockHeld"),
        ):
            self.assertEqual(body.count("SpinLockGuard guard(g_pci_config_lock)"), 1)
            self.assertIn(helper, body)
            self.assertNotIn("EcamCovers", body)
            self.assertNotIn("kConfigAddressPort", body)

    def test_one_lock_spans_the_entire_bar_transaction(self) -> None:
        self.assertEqual(self.bar.count("SpinLockGuard guard(g_pci_config_lock)"), 1)
        self.assertNotRegex(self.bar, r"\bPciConfigRead32\s*\(")
        self.assertNotRegex(self.bar, r"\bPciConfigWrite32\s*\(")
        self.assertLess(self.bar.index("RefuseForbiddenConfigWrite"), self.bar.index("SpinLockGuard"))
        self.assertIn("header_type != 0", self.bar)
        self.assertIn("slot + 1 == index", self.bar)

    def test_command_write_never_echoes_status_and_preserves_other_bits(self) -> None:
        self.assertIn("constexpr u16 kCommandIoDecode = 1U << 0", self.source)
        self.assertIn("constexpr u16 kCommandMemoryDecode = 1U << 1", self.source)
        self.assertRegex(
            self.bar,
            r"const\s+u16\s+original_command\s*=\s*static_cast<u16>\("
            r"PciConfigRead32LockHeld\(addr,\s*0x04\)\s*&\s*0xFFFFu\)",
        )
        self.assertIn("original_command & ~(kCommandIoDecode | kCommandMemoryDecode)", self.bar)
        self.assertIn("static_cast<u32>(decode_disabled_command)", self.bar)
        self.assertIn("static_cast<u32>(original_command)", self.bar)
        self.assertNotIn("command_status", self.bar)

    def test_64_bit_probe_and_restoration_order_is_atomic(self) -> None:
        probe_low_write = self.bar.index("PciConfigWrite32LockHeld(addr, offset, 0xFFFFFFFFu)")
        probe_high_write = self.bar.index("PciConfigWrite32LockHeld(addr, high_offset, 0xFFFFFFFFu)")
        probe_low_read = self.bar.index("const u32 probe_low")
        probe_high_read = self.bar.index("const u32 probe_high")
        restore_high = self.bar.index("PciConfigWrite32LockHeld(addr, high_offset, original_high)")
        restore_low = self.bar.index("PciConfigWrite32LockHeld(addr, offset, original_low)")
        restore_command = self.bar.rindex("PciConfigWrite32LockHeld(addr, 0x04, static_cast<u32>(original_command))")
        self.assertLess(probe_low_write, probe_high_write)
        self.assertLess(probe_high_write, probe_low_read)
        self.assertLess(probe_low_read, probe_high_read)
        self.assertLess(probe_high_read, restore_high)
        self.assertLess(restore_high, restore_low)
        self.assertLess(restore_low, restore_command)

    def test_arithmetic_decoder_fails_closed(self) -> None:
        decoder = code_only(function_body(self.header, "DecodeBarProbe"))
        for contract in (
            "index + 1 >= 6",
            "memory_type == 0x3u",
            "(original_low & attribute_mask) != (probe_low & attribute_mask)",
            "original_low | probe_low",
            "size == 0",
            "size & (size - 1)",
            "probe_mask != canonical_mask",
            "address & (size - 1)",
            "address > width_mask - (size - 1)",
        ):
            self.assertIn(contract, decoder)
        self.assertIn("is_below_1m", decoder)
        self.assertIn("0xFFFFFULL", decoder)
        self.assertIn("0x000FFFF0ULL", decoder)
        self.assertNotIn("memory_type != 0", decoder)
        self.assertIn("is_below_1m", self.bar)
        self.assertIn("memory_type == 0x3u", self.bar)
        self.assertNotIn("memory_type != 0", self.bar)
        self.assertIn("detail::DecodeBarProbe", self.bar)


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
