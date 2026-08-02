#!/usr/bin/env python3
"""Structural gate for the clean-room MT7921 preflight boundary."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER_PATH = ROOT / "kernel/drivers/net/mt7921_contract.h"
SOURCE_PATH = ROOT / "kernel/drivers/net/mt7921_contract.cpp"
HOST_TEST_PATH = ROOT / "tests/host/test_mt7921_contract.cpp"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def enum_body(source: str, name: str) -> str:
    match = re.search(rf"enum\s+class\s+{re.escape(name)}\s*:[^{{]+{{(?P<body>.*?)}};", source, re.S)
    if match is None:
        raise AssertionError(f"enum not found: {name}")
    return match.group("body")


class Mt7921ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read(HEADER_PATH)
        cls.source = read(SOURCE_PATH)
        cls.host_test = read(HOST_TEST_PATH)

    def test_exact_host_identity_and_resource_contract_are_pinned(self) -> None:
        for token in (
            "kPciVendorId = 0x14C3",
            "kPciDeviceId = 0x7961",
            "kSubsystemVendorId = 0x105B",
            "kSubsystemDeviceId = 0xE0B7",
            "kRevisionId = 0x00",
            "kPciBaseClass = 0x02",
            "kPciSubclass = 0x80",
            "kRequiredBarIndex = 0",
            "kMinimumBarBytes = 0x100000",
            "kFixedRegisterWindowCount = 44",
        ):
            self.assertIn(token, self.header)

    def test_contract_has_no_hardware_effect_surface(self) -> None:
        self.assertEqual(re.findall(r'^#include\s+"([^"]+)"', self.source, re.M),
                         ["drivers/net/mt7921_contract.h"])
        for forbidden in (
            "reinterpret_cast",
            "volatile",
            "Mmio32",
            "PciWrite",
            "DmaMap",
            "EnableIrq",
            "driver_online",
            "link_up",
            "KLOG_",
            "sched::",
        ):
            self.assertNotIn(forbidden, self.source)
        self.assertNotIn('drivers/net/mt76', self.header + self.source)

    def test_ready_phase_cannot_be_confused_with_online(self) -> None:
        phase = enum_body(self.header, "ContractPhase")
        self.assertIn("ReadyForHardwareBringUp", phase)
        self.assertNotRegex(phase, r"\bOnline\b")
        self.assertNotIn("ContractMarkOnline", self.header + self.source)

    def test_all_preflight_validators_and_teardown_are_exposed(self) -> None:
        for name in (
            "ValidateIdentity",
            "ValidateBar",
            "PlanRegisterAccess",
            "FixedRegisterWindowAt",
            "ContractPlanRegisterAccess",
            "ValidateFirmwareContainer",
            "ValidateMcuEnvelope",
            "ValidateRingLayout",
            "ContractAcceptIdentity",
            "ContractAcceptBar",
            "ContractAcceptFirmwareSet",
            "ContractAcceptRingSet",
            "ContractBeginTeardown",
            "ContractFinishTeardown",
        ):
            self.assertRegex(self.header, rf"\b{re.escape(name)}\s*\(")
            self.assertRegex(self.source, rf"\b{re.escape(name)}\s*\(")

    def test_container_endianness_and_bounds_are_explicit(self) -> None:
        for token in (
            "ReadBe32",
            "ReadLe32",
            "kPatchDescriptorVersion",
            "kPatchRegionBytes",
            "kRamTrailerBytes",
            "kRamRegionBytes",
            "FirmwareRegionOverlap",
            "FirmwareTableOutOfBounds",
            "AddOverflows",
        ):
            self.assertIn(token, self.source)

    def test_fixed_register_windows_are_exact_and_disjoint(self) -> None:
        rows = re.findall(
            r"\{0x([0-9A-Fa-f]{8}), 0x([0-9A-Fa-f]{5}), 0x([0-9A-Fa-f]{5})\},",
            self.source,
        )
        self.assertEqual(len(rows), 44)
        windows = [(int(chip, 16), int(bar, 16), int(size, 16)) for chip, bar, size in rows]
        for chip_base, bar_offset, size in windows:
            self.assertGreater(size, 0)
            self.assertGreaterEqual(chip_base, 0x100000)
            self.assertLessEqual(bar_offset + size, 0x100000)
            self.assertFalse(
                bar_offset < 0x50000 and 0x40000 < bar_offset + size,
                f"window at bar 0x{bar_offset:x} aliases the L1 window",
            )
        for index, (chip_base, bar_offset, size) in enumerate(windows):
            for prior_chip, prior_bar, prior_size in windows[:index]:
                self.assertFalse(
                    chip_base < prior_chip + prior_size and prior_chip < chip_base + size,
                    f"chip ranges 0x{chip_base:x}/0x{prior_chip:x} alias",
                )
                self.assertFalse(
                    bar_offset < prior_bar + prior_size and prior_bar < bar_offset + size,
                    f"bar ranges 0x{bar_offset:x}/0x{prior_bar:x} alias",
                )
        self.assertIn((0x820D0000, 0x30000, 0x10000), windows)
        self.assertIn((0x7C000000, 0xF0000, 0x10000), windows)
        self.assertIn((0x74030000, 0x10000, 0x10000), windows)
        self.assertIn("static_assert(FixedWindowsWellFormed()", self.source)

    def test_hostile_runtime_cases_remain_covered(self) -> None:
        for token in (
            "WrongPciIdentity",
            "WrongPciClass",
            "WrongPciRevision",
            "AddressOverflow",
            "UnsupportedRegister",
            "FirmwareTableOutOfBounds",
            "FirmwareRegionOverlap",
            "MakePaddingOverlapPatch",
            "TestFixedRegisterWindows",
            "TestContractRegisterPlanning",
            "stale_generation",
            "McuLengthMismatch",
            "McuFieldInvalid",
            "RingByteCountOverflow",
            "RingDmaAddressInvalid",
            "TestRingSetDmaAliasing",
            "InvalidStateTransition",
            "TeardownPending",
            "reuse_generation",
            "first_lifecycle.generation, 1u",
            "forged_zero_generation",
            "poisoned_plan",
        ):
            self.assertIn(token, self.host_test)

    def test_outputs_are_failure_atomic_and_active_generations_are_nonzero(self) -> None:
        for token in (
            "if (plan != nullptr)",
            "if (window != nullptr)",
            "if (summary != nullptr)",
            "FirmwareSummary staged = {}",
            "McuSummary staged = {}",
            "state->generation = 1",
            "state->generation == 0",
        ):
            self.assertIn(token, self.source)
        self.assertIn("0 until first identity acceptance", self.header)


if __name__ == "__main__":
    unittest.main(verbosity=2)
