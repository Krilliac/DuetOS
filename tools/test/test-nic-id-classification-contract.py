#!/usr/bin/env python3
"""Structural safety contract for NIC classification and probe dispatch."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    """Return a C/C++ function body using a small comment/string-aware scan."""
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
        elif state == "literal":
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


class NicIdClassificationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ids = read("kernel/drivers/net/nic_ids.h")
        cls.net = read("kernel/drivers/net/net.cpp")
        cls.mt76 = read("kernel/drivers/net/mt76.h")
        cls.mt76_fw = read("kernel/drivers/net/mt76_fw.cpp")
        cls.inventory = read("kernel/net/wireless/inventory.cpp")
        cls.drivers = {
            "Iwlwifi": read("kernel/drivers/net/iwlwifi.cpp"),
            "Rtl88xx": read("kernel/drivers/net/rtl88xx.cpp"),
            "Bcm43xx": read("kernel/drivers/net/bcm43xx.cpp"),
            "Mt76": read("kernel/drivers/net/mt76.cpp"),
        }

    def test_incompatible_intel_and_broadcom_ranges_are_absent(self) -> None:
        classic = function_body(self.ids, "IntelIsE1000ClassicId")
        i40e = function_body(self.ids, "IntelIsI40eId")
        broadcom = function_body(self.ids, "BroadcomWirelessCandidateBackendsFromDeviceId")
        for body in (classic, i40e, broadcom):
            self.assertNotRegex(body, r"\bdid\s*>?=\s*0x[0-9A-Fa-f]+")
            self.assertNotRegex(body, r"\bdid\s*<=\s*0x[0-9A-Fa-f]+")
        self.assertNotIn("0x4300..0x43FF", self.ids)
        self.assertIn("case 0x1000:", classic)
        self.assertIn("case 0xA8D6:", broadcom)
        self.assertIn("case 0xAA52:", broadcom)

    def test_wireless_inventory_is_split_by_real_backend(self) -> None:
        for backend in (
            "IntelIwlegacy",
            "IntelIwlwifi",
            "RealtekRtlwifi",
            "RealtekRtw88",
            "RealtekRtw89",
            "BroadcomB43Ssb",
            "BroadcomBcma",
            "BroadcomBrcmfmac",
            "MediaTekMt76",
        ):
            self.assertIn(backend, self.ids)
        for tag in (
            '"iwlegacy-3945"',
            '"iwlwifi-9000"',
            '"rtlwifi-pci"',
            '"rtw88-pci"',
            '"rtw89-pci"',
            '"b43-ssb-wifi"',
            '"brcm-bcma-wifi"',
            '"brcmfmac-pcie"',
            '"brcm-wifi-candidate"',
        ):
            self.assertIn(tag, self.ids)

    def test_unaudited_wireless_backends_fail_closed(self) -> None:
        for function in (
            "IntelIwlwifiProbeEligible",
            "RealtekWirelessProbeEligible",
            "BroadcomWirelessProbeEligible",
        ):
            body = function_body(self.ids, function)
            self.assertRegex(body, r"\(void\)\s*did\s*;")
            self.assertRegex(body, r"return\s+false\s*;")
        self.assertRegex(
            function_body(self.ids, "BroadcomWirelessProbeEligible"),
            r"\(void\)\s*backend\s*;",
        )

        for prefix, source in self.drivers.items():
            bring_up = function_body(source, f"{prefix}BringUp")
            gate = "Bcm43xxMatches(n)" if prefix == "Bcm43xx" else f"{prefix}Matches(n.vendor_id, n.device_id)"
            self.assertIn(gate, bring_up)
            gate_at = bring_up.index(gate)
            first_mmio = min(
                (position for token in ("n.mmio_virt", "Mmio32Read")
                 if (position := bring_up.find(token)) >= 0),
                default=len(bring_up),
            )
            self.assertLess(gate_at, first_mmio)

        mt76_matches = function_body(self.drivers["Mt76"], "Mt76Matches")
        self.assertIn("Mt76FamilyFromIdentity", mt76_matches)
        self.assertRegex(mt76_matches, r"return\s+false\s*;")
        self.assertIn("Mt76FamilyFromIdentity(n.vendor_id, n.device_id)",
                      function_body(self.drivers["Mt76"], "Mt76BringUp"))

    def test_mediatek_exact_families_and_companion_rows(self) -> None:
        device = function_body(self.mt76, "Mt76FamilyFromDeviceId")
        identity = function_body(self.mt76, "Mt76FamilyFromIdentity")
        primary = function_body(self.mt76, "Mt76FamilyIsPrimaryAdapter")
        tag = function_body(self.mt76, "Mt76InventoryTag")

        for device_id in (
            "0x7615", "0x7611", "0x7663", "0x7915", "0x7906",
            "0x7961", "0x0608", "0x7922", "0x0616", "0x7920",
            "0x7902", "0x7925", "0x0717", "0x7927", "0x6639", "0x0738",
        ):
            self.assertIn(f"case {device_id}:", device)
        self.assertIn("case 0x7916:", device)
        self.assertIn("case 0x790A:", device)
        self.assertRegex(device, re.compile(r"case\s+0x7906:.*?return\s+Mt76Family::Mt7916", re.DOTALL))
        self.assertIn("Mt76Family::HifCompanion", device)
        self.assertIn("kVendorIttim", identity)
        self.assertIn("device_id == 0x7922", identity)
        self.assertIn("family != Mt76Family::HifCompanion", primary)
        self.assertNotIn("family != Mt76Family::Mt7916", primary)
        self.assertIn('return "mt7916-wifi"', tag)
        self.assertIn("case Mt76Family::HifCompanion:", tag)
        self.assertRegex(tag, re.compile(r"case\s+Mt76Family::HifCompanion:.*?return\s+nullptr", re.DOTALL))

        mediatek_tag = function_body(self.net, "MediatekNicTag")
        self.assertIn("Mt76FamilyFromIdentity", mediatek_tag)
        self.assertIn("Mt76InventoryTag", mediatek_tag)
        run_probe = function_body(self.net, "RunVendorProbe")
        self.assertIn("case kVendorIttim:", run_probe)
        self.assertIn("family == nullptr", run_probe)
        self.assertIn("Mt76FamilyFromIdentity", self.inventory)

        firmware = function_body(self.mt76_fw, "Mt76FirmwareBasenameForFamily")
        for unsupported in ("Mt7902", "Mt7920", "Mt7927", "HifCompanion"):
            self.assertNotIn(f"case Mt76Family::{unsupported}:", firmware)
        self.assertRegex(firmware, re.compile(r"default:.*?return\s+nullptr", re.DOTALL))

    def test_bar_selection_is_metadata_until_safe_gate_opens(self) -> None:
        realtek_bar = function_body(self.ids, "RealtekWirelessPreferredMmioBar")
        for device_id in ("0x8171", "0x8172", "0x8173", "0x8174", "0x8192"):
            self.assertIn(f"case {device_id}:", realtek_bar)
        self.assertRegex(realtek_bar, r"return\s+1\s*;")
        self.assertIn("kInvalidPciBar", realtek_bar)
        self.assertNotIn("? 0 : 2", realtek_bar)
        net_init = function_body(self.net, "NetInit")
        self.assertIn("LivePciIdentityMatches(nic)", net_init)
        self.assertLess(net_init.index("LivePciIdentityMatches(nic)"), net_init.index("PciReadBar"))
        self.assertIn("DisablePciBusMasterForProbe(d.addr)", net_init)
        self.assertLess(net_init.index("DisablePciBusMasterForProbe(d.addr)"), net_init.index("PciReadBar"))
        self.assertIn("RealtekWirelessPreferredMmioBar", net_init)
        self.assertIn("requires_mapped_mmio", net_init)
        self.assertLess(net_init.index("requires_mapped_mmio"), net_init.index("PciReadBar"))
        self.assertNotIn("MapMmio(bar.address", net_init)

    def test_broadcom_subsystem_qualified_ids_do_not_flatten(self) -> None:
        candidates = function_body(self.ids, "BroadcomWirelessCandidateBackendsFromDeviceId")
        identity = function_body(self.ids, "BroadcomWirelessBackendFromIdentity")
        identity_tag = function_body(self.ids, "BroadcomWirelessTagFromIdentity")
        self.assertIn("case 0x4355:", candidates)
        self.assertIn("case 0x4365:", candidates)
        self.assertIn("WirelessBackend::BroadcomBcma", candidates)
        self.assertIn("WirelessBackend::BroadcomBrcmfmac", candidates)
        for token in (
            "subsystem_known",
            "kVendorBroadcom",
            "0x1028",
            "0x105B",
            "0x103C",
            "0x0016",
            "0x0018",
            "0xE092",
            "0x804A",
        ):
            self.assertIn(token, identity)
        self.assertIn("BroadcomWirelessBackendFromIdentity", identity_tag)
        self.assertIn('"brcm-wifi-candidate"', identity_tag)
        run_probe = function_body(self.net, "RunVendorProbe")
        for qualifier in ("n.subsystem_vendor_id", "n.subsystem_device_id", "n.subsystem_known"):
            self.assertIn(qualifier, run_probe)

    def test_online_state_is_not_derived_from_classification(self) -> None:
        run_probe = function_body(self.net, "RunVendorProbe")
        self.assertIn('kVendorAmd, "AMD"', self.net)
        for classifier in (
            "IntelNicTag",
            "RealtekNicTag",
            "BroadcomNicTag",
            "MediatekNicTag",
        ):
            self.assertIn(classifier, run_probe)
        classifier_prefix = run_probe[: run_probe.index("bool brought_up")]
        self.assertNotIn("driver_online", classifier_prefix)
        self.assertNotRegex(classifier_prefix, r"Mmio|MMIO")

    def test_virtio_modern_transport_is_the_only_functional_identity(self) -> None:
        gate = function_body(self.ids, "VirtioNetBringUpEligible")
        self.assertIn("did == 0x1041", gate)
        self.assertNotIn("0x1000", gate)
        run_probe = function_body(self.net, "RunVendorProbe")
        self.assertIn("VirtioNetBringUpEligible(n.device_id)", run_probe)
        self.assertIn("VirtioNetRestart(address, iface_index, &activation)", run_probe)

    def test_broadcom_chip_name_boundary_is_strict(self) -> None:
        formatter = function_body(self.ids, "BcmChipNameFormat")
        self.assertIn("chip_id > 0xA000", formatter)
        self.assertNotIn("chip_id >= 0xA000", formatter)


if __name__ == "__main__":
    unittest.main(verbosity=2)
