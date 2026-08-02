#!/usr/bin/env python3
"""Structural contract for restart-safe NIC registry publication."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
NET_H = (ROOT / "kernel/drivers/net/net.h").read_text(encoding="utf-8")
NET_CPP = (ROOT / "kernel/drivers/net/net.cpp").read_text(encoding="utf-8")
INVENTORY = (ROOT / "kernel/net/wireless/inventory.cpp").read_text(encoding="utf-8")
NETPANEL = (ROOT / "kernel/drivers/video/netpanel.cpp").read_text(encoding="utf-8")
SHELL_NETWORK = (ROOT / "kernel/shell/shell_network.cpp").read_text(encoding="utf-8")


def body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class NetRegistryLifecycleContract(unittest.TestCase):
    def test_public_api_is_result_and_copy_out(self) -> None:
        self.assertIn("Result<void> NetInit();", NET_H)
        self.assertIn("bool NicSnapshot(u64 index, NicInfo* out);", NET_H)
        self.assertNotRegex(NET_H, r"const\s+NicInfo\s*&\s*Nic\s*\(")

    def test_registry_has_explicit_locked_states(self) -> None:
        for token in ("Starting", "Running", "Stopping", "Quarantined"):
            self.assertIn(token, NET_CPP)
        self.assertIn("SpinLock g_nic_registry_lock", NET_CPP)
        self.assertNotIn("g_init_done", NET_CPP)

    def test_init_publishes_only_after_population(self) -> None:
        init = body(NET_CPP, "Result<void> NetInit()")
        self.assertLess(init.index("NicRegistryState::Starting"), init.index("PciDeviceCount"))
        for field in (
            "subsystem_vendor_id",
            "subsystem_device_id",
            "class_code",
            "programming_interface",
            "revision_id",
            "subsystem_known",
        ):
            self.assertIn(f"nic.{field} = d.{field}", init)
        self.assertLess(init.index("g_nics[nic_index] = nic"), init.rindex("NicRegistryState::Running"))

    def test_shutdown_quarantines_failed_proofs(self) -> None:
        shutdown = body(NET_CPP, "Result<void> NetShutdown()")
        self.assertLess(shutdown.index("NicRegistryState::Stopping"), shutdown.index("E1000QuiesceAll"))
        self.assertGreaterEqual(shutdown.count("NicRegistryState::Quarantined"), 2)
        for quiesce in ("PcnetQuiesceAll", "E1000QuiesceAll", "VirtioNetQuiesce"):
            self.assertEqual(shutdown.count(quiesce), 1)
        self.assertRegex(
            shutdown,
            r"if\s*\(\s*unsupported_online\s*\|\|\s*!pcnet_quiesced\s*\|\|\s*!e1000_quiesced\s*\|\|\s*!virtio_net_quiesced\s*\)",
        )
        self.assertLess(shutdown.index("E1000QuiesceAll"), shutdown.index("g_nic_count = 0"))
        self.assertLess(shutdown.index("g_nic_count = 0"), shutdown.rindex("NicRegistryState::Stopped"))

    def test_modern_virtio_activation_uses_registry_identity_and_slot(self) -> None:
        probe = body(NET_CPP, "RunVendorProbe")
        self.assertIn("VirtioNetBringUpEligible(n.device_id)", probe)
        for field in ("bus", "device", "function"):
            self.assertIn(f"address.{field} = n.{field}", probe)
        self.assertIn("VirtioNetRestart(address, iface_index, &activation)", probe)
        self.assertLess(probe.index("VirtioNetRestart"), probe.index("n.driver_online = true"))
        unsupported = body(NET_CPP, "HasOnlineBackendWithoutRestartContract")
        self.assertIn("VirtioNetBringUpEligible(nic.device_id)", unsupported)

    def test_snapshot_copies_under_registry_lock(self) -> None:
        snapshot = body(NET_CPP, "bool NicSnapshot")
        self.assertIn("SpinLockGuard guard(g_nic_registry_lock)", snapshot)
        self.assertIn("g_nic_registry_state != NicRegistryState::Running", snapshot)
        self.assertIn("*out = g_nics[index]", snapshot)

    def test_module_start_propagates_init_failure(self) -> None:
        register = body(NET_CPP, "Result<void> RegisterNetModule()")
        self.assertRegex(register, r"return\s+::duetos::drivers::net::NetInit\(\)")

    def test_wireless_inventory_uses_candidates_not_functional_gates(self) -> None:
        ingest = body(INVENTORY, "void IngestNic")
        self.assertIn("NicFamilyLooksWireless", ingest)
        for forbidden in ("IwlwifiMatches", "Rtl88xxMatches", "Bcm43xxMatches", "Mt76Matches"):
            self.assertNotIn(forbidden, ingest)

    def test_status_surfaces_do_not_treat_inventory_as_connectivity(self) -> None:
        presence = body(NETPANEL, "NicPanelPresence ReadNicPanelPresence()")
        self.assertIn("NicSnapshot", presence)
        self.assertIn("nic.driver_online", presence)
        self.assertIn("nic.link_up", presence)
        self.assertIn("OFFLINE (no driver)", NETPANEL)
        self.assertIn("WIFI: inventory refreshed adapters=", SHELL_NETWORK)
        self.assertNotIn("WIFI: hardware path activated adapters=", SHELL_NETWORK)


if __name__ == "__main__":
    unittest.main()
