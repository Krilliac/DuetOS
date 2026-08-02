#!/usr/bin/env python3
"""Structural contract for restart-safe NIC worker and DMA teardown."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    start = re.search(rf"\b{re.escape(name)}\s*\([^;{{]*\)\s*\{{", source)
    if start is None:
        raise AssertionError(f"definition not found: {name}")
    opening = source.find("{", start.start())
    depth = 0
    index = opening
    state = "code"
    quote = ""
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "/":
                state = "line"
                index += 2
                continue
            if current == "/" and following == "*":
                state = "block"
                index += 2
                continue
            if current in ('"', "'"):
                quote = current
                state = "literal"
            elif current == "{":
                depth += 1
            elif current == "}":
                depth -= 1
                if depth == 0:
                    return source[opening : index + 1]
        elif state == "line":
            if current == "\n":
                state = "code"
        elif state == "block":
            if current == "*" and following == "/":
                state = "code"
                index += 2
                continue
        elif state == "literal":
            if current == "\\":
                index += 2
                continue
            if current == quote:
                state = "code"
        index += 1
    raise AssertionError(f"unterminated definition: {name}")


def ordered(body: str, *needles: str) -> None:
    position = -1
    for needle in needles:
        next_position = body.find(needle, position + 1)
        if next_position < 0:
            raise AssertionError(f"missing ordered token: {needle}")
        position = next_position


class DriverWorkerLifecycleContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lease = read("kernel/drivers/net/wireless_watch.h")
        cls.net = read("kernel/drivers/net/net.cpp")
        cls.net_header = read("kernel/drivers/net/net.h")
        cls.wireless = {
            "Iwlwifi": read("kernel/drivers/net/iwlwifi.cpp"),
            "Rtl88xx": read("kernel/drivers/net/rtl88xx.cpp"),
            "Bcm43xx": read("kernel/drivers/net/bcm43xx.cpp"),
            "Mt76": read("kernel/drivers/net/mt76.cpp"),
        }

    def test_lease_requires_exact_retire_and_ack_receipts(self) -> None:
        prepare = function_body(self.lease, "DriverWorkerLeasePrepare")
        acknowledge = function_body(self.lease, "DriverWorkerLeaseAcknowledge")
        release = function_body(self.lease, "DriverWorkerLeaseRelease")
        self.assertIn("CompareExchange", prepare)
        self.assertIn("kDriverWorkerLeasePreparing", prepare)
        self.assertIn("retire_generation", acknowledge)
        self.assertIn("active_generation", acknowledge)
        self.assertIn("DriverWorkerLeaseIsAcknowledged", release)
        self.assertIn("CompareExchange", release)

    def test_worker_captures_generation_and_acknowledges_exit(self) -> None:
        worker = function_body(self.net, "E1000RxPollEntry")
        ordered(
            worker,
            "DriverWorkerLeaseActiveGeneration",
            "DriverWorkerLeaseShouldRun",
            "E1000DrainRx",
            "DriverWorkerLeaseAcknowledge",
        )
        self.assertNotIn("while (true)", worker)
        self.assertNotIn("NicInfo", worker)

    def test_bringup_publishes_stack_receipt_and_gate_before_task(self) -> None:
        bring_up = function_body(self.net, "E1000BringUp")
        self.assertIn("LivePciIdentityMatches(n)", bring_up)
        ordered(
            bring_up,
            "DriverWorkerLeasePrepare",
            "NetStackBindInterfaceOwned",
            "E1000EnableDatapath",
            "DriverOperationGateOpen",
            "SchedCreate",
            "n.driver_online = true",
        )
        self.assertIn("E1000AbortUnstartedBringUp", bring_up)
        self.assertIn("worker == nullptr", bring_up)
        self.assertNotIn("TaskCreateResult", bring_up)
        self.assertNotIn("PciMsixBindSimple", bring_up)
        self.assertNotIn("kE1000RegIvar", self.net)

    def test_shutdown_joins_worker_and_pins_before_dma_free(self) -> None:
        quiesce = function_body(self.net, "E1000QuiesceOne")
        ordered(
            quiesce,
            "DriverOperationGateClose",
            "DriverWorkerLeaseRequestRetire",
            "DriverWorkerLeaseIsAcknowledged",
            "DriverOperationGatePinCount",
            "E1000UnbindStack",
            "DriverWorkerLeaseRelease",
            "E1000DisableHardware",
            "E1000FreeDmaStorage",
            "E1000ClearRuntimeFields",
        )
        timeout = quiesce[quiesce.index("if (!worker_done || !operations_done)") :]
        self.assertLess(timeout.index("return false"), timeout.index("E1000FreeDmaStorage"))

        shutdown = function_body(self.net, "NetShutdown")
        ordered(
            shutdown,
            "HasOnlineBackendWithoutRestartContract",
            "E1000QuiesceAll",
            "ErrorCode::Busy",
            "g_nic_count = 0",
            "NicRegistryState::Stopped",
        )

    def test_tx_path_is_pinned_serialized_and_ring_full_safe(self) -> None:
        send = function_body(self.net, "E1000Send")
        ordered(
            send,
            "E1000AcquireOperation",
            "SpinLockAcquire",
            "DmaSyncForCpu",
            "kE1000TxStatusDd",
            "tx_in_flight >= kE1000TxRingSlots - 1",
            "DmaSyncForDevice",
            "kE1000RegTdt",
            "SpinLockRelease",
            "E1000ReleaseOperation",
        )
        context = re.search(r"struct\s+E1000Ctx\s*\{(?P<body>.*?)\n\};", self.net, re.DOTALL)
        self.assertIsNotNone(context)
        context_body = context.group("body")
        self.assertIn("DriverOperationGate operations", context_body)
        self.assertIn("DriverWorkerLease rx_worker", context_body)
        self.assertIn("SpinLock tx_lock", context_body)
        self.assertNotIn("accepting_operations", context_body)
        self.assertNotIn("operation_pins", context_body)
        self.assertNotRegex(context_body, r"NicInfo\s*\*")
        self.assertNotRegex(self.net, r"\*?ctx\s*=\s*\{\}")

    def test_rx_rejects_fragments_errors_and_syncs_dma(self) -> None:
        drain = function_body(self.net, "E1000DrainRx")
        ordered(
            drain,
            "DriverOperationGateIsOpen",
            "DmaSyncForCpu",
            "kE1000RxStatusDd",
            "d.errors",
            "kE1000RxStatusEop",
            "rx_discard_until_eop",
            "NetStackInjectRx",
            "DmaSyncForDevice",
            "kE1000RegRdt",
        )

    def test_pci_and_dma_teardown_is_fail_closed(self) -> None:
        bring_up = function_body(self.net, "E1000BringUp")
        ordered(
            bring_up,
            "E1000PreparePciCommand",
            "E1000AbortUnstartedBringUp",
            "E1000Reset",
        )
        ordered(bring_up, "E1000MacIsUsable", "n.mac_valid = false", "E1000AbortUnstartedBringUp")
        disable = function_body(self.net, "E1000DisableHardware")
        ordered(
            disable,
            "kE1000RegRctl",
            "kE1000RegTctl",
            "E1000DisableBusMaster",
            "E1000Reset",
            "E1000RestorePciCommand",
        )
        free = function_body(self.net, "E1000FreeDmaStorage")
        self.assertIn("!ctx.dma_armed", free)
        self.assertIn("FreeDmaCoherent", free)
        self.assertNotIn("FreeContiguousFrames", free)
        command = function_body(self.net, "E1000UpdatePciCommand")
        self.assertIn("PciConfigWrite32", command)
        self.assertIn("static_cast<u32>(desired)", command)
        disarm = function_body(self.net, "DisablePciBusMasterForProbe")
        self.assertIn("PciConfigWrite32", disarm)
        self.assertIn("~kPciCommandBusMaster", disarm)
        abort = function_body(self.net, "E1000AbortUnstartedBringUp")
        ordered(
            abort,
            "E1000UnbindStack",
            "DriverOperationGatePinCount",
            "if (!stack_unbound || !worker_released || !operations_drained)",
            "E1000DisableHardware",
            "E1000FreeDmaStorage",
        )

    def test_wireless_watchers_are_not_immortal_tasks(self) -> None:
        for prefix, source in self.wireless.items():
            start = function_body(source, f"{prefix}StartWatch")
            self.assertNotIn("SchedCreate", start)
            self.assertNotRegex(source, rf"\b{prefix}WatchEntry\b")
        self.assertIn("backend-specific wireless watchers", self.lease)
        self.assertIn("raw NicInfo pointers plus immortal loops", self.lease)

    def test_mmio_cache_owns_restart_mappings(self) -> None:
        acquire = function_body(self.net, "AcquireNicMmioMapping")
        self.assertIn("SamePciAddress", acquire)
        self.assertIn("bar_index", acquire)
        self.assertIn("physical_address", acquire)
        self.assertIn("mapped_bytes", acquire)
        self.assertIn("mapping cache exhausted", acquire)
        self.assertNotIn("UnmapMmio", self.net)
        self.assertIn("bounded BDF/BAR cache", self.net_header)


if __name__ == "__main__":
    unittest.main(verbosity=2)
