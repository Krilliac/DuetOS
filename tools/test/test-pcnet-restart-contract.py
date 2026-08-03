#!/usr/bin/env python3
"""Structural guardrails for the restart-safe AMD PCnet backend."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/drivers/net/pcnet.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/drivers/net/pcnet.cpp").read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
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
    match = re.search(rf"\b{re.escape(name)}\s*\([^;{{]*\)\s*\{{", clean)
    if match is None:
        raise AssertionError(f"definition not found: {name}")
    opening = clean.find("{", match.start())
    depth = 0
    for position in range(opening, len(clean)):
        if clean[position] == "{":
            depth += 1
        elif clean[position] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : position + 1]
    raise AssertionError(f"unterminated definition: {name}")


def ordered(text: str, *tokens: str) -> None:
    position = -1
    for token in tokens:
        position = text.find(token, position + 1)
        if position < 0:
            raise AssertionError(f"missing ordered token: {token}")


class PcnetRestartContract(unittest.TestCase):
    def test_public_surface_and_wire_helpers_are_bounded(self) -> None:
        self.assertIn("bool PcnetBringUp(NicInfo& nic, u32 iface_index);", HEADER)
        self.assertIn("bool PcnetQuiesceAll();", HEADER)
        for token in ("PcnetDescriptor", "PcnetInitBlock", "InspectRx", "TxRingFull", "Csr0RuntimeAckValue"):
            self.assertIn(token, HEADER)
        self.assertIn("wire_bytes > kMaximumFrameBytes + kEthernetFcsBytes", HEADER)

    def test_context_owns_stable_lifetime_domains(self) -> None:
        for token in (
            "DriverOperationGate operations",
            "DriverWorkerLease rx_worker",
            "SpinLock tx_lock",
            "SpinLock csr_lock",
            "NetInterfaceBinding stack_binding",
        ):
            self.assertIn(token, SOURCE)
        clear = function_body(SOURCE, "ClearRuntimeFields")
        self.assertNotRegex(clear, r"ctx\s*=\s*PcnetCtx")
        for stable in ("operations =", "rx_worker =", "tx_lock =", "csr_lock ="):
            self.assertNotIn(stable, clear)

    def test_bringup_keeps_bme_off_until_publication(self) -> None:
        bringup = function_body(SOURCE, "PcnetBringUp")
        ordered(
            bringup,
            "LivePciIdentityMatches",
            "SaveAndDisarmPci",
            "PciReadBar",
            "EnableIoDecode",
            "ResetAndSelectStyle",
            "AllocateDmaStorage",
            "DriverWorkerLeasePrepare",
            "NetStackBindInterfaceOwned",
            "InitializeAndStart",
            "DriverOperationGateOpen",
            "SchedCreate",
            "driver_online = true",
            "DhcpStart(iface_index)",
        )
        ordered(bringup, "nic.mac_valid = true", "if (!MacIsUsable(nic))", "nic.mac_valid = false")
        identity = function_body(SOURCE, "LivePciIdentityMatches")
        for token in ("PciDeviceCount", "PciConfigRead32(address, 0x00)", "PciConfigRead32(address, 0x08)",
                      "PciConfigRead8(address, 0x0E)", "PciConfigRead32(address, 0x2C)",
                      "live_subsystem != 0", "live_subsystem != 0xFFFFFFFFu"):
            self.assertIn(token, identity)

    def test_tx_is_serialized_bounded_and_publishes_own_last(self) -> None:
        send = function_body(SOURCE, "SendFrame")
        ordered(send, "AcquireOperation", "SpinLockAcquire(ctx.tx_lock)", "DmaSyncForCpu", "TxRingFull")
        ordered(send, "DmaSyncForDevice(ctx.tx_buf_dma", "descriptor.status |= contract::kDescriptorOwn")
        ordered(send, "SpinLockRelease(ctx.tx_lock", "WriteCsr(ctx, 0, contract::kCsr0TransmitDemand)")
        self.assertIn("len > contract::kMaximumFrameBytes", send)

    def test_rx_uses_exact_binding_and_hostile_descriptor_policy(self) -> None:
        drain = function_body(SOURCE, "DrainRx")
        self.assertIn("contract::InspectRx", drain)
        self.assertIn("NetStackInjectRx(ctx.stack_binding", drain)
        ordered(drain, "descriptor.status = 0", "DmaSyncForDevice", "descriptor.status = contract::kDescriptorOwn")
        self.assertNotIn("NetStackInjectRx(0", SOURCE)
        self.assertNotIn("NetStackBindInterface(0", SOURCE)

    def test_csr0_writes_never_echo_w1c_status(self) -> None:
        self.assertNotRegex(SOURCE, r"ReadCsr\([^)]*,\s*0\s*\)\s*\|")
        ack = function_body(SOURCE, "AckRuntimeCauses")
        self.assertIn("Csr0RuntimeAckValue(status)", ack)
        self.assertIn("arch::Outl(ctx.io + kRdp, ack)", ack)

    def test_shutdown_proves_every_join_before_dma_free(self) -> None:
        quiesce = function_body(SOURCE, "QuiesceOne")
        ordered(
            quiesce,
            "DriverOperationGateClose",
            "DriverWorkerLeaseRequestRetire",
            "WaitForJoins",
            "UnbindStack",
            "DriverWorkerLeaseRelease",
            "StopHardwareAndDisarm",
            "FreeDmaStorage",
            "ClearRuntimeFields",
        )
        stop = function_body(SOURCE, "StopHardwareAndDisarm")
        ordered(stop, "WriteCsr(ctx, 0, contract::kCsr0Stop)", "DisableBusMaster", "RestoreSafePciCommand")
        self.assertLess(stop.index("bus_master_disabled"), stop.index("ctx.dma_published = false"))
        abort = function_body(SOURCE, "AbortUnstartedBringUp")
        ordered(abort, "worker_released", "worker_released && StopHardwareAndDisarm")


if __name__ == "__main__":
    unittest.main()
