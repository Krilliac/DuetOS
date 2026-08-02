#!/usr/bin/env python3
"""Structural guardrails for restart-safe virtio-net ownership."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/drivers/virtio/virtio_net.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/drivers/virtio/virtio_net.cpp").read_text(encoding="utf-8")
NET_SOURCE = (ROOT / "kernel/drivers/net/net.cpp").read_text(encoding="utf-8")


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
    match = re.search(rf"\b{re.escape(name)}\s*\([^;{{]*\)\s*(?:const\s*)?\{{", clean)
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


class VirtioNetRestartContract(unittest.TestCase):
    def test_public_contract_is_bounded_and_truthful(self) -> None:
        for token in (
            "kRxSlots = 32",
            "kRxBufferBytes = 2048",
            "kMinimumFrameBytes = 14",
            "kMaximumFrameBytes = 1518",
            "InspectRxCompletion",
            "bool close_admission",
            "TransportFingerprint",
            "SameTransport",
            "HeaderIsSupported",
            "MayReleaseDma",
            "bool VirtioNetRestart(",
            "pci::DeviceAddress expected_address",
            "VirtioNetActivation* out_activation",
            "bool VirtioNetQuiesce();",
            "no detach callback yet",
        ):
            self.assertIn(token, HEADER)

    def test_context_owns_stable_lifetime_domains(self) -> None:
        for token in (
            "DriverOperationGate operations",
            "DriverWorkerLease rx_worker",
            "SpinLock lifecycle_lock",
            "SpinLock tx_lock",
            "NetInterfaceBinding stack_binding",
        ):
            self.assertIn(token, SOURCE)
        clear = function_body(SOURCE, "ClearRuntimeFields")
        self.assertNotRegex(clear, r"state\s*=\s*NetState")
        for stable in ("operations =", "rx_worker =", "lifecycle_lock =", "tx_lock ="):
            self.assertNotIn(stable, clear)

    def test_probe_only_stages_a_safe_exact_transport(self) -> None:
        probe = function_body(SOURCE, "VirtioNetProbe")
        ordered(
            probe,
            "pci::PciConfigRead16",
            "WritePciCommand",
            "ReadTransportFingerprint",
            "FingerprintMatchesLayout",
            "g_net.transport_staged = true",
            "ResetDevice",
            "SetBusMaster(g_net, false)",
            "LifecyclePhase::Idle",
        )
        for forbidden in ("NetStackBindInterfaceOwned", "DriverOperationGateOpen", "SchedCreate", "DhcpStart"):
            self.assertNotIn(forbidden, probe)

    def test_restart_publication_order_is_restart_safe(self) -> None:
        restart = function_body(SOURCE, "VirtioNetRestart")
        ordered(
            restart,
            "TryBeginStart",
            "ClearRuntimeFields",
            "WritePciCommand(expected_address, current_safe, false)",
            "ReadTransportFingerprint",
            "SameTransport",
            "PrepareDevice",
            "VirtioNegotiate",
            "VirtioQueueSetup",
            "AllocatePacketBuffers",
            "DriverWorkerLeasePrepare",
            "NetStackBindInterfaceOwned",
            "dma_published = true",
            "SetBusMaster(g_net, true)",
            "VirtioMarkDriverOk",
            "PostRxDescriptor",
            "DriverOperationGateOpen",
            "SchedCreate",
            "CompleteStart",
            "DhcpStart",
        )
        self.assertIn("AbortBringUp", restart)
        complete = function_body(SOURCE, "CompleteStart")
        ordered(complete, "LifecyclePhase::Starting", "DriverOperationGateIsOpen", "LifecyclePhase::Running")
        self.assertIn("g_net.txq.queue_size < 2", restart)
        self.assertIn("descriptor < g_net.rxq.queue_size", restart)
        self.assertNotIn("kNetFeatureMq", SOURCE)

    def test_failed_initial_bme_clear_is_quarantined_for_shutdown_retry(self) -> None:
        restart = function_body(SOURCE, "VirtioNetRestart")
        match = re.search(
            r"if \(!WritePciCommand\(expected_address, current_safe, false\)\)\s*\{(?P<body>.*?)\n\s*\}",
            restart,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        failure = match.group("body")
        self.assertIn("SetPhase(g_net, LifecyclePhase::Quarantined)", failure)
        self.assertNotIn("transport_staged = false", failure)

    def test_tx_is_context_bearing_pinned_and_serialized(self) -> None:
        transmit = function_body(SOURCE, "StackTransmit")
        self.assertIn("static_cast<NetState*>", transmit)
        self.assertIn("iface_index != state->iface_index", transmit)
        send = function_body(SOURCE, "SendFrame")
        ordered(
            send,
            "DriverOperationGateTryAcquire",
            "SpinLockAcquire(state.tx_lock)",
            "state.tx_buffer_virt",
            "VirtioQueuePublish",
            "VirtioQueueTryPop",
            "SpinLockRelease(state.tx_lock",
            "ReleaseOperation",
        )
        self.assertIn("MarkDeviceFaulted", send)
        self.assertIn("DriverOperationGateClose", send)
        self.assertNotIn("VirtioNetTxTrampoline", SOURCE)
        self.assertNotIn("NetStackBindInterface(kVirtioNetIfaceIndex", SOURCE)

    def test_rx_uses_exact_binding_outside_driver_locks(self) -> None:
        drain = function_body(SOURCE, "DrainRx")
        ordered(
            drain,
            "DriverOperationGateTryAcquire",
            "InspectRxCompletion",
            "NetStackInjectRx(state.stack_binding",
            "PostRxDescriptor",
            "ReleaseOperation",
        )
        self.assertNotIn("SpinLockAcquire", drain)
        self.assertIn("state.rxq.queue_size", drain)
        self.assertIn("HeaderIsSupported", drain)
        ordered(drain, "if (inspection.close_admission)", "DriverOperationGateClose", "break")
        self.assertNotIn("NetStackInjectRx(kVirtioNetIfaceIndex", SOURCE)

    def test_worker_has_exact_retire_and_ack_generation(self) -> None:
        worker = function_body(SOURCE, "RxPollEntry")
        ordered(
            worker,
            "DriverWorkerLeaseActiveGeneration",
            "DriverWorkerLeaseShouldRun",
            "DrainRx",
            "DriverWorkerLeaseAcknowledge",
        )
        self.assertNotIn("for (;;)", worker)

    def test_quiesce_joins_before_unbind_and_dma_release(self) -> None:
        quiesce = function_body(SOURCE, "QuiesceStartedContext")
        ordered(
            quiesce,
            "DriverOperationGateClose",
            "DriverWorkerLeaseRequestRetire",
            "WaitForJoins",
            "UnbindStack",
            "DriverWorkerLeaseRelease",
            "StopHardwareAndDisarm",
            "MayReleaseDma",
            "FreeDmaStorage",
            "ClearRuntimeFields",
        )
        abort = function_body(SOURCE, "AbortBringUp")
        ordered(abort, "worker_released", "if (worker_released)", "StopHardwareAndDisarm")

    def test_invalid_context_cannot_mutate_lifecycle_phase(self) -> None:
        public_quiesce = function_body(SOURCE, "VirtioNetQuiesce")
        ordered(public_quiesce, "arch::ReadRflags", "return false", "TryBeginStop", "QuiesceStartedContext")
        before_transition = public_quiesce[: public_quiesce.index("TryBeginStop")]
        self.assertNotIn("SetPhase", before_transition)

    def test_hardware_stop_is_reset_plus_verified_bme_off(self) -> None:
        stop = function_body(SOURCE, "StopHardwareAndDisarm")
        ordered(stop, "SetBusMaster(state, false)", "ResetDevice")
        self.assertIn("proof.device_reset && proof.bus_master_disabled", stop)
        command = function_body(SOURCE, "WritePciCommand")
        self.assertIn("PciConfigWrite32", command)
        self.assertIn("static_cast<u32>(desired)", command)
        self.assertNotIn("PciConfigRead32", command)

    def test_dma_free_requires_stop_proof_and_releases_every_page(self) -> None:
        free = function_body(SOURCE, "FreeDmaStorage")
        self.assertIn("!state.dma_published", free)
        self.assertIn("FreeQueueFrames(state.txq)", free)
        self.assertIn("FreeQueueFrames(state.rxq)", free)
        self.assertIn("state.header_phys", free)
        self.assertIn("state.tx_buffer_phys", free)
        self.assertIn("state.rx_frame_phys", free)

    def test_net_shutdown_attempts_every_restart_safe_backend(self) -> None:
        shutdown = function_body(NET_SOURCE, "NetShutdown")
        ordered(shutdown, "PcnetQuiesceAll", "E1000QuiesceAll", "VirtioNetQuiesce")
        self.assertIn("!pcnet_quiesced || !e1000_quiesced || !virtio_net_quiesced", shutdown)


if __name__ == "__main__":
    unittest.main(verbosity=2)
