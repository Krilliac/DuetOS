#!/usr/bin/env python3
"""Freeze the dedicated native Service Control v1 ABI and trust boundary."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ABI = json.loads((ROOT / "abi/native_syscalls.json").read_text(encoding="utf-8"))
PUBLIC = (ROOT / "userland/libc/include/duet/service_control.h").read_text(encoding="utf-8")
INTERNAL = (ROOT / "kernel/syscall/service_control_ingress.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/syscall/service_control_ingress.cpp").read_text(encoding="utf-8")
SYSCALL_H = (ROOT / "kernel/syscall/syscall.h").read_text(encoding="utf-8")
SYSCALL_CPP = (ROOT / "kernel/syscall/syscall.cpp").read_text(encoding="utf-8")
LIBC = (ROOT / "userland/libc/src/syscall.c").read_text(encoding="utf-8")
PROCESS_H = (ROOT / "kernel/proc/process.h").read_text(encoding="utf-8")
PROCESS_CPP = (ROOT / "kernel/proc/process.cpp").read_text(encoding="utf-8")
NAMES = (ROOT / "kernel/syscall/syscall_names.def").read_text(encoding="utf-8")
GENERATED = (ROOT / "kernel/syscall/syscall_idl_generated.def").read_text(encoding="utf-8")
NUMBERS = (ROOT / "userland/libc/include/duet/syscall_numbers_generated.h").read_text(encoding="utf-8")
POLICY = json.loads((ROOT / "docs/native-syscall-policy.json").read_text(encoding="utf-8"))


def syscall_row(document: dict, number: int) -> dict:
    matches = [row for row in document["syscalls"] if row["number"] == number]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one syscall {number}, got {len(matches)}")
    return matches[0]


class ServiceControlIngressContract(unittest.TestCase):
    def test_syscall_228_is_separate_and_generated_everywhere(self) -> None:
        row = syscall_row(ABI, 228)
        self.assertEqual(row["name"], "SYS_SERVICE_CONTROL")
        self.assertEqual(row["status"], "implemented")
        self.assertEqual(row["authorization"]["mode"], "dynamic")
        self.assertEqual(row["authorization"]["owner"], "kernel/syscall/service_control_ingress.cpp")
        self.assertEqual([arg["register"] for arg in row["arguments"]], ["rdi", "rsi", "rdx", "r10"])
        self.assertEqual(syscall_row(ABI, 227)["name"], "SYS_SERVICE_ENDPOINT_OP")
        self.assertIn("SYS_SERVICE_CONTROL = 228", SYSCALL_H)
        self.assertIn("X(SYS_SERVICE_CONTROL, 228)", NAMES)
        self.assertIn("DUETOS_NATIVE_SYSCALL(SYS_SERVICE_CONTROL, 228, Dynamic", GENERATED)
        self.assertIn("DUET_SYS_SERVICE_CONTROL = 228", NUMBERS)
        self.assertEqual(syscall_row(POLICY, 228)["name"], "SYS_SERVICE_CONTROL")

    def test_v1_is_fixed_pointer_free_and_zero_reserved(self) -> None:
        operations = {
            "DESCRIBE_SELF": 1,
            "MARK_READY": 2,
            "ENUMERATE": 3,
            "ACTIVATE": 4,
            "STOP": 5,
            "RESTAGE": 6,
            "EXIT_DEQUEUE": 7,
            "EXIT_ACK": 8,
        }
        for name, value in operations.items():
            self.assertRegex(PUBLIC, rf"DUET_SERVICE_CONTROL_OP_{name}\s*=\s*{value}")
        self.assertIn("sizeof(duet_service_control_request_v1) == 80", PUBLIC)
        self.assertIn("sizeof(duet_service_control_result_v1) == 112", PUBLIC)
        request = re.search(
            r"typedef struct duet_service_control_request_v1\s*\{(?P<body>.*?)\}\s*duet_service_control_request_v1;",
            PUBLIC,
            re.S,
        )
        self.assertIsNotNone(request)
        body = re.sub(r"/\*.*?\*/", "", request.group("body"), flags=re.S)
        self.assertNotIn("*", body)
        self.assertNotRegex(body, r"capabilit(?:y|ies)")
        self.assertIn("uint64_t operation_token", body)
        self.assertIn("uint64_t event_sequence", body)
        self.assertIn("uint64_t reserved[1]", body)
        self.assertIn("offsetof(duet_service_control_request_v1, operation_token) == 56", PUBLIC)
        self.assertIn("offsetof(duet_service_control_request_v1, event_sequence) == 64", PUBLIC)
        self.assertIn("request.flags == 0", SOURCE)
        self.assertIn("request.reserved[0] == 0", SOURCE)
        self.assertNotIn("request.reserved[1]", SOURCE)
        self.assertIn("event.reserved", SOURCE)

    def test_self_authority_is_derived_and_ready_is_one_atomic_public_call(self) -> None:
        self.assertIn("FindCallerService(runtime, caller->process", SOURCE)
        self.assertIn("ProcessKeyIsValid(caller->process)", SOURCE)
        self.assertIn("RequestMatchesService(request_copy, runtime, service, true)", SOURCE)
        self.assertEqual(SOURCE.count("ServiceLifecycleBrokerMarkReady("), 1)
        self.assertNotIn("ServiceDirectoryCommitJointReady(", SOURCE)
        self.assertLess(SOURCE.index("ServiceDirectoryLookup("), SOURCE.index("ServiceLifecycleBrokerMarkReady("))
        self.assertLess(
            SOURCE.index("ServiceLifecycleBrokerMarkReady("), SOURCE.index("ServiceDirectoryReleaseOperation(")
        )

    def test_supervisor_has_a_dedicated_non_wire_capability(self) -> None:
        self.assertRegex(PROCESS_H, r"kCapServiceControl\s*=\s*12")
        self.assertIn('return "ServiceControl";', PROCESS_CPP)
        self.assertIn("CapSetHas(caller->capabilities, kCapServiceControl)", SOURCE)
        self.assertIn("ProcessCapsSnapshot(process)", SOURCE)
        self.assertNotIn("required_cap", PUBLIC)
        self.assertNotIn("capability_mask", PUBLIC)
        # The manifest decision is explicit and row-scoped: the authority may
        # admit bit 12, but only serviced requests it.
        manifest_h = (ROOT / "kernel/core/service_manifest.h").read_text(encoding="utf-8")
        self.assertIn("kServiceManifestCapabilityMaskV1 = 0x1FFEULL", manifest_h)
        services = (ROOT / "config/services.toml").read_text(encoding="utf-8")
        rows = services.split("[[service]]")[1:]
        holders = [row for row in rows if '"service-control"' in row]
        self.assertEqual(1, len(holders))
        self.assertIn('name = "serviced"', holders[0])

    def test_platform_is_typed_one_shot_and_fail_closed(self) -> None:
        for callback in ("activate", "stop", "restage", "exit_dequeue", "exit_ack"):
            self.assertRegex(INTERNAL, rf"ServiceControlPlatform.*FnV1\s+{callback};")
        self.assertIn("PlatformAlreadyInstalled", INTERNAL)
        self.assertIn("state->platform_installed != 0", SOURCE)
        self.assertIn("if (!SnapshotPlatform(*state, &platform))", SOURCE)
        self.assertIn("DUET_SERVICE_CONTROL_STATUS_NOT_READY", SOURCE)
        self.assertNotIn("service_exit_reap_ledger.h", SOURCE)
        self.assertNotIn("service_bootstrap_live.h", SOURCE)
        # SnapshotPlatform's guard ends before any callback dispatch.
        snapshot_end = SOURCE.index("void InitializeResult", SOURCE.index("bool SnapshotPlatform"))
        for call in ("platform.activate(", "platform.stop(", "platform.restage(", "platform.exit_dequeue(", "platform.exit_ack("):
            self.assertGreater(SOURCE.index(call), snapshot_end)

    def test_exact_identity_busy_replay_and_no_wrap_are_preserved(self) -> None:
        self.assertIn("request.transition_generation != service.snapshot.transition_generation", SOURCE)
        self.assertIn("request.process_identity == service.snapshot.instance.process_identity", SOURCE)
        self.assertIn("request.operation_token != 0", SOURCE)
        self.assertIn("request.operation_token == 0", SOURCE)
        self.assertIn("request.event_sequence != 0", SOURCE)
        self.assertIn("RequestProcess(request), request.event_sequence", SOURCE)
        self.assertIn("FillServiceResult(runtime, current, result)", SOURCE)
        self.assertIn("result->event_sequence = request_copy.event_sequence", SOURCE)
        self.assertIn("ServiceControlPlatformStatusV1::Busy", SOURCE)
        self.assertIn("ServiceControlPlatformStatusV1::ReplayRejected", SOURCE)
        self.assertIn("kServiceTransitionGenerationMaximum", SOURCE)
        self.assertIn("DUET_SERVICE_CONTROL_STATUS_GENERATION_EXHAUSTED", SOURCE)
        self.assertNotRegex(SOURCE, r"operation_token\s*\+\+")
        self.assertNotRegex(SOURCE, r"event_sequence\s*\+\+")

    def test_dispatch_copy_and_libc_r10_wiring_are_failure_atomic(self) -> None:
        self.assertIn('#include "syscall/service_control_ingress.h"', SYSCALL_CPP)
        self.assertIn("case SYS_SERVICE_CONTROL:", SYSCALL_CPP)
        self.assertIn("DoServiceControl(frame);", SYSCALL_CPP)
        wrapper = re.search(r"long duet_service_control\(.*?^\}", LIBC, re.S | re.M)
        self.assertIsNotNone(wrapper)
        self.assertIn('mov %5, %%r10', wrapper.group(0))
        self.assertIn("DUET_SYS_SERVICE_CONTROL", wrapper.group(0))
        do_syscall = SOURCE[SOURCE.index("void DoServiceControl(") :]
        self.assertLess(do_syscall.index("mm::CopyFromUser"), do_syscall.index("AddressSpaceAcquireWriteLease"))
        self.assertLess(
            do_syscall.index("AddressSpaceAcquireWriteLease"), do_syscall.index("ServiceControlIngressExecute(")
        )
        self.assertLess(
            do_syscall.index("ServiceControlIngressExecute("), do_syscall.index("AddressSpaceCopyToWriteLease")
        )
        self.assertIn("frame->rsi != sizeof(duet_service_control_request_v1)", do_syscall)
        self.assertIn("frame->r10 != sizeof(duet_service_control_result_v1)", do_syscall)
        self.assertIn("const duet_service_control_request_v1 request_copy = *request", SOURCE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
