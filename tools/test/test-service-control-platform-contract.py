#!/usr/bin/env python3
"""Freeze the typed service-control production adapter trust boundary."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/core/service_control_platform.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/core/service_control_platform.cpp").read_text(encoding="utf-8")
INGRESS = (ROOT / "kernel/syscall/service_control_ingress.cpp").read_text(encoding="utf-8")
PUBLIC = (ROOT / "userland/libc/include/duet/service_control.h").read_text(encoding="utf-8")


def body(start: str, end: str) -> str:
    begin = SOURCE.index(start)
    finish = SOURCE.index(end, begin)
    return SOURCE[begin:finish]


class ServiceControlPlatformContract(unittest.TestCase):
    def test_initialization_is_complete_one_shot_and_dormant(self) -> None:
        init = body("ServiceControlPlatformInitializeResultV1 InitializePlatform(",
                    "#if !defined(DUETOS_HOST_TEST)",)
        self.assertIn("BeginInitialize(platform)", init)
        self.assertIn("runtime_inspect", init)
        self.assertIn("bind_authority", init)
        self.assertIn("broker_describe", init)
        self.assertIn("ledger_inspect", init)
        self.assertIn("live_inspect", init)
        self.assertIn("StateStore(platform, ServiceControlPlatformAdapterStateV1::Open)", init)
        self.assertIn("operations->install_ingress", init)
        self.assertNotIn("operations->activate", init)
        for callback in ("ActivateCallback", "StopCallback", "RestageCallback", "ExitDequeueCallback",
                         "ExitAckCallback"):
            self.assertIn(f"&{callback}", init)

    def test_callbacks_rebind_authority_without_adapter_lock(self) -> None:
        resolve = body("ServiceControlPlatformStatusV1 ResolveFreshAuthority(",
                       "bool TargetBaseIsValid(")
        self.assertIn("runtime_inspect", resolve)
        self.assertIn("bind_authority", resolve)
        self.assertIn("broker_describe", resolve)
        self.assertIn("AuthorityEquals(fresh.authority, platform->authority)", resolve)
        self.assertIn("AuthorityEquals(fresh.authority, *supplied)", resolve)
        self.assertNotRegex(HEADER + SOURCE, r"SpinLock|std::mutex|LockGuard")

    def test_production_wiring_uses_exact_real_owners(self) -> None:
        required = (
            "ServiceBootstrapActivateV1(request)",
            "ServiceLifecycleBrokerRequestStop(",
            "SchedFindProcessByKeyRetained(process)",
            "SchedKillByProcess(retained.Get())",
            "ServiceBootstrapStageFindServiceV1(",
            "ServiceBootstrapLiveRestageV1(",
            "ServiceExitReapLedgerDequeueForDelivery(",
            "ServiceExitReapLedgerQueryRestageExact(",
            "ServiceExitReapLedgerAcknowledgeDelivery(",
            "ServiceControlIngressInstallKernelPlatformV1(platform)",
        )
        for symbol in required:
            self.assertIn(symbol, SOURCE)

    def test_restage_and_ack_preserve_independent_exact_values(self) -> None:
        restage = body("ServiceControlPlatformStatusV1 RestageCallback(",
                       "bool DeliveryRecordIsCanonical(")
        acknowledge = body("ServiceControlPlatformStatusV1 ExitAckCallback(",
                            "ServiceControlPlatformInitializeResultV1 InitializePlatform(")
        self.assertIn("TargetEventKey(target)", restage)
        self.assertIn("restage_query_exact", restage)
        self.assertIn("TeardownComplete", restage)
        self.assertIn("TargetEventKey(target)", acknowledge)
        self.assertIn("acknowledgement_token == 0", acknowledge)
        self.assertIn("exit_acknowledge_exact", acknowledge)
        self.assertIn("uint64_t operation_token", PUBLIC)
        self.assertIn("uint64_t event_sequence", PUBLIC)
        self.assertIn("uint64_t reserved[1]", PUBLIC)
        self.assertIn("RequestProcess(request), request.event_sequence", INGRESS)
        self.assertRegex(
            INGRESS,
            re.compile(r"DUET_SERVICE_CONTROL_OP_RESTAGE:.*?operation_token == 0.*?event_sequence != 0", re.S),
        )
        self.assertRegex(
            INGRESS,
            re.compile(r"DUET_SERVICE_CONTROL_OP_EXIT_ACK:.*?operation_token != 0.*?event_sequence != 0", re.S),
        )

    def test_no_user_pointer_or_fabricated_success_authority(self) -> None:
        target = re.search(r"struct ServiceControlPlatformTargetV1\s*\{(?P<body>.*?)\};",
                           (ROOT / "kernel/syscall/service_control_ingress.h").read_text(encoding="utf-8"), re.S)
        self.assertIsNotNone(target)
        self.assertNotIn("*", target.group("body"))
        stop = body("ServiceControlPlatformStatusV1 StopCallback(",
                    "ServiceControlPlatformStatusV1 RestageCallback(")
        self.assertIn("request_stop", stop)
        self.assertIn("kill_exact_process", stop)
        self.assertIn("ServiceControlPlatformKillExactResultV1::Rejected", stop)
        self.assertIn("MapRuntimeFailure", SOURCE)
        self.assertIn("MapLifecycleFailure", SOURCE)
        self.assertIn("MapStageFailure", SOURCE)
        self.assertIn("restaged.previous_active_bank == restaged.active_bank", SOURCE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
