#!/usr/bin/env python3
"""Structural contract for ProcessKey-aware accepted endpoint teardown."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DIRECTORY_H = (ROOT / "kernel/core/service_directory.h").read_text(encoding="utf-8")
DIRECTORY_CPP = (ROOT / "kernel/core/service_directory.cpp").read_text(encoding="utf-8")
RUNTIME_H = (ROOT / "kernel/core/service_runtime.h").read_text(encoding="utf-8")
RUNTIME_CPP = (ROOT / "kernel/core/service_runtime.cpp").read_text(encoding="utf-8")
PROCESS_CPP = (ROOT / "kernel/proc/process.cpp").read_text(encoding="utf-8")
SCHED_CPP = (ROOT / "kernel/sched/sched.cpp").read_text(encoding="utf-8")
HOST_TEST = (ROOT / "tests/host/test_service_process_endpoint_teardown.cpp").read_text(encoding="utf-8")


def braced_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated body: {signature}")


def require_order(source: str, *tokens: str) -> None:
    cursor = 0
    for token in tokens:
        found = source.find(token, cursor)
        if found < 0:
            raise AssertionError(f"missing ordered token: {token}")
        cursor = found + len(token)


class ServiceProcessEndpointTeardownContract(unittest.TestCase):
    def test_directory_transfer_is_process_exact_and_has_no_second_capacity_limit(self) -> None:
        self.assertIn("kServiceDirectoryProcessTeardownBatchCapacity = 4", DIRECTORY_H)
        self.assertIn(
            "kServiceDirectoryCapacity * kServiceDirectoryAcceptedCapacity",
            braced_body(DIRECTORY_H, "namespace duetos::core"),
        )
        accepted = braced_body(DIRECTORY_H, "struct ServiceDirectoryAcceptedChannel\n")
        self.assertIn("bool process_teardown_deferred", accepted)
        directory = braced_body(DIRECTORY_H, "struct ServiceDirectory\n")
        self.assertIn("u32 deferred_scan_hint", directory)
        result = braced_body(DIRECTORY_H, "struct [[nodiscard]] ServiceDirectoryDeferAcceptedProcessResult")
        for token in ("ServiceDirectoryStatus status", "u32 newly_deferred_channels", "u32 deferred_channels"):
            self.assertIn(token, result)
        self.assertRegex(
            DIRECTORY_H,
            re.compile(
                r"ServiceDirectoryDeferAcceptedProcess\(ServiceDirectory\* directory,\s*"
                r"ProcessKey server_process\);"
            ),
        )

    def test_directory_transfer_marks_every_exact_row_in_place_without_external_calls(self) -> None:
        transfer = braced_body(
            DIRECTORY_CPP,
            "ServiceDirectoryDeferAcceptedProcessResult ServiceDirectoryDeferAcceptedProcess",
        )
        require_order(
            transfer,
            "ProcessKeyIsValid(server_process)",
            "DirectoryGuard guard(*directory)",
            "accepted.server_process == server_process",
            "accepted.process_teardown_deferred = true",
            "++newly_deferred_channels",
            "++deferred_channels",
        )
        for forbidden in ("HandleTable", "KObjectRelease", "ServiceEndpointReleaseOwner", "ServiceDirectoryReleaseAcceptedChannel"):
            self.assertNotIn(forbidden, transfer)

    def test_directory_drive_is_rotating_bounded_and_releases_outside_lock(self) -> None:
        drive = braced_body(
            DIRECTORY_CPP,
            "ServiceDirectoryDriveDeferredAcceptedResult ServiceDirectoryDriveDeferredAccepted",
        )
        require_order(
            drive,
            "ServiceDirectoryAcceptedChannelKey batch",
            "DirectoryGuard guard(*directory)",
            "const u32 scan_start = directory->deferred_scan_hint",
            "scanned < kServiceDirectoryDeferredAcceptedCapacity",
            "batch_count < kServiceDirectoryProcessTeardownBatchCapacity",
            "accepted.process_teardown_deferred",
            "batch[batch_count++] = accepted.key",
            "directory->deferred_scan_hint",
            "ServiceDirectoryReleaseAcceptedChannel",
            "released.status == ServiceDirectoryStatus::Busy",
            "continue",
            "u32 pending_channels = 0",
            "accepted.process_teardown_deferred",
            "if (pending_channels != 0)",
            "ServiceDirectoryStatus::Busy",
        )
        self.assertIn("ServiceDirectoryStatus::StaleAcceptedChannel", drive)
        self.assertIn("failure_status = released.status", drive)
        self.assertNotIn("ServiceEndpointReleaseOwner", drive)
        self.assertNotIn("HandleTable", drive)

    def test_service_close_preserves_exact_deferred_rows(self) -> None:
        close = braced_body(DIRECTORY_CPP, "ServiceDirectoryCloseResult CloseEntry")
        require_order(
            close,
            "if (accepted.process_teardown_deferred)",
            "continue",
            "batch.channels[batch.count++].owner = accepted.owner",
            "ClearAcceptedLocked(accepted)",
        )

    def test_runtime_is_the_only_production_directory_root(self) -> None:
        self.assertIn("ServiceRuntimeDeferAcceptedProcessKernelV1(ProcessKey process)", RUNTIME_H)
        self.assertIn("ServiceRuntimeDriveDeferredAcceptedKernelV1()", RUNTIME_H)
        transfer = braced_body(
            RUNTIME_CPP,
            "ServiceRuntimeDeferAcceptedProcessResultV1 DeferAcceptedProcess(ServiceRuntimeV1* runtime",
        )
        require_order(transfer, "ServiceRuntimeInspectV1", "ServiceDirectoryDeferAcceptedProcess(&runtime->directory")
        drive = braced_body(
            RUNTIME_CPP,
            "ServiceRuntimeDriveDeferredAcceptedResultV1 DriveDeferredAccepted(ServiceRuntimeV1* runtime)",
        )
        require_order(drive, "ServiceRuntimeInspectV1", "ServiceDirectoryDriveDeferredAccepted(&runtime->directory")
        kernel_transfer = braced_body(
            RUNTIME_CPP,
            "ServiceRuntimeDeferAcceptedProcessResultV1 ServiceRuntimeDeferAcceptedProcessKernelV1",
        )
        require_order(
            kernel_transfer,
            "ServiceRuntimeKernelLookupV1(&status)",
            "DeferAcceptedProcessFailure(status",
            "DeferAcceptedProcess(runtime, process)",
        )
        self.assertIn("fall through to raw ServiceEndpoint handle release", kernel_transfer)
        # The full state classification lives in the shared lookup so every
        # kernel entry point fails closed off one snapshot.
        lookup = braced_body(RUNTIME_CPP, "static ServiceRuntimeV1* ServiceRuntimeKernelLookupV1")
        require_order(
            lookup,
            "RuntimeStateLoad(&g_kernel_service_runtime)",
            "ServiceRuntimeStateV1::Uninitialized",
            "ServiceRuntimeStateV1::Initializing",
            "ServiceRuntimeStateV1::Failed",
            "ServiceRuntimeStatusV1::CorruptState",
        )

    def test_process_cancels_ingress_and_transfers_owners_before_raw_drain(self) -> None:
        teardown = braced_body(PROCESS_CPP, "void TeardownProcessRuntimeResources")
        require_order(
            teardown,
            "const ProcessKey process_key = ProcessKeySnapshot(p)",
            "ServiceEndpointIngressCancelProcessKernel(process_key)",
            "TransferAcceptedServiceEndpointOwners(process_key)",
            "mm::AddressSpaceRelease(p->as)",
            "HandleTableDrain(p->kobj_handles)",
        )
        self.assertEqual(teardown.count("HandleTableDrain(p->kobj_handles)"), 1)

    def test_process_transfer_has_no_wait_retry_or_raw_release(self) -> None:
        helper = braced_body(PROCESS_CPP, "void TransferAcceptedServiceEndpointOwners")
        require_order(
            helper,
            "ServiceRuntimeDeferAcceptedProcessKernelV1",
            "deferred.runtime_status == ServiceRuntimeStatusV1::NotInitialized",
            "deferred.runtime_status != ServiceRuntimeStatusV1::Ok",
            "deferred.directory_status != ServiceDirectoryStatus::Ok",
        )
        for forbidden in ("for (;;)", "SchedYield", "SchedSleep", "HandleTableDrain", "KObjectRelease"):
            self.assertNotIn(forbidden, helper)

    def test_scheduler_reaper_drives_busy_rows_without_holding_scheduler_lock(self) -> None:
        helper = braced_body(SCHED_CPP, "bool DriveServiceRuntimeMaintenance()")
        require_order(
            helper,
            "ServiceRuntimeDriveDeferredAcceptedKernelV1",
            "ServiceRuntimeStatusV1::NotInitialized",
            "ServiceDirectoryStatus::Ok",
            "deferred.pending_channels != 0",
            "ServiceDirectoryStatus::Busy",
        )
        self.assertNotIn("SpinLockAcquire", helper)
        reaper = braced_body(SCHED_CPP, "[[noreturn]] void ReaperMain")
        require_order(
            reaper,
            "arch::Sti()",
            "DriveServiceRuntimeMaintenance()",
            "SpinLockAcquire(g_sched_lock)",
            "if (service_runtime_work_pending)",
            "SpinLockRelease(g_sched_lock, wait_flags)",
            "SchedSleepTicks(1)",
            "WaitQueueBlockCurrentLocked(&g_reaper_wq)",
        )

    def test_hostile_test_covers_stale_duplicate_suspend_and_fair_handoff(self) -> None:
        for token in (
            "++stale.identity",
            "duplicate.newly_deferred_channels, 0U",
            "concurrent service close cannot move",
            "HandleTableDrain(fixture->server_handles)",
            "ServiceEndpointAcquireOperation",
            "peer_woken",
            "resume_peer",
            "peer_receive.lease.port->readable.wait",
            "busy.pending_channels",
            "ServiceEndpointReleaseOperation",
            "peer_release_status",
            "completed.pending_channels, 0U",
            "kServiceDirectoryProcessTeardownBatchCapacity + 1U",
            "fixture->service.slot, 0U",
            "accepted[0].accepted.slot, 0U",
            "first.pending_channels, 2U",
            "second.pending_channels, 1U",
            "std::barrier",
            "left.newly_deferred_channels + right.newly_deferred_channels, 1U",
        ):
            self.assertIn(token, HOST_TEST)

    def test_hostile_test_proves_transfer_precedes_raw_handle_drain(self) -> None:
        require_order(
            HOST_TEST,
            "ServiceDirectoryDeferAcceptedProcess(&fixture->directory, fixture->server_process)",
            "HandleTableDrain(fixture->server_handles)",
            "ServiceDirectoryDriveDeferredAccepted(&fixture->directory)",
            "fixture->Cleanup()",
        )


if __name__ == "__main__":
    unittest.main()
