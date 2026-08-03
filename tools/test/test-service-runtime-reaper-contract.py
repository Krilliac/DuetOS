#!/usr/bin/env python3
"""Structural contract for scheduler-owned service-runtime maintenance."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCHED = (ROOT / "kernel/sched/sched.cpp").read_text(encoding="utf-8")
RUNTIME = (ROOT / "kernel/core/service_runtime.h").read_text(encoding="utf-8")


def braced_body(source: str, marker: str) -> str:
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated body for {marker}")


def require_order(body: str, *tokens: str) -> None:
    cursor = 0
    for token in tokens:
        found = body.find(token, cursor)
        if found < 0:
            raise AssertionError(f"missing or out-of-order token: {token}")
        cursor = found + len(token)


class ServiceRuntimeReaperContract(unittest.TestCase):
    def test_runtime_exports_both_bounded_kernel_drivers(self) -> None:
        self.assertIn("ServiceRuntimeDriveDeferredAcceptedKernelV1()", RUNTIME)
        self.assertIn("ServiceRuntimeDriveExitReapKernelV1(u64 now_ns)", RUNTIME)
        self.assertIn("kServiceRuntimeExitReapAcquireBudgetV1 = 1", RUNTIME)
        self.assertIn("kServiceRuntimeExitReapPumpStepBudgetV1 = 4", RUNTIME)

    def test_maintenance_drives_endpoints_then_reap_with_one_clock_epoch(self) -> None:
        helper = braced_body(SCHED, "bool DriveServiceRuntimeMaintenance()")
        require_order(
            helper,
            "ServiceRuntimeDriveDeferredAcceptedKernelV1",
            "ServiceDirectoryStatus::Busy",
            "ServiceRuntimeDriveExitReapKernelV1(time::MonotonicNs())",
            "ServiceExitReapStatus::CapacityExhausted",
            "exit_reap.pump.status",
            "exit_reap.pump.rows_pending",
        )
        self.assertNotIn("SpinLockAcquire", helper)
        self.assertNotIn("SchedSleep", helper)
        self.assertNotIn("live_rows", helper)

    def test_acquisition_outcomes_are_exact_and_fail_closed(self) -> None:
        helper = braced_body(SCHED, "bool DriveServiceRuntimeMaintenance()")
        for token in (
            "ServiceExitReapStatus::Ok",
            "ServiceExitObserverStatus::Ok",
            "ServiceExitReapStatus::NoEvent",
            "ServiceExitObserverStatus::NoEvent",
            "ServiceExitReapStatus::CapacityExhausted",
            "exit-reap acquisition failed closed",
            "exit-reap pump failed closed",
        ):
            self.assertIn(token, helper)

        capacity = braced_body(
            helper,
            "else if (exit_reap.acquire_status == core::ServiceExitReapStatus::CapacityExhausted)",
        )
        self.assertIn("exit_reap.observer_status != core::ServiceExitObserverStatus::Ok", capacity)
        self.assertIn("full exit-reap ledger returned inconsistent observer status", capacity)

    def test_reaper_retries_without_holding_scheduler_lock(self) -> None:
        reaper = braced_body(SCHED, "[[noreturn]] void ReaperMain")
        require_order(
            reaper,
            "arch::Sti()",
            "DriveServiceRuntimeMaintenance()",
            "SpinLockAcquire(g_sched_lock)",
            "if (service_runtime_work_pending)",
            "SpinLockRelease(g_sched_lock",
            "SchedSleepTicks(1)",
            "WaitQueueBlockCurrentLocked(&g_reaper_wq)",
        )


if __name__ == "__main__":
    unittest.main()
