#!/usr/bin/env python3
"""Structural guards for the durable service exit reap ledger.

These checks pin the irreversible stage ordering, the exactly-once observer
receipt discipline, the absence of drop-on-retry patterns, the lock-versus-
external-call separation, and the public-token authority split.  They
complement — never substitute for — the hosted behavioural test
tests/host/test_service_exit_reap_ledger.cpp.
"""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/core/service_exit_reap_ledger.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/core/service_exit_reap_ledger.cpp").read_text(encoding="utf-8")
HOST_TEST = (ROOT / "tests/host/test_service_exit_reap_ledger.cpp").read_text(encoding="utf-8")


def body(begin: str, end: str) -> str:
    start = SOURCE.index(begin)
    return SOURCE[start : SOURCE.index(end, start)]


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


class ServiceExitReapLedgerContract(unittest.TestCase):
    def test_capacity_is_tied_to_the_observer(self) -> None:
        self.assertIn(
            "kServiceExitObserverCapacity * kServiceExitReapRowsPerObserverSlot",
            HEADER,
        )
        self.assertIn(
            "static_assert(kServiceExitReapLedgerCapacity >= kServiceExitObserverCapacity",
            HEADER,
        )
        self.assertIn("ServiceExitReapRow rows[kServiceExitReapLedgerCapacity]", HEADER)

    def test_stage_ladder_is_declared_in_irreversible_order(self) -> None:
        enum = HEADER[HEADER.index("enum class ServiceExitReapRowStage") :]
        enum = enum[: enum.index("};")]
        order = [
            "Free",
            "Acquired",
            "LifecycleCommitted",
            "DirectoryDraining",
            "DirectoryCommitted",
            "ReadyForDelivery",
            "Delivered",
        ]
        positions = [enum.index(stage) for stage in order]
        self.assertEqual(positions, sorted(positions))

    def test_no_heap_no_sleep_no_wall_clock(self) -> None:
        for forbidden in (
            "new ",
            "delete ",
            "malloc",
            "KMalloc",
            "KFree",
            "kheap",
            "std::vector",
            "Sleep(",
            "sleep(",
            "SchedYield",
            "WaitQueue",
            "TimeNow",
            "rdtsc",
        ):
            self.assertNotIn(forbidden, SOURCE)
            self.assertNotIn(forbidden, HEADER)
        # Timestamps enter as arguments; the module never reads a clock.
        self.assertIn("u64 now_ns", HEADER)

    def test_event_identity_is_separate_from_ack_authority(self) -> None:
        self.assertIn("struct ServiceExitReapEventKey", HEADER)
        self.assertIn("u64 event_sequence", HEADER)
        self.assertIn("u64 delivery_token", HEADER)
        acknowledge = body(
            "ServiceExitReapStatus ServiceExitReapLedgerAcknowledgeDelivery(",
            "ServiceExitReapOwnerExitResult ServiceExitReapLedgerNotifyDeliveryOwnerExit(",
        )
        self.assertIn("ServiceExitReapEventKey event", acknowledge)
        self.assertIn("RowMatchesEventKey(row, event)", acknowledge)
        self.assertIn("row.delivery_token != delivery_token", acknowledge)
        mint = body("u64 MintNonWrapping(", "void IncrementSaturating(")
        self.assertIn("return 0;", mint)
        self.assertIn("~static_cast<u64>(0)", mint)

    def test_observer_receipt_is_dequeued_exactly_once_and_requeued_only_pre_commit(self) -> None:
        self.assertEqual(SOURCE.count("ServiceExitObserverDequeue("), 1)
        self.assertEqual(SOURCE.count("ServiceExitObserverRequeue("), 1)
        rollback = body("ServiceExitReapRollbackResult ServiceExitReapLedgerRollbackAcquired(",
                        "namespace\n{\n\nstruct ReapPumpWorkItem")
        self.assertIn("ServiceExitObserverRequeue(", rollback)
        self.assertIn("row.stage != ServiceExitReapRowStage::Acquired", rollback)
        self.assertIn("ServiceExitReapStatus::WrongStage", rollback)
        # The requeue stage gate appears strictly before the requeue call.
        self.assertLess(rollback.index("row.stage != ServiceExitReapRowStage::Acquired"),
                        rollback.index("ServiceExitObserverRequeue("))

    def test_lifecycle_commit_is_called_once_and_never_after_settlement(self) -> None:
        self.assertEqual(SOURCE.count("ServiceLifecycleBrokerObserveExit("), 1)
        pump = body("ServiceExitReapPumpResult ServiceExitReapLedgerPump(",
                    "ServiceExitReapDeliveryResult ServiceExitReapLedgerDequeueForDelivery(")
        observe = pump.index("ServiceLifecycleBrokerObserveExit(")
        # The ObserveExit arm is entered only from the Acquired stage.
        gate = pump.rindex("ServiceExitReapRowStage::Acquired", 0, observe)
        self.assertLess(gate, observe)

    def test_directory_busy_retains_the_row_and_never_drops(self) -> None:
        pump = body("ServiceExitReapPumpResult ServiceExitReapLedgerPump(",
                    "ServiceExitReapDeliveryResult ServiceExitReapLedgerDequeueForDelivery(")
        self.assertEqual(pump.count("ServiceDirectoryOwnerCrashed("), 1)
        retryable = body("bool EndpointReleaseStatusIsRetryable(", "bool DirectoryOutcomeIsTerminal(")
        for status in ("Busy", "EndpointReleaseFailed", "NotInitialized"):
            self.assertIn(f"ServiceDirectoryStatus::{status}", retryable)
        for status in ("Busy", "ResourceReleaseFailed"):
            self.assertIn(f"ServiceEndpointStatus::{status}", retryable)
        self.assertIn("DirectoryOutcomeIsRetryable(closed.status, closed.endpoint_status)", pump)
        self.assertIn("ServiceExitReapRowStage::DirectoryDraining", pump)
        # No pump arm frees a row: rows are freed only by the exact ACK and
        # the explicit pre-commit rollback.
        self.assertNotIn("ClearRow", pump)
        self.assertEqual(SOURCE.count("--ledger->live_rows;"), 2)
        acknowledge = body("ServiceExitReapStatus ServiceExitReapLedgerAcknowledgeDelivery(",
                           "ServiceExitReapOwnerExitResult ServiceExitReapLedgerNotifyDeliveryOwnerExit(")
        self.assertIn("--ledger->live_rows;", acknowledge)
        rollback = body("ServiceExitReapRollbackResult ServiceExitReapLedgerRollbackAcquired(",
                        "namespace\n{\n\nstruct ReapPumpWorkItem")
        self.assertIn("--ledger->live_rows;", rollback)

    def test_status_disposition_pairs_are_semantically_canonical(self) -> None:
        canonical = body("bool LifecycleStatusIsRetryable(", "bool RowIsCanonical(")
        for validator in (
            "LifecycleSettlementIsCanonical",
            "DirectorySettlementIsCanonical",
            "ObserverAckSettlementIsCanonical",
        ):
            self.assertIn(validator, canonical)
        self.assertIn("ServiceLifecycleStatus::StaleGeneration", canonical)
        self.assertIn("ServiceDirectoryStatus::StaleKey", canonical)
        self.assertIn("ServiceExitObserverStatus::InvalidEventReceipt", canonical)
        row = body("bool RowIsCanonical(", "bool LedgerIsCanonicalLocked(")
        for validator in (
            "LifecycleSettlementIsCanonical(row)",
            "DirectorySettlementIsCanonical(row)",
            "ObserverAckSettlementIsCanonical(row)",
        ):
            self.assertIn(validator, row)

    def test_host_race_seams_are_exact_and_quiescent(self) -> None:
        for point in (
            "ObserverDequeueReturnedBeforeLedgerApply",
            "RollbackReservedBeforeObserverRequeue",
            "PumpSelectedBeforeExternalCall",
            "ObserverAckReturnedBeforeLedgerApply",
        ):
            self.assertIn(point, HEADER)
            self.assertIn(point, SOURCE)
            self.assertIn(point, HOST_TEST)
        for field in ("u32 row;", "u64 admission;", "ServiceExitReapRowStage stage;"):
            self.assertIn(field, HEADER)
        self.assertNotIn("std::mutex g_host_spinlock", HOST_TEST)
        self.assertIn("std::atomic_ref<u32> next_ticket", HOST_TEST)

    def test_no_lock_is_held_across_external_calls(self) -> None:
        externals = (
            "ServiceExitObserverDequeue(",
            "ServiceExitObserverRequeue(",
            "ServiceExitObserverAcknowledge(",
            "ServiceLifecycleBrokerObserveExit(",
            "ServiceDirectoryOwnerCrashed(",
        )
        # Every external call must sit at brace depth zero relative to every
        # SpinLockGuard scope: scan each function body and require that no
        # external call appears between a guard construction and the end of
        # its enclosing block.
        for external in externals:
            for match in re.finditer(re.escape(external), SOURCE):
                position = match.start()
                depth = 0
                guard_depths: list[int] = []
                for index in range(position):
                    ch = SOURCE[index]
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        while guard_depths and guard_depths[-1] > depth:
                            guard_depths.pop()
                    elif SOURCE.startswith("sync::SpinLockGuard", index):
                        guard_depths.append(depth)
                self.assertEqual(
                    guard_depths,
                    [],
                    f"{external} reachable while a SpinLockGuard scope is open at offset {position}",
                )

    def test_admission_refuses_before_observer_dequeue_when_full(self) -> None:
        acquire = body("ServiceExitReapAcquireResult ServiceExitReapLedgerAcquireFromObserver(",
                       "ServiceExitReapRollbackResult ServiceExitReapLedgerRollbackAcquired(")
        self.assertLess(acquire.index("CapacityExhausted"), acquire.index("ServiceExitObserverDequeue("))
        self.assertIn("SequenceExhausted", acquire)

    def test_directory_identity_is_carried_by_the_same_observer_event(self) -> None:
        acquire = body("ServiceExitReapAcquireResult ServiceExitReapLedgerAcquireFromObserver(",
                       "ServiceExitReapRollbackResult ServiceExitReapLedgerRollbackAcquired(")
        self.assertIn("row.directory_service = dequeued.event.directory_service", acquire)
        self.assertIn("row.directory_bound = 1", acquire)
        self.assertIn("ServiceKeyIsValid(event.directory_service)", SOURCE)
        self.assertIn("row.directory_service == row.event.directory_service", SOURCE)
        self.assertNotIn("ServiceExitReapDirectoryBinding", HEADER + SOURCE + HOST_TEST)
        self.assertNotIn("ServiceExitReapDirectoryDisposition::Unbound", HEADER + SOURCE + HOST_TEST)
        for token in (
            "same reservation before it is consumed",
            "slot is recycled before the reap pump",
            "replacement.directory_key.generation",
            "ServiceExitReapDirectoryDisposition::SettledAbsent",
        ):
            self.assertIn(token, HOST_TEST)

    def test_token_is_reserved_before_observer_ack_and_fails_closed(self) -> None:
        pump = body("ServiceExitReapPumpResult ServiceExitReapLedgerPump(",
                    "ServiceExitReapDeliveryResult ServiceExitReapLedgerDequeueForDelivery(")
        self.assertEqual(pump.count("MintNonWrapping(&g_next_reap_delivery_token)"), 1)
        self.assertIn("TokenSpaceExhausted", pump)
        self.assertLess(
            pump.index("row.delivery_token = token"),
            pump.index("ServiceExitObserverAcknowledge(observer, &receipt)"),
        )
        self.assertLess(
            pump.index("acked != ServiceExitObserverStatus::Ok"),
            pump.index("row.stage = ServiceExitReapRowStage::ReadyForDelivery"),
        )
        deliver = body("ServiceExitReapDeliveryResult ServiceExitReapLedgerDequeueForDelivery(",
                       "ServiceExitReapStatus ServiceExitReapLedgerAcknowledgeDelivery(")
        self.assertNotIn("MintNonWrapping", deliver)
        owner_exit = body("ServiceExitReapOwnerExitResult ServiceExitReapLedgerNotifyDeliveryOwnerExit(",
                          "ServiceExitReapRestageResult ServiceExitReapLedgerQueryRestageExact(")
        self.assertNotIn("MintNonWrapping", owner_exit)
        self.assertIn("row.delivery_owner = kInvalidProcessKey", owner_exit)
        self.assertIn("ServiceExitReapRowStage::ReadyForDelivery", owner_exit)

    def test_zero_step_pump_still_validates_state(self) -> None:
        pump = body("ServiceExitReapPumpResult ServiceExitReapLedgerPump(",
                    "ServiceExitReapDeliveryResult ServiceExitReapLedgerDequeueForDelivery(")
        loop = pump.index("for (u32 step = 0; step < max_steps; ++step)")
        self.assertLess(pump.index("ReadyLedgerLocked(*ledger)"), loop)
        self.assertLess(pump.index("LedgerIsCanonicalLocked(*ledger)"), loop)
        self.assertIn("ServiceExitReapLedgerPump(&ledger, &broker, &directory, &observer, 0, 0)", HOST_TEST)

    def test_acknowledge_fails_closed_and_frees_only_the_exact_row(self) -> None:
        acknowledge = body("ServiceExitReapStatus ServiceExitReapLedgerAcknowledgeDelivery(",
                           "ServiceExitReapOwnerExitResult ServiceExitReapLedgerNotifyDeliveryOwnerExit(")
        self.assertIn("ServiceExitReapStatus::StaleToken", acknowledge)
        self.assertIn("ServiceExitReapStatus::StaleEvent", acknowledge)
        self.assertIn("ServiceExitReapStatus::WrongStage", acknowledge)
        self.assertIn("ServiceExitReapStatus::ForeignAcknowledger", acknowledge)
        self.assertLess(acknowledge.index("WrongStage"), acknowledge.index("ForeignAcknowledger"))
        self.assertLess(acknowledge.index("ForeignAcknowledger"), acknowledge.index("ClearRow"))

    def test_close_refuses_live_rows(self) -> None:
        close = body("ServiceExitReapStatus ServiceExitReapLedgerClose(",
                     "ServiceExitReapAcquireResult ServiceExitReapLedgerAcquireFromObserver(")
        self.assertIn("ServiceExitReapStatus::RowsLive", close)
        self.assertNotIn("ClearRow", close)

    def test_restage_is_exact_and_independent_of_delivery_ack(self) -> None:
        restage = body("ServiceExitReapRestageResult ServiceExitReapLedgerQueryRestageExact(",
                       "ServiceExitReapStatus ServiceExitReapLedgerInspect(")
        self.assertIn("RowMatchesEventKey(row, event)", restage)
        self.assertIn("RowHasAuthoritativeRestageSettlement(row)", restage)
        self.assertIn("ledger->acquisitions_inflight", restage)
        self.assertIn("kServiceExitReapRowsPerObserverSlot", restage)
        self.assertNotIn("delivery_token", strip_comments(restage))
        self.assertIn("ServiceExitReapStatus::NotFound", restage)

    def test_canonical_validation_is_applied_to_authority_paths(self) -> None:
        for begin, end in (
            (
                "ServiceExitReapRollbackResult ServiceExitReapLedgerRollbackAcquired(",
                "namespace\n{\n\nstruct ReapPumpWorkItem",
            ),
            (
                "ServiceExitReapStatus ServiceExitReapLedgerAcknowledgeDelivery(",
                "ServiceExitReapOwnerExitResult ServiceExitReapLedgerNotifyDeliveryOwnerExit(",
            ),
            (
                "ServiceExitReapOwnerExitResult ServiceExitReapLedgerNotifyDeliveryOwnerExit(",
                "ServiceExitReapRestageResult ServiceExitReapLedgerQueryRestageExact(",
            ),
            (
                "ServiceExitReapRestageResult ServiceExitReapLedgerQueryRestageExact(",
                "ServiceExitReapStatus ServiceExitReapLedgerInspect(",
            ),
        ):
            self.assertIn("LedgerIsCanonicalLocked(*ledger)", body(begin, end))

    def test_hosted_test_exercises_the_required_scenarios(self) -> None:
        for scenario in (
            "ServiceExitReapLedgerRollbackAcquired",
            "ServiceExitReapLedgerNotifyDeliveryOwnerExit",
            "ServiceExitReapStatus::ForeignAcknowledger",
            "ServiceExitReapStatus::WrongStage",
            "ServiceExitReapStatus::StaleToken",
            "ServiceExitReapStatus::StaleEvent",
            "ServiceExitReapStatus::CapacityExhausted",
            "ServiceExitReapStatus::RowsLive",
            "ServiceExitReapStatus::TokenSpaceExhausted",
            "ServiceExitReapLedgerHostSetNextDeliveryTokenForTest",
            "ServiceExitReapLedgerHostSetHook",
            "ServiceExitReapLedgerQueryRestageExact",
            "ServiceExitReapObserverAckDisposition::Refused",
            "ServiceExitReapDirectoryDisposition::SettledAbsent",
            "ServiceDirectoryLookup",
            "ServiceDirectoryOwnerCrashed",
            "ServiceLifecycleBrokerCommitDirectoryPublication",
            "ServiceExitObserverPublishExit",
            "std::thread",
        ):
            self.assertIn(scenario, HOST_TEST)


if __name__ == "__main__":
    unittest.main()
