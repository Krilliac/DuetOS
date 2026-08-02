#!/usr/bin/env python3
"""Structural guards for exact publication-reserved service exit events."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/core/service_exit_observer.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/core/service_exit_observer.cpp").read_text(encoding="utf-8")
HOST_TEST = (ROOT / "tests/host/test_service_exit_observer.cpp").read_text(encoding="utf-8")


def body(begin: str, end: str) -> str:
    start = SOURCE.index(begin)
    return SOURCE[start : SOURCE.index(end, start)]


class ServiceExitObserverContract(unittest.TestCase):
    def test_fixed_capacity_and_exact_authority_are_frozen(self) -> None:
        for token in (
            "kServiceExitObserverCapacity = kServiceLifecycleCapacity",
            "u64 observer_epoch;",
            "u32 slot;",
            "u32 generation;",
            "ServiceLifecycleStartTicket start;",
            "ProcessKey process;",
            "ServiceExitObserverSlot slots[kServiceExitObserverCapacity]",
        ):
            self.assertIn(token, HEADER)
        self.assertIn("registration.observer_epoch == observer->observer_epoch", SOURCE)
        self.assertIn("slot.generation == registration.generation", SOURCE)
        self.assertIn("slot.start == registration.start", SOURCE)

    def test_reserve_precedes_bind_and_generation_never_wraps(self) -> None:
        reserve = body("ServiceExitReservationResult ServiceExitObserverReserve(",
                       "ServiceExitObserverStatus ServiceExitObserverBindAtSchedulerPublication(")
        self.assertLess(reserve.index("++slot.generation"), reserve.index("ServiceExitObserverSlotState::Reserved"))
        self.assertIn("candidate.generation < kServiceExitObserverGenerationMaximum", reserve)
        self.assertIn("DuplicateRegistration", reserve)
        release = body("void ReleaseSlot(", "void ClearObserver(")
        self.assertIn("ServiceExitObserverSlotState::Retired", release)
        self.assertNotIn("slot->generation = 0", release)

    def test_publication_bind_is_scalar_and_failure_atomic(self) -> None:
        bind = body("ServiceExitObserverStatus ServiceExitObserverBindAtSchedulerPublication(",
                    "ServiceExitObserverStatus ServiceExitObserverAbort(")
        self.assertLess(bind.index("RegistrationMatches"), bind.index("slot.process = process"))
        self.assertLess(bind.index("DuplicateProcess"), bind.index("slot.process = process"))
        self.assertIn("slot.state = ServiceExitObserverSlotState::Bound", bind)
        for forbidden in ("SchedCreate(", "SchedYield(", "KMalloc(", "KFree(", "KObjectRelease(",
                          "ServiceLifecycleBrokerCommit"):
            self.assertNotIn(forbidden, bind)

        rollback = body("ServiceExitObserverStatus ServiceExitObserverRollbackBound(",
                        "ServiceExitObserverStatus ServiceExitObserverPublishExit(")
        self.assertIn("slot.state != ServiceExitObserverSlotState::Bound", rollback)
        self.assertIn("slot.process != process", rollback)
        self.assertIn("ReleaseSlot(&slot)", rollback)
        self.assertIn("--observer->active_count", rollback)
        self.assertNotIn("ExitPending", rollback)
        self.assertNotIn("PublishSequenceLocked", rollback)

    def test_exit_delivery_is_one_shot_and_acknowledged(self) -> None:
        publish = body("ServiceExitObserverStatus ServiceExitObserverPublishExit(",
                       "ServiceExitDequeueResult ServiceExitObserverDequeue(")
        self.assertLess(publish.index("slot.exit_code = exit_code"),
                        publish.index("slot.state = ServiceExitObserverSlotState::ExitPending"))
        self.assertLess(publish.index("ServiceExitObserverSlotState::ExitPending"),
                        publish.index("PublishSequenceLocked(observer)"))
        self.assertIn("ExitAlreadyPublished", publish)

        dequeue = body("ServiceExitDequeueResult ServiceExitObserverDequeue(",
                       "ServiceExitObserverStatus ServiceExitObserverAcknowledge(")
        self.assertIn("slot.state = ServiceExitObserverSlotState::Delivered", dequeue)
        self.assertIn("ServiceLifecycleInstanceToken{slot.start", dequeue)
        acknowledge = body("ServiceExitObserverStatus ServiceExitObserverAcknowledge(",
                           "ServiceExitObserverStatus ServiceExitObserverRequeue(")
        self.assertIn("ServiceExitObserverSlotState::Delivered", acknowledge)
        self.assertIn("ReleaseSlot(&slot)", acknowledge)
        requeue = body("ServiceExitObserverStatus ServiceExitObserverRequeue(",
                       "ServiceExitObserverStatus ServiceExitObserverBeginDrain(")
        self.assertIn("slot.state = ServiceExitObserverSlotState::ExitPending", requeue)
        self.assertIn("PublishSequenceLocked(observer)", requeue)

    def test_kernel_install_is_one_static_lifetime_pointer(self) -> None:
        install = body("ServiceExitObserverStatus ServiceExitObserverInstallKernelObserver(",
                       "ServiceExitObserverStatus ServiceExitObserverPublishKernelProcessExit(")
        self.assertIn("__atomic_compare_exchange_n(&g_kernel_observer", install)
        self.assertIn("ServiceExitObserverState::Open", install)
        publish = body("ServiceExitObserverStatus ServiceExitObserverPublishKernelProcessExit(", "#else")
        self.assertIn("__atomic_load_n(&g_kernel_observer, __ATOMIC_ACQUIRE)", publish)
        self.assertIn("ServiceExitObserverPublishExit", publish)

    def test_hostile_test_covers_fast_exit_retry_capacity_and_contention(self) -> None:
        for token in (
            "A Process may exit immediately after the publication gate",
            "lifecycle commit rejects after observer binding",
            "ServiceExitObserverRollbackBound",
            "ServiceExitObserverRequeue",
            "kServiceExitObserverGenerationMaximum - 1",
            "CapacityExhausted",
            "constexpr u32 kWorkers = 32",
            "ServiceExitObserverBeginDrain",
            "ServiceExitObserverFinishDrain",
        ):
            self.assertIn(token, HOST_TEST)


if __name__ == "__main__":
    unittest.main()
