#!/usr/bin/env python3
"""Structural guards for the authenticated service request lifecycle."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE_HEADER = (ROOT / "kernel/ipc/channel_core.h").read_text(encoding="utf-8")
CORE_SOURCE = (ROOT / "kernel/ipc/channel_core.cpp").read_text(encoding="utf-8")
ENDPOINT_HEADER = (ROOT / "kernel/core/service_endpoint.h").read_text(encoding="utf-8")
ENDPOINT_SOURCE = (ROOT / "kernel/core/service_endpoint.cpp").read_text(encoding="utf-8")
CORE_TEST = (ROOT / "tests/host/test_channel_core.cpp").read_text(encoding="utf-8")
ENDPOINT_TEST = (ROOT / "tests/host/test_service_endpoint.cpp").read_text(encoding="utf-8")


def body_between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin + len(start))]


def assert_order(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = 0
    for token in tokens:
        found = source.find(token, cursor)
        test.assertGreaterEqual(found, 0, token)
        cursor = found + len(token)


class ServiceEndpointRequestLifecycleContract(unittest.TestCase):
    def test_channel_core_exposes_every_pinned_transition(self) -> None:
        for token in (
            "ChannelCoreRequestCommitResult",
            "ChannelCoreRequestTransitionResult",
            "ChannelCoreCommitRequest(",
            "ChannelCoreCancelRequest(",
            "ChannelCoreCompleteRequest(",
            "EndpointRequestCompletionAuthority completion_authority;",
        ):
            self.assertIn(token, CORE_HEADER)

    def test_operation_pin_is_bound_to_exact_endpoint_role(self) -> None:
        for token in (
            "ChannelCoreOperationBinding binding;",
            "slot.binding != pin.binding",
            "slot.binding = binding",
            "slot.binding = kInvalidChannelCoreOperationBinding",
        ):
            self.assertIn(token, CORE_HEADER + CORE_SOURCE)
        self.assertIn("operation.core_pin.binding == ServiceEndpointOperationBinding(operation.identity.role)",
                      ENDPOINT_HEADER)
        acquire = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointOperationResult ServiceEndpointAcquireOperation(",
            "ServiceEndpointDirectionResult ServiceEndpointBorrowDirection(",
        )
        self.assertIn("ServiceEndpointOperationBinding(identity.role)", acquire)

    def test_channel_transitions_validate_canonical_core_and_exact_pin(self) -> None:
        regions = (
            body_between(CORE_SOURCE, "ChannelCoreRequestCommitResult ChannelCoreCommitRequest(",
                         "ChannelCoreRequestTransitionResult ChannelCoreCancelRequest("),
            body_between(CORE_SOURCE, "ChannelCoreRequestTransitionResult ChannelCoreCancelRequest(",
                         "ChannelCoreRequestTransitionResult ChannelCoreCompleteRequest("),
            body_between(CORE_SOURCE, "ChannelCoreRequestTransitionResult ChannelCoreCompleteRequest(",
                         "namespace\n{"),
        )
        ledger_calls = (
            "EndpointRequestLedgerCommit",
            "EndpointRequestLedgerCancel",
            "EndpointRequestLedgerComplete",
        )
        for region, ledger_call in zip(regions, ledger_calls, strict=True):
            assert_order(self, region, "CoreGuard guard", "CoreIsCanonical", "ValidatePinLocked", ledger_call)
            self.assertIn("ChannelCoreDirectionIndex(direction)", region)
            for forbidden in ("KObject", "HandleTable", "sink.", "callback"):
                self.assertNotIn(forbidden, region)

    def test_commit_mints_authority_only_on_ledger_success(self) -> None:
        commit = body_between(
            CORE_SOURCE,
            "ChannelCoreRequestCommitResult ChannelCoreCommitRequest(",
            "ChannelCoreRequestTransitionResult ChannelCoreCancelRequest(",
        )
        assert_order(
            self,
            commit,
            "EndpointRequestLedgerCommit",
            "committed.status == EndpointRequestLedgerStatus::Ok",
            "committed.completion_authority",
        )
        self.assertIn("kInvalidEndpointRequestCompletionAuthority", CORE_SOURCE)

    def test_endpoint_api_constrains_roles_instead_of_trusting_wire_direction(self) -> None:
        reserve = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestReserveResult ServiceEndpointReserveRequest(const ServiceEndpointOperation* operation,\n"
            "                                                                  u64 request_id)",
            "ServiceEndpointRequestReserveResult ServiceEndpointReserveRequest(const ServiceEndpointOperation* operation,\n"
            "                                                                  ServiceEndpointTrafficDirection direction",
        )
        commit = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestCommitResult ServiceEndpointCommitReceivedRequest(",
            "ServiceEndpointRequestTransitionResult ServiceEndpointRejectReceivedRequest(",
        )
        reject = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestTransitionResult ServiceEndpointRejectReceivedRequest(",
            "ServiceEndpointRequestTransitionResult ServiceEndpointCancelSentRequest(",
        )
        cancel = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestTransitionResult ServiceEndpointCancelSentRequest(",
            "ServiceEndpointRequestTransitionResult ServiceEndpointCompleteReceivedRequest(",
        )
        complete = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestTransitionResult ServiceEndpointCompleteReceivedRequest(",
            "ServiceEndpointStatus ServiceEndpointReleaseOperation(",
        )
        self.assertIn("ServiceEndpointTrafficDirection::Send", reserve)
        self.assertIn("ServiceEndpointTrafficDirection::Receive", commit)
        self.assertIn("ServiceEndpointTrafficDirection::Receive", reject)
        self.assertIn("ServiceEndpointTrafficDirection::Send", cancel)
        self.assertIn("ServiceEndpointTrafficDirection::Receive", complete)

    def test_compatibility_overload_refuses_receive_reservation(self) -> None:
        compatibility = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestReserveResult ServiceEndpointReserveRequest(const ServiceEndpointOperation* operation,\n"
            "                                                                  ServiceEndpointTrafficDirection direction",
            "ServiceEndpointRequestCommitResult ServiceEndpointCommitReceivedRequest(",
        )
        assert_order(
            self,
            compatibility,
            "direction != ServiceEndpointTrafficDirection::Send",
            "ServiceEndpointStatus::InvalidArgument",
            "return ServiceEndpointReserveRequest(operation, request_id)",
        )

    def test_normal_ledger_rejection_is_not_reported_as_core_corruption(self) -> None:
        mapping = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointStatus RequestChannelFailureStatus(",
            "ServiceEndpointInspectResult InspectFailure(",
        )
        self.assertIn("ipc::ChannelCoreStatus::LedgerFailure", mapping)
        self.assertIn("ServiceEndpointStatus::RequestRejected", mapping)
        self.assertIn("return \"request-rejected\"", ENDPOINT_SOURCE)

    def test_operation_acquire_maps_expected_bounded_failures(self) -> None:
        mapping = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointStatus OperationAcquireFailureStatus(",
            "ServiceEndpointInspectResult InspectFailure(",
        )
        for channel_status, endpoint_status in (
            ("Draining", "Closing"),
            ("Drained", "Drained"),
            ("Busy", "Busy"),
            ("OperationIdentityExhausted", "CapacityExhausted"),
        ):
            self.assertIn(f"ipc::ChannelCoreStatus::{channel_status}", mapping)
            self.assertIn(f"ServiceEndpointStatus::{endpoint_status}", mapping)

    def test_invalid_request_cleanup_does_not_orphan_detached_resources(self) -> None:
        drain = body_between(ENDPOINT_SOURCE, "ServiceEndpointStatus DriveDrain(",
                             "void DestroyEndpointObject(")
        assert_order(
            self,
            drain,
            "request_cleanup_failed = slot->request_cleanup_failed",
            "detached = drained.detached",
            "DeliverRequestCleanup",
            "ChannelCoreReleaseDetachedCleanup(&detached)",
            "slot->request_cleanup_failed = slot->request_cleanup_failed || request_cleanup_failed",
            "slot->detached_cleanup = detached",
        )
        self.assertIn("leaving the endpoint slot quarantined", drain)
        self.assertIn("request_cleanup_failed", ENDPOINT_HEADER)

    def test_cancel_and_complete_invalidate_only_after_success(self) -> None:
        reject = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestTransitionResult ServiceEndpointRejectReceivedRequest(",
            "ServiceEndpointRequestTransitionResult ServiceEndpointCancelSentRequest(",
        )
        cancel = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestTransitionResult ServiceEndpointCancelSentRequest(",
            "ServiceEndpointRequestTransitionResult ServiceEndpointCompleteReceivedRequest(",
        )
        complete = body_between(
            ENDPOINT_SOURCE,
            "ServiceEndpointRequestTransitionResult ServiceEndpointCompleteReceivedRequest(",
            "ServiceEndpointStatus ServiceEndpointReleaseOperation(",
        )
        for transition in (reject, cancel):
            assert_order(
                self,
                transition,
                "ChannelCoreCancelRequest",
                "cancelled.status != ipc::ChannelCoreStatus::Ok",
                "*request_key = ipc::kInvalidEndpointRequestKey",
            )
        assert_order(
            self,
            complete,
            "ChannelCoreCompleteRequest",
            "completed.status != ipc::ChannelCoreStatus::Ok",
            "*completion_authority = ipc::kInvalidEndpointRequestCompletionAuthority",
        )

    def test_hostile_tests_cover_direction_replay_stale_pin_and_drain(self) -> None:
        for token in (
            "Direction swaps",
            "EndpointRequestLedgerStatus::StaleIdentity",
            "EndpointRequestLedgerStatus::ReplayRejected",
            "ChannelCoreStatus::StaleOperation",
            "request_cleanup[0].detached_count, 1U",
        ):
            self.assertIn(token, CORE_TEST + ENDPOINT_TEST)
        self.assertIn("The sender cannot commit its own outgoing request", ENDPOINT_TEST)
        self.assertIn("ServiceEndpointTrafficDirection::Receive, 1", ENDPOINT_TEST)
        for token in (
            "cannot be spliced",
            "ordinary backpressure",
            "Acceptor sends, Initiator receives/commits",
            "already-detached ports/tables/charge",
        ):
            self.assertIn(token, ENDPOINT_TEST)


if __name__ == "__main__":
    unittest.main(verbosity=2)
