#!/usr/bin/env python3
"""Structural guards for directional endpoint-ledger identity and reuse."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
LEDGER_HEADER = (ROOT / "kernel/ipc/endpoint_request_ledger.h").read_text(encoding="utf-8")
LEDGER_SOURCE = (ROOT / "kernel/ipc/endpoint_request_ledger.cpp").read_text(encoding="utf-8")
CHANNEL_SOURCE = (ROOT / "kernel/ipc/channel_core.cpp").read_text(encoding="utf-8")
HOST_TEST = (ROOT / "tests/host/test_endpoint_request_ledger.cpp").read_text(encoding="utf-8")


def body_between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin + len(start))]


class EndpointRequestLedgerIdentityContract(unittest.TestCase):
    def test_keys_bind_epoch_and_direction(self) -> None:
        for token in (
            "enum class EndpointRequestDirection : u64",
            "struct EndpointRequestLedgerIdentity",
            "EndpointRequestLedgerIdentity ledger_identity;",
            "EndpointRequestDirectionIsValid(identity.direction)",
            "lhs.ledger_identity == rhs.ledger_identity",
        ):
            self.assertIn(token, LEDGER_HEADER)

    def test_initialize_is_one_shot_and_reset_requires_newer_drained_identity(self) -> None:
        initialize = body_between(
            LEDGER_SOURCE,
            "EndpointRequestLedgerStatus EndpointRequestLedgerInitialize(",
            "EndpointRequestLedgerStatus EndpointRequestLedgerReset(",
        )
        reset = body_between(
            LEDGER_SOURCE,
            "EndpointRequestLedgerStatus EndpointRequestLedgerReset(",
            "bool EndpointRequestLedgerIsCanonical(",
        )
        self.assertIn("EndpointRequestLedgerIsCanonical(*ledger)", initialize)
        self.assertIn("ledger->state != EndpointRequestLedgerState::Uninitialized", initialize)
        self.assertNotIn("ClearLedger", initialize)
        for token in (
            "ledger->state != EndpointRequestLedgerState::Draining",
            "next_identity.direction != ledger->identity.direction",
            "ledger->identity.endpoint_epoch == kEndpointRequestEpochMaximum",
            "next_identity.endpoint_epoch <= ledger->identity.endpoint_epoch",
        ):
            self.assertIn(token, reset)

    def test_commit_and_drain_return_bounded_values(self) -> None:
        for token in (
            "struct [[nodiscard]] EndpointRequestCommitResult",
            "struct [[nodiscard]] EndpointRequestDrainResult",
            "EndpointRequestKey detached_keys[kEndpointRequestLedgerCapacity];",
            "EndpointRequestCommitResult EndpointRequestLedgerCommit(",
            "EndpointRequestDrainResult EndpointRequestLedgerDrain(",
        ):
            self.assertIn(token, LEDGER_HEADER)
        drain = body_between(
            LEDGER_SOURCE,
            "EndpointRequestDrainResult EndpointRequestLedgerDrain(",
            "const char* EndpointRequestLedgerStatusName(",
        )
        self.assertIn("result.detached_keys[result.detached_count++]", drain)
        self.assertIn("ledger->state = EndpointRequestLedgerState::Draining", drain)

    def test_channel_core_uses_one_nonwrapping_epoch_for_both_directions(self) -> None:
        for token in (
            "g_next_channel_epoch = allocated == kChannelEpochMaximum ? kChannelEpochInvalid : allocated + 1",
            "EndpointRequestDirection::InitiatorToAcceptor",
            "EndpointRequestDirection::AcceptorToInitiator",
            "EndpointRequestLedgerReset(",
            "EndpointRequestLedgerDrain(&ledgers[0])",
            "EndpointRequestLedgerDrain(&ledgers[1])",
        ):
            self.assertIn(token, CHANNEL_SOURCE)

    def test_host_proof_covers_alias_rejection_reset_and_exact_drain(self) -> None:
        for token in (
            "Equal request IDs in opposite directions",
            "Reset is the only reuse boundary",
            "actual_drain.detached_count",
            "250000",
            "Race Cancel against Complete",
        ):
            self.assertIn(token, HOST_TEST)


if __name__ == "__main__":
    unittest.main()
