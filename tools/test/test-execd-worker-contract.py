#!/usr/bin/env python3
"""Structural contract for the bounded, generation-safe execd worker engine."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "userland/native-apps/execd/worker.h"
INTERNAL = ROOT / "userland/native-apps/execd/worker_internal.h"
CORE = ROOT / "userland/native-apps/execd/worker.c"
REQUESTS = ROOT / "userland/native-apps/execd/worker_request.c"
HOST_TEST = ROOT / "tests/host/test_execd_worker.cpp"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Mask comments and literals while preserving braces and line structure."""
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
    return "".join(masked)


def function_body(source: str, name: str) -> str:
    clean = code_only(source)
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", clean):
        opening = clean.find("{", match.end())
        semicolon = clean.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        depth = 0
        for position in range(opening, len(clean)):
            if clean[position] == "{":
                depth += 1
            elif clean[position] == "}":
                depth -= 1
                if depth == 0:
                    return clean[opening : position + 1]
    raise AssertionError(f"definition not found: {name}")


def struct_body(source: str, name: str) -> str:
    match = re.search(rf"typedef\s+struct\s+{re.escape(name)}\s*\{{(?P<body>.*?)\}}\s*{re.escape(name)}\s*;", source,
                      re.DOTALL)
    if match is None:
        raise AssertionError(f"struct not found: {name}")
    return match.group("body")


class ExecdWorkerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public = read(PUBLIC)
        cls.internal = read(INTERNAL)
        cls.core = read(CORE)
        cls.requests = read(REQUESTS)
        cls.host_test = read(HOST_TEST)
        cls.engine_code = code_only("\n".join((cls.public, cls.internal, cls.core, cls.requests)))

    def test_surface_is_fixed_capacity_and_allocation_free(self) -> None:
        self.assertIn("#define EXECD_WORKER_MAX_PEERS 16U", self.public)
        self.assertIn("#define EXECD_WORKER_MAX_REQUESTS 32U", self.public)
        self.assertIn("#define EXECD_WORKER_STORAGE_BYTES 32768U", self.public)
        self.assertIn("_Static_assert(sizeof(ExecdWorkerImpl) <= EXECD_WORKER_STORAGE_BYTES", self.internal)
        includes = re.findall(r"^\s*#include\s+(.+)$", self.public, re.MULTILINE)
        self.assertEqual(includes, ["<stdint.h>"])
        for forbidden in (
            r"\bmalloc\b",
            r"\bcalloc\b",
            r"\brealloc\b",
            r"\bfree\s*\(",
            r"\bKMalloc\b",
            r"\bKFree\b",
            r"\bCreateThread\b",
            r"\bpthread_",
            r"\bWaitFor",
        ):
            self.assertNotRegex(self.engine_code, forbidden)

    def test_authority_snapshots_are_pointer_free_and_canonicalized(self) -> None:
        for name in (
            "ExecdWorkerInstanceIdentity",
            "ExecdWorkerPeerIdentity",
            "ExecdWorkerSourceAuthority",
            "ExecdWorkerPlanAuthority",
            "ExecdWorkerParseRequest",
        ):
            self.assertNotIn("*", struct_body(self.public, name), name)
        for token in (
            "service_identity",
            "instance_generation",
            "published_endpoint_epoch",
            "credential",
            "channel_epoch",
            "immutable_policy_id",
            "sealed",
            "read_only",
            "source_hash[32]",
            "object_hash[32]",
        ):
            self.assertIn(token, self.public)
        self.assertIn("ExecdWorkerInternalSourceIsCanonical", self.core)
        self.assertIn("ExecdWorkerInternalPlanIsCanonical", self.core)

    def test_receipts_bind_exact_instance_peer_slot_and_generation(self) -> None:
        peer_receipt = struct_body(self.public, "ExecdWorkerPeerReceipt")
        request_receipt = struct_body(self.public, "ExecdWorkerRequestReceipt")
        for token in ("instance", "peer", "peer_generation", "peer_slot"):
            self.assertIn(token, peer_receipt)
        for token in ("peer", "request_generation", "request_id", "request_slot"):
            self.assertIn(token, request_receipt)
        resolve_peer = function_body(self.core, "ExecdWorkerInternalResolvePeer")
        self.assertIn("ExecdWorkerInternalInstanceEqual", resolve_peer)
        self.assertIn("peer->generation != receipt->peer_generation", resolve_peer)
        self.assertIn("ExecdWorkerInternalPeerEqual", resolve_peer)
        resolve_request = function_body(self.core, "ExecdWorkerInternalResolveRequest")
        self.assertIn("request->generation != receipt->request_generation", resolve_request)
        self.assertIn("request->request_id != receipt->request_id", resolve_request)

    def test_submit_commits_only_exact_monotonic_ids_after_capacity_is_known(self) -> None:
        body = function_body(self.requests, "ExecdWorkerSubmit")
        self.assertIn("request_snapshot.request_id < peer_row->next_request_id", body)
        self.assertIn("request_snapshot.request_id > peer_row->next_request_id", body)
        self.assertIn("free_slot == EXECD_WORKER_MAX_REQUESTS", body)
        assignment = re.search(r"peer_row->next_request_id\s*=\s*(?!=)", body)
        self.assertIsNotNone(assignment)
        self.assertLess(body.index("free_slot == EXECD_WORKER_MAX_REQUESTS"), assignment.start())
        self.assertIn("request_snapshot.request_id == UINT64_MAX ? 0", body)
        self.assertIn("return EXECD_WORKER_SEQUENCE_EXHAUSTED", body)

    def test_slot_generation_never_wraps(self) -> None:
        retire_request = function_body(self.core, "ExecdWorkerInternalRetireRequest")
        finalize_peer = function_body(self.core, "ExecdWorkerInternalMaybeFinalizePeer")
        for body, retired_state in (
            (retire_request, "EXECD_WORKER_SLOT_RETIRED"),
            (finalize_peer, "EXECD_WORKER_PEER_STATE_RETIRED"),
        ):
            self.assertIn("generation == UINT64_MAX", body)
            self.assertIn(retired_state, body)
            self.assertIn("generation + UINT64_C(1)", body)

    def test_cancellation_has_an_explicit_linearization_for_every_phase(self) -> None:
        cancel = function_body(self.requests, "ExecdWorkerCancel")
        for state in (
            "EXECD_WORKER_SLOT_QUEUED",
            "EXECD_WORKER_SLOT_RUNNING",
            "EXECD_WORKER_SLOT_REPLY_READY",
            "EXECD_WORKER_SLOT_REPLY_PUBLISHING",
        ):
            self.assertIn(state, cancel)
        self.assertIn("EXECD_WORKER_REPLY_CANCELLED", cancel)
        self.assertIn("EXECD_WORKER_PLAN_DISCARD", cancel)
        self.assertIn("EXECD_WORKER_CANCEL_TOO_LATE", cancel)
        complete = function_body(self.requests, "ExecdWorkerComplete")
        self.assertIn("request->cancel_requested", complete)
        self.assertIn("EXECD_WORKER_PLAN_DISCARD", complete)

    def test_reply_publication_is_two_phase_and_cleanup_distinguishes_ownership(self) -> None:
        self.assertIn("ExecdWorkerGetNextReply", self.public)
        self.assertIn("ExecdWorkerCommitReply", self.public)
        self.assertIn("ExecdWorkerAbortReply", self.public)
        self.assertIn("resolve the returned lease before any other engine", self.public)
        self.assertIn("Every other result leaves that duty with the caller", self.public)
        self.assertIn("only when Complete returns EXECD_WORKER_OK", self.public)
        commit = function_body(self.requests, "ExecdWorkerCommitReply")
        abort = function_body(self.requests, "ExecdWorkerAbortReply")
        reserve = function_body(self.requests, "ExecdWorkerGetNextReply")
        self.assertLess(
            reserve.index("return EXECD_WORKER_REPLY_IN_FLIGHT"),
            reserve.index("request->state = EXECD_WORKER_SLOT_REPLY_PUBLISHING"),
        )
        self.assertIn("EXECD_WORKER_SLOT_REPLY_PUBLISHING", commit)
        self.assertIn("EXECD_WORKER_PLAN_PUBLISHED", commit)
        self.assertIn("EXECD_WORKER_SLOT_REPLY_PUBLISHING", abort)
        self.assertIn("EXECD_WORKER_SLOT_REPLY_READY", abort)
        self.assertIn("EXECD_WORKER_PLAN_PUBLISHED", self.public)
        self.assertIn("EXECD_WORKER_PLAN_DISCARD", self.public)

    def test_close_and_drain_never_drop_running_work_behind_a_worker(self) -> None:
        close = function_body(self.requests, "ExecdWorkerClosePeer")
        drain = function_body(self.requests, "ExecdWorkerBeginDrain")
        for body in (close, drain):
            self.assertIn("EXECD_WORKER_SLOT_RUNNING", body)
            self.assertIn("request->cancel_requested = 1", body)
            self.assertIn("ExecdWorkerInternalRetireRequest", body)
        finish = function_body(self.requests, "ExecdWorkerFinishDrain")
        self.assertIn("peer_count != 0 || implementation->request_count != 0", finish)
        self.assertIn("EXECD_WORKER_BUSY", finish)

    def test_hostile_host_suite_covers_all_state_edges(self) -> None:
        for test in (
            "TestInitializationAndIdentity",
            "TestPeerAndRequestOrdering",
            "TestSuccessReplyTransaction",
            "TestCancellationLinearization",
            "TestPeerCloseAndDrain",
            "TestGenerationAndSequenceExhaustion",
            "TestCapacityDoesNotAdvanceSequence",
        ):
            self.assertRegex(self.host_test, rf"\b{test}\s*\(")
        for token in (
            "EXECD_WORKER_ALIASED_STORAGE",
            "EXECD_WORKER_PLAN_PUBLISHED",
            "EXECD_WORKER_PLAN_DISCARD",
            "EXECD_WORKER_CANCEL_TOO_LATE",
            "EXECD_WORKER_GENERATION_EXHAUSTED",
            "EXECD_WORKER_SEQUENCE_EXHAUSTED",
            "EXECD_WORKER_REQUEST_CAPACITY",
            "ExecdWorkerBeginDrain",
            "ExecdWorkerFinishDrain",
        ):
            self.assertIn(token, self.host_test)


if __name__ == "__main__":
    unittest.main(verbosity=2)
