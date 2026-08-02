#!/usr/bin/env python3
"""Structural contract for netd's bounded socket-authority engine."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "userland/native-apps/netd/socket_engine.h"
INTERNAL = ROOT / "userland/native-apps/netd/socket_engine_internal.h"
CORE = ROOT / "userland/native-apps/netd/socket_engine.c"
VALIDATE = ROOT / "userland/native-apps/netd/socket_engine_validate.c"
REQUESTS = ROOT / "userland/native-apps/netd/socket_engine_request.c"
LIFECYCLE = ROOT / "userland/native-apps/netd/socket_engine_lifecycle.c"
HOST_TEST = ROOT / "tests/host/test_netd_socket_engine.cpp"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Mask comments and literals while preserving braces and newlines."""
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
    match = re.search(
        rf"typedef\s+struct\s+{re.escape(name)}\s*\{{(?P<body>.*?)\}}\s*{re.escape(name)}\s*;",
        source,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"struct not found: {name}")
    return match.group("body")


class NetdSocketEngineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public = read(PUBLIC)
        cls.internal = read(INTERNAL)
        cls.core = read(CORE)
        cls.validate = read(VALIDATE)
        cls.requests = read(REQUESTS)
        cls.lifecycle = read(LIFECYCLE)
        cls.host_test = read(HOST_TEST)
        cls.engine_code = code_only(
            "\n".join((cls.public, cls.internal, cls.core, cls.validate, cls.requests, cls.lifecycle))
        )

    def test_engine_is_fixed_capacity_allocation_free_and_actor_owned(self) -> None:
        for token in (
            "#define NETD_SOCKET_ENGINE_MAX_PEERS 16U",
            "#define NETD_SOCKET_ENGINE_MAX_SOCKETS 64U",
            "#define NETD_SOCKET_ENGINE_MAX_REQUESTS 64U",
            "#define NETD_SOCKET_ENGINE_CLEANUP_CAPACITY NETD_SOCKET_ENGINE_MAX_SOCKETS",
            "#define NETD_SOCKET_ENGINE_STORAGE_BYTES 65536U",
            "One netd control actor owns every mutating call",
        ):
            self.assertIn(token, self.public)
        self.assertIn("_Static_assert(sizeof(NetdSocketEngineImpl) <= NETD_SOCKET_ENGINE_STORAGE_BYTES", self.internal)
        includes = re.findall(r"^\s*#include\s+(.+)$", self.public, re.MULTILINE)
        self.assertEqual(includes, ["<stdint.h>"])
        for forbidden in (
            r"\bmalloc\s*\(",
            r"\bcalloc\s*\(",
            r"\brealloc\s*\(",
            r"\bfree\s*\(",
            r"\bnew\b",
            r"\bdelete\b",
            r"\bKMalloc\s*\(",
            r"\bKFree\s*\(",
            r"\bCreateThread\s*\(",
            r"\bpthread_",
            r"\bduet_socket\s*\(",
            r"\bduet_bind\s*\(",
            r"\bduet_connect\s*\(",
            r"\bPacketRing\b",
            r"\bNetworkMaster\b",
        ):
            self.assertNotRegex(self.engine_code, forbidden)
        # CLAUDE.md's ~500-line threshold is a cohesion check, not a hard 500.
        for source in (self.core, self.validate, self.requests, self.lifecycle):
            self.assertLessEqual(len(source.splitlines()), 520)

    def test_authority_and_receipts_are_exact_pointer_free_values(self) -> None:
        for name in (
            "NetdSocketEngineInstanceIdentity",
            "NetdSocketEnginePeerIdentity",
            "NetdSocketEnginePeerAuthority",
            "NetdSocketEngineTransportReceipt",
            "NetdSocketEnginePeerReceipt",
            "NetdSocketEngineSocketRef",
            "NetdSocketEngineRequestReceipt",
            "NetdSocketEngineWorkLease",
            "NetdSocketEngineReplyLease",
        ):
            self.assertNotIn("*", struct_body(self.public, name), name)
        for token in (
            "service_identity",
            "instance_generation",
            "published_endpoint_epoch",
            "NetdSocketEngineProcessKey process",
            "NetdSocketEngineCredentialKey credential",
            "NetdSocketEngineChannelIdentity channel",
            "NETD_SOCKET_ENGINE_CHANNEL_ACCEPTOR",
            "authority_identity",
            "network_namespace_identity",
            "allowed_methods",
            "socket_limit",
            "request_limit",
        ):
            self.assertIn(token, self.public)
        resolve = function_body(self.core, "NetdSocketEngineInternalResolvePeer")
        for token in (
            "NetdSocketEngineInternalInstanceEqual",
            "row->generation != receipt->peer_generation",
            "NetdSocketEngineInternalPeerEqual",
            "NetdSocketEngineInternalAuthorityEqual",
        ):
            self.assertIn(token, resolve)

    def test_transport_attachment_is_explicit_one_shot_and_fail_closed(self) -> None:
        attach = function_body(self.core, "NetdSocketEngineAttachTransport")
        self.assertIn("NETD_SOCKET_ENGINE_TRANSPORT_ALREADY_ATTACHED", attach)
        self.assertIn("implementation->state = NETD_SOCKET_ENGINE_STATE_OPEN", attach)
        open_peer = function_body(self.core, "NetdSocketEngineOpenPeer")
        self.assertIn("NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT", open_peer)
        self.assertIn("NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE", open_peer)
        resolve_submission = function_body(self.requests, "ResolveSubmissionPeer")
        self.assertIn("NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE", resolve_submission)
        complete = function_body(self.requests, "NetdSocketEngineComplete")
        self.assertIn("NetdSocketEngineInternalTransportEqual", complete)
        socket_ref = struct_body(self.public, "NetdSocketEngineSocketRef")
        for token in ("instance_generation", "transport_generation", "generation", "slot"):
            self.assertIn(token, socket_ref)

    def test_writable_outputs_cannot_alias_read_inputs(self) -> None:
        checks = (
            (self.core, "NetdSocketEngineAttachTransport", "transport", "receipt_out"),
            (self.core, "NetdSocketEngineOpenPeer", "peer", "receipt_out"),
            (self.core, "NetdSocketEngineOpenPeer", "authority", "receipt_out"),
            (self.core, "NetdSocketEngineInspectSocket", "peer", "snapshot_out"),
            (self.core, "NetdSocketEngineInspectSocket", "socket", "snapshot_out"),
            (self.core, "NetdSocketEngineInspectRequest", "receipt", "snapshot_out"),
            (self.requests, "NetdSocketEngineSubmitOpen", "peer", "receipt_out"),
            (self.requests, "NetdSocketEngineSubmitClose", "peer", "receipt_out"),
            (self.requests, "NetdSocketEngineSubmitClose", "socket", "receipt_out"),
            (self.requests, "NetdSocketEngineCheckCancellation", "lease", "cancellation_out"),
            (self.lifecycle, "NetdSocketEngineClosePeer", "receipt", "cleanup_out"),
            (self.lifecycle, "NetdSocketEngineBeginDrain", "transport", "cleanup_out"),
        )
        for source, name, read_input, output in checks:
            body = function_body(source, name)
            self.assertRegex(
                body,
                rf"NetdSocketEngineInternalRangesOverlap\s*\(\s*{read_input}\s*,\s*sizeof\(\*{read_input}\)\s*,\s*"
                rf"{output}\s*,\s*sizeof\(\*{output}\)\s*\)",
                name,
            )

    def test_capacity_and_identity_checks_precede_sequence_consumption(self) -> None:
        submit_open = function_body(self.requests, "NetdSocketEngineSubmitOpen")
        for check in (
            "peer_row->active_requests >= peer_row->authority.request_limit",
            "peer_row->active_sockets >= peer_row->authority.socket_limit",
            "request_slot == NETD_SOCKET_ENGINE_INVALID_SLOT",
            "socket_slot == NETD_SOCKET_ENGINE_INVALID_SLOT",
        ):
            self.assertLess(submit_open.index(check), submit_open.index("AdvanceRequestSequence"), check)
        submit_close = function_body(self.requests, "NetdSocketEngineSubmitClose")
        for check in (
            "NetdSocketEngineInternalResolveSocket",
            "SocketHasActiveRequest",
            "peer_row->active_requests >= peer_row->authority.request_limit",
            "request_slot == NETD_SOCKET_ENGINE_INVALID_SLOT",
        ):
            self.assertLess(submit_close.index(check), submit_close.index("AdvanceRequestSequence"), check)

    def test_slot_generations_and_request_sequence_never_wrap(self) -> None:
        for name, retired in (
            ("NetdSocketEngineInternalRetireRequest", "NETD_SOCKET_ENGINE_REQUEST_RETIRED"),
            ("NetdSocketEngineInternalRetireSocket", "NETD_SOCKET_ENGINE_SOCKET_RETIRED"),
            ("NetdSocketEngineInternalMaybeFinalizePeer", "NETD_SOCKET_ENGINE_PEER_STATE_RETIRED"),
        ):
            body = function_body(self.core, name)
            self.assertIn("generation == UINT64_MAX", body)
            self.assertIn(retired, body)
            self.assertIn("generation + UINT64_C(1)", body)
        sequence = function_body(self.requests, "AdvanceRequestSequence")
        self.assertIn("request_id == UINT64_MAX ? 0", sequence)
        check = function_body(self.requests, "CheckRequestSequence")
        self.assertIn("NETD_SOCKET_ENGINE_SEQUENCE_EXHAUSTED", check)

    def test_work_reply_cancel_and_drain_are_explicit_transactions(self) -> None:
        claim = function_body(self.requests, "NetdSocketEngineClaimNext")
        self.assertIn("NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL", claim)
        complete = function_body(self.requests, "NetdSocketEngineComplete")
        self.assertIn("request->cancel_requested", complete)
        self.assertIn("NETD_SOCKET_ENGINE_STATE_DRAINING", complete)
        self.assertIn("completion->reserved32 != 0", complete)
        get_reply = function_body(self.lifecycle, "NetdSocketEngineGetNextReply")
        self.assertIn("NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL", get_reply)
        commit = function_body(self.lifecycle, "NetdSocketEngineCommitReply")
        self.assertIn("NetdSocketEngineInternalRetireRequest", commit)
        abort = function_body(self.lifecycle, "NetdSocketEngineAbortReply")
        self.assertIn("NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL", abort)
        abandon = function_body(self.lifecycle, "AbandonPeer")
        for token in (
            "request->cancel_requested = 1",
            "request->abandon_cleanup_reason = (uint8_t)reason",
            "AppendSocketCleanup",
            "NetdSocketEngineInternalRetireSocket",
        ):
            self.assertIn(token, abandon)
        self.assertIn("request->abandon_cleanup_reason", complete)
        begin = function_body(self.lifecycle, "NetdSocketEngineBeginDrain")
        self.assertIn("NetdSocketEngineInternalTransportEqual", begin)
        self.assertIn("NETD_SOCKET_ENGINE_STATE_DRAINING", begin)
        self.assertIn("AbandonPeer", begin)
        finish = function_body(self.lifecycle, "NetdSocketEngineFinishDrain")
        self.assertIn("NETD_SOCKET_ENGINE_BUSY", finish)
        self.assertIn("NETD_SOCKET_ENGINE_STATE_CLOSED", finish)

    def test_internal_validation_is_phase_exact_and_rejects_reserved_bits(self) -> None:
        validate = function_body(self.validate, "NetdSocketEngineInternalValidate")
        for token in (
            "requests_by_socket",
            "publishing_count > 1",
            "peer->generation < implementation->first_slot_generation",
            "socket->reserved32 != 0",
            "request->socket_generation != request->request.socket.generation",
            "request->request.reserved16 != 0",
            "socket->state != NETD_SOCKET_ENGINE_SOCKET_RESERVED",
            "socket->state != NETD_SOCKET_ENGINE_SOCKET_CLOSING",
            "socket->state != NETD_SOCKET_ENGINE_SOCKET_OPEN",
            "NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT",
        ):
            self.assertIn(token, validate)

    def test_hostile_host_suite_covers_critical_edges(self) -> None:
        for test in (
            "TestInitializationAndFailClosedTransport",
            "TestExactPeerIdentityRightsAndQuota",
            "TestOpenCloseReplyTransaction",
            "TestCancellationLinearization",
            "TestPeerCloseCleansEveryOwnershipPhase",
            "TestTransportDrainWaitsForPinnedWork",
            "TestSequenceAndGenerationExhaustion",
            "TestDeferredSocketReferenceStaysPinned",
            "TestCorruptInternalStateFailsClosed",
            "TestSocketOwnershipAndBackendIdentityAreExact",
        ):
            self.assertRegex(self.host_test, rf"\b{test}\s*\(")
        for token in (
            "NETD_SOCKET_ENGINE_ALIASED_STORAGE",
            "NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE",
            "NETD_SOCKET_ENGINE_STALE_TRANSPORT",
            "NETD_SOCKET_ENGINE_UNAUTHORIZED",
            "NETD_SOCKET_ENGINE_SOCKET_CAPACITY",
            "NETD_SOCKET_ENGINE_REPLAYED_REQUEST",
            "NETD_SOCKET_ENGINE_OUT_OF_ORDER_REQUEST",
            "NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT",
            "NETD_SOCKET_ENGINE_CANCEL_TOO_LATE",
            "NETD_SOCKET_ENGINE_CLEANUP_CANCELLED_OPEN",
            "NETD_SOCKET_ENGINE_CLEANUP_PEER_CLOSED",
            "NETD_SOCKET_ENGINE_CLEANUP_TRANSPORT_DRAIN",
            "NETD_SOCKET_ENGINE_STALE_SOCKET",
            "NETD_SOCKET_ENGINE_GENERATION_EXHAUSTED",
            "NETD_SOCKET_ENGINE_SEQUENCE_EXHAUSTED",
            "completion.reserved32 = 1",
            "NETD_SOCKET_ENGINE_CORRUPT_STATE",
            "NETD_SOCKET_ENGINE_STALE_SOCKET",
            "NetdSocketEngineBeginDrain",
            "NetdSocketEngineFinishDrain",
        ):
            self.assertIn(token, self.host_test)


if __name__ == "__main__":
    unittest.main(verbosity=2)
