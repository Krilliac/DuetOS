#!/usr/bin/env python3
"""Structural contract for displayd's bounded policy-only compositor engine."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "userland/native-apps/displayd/display_engine.h"
INTERNAL = ROOT / "userland/native-apps/displayd/display_engine_internal.h"
CORE = ROOT / "userland/native-apps/displayd/display_engine.c"
REQUESTS = ROOT / "userland/native-apps/displayd/display_engine_request.c"
VALIDATE = ROOT / "userland/native-apps/displayd/display_engine_validate.c"
EVENTS = ROOT / "userland/native-apps/displayd/display_engine_event.c"
HOST_TEST = ROOT / "tests/host/test_displayd_engine.cpp"
DORMANT_MAIN = ROOT / "userland/native-apps/displayd/displayd.c"


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
    match = re.search(
        rf"typedef\s+struct\s+{re.escape(name)}\s*\{{(?P<body>.*?)\}}\s*{re.escape(name)}\s*;",
        source,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"struct not found: {name}")
    return match.group("body")


class DisplaydEngineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.public = read(PUBLIC)
        cls.internal = read(INTERNAL)
        cls.core = read(CORE)
        cls.requests = read(REQUESTS)
        cls.validate = read(VALIDATE)
        cls.events = read(EVENTS)
        cls.host_test = read(HOST_TEST)
        cls.dormant_main = read(DORMANT_MAIN)
        cls.engine_code = code_only(
            "\n".join((cls.public, cls.internal, cls.core, cls.requests, cls.validate, cls.events))
        )

    def test_surface_is_fixed_capacity_allocation_free_and_single_owner(self) -> None:
        for token in (
            "#define DISPLAYD_ENGINE_MAX_PEERS 16U",
            "#define DISPLAYD_ENGINE_MAX_SURFACES 64U",
            "#define DISPLAYD_ENGINE_MAX_REQUESTS 64U",
            "#define DISPLAYD_ENGINE_MAX_EVENTS 128U",
            "#define DISPLAYD_ENGINE_MAX_EVENTS_PER_PEER 16U",
            "#define DISPLAYD_ENGINE_SERVICE_CAPACITY 64U",
            "#define DISPLAYD_ENGINE_CREDENTIAL_GENERATION_MAX",
            "#define DISPLAYD_ENGINE_STORAGE_BYTES 131072U",
            "One displayd event-loop thread owns every call",
        ):
            self.assertIn(token, self.public)
        self.assertIn("_Static_assert(sizeof(DisplaydEngineImpl) <= DISPLAYD_ENGINE_STORAGE_BYTES", self.internal)
        includes = re.findall(r"^\s*#include\s+(.+)$", self.public, re.MULTILINE)
        self.assertEqual(includes, ["<stdint.h>"])
        for forbidden in (
            r"\bmalloc\b",
            r"\bcalloc\b",
            r"\brealloc\b",
            r"\bfree\s*\(",
            r"\bnew\b",
            r"\bdelete\b",
            r"\bKMalloc\b",
            r"\bKFree\b",
            r"\bCreateThread\b",
            r"\bpthread_",
            r"\bSyscall\b",
            r"\bServiceEndpoint\b",
            r"\bGuiBroker\b",
            r"\bFramebuffer\b",
        ):
            self.assertNotRegex(self.engine_code, forbidden)

    def test_authority_is_an_exact_pointer_free_snapshot(self) -> None:
        for name in (
            "DisplaydEngineInstanceIdentity",
            "DisplaydPeerIdentity",
            "DisplaydPeerReceipt",
            "DisplaydSurfaceIdentity",
            "DisplaydRequestReceipt",
            "DisplaydEventLease",
        ):
            self.assertNotIn("*", struct_body(self.public, name), name)
        for token in (
            "service_identity",
            "instance_generation",
            "published_endpoint_epoch",
            "DisplaydProcessKey process",
            "DisplaydCredentialKey credential",
            "DisplaydChannelIdentity channel",
            "integrity",
            "peer_generation",
            "request_generation",
            "event_generation",
            "DISPLAYD_CHANNEL_ROLE_INITIATOR = 0",
            "DISPLAYD_CHANNEL_ROLE_ACCEPTOR = 1",
        ):
            self.assertIn(token, self.public)
        resolve_peer = function_body(self.validate, "DisplaydInternalResolvePeer")
        self.assertIn("DisplaydInternalInstanceEqual", resolve_peer)
        self.assertIn("row->generation != receipt->generation", resolve_peer)
        self.assertIn("DisplaydInternalPeerEqual", resolve_peer)
        self.assertIn("identity->service_slot < DISPLAYD_ENGINE_SERVICE_CAPACITY", self.validate)
        self.assertIn("identity->credential.generation > DISPLAYD_ENGINE_CREDENTIAL_GENERATION_MAX", self.validate)

    def test_exact_monotonic_request_ids_and_global_fifo_are_explicit(self) -> None:
        submit = function_body(self.requests, "DisplaydEngineSubmit")
        self.assertIn("request->request_id < peer_row->next_request_id", submit)
        self.assertIn("request->request_id > peer_row->next_request_id", submit)
        self.assertLess(submit.index("impl->request_count >= DISPLAYD_ENGINE_MAX_REQUESTS"),
                        submit.index("++peer_row->next_request_id"))
        self.assertIn("peer_row->request_sequence_exhausted", submit)
        self.assertIn("peer_row->next_request_id == UINT64_MAX", submit)
        apply_next = function_body(self.requests, "DisplaydEngineApplyNext")
        self.assertIn("impl->requests[index].fifo_ticket < best_ticket", apply_next)

    def test_writable_outputs_cannot_alias_read_inputs(self) -> None:
        checks = (
            (self.core, "DisplaydEngineOpenPeer", "peer", "receipt_out"),
            (self.core, "DisplaydEngineClosePeer", "peer", "summary_out"),
            (self.events, "DisplaydEngineGetNextEvent", "peer", "publication_out"),
            (self.validate, "DisplaydEngineInspectPeer", "peer", "snapshot_out"),
            (self.validate, "DisplaydEngineInspectSurface", "surface", "snapshot_out"),
            (self.validate, "DisplaydEngineInspectRequest", "request", "snapshot_out"),
            (self.requests, "DisplaydEngineSubmit", "peer", "receipt_out"),
            (self.requests, "DisplaydEngineSubmit", "request", "receipt_out"),
            (self.requests, "DisplaydEngineCancel", "peer", "receipt_out"),
            (self.requests, "DisplaydEngineGetNextReply", "peer", "publication_out"),
        )
        for source, name, read_input, output in checks:
            body = function_body(source, name)
            self.assertRegex(
                body,
                rf"DisplaydInternalRangesOverlap\s*\(\s*{read_input}\s*,\s*sizeof\(\*{read_input}\)\s*,\s*"
                rf"{output}\s*,\s*sizeof\(\*{output}\)\s*\)",
                name,
            )

    def test_slot_and_sequence_generations_never_wrap(self) -> None:
        next_generation = function_body(self.core, "DisplaydInternalNextGeneration")
        self.assertIn("generation == UINT64_MAX", next_generation)
        self.assertIn("return 0", next_generation)
        reserve = function_body(self.events, "DisplaydInternalReserveEvents")
        self.assertIn("peer->event_sequence_exhausted", reserve)
        self.assertIn("UINT64_MAX - peer->next_event_sequence + 1U < needed", reserve)
        self.assertIn("engine->event_fifo_exhausted", reserve)

    def test_mutations_reserve_events_before_state_changes(self) -> None:
        checks = (
            ("ApplyCreate", "surface->state = DISPLAYD_SURFACE_LIVE"),
            ("ApplyDestroy", "DisplaydInternalRetireSurface"),
            ("ApplyBounds", "surface->bounds = request_row->request.bounds"),
            ("ApplyVisibility", "surface->visible = request_row->request.visible"),
            ("ApplyRaise", "DisplaydInternalZRaise"),
            ("ApplyFocus", "engine->focused_surface = request_row->request.surface"),
        )
        for name, mutation in checks:
            body = function_body(self.requests, name)
            self.assertIn("ReserveMutationEvents", body, name)
            self.assertIn(mutation, body, name)
            self.assertLess(body.index("ReserveMutationEvents"), body.index(mutation), name)
            self.assertLess(body.index(mutation), body.index("DisplaydInternalPublishEvents"), name)

    def test_publication_and_teardown_have_explicit_transactions(self) -> None:
        for prefix in ("Reply", "Event"):
            self.assertIn(f"DisplaydEngineGetNext{prefix}", self.public)
            self.assertIn(f"DisplaydEngineCommit{prefix}", self.public)
            self.assertIn(f"DisplaydEngineAbort{prefix}", self.public)
        close = function_body(self.core, "DisplaydEngineClosePeer")
        event_retire = close.index("DisplaydInternalRetireEvent")
        request_retire = close.index("DisplaydInternalRetireRequest")
        surface_retire = close.index("DisplaydInternalRetireSurface")
        peer_retire = close.index("peer_row->state = DISPLAYD_PEER_RETIRED")
        self.assertLess(event_retire, peer_retire)
        self.assertLess(request_retire, peer_retire)
        self.assertLess(surface_retire, peer_retire)
        begin = function_body(self.core, "DisplaydEngineBeginDrain")
        self.assertIn("DisplaydEngineClosePeer", begin)
        self.assertIn("DISPLAYD_ENGINE_STATE_DRAINING", begin)
        finish = function_body(self.core, "DisplaydEngineFinishDrain")
        self.assertIn("DISPLAYD_ENGINE_NOT_DRAINED", finish)
        self.assertIn("DISPLAYD_ENGINE_STATE_CLOSED", finish)

    def test_hostile_host_suite_covers_core_state_edges(self) -> None:
        for test in (
            "TestInitializationAndIdentity",
            "TestRequestOrderingCancellationAndPublication",
            "TestSurfaceFocusAndZOrder",
            "TestEventCapacityIsAtomic",
            "TestReuseCloseAndTerminalDrain",
            "TestGenerationAndSequenceExhaustion",
            "TestMutationSequenceExhaustion",
        ):
            self.assertRegex(self.host_test, rf"\b{test}\s*\(")
        for token in (
            "DISPLAYD_ENGINE_ALIASED_STORAGE",
            "DISPLAYD_ENGINE_REPLAYED_REQUEST",
            "DISPLAYD_ENGINE_OUT_OF_ORDER_REQUEST",
            "DISPLAYD_ENGINE_REPLY_IN_FLIGHT",
            "DISPLAYD_ENGINE_EVENT_IN_FLIGHT",
            "DISPLAYD_REPLY_WRONG_OWNER",
            "DISPLAYD_REPLY_EVENT_QUEUE_FULL",
            "DISPLAYD_ENGINE_STALE_SURFACE",
            "DISPLAYD_ENGINE_STALE_PEER",
            "DISPLAYD_ENGINE_GENERATION_EXHAUSTED",
            "DISPLAYD_ENGINE_SEQUENCE_EXHAUSTED",
            "DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED",
            "DISPLAYD_REPLY_EVENT_SEQUENCE_EXHAUSTED",
            "DisplaydEngineBeginDrain",
            "DisplaydEngineFinishDrain",
        ):
            self.assertIn(token, self.host_test)

    def test_existing_displayd_entrypoint_remains_dormant(self) -> None:
        self.assertRegex(self.dormant_main, r"\breturn\s+72\s*;")
        lowered = self.dormant_main.lower()
        self.assertIn("displaymaster", lowered)
        self.assertIn("no endpoint", lowered)
        self.assertIn("lease is asserted", lowered)
        self.assertIn("parkwithoutendpoint();", lowered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
