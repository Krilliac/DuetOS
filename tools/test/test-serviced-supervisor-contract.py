#!/usr/bin/env python3
"""Structural guards for the fixed-capacity user-mode serviced supervisor."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "userland/native-apps/serviced"
HEADER = (BASE / "supervisor.h").read_text(encoding="utf-8")
INTERNAL = (BASE / "supervisor_internal.h").read_text(encoding="utf-8")
SOURCES = {
    path.name: path.read_text(encoding="utf-8")
    for path in sorted(BASE.glob("supervisor*.c"))
}
SOURCE = "\n".join(SOURCES.values())
HOST_TEST = (ROOT / "tests/host/test_serviced_supervisor.cpp").read_text(encoding="utf-8")
CMAKE = (ROOT / "tests/host/CMakeLists.txt").read_text(encoding="utf-8")


class ServicedSupervisorContract(unittest.TestCase):
    def test_storage_and_work_are_strictly_bounded(self) -> None:
        for token in (
            "SERVICED_SUPERVISOR_MAX_SERVICES 64U",
            "SERVICED_SUPERVISOR_MAX_RESTARTS 16U",
            "SERVICED_SUPERVISOR_MAX_CLIENTS 16U",
            "SERVICED_SUPERVISOR_ACTION_CAPACITY 64U",
            "uint8_t bytes[SERVICED_SUPERVISOR_STORAGE_BYTES]",
            "ServicedSupervisorRow rows[SERVICED_SUPERVISOR_MAX_SERVICES]",
            "ServicedSupervisorClientLedger clients[SERVICED_SUPERVISOR_MAX_CLIENTS]",
        ):
            self.assertIn(token, HEADER + INTERNAL)
        self.assertNotRegex(SOURCE, r"\b(?:malloc|calloc|realloc|free|new|delete)\s*\(")
        self.assertNotRegex(SOURCE, r"for\s*\(\s*;\s*;")
        self.assertNotRegex(SOURCE, r"while\s*\(\s*(?:1|true)\s*\)")

    def test_boundary_is_freestanding_and_has_no_kernel_authority(self) -> None:
        self.assertEqual(re.findall(r"^#include\s+(.+)$", HEADER, re.MULTILINE), ["<stdint.h>"])
        for name, source in SOURCES.items():
            self.assertEqual(
                re.findall(r"^#include\s+(.+)$", source, re.MULTILINE),
                ['"supervisor_internal.h"'],
                name,
            )
        self.assertEqual(
            re.findall(r"^#include\s+(.+)$", INTERNAL, re.MULTILINE),
            ['"supervisor.h"'],
        )
        for forbidden in ("LifecycleBroker*", "Process*", "Task*", "Capability", "KObject"):
            self.assertNotIn(forbidden, HEADER)

    def test_exact_observed_identity_is_never_partial(self) -> None:
        for token in (
            "uint32_t service_slot;",
            "uint64_t instance_generation;",
            "ServicedSupervisorProcessKey process;",
            "uint64_t endpoint_epoch;",
            "left->process.identity == right->process.identity",
            "left->process.pid == right->process.pid",
            "left->endpoint_epoch == right->endpoint_epoch",
        ):
            self.assertIn(token, HEADER + SOURCE)
        self.assertIn("event->observed.instance_generation == event->instance_generation", SOURCE)
        self.assertIn("ServicedSupervisorInternalObservedEqual(&row->observed, &event->observed)", SOURCE)

    def test_manifest_and_restart_policy_are_closed_and_nonwrapping(self) -> None:
        for token in (
            "manifest_identity",
            "manifest_generation",
            "dependency_mask",
            "SERVICED_RESTART_NEVER",
            "SERVICED_RESTART_ALWAYS",
            "SERVICED_RESTART_ON_FAILURE",
            "restart_limit <= SERVICED_SUPERVISOR_MAX_RESTARTS",
            "row->transition_generation == UINT64_MAX",
            "SERVICED_PHASE_GENERATION_EXHAUSTED",
            "PruneRestartWindow",
            "SERVICED_PHASE_CRASH_LOOP",
            "action.target_instance_generation = expected_generation + UINT64_C(1)",
        ):
            self.assertIn(token, HEADER + SOURCE)

    def test_ordered_event_apply_and_ack_are_separate(self) -> None:
        for api in (
            "ServicedSupervisorApplyLifecycleEvent",
            "ServicedSupervisorGetPendingEventActions",
            "ServicedSupervisorBuildEventAcknowledgement",
            "ServicedSupervisorCommitEventAcknowledgement",
        ):
            self.assertIn(api, HEADER)
        event = SOURCES["supervisor_event.c"]
        self.assertIn("event_snapshot.event_sequence != implementation->last_acknowledged_event_sequence +", event)
        self.assertIn("implementation->pending_actions = result_out->actions", event)
        self.assertIn("implementation->has_pending_acknowledgement = 1", event)
        apply_pos = event.index("implementation->has_pending_acknowledgement = 1")
        commit_pos = event.index("implementation->last_acknowledged_event_sequence = receipt->event_sequence")
        self.assertLess(apply_pos, commit_pos)

    def test_command_dedup_is_bounded_and_compares_the_full_request(self) -> None:
        command = SOURCES["supervisor_command.c"]
        for token in (
            "command_snapshot.request_id < client->request_id",
            "SERVICED_SUPERVISOR_REPLAYED_REQUEST",
            "SERVICED_SUPERVISOR_REQUEST_ID_CONFLICT",
            "SERVICED_SUPERVISOR_CLIENT_CAPACITY",
            "command_snapshot.service_identity != client->service_identity",
            "command_snapshot.expected_transition_generation != client->expected_transition_generation",
            "command_snapshot.now_ns != client->now_ns",
            "result_out->actions = client->actions",
        ):
            self.assertIn(token, command)
        find_target = command.index("row = ServicedSupervisorInternalFind")
        accept_time = command.index("ServicedSupervisorPolicyAcceptTimestamp", find_target)
        mutate = command.index("ApplyCommandMutation", accept_time)
        self.assertLess(find_target, accept_time)
        self.assertLess(accept_time, mutate)

    def test_restart_reconciliation_requires_both_exact_views(self) -> None:
        reconcile = SOURCES["supervisor_reconcile.c"]
        self.assertIn("ServicedSupervisorInternalObservedEqual(&source->lifecycle_identity", reconcile)
        self.assertIn("&source->directory_identity", reconcile)
        self.assertIn("row->adopted = 1", reconcile)
        self.assertIn("row->adopted = 0", reconcile)
        self.assertIn("SERVICED_ACTION_REASON_RECONCILE_MISMATCH", reconcile)
        self.assertIn("prior->lifecycle_identity.process.identity ==", reconcile)
        self.assertIn("prior->lifecycle_identity.endpoint_epoch ==", reconcile)

    def test_hostile_test_and_build_registration_cover_the_contract(self) -> None:
        for token in (
            "TestOrderedEventsAndDependencies",
            "TestCrashLoopAndDependencyDrain",
            "TestOnFailurePolicy",
            "TestRestartReconciliation",
            "TestGenerationExhaustion",
            "TestCommandLedgerCapacity",
            "TestRejectedCommandCannotPoisonClock",
            "TestStartFailureEndpointCloseAndCancellation",
            "TestEndpointCloseDrainsDependentsFirst",
            "SERVICED_SUPERVISOR_WRONG_INSTANCE",
            "SERVICED_SUPERVISOR_PENDING_ACKNOWLEDGEMENT",
            "SERVICED_SUPERVISOR_REQUEST_ID_CONFLICT",
            "SERVICED_SUPERVISOR_CLIENT_CAPACITY",
        ):
            self.assertIn(token, HOST_TEST)
        self.assertIn("project(duetos-host-tests C CXX)", CMAKE)
        self.assertIn("add_host_test(serviced_supervisor)", CMAKE)
        for name in SOURCES:
            self.assertIn(name, CMAKE)


if __name__ == "__main__":
    unittest.main()
