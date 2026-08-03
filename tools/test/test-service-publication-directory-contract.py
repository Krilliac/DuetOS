#!/usr/bin/env python3
"""Structural contract for atomic lifecycle/ServiceDirectory publication."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACTIVATION_H = (ROOT / "kernel/core/service_bootstrap_activation.h").read_text(encoding="utf-8")
ACTIVATION_CPP = (ROOT / "kernel/core/service_bootstrap_activation.cpp").read_text(encoding="utf-8")
BROKER_H = (ROOT / "kernel/core/service_lifecycle_broker.h").read_text(encoding="utf-8")
BROKER_CPP = (ROOT / "kernel/core/service_lifecycle_broker.cpp").read_text(encoding="utf-8")
DIRECTORY_H = (ROOT / "kernel/core/service_directory.h").read_text(encoding="utf-8")
DIRECTORY_CPP = (ROOT / "kernel/core/service_directory.cpp").read_text(encoding="utf-8")
RUNTIME_H = (ROOT / "kernel/core/service_runtime.h").read_text(encoding="utf-8")
RUNTIME_CPP = (ROOT / "kernel/core/service_runtime.cpp").read_text(encoding="utf-8")
HOST_TEST = (ROOT / "tests/host/test_service_publication_directory.cpp").read_text(encoding="utf-8")
BOOT_HEADER = (ROOT / "kernel/core/boot_service_manifest_data.h").read_text(encoding="utf-8")


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


class ServicePublicationDirectoryContract(unittest.TestCase):
    def test_activation_request_has_one_runtime_authority_root(self) -> None:
        request = braced_body(ACTIVATION_H, "struct ServiceBootstrapActivationRequestV1")
        self.assertIn("ServiceRuntimeV1* runtime", request)
        for mixable in (
            "ServiceBootstrapStageRuntimeV1* stage",
            "ServiceLifecycleBroker* broker",
            "ServiceExitObserver* exit_observer",
            "ServiceDirectory* directory",
        ):
            self.assertNotIn(mixable, request)
        bind = braced_body(RUNTIME_CPP, "ServiceRuntimeStatusV1 ServiceRuntimeBindActivationAuthorityV1")
        require_order(bind, "ServiceRuntimeInspectV1", "ServiceObjectPackageGetManifestV1", "*authority_out")

    def test_runtime_owns_and_revalidates_the_single_directory(self) -> None:
        runtime = braced_body(RUNTIME_H, "struct ServiceRuntimeV1")
        for token in (
            "ServiceLifecycleBroker lifecycle",
            "ServiceExitObserver exit_observer",
            "ServiceEndpointOwner endpoint_owner",
            "ServiceDirectory directory",
        ):
            self.assertIn(token, runtime)
        inspect = braced_body(RUNTIME_CPP, "ServiceRuntimeStatusV1 ServiceRuntimeInspectV1")
        for token in (
            "ServiceDirectoryValidateRuntimeOwner",
            "lifecycle.snapshot.manifest_object_hash",
            "manifest.sealed_object_hash",
            "authority.sealed_object_hash",
            "manifest.sealed_object_extent",
            "authority.sealed_object_extent",
        ):
            self.assertIn(token, inspect)

    def test_private_process_identity_and_registration_precede_task_creation(self) -> None:
        activate = braced_body(ACTIVATION_CPP, "ServiceBootstrapActivationResultV1 ActivateWithPlatform")
        require_order(
            activate,
            "ServiceRuntimeBindActivationAuthorityV1",
            "ServiceObjectPackageGetManifestV1",
            "ServiceLifecycleBrokerReserveStartWithDependencies",
            "ServiceExitObserverReserve",
            "create_process",
            "snapshot_process_identity",
            "ServiceDirectoryReserveRegistration",
            "install_publication_gate",
            "create_user_task_prepared",
        )
        self.assertIn("lifecycle_ticket.transition", activate)
        self.assertIn("ServiceInstanceKey{private_process.identity, private_process.pid}", activate)
        self.assertNotIn("request.stage", activate)
        self.assertNotIn("request.broker", activate)
        self.assertNotIn("request.exit_observer", activate)

    def test_gate_binds_observer_then_uses_broker_owned_joint_commit(self) -> None:
        gate = braced_body(ACTIVATION_CPP, "bool CommitLifecyclePublication")
        require_order(
            gate,
            "process == context->expected_process",
            "ServiceExitObserverBindAtSchedulerPublication",
            "ServiceLifecycleBrokerCommitDirectoryPublication",
            "ServiceExitObserverRollbackBound",
        )
        self.assertIn("directory_registration_owned", gate)
        self.assertIn("process, *context->directory_registration", gate)
        self.assertIn("context->directory, context->directory_registration", gate)

    def test_lifecycle_lock_covers_final_directory_publish_and_exact_rollback(self) -> None:
        joint = braced_body(
            BROKER_CPP,
            "ServiceLifecycleDirectoryPublicationResult ServiceLifecycleBrokerCommitDirectoryPublication",
        )
        require_order(
            joint,
            "sync::SpinLockGuard guard(broker->lock)",
            "ServiceTransitionIsCurrentStart",
            "UnpublishedPublicationRollbackToken rollback",
            "ServiceTransitionCommitAtSchedulerPublication",
            "ServiceDirectoryPublishRegistration",
            "RollbackUnpublishedPublicationLocked",
        )
        rollback = braced_body(BROKER_CPP, "ServiceLifecycleStatus RollbackUnpublishedPublicationLocked")
        for token in (
            "rollback->broker_epoch",
            "rollback->row_index",
            "rollback->ticket.transition",
            "rollback->instance",
            "ServiceTransitionIsCurrentRunning",
            "row = rollback->prior_row",
            "rollback->valid = false",
        ):
            self.assertIn(token, rollback)
        self.assertIn("holds the lifecycle lock continuously", BROKER_H)
        self.assertIn("scheduler -> lifecycle -> directory", DIRECTORY_H)

    def test_directory_publication_lock_body_is_visibility_only(self) -> None:
        publish = braced_body(DIRECTORY_CPP, "ServiceDirectoryStatus ServiceDirectoryPublishRegistration")
        for forbidden in (
            "ServiceEndpointCreate",
            "HandleTable",
            "KObject",
            "KMalloc",
            "KFree",
            "KLOG",
            "callback",
            "Wait",
        ):
            self.assertNotIn(forbidden, publish)
        require_order(publish, "DirectoryGuard guard", "row->reservation_authority = 0", "row->state")
        self.assertIn("g_fail_registration_publication.exchange", publish)
        self.assertIn("ServiceDirectoryHostFailNextRegistrationPublicationForTest", DIRECTORY_CPP)

    def test_joint_readiness_prevalidates_both_exact_identities_before_no_fail_commit(self) -> None:
        lifecycle_row = braced_body(BROKER_H, "struct ServiceLifecycleRow")
        lifecycle_snapshot = braced_body(BROKER_H, "struct ServiceLifecycleSnapshot")
        directory_row = braced_body(DIRECTORY_H, "struct ServiceDirectoryRow")
        directory_snapshot = braced_body(DIRECTORY_H, "struct ServiceDirectoryEntrySnapshot")
        for body in (lifecycle_row, lifecycle_snapshot, directory_row, directory_snapshot):
            self.assertIn("bool ready", body)

        mark = braced_body(BROKER_CPP, "ServiceLifecycleDirectoryReadyResult ServiceLifecycleBrokerMarkReady")
        require_order(
            mark,
            "sync::SpinLockGuard guard(broker->lock)",
            "ValidateTokenEpoch",
            "ServiceTransitionIsCurrentRunning",
            "ServiceDirectoryCommitJointReady",
        )
        directory_mark = braced_body(DIRECTORY_CPP, "ServiceDirectoryStatus ServiceDirectoryCommitJointReady")
        require_order(
            directory_mark,
            "DirectoryGuard guard",
            "ResolveExactLocked",
            "row->owner == owner",
            "row->state != ServiceDirectoryEntryState::Active",
            "row->ready = true",
            "*lifecycle_ready = true",
        )
        self.assertNotIn("HostFail", directory_mark)
        self.assertNotIn("ServiceEndpoint", directory_mark)
        self.assertNotIn("HandleTable", directory_mark)

        production_occurrences: dict[str, int] = {}
        leaf_pattern = re.compile(r"\bServiceDirectoryCommitJointReady\s*\(")
        for path in (ROOT / "kernel").rglob("*.cpp"):
            count = len(leaf_pattern.findall(path.read_text(encoding="utf-8")))
            if count:
                production_occurrences[path.relative_to(ROOT).as_posix()] = count
        self.assertEqual(
            production_occurrences,
            {
                "kernel/core/service_directory.cpp": 1,
                "kernel/core/service_lifecycle_broker.cpp": 1,
            },
        )
        self.assertIn("single-callsite", DIRECTORY_H)
        self.assertIn("no other production caller", DIRECTORY_H)

        dependencies = braced_body(BROKER_CPP, "bool DependenciesAreRunningLocked")
        self.assertIn("!dependency.ready", dependencies)
        publication = braced_body(
            BROKER_CPP,
            "ServiceLifecycleDirectoryPublicationResult ServiceLifecycleBrokerCommitDirectoryPublication",
        )
        self.assertLess(publication.index("row.ready = false"), publication.index("ServiceDirectoryPublishRegistration"))

    def test_only_connect_is_gated_while_owner_control_paths_remain_available(self) -> None:
        lookup = braced_body(DIRECTORY_CPP, "ServiceDirectoryLookupResult ServiceDirectoryLookup")
        connect = braced_body(DIRECTORY_CPP, "ServiceDirectoryConnectResult ServiceDirectoryConnect")
        accept = braced_body(DIRECTORY_CPP, "ServiceDirectoryAcceptResult ServiceDirectoryAccept")
        self.assertNotIn("row.ready", lookup)
        self.assertNotIn("row->ready", lookup)
        self.assertIn("!row->ready", connect)
        self.assertNotIn("row.ready", accept)
        self.assertNotIn("row->ready", accept)
        close = braced_body(DIRECTORY_CPP, "ServiceDirectoryCloseResult CloseEntry")
        self.assertLess(close.index("row->ready = false"), close.index("row->state = ServiceDirectoryEntryState::Closing"))

    def test_hostile_tests_cover_failure_identity_success_and_stop_race(self) -> None:
        for token in (
            "ServiceDirectoryHostFailNextRegistrationPublicationForTest",
            "ServiceTransitionPhase::Starting",
            "ServiceTransitionPhase::Failed",
            "ServiceDirectoryEntryState::Reserved",
            "ServiceDirectoryEntryState::Active",
            "ServiceDirectoryStatus::OwnerMismatch",
            "ServiceLifecycleBrokerMarkReady",
            "ServiceDirectoryStatus::QueueEmpty",
            "EXPECT_TRUE(lifecycle.ready)",
            "EXPECT_TRUE(directory.snapshot.ready)",
            "std::barrier",
            "ServiceLifecycleBrokerRequestStop",
            "lifecycle.phase != ServiceTransitionPhase::Running",
        ):
            self.assertIn(token, HOST_TEST)

    def test_live_boot_activation_is_wired(self) -> None:
        self.assertIn("Activation transaction", ACTIVATION_H)
        self.assertIn("ServiceBootstrapLiveActivateAllV1", ACTIVATION_H)


if __name__ == "__main__":
    unittest.main()
