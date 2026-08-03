#!/usr/bin/env python3
"""Structural guards for live authenticated service activation."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/core/service_bootstrap_activation.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/core/service_bootstrap_activation.cpp").read_text(encoding="utf-8")
STAGE_HEADER = (ROOT / "kernel/core/service_bootstrap_stage.h").read_text(encoding="utf-8")
STAGE_SOURCE = (ROOT / "kernel/core/service_bootstrap_stage.cpp").read_text(encoding="utf-8")
DOMAIN_HEADER = (ROOT / "kernel/proc/resource_domain.h").read_text(encoding="utf-8")
DOMAIN_SOURCE = (ROOT / "kernel/proc/resource_domain.cpp").read_text(encoding="utf-8")
BROKER_SOURCE = (ROOT / "kernel/core/service_lifecycle_broker.cpp").read_text(encoding="utf-8")
PROCESS_SOURCE = (ROOT / "kernel/proc/process.cpp").read_text(encoding="utf-8")
HOST_CMAKE = (ROOT / "tests/host/CMakeLists.txt").read_text(encoding="utf-8")
WIKI = (ROOT / "wiki/kernel/Service-Bootstrap.md").read_text(encoding="utf-8")


class ServiceBootstrapActivationContract(unittest.TestCase):
    def test_stage_receipt_is_exact_nonwrapping_and_alias_safe(self) -> None:
        for token in (
            "ServiceBootstrapActivationStateV1::Staged",
            "ServiceBootstrapActivationStateV1::Activating",
            "ServiceBootstrapActivationStateV1::TransferredPublished",
            "ServiceBootstrapActivationStateV1::ConsumedFailed",
            "kServiceBootstrapActivationGenerationMaximum",
            "receipt.registry_identity == runtime.registry_identity",
            "receipt.activation_generation == row.activation_generation",
            "receipt.memory_object == row.memory_object",
        ):
            self.assertIn(token, STAGE_SOURCE + STAGE_HEADER)
        begin = STAGE_SOURCE[
            STAGE_SOURCE.index("ServiceBootstrapStageBeginActivationV1(") :
            STAGE_SOURCE.index("ServiceBootstrapStageCancelActivationV1(")
        ]
        self.assertLess(begin.index("RangesOverlap"), begin.index("ZeroBytes(lease_out"))
        self.assertLess(begin.index("RuntimeStructureIsCanonical"), begin.index("ZeroBytes(lease_out"))
        self.assertLess(begin.index("ActivationLeaseAliasesRetainedStorage"), begin.index("ZeroBytes(lease_out"))
        self.assertIn("ActivationGenerationExhausted", begin)
        aliases = STAGE_SOURCE[
            STAGE_SOURCE.index("bool ActivationLeaseAliasesRetainedStorage") : STAGE_SOURCE.index("} // namespace")
        ]
        for token in (
            "runtime.rows",
            "image.pages",
            "image.regions",
            "image.plan_storage",
            "admission.storage",
            "object.bytes",
        ):
            self.assertIn(token, aliases)

    def test_dependency_readiness_and_reserve_share_the_broker_lock(self) -> None:
        reserve = BROKER_SOURCE[
            BROKER_SOURCE.index("ServiceLifecycleBrokerReserveStartWithDependencies(") :
            BROKER_SOURCE.index("ServiceLifecycleBrokerRecordSpawnFailure(")
        ]
        self.assertLess(reserve.index("SpinLockGuard"), reserve.index("ReserveStartLocked"))
        shared = BROKER_SOURCE[
            BROKER_SOURCE.index("ServiceLifecycleStartResult ReserveStartLocked") :
            BROKER_SOURCE.index("} // namespace", BROKER_SOURCE.index("ServiceLifecycleStartResult ReserveStartLocked"))
        ]
        self.assertIn("DependenciesAreRunningLocked", shared)
        self.assertIn("DependencyNotReady", shared)
        self.assertIn("!dependency.ready", BROKER_SOURCE)

    def test_transaction_order_and_exact_publication_gate_are_frozen(self) -> None:
        body = SOURCE[SOURCE.index("ServiceBootstrapActivationResultV1 ActivateWithPlatform") :]
        tokens = (
            "ServiceObjectPackageGetManifestV1",
            "ServiceLifecycleBrokerDescribe",
            "ServiceObjectPackageResolveExecutableV1",
            "ServiceBootstrapStageBeginActivationV1",
            "ServiceLifecycleBrokerReserveStartWithDependencies",
            "ServiceExitObserverReserve",
            "ResourceDomainCreateBoundedAuthenticatedService",
            "create_address_space",
            "UserStackPlan",
            "reserve_user_range",
            "map_reserved_user_page",
            "LoadImageMapInto",
            "create_process",
            "configure_process_stack",
            "replace_resource_domain",
            "install_publication_gate",
            "create_user_task_prepared",
            "ServiceBootstrapStageFinishActivationV1",
        )
        cursor = 0
        for token in tokens:
            found = body.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)
        gate = SOURCE[SOURCE.index("bool CommitLifecyclePublication") : SOURCE.index("struct TaskPrepareContext")]
        self.assertLess(gate.index("ServiceExitObserverBindAtSchedulerPublication"),
                        gate.index("ServiceLifecycleBrokerCommitPublication"))
        self.assertIn("ServiceLifecycleBrokerCommitPublication", gate)
        self.assertIn("ServiceInstanceKey{process.identity, process.pid}", gate)
        self.assertIn("process, *context->directory_registration", gate)
        self.assertIn("context->directory, context->directory_registration", gate)
        self.assertGreater(gate.index("ServiceExitObserverRollbackBound"),
                           gate.index("ServiceLifecycleBrokerCommitPublication"))

    def test_exit_observer_registration_is_failure_atomic_and_reaper_publishes_terminal_state(self) -> None:
        failure = SOURCE[SOURCE.index("auto fail =") : SOURCE.index("const ServiceLifecycleStartResult lifecycle")]
        self.assertIn("ServiceExitObserverAbort", failure)
        self.assertIn("exit_observer_cleanup_status", failure)

        publication_start = SOURCE.index("PublicationContext publication")
        publication = SOURCE[publication_start : SOURCE.index("result.stage_status =", publication_start)]
        for token in (
            "publication.bind_status",
            "publication.rollback_status",
            "ExitObserverCleanupFailed",
        ):
            self.assertIn(token, publication)

        reaper = PROCESS_SOURCE[
            PROCESS_SOURCE.index("void ProcessCompleteExitFromReaper") :
            PROCESS_SOURCE.index("void ProcessRelease", PROCESS_SOURCE.index("void ProcessCompleteExitFromReaper"))
        ]
        cursor = 0
        for token in (
            "TeardownProcessRuntimeResources(process, true)",
            "ProcessLifecycleTransition(process, ProcessLifecycleState::Exiting, ProcessLifecycleState::Exited)",
            "ProcessKeySnapshot(process)",
            "ProcessWin32ExitCodeSnapshot(process)",
            "ServiceExitObserverPublishKernelProcessExit",
        ):
            found = reaper.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)
        for benign in (
            "ServiceExitObserverStatus::NotFound",
            "ServiceExitObserverStatus::NotInitialized",
            "ServiceExitObserverStatus::Closed",
        ):
            self.assertIn(benign, reaper)

    def test_stack_and_image_mapping_enforce_ownership_and_wx(self) -> None:
        self.assertIn("kUserStackReserveMin", SOURCE)
        self.assertIn("kUserStackCommitMinPages", SOURCE)
        self.assertIn("result.stack.top - 8", SOURCE)
        self.assertRegex(
            SOURCE,
            re.compile(
                r"kPagePresent\s*\|\s*mm::kPageUser\s*\|\s*mm::kPageWritable\s*\|\s*mm::kPageNoExecute",
                re.MULTILINE,
            ),
        )
        self.assertIn("PageFlagsForProtection", SOURCE)
        exact_unmap = SOURCE[
            SOURCE.index("bool ProductionUnmapImageExact") : SOURCE.index("const fs::RamfsNode* ProductionTrustedRoot")
        ]
        self.assertIn("AddressSpaceLookupUserFrame", exact_unmap)
        self.assertIn("AddressSpaceUnmapUserPage", exact_unmap)

    def test_transferred_frames_unwind_only_through_private_graph_teardown(self) -> None:
        self.assertNotIn("LoadImageRelease", SOURCE)
        failure = SOURCE[SOURCE.index("auto fail =") : SOURCE.index("const ServiceLifecycleStartResult lifecycle")]
        self.assertIn("release_process", failure)
        self.assertIn("release_address_space", failure)
        self.assertIn("ConsumedFailed", failure)
        self.assertIn("AddressSpaceRelease(address_space)", SOURCE)

    def test_signed_limits_are_exact_not_profile_defaults(self) -> None:
        self.assertIn("ResourceDomainCreateBoundedAuthenticatedService", DOMAIN_HEADER)
        bounded = DOMAIN_SOURCE[
            DOMAIN_SOURCE.index("bool ResourceDomainCreateBoundedAuthenticatedService") :
            DOMAIN_SOURCE.index("bool ResourceDomainRetain")
        ]
        self.assertIn("requested_section_objects > kAuthenticatedServiceSectionObjectLimit", bounded)
        self.assertIn("requested_section_pages > kAuthenticatedServiceSectionPageLimit", bounded)
        process = SOURCE[SOURCE.index("process = platform->create_process") :]
        self.assertIn("const CapSet caps{service->requested_capability_ceiling}", SOURCE)
        self.assertIn("service->requested_tick_budget", process)
        self.assertIn("caps", process)

    def test_postpublication_stage_commit_is_a_production_invariant(self) -> None:
        tail = SOURCE[SOURCE.index("result.task =") :]
        self.assertIn("KASSERT(result.stage_status == ServiceBootstrapStageStatus::Ok", tail)
        self.assertIn("published service could not commit exact stage receipt", tail)

    def test_live_activation_boundary_and_host_gate_are_registered(self) -> None:
        self.assertIn("Activation transaction", HEADER)
        self.assertIn("ServiceBootstrapLiveActivateAllV1", HEADER)
        self.assertIn("add_host_test(service_bootstrap_activation)", HOST_CMAKE)
        self.assertIn("kernel/core/service_bootstrap_activation.cpp", HOST_CMAKE)
        self.assertIn("activation consumer", WIKI)
        self.assertIn("ActivationReady = true", WIKI)


if __name__ == "__main__":
    unittest.main()
