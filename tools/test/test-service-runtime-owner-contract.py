#!/usr/bin/env python3
"""Structural contract for the static service-runtime owner."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/core/service_runtime.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/core/service_runtime.cpp").read_text(encoding="utf-8")


class ServiceRuntimeOwnerContract(unittest.TestCase):
    def test_owner_embeds_every_static_lifetime_component(self) -> None:
        body = HEADER[HEADER.index("struct ServiceRuntimeV1") : HEADER.index("struct ServiceRuntimeInitializeResultV1")]
        for token in (
            "ServiceBootstrapStageRuntimeV1* stage",
            "ServiceLifecycleBroker lifecycle",
            "ServiceExitObserver exit_observer",
            "ServiceEndpointOwner endpoint_owner",
            "ServiceDirectory directory",
            "ServiceExitReapLedger exit_reap_ledger",
        ):
            self.assertIn(token, body)

    def test_preflight_precedes_every_irreversible_initialization(self) -> None:
        body = SOURCE[SOURCE.index("ServiceRuntimeInitializeResultV1 InitializeRuntime") : SOURCE.index("} // namespace")]
        order = (
            "RuntimeStorageIsPristine(*runtime)",
            "ServiceBootstrapStageInspectV1",
            "ServiceObjectPackageGetManifestV1",
            "ServiceLifecycleBrokerMintEpoch",
            "ServiceLifecycleBrokerInitialize",
            "ServiceExitObserverMintEpoch",
            "ServiceExitObserverInitialize",
            "ServiceEndpointOwnerInitialize",
            "ServiceDirectoryInitialize",
            "ServiceExitReapLedgerInitialize",
            "ServiceExitObserverInstallKernelObserver",
            "ServiceRuntimeStateV1::Open",
        )
        cursor = 0
        for token in order:
            found = body.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)

    def test_global_runtime_is_not_exposed_before_open(self) -> None:
        anchor = "ServiceRuntimeV1* ServiceRuntimeKernelLookupV1"
        getter = SOURCE[SOURCE.index(anchor) : SOURCE.index("#else", SOURCE.index(anchor))]
        self.assertIn("kServiceRuntimeInitializedMarkerV1", getter)
        self.assertIn("ServiceRuntimeStateV1::Open", getter)
        self.assertIn("return &g_kernel_service_runtime;", getter)

    def test_kernel_lookup_classifies_from_a_single_state_load(self) -> None:
        # Two loads let a legal Initializing->Open transition land between the
        # reject and the classify, which reads as CorruptState and panics the
        # reaper. Every kernel entry point must classify off one snapshot.
        lookup = SOURCE[
            SOURCE.index("ServiceRuntimeV1* ServiceRuntimeKernelLookupV1") : SOURCE.index(
                "ServiceRuntimeV1* ServiceRuntimeKernelV1"
            )
        ]
        self.assertEqual(lookup.count("RuntimeStateLoad(&g_kernel_service_runtime)"), 1)
        kernel_entry_points = SOURCE[
            SOURCE.index("ServiceRuntimeV1* ServiceRuntimeKernelV1") : SOURCE.index(
                "#else", SOURCE.index("ServiceRuntimeV1* ServiceRuntimeKernelV1")
            )
        ]
        self.assertNotIn("RuntimeStateLoad(&g_kernel_service_runtime)", kernel_entry_points)

    def test_host_path_cannot_install_global_observer(self) -> None:
        self.assertRegex(SOURCE, r"#if !defined\(DUETOS_HOST_TEST\)\s+if \(install_kernel_observer\)")
        host = SOURCE[SOURCE.index("ServiceRuntimeInitializeResultV1 ServiceRuntimeInitializeForTestV1") : SOURCE.index("#endif", SOURCE.index("ServiceRuntimeInitializeResultV1 ServiceRuntimeInitializeForTestV1"))]
        self.assertIn("InitializeRuntime(runtime, stage, false)", host)

    def test_failure_is_terminal_not_reset_in_place(self) -> None:
        self.assertGreaterEqual(SOURCE.count("RuntimeStateStore(runtime, ServiceRuntimeStateV1::Failed)"), 6)
        self.assertNotIn("ServiceRuntimeReset", HEADER + SOURCE)

    def test_inspection_revalidates_exact_stage_identity(self) -> None:
        inspect = SOURCE[SOURCE.index("ServiceRuntimeStatusV1 ServiceRuntimeInspectV1") : SOURCE.index("const char* ServiceRuntimeStatusNameV1")]
        self.assertIn("lifecycle.snapshot.manifest_identity", inspect)
        self.assertIn("runtime->stage->package.manifest_plan.document.manifest_identity", inspect)
        self.assertIn("lifecycle.snapshot.manifest_authority_identity != stage.authority_identity", inspect)
        self.assertIn("stage.registry_identity == 0", inspect)
        self.assertIn("snapshot.stage_registry_identity = stage.registry_identity", inspect)
        self.assertIn("ServiceExitReapLedgerInspect", inspect)
        self.assertIn("exit_reap.state != ServiceExitReapLedgerState::Open", inspect)

    def test_activation_authority_exposes_only_the_embedded_ledger(self) -> None:
        authority = HEADER[
            HEADER.index("struct ServiceRuntimeActivationAuthorityV1") :
            HEADER.index("#if !defined(DUETOS_HOST_TEST)")
        ]
        bind = SOURCE[
            SOURCE.index("ServiceRuntimeStatusV1 ServiceRuntimeBindActivationAuthorityV1") :
            SOURCE.index("const char* ServiceRuntimeStatusNameV1")
        ]
        self.assertIn("ServiceExitReapLedger* exit_reap_ledger", authority)
        self.assertIn("&runtime->exit_reap_ledger", bind)

    def test_exit_reap_maintenance_is_bounded_ordered_and_clock_agnostic(self) -> None:
        self.assertIn("kServiceRuntimeExitReapAcquireBudgetV1 = 1", HEADER)
        self.assertIn("kServiceRuntimeExitReapPumpStepBudgetV1 = 4", HEADER)
        drive = SOURCE[
            SOURCE.index("ServiceRuntimeDriveExitReapResultV1 DriveExitReap(") :
            SOURCE.index("ServiceRuntimeInitializeResultV1 InitializeRuntime")
        ]
        order = (
            "ServiceRuntimeInspectV1",
            "ServiceExitReapLedgerAcquireFromObserver",
            "ServiceExitReapLedgerPump",
        )
        cursor = 0
        for token in order:
            found = drive.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)
        self.assertIn("attempt < kServiceRuntimeExitReapAcquireBudgetV1", drive)
        self.assertIn("now_ns, kServiceRuntimeExitReapPumpStepBudgetV1", drive)
        self.assertNotIn("MonotonicNs", drive)
        self.assertIn("ServiceRuntimeDriveExitReapKernelV1(u64 now_ns)", HEADER + SOURCE)
        self.assertIn("ServiceRuntimeDriveExitReapForTestV1(ServiceRuntimeV1* runtime, u64 now_ns)", HEADER + SOURCE)

    def test_no_runtime_policy_or_scheduler_entry(self) -> None:
        forbidden = (
            "SchedCreate",
            "ServiceBootstrapActivate",
            "restart_policy",
            "CopyFromUser",
            "CopyToUser",
            "ProcessCreate",
        )
        for token in forbidden:
            self.assertNotIn(token, SOURCE)


if __name__ == "__main__":
    unittest.main()
