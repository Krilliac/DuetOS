#!/usr/bin/env python3
"""Structural guards for authority-bound unpublished service staging."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/core/service_bootstrap_stage.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/core/service_bootstrap_stage.cpp").read_text(encoding="utf-8")
LOAD_HEADER = (ROOT / "kernel/loader/load_image.h").read_text(encoding="utf-8")
LOAD_SOURCE = (ROOT / "kernel/loader/load_image.cpp").read_text(encoding="utf-8")
ADMISSION_HEADER = (ROOT / "kernel/loader/exec_admission.h").read_text(encoding="utf-8")
ADMISSION_SOURCE = (ROOT / "kernel/loader/exec_admission.cpp").read_text(encoding="utf-8")
KERNEL_CMAKE = (ROOT / "kernel/CMakeLists.txt").read_text(encoding="utf-8")
HOST_CMAKE = (ROOT / "tests/host/CMakeLists.txt").read_text(encoding="utf-8")
WIKI = (ROOT / "wiki/kernel/Service-Bootstrap.md").read_text(encoding="utf-8")


class ServiceBootstrapStageContract(unittest.TestCase):
    def test_generated_definition_is_consumed_without_claiming_readiness(self) -> None:
        self.assertIn('#include "service-package/generated_boot_service_package_data.h"', SOURCE)
        self.assertIn("generated::kBootServicePackageDefinition", SOURCE)
        self.assertIn("static_assert(generated::kBootServicePackageAuthorityBound)", SOURCE)
        self.assertIn("static_assert(!generated::kBootServicePackageBootstrapPlansBound)", SOURCE)
        self.assertIn("static_assert(!generated::kBootServicePackageActivationReady)", SOURCE)

    def test_package_resolution_staging_and_admission_are_ordered(self) -> None:
        body = SOURCE[SOURCE.index("ServiceBootstrapStageInitializeV1(") :]
        tokens = (
            "ServiceObjectPackageInitializeV1",
            "ServiceObjectPackageGetManifestV1",
            "PreflightSlots",
            "ServiceObjectPackageResolveExecutableV1",
            "PrepareStagedRow",
            "ServiceBootstrapStageState::Ready",
        )
        cursor = 0
        for token in tokens:
            found = body.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)

        prepare = SOURCE[SOURCE.index("ServiceBootstrapStageResultV1 PrepareStagedRow") : SOURCE.index("bool ImageOwnershipIsCanonical")]
        prepare_tokens = (
            "ElfLoadImagePrepare",
            "LoadImageInspect",
            "LoadImagePlanBytes",
            "ExecAdmissionInitialize",
            "ExecAdmissionPrepare",
            "ExecAdmissionConsume",
        )
        cursor = 0
        for token in prepare_tokens:
            found = prepare.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)

    def test_memory_object_identity_is_runtime_minted_and_exactly_scoped(self) -> None:
        self.assertIn("kServiceBootstrapMemoryObjectTypeTag", HEADER)
        self.assertIn("MemoryObjectForManifestIndex(runtime->registry_identity, manifest_index)", SOURCE)
        self.assertIn("MintRegistryIdentity", SOURCE)
        self.assertIn("kServiceBootstrapMemoryObjectRegistryMaximum", SOURCE)
        self.assertIn("MemoryObjectMatchesManifestIndex(memory_object, manifest_index)", SOURCE)
        self.assertNotIn("encoded_registry != runtime.registry_identity", SOURCE)
        scoped = SOURCE[SOURCE.index("bool ScopedBackingQuery(") : SOURCE.index("bool RuntimeIsCanonical(")]
        self.assertIn("memory_object != row.memory_object", scoped)
        self.assertIn("LoadImageBackingQuery", scoped)
        backing = SOURCE[SOURCE.index("bool ServiceBootstrapStageBackingQueryV1") : SOURCE.index("ServiceBootstrapStageInspectV1")]
        self.assertIn("row.memory_object != memory_object", backing)
        self.assertIn("MemoryObjectMatchesManifestIndex(memory_object, manifest_index)", backing)
        slot = re.search(
            r"struct\s+ServiceBootstrapSlotStorageV1\s*\{(?P<body>.*?)\};",
            HEADER,
            re.DOTALL,
        )
        self.assertIsNotNone(slot)
        self.assertNotRegex(slot.group("body"), r"ObjectHandle\s+memory_object")

    def test_all_storage_is_preflighted_before_any_frame_staging(self) -> None:
        initialize = SOURCE[SOURCE.index("ServiceBootstrapStageInitializeV1(") :]
        self.assertLess(initialize.index("PreflightSlots"), initialize.index("PrepareStagedRow"))
        preflight = SOURCE[SOURCE.index("ServiceBootstrapStageStatus PreflightSlots") : SOURCE.index("bool ResetImageAndAdmission")]
        for needle in (
            "SlotShapeIsValid",
            "SlotStorageOverlap",
            "definition.manifest_bytes",
            "definition.manifest_authority",
            "artifact.bytes",
        ):
            self.assertIn(needle, preflight)

    def test_failure_releases_prior_images_and_no_activation_primitive_appears(self) -> None:
        initialize = SOURCE[SOURCE.index("ServiceBootstrapStageInitializeV1(") :]
        self.assertGreaterEqual(initialize.count("ResetSlotOutputs(slots, service_count)"), 5)
        self.assertIn("LoadImageRelease(image)", SOURCE)
        for forbidden in (
            "LoadImageMapInto",
            "ProcessCreate",
            "SchedCreate",
            "PublishCreatedTask",
            "ServiceLifecycleBrokerInitialize",
        ):
            self.assertNotIn(forbidden, initialize)
        self.assertIn("does not map an AddressSpace", HEADER)

    def test_service_kind_and_authorized_frame_budget_are_consumed(self) -> None:
        initialize = SOURCE[SOURCE.index("ServiceBootstrapStageInitializeV1(") :]
        self.assertIn("service.kind != ServiceManifestKind::Native", SOURCE)
        self.assertIn("service.kind != ServiceManifestKind::Broker", SOURCE)
        self.assertIn("BudgetedAllocateFrame", SOURCE)
        self.assertIn("row->frame_allocations >= row->frame_budget_pages", SOURCE)
        self.assertIn("row.frame_budget_exhausted != 0", SOURCE)
        self.assertIn("budgeted_frame_hooks", SOURCE)
        self.assertIn("image_snapshot.present_pages > service.requested_frame_budget_pages", SOURCE)
        self.assertIn("ResourceBudgetExceeded", SOURCE)
        prepare = SOURCE[SOURCE.index("ServiceBootstrapStageResultV1 PrepareStagedRow") : SOURCE.index("bool ImageOwnershipIsCanonical")]
        mismatch = prepare.index("image_snapshot.present_pages != row->frame_allocations")
        over_budget = prepare.index("image_snapshot.present_pages > service.requested_frame_budget_pages")
        self.assertLess(mismatch, over_budget)
        self.assertIn("ServiceBootstrapStageStatus::CorruptRuntime", prepare[mismatch:over_budget])
        self.assertIn("must outlive it", HEADER)

    def test_restage_is_off_row_failure_atomic_and_commits_last(self) -> None:
        restage = SOURCE[SOURCE.index("ServiceBootstrapStageResultV1 ServiceBootstrapStageRestageV1") : SOURCE.index("ServiceBootstrapStageStatus ServiceBootstrapStageDiscardV1")]
        tokens = (
            "expected_activation_generation != selected->activation_generation",
            "TerminalRowOwnsNoPackageFrames",
            "ResolveRestageBank",
            "PreflightRestageSlot",
            "ExecAdmissionQuiescentSuccessorIdentity",
            "ServiceObjectPackageResolveExecutableV1",
            "MintRegistryIdentity",
            "ResetRetiredRestageSlot",
            "PrepareStagedRow",
            "CopyBankRegistry",
            "BindBank",
            "RowStructureIsCanonical",
            "AdoptPreparedRow",
        )
        cursor = 0
        for token in tokens:
            found = restage.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)
        commit = "AdoptPreparedRow(selected, prepared);"
        after_commit = restage[restage.index(commit) + len(commit) :]
        self.assertNotIn("Reset", after_commit)
        self.assertNotIn("Prepare", after_commit)
        self.assertIn("permanent caller-owned runtime storage", HEADER)
        self.assertIn("must not\n// live in the Restage call frame", HEADER)

        self.assertIn("struct ServiceBootstrapStageBankBindingV1", HEADER)
        for owner_field in ("runtime_registry_identity", "service_identity", "activation_generation", "manifest_index"):
            self.assertIn(owner_field, HEADER[HEADER.index("struct ServiceBootstrapStageBankBindingV1") :])
        resolve = SOURCE[SOURCE.index("ServiceBootstrapStageStatus ResolveRestageBank") : SOURCE.index("ServiceBootstrapStageStatus PreflightRestageSlot")]
        self.assertIn("SlotDescriptorsEqual", resolve)
        self.assertIn("row.active_bank_index", resolve)
        self.assertIn("row.bank_count >= kServiceBootstrapStageBankCapacityV1", resolve)
        self.assertIn("newly_registered_bank && !SlotShapeIsValid(*replacement)", restage)
        self.assertLess(restage.index("newly_registered_bank && !SlotShapeIsValid(*replacement)"), restage.index("ResetRetiredRestageSlot"))
        preflight = SOURCE[SOURCE.index("ServiceBootstrapStageStatus PreflightRestageSlot") : SOURCE.index("bool ResetImageAndAdmission")]
        self.assertIn("row.banks[bank_index].storage", preflight)
        self.assertIn("replacement_is_registered", preflight)

    def test_retired_banks_use_loader_owned_quiescent_resets(self) -> None:
        reset = SOURCE[SOURCE.index("bool ResetImageAndAdmission") : SOURCE.index("bool RetiredSlotBindingsMatch")]
        self.assertIn("LoadImageRelease", reset)
        self.assertIn("LoadImageResetQuiescent", reset)
        self.assertIn("ExecAdmissionResetQuiescent", reset)
        self.assertNotIn("ZeroBytes", reset)
        self.assertNotIn("memset", reset)

        retired_reset = SOURCE[SOURCE.index("ServiceBootstrapStageStatus ResetRetiredRestageSlot") : SOURCE.index("void ResetSlotOutputs")]
        for needle in (
            "LoadImageCanResetQuiescent",
            "ExecAdmissionCanResetQuiescent",
            "LoadImageResetQuiescent",
            "ExecAdmissionResetQuiescent",
        ):
            self.assertIn(needle, retired_reset)
        self.assertLess(retired_reset.index("LoadImageCanResetQuiescent"), retired_reset.index("LoadImageResetQuiescent"))
        self.assertLess(retired_reset.index("ExecAdmissionCanResetQuiescent"), retired_reset.index("ExecAdmissionResetQuiescent"))

        load_reset = LOAD_SOURCE[LOAD_SOURCE.index("LoadImageStatus LoadImageCanResetQuiescent") : LOAD_SOURCE.index("LoadImageStatus LoadImageClaimRange")]
        self.assertIn("LoadImageState::Transferred", load_reset)
        self.assertIn("LoadImageState::Failed", load_reset)
        self.assertIn("LoadImagePageState::PackageOwned", load_reset)
        self.assertIn("LoadImageStatus::OwnershipOutstanding", load_reset)
        self.assertIn("LoadImageCanResetQuiescent(image)", load_reset)
        self.assertIn("LoadImageCanResetQuiescent", LOAD_HEADER)
        self.assertIn("LoadImageResetQuiescent", LOAD_HEADER)
        self.assertIn("independent", LOAD_HEADER)
        self.assertIn("neither freed nor made reusable", LOAD_HEADER)

        admission_reset = ADMISSION_SOURCE[ADMISSION_SOURCE.index("ExecAdmissionStatus ExecAdmissionCanResetQuiescent") : ADMISSION_SOURCE.index("ExecAdmissionPrepareResult ExecAdmissionPrepare")]
        self.assertIn("LockIsQuiescent", admission_reset)
        self.assertIn("active_identity != 0", admission_reset)
        self.assertIn("cancel_requested != 0", admission_reset)
        self.assertIn("ResetLockCanonicalZero", admission_reset)
        self.assertIn("ExecAdmissionCanResetQuiescent(admission)", admission_reset)
        self.assertIn("ExecAdmissionQuiescentSuccessorIdentity", ADMISSION_HEADER)
        self.assertIn("ExecAdmissionCanResetQuiescent", ADMISSION_HEADER)
        self.assertIn("ExecAdmissionResetQuiescent", ADMISSION_HEADER)

    def test_discard_distinguishes_ownership_advance_from_corruption(self) -> None:
        discard = SOURCE[SOURCE.index("ServiceBootstrapStageStatus ServiceBootstrapStageDiscardV1(") :]
        self.assertIn("RuntimeStructureIsCanonical(*runtime, false)", discard)
        self.assertIn("ServiceBootstrapActivationStateV1::Staged", discard)
        self.assertIn("ImageIsSealedPackageOwned", discard)
        self.assertIn("ServiceBootstrapStageStatus::CannotDiscard", discard)

    def test_build_host_contract_and_activation_gap_are_registered(self) -> None:
        self.assertIn("add_dependencies(duetos-kernel-stage1 duetos-service-package-data)", KERNEL_CMAKE)
        self.assertIn("add_dependencies(duetos-kernel duetos-service-package-data)", KERNEL_CMAKE)
        self.assertIn("add_host_test(service_bootstrap_stage)", HOST_CMAKE)
        self.assertIn("kernel/core/service_bootstrap_stage.cpp", HOST_CMAKE)
        self.assertIn("Why the readiness markers stay false", WIKI)
        self.assertIn("ActivationReady = false", WIKI)
        self.assertIn("scheduler publication lock", WIKI)
        self.assertRegex(WIKI, r"compiled(?:-| )but(?:-| )dormant")
        self.assertIn("section GC may discard", HEADER)


if __name__ == "__main__":
    unittest.main()
