#!/usr/bin/env python3
"""Hostile structural contract for the live, non-activating service anchor."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/core/service_bootstrap_live.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/core/service_bootstrap_live.cpp").read_text(encoding="utf-8")
BRINGUP = (ROOT / "kernel/core/boot_bringup.cpp").read_text(encoding="utf-8")
MAIN = (ROOT / "kernel/core/main.cpp").read_text(encoding="utf-8")
KERNEL_CMAKE = (ROOT / "kernel/CMakeLists.txt").read_text(encoding="utf-8")
PROFILE_RUNNER = (ROOT / "tools/test/profile-boot-smoke.sh").read_text(encoding="utf-8")
FULL_RUNNER = (ROOT / "tools/test/ctest-boot-smoke.sh").read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^)]*\)\s*\{{", source)
    if match is None:
        raise AssertionError(f"missing function {name}")
    opening = source.find("{", match.start())
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated function {name}")


class ServiceBootstrapLiveContract(unittest.TestCase):
    def test_fixed_storage_is_small_explicit_and_build_frozen(self) -> None:
        for token in (
            "kServiceBootstrapLiveServiceCapacityV1 = 5",
            "kServiceBootstrapLiveImageBytesPerServiceV1 = 64ULL * 1024ULL",
            "kServiceBootstrapLiveRegionsPerServiceV1 = 8",
            "kServiceBootstrapLiveTotalArtifactByteCapacityV1 = 256ULL * 1024ULL",
            "images[kServiceBootstrapLiveServiceCapacityV1]",
            "pages[kServiceBootstrapLiveServiceCapacityV1][kServiceBootstrapLivePagesPerServiceV1]",
            "plan_storage[kServiceBootstrapLiveServiceCapacityV1][loader::kLoadImageMaxPlanBytes]",
            "admissions[kServiceBootstrapLiveServiceCapacityV1]",
            "admission_storage[kServiceBootstrapLiveServiceCapacityV1][loader::kExecAdmissionMaxPlanBytes]",
        ):
            self.assertIn(token, HEADER + SOURCE)
        self.assertRegex(
            SOURCE,
            r"regions\[kServiceBootstrapLiveServiceCapacityV1\]\s*"
            r"\[kServiceBootstrapLiveRegionsPerServiceV1\]",
        )
        self.assertIn("kBootServicePackageArtifactCount == kServiceBootstrapLiveServiceCapacityV1", SOURCE)
        self.assertIn("kBootServicePackageTotalArtifactBytes <=", SOURCE)
        for forbidden in ("KMalloc(", "KFree(", "malloc(", "new ", "std::vector"):
            self.assertNotIn(forbidden, SOURCE)

    def test_frame_hooks_publish_canonical_outputs_and_pair_cleanup(self) -> None:
        allocate = function_body(SOURCE, "AllocateLiveFrame")
        release = function_body(SOURCE, "ReleaseLiveFrame")
        ordered = (
            "*frame_out = loader::kLoadImageInvalidFrame",
            "*writable_page_out = nullptr",
            "mm::AllocateFrame()",
            "mm::PhysToVirt(frame)",
        )
        cursor = 0
        for token in ordered:
            found = allocate.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)
        self.assertIn("mm::FreeFrame(frame)", release)
        self.assertIn("++g_service_bootstrap_live.release_count", release)

    def test_one_shot_count_preflight_stage_and_runtime_are_ordered(self) -> None:
        initialize = function_body(SOURCE, "ServiceBootstrapLiveInitializeV1")
        order = (
            "BeginOneShotInitialize()",
            "ServiceBootstrapGeneratedServiceCountV1()",
            "result.generated_service_count != kServiceBootstrapLiveServiceCapacityV1",
            "BuildSlotDescriptors(slots)",
            "ServiceBootstrapStageGeneratedV1",
            "ServiceRuntimeInitializeKernelV1",
            "ServiceBootstrapLiveStateV1::RuntimeOpenCompatibilityRequired",
        )
        cursor = 0
        for token in order:
            found = initialize.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)
        self.assertIn("__atomic_compare_exchange_n", SOURCE)

    def test_runtime_failure_discards_only_still_private_stage(self) -> None:
        initialize = function_body(SOURCE, "ServiceBootstrapLiveInitializeV1")
        runtime_failure = initialize[initialize.index("result.runtime.status != ServiceRuntimeStatusV1::Ok") :]
        self.assertLess(runtime_failure.index("ServiceBootstrapStageDiscardV1"),
                        runtime_failure.index("LiveStateStore(ServiceBootstrapLiveStateV1::Failed)"))
        self.assertIn("RuntimeFailedStageDiscardFailed", runtime_failure)
        self.assertIn("cannot be reset", initialize)

    def test_anchor_cannot_activate_or_publish_any_service(self) -> None:
        for forbidden in (
            "ServiceBootstrapActivateV1",
            "ServiceBootstrapStageBeginActivationV1",
            "SchedCreate",
            "ProcessCreate",
            "ServiceDirectoryRegister",
            "ServiceDirectoryPublish",
            "ServiceLifecycleBrokerMarkReady",
            "ServiceDirectoryCommitJointReady",
        ):
            self.assertNotIn(forbidden, SOURCE)
        self.assertIn("static_assert(!generated::kBootServicePackageActivationReady)", SOURCE)
        self.assertIn("process_count", HEADER)
        self.assertIn("published_endpoint_count", HEADER)

    def test_boot_call_is_unique_and_precedes_compatibility_manager(self) -> None:
        self.assertEqual(BRINGUP.count("ServiceBootstrapLiveInitializeV1()"), 1)
        devices = function_body(BRINGUP, "BootBringupDevices")
        self.assertLess(devices.index("ServiceBootstrapLiveInitializeV1()"), devices.index("ServiceManagerInit()"))
        self.assertIn("FrameAllocatorInit(multiboot_info)", BRINGUP)
        self.assertIn("RunInitArray()", BRINGUP)
        self.assertIn("PagingInit()", BRINGUP)
        main_order = ("BootBringupEarly(", "BootBringupMemPaging(", "BootBringupDevices(")
        cursor = 0
        for token in main_order:
            found = MAIN.find(token, cursor)
            self.assertGreaterEqual(found, 0, token)
            cursor = found + len(token)

    def test_fallback_log_never_claims_service_readiness(self) -> None:
        devices = function_body(BRINGUP, "BootBringupDevices")
        self.assertIn("activation disabled, compatibility manager retained", devices)
        self.assertIn("live anchor failed; compatibility manager retained", devices)
        self.assertIn("service_bootstrap.status == ServiceBootstrapLiveStatusV1::StageFailed", devices)
        self.assertIn("service_bootstrap.status == ServiceBootstrapLiveStatusV1::RuntimeFailed", devices)
        self.assertNotIn("services ready", devices)
        self.assertIn("RuntimeOpenCompatibilityRequired", HEADER)
        for explicit_zero in (
            "snapshot.activation_ready = 0",
            "snapshot.process_count = 0",
            "snapshot.published_endpoint_count = 0",
        ):
            self.assertIn(explicit_zero, SOURCE)

    def test_every_qemu_runner_requires_the_live_anchor(self) -> None:
        marker = "package staged and runtime open; activation disabled, compatibility manager retained"
        self.assertIn(marker, BRINGUP)
        self.assertIn(marker, PROFILE_RUNNER)
        self.assertIn(marker, FULL_RUNNER)
        self.assertIn("live anchor failed; compatibility manager retained", BRINGUP)

    def test_source_is_in_both_kernel_stages_via_configure_depends_glob(self) -> None:
        self.assertRegex(KERNEL_CMAKE, r"file\(GLOB_RECURSE DUETOS_KERNEL_SHARED_SOURCES")
        self.assertIn("CONFIGURE_DEPENDS", KERNEL_CMAKE)
        self.assertIn('"${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"', KERNEL_CMAKE)
        self.assertIn("add_executable(duetos-kernel-stage1", KERNEL_CMAKE)
        self.assertIn("add_executable(duetos-kernel", KERNEL_CMAKE)
        self.assertIn("add_dependencies(duetos-kernel-stage1 duetos-service-package-data)", KERNEL_CMAKE)
        self.assertIn("add_dependencies(duetos-kernel duetos-service-package-data)", KERNEL_CMAKE)


if __name__ == "__main__":
    unittest.main()
