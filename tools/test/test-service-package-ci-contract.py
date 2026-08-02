#!/usr/bin/env python3
"""Structural contract for service-package generation and CI verification."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class ServicePackageCiContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = read(".github/workflows/build.yml")
        cls.cmake = read("kernel/CMakeLists.txt")

    def test_debug_ci_runs_deterministic_package_verifier(self) -> None:
        debug = self.workflow.split("\n  build-debug:\n", 1)[1].split("\n  build-release:\n", 1)[0]
        self.assertIn("Verify deterministic service package and typed binding", debug)
        self.assertIn("--target duetos-service-package-verify --parallel 2", debug)

    def test_verifier_depends_on_generation_and_typed_compile_check(self) -> None:
        self.assertIn("add_custom_target(duetos-service-package-verify", self.cmake)
        self.assertIn(
            "add_dependencies(duetos-service-package-verify duetos-service-package-data)",
            self.cmake,
        )
        self.assertIn(
            "add_dependencies(duetos-service-package-verify duetos-service-package-data-compile-check)",
            self.cmake,
        )

    def test_typed_binding_stays_fail_closed_until_activation_is_bound(self) -> None:
        self.assertIn(
            "static_assert(duetos::core::generated::kBootServicePackageAuthorityBound)", self.cmake
        )
        self.assertIn(
            "static_assert(duetos::core::generated::kBootServicePackageBootstrapPlansBound)", self.cmake
        )
        self.assertIn(
            "static_assert(!duetos::core::generated::kBootServicePackageProcessPublicationBound)", self.cmake
        )
        self.assertIn(
            "static_assert(!duetos::core::generated::kBootServicePackageEndpointReadinessBound)", self.cmake
        )
        self.assertIn(
            "static_assert(!duetos::core::generated::kBootServicePackageActivationReady)", self.cmake
        )

    def test_ci_enrolls_this_contract(self) -> None:
        self.assertIn("python3 tools/test/test-service-package-ci-contract.py", self.workflow)


if __name__ == "__main__":
    unittest.main()
