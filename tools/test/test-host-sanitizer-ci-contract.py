#!/usr/bin/env python3
"""Structural contract for deterministic Rust-backed ASan/UBSan and TSan CI."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class HostSanitizerCiContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = read(".github/workflows/build.yml")
        cls.cmake = read("tests/host/CMakeLists.txt")
        cls.spinlock = read("tests/fuzz/host_shim/sync/spinlock.h")

    def test_ci_runs_both_sanitizer_modes(self) -> None:
        self.assertIn("sanitizer: [asan-ubsan, thread]", self.workflow)
        self.assertIn("DUETOS_HOST_TESTS_SANITIZERS=${{ matrix.sanitizer == 'asan-ubsan' }}", self.workflow)
        self.assertIn("DUETOS_HOST_TESTS_TSAN=${{ matrix.sanitizer == 'thread' }}", self.workflow)

    def test_host_job_installs_repo_pinned_rust(self) -> None:
        host_job = self.workflow.split("\n  host-tests:\n", 1)[1].split(
            "\n  pre-publish-lifetime-snapshot:", 1
        )[0]
        self.assertIn("sh -s -- -y --default-toolchain none --profile minimal", host_job)
        self.assertIn("rustup show", host_job)
        self.assertIn("rustc --version --verbose", host_job)

    def test_cmake_rejects_composed_sanitizer_runtimes(self) -> None:
        self.assertIn('option(DUETOS_HOST_TESTS_TSAN "Enable ThreadSanitizer', self.cmake)
        self.assertIn("DUETOS_HOST_TESTS_SANITIZERS AND DUETOS_HOST_TESTS_TSAN", self.cmake)
        self.assertIn("-fsanitize=thread", self.cmake)
        self.assertIn("-fsanitize=address,undefined", self.cmake)

    def test_hosted_spinlock_is_tsan_visible(self) -> None:
        self.assertIn("#if defined(DUETOS_HOST_TEST)", self.spinlock)
        self.assertIn("__atomic_fetch_add(&lock.next_ticket", self.spinlock)
        self.assertIn("__atomic_load_n(&lock.now_serving, __ATOMIC_ACQUIRE)", self.spinlock)
        self.assertIn("__atomic_fetch_add(&lock.now_serving", self.spinlock)
        self.assertIn("__ATOMIC_RELEASE", self.spinlock)

    def test_ci_enrolls_this_contract(self) -> None:
        self.assertIn("python3 tools/test/test-host-sanitizer-ci-contract.py", self.workflow)


if __name__ == "__main__":
    unittest.main()
