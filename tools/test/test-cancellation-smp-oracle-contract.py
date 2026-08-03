#!/usr/bin/env python3
"""Structural contract for the verdict-bearing cancellation SMP profile."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class CancellationSmpOracleContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.oracle = read("kernel/test/cancellation_smp_oracle.cpp")
        cls.profile_h = read("kernel/test/smoke_profile.h")
        cls.profile_cpp = read("kernel/test/smoke_profile.cpp")
        cls.runner = read("tools/test/profile-boot-smoke.sh")
        cls.docs = read("wiki/tooling/QEMU-Smoke.md")
        cls.workflow = read(".github/workflows/build.yml")

    def test_profile_is_explicit_and_runs_after_bringup(self) -> None:
        self.assertIn("CancellationSmp", self.profile_h)
        self.assertIn('TokenMatches(value, end, "cancellation-smp")', self.profile_cpp)
        self.assertIn('return "cancellation-smp"', self.profile_cpp)
        self.assertIn("RunCancellationSmpOracle()", self.profile_cpp)
        self.assertIn("runtime cancellation oracle failed", self.profile_cpp)

    def test_publication_tombstone_has_overlap_and_post_kill_oracles(self) -> None:
        for token in (
            "SchedCreateUserPrepared",
            "SchedKillByProcess",
            "ProcessTerminationLoad",
            "ProcessTerminationState::Closed",
            '"cancel-publish-reject"',
            "WaitForProcessReaped",
        ):
            self.assertIn(token, self.oracle)

    def test_residual_wait_families_race_real_production_apis(self) -> None:
        for token in (
            "KMutexAcquireTimed",
            "KMutexRelease",
            "IocpWait",
            "kIocpRaceTicks",
            "KMessagePortWaitReadableHandle",
            "KMessagePortCloseHandle",
            "KObjectRefcount",
        ):
            self.assertIn(token, self.oracle)

    def test_workers_and_coordinator_are_bounded(self) -> None:
        self.assertIn("kControlWaitTicks", self.oracle)
        self.assertIn("kWorkerWaitTicks", self.oracle)
        self.assertIn("WaitForFlagWorker", self.oracle)
        self.assertIn("SchedSnapshotBlockedTasks", self.oracle)
        self.assertNotIn("for (;;)", self.oracle)
        self.assertNotIn("while (true)", self.oracle)

    def test_runner_requires_each_case_and_exact_cpu_marker(self) -> None:
        for marker in (
            "[cancel-smp] case=publication-barrier PASS",
            "[cancel-smp] case=kmutex-wake PASS",
            "[cancel-smp] case=iocp-timeout PASS",
            "[cancel-smp] case=message-port-close PASS",
            "[cancel-smp] PASS cpus=${EXPECTED_CPUS} cases=4",
        ):
            self.assertIn(marker, self.runner)

    def test_docs_pin_both_supported_qemu_topologies(self) -> None:
        self.assertIn("DUETOS_EXPECTED_CPUS=2", self.docs)
        self.assertIn("DUETOS_EXPECTED_CPUS=4", self.docs)
        self.assertIn("[cancel-smp] PASS cpus=N cases=4", self.docs)

    def test_ci_runs_both_supported_qemu_topologies(self) -> None:
        self.assertIn("- cancellation-smp", self.workflow)
        self.assertRegex(self.workflow, r"- profile: cancellation-smp\s+cpus: 2")
        self.assertRegex(self.workflow, r"cpus:\s+- 4")


if __name__ == "__main__":
    unittest.main()
