#!/usr/bin/env python3
"""Structural contract for the focused browser PE QEMU profile."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class BrowserSmokeProfileContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile_h = read("kernel/test/smoke_profile.h")
        cls.profile_cpp = read("kernel/test/smoke_profile.cpp")
        cls.ring3 = read("kernel/proc/ring3_smoke.cpp")
        cls.runner = read("tools/test/profile-boot-smoke.sh")
        cls.workflow = read(".github/workflows/build.yml")
        cls.docs = read("wiki/reference/Smoke-Test-Suite.md")

    def test_kernel_profile_selects_both_browser_pes(self) -> None:
        self.assertIn("Browser", self.profile_h)
        self.assertIn('TokenMatches(value, end, "browser")', self.profile_cpp)
        self.assertIn('return "browser"', self.profile_cpp)
        self.assertIn('SpawnPeFile("ring3-browser-pe"', self.ring3)
        self.assertIn('SpawnPeFile("ring3-mini-browser"', self.ring3)

    def test_runner_requires_spawn_and_completion_markers(self) -> None:
        self.assertRegex(self.runner, r"(?m)^\s*browser\)\s*$")
        for marker in (
            'pe spawn name="ring3-browser-pe"',
            "[ring3-browser-pe] PASS",
            'pe spawn name="ring3-mini-browser"',
            "[ring3-mini-browser] PASS",
        ):
            self.assertIn(marker, self.runner)
        self.assertIn("linux browser cancellation-smp", self.runner)

    def test_ci_enrolls_browser_at_four_vcpus(self) -> None:
        self.assertIn("- browser", self.workflow)
        self.assertRegex(self.workflow, r"cpus:\s+- 4")
        self.assertIn('profile-boot-smoke.sh "${{ matrix.profile }}"', self.workflow)

    def test_documented_tokens_are_case_exact_and_claim_only_the_gate(self) -> None:
        for token in (
            "smoke=bringup",
            "smoke=pe-hello",
            "smoke=pe-winapi",
            "smoke=pe-winkill",
            "smoke=linux",
            "smoke=browser",
            "smoke=cancellation-smp",
        ):
            self.assertIn(token, self.docs)
        self.assertNotRegex(self.docs, r"smoke=(?:Bringup|PeHello|PeWinapi|PeWinkill|Linux)")
        self.assertIn("API/ABI path", self.docs)
        self.assertIn("does not prove Internet reachability", self.docs)


if __name__ == "__main__":
    unittest.main()
