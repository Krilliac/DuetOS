#!/usr/bin/env python3
"""Structural contract for singleton main-push rolling publication."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
ROLLING_TAG = re.compile(
    r"(?m)^\s+tag_name:\s*(latest-debug|latest-release)\s*$"
)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def job_block(workflow: str, name: str) -> str:
    marker = f"\n  {name}:\n"
    if marker not in workflow:
        raise AssertionError(f"missing workflow job: {name}")
    remainder = workflow.split(marker, 1)[1]
    next_job = re.search(r"\n  [a-zA-Z0-9_-]+:\n", remainder)
    return remainder[: next_job.start()] if next_job else remainder


class ReleasePublisherSingletonContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build = read(".github/workflows/build.yml")
        cls.release = read(".github/workflows/release.yml")
        cls.build_docs = read("wiki/tooling/Build-System.md")
        cls.arch_docs = read("wiki/getting-started/Architecture-Overview.md")
        cls.decisions = read("wiki/reference/Design-Decisions.md")

    def test_release_workflow_is_tag_and_manual_only(self) -> None:
        trigger = self.release.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
        push = trigger.split("  push:\n", 1)[1].split(
            "  workflow_dispatch:\n", 1
        )[0]

        self.assertNotRegex(push, r"(?m)^\s+branches:\s*$")
        self.assertNotIn("main", push)
        self.assertRegex(push, r"(?m)^\s+tags:\s*$")
        self.assertIn("- 'v*'", push)
        self.assertIn("  workflow_dispatch:\n", trigger)
        self.assertIn("source_ref:", trigger)

    def test_build_main_publisher_has_the_complete_gate(self) -> None:
        trigger = self.build.split("\non:\n", 1)[1].split("\nconcurrency:\n", 1)[0]
        self.assertIn("branches: [main, claude/**]", trigger)

        publisher = job_block(self.build, "publish-rolling")
        self.assertIn(
            "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
            publisher,
        )
        needs_match = re.search(r"(?m)^\s+needs:\s*\[([^]]+)]\s*$", publisher)
        self.assertIsNotNone(needs_match)
        actual_needs = {
            item.strip() for item in needs_match.group(1).split(",")
        }
        self.assertEqual(
            actual_needs,
            {
                "check-format",
                "check-rust",
                "build-debug",
                "build-release",
                "qemu-smoke",
                "host-tests",
                "pre-publish-lifetime-snapshot",
            },
        )
        self.assertEqual(
            ROLLING_TAG.findall(publisher), ["latest-debug", "latest-release"]
        )

    def test_no_other_workflow_can_be_a_main_push_rolling_writer(self) -> None:
        owners: dict[str, list[str]] = {}
        for workflow_path in sorted(WORKFLOW_DIR.glob("*.yml")):
            tags = ROLLING_TAG.findall(workflow_path.read_text(encoding="utf-8"))
            if tags:
                owners[workflow_path.name] = tags

        self.assertEqual(
            owners,
            {
                "build.yml": ["latest-debug", "latest-release"],
                "release.yml": ["latest-debug", "latest-release"],
            },
        )

        publisher = job_block(self.build, "publish-rolling")
        build_without_publisher = self.build.replace(publisher, "", 1)
        self.assertEqual(ROLLING_TAG.findall(build_without_publisher), [])

        release_trigger = self.release.split("\non:\n", 1)[1].split(
            "\npermissions:\n", 1
        )[0]
        self.assertNotIn("branches:", release_trigger)

    def test_docs_preserve_singleton_and_immutable_source_boundary(self) -> None:
        for document in (self.build_docs, self.arch_docs, self.decisions):
            self.assertIn("sole", document)
            self.assertIn("full commit SHA", document)
            self.assertRegex(document, r"moving\s+branch")


if __name__ == "__main__":
    unittest.main()
