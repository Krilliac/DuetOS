#!/usr/bin/env python3
"""Semantic call-order guard for the smoke-profile SMP boot boundary."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAIN_CPP = ROOT / "kernel/core/main.cpp"


def strip_comments_and_literals(source: str) -> str:
    """Blank comments and quoted literals while preserving offsets/newlines."""

    result = list(source)
    index = 0
    state = "code"
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if current == "/" and following == "/":
                result[index] = result[index + 1] = " "
                state = "line-comment"
                index += 2
                continue
            if current == "/" and following == "*":
                result[index] = result[index + 1] = " "
                state = "block-comment"
                index += 2
                continue
            if current == '"':
                result[index] = " "
                state = "string"
            elif current == "'":
                result[index] = " "
                state = "character"
            index += 1
            continue

        if state == "line-comment":
            if current == "\n":
                state = "code"
            else:
                result[index] = " "
            index += 1
            continue

        if state == "block-comment":
            if current == "*" and following == "/":
                result[index] = result[index + 1] = " "
                state = "code"
                index += 2
            else:
                if current != "\n":
                    result[index] = " "
                index += 1
            continue

        if current == "\\" and following:
            result[index] = " "
            if following != "\n":
                result[index + 1] = " "
            index += 2
            continue
        if (state == "string" and current == '"') or (state == "character" and current == "'"):
            result[index] = " "
            state = "code"
        elif current != "\n":
            result[index] = " "
        index += 1

    return "".join(result)


def kernel_main_body(source: str, *, sanitize: bool = True) -> str:
    cleaned = strip_comments_and_literals(source)
    signature = re.search(
        r'extern\s+"C"\s+void\s+kernel_main\s*\([^)]*\)\s*\{',
        source,
    )
    if signature is None:
        raise AssertionError("kernel_main definition is missing")

    open_brace = cleaned.find("{", signature.start())
    if open_brace < 0:
        raise AssertionError("kernel_main opening brace is missing")
    depth = 0
    for index in range(open_brace, len(cleaned)):
        if cleaned[index] == "{":
            depth += 1
        elif cleaned[index] == "}":
            depth -= 1
            if depth == 0:
                body_source = cleaned if sanitize else source
                return body_source[open_brace + 1 : index]
    raise AssertionError("kernel_main closing brace is missing")


def unique_position(body: str, label: str, pattern: str) -> int:
    matches = list(re.finditer(pattern, body))
    if len(matches) != 1:
        raise AssertionError(f"expected one {label} call, found {len(matches)}")
    return matches[0].start()


class SmokeProfileOrderTests(unittest.TestCase):
    def test_profile_exit_follows_smp_topology_ipi_and_userland(self) -> None:
        source = MAIN_CPP.read_text(encoding="utf-8")
        body = kernel_main_body(source)
        raw_body = kernel_main_body(source, sanitize=False)

        spawn_selectors = [match.start() for match in re.finditer(r"\bSmokeProfileShouldSpawn\s*\(", body)]
        self.assertTrue(spawn_selectors, "profile target selection is missing")

        ordered_calls = [
            ("last profile target selector", max(spawn_selectors)),
            (
                "reschedule IPI install",
                unique_position(body, "reschedule IPI install", r"\bSmpInstallReschedIpiHandler\s*\("),
            ),
            (
                "AP timer IPI install",
                unique_position(body, "AP timer IPI install", r"\bSmpInstallApTimerIpiHandler\s*\("),
            ),
            (
                "TLB IPI install",
                unique_position(body, "TLB IPI install", r"\bSmpInstallTlbShootdownIpiHandler\s*\("),
            ),
            ("cross-CPU IPI install", unique_position(body, "cross-CPU IPI install", r"\bIpiCallInstall\s*\(")),
            ("CPU hotplug registration", unique_position(body, "CPU hotplug registration", r"\bSmpCpuhpRegister\s*\(")),
            ("AP bring-up", unique_position(body, "AP bring-up", r"\bSmpStartAps\s*\(")),
            (
                "SMP phase",
                unique_position(
                    body,
                    "SMP phase",
                    r"\bRunPhase\s*\(\s*duetos::core::Phase::Smp\s*\)",
                ),
            ),
            (
                "topology finalization",
                unique_position(body, "topology finalization", r"\bTopologyAssignClusters\s*\("),
            ),
            ("topology dump", unique_position(body, "topology dump", r"\bTopologyDump\s*\(")),
            ("cross-CPU IPI check", unique_position(body, "cross-CPU IPI check", r"\bIpiCallSelfTest\s*\(")),
            (
                "Userland phase",
                unique_position(
                    body,
                    "Userland phase",
                    r"\bRunPhase\s*\(\s*duetos::core::Phase::Userland\s*\)",
                ),
            ),
            ("heartbeat start", unique_position(body, "heartbeat start", r"\bStartHeartbeatThread\s*\(")),
            (
                "selfthink start",
                unique_position(body, "selfthink start", r"\bStartSelfthinkThread\s*\("),
            ),
            ("init completion", unique_position(body, "init completion", r"\bMarkInitComplete\s*\(")),
            (
                "canonical all-online marker",
                unique_position(
                    raw_body,
                    "canonical all-online marker",
                    r'\bSerialWrite\s*\(\s*"\[boot\] All subsystems online\. Entering idle loop\.\\n"\s*\)',
                ),
            ),
            (
                "smoke profile termination",
                unique_position(body, "smoke profile termination", r"\bSmokeProfileSleepAndExit\s*\("),
            ),
            (
                "optional CRTRACE survey",
                unique_position(body, "optional CRTRACE survey", r"\bCleanroomTraceCount\s*\("),
            ),
            ("normal boot-task exit", unique_position(body, "normal boot-task exit", r"\bSchedExit\s*\(")),
        ]

        for (earlier_label, earlier), (later_label, later) in zip(ordered_calls, ordered_calls[1:]):
            self.assertLess(earlier, later, f"{earlier_label} must precede {later_label}")


if __name__ == "__main__":
    unittest.main()
