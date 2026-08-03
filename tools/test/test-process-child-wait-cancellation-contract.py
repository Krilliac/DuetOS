#!/usr/bin/env python3
"""Structural contracts for cancellable Linux child-event waits."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def mask_comments_and_literals(text: str) -> str:
    output = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        if state == "code":
            if text.startswith("//", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "line"
                continue
            if text.startswith("/*", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "block"
                continue
            if text[index] in {'"', "'"}:
                quote = text[index]
                output[index] = " "
                state = "literal"
        elif state == "line":
            if text[index] == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block":
            output[index] = " "
            if text.startswith("*/", index):
                output[index + 1] = " "
                index += 1
                state = "code"
        else:
            output[index] = " "
            if text[index] == "\\" and index + 1 < len(text):
                output[index + 1] = " "
                index += 1
            elif text[index] == quote:
                state = "code"
        index += 1
    return "".join(output)


def function_body(source: str, signature: str) -> str:
    masked = mask_comments_and_literals(source)
    match = re.search(signature + r"\s*\([^;{}]*\)\s*\{", masked)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = masked.find("{", match.start())
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return masked[opening : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class ProcessChildWaitCancellationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = read("kernel/proc/process.h")
        cls.process_cpp = read("kernel/proc/process.cpp")
        cls.linux_waits = read("kernel/subsystems/linux/syscall_stub.cpp")

    def test_process_boundary_returns_result_bearing_cancellable_outcome(self) -> None:
        self.assertRegex(
            self.process_h,
            r"sched::WaitQueueBlockResult\s+ProcessWaitForLinuxChildEvent\s*\(",
        )
        body = function_body(
            self.process_cpp,
            r"sched::WaitQueueBlockResult\s+ProcessWaitForLinuxChildEvent",
        )
        self.assertIn("WaitQueueBlockIfSequenceUnchangedCancellable", body)
        self.assertIn("WaitQueueBlockTimeoutCancellable", body)
        self.assertRegex(body, r"observed_sequence\s*==\s*~u64\s*\{\s*0\s*\}")
        self.assertNotRegex(body, r"(?<!Cancellable)\bWaitQueueBlockIfSequenceUnchanged\s*\(")
        self.assertNotRegex(body, r"\bSchedExit\s*\(")

    def test_child_event_sequence_never_wraps(self) -> None:
        stable = function_body(self.process_cpp, r"bool\s+AdvanceStableEventSequenceLocked")
        self.assertRegex(stable, r"previous\s*==\s*~u64\s*\{\s*0\s*\}")
        self.assertRegex(stable, r"return\s+false\s*;")
        self.assertRegex(stable, r"__atomic_store_n\s*\([^;]*previous\s*\+\s*1[^;]*__ATOMIC_RELEASE")
        self.assertNotRegex(stable, r"previous\s*=\s*0")

    def test_wait4_and_waitid_return_eintr_only_for_explicit_cancellation(self) -> None:
        for signature in (r"i64\s+DoWait4", r"i64\s+DoWaitid"):
            body = function_body(self.linux_waits, signature)
            call = body.index("ProcessWaitForLinuxChildEvent")
            nonblocking = body.index("if (nonblocking)")
            self.assertLess(nonblocking, call, "WNOHANG must return before any blocking operation")
            self.assertRegex(
                body[call:],
                r"block_result\s*==\s*sched::WaitQueueBlockResult::Cancelled\s*\)\s*return\s+kEINTR\s*;",
            )
            self.assertEqual(body.count("return kEINTR"), 1)
            self.assertNotRegex(body, r"\bSpinLock(?:Acquire|Guard)\b")
            self.assertNotRegex(body, r"\bSchedExit\s*\(")


if __name__ == "__main__":
    unittest.main(verbosity=2)
