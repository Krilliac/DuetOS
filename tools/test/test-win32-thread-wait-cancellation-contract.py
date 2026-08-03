#!/usr/bin/env python3
"""Structural contracts for Win32 local-thread wait cancellation."""

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


class Win32ThreadWaitCancellationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = read("kernel/proc/process.h")
        cls.process_cpp = read("kernel/proc/process.cpp")
        cls.thread_cpp = read("kernel/subsystems/win32/thread_syscall.cpp")
        cls.thread_h = read("kernel/subsystems/win32/thread_syscall.h")
        cls.dispatch = read("kernel/syscall/syscall.cpp")
        cls.sched_h = read("kernel/sched/sched.h")

    def test_thread_rows_own_persistent_sequence_and_wait_queue(self) -> None:
        masked = mask_comments_and_literals(self.process_h)
        row = re.search(r"struct\s+Win32ThreadHandle\s*\{(?P<body>.*?)\}\s*;", masked, re.S)
        self.assertIsNotNone(row)
        body = row.group("body")
        self.assertRegex(body, r"u64\s+generation\s*;")
        self.assertRegex(body, r"u64\s+event_sequence\s*;")
        self.assertRegex(body, r"sched::WaitQueue\s+waiters\s*;")

        create = function_body(self.thread_cpp, r"void\s+DoThreadCreate")
        self.assertNotIn("event_sequence", create, "slot reuse reset the stable event sequence")
        self.assertNotIn(".waiters", create, "slot reuse reset a live wait queue")

    def test_exit_publishes_before_waking_outside_the_slot_lock(self) -> None:
        body = function_body(self.process_cpp, r"void\s+ProcessPublishWin32ThreadExit")
        published = body.index("row.exited = true")
        sequence = body.index("AdvanceStableEventSequenceLocked")
        unlock = body.index("SpinLockRelease")
        wake = body.index("WaitQueueWakeAll")
        self.assertTrue(published < sequence < unlock < wake)
        self.assertIn("waiters_to_wake", body)

    def test_wait_snapshots_exact_generation_and_tid_without_blocking_under_lock(self) -> None:
        snapshot = function_body(self.thread_cpp, r"bool\s+SnapshotThreadWait")
        self.assertIn("row.generation == expected_generation", snapshot)
        self.assertIn("row.tid == expected_tid", snapshot)
        self.assertLess(snapshot.index("SpinLockAcquire"), snapshot.index("SpinLockRelease"))
        self.assertNotIn("WaitQueueBlock", snapshot)

        wait = function_body(self.thread_cpp, r"void\s+DoThreadWait")
        self.assertNotIn("SpinLockAcquire", wait)
        self.assertIn("SnapshotThreadWait", wait)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedCancellable", wait)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedTimeoutCancellable", wait)
        self.assertIn("WaitQueueBlockTimeoutCancellable", wait)
        self.assertIn("expected_generation", wait)
        self.assertIn("expected_tid", wait)
        self.assertRegex(
            wait,
            r"block_result\s*==\s*sched::WaitQueueBlockResult::Cancelled",
        )
        self.assertNotRegex(wait, r"\bSched(?:SleepTicks|Yield|Exit)\s*\(")
        self.assertIn("kThreadWaitObject0", wait)
        self.assertIn("kThreadWaitTimeout", wait)

    def test_finite_wait_uses_scheduler_atomic_timed_sequence_bridge(self) -> None:
        self.assertRegex(
            self.sched_h,
            r"WaitQueueBlockResult\s+WaitQueueBlockIfSequenceUnchangedTimeoutCancellable\s*\(",
        )
        dispatch = mask_comments_and_literals(self.dispatch)
        match = re.search(
            r"case\s+SYS_THREAD_WAIT\s*:\s*subsystems::win32::DoThreadWait\s*\(\s*frame\s*\)\s*;\s*return\s*;",
            dispatch,
        )
        self.assertIsNotNone(match, "SYS_THREAD_WAIT dispatch must remain a thin helper call")
        self.assertRegex(self.thread_h, r"void\s+DoThreadWait\s*\(\s*arch::TrapFrame\s*\*\s*frame\s*\)\s*;")


if __name__ == "__main__":
    unittest.main(verbosity=2)
