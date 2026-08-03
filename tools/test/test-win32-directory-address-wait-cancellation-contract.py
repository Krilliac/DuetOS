#!/usr/bin/env python3
"""Structural contracts for cancellable Win32 address and directory waits."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def mask_comments_and_literals(text: str) -> str:
    out = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        if state == "code":
            if text.startswith("//", index):
                out[index] = out[index + 1] = " "
                index += 2
                state = "line"
                continue
            if text.startswith("/*", index):
                out[index] = out[index + 1] = " "
                index += 2
                state = "block"
                continue
            if text[index] in {'"', "'"}:
                quote = text[index]
                out[index] = " "
                state = "literal"
        elif state == "line":
            if text[index] == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "block":
            out[index] = " "
            if text.startswith("*/", index):
                out[index + 1] = " "
                index += 1
                state = "code"
        else:
            out[index] = " "
            if text[index] == "\\" and index + 1 < len(text):
                out[index + 1] = " "
                index += 1
            elif text[index] == quote:
                state = "code"
        index += 1
    return "".join(out)


def function_body(source: str, signature: str) -> str:
    code = mask_comments_and_literals(source)
    match = re.search(signature + r"\s*\([^;{}]*\)\s*\{", code)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = code.find("{", match.start())
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[opening : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class WaitOnAddressCancellationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = read("kernel/subsystems/win32/waitaddr_syscall.cpp")
        cls.code = mask_comments_and_literals(cls.source)

    def test_bucket_owns_stable_release_acquire_sequence(self) -> None:
        self.assertRegex(self.code, r"g_futex_sequence\s*\[\s*kBuckets\s*\]")
        snapshot = function_body(self.source, r"u64\s+SequenceSnapshot")
        publish = function_body(self.source, r"void\s+PublishBucketEvent")
        self.assertIn("__ATOMIC_ACQUIRE", snapshot)
        self.assertIn("__atomic_compare_exchange_n", publish)
        self.assertIn("__ATOMIC_RELEASE", publish)
        self.assertIn("kSaturatedSequence", publish)

    def test_compare_then_block_uses_atomic_scheduler_bridge(self) -> None:
        body = function_body(self.source, r"void\s+DoWaitOnAddress")
        self.assertLess(body.index("SequenceSnapshot"), body.index("CopyFromUser"))
        self.assertIn("WaitQueueBlockIfSequenceUnchangedCancellable", body)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedTimeoutCancellable", body)
        self.assertIn("WaitQueueBlockTimeoutCancellable", body)
        self.assertRegex(body, r"WaitQueueBlockResult::Cancelled")
        self.assertRegex(body, r"frame->rax\s*=\s*static_cast<u64>\s*\(\s*-1\s*\)")
        self.assertNotRegex(body, r"\bWaitQueueBlock\s*\(")
        self.assertNotRegex(body, r"\bWaitQueueBlockTimeout\s*\(")
        self.assertNotIn("arch::Cli", body)
        self.assertNotIn("arch::Sti", body)

    def test_wake_publishes_before_scheduler_wake(self) -> None:
        body = function_body(self.source, r"void\s+DoWakeByAddress")
        self.assertLess(body.index("PublishBucketEvent"), body.index("WaitQueueWakeAll"))


class DirectoryNotificationCancellationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = read("kernel/subsystems/win32/dir_syscall.cpp")
        cls.code = mask_comments_and_literals(cls.source)

    def test_subscription_has_exact_persistent_identity_and_sequence(self) -> None:
        row = re.search(r"struct\s+DirNotifySub\s*\{(?P<body>.*?)\}\s*;", self.code, re.S)
        self.assertIsNotNone(row)
        body = row.group("body")
        for field in ("generation", "event_sequence", "owner", "dir_slot", "closed"):
            self.assertRegex(body, rf"\b{field}\b")
        allocation = function_body(self.source, r"i64\s+SysDirNotify")
        self.assertNotRegex(allocation, r"\.wq\.(?:head|tail)\s*=")
        self.assertNotRegex(allocation, r"event_sequence\s*=\s*0")

    def test_publish_advances_sequence_before_wake(self) -> None:
        body = function_body(self.source, r"void\s+Win32DirNotifyPublish")
        self.assertLess(body.index("AdvanceDirNotifySequenceLocked"), body.index("WaitQueueWakeOne"))
        self.assertIn("g_dir_notify_lock", body)

    def test_wait_is_cancellable_lost_wake_free_and_saturation_safe(self) -> None:
        body = function_body(self.source, r"i64\s+SysDirNotify")
        self.assertIn("DirNotifySequenceSnapshot", body)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedCancellable", body)
        self.assertIn("WaitQueueBlockTimeoutCancellable", body)
        self.assertIn("kSaturatedNotifySequence", body)
        self.assertIn("WaitQueueBlockResult::Cancelled", body)
        self.assertNotRegex(body, r"\bWaitQueueBlock\s*\(")
        self.assertNotRegex(body, r"\bWaitQueueBlockTimeout\s*\(")
        self.assertNotIn("arch::Cli", body)
        self.assertNotIn("arch::Sti", body)

    def test_close_marks_exact_waiters_terminal_before_recycle(self) -> None:
        close = function_body(self.source, r"void\s+SysDirClose")
        cancel = function_body(self.source, r"void\s+CancelDirNotifyForHandleLocked")
        self.assertIn("win32_file_lock", close)
        self.assertLess(close.index("CancelDirNotifyForHandleLocked"), close.rindex("SpinLockRelease"))
        self.assertIn("sub.owner != proc", cancel)
        self.assertIn("sub.dir_slot != dir_slot", cancel)
        self.assertLess(cancel.index("sub.closed = true"), cancel.index("AdvanceDirNotifySequenceLocked"))
        self.assertLess(cancel.index("AdvanceDirNotifySequenceLocked"), cancel.index("WaitQueueWakeAll"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
