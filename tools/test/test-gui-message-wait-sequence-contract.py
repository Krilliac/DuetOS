#!/usr/bin/env python3
"""Structural contract for cancellation-safe, lost-wake-free GetMessage."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCHED_H = (ROOT / "kernel/sched/sched.h").read_text(encoding="utf-8")
WIDGET_H = (ROOT / "kernel/drivers/video/widget.h").read_text(encoding="utf-8")
WIDGET_CPP = (ROOT / "kernel/drivers/video/widget.cpp").read_text(encoding="utf-8")
WINDOW_SYSCALL = (ROOT / "kernel/subsystems/win32/window_syscall.cpp").read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank comments and literals while preserving offsets and braces."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for offset in range(begin, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise AssertionError("unterminated block comment")
            end += 2
            blank(index, end)
            index = end
            continue
        raw_prefix = next(
            (prefix for prefix in ('u8R"', 'uR"', 'UR"', 'LR"', 'R"') if source.startswith(prefix, index)),
            None,
        )
        if raw_prefix is not None:
            delimiter_begin = index + len(raw_prefix)
            opening = source.find("(", delimiter_begin, delimiter_begin + 17)
            if opening >= 0:
                delimiter = source[delimiter_begin:opening]
                terminator = ")" + delimiter + '"'
                end = source.find(terminator, opening + 1)
                if end < 0:
                    raise AssertionError("unterminated raw string")
                end += len(terminator)
                blank(index, end)
                index = end
                continue
        if (
            source[index] == "'"
            and index > 0
            and index + 1 < len(source)
            and source[index - 1].isalnum()
            and source[index + 1].isalnum()
        ):
            index += 1
            continue
        if source[index] in "\"'":
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            else:
                raise AssertionError("unterminated quoted literal")
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(masked)


def matching(source: str, opening: int, left: str = "{", right: str = "}") -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} region")


def function_body(source: str, signature: str) -> str:
    code = code_only(source)
    for match in re.finditer(signature + r"\s*\(", code):
        opening_paren = code.find("(", match.start())
        closing_paren = matching(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        semicolon = code.find(";", closing_paren + 1)
        if semicolon >= 0 and (opening_brace < 0 or semicolon < opening_brace):
            continue
        if opening_brace >= 0:
            return code[opening_brace + 1 : matching(code, opening_brace)]
    raise AssertionError(f"missing function definition: {signature}")


class GuiMessageWaitSequenceContract(unittest.TestCase):
    def test_scheduler_exposes_result_bearing_cancellable_sequence_wait(self) -> None:
        code = code_only(SCHED_H)
        enum = re.search(r"enum\s+class\s+WaitQueueBlockResult[^\{]*\{(?P<body>.*?)\}", code, re.DOTALL)
        self.assertIsNotNone(enum, "scheduler wait result enum is missing")
        body = enum.group("body")
        for value in ("Woken", "TimedOut", "Cancelled", "SequenceChanged"):
            self.assertRegex(body, rf"\b{value}\b")
        self.assertRegex(
            code,
            r"WaitQueueBlockIfSequenceUnchangedCancellable\s*\(\s*WaitQueue\s*\*[^,]+,\s*"
            r"const\s+u64\s*\*[^,]+,\s*u64\s+[^\)]+\)",
        )

    def test_widget_sequence_is_monotonic_published_and_saturation_safe(self) -> None:
        publish = function_body(WIDGET_CPP, r"void\s+PublishWindowMsgEvent")
        snapshot = function_body(WIDGET_CPP, r"u64\s+WindowMsgSequenceSnapshot")
        wait = function_body(WIDGET_CPP, r"WindowMsgWaitResult\s+WindowMsgWaitIfSequenceUnchangedCancellable")
        self.assertRegex(code_only(WIDGET_CPP), r"g_msg_event_sequence\s*=\s*1\s*;")
        self.assertIn("__atomic_compare_exchange_n", publish)
        self.assertIn("__ATOMIC_RELEASE", publish)
        self.assertIn("__ATOMIC_ACQUIRE", snapshot)
        self.assertRegex(wait, r"observed_sequence\s*==\s*kSaturated")
        self.assertIn("WaitQueueBlockIfSequenceUnchangedCancellable", wait)
        self.assertIn("WaitQueueBlockResult::Cancelled", wait)

    def test_publish_precedes_deferred_or_immediate_broadcast(self) -> None:
        wake = function_body(WIDGET_CPP, r"void\s+WindowMsgWakeAll")
        publish_at = wake.find("PublishWindowMsgEvent")
        pending_at = wake.find("g_msg_wake_pending")
        broadcast_at = wake.find("WakeWindowMsgWaitersNow")
        self.assertGreaterEqual(publish_at, 0)
        self.assertGreater(pending_at, publish_at)
        self.assertGreater(broadcast_at, publish_at)
        unlock = function_body(WIDGET_CPP, r"void\s+CompositorUnlock")
        self.assertIn("WakeWindowMsgWaitersNow", unlock)
        self.assertNotIn("WindowMsgWakeAll", unlock)

    def test_getmessage_snapshots_before_probe_and_never_polls(self) -> None:
        body = function_body(WINDOW_SYSCALL, r"void\s+DoWinGetMsg")
        snapshot_at = body.find("WindowMsgSequenceSnapshot")
        probe_at = body.find("GuiMessageProbeQueue")
        wait_at = body.find("WindowMsgWaitIfSequenceUnchangedCancellable")
        self.assertGreaterEqual(snapshot_at, 0)
        self.assertGreater(probe_at, snapshot_at)
        self.assertGreater(wait_at, probe_at)
        self.assertNotIn("WindowMsgWaitBlockTimeout", body)
        self.assertNotIn("WaitQueueBlockTimeout", body)
        self.assertNotIn("arch::Cli", body)
        self.assertNotIn("arch::Sti", body)

    def test_getmessage_unwinds_on_cancelled_dequeue(self) -> None:
        body = function_body(WINDOW_SYSCALL, r"void\s+DoWinGetMsg")
        cancelled = re.search(
            r"wait_result\s*==\s*WindowMsgWaitResult::Cancelled\s*\)\s*\{(?P<body>.*?)\}",
            body,
            re.DOTALL,
        )
        self.assertIsNotNone(cancelled)
        cancel_body = cancelled.group("body")
        self.assertRegex(cancel_body, r"frame->rax\s*=\s*static_cast<u64>\s*\(\s*-1\s*\)")
        self.assertRegex(cancel_body, r"\breturn\s*;")

    def test_widget_surface_no_longer_exposes_timeout_wait(self) -> None:
        code = code_only(WIDGET_H)
        self.assertNotIn("WindowMsgWaitBlockTimeout", code)
        self.assertIn("WindowMsgSequenceSnapshot", code)
        self.assertIn("WindowMsgWaitIfSequenceUnchangedCancellable", code)


class ParserHostileTests(unittest.TestCase):
    def test_comments_and_raw_literals_cannot_spoof_function_body(self) -> None:
        fixture = r'''
        // void Target() { Fake(); }
        const char* decoy = R"tag(void Target() { Fake(); })tag";
        void Target() { Real(); }
        '''
        body = function_body(fixture, r"void\s+Target")
        self.assertIn("Real", body)
        self.assertNotIn("Fake", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
