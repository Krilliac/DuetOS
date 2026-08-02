#!/usr/bin/env python3
"""Hostile structural contract for cancellation-safe Linux pipe waits."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "kernel/subsystems/linux/syscall_pipe.cpp").read_text(encoding="utf-8")


def code_only(source: str) -> str:
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


def matching(source: str, opening: int, left: str, right: str) -> int:
    if opening < 0 or source[opening] != left:
        raise AssertionError(f"missing opening {left!r}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} region")


def function_body(signature: str) -> str:
    source = code_only(SOURCE)
    for match in re.finditer(signature + r"\s*\(", source):
        opening_paren = source.find("(", match.start())
        closing_paren = matching(source, opening_paren, "(", ")")
        opening_brace = source.find("{", closing_paren + 1)
        declaration_end = source.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            return source[opening_brace + 1 : matching(source, opening_brace, "{", "}")]
    raise AssertionError(f"missing function definition: {signature}")


def require_order(body: str, *needles: str) -> None:
    positions = [body.find(needle) for needle in needles]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError(f"required order absent: {needles!r}; positions={positions!r}")


class LinuxPipeWaitCancellationContract(unittest.TestCase):
    def test_pipe_and_eventfd_own_stable_predicate_epochs(self) -> None:
        code = code_only(SOURCE)
        pipe = re.search(r"struct\s+Pipe\s*\{(?P<body>.*?)\};", code, re.S)
        eventfd = re.search(r"struct\s+Eventfd\s*\{(?P<body>.*?)\};", code, re.S)
        self.assertIsNotNone(pipe)
        self.assertIsNotNone(eventfd)
        self.assertIn("u64 read_sequence", pipe.group("body"))
        self.assertIn("u64 write_sequence", pipe.group("body"))
        self.assertIn("u64 read_sequence", eventfd.group("body"))
        self.assertIn("p.read_sequence = 1", function_body(r"i32\s+PipeAlloc"))
        self.assertIn("p.write_sequence = 1", function_body(r"i32\s+PipeAlloc"))
        self.assertIn("e.read_sequence = 1", function_body(r"i32\s+EventfdAlloc"))

    def test_epoch_publication_is_release_ordered_and_nonwrapping(self) -> None:
        publish = function_body(r"void\s+WaitSequencePublishLocked")
        self.assertIn("__atomic_load_n(sequence, __ATOMIC_RELAXED)", publish)
        self.assertIn("observed != ~u64{0}", publish)
        self.assertIn("__atomic_store_n(sequence, observed + 1, __ATOMIC_RELEASE)", publish)

    def test_wait_bridge_is_sequence_linearized_and_cancellable(self) -> None:
        body = function_body(r"bool\s+PipeWaitCancellable")
        self.assertIn("WaitQueueBlockIfSequenceUnchangedCancellable", body)
        self.assertIn("WaitQueueBlockTimeoutCancellable", body)
        self.assertGreaterEqual(body.count("WaitQueueBlockResult::Cancelled"), 2)
        self.assertNotRegex(body, r"\bWaitQueueBlock(?:Timeout)?\s*\(")
        self.assertNotIn("SchedExit", body)

    def test_every_blocking_production_path_unwinds_its_pin_on_cancel(self) -> None:
        cases = (
            (r"i64\s+PipeRead", "PipePin pin", "p.read_sequence"),
            (r"i64\s+PipeWrite", "PipePin pin", "p.write_sequence"),
            (r"i64\s+PipeReadKernel", "PipePin pin", "p.read_sequence"),
            (r"i64\s+PipeWriteKernel", "PipePin pin", "p.write_sequence"),
            (r"i64\s+PipeSpliceFromPipe", "PipePin src_pin", "src.read_sequence"),
            (r"i64\s+PipeTeeFromPipe", "PipePin src_pin", "src.read_sequence"),
            (r"i64\s+EventfdRead", "EventfdPin pin", "e.read_sequence"),
        )
        for signature, pin, sequence in cases:
            body = function_body(signature)
            require_order(body, pin, "while (true)", "WaitSequenceSnapshotLocked", "PipeWaitCancellable")
            self.assertIn(sequence, body, signature)
            self.assertIn("return kEINTR", body, signature)
            self.assertNotRegex(body, r"\bWaitQueueBlock(?:Timeout)?\s*\(", signature)
            self.assertNotIn("SchedExit", body, signature)

    def test_predicate_producers_publish_before_wake(self) -> None:
        cases = (
            (r"void\s+PipeReleaseRead", "WaitSequencePublishLocked(&p.write_sequence)",
             "WaitQueueWakeAll(&p.write_wq)"),
            (r"void\s+PipeReleaseWrite", "WaitSequencePublishLocked(&p.read_sequence)",
             "WaitQueueWakeAll(&p.read_wq)"),
            (r"i64\s+PipeRead", "WaitSequencePublishLocked(&p.write_sequence)",
             "WaitQueueWakeOne(&p.write_wq)"),
            (r"i64\s+PipeWrite", "WaitSequencePublishLocked(&p.read_sequence)",
             "WaitQueueWakeOne(&p.read_wq)"),
            (r"i64\s+PipeReadKernel", "WaitSequencePublishLocked(&p.write_sequence)",
             "WaitQueueWakeOne(&p.write_wq)"),
            (r"i64\s+PipeWriteKernel", "WaitSequencePublishLocked(&p.read_sequence)",
             "WaitQueueWakeOne(&p.read_wq)"),
            (r"void\s+EventfdRelease", "WaitSequencePublishLocked(&e.read_sequence)",
             "WaitQueueWakeAll(&e.read_wq)"),
            (r"i64\s+EventfdWrite", "WaitSequencePublishLocked(&e.read_sequence)",
             "WaitQueueWakeOne(&e.read_wq)"),
        )
        for signature, publish, wake in cases:
            require_order(function_body(signature), publish, wake)

        splice = function_body(r"i64\s+PipeSpliceFromPipe")
        require_order(splice, "WaitSequencePublishLocked(&dst.read_sequence)",
                      "WaitSequencePublishLocked(&src.write_sequence)",
                      "WaitQueueWakeOne(&dst.read_wq)", "WaitQueueWakeOne(&src.write_wq)")
        tee = function_body(r"i64\s+PipeTeeFromPipe")
        require_order(tee, "WaitSequencePublishLocked(&dst.read_sequence)",
                      "WaitQueueWakeOne(&dst.read_wq)")

    def test_file_contains_no_direct_terminal_exit(self) -> None:
        self.assertNotIn("SchedExit", code_only(SOURCE))


if __name__ == "__main__":
    unittest.main()
