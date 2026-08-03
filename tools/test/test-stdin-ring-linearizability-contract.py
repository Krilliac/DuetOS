#!/usr/bin/env python3
"""Structural contract for the per-process SMP-safe stdin ring."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while retaining source offsets."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for offset in range(begin, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end < 0:
                end = len(source)
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
            open_paren = source.find("(", delimiter_begin, delimiter_begin + 17)
            if open_paren >= 0:
                delimiter = source[delimiter_begin:open_paren]
                if not re.search(r"[\s\\()]", delimiter):
                    terminator = ")" + delimiter + '"'
                    end = source.find(terminator, open_paren + 1)
                    if end < 0:
                        raise AssertionError("unterminated raw string")
                    end += len(terminator)
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


def matching_delimiter(source: str, opening: int, left: str = "{", right: str = "}") -> int:
    if opening < 0 or source[opening] != left:
        raise AssertionError(f"missing opening delimiter {left!r}")
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
        closing_paren = matching_delimiter(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        declaration_end = code.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            closing_brace = matching_delimiter(code, opening_brace)
            return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function definition: {signature}")


def type_body(source: str, declaration: str) -> str:
    code = code_only(source)
    match = re.search(declaration + r"[^;{]*\{", code)
    if match is None:
        raise AssertionError(f"missing type: {declaration}")
    opening = code.find("{", match.start())
    return code[opening + 1 : matching_delimiter(code, opening)]


def guarded_block(source: str, lock_token: str) -> str:
    """Return the innermost lexical block containing a lock-guard token."""
    code = code_only(source)
    target = code.find(lock_token)
    if target < 0:
        raise AssertionError(f"missing lock token: {lock_token}")
    stack: list[int] = []
    candidates: list[tuple[int, int]] = []
    for index, char in enumerate(code):
        if char == "{":
            stack.append(index)
        elif char == "}":
            opening = stack.pop()
            if opening < target < index:
                candidates.append((opening, index))
    if not candidates:
        raise AssertionError("lock token is not in a lexical block")
    opening, closing = max(candidates, key=lambda pair: pair[0])
    return code[opening + 1 : closing]


def assert_ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class ParserHostileTests(unittest.TestCase):
    def test_comments_and_literals_cannot_supply_contract_tokens(self) -> None:
        hostile = r'''
// sync::SpinLockGuard ring_guard(r.lock);
/* WaitQueueBlockIfSequenceUnchanged(&r.waiters, &r.event_sequence, observed); */
const char* normal = "StdinAdvanceEventLocked(r);";
const char* raw = u8R"tag(mm::CopyToUser(fake) // } {)tag";
int visible = 7;
'''
        visible = code_only(hostile)
        self.assertNotIn("SpinLockGuard", visible)
        self.assertNotIn("WaitQueueBlockIfSequenceUnchanged", visible)
        self.assertNotIn("StdinAdvanceEventLocked", visible)
        self.assertIn("int visible = 7;", visible)


class StdinRingLinearizabilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")

    def test_ring_owns_lock_atomic_epoch_and_power_of_two_capacity(self) -> None:
        ring = type_body(self.process_h, r"struct\s+StdinRing")
        self.assertRegex(ring, r"kCap\s*=\s*256")
        self.assertIn("static_assert((kCap & (kCap - 1)) == 0)", ring)
        self.assertRegex(ring, r"u32\s+head\s*;")
        self.assertRegex(ring, r"u32\s+tail\s*;")
        self.assertRegex(ring, r"sync::SpinLock\s+lock\s*;")
        self.assertRegex(ring, r"u64\s+event_sequence\s*;")
        self.assertRegex(ring, r"sched::WaitQueue\s+waiters\s*;")

        create = function_body(self.process_cpp, r"Process\s*\*\s*ProcessCreate")
        self.assertRegex(create, r"memset\s*\(\s*p\s*,\s*0\s*,\s*sizeof\s*\(\s*Process\s*\)\s*\)")

    def test_event_epoch_is_nonwrapping_and_release_published(self) -> None:
        advance = function_body(self.process_cpp, r"void\s+StdinAdvanceEventLocked")
        assert_ordered(
            self,
            advance,
            "__atomic_load_n(&ring.event_sequence, __ATOMIC_RELAXED)",
            "previous != ~u64{0}",
            "__atomic_store_n(&ring.event_sequence, previous + 1, __ATOMIC_RELEASE)",
        )
        self.assertNotIn("WaitQueueWake", advance)
        self.assertNotIn("ProcessRelease", advance)

    def test_producer_mutates_and_publishes_under_ring_lock_then_wakes(self) -> None:
        feed = function_body(self.process_cpp, r"void\s+ProcessFeedStdinFocusChar")
        locked = guarded_block(feed, "SpinLockGuard ring_guard(r.lock)")
        assert_ordered(
            self,
            locked,
            "SpinLockGuard ring_guard(r.lock)",
            "r.head - r.tail >= Process::StdinRing::kCap",
            "++r.tail",
            "r.buf[r.head & (Process::StdinRing::kCap - 1)]",
            "++r.head",
            "StdinAdvanceEventLocked(r)",
        )
        self.assertEqual(locked.count("++r.tail"), 1)
        for forbidden in ("WaitQueueWake", "ProcessRelease", "CopyToUser", "g_sched_lock"):
            self.assertNotIn(forbidden, locked)

        outside = feed.replace(locked, "", 1)
        self.assertNotIn("r.head", outside)
        self.assertNotIn("r.tail", outside)
        self.assertNotIn("r.buf", outside)
        assert_ordered(self, feed, "StdinAdvanceEventLocked(r)", "WaitQueueWakeOne(&r.waiters)")
        self.assertNotIn("arch::Cli", feed)
        self.assertNotIn("arch::Sti", feed)

    def test_reader_snapshots_or_drains_under_lock_and_conditionally_blocks(self) -> None:
        read = function_body(self.process_cpp, r"i64\s+ProcessReadStdinBlocking")
        locked = guarded_block(read, "SpinLockGuard ring_guard(r.lock)")
        assert_ordered(
            self,
            locked,
            "SpinLockGuard ring_guard(r.lock)",
            "r.head - r.tail",
            "scratch[i] = r.buf",
            "r.tail += to_copy_u32",
            "__atomic_load_n(&r.event_sequence, __ATOMIC_ACQUIRE)",
        )
        for forbidden in (
            "CopyToUser",
            "WaitQueueBlock",
            "WaitQueueBlockIfSequenceUnchanged",
            "ProcessRelease",
            "g_sched_lock",
        ):
            self.assertNotIn(forbidden, locked)

        outside = read.replace(locked, "", 1)
        self.assertNotIn("r.head", outside)
        self.assertNotIn("r.tail", outside)
        self.assertNotIn("r.buf", outside)
        assert_ordered(
            self,
            read,
            "__atomic_load_n(&r.event_sequence, __ATOMIC_ACQUIRE)",
            "WaitQueueBlockIfSequenceUnchanged(&r.waiters, &r.event_sequence, observed_sequence)",
            "mm::CopyToUser(dst_user, scratch, to_copy_u32)",
        )
        self.assertNotIn("WaitQueueBlock(&r.waiters)", read)
        self.assertNotIn("arch::Cli", read)
        self.assertNotIn("arch::Sti", read)

    def test_focus_owns_strong_reference_and_releases_outside_focus_lock(self) -> None:
        claim = function_body(self.process_cpp, r"void\s+StdinFocusClaimIfEmpty")
        assert_ordered(
            self,
            claim,
            "ProcessRetain(process)",
            "ScopedProcessRef candidate(process)",
            "ScopedProcessRuntimeAccess runtime_access(process)",
            "SpinLockGuard focus_guard(g_stdin_focus_lock)",
            "g_stdin_focus = candidate.Detach()",
        )

        clear = function_body(self.process_cpp, r"void\s+StdinFocusClearIf")
        locked = guarded_block(clear, "SpinLockGuard focus_guard(g_stdin_focus_lock)")
        self.assertIn("g_stdin_focus = nullptr", locked)
        self.assertNotIn("ProcessRelease", locked)
        assert_ordered(self, clear, "g_stdin_focus = nullptr", "ProcessRelease(detached)")

        feed = function_body(self.process_cpp, r"void\s+ProcessFeedStdinFocusChar")
        assert_ordered(
            self,
            feed,
            "ProcessRetain(g_stdin_focus)",
            "process = g_stdin_focus",
            "ScopedProcessRef focus_pin(process)",
            "ScopedProcessRuntimeAccess runtime_access(process)",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
