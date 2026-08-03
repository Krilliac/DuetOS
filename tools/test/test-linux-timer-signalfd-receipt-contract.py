#!/usr/bin/env python3
"""Hostile structural contract for timerfd/signalfd fd identity."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ASYNC_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_async_io.cpp"
ASYNC_H = ROOT / "kernel" / "subsystems" / "linux" / "syscall_async_io.h"
MISC_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_misc.cpp"


def code_only(source: str) -> str:
    """Blank comments and quoted literals without hiding code delimiters."""
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
            blank(index, end + 2)
            index = end + 2
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
                if not re.search(r"[\s\\()]", delimiter):
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
                elif source[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            else:
                raise AssertionError("unterminated quoted literal")
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(masked)


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
    depth = 0
    for index in range(opening, len(source)):
        depth += source[index] == left
        depth -= source[index] == right
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
        closing_brace = matching_delimiter(code, opening_brace, "{", "}")
        return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function: {signature}")


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class ParserHostileTests(unittest.TestCase):
    def test_comments_strings_raw_literals_and_digit_separators_are_masked(self) -> None:
        hostile = r'''
// p->linux_fds[fd].state = 7;
/* LinuxFdAttachKFile(p, fd, 8, idx, release); */
const char* normal = "LinuxFdAllocLowest(p, 3)";
const char* raw = u8R"tag(LinuxFdSetCloexec(p, fd, true); // } {)tag";
u64 visible = 10'000'000ull;
'''
        visible = code_only(hostile)
        self.assertNotIn("linux_fds", visible)
        self.assertNotIn("LinuxFdAttachKFile", visible)
        self.assertNotIn("LinuxFdAllocLowest", visible)
        self.assertNotIn("LinuxFdSetCloexec", visible)
        self.assertIn("10'000'000ull", visible)

    def test_function_parser_skips_forward_declaration(self) -> None:
        hostile = "bool Probe(int x); bool Probe(int x) { return x != 0; }"
        self.assertIn("return x != 0", function_body(hostile, r"bool\s+Probe"))


class TimerSignalfdReceiptProductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.async_cpp = ASYNC_CPP.read_text(encoding="utf-8")
        cls.async_code = code_only(cls.async_cpp)
        cls.async_h = code_only(ASYNC_H.read_text(encoding="utf-8"))
        cls.misc_cpp = MISC_CPP.read_text(encoding="utf-8")

    def test_async_tu_never_publishes_or_reloads_raw_fd_slots(self) -> None:
        self.assertNotRegex(self.async_code, r"\blinux_fds\s*\[")
        for legacy in (
            "LinuxFdAllocLowest",
            "LinuxFdAttachKFile",
            "LinuxFdSetCloexec(",
        ):
            self.assertNotIn(legacy, self.async_code)

    def test_timerfd_creation_is_prepare_then_atomic_bind(self) -> None:
        body = function_body(self.async_cpp, r"i64\s+DoTimerfdCreate")
        ordered(
            self,
            body,
            "TimerfdAlloc",
            "KFileCreate(ipc::KFileKind::Timerfd",
            "LinuxFdPrepare",
            "LinuxFdBindLowest",
        )
        self.assertIn("LinuxFdPreparedRelease", body)
        self.assertIn("KObjectRelease", body)

    def test_signalfd_creation_is_prepare_then_atomic_bind(self) -> None:
        body = function_body(self.async_cpp, r"i64\s+DoSignalfd")
        ordered(
            self,
            body,
            "SignalfdAlloc",
            "KFileCreate(ipc::KFileKind::Signalfd",
            "LinuxFdPrepare",
            "LinuxFdBindLowest",
        )
        self.assertIn("LinuxFdPreparedRelease", body)
        self.assertIn("KObjectRelease", body)

    def test_timerfd_operations_pin_exact_receipts(self) -> None:
        for name in ("DoTimerfdSettime", "DoTimerfdGettime"):
            with self.subTest(function=name):
                body = function_body(self.async_cpp, rf"i64\s+{name}")
                ordered(
                    self,
                    body,
                    "LinuxFdAcquire",
                    "acquired.snapshot.first_cluster",
                    "TimerfdPin",
                    "LinuxFdAcquiredRelease",
                )
                self.assertNotRegex(body, r"\blinux_fds\s*\[")

    def test_signalfd_update_pins_exact_receipt(self) -> None:
        body = function_body(self.async_cpp, r"i64\s+DoSignalfd")
        ordered(
            self,
            body,
            "LinuxFdAcquire",
            "acquired.snapshot.first_cluster",
            "SignalfdPin",
            "LinuxFdAcquiredRelease",
            "SignalfdAlloc",
        )

    def test_settime_mutates_before_user_copyout_without_relocking(self) -> None:
        body = function_body(self.async_cpp, r"i64\s+DoTimerfdSettime")
        ordered(
            self,
            body,
            "SpinLockAcquire(g_async_lock)",
            "old_spec.it_value_sec",
            "t.next_expiry_tick =",
            "SpinLockRelease(g_async_lock",
            "CopyToUser",
            "LinuxFdAcquiredRelease",
        )
        locked_end = body.find("SpinLockRelease(g_async_lock")
        self.assertNotIn("CopyToUser", body[:locked_end])

    def test_epoll_control_key_also_matches_exact_retained_identity(self) -> None:
        match = function_body(self.async_cpp, r"bool\s+EpollWatchMatchesIdentity")
        for token in (
            "source_fd",
            "snapshot.generation",
            "snapshot.ofd",
            "kfile_ref",
        ):
            self.assertIn(token, match)
        ctl = function_body(self.async_cpp, r"i64\s+DoEpollCtl")
        self.assertIn("EpollWatchMatchesIdentity", ctl)

    def test_signalfd_readiness_uses_explicit_process_and_retained_pool_index(self) -> None:
        self.assertRegex(
            self.async_h,
            r"LinuxFdEpollReady\s*\(\s*const\s+core::LinuxFdAcquired&[^;]*core::Process\s*\*",
        )
        ready = function_body(self.async_cpp, r"u32\s+LinuxFdEpollReady")
        self.assertNotIn("CurrentProcess", ready)
        self.assertIn("ProcessLinuxSignalPendingSnapshot(signal_owner)", ready)
        self.assertNotIn("signal_owner->linux_pending_signals", ready)
        self.assertIn("SignalfdPin pin(slot.first_cluster)", ready)
        poll = function_body(self.misc_cpp, r"i64\s+DoPoll")
        self.assertIn("LinuxFdEpollReady(acquired, want, p)", poll)


if __name__ == "__main__":
    unittest.main(verbosity=2)
