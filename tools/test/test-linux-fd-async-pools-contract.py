#!/usr/bin/env python3
"""Structural contract for exact Linux fd identity in async/pool callers."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LINUX = ROOT / "kernel" / "subsystems" / "linux"
SOURCES = {
    "fanotify": LINUX / "fanotify.cpp",
    "inotify": LINUX / "inotify.cpp",
    "mq": LINUX / "msg_queues.cpp",
    "extra": LINUX / "extra_syscalls.cpp",
}


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving offsets."""
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


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
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
            closing_brace = matching_delimiter(code, opening_brace, "{", "}")
            return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function definition: {signature}")


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class ParserHostileTests(unittest.TestCase):
    def test_comments_literals_and_digit_separators_are_masked(self) -> None:
        hostile = r'''
// p->linux_fds[fd].state = 13;
/* LinuxFdAttachKFile(p, fd, 13, idx, release); */
const char* normal = "LinuxFdAllocLowest(p, 3)";
const char* raw = u8R"tag(LinuxFdSetOffset(p, fd, 9); // })tag";
u64 visible = 10'000'000ull;
'''
        visible = code_only(hostile)
        self.assertNotIn("linux_fds", visible)
        self.assertNotIn("LinuxFdAttachKFile", visible)
        self.assertNotIn("LinuxFdAllocLowest", visible)
        self.assertNotIn("LinuxFdSetOffset", visible)
        self.assertIn("10'000'000ull", visible)


class LinuxFdAsyncPoolsContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = {name: path.read_text(encoding="utf-8") for name, path in SOURCES.items()}
        cls.code = {name: code_only(text) for name, text in cls.source.items()}

    def test_owned_files_have_no_raw_fd_table_access_or_legacy_publish(self) -> None:
        for name, code in self.code.items():
            with self.subTest(source=name):
                self.assertNotRegex(code, r"\blinux_fds\s*\[")
                self.assertNotIn("LinuxFdAllocLowest", code)
                self.assertNotIn("LinuxFdAttachKFile", code)
                self.assertNotIn("LinuxFdGetOffset", code)
                self.assertNotIn("LinuxFdSetOffset", code)

    def test_pool_descriptor_creation_is_prepare_then_atomic_bind(self) -> None:
        cases = (
            ("fanotify", r"i64\s+DoFanotifyInit", "KFileKind::Fanotify"),
            ("inotify", r"i64\s+InotifyInit1", "KFileKind::Inotify"),
            ("mq", r"i64\s+DoMqOpen", "KFileKind::PosixMq"),
            ("extra", r"i64\s+DoMemfdCreate", "KFileKind::Memfd"),
        )
        for source_name, signature, kind in cases:
            with self.subTest(function=signature):
                body = function_body(self.source[source_name], signature)
                ordered(self, body, f"KFileCreate(ipc::{kind}", "LinuxFdPrepare", "LinuxFdBindLowest")
                self.assertIn("LinuxFdPreparedRelease", body)
                self.assertIn("KObjectRelease", body)

    def test_pool_users_pin_identity_from_acquired_snapshot(self) -> None:
        cases = (
            ("fanotify", r"i64\s+DoFanotifyMark", "FanPin"),
            ("inotify", r"i64\s+DoInotifyAddWatch", "InotifyPin"),
            ("inotify", r"i64\s+DoInotifyRmWatch", "InotifyPin"),
            ("mq", r"i64\s+DoMqGetsetattr", "PosixMqPin"),
        )
        for source_name, signature, pin in cases:
            with self.subTest(function=signature):
                body = function_body(self.source[source_name], signature)
                ordered(self, body, "LinuxFdAcquire", "acquired.snapshot.first_cluster", pin, "LinuxFdAcquiredRelease")
                self.assertNotRegex(body, r"\blinux_fds\s*\[")

    def test_posix_mq_blockers_hold_exact_receipt_across_wait_without_pool_pin(self) -> None:
        self.assertIn(
            "~LinuxFdAcquiredGuard() { core::LinuxFdAcquiredRelease(acquired); }",
            self.source["mq"],
        )
        for signature in (r"i64\s+DoMqTimedsend", r"i64\s+DoMqTimedreceive"):
            with self.subTest(function=signature):
                body = function_body(self.source["mq"], signature)
                ordered(
                    self,
                    body,
                    "LinuxFdAcquire",
                    "LinuxFdAcquiredGuard acquired_guard",
                    "acquired.snapshot.first_cluster",
                    "WaitWithDeadline",
                )
                self.assertNotIn("PosixMqPin", body)
                self.assertNotIn("LinuxFdAcquiredRelease", body)
                self.assertNotRegex(body, r"\blinux_fds\s*\[")

    def test_copy_file_range_serializes_exact_ofds_and_commits_by_generation(self) -> None:
        body = function_body(self.source["extra"], r"i64\s+DoCopyFileRange")
        self.assertGreaterEqual(body.count("LinuxFdAcquire"), 2)
        self.assertIn("input.snapshot.ofd < output.snapshot.ofd", body)
        self.assertGreaterEqual(body.count("LinuxFdIoGuardEnter"), 4)
        self.assertIn("LinuxFdRefreshAcquired", body)
        self.assertIn("LinuxFdIoGuardGetOffset", body)
        self.assertIn("LinuxFdIoGuardSetOffset", body)
        self.assertIn("LinuxFdCommitRegularMetadataAcquired", body)
        self.assertIn("kLinuxFdFlagPendingCreate", body)
        self.assertLess(body.rfind("LinuxFdIoGuardExit"), body.rfind("LinuxFdAcquiredRelease"))
        self.assertNotRegex(body, r"\blinux_fds\s*\[")

    def test_close_range_releases_detached_receipts_outside_fd_lock(self) -> None:
        body = function_body(self.source["extra"], r"i64\s+DoCloseRange")
        ordered(self, body, "LinuxFdUnbind", "LinuxFdDetachedRelease")
        self.assertNotIn("DoClose", body)

    def test_validation_and_root_handle_open_use_receipts(self) -> None:
        notify = function_body(self.source["mq"], r"i64\s+DoMqNotify")
        ordered(self, notify, "LinuxFdAcquire", "LinuxFdAcquiredRelease")
        fstatfs = function_body(self.source["extra"], r"i64\s+DoFstatfs")
        ordered(self, fstatfs, "LinuxFdAcquire", "CopyToUser", "LinuxFdAcquiredRelease")
        open_handle = function_body(self.source["extra"], r"i64\s+DoOpenByHandleAt")
        ordered(self, open_handle, "Process::LinuxFd payload", "LinuxFdPrepare", "LinuxFdBindLowest")


if __name__ == "__main__":
    unittest.main(verbosity=2)
