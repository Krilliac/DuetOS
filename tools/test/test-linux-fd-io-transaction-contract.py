#!/usr/bin/env python3
"""Structural fence for Linux fd syscall transaction migration."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OWNED = (
    ROOT / "kernel/subsystems/linux/syscall_fd.cpp",
    ROOT / "kernel/subsystems/linux/syscall_file.cpp",
    ROOT / "kernel/subsystems/linux/syscall_io.cpp",
    ROOT / "kernel/subsystems/linux/syscall_pipe.cpp",
)


def code_only(source: str) -> str:
    """Blank comments and quoted literals without changing line structure."""
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


class ParserHostileTests(unittest.TestCase):
    def test_comments_and_literals_cannot_hide_raw_slot_access(self) -> None:
        hostile = r'''
// process->linux_fds[fd].state = 2;
/* LinuxFdAllocLowest(process, 3); */
const char* decoy = "LinuxFdClose(process, fd)";
int visible = process->linux_fds[fd].state;
'''
        visible = code_only(hostile)
        self.assertNotIn("LinuxFdAllocLowest", visible)
        self.assertNotIn("LinuxFdClose", visible)
        self.assertEqual(visible.count("linux_fds["), 1)


class LinuxFdIoTransactionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = {path.name: code_only(path.read_text(encoding="utf-8")) for path in OWNED}

    def test_owned_callers_never_touch_process_fd_slots_directly(self) -> None:
        for name, source in self.sources.items():
            self.assertNotRegex(source, r"\blinux_fds\s*\[", f"raw fd-table access remains in {name}")

    def test_owned_callers_do_not_use_legacy_multistep_helpers(self) -> None:
        forbidden = (
            "LinuxFdAllocLowest",
            "LinuxFdAttachKFile",
            "LinuxFdAttachKFileOwned",
            "LinuxFdClose",
            "LinuxFdDup",
            "LinuxFdGetOffset",
            "LinuxFdSetOffset",
            "LinuxFdGetStatusFlags",
            "LinuxFdSetStatusFlags",
            "LinuxFdSetCloexec",
        )
        for name, source in self.sources.items():
            for symbol in forbidden:
                self.assertNotRegex(source, rf"\b{symbol}\s*\(", f"legacy helper {symbol} remains in {name}")

    def test_creation_and_teardown_use_explicit_ownership_receipts(self) -> None:
        file_source = self.sources["syscall_file.cpp"]
        pipe_source = self.sources["syscall_pipe.cpp"]
        self.assertIn("LinuxFdPrepare", file_source)
        self.assertIn("LinuxFdBindLowest", file_source)
        self.assertIn("LinuxFdUnbind", file_source)
        self.assertIn("LinuxFdDetachedRelease", file_source)
        self.assertIn("LinuxFdPrepare", pipe_source)
        self.assertIn("LinuxFdBindPairLowest", pipe_source)
        self.assertIn("LinuxFdPreparedRelease", pipe_source)

    def test_operational_paths_hold_explicit_acquired_receipts(self) -> None:
        fd_source = self.sources["syscall_fd.cpp"]
        file_source = self.sources["syscall_file.cpp"]
        io_source = self.sources["syscall_io.cpp"]
        self.assertIn("LinuxFdDuplicateLowest", fd_source)
        self.assertIn("LinuxFdDuplicateExact", fd_source)
        for source in (file_source, io_source):
            self.assertIn("LinuxFdAcquire", source)
            self.assertIn("LinuxFdAcquiredRelease", source)

    def test_regular_io_uses_shared_ofd_serialization_and_exact_metadata_commit(self) -> None:
        source = self.sources["syscall_io.cpp"]
        self.assertIn("LinuxFdIoGuardEnter", source)
        self.assertIn("LinuxFdIoGuardExit", source)
        self.assertIn("LinuxFdRefreshAcquired", source)
        self.assertIn("LinuxFdIoGuardGetOffset", source)
        self.assertIn("LinuxFdIoGuardSetOffset", source)
        self.assertIn("LinuxFdCommitRegularMetadataAcquired", source)

    def test_fcntl_and_pipe_rollback_use_generation_checked_receipts(self) -> None:
        fd_source = self.sources["syscall_fd.cpp"]
        pipe_source = self.sources["syscall_pipe.cpp"]
        self.assertIn("LinuxFdSetCloexecAcquired", fd_source)
        self.assertIn("LinuxFdIoGuardGetStatusFlags", fd_source)
        self.assertIn("LinuxFdIoGuardSetStatusFlags", fd_source)
        self.assertIn("LinuxFdUnbindAcquired", pipe_source)


if __name__ == "__main__":
    unittest.main()
