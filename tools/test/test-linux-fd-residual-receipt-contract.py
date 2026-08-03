#!/usr/bin/env python3
"""Hostile structural fence for residual Linux fd receipt callers."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LINUX = ROOT / "kernel/subsystems/linux"
SOURCES = {
    name: LINUX / name
    for name in (
        "syscall_xattr.cpp",
        "syscall_path.cpp",
        "syscall_fs_mut.cpp",
        "syscall_misc.cpp",
        "syscall_socket.cpp",
        "syscall_stub.cpp",
        "syscall_clone.cpp",
    )
}


def code_only(source: str) -> str:
    """Blank comments and quoted literals while preserving delimiters."""
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
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise AssertionError("unterminated block comment")
            blank(index, end + 2)
            index = end + 2
        elif (source[index] == "'" and index > 0 and index + 1 < len(source)
              and source[index - 1].isalnum() and source[index + 1].isalnum()):
            index += 1
        elif source[index] in "\"'":
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
            blank(index, end)
            index = end
        else:
            index += 1
    return "".join(masked)


def function_body(source: str, signature: str) -> str:
    code = code_only(source)
    match = re.search(signature + r"\s*\([^;{]*\)\s*\{", code)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = code.find("{", match.start())
    depth = 0
    for index in range(opening, len(code)):
        depth += code[index] == "{"
        depth -= code[index] == "}"
        if depth == 0:
            return code[opening + 1 : index]
    raise AssertionError(f"unterminated function: {signature}")


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class LinuxFdResidualReceiptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = {name: path.read_text(encoding="utf-8") for name, path in SOURCES.items()}
        cls.code = {name: code_only(text) for name, text in cls.source.items()}

    def test_parser_ignores_comment_and_string_decoys(self) -> None:
        hostile = '// p->linux_fds[fd].state = 6;\nconst char* s = "LinuxFdClose(p, fd)";\nint live = 1;'
        visible = code_only(hostile)
        self.assertNotIn("linux_fds", visible)
        self.assertNotIn("LinuxFdClose", visible)
        self.assertIn("int live = 1", visible)

    def test_owned_files_have_no_raw_slots_or_legacy_helpers(self) -> None:
        forbidden = r"\bLinuxFd(?:AllocLowest|AttachKFile(?:Owned)?|Close|Dup|GetOffset|SetOffset|GetStatusFlags|SetStatusFlags|SetCloexec)\s*\("
        for name, code in self.code.items():
            with self.subTest(source=name):
                self.assertNotRegex(code, r"\blinux_fds\s*\[")
                self.assertNotRegex(code, forbidden)

    def test_regular_truncate_is_guarded_and_commits_shared_metadata(self) -> None:
        body = function_body(self.source["syscall_fs_mut.cpp"], r"i64\s+DoFtruncate")
        ordered(self, body, "LinuxFdAcquire", "LinuxFdIoGuardEnter", "Fat32TruncateAtPath",
                "LinuxFdCommitRegularMetadataAcquired", "LinuxFdIoGuardExit", "LinuxFdAcquiredRelease")

    def test_poll_and_directory_cursors_hold_receipts(self) -> None:
        poll = function_body(self.source["syscall_misc.cpp"], r"i64\s+DoPoll")
        ordered(self, poll, "LinuxFdAcquire", "LinuxFdEpollReady(acquired", "LinuxFdAcquiredRelease")
        for name in ("DoGetdents64", "DoGetdents"):
            body = function_body(self.source["syscall_misc.cpp"], rf"i64\s+{name}")
            ordered(self, body, "LinuxFdAcquire", "LinuxFdIoGuardEnter", "u32 next_index =",
                    "CopyToUser", "dh.next_index = next_index", "LinuxFdIoGuardExit", "LinuxFdAcquiredRelease")

    def test_socket_publication_and_copyout_rollback_are_exact(self) -> None:
        socket = self.source["syscall_socket.cpp"]
        bind = function_body(socket, r"i64\s+BindSocket")
        ordered(self, bind, "KFileCreate", "LinuxFdPrepare", "LinuxFdBindLowest")
        accept = function_body(socket, r"i64\s+DoAccept4")
        ordered(self, accept, "BindSocket", "LinuxFdUnbindAcquired", "LinuxFdDetachedRelease",
                "LinuxFdAcquiredRelease")
        acquire = function_body(socket, r"bool\s+FdAcquireSocket")
        ordered(self, acquire, "MaskedIndex", "LinuxFdAcquire", "acquired->snapshot.first_cluster")

    def test_every_socket_operation_pins_one_identity(self) -> None:
        socket = self.source["syscall_socket.cpp"]
        for name in ("DoBind", "DoListen", "DoConnect", "DoSendto", "DoRecvfrom", "DoSendmsg", "DoRecvmsg",
                     "DoShutdown", "DoGetsockname", "DoGetpeername", "DoSetsockopt", "DoGetsockopt", "DoRecvmmsg",
                     "DoSendmmsg"):
            body = function_body(socket, rf"i64\s+{name}")
            with self.subTest(function=name):
                ordered(self, body, "FdAcquireSocket", "LinuxFdAcquiredRelease")
        self.assertNotIn("DoRecvmsg(fd", function_body(socket, r"i64\s+DoRecvmmsg"))
        self.assertNotIn("DoSendmsg(fd", function_body(socket, r"i64\s+DoSendmmsg"))

    def test_readiness_declaration_requires_retained_identity(self) -> None:
        header = code_only((LINUX / "syscall_async_io.h").read_text(encoding="utf-8"))
        self.assertRegex(header, r"LinuxFdEpollReady\s*\(\s*const core::LinuxFdAcquired&")

    def test_fork_inheritance_is_failure_atomic(self) -> None:
        body = function_body(self.source["syscall_clone.cpp"], r"i64\s+DoFork")
        ordered(self, body, "if (!core::LinuxFdInheritFromParent", "ProcessRelease(child)", "return kENOMEM")


if __name__ == "__main__":
    unittest.main(verbosity=2)
