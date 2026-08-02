#!/usr/bin/env python3
"""Hostile structural contract for coherent process-owned Linux CWD state."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
SYSCALL_PATH_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_path.cpp"


def code_only(source: str) -> str:
    """Blank comments and literals so they cannot satisfy source contracts."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for index in range(begin, end):
            if masked[index] not in "\r\n":
                masked[index] = " "

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
        closing_brace = matching_delimiter(code, opening_brace, "{", "}")
        return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function definition: {signature}")


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class LinuxCwdSyncContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.syscall_path_cpp = SYSCALL_PATH_CPP.read_text(encoding="utf-8")

    def test_process_owns_leaf_lock_and_fixed_snapshot(self) -> None:
        self.assertRegex(
            self.process_h,
            r"mutable\s+sync::SpinLock\s+linux_cwd_lock\s*;\s*char\s+linux_cwd\s*\[kLinuxCwdCap\]\s*;",
        )
        self.assertRegex(
            self.process_h,
            r"struct\s+LinuxCwdSnapshot\s*\{[^}]*char\s+path\s*\[Process::kLinuxCwdCap\]\s*;"
            r"[^}]*u64\s+length\s*;",
        )
        self.assertIn("never nest it with fd/OFD/handle/VM locks", self.process_h)

    def test_public_api_is_result_bearing_and_process_scoped(self) -> None:
        header_code = code_only(self.process_h)
        self.assertRegex(
            header_code,
            r"bool\s+ProcessSnapshotLinuxCwd\s*\(\s*const\s+Process\s*\*\s*process\s*,"
            r"\s*LinuxCwdSnapshot\s*\*\s*snapshot_out\s*\)\s*;",
        )
        self.assertRegex(
            header_code,
            r"bool\s+ProcessReplaceLinuxCwd\s*\(\s*Process\s*\*\s*process\s*,"
            r"\s*const\s+char\s*\*\s*path\s*,\s*u64\s+length\s*\)\s*;",
        )

    def test_process_create_initializes_lock_and_default_before_publication(self) -> None:
        create = function_body(self.process_cpp, r"Process\s*\*\s*ProcessCreate")
        ordered(
            self,
            create,
            "p->linux_cwd_lock.next_ticket = 0",
            "p->linux_cwd_lock.now_serving = 0",
            "p->linux_cwd_lock.owner_cpu = 0xFFFFFFFFu",
            "p->linux_cwd_lock.class_id = sync::kLockClassUnclassified",
            "p->linux_cwd[0] =",
            "return p",
        )

    def test_snapshot_copies_under_lock_then_publishes_local_result(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+ProcessSnapshotLinuxCwd")
        ordered(
            self,
            body,
            "*snapshot_out = LinuxCwdSnapshot{}",
            "LinuxCwdSnapshot candidate{}",
            "SpinLockGuard cwd_guard(process->linux_cwd_lock)",
            "candidate.path[i] = process->linux_cwd[i]",
            "candidate.length < Process::kLinuxCwdCap",
            "*snapshot_out = candidate",
        )
        for forbidden in ("KMalloc", "CopyToUser", "CopyFromUser", "KLOG_", "linux_fd_lock", "g_ofd_lock"):
            self.assertNotIn(forbidden, body)

    def test_replace_builds_candidate_before_leaf_copy(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+ProcessReplaceLinuxCwd")
        ordered(
            self,
            body,
            "length == 0",
            "length >= Process::kLinuxCwdCap",
            "char candidate[Process::kLinuxCwdCap]{}",
            "if (path[i] == 0)",
            "candidate[i] = path[i]",
            "SpinLockGuard cwd_guard(process->linux_cwd_lock)",
            "process->linux_cwd[i] = candidate[i]",
            "return true",
        )
        locked_copy = body.find("SpinLockGuard cwd_guard(process->linux_cwd_lock)")
        self.assertNotIn("path[i]", body[locked_copy:])
        for forbidden in ("KMalloc", "CopyToUser", "CopyFromUser", "KLOG_", "linux_fd_lock", "g_ofd_lock"):
            self.assertNotIn(forbidden, body)

    def test_chdir_replaces_from_validated_kernel_copy(self) -> None:
        body = function_body(self.syscall_path_cpp, r"i64\s+DoChdir")
        ordered(
            self,
            body,
            "mm::CopyUserCString(kbuf",
            "copy.status == mm::UserStringCopyStatus::NoTerminator",
            "const u64 len = copy.length",
            "len == 0",
            "ProcessReplaceLinuxCwd(p, kbuf, len)",
            "KLOG_INFO_S",
        )
        self.assertIn("kbuf", body[body.rfind("KLOG_INFO_S") :])

    def test_fchdir_releases_fd_receipt_before_cwd_replacement(self) -> None:
        body = function_body(self.syscall_path_cpp, r"i64\s+DoFchdir")
        ordered(
            self,
            body,
            "LinuxFdAcquire(p",
            "acquired.snapshot.path[cwd_len]",
            "const bool path_terminated",
            "LinuxFdAcquiredRelease(&acquired)",
            "!path_terminated",
            "ProcessReplaceLinuxCwd(p, cwd, cwd_len)",
            "KLOG_INFO_S",
        )
        self.assertIn("cwd", body[body.rfind("KLOG_INFO_S") :])
        replace = body.find("ProcessReplaceLinuxCwd(p, cwd, cwd_len)")
        self.assertNotIn("acquired.snapshot", body[replace:])

    def test_getcwd_user_copy_consumes_unlocked_local_snapshot(self) -> None:
        body = function_body(self.syscall_path_cpp, r"i64\s+DoGetcwd")
        ordered(
            self,
            body,
            "LinuxCwdSnapshot cwd{}",
            "ProcessSnapshotLinuxCwd(p, &cwd)",
            "const u64 need = cwd.length + 1",
            "mm::CopyToUser(reinterpret_cast<void*>(user_buf), cwd.path, need)",
            "KLOG_DEBUG_S",
        )
        self.assertIn("cwd.path", body[body.rfind("KLOG_DEBUG_S") :])

    def test_syscall_callers_do_not_access_raw_process_cwd_storage(self) -> None:
        caller_code = code_only(self.syscall_path_cpp)
        self.assertNotRegex(caller_code, r"(?:->|\.)\s*linux_cwd\b")


if __name__ == "__main__":
    unittest.main()
