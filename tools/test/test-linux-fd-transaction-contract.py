#!/usr/bin/env python3
"""Hostile structural contract for the Linux fd transaction core."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
HANDLE_H = ROOT / "kernel" / "ipc" / "handle_table.h"
HANDLE_CPP = ROOT / "kernel" / "ipc" / "handle_table.cpp"


def code_only(source: str) -> str:
    """Blank comments and C/C++ literals while preserving delimiters/offsets."""
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


def type_body(source: str, declaration: str) -> str:
    code = code_only(source)
    match = re.search(declaration + r"[^;{]*\{", code)
    if match is None:
        raise AssertionError(f"missing type definition: {declaration}")
    opening = code.find("{", match.start())
    return code[opening + 1 : matching_delimiter(code, opening, "{", "}")]


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class ParserHostileTests(unittest.TestCase):
    def test_comments_and_literals_do_not_supply_contract_evidence(self) -> None:
        hostile = r'''
// struct LinuxFdAcquired { Process::LinuxFd snapshot; };
/* LinuxFdExport(source, fd, &transfer); */
const char* normal = "HandleTableAdoptReplace(table, old, next, rights) { }";
const char* raw = u8R"tag(LinuxFdTransferRelease(&fake); // })tag";
int visible = 7;
'''
        visible = code_only(hostile)
        self.assertNotIn("LinuxFdAcquired", visible)
        self.assertNotIn("LinuxFdExport", visible)
        self.assertNotIn("HandleTableAdoptReplace", visible)
        self.assertNotIn("LinuxFdTransferRelease", visible)
        self.assertIn("int visible = 7;", visible)

    def test_function_slicer_skips_a_prototype_and_literal_decoy(self) -> None:
        hostile = r'''
bool Probe(int);
const char* decoy = "bool Probe(int) { return false; }";
bool Probe(int value) { return value != 0; }
'''
        self.assertIn("return value != 0;", function_body(hostile, r"bool\s+Probe"))


class LinuxFdTransactionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.handle_h = HANDLE_H.read_text(encoding="utf-8")
        cls.handle_cpp = HANDLE_CPP.read_text(encoding="utf-8")

    def test_process_has_one_fd_lock_and_nonzero_slot_generation(self) -> None:
        process = type_body(self.process_h, r"struct\s+Process\b")
        linux_fd = type_body(self.process_h, r"struct\s+LinuxFd")
        self.assertRegex(process, r"sync::SpinLock\s+linux_fd_lock\s*;")
        self.assertRegex(linux_fd, r"u32\s+generation\s*;")
        create = function_body(self.process_cpp, r"Process\s*\*\s*ProcessCreate")
        self.assertIn("p->linux_fds[i].generation = 1", create)

    def test_receipts_expose_exact_strong_identity_and_explicit_cleanup(self) -> None:
        common = {
            "LinuxFdPrepared": ("Process::LinuxFd snapshot", "ipc::KObject* kfile_ref", "bool owns_ofd_ref"),
            "LinuxFdAcquired": ("Process::LinuxFd snapshot", "ipc::KObject* kfile_ref", "bool owns_ofd_ref"),
            "LinuxFdDetached": (
                "u32 source_fd",
                "Process::LinuxFd snapshot",
                "ipc::KObject* kfile_ref",
                "bool owns_ofd_ref",
            ),
            "LinuxFdTransfer": (
                "u32 source_fd",
                "Process::LinuxFd snapshot",
                "ipc::KObject* kfile_ref",
                "bool owns_ofd_ref",
            ),
        }
        for name, fields in common.items():
            body = re.sub(r"\s+", " ", type_body(self.process_h, rf"struct\s+{name}"))
            for field in fields:
                self.assertIn(field, body, f"{name} missing {field}")
        for cleanup in (
            "LinuxFdPreparedRelease",
            "LinuxFdAcquiredRelease",
            "LinuxFdDetachedRelease",
            "LinuxFdTransferRelease",
        ):
            self.assertRegex(code_only(self.process_h), rf"\bvoid\s+{cleanup}\s*\(")

    def test_acquire_and_clone_retain_identity_without_borrowed_slot_escape(self) -> None:
        retain = function_body(self.process_cpp, r"bool\s+LinuxFdRetainSlotLocked")
        ordered(
            self,
            retain,
            "candidate.snapshot = slot",
            "HandleTableLookupRef",
            "OfdRetainLocked",
            "*acquired = candidate",
        )
        acquire = function_body(self.process_cpp, r"bool\s+LinuxFdAcquire")
        ordered(self, acquire, "SpinLockGuard guard(p->linux_fd_lock)", "LinuxFdRetainSlotLocked")
        clone = function_body(self.process_cpp, r"bool\s+LinuxFdAcquiredClone")
        self.assertIn("OfdRetainLocked", clone)
        self.assertIn("KObjectAcquire", clone)
        self.assertNotIn("linux_fds", clone)

    def test_detach_moves_references_and_cleanup_runs_in_public_release(self) -> None:
        detach = function_body(self.process_cpp, r"bool\s+LinuxFdDetachSlotLocked")
        ordered(self, detach, "HandleTableDetach", "LinuxFdClearSlotLocked", "*detached = candidate")
        self.assertNotIn("KObjectRelease", detach)
        release = function_body(self.process_cpp, r"void\s+LinuxFdDetachedRelease")
        ordered(self, release, "LinuxFdClearSnapshot", "KObjectRelease", "LinuxFdReleaseOfd")

    def test_exact_import_uses_failure_atomic_handle_adoption_then_deferred_release(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdImportExact")
        ordered(
            self,
            body,
            "SpinLockGuard guard(destination->linux_fd_lock)",
            "HandleTableAdoptReplace",
            "LinuxFdPublishLocked",
            "LinuxFdConsumeTransfer",
            "KObjectRelease(displaced_object)",
            "LinuxFdReleaseOfd(displaced_ofd)",
        )

    def test_pair_bind_and_table_import_have_explicit_rollback(self) -> None:
        pair = function_body(self.process_cpp, r"bool\s+LinuxFdBindPairLowest")
        ordered(self, pair, "HandleTableInsert", "HandleTableDetach", "LinuxFdPublishLocked")
        table_import = function_body(self.process_cpp, r"bool\s+LinuxFdImportTable")
        ordered(self, table_import, "HandleTableInsert", "HandleTableDetach", "LinuxFdPublishLocked")
        self.assertNotIn("KObjectRelease", pair)
        self.assertNotIn("KObjectRelease", table_import)

    def test_legacy_entry_points_are_receipt_core_wrappers(self) -> None:
        close = function_body(self.process_cpp, r"void\s+LinuxFdClose")
        self.assertIn("LinuxFdUnbind", close)
        self.assertIn("LinuxFdDetachedRelease", close)
        self.assertNotIn("HandleTableRemove", close)

        duplicate = function_body(self.process_cpp, r"bool\s+LinuxFdDup")
        self.assertIn("LinuxFdDuplicateExact", duplicate)
        self.assertNotIn("linux_fds", duplicate)

        copy = function_body(self.process_cpp, r"bool\s+LinuxFdCopyAcrossProcesses")
        ordered(self, copy, "LinuxFdExport", "LinuxFdImportExact", "LinuxFdTransferRelease")
        self.assertNotIn("linux_fds", copy)
        self.assertNotIn("HandleTableDuplicate", copy)

        inherit = function_body(self.process_cpp, r"bool\s+LinuxFdInheritFromParent")
        ordered(
            self,
            inherit,
            "LinuxFdExportTable",
            "KFileKind::DirSnapshot",
            "LinuxFdTransferRelease",
            "LinuxFdImportTable",
            "return imported",
        )
        self.assertNotIn("linux_fds", inherit)

        cloexec = function_body(self.process_cpp, r"void\s+LinuxFdCloseOnExec")
        ordered(self, cloexec, "LinuxFdDetachCloexec", "LinuxFdDetachedRelease")

    def test_handle_adopt_replace_is_generation_safe_and_never_releases_in_lock(self) -> None:
        result = type_body(self.handle_h, r"struct\s+HandleAdoptReplaceResult")
        self.assertRegex(result, r"Handle\s+handle\s*;")
        self.assertRegex(result, r"KObject\s*\*\s*displaced\s*;")
        body = function_body(self.handle_cpp, r"HandleTableAdoptReplace")
        ordered(
            self,
            body,
            "KObjectRefcount(replacement)",
            "slot.state = HandleSlotState::Closing",
            "slot.acquisition_pins == 0",
            "++slot.generation",
            "slot.obj = replacement",
        )
        self.assertNotIn("KObjectAcquire", body)
        self.assertNotIn("KObjectRelease", body)


if __name__ == "__main__":
    unittest.main()
