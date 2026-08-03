#!/usr/bin/env python3
"""Hostile structural contract for strong pidfd Process identity.

The gate masks comments and every C/C++ literal form before inspecting the
implementation.  A prose promise about ownership therefore cannot satisfy a
missing retain/release, target lookup, or post-Exited readiness check.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KFILE_H = ROOT / "kernel" / "ipc" / "kfile.h"
KFILE_CPP = ROOT / "kernel" / "ipc" / "kfile.cpp"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
PIDFD_CPP = ROOT / "kernel" / "subsystems" / "linux" / "pidfd_splice.cpp"
ASYNC_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_async_io.cpp"


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

        # Do not parse C++ digit separators as character literals.
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


def matching_brace(source: str, opening: int) -> int:
    if opening < 0 or source[opening] != "{":
        raise AssertionError("missing opening brace")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError("unterminated brace region")


def function_body(source: str, signature: str) -> str:
    code = code_only(source)
    for match in re.finditer(signature + r"\s*\(", code):
        opening = code.find("{", match.end())
        semicolon = code.find(";", match.end(), opening if opening >= 0 else None)
        if opening >= 0 and semicolon < 0:
            return code[opening + 1 : matching_brace(code, opening)]
    raise AssertionError(f"missing function definition: {signature}")


def type_body(source: str, signature: str) -> str:
    code = code_only(source)
    match = re.search(signature, code)
    if match is None:
        raise AssertionError(f"missing type definition: {signature}")
    opening = code.find("{", match.end())
    return code[opening + 1 : matching_brace(code, opening)]


def case_body(source: str, label: str) -> str:
    match = re.search(rf"\bcase\s+{re.escape(label)}\s*:", source)
    if match is None:
        raise AssertionError(f"missing case {label}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"case {label} needs an explicit scope")
    return source[opening + 1 : matching_brace(source, opening)]


def require_order(body: str, *needles: str) -> None:
    cursor = -1
    for needle in needles:
        position = body.find(needle, cursor + 1)
        if position < 0:
            raise AssertionError(f"PRODUCTION RED: missing ordered token: {needle}")
        if position <= cursor:
            raise AssertionError(f"PRODUCTION RED: out-of-order token: {needle}")
        cursor = position


def compact(source: str) -> str:
    return re.sub(r"\s+", "", source)


class ParserHostileTests(unittest.TestCase):
    def test_comments_literals_and_raw_strings_cannot_spoof_contract(self) -> None:
        hostile = r'''
// ProcessRetain(target); ProcessRelease(target);
const char* ordinary = "KFileCreatePidfd(target); LinuxFdExport(target, fd, &transfer);";
const char* raw = R"tag(ProcessLifecycleState::Exited; LinuxFdImportLowest(caller, 3, &transfer))tag";
int visible = 7;
'''
        visible = code_only(hostile)
        self.assertNotIn("ProcessRetain", visible)
        self.assertNotIn("KFileCreatePidfd", visible)
        self.assertNotIn("ProcessLifecycleState", visible)
        self.assertNotIn("LinuxFdExport", visible)
        self.assertNotIn("LinuxFdImportLowest", visible)
        self.assertIn("int visible = 7;", visible)

    def test_function_parser_skips_declaration_decoy(self) -> None:
        hostile = "void Keep(Process* target);\nvoid Keep(Process* target) { ProcessRetain(target); }"
        self.assertIn("ProcessRetain(target)", function_body(hostile, r"void\s+Keep"))


class PidfdStrongIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.kfile_h = KFILE_H.read_text(encoding="utf-8")
        cls.kfile_cpp = KFILE_CPP.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.pidfd_cpp = PIDFD_CPP.read_text(encoding="utf-8")
        cls.async_cpp = ASYNC_CPP.read_text(encoding="utf-8")

    def test_kfile_owns_exactly_one_immutable_process_edge(self) -> None:
        kfile = type_body(self.kfile_h, r"struct\s+KFile")
        self.assertEqual(kfile.count("retained_process_target"), 1)

        factory = function_body(self.kfile_cpp, r"KFileCreatePidfd")
        require_order(factory, "ProcessRetain(target)", "f->retained_process_target = target", "return f")
        self.assertEqual(factory.count("ProcessRetain(target)"), 1)

        acquire = function_body(self.kfile_cpp, r"KFileAcquirePidfdTarget")
        self.assertIn("f->kind != KFileKind::Pidfd", acquire)
        require_order(acquire, "target = f->retained_process_target", "ProcessRetain(target)", "return target")

        destroy = function_body(self.kfile_cpp, r"void\s+KFileDestroy")
        require_order(
            destroy,
            "retained_process_target = f->retained_process_target",
            "f->retained_process_target = nullptr",
            "KFree(f)",
            "ProcessRelease(retained_process_target)",
        )
        self.assertEqual(destroy.count("ProcessRelease(retained_process_target)"), 1)

    def test_generic_factories_reject_weak_pidfd_creation(self) -> None:
        ordinary = function_body(self.kfile_cpp, r"KFileCreate")
        owner = function_body(self.kfile_cpp, r"KFileCreateWithOwner")
        self.assertIn("kind == KFileKind::Pidfd", ordinary)
        self.assertIn("kind == KFileKind::Pidfd", owner)
        self.assertIn("ErrorCode::InvalidArgument", ordinary)
        self.assertIn("ErrorCode::InvalidArgument", owner)

    def test_open_retains_live_target_then_transactionally_publishes_receipt(self) -> None:
        body = function_body(self.pidfd_cpp, r"i64\s+DoPidfdOpen")
        require_order(
            body,
            "SchedFindProcessByPidRetained(pid)",
            "ScopedProcessRuntimeAccess target_runtime(target.Get())",
            "SchedProcessAlive(target_pid)",
            "KFileCreatePidfd(target.Get())",
            "payload.state = 12",
            "LinuxFdPrepare(&prepared",
            "LinuxFdBindLowest(caller, 3, &prepared, true)",
        )
        self.assertNotIn("SchedProcessExists", body)
        self.assertNotIn("LinuxFdAttachKFile", body)
        self.assertNotIn("HandleTableInsert", body)
        self.assertNotRegex(body, r"\bcaller\s*->\s*linux_fds\b")

    def test_target_acquisition_consumes_retained_receipt_and_never_pid_resolves(self) -> None:
        body = function_body(self.pidfd_cpp, r"LinuxPidfdAcquireTarget")
        require_order(
            body,
            "acquired.snapshot.state != 12",
            "acquired.kfile_ref == nullptr",
            "reinterpret_cast<const ipc::KFile*>(acquired.kfile_ref)",
            "KFileAcquirePidfdTarget(file)",
        )
        self.assertNotIn("first_cluster", body)
        self.assertNotIn("SchedFindProcessByPid", body)
        self.assertNotIn("HandleTableLookupRef", body)

    def test_send_signal_uses_kfile_target_then_runtime_admits(self) -> None:
        body = function_body(self.pidfd_cpp, r"i64\s+DoPidfdSendSignal")
        require_order(
            body,
            "LinuxFdAcquire(caller",
            "LinuxPidfdAcquireTarget(acquired)",
            "LinuxFdAcquiredRelease(&acquired)",
            "ScopedProcessRuntimeAccess target_runtime(target.Get())",
            "SchedProcessAlive(target_pid)",
            "LinuxSignalDeliver(target.Get()",
        )
        self.assertNotIn("SchedFindProcessByPid", body)
        self.assertNotIn("first_cluster", body)
        self.assertNotRegex(body, r"\bcaller\s*->\s*linux_fds\b")

    def test_getfd_exports_retained_identity_then_imports_without_raw_target_slot_reads(self) -> None:
        body = function_body(self.pidfd_cpp, r"i64\s+DoPidfdGetfd")
        require_order(
            body,
            "LinuxFdAcquire(caller",
            "LinuxPidfdAcquireTarget(pidfd_acquired)",
            "LinuxFdAcquiredRelease(&pidfd_acquired)",
            "ScopedProcessRuntimeAccess target_runtime(target.Get())",
            "SchedProcessAlive(target_pid)",
            "LinuxFdTransfer",
            "LinuxFdExport(target.Get()",
            "LinuxFdImportLowest(caller",
            "LinuxFdTransferRelease",
        )
        self.assertNotIn(
            "LinuxFdCopyAcrossProcesses",
            body,
            "PRODUCTION RED: pidfd_getfd still performs the old dual-table copy instead of export/import",
        )
        self.assertNotRegex(
            body,
            r"\btarget\s*->\s*linux_fds\b|\btarget\.Get\s*\(\s*\)\s*->\s*linux_fds\b",
            "PRODUCTION RED: pidfd_getfd reads the target fd slot without the fd-table transaction lock",
        )
        self.assertNotRegex(
            body,
            r"SpinLock(?:Guard|Acquire)[^;\n]*(?:linux_fd|fd_table)",
            "PRODUCTION RED: pidfd_getfd holds the fd lock across transfer cleanup instead of using receipt APIs",
        )
        self.assertNotIn("SchedFindProcessByPid", body)
        self.assertNotIn("first_cluster", body)

    def test_epoll_readiness_requires_exact_exited_lifecycle(self) -> None:
        ready = function_body(self.async_cpp, r"u32\s+LinuxFdEpollReady")
        pidfd = case_body(ready, "12")
        require_order(
            pidfd,
            "acquired.kfile_ref == nullptr",
            "ScopedProcessRef target(LinuxPidfdAcquireTarget(acquired))",
            "target && core::ProcessLifecycleLoad(target.Get()) == core::ProcessLifecycleState::Exited",
            "ready |= kEPOLLIN",
        )
        self.assertNotIn("SchedProcessAlive", pidfd)
        self.assertNotIn("first_cluster", pidfd)
        self.assertNotIn("CurrentProcess", ready)
        self.assertNotIn("linux_fds", ready)

    def test_descriptor_duplication_shares_kfile_instead_of_process_refs(self) -> None:
        duplicate = function_body(self.process_cpp, r"bool\s+LinuxFdDup")
        self.assertTrue(
            "HandleTableDuplicate" in duplicate or "LinuxFdDuplicateExact" in duplicate,
            "descriptor dup neither retains the KFile nor delegates to the fd transaction helper",
        )
        self.assertNotIn("ProcessRetain", duplicate)
        self.assertNotIn("KFileCreatePidfd", duplicate)

        cross_process = function_body(self.process_cpp, r"bool\s+LinuxFdCopyAcrossProcesses")
        if "HandleTableDuplicate" not in cross_process:
            require_order(
                cross_process,
                "LinuxFdExport(",
                "LinuxFdImportExact(",
                "LinuxFdTransferRelease(",
            )
        self.assertNotIn("ProcessRetain", cross_process)
        self.assertNotIn("KFileCreatePidfd", cross_process)


if __name__ == "__main__":
    unittest.main(verbosity=2)
