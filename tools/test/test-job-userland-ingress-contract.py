#!/usr/bin/env python3
"""Hostile structural contract for the real Win32 Job-object ingress."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def mask_comments_and_literals(text: str) -> str:
    output = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        if state == "code":
            if text.startswith("//", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "line"
                continue
            if text.startswith("/*", index):
                output[index] = output[index + 1] = " "
                index += 2
                state = "block"
                continue
            if text[index] in {'"', "'"}:
                quote = text[index]
                output[index] = " "
                state = "literal"
        elif state == "line":
            if text[index] == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block":
            output[index] = " "
            if text.startswith("*/", index):
                output[index + 1] = " "
                index += 1
                state = "code"
        else:
            output[index] = " "
            if text[index] == "\\" and index + 1 < len(text):
                output[index + 1] = " "
                index += 1
            elif text[index] == quote:
                state = "code"
        index += 1
    return "".join(output)


def function_body(source: str, signature: str) -> str:
    masked = mask_comments_and_literals(source)
    match = re.search(signature + r"\s*\([^;{}]*\)\s*\{", masked)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = masked.find("{", match.start())
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return masked[opening : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class JobUserlandIngressContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ntdll = read("userland/libs/ntdll/ntdll.c")
        cls.ntdll_internal = read("userland/libs/ntdll/ntdll_internal.h")
        cls.ntdll_job = read("userland/libs/ntdll/ntdll_token.c")
        cls.ntdll_rtl = read("userland/libs/ntdll/ntdll_rtl.c")
        cls.kernel32 = read("userland/libs/kernel32/kernel32_io.c")
        cls.kernel32_build = read("tools/build/build-kernel32-dll.sh")
        cls.ntdll_build = read("tools/build/build-ntdll-dll.sh")
        cls.smoke = read("userland/apps/jobobj_smoke/jobobj_smoke.c")
        cls.kernel_job_h = read("kernel/subsystems/win32/job_syscall.h")

    def test_ntdll_handle_shape_matches_kernel_generation_band(self) -> None:
        for expected in (
            "DUETOS_JOB_HANDLE_BASE 0xC00ULL",
            "DUETOS_JOB_HANDLE_CAP 8ULL",
            "DUETOS_JOB_HANDLE_TAG_MASK 0xFFFULL",
            "DUETOS_JOB_HANDLE_GENERATION_SHIFT 12",
        ):
            self.assertIn(expected, self.ntdll_internal)
        predicate = function_body(self.ntdll_internal, r"static\s+inline\s+BOOL\s+ntdll_is_job_handle")
        self.assertIn("1ULL << 63", predicate)
        self.assertIn("DUETOS_JOB_HANDLE_GENERATION_SHIFT", predicate)
        self.assertIn("ntdll_has_job_handle_tag", predicate)
        self.assertIn("kJobHandleBase = 0xC00ULL", self.kernel_job_h)
        self.assertIn("kJobHandleGenerationShift = 12", self.kernel_job_h)

    def test_ntclose_uses_dedicated_job_close_and_observes_failure(self) -> None:
        body = function_body(self.ntdll, r"NTSTATUS\s+NtClose")
        self.assertRegex(body, r"ntdll_has_job_handle_tag\s*\(\s*h\s*\)\s*\?\s*168\s*:\s*22")
        self.assertRegex(body, r"if\s*\(\s*rv\s*<\s*0\s*\)\s*return\s+NTSTATUS_INVALID_HANDLE")
        close = function_body(self.kernel32, r"BOOL\s+CloseHandle")
        self.assertIn("NtClose(h)", close)
        self.assertNotIn("int $0x80", close)
        self.assertNotRegex(close, r"return\s+1\s*;")

    def test_job_nt_surface_uses_real_syscalls_and_no_legacy_stub(self) -> None:
        calls = {
            "NtCreateJobObject": 163,
            "NtAssignProcessToJobObject": 164,
            "NtTerminateJobObject": 166,
        }
        for function, number in calls.items():
            with self.subTest(function=function):
                body = function_body(self.ntdll_job, rf"NTSTATUS\s+{function}")
                self.assertIn(str(number), body)
                self.assertNotIn("NTSTATUS_NOT_IMPLEMENTED", body)
        is_in = function_body(self.ntdll_job, r"static\s+long\s+long\s+ntdll_job_is_process_in_syscall")
        query = function_body(self.ntdll_job, r"static\s+long\s+long\s+ntdll_job_query_syscall")
        self.assertIn("165", is_in)
        self.assertIn("167", query)
        self.assertGreaterEqual(self.ntdll_job.count("int $0x80"), 5)
        self.assertIn("ntdll_token.c", self.ntdll_build)

    def test_kernel32_facades_do_not_duplicate_the_syscall_abi(self) -> None:
        pairs = (
            ("CreateJobObjectW", "NtCreateJobObject"),
            ("AssignProcessToJobObject", "NtAssignProcessToJobObject"),
            ("IsProcessInJob", "NtIsProcessInJob"),
            ("TerminateJobObject", "NtTerminateJobObject"),
            ("QueryInformationJobObject", "NtQueryInformationJobObject"),
        )
        for function, nt_function in pairs:
            with self.subTest(function=function):
                body = function_body(self.kernel32, rf"(?:HANDLE|BOOL)\s+{function}")
                self.assertIn(nt_function, body)
                self.assertNotIn("int $0x80", body)
        self.assertIn("RtlNtStatusToDosError", self.kernel32)
        self.assertIn("NTSTATUS_INVALID_HANDLE", self.ntdll_rtl)

    def test_shipping_kernel32_exports_every_real_job_entry(self) -> None:
        for export in (
            "CreateJobObjectW",
            "AssignProcessToJobObject",
            "IsProcessInJob",
            "TerminateJobObject",
            "QueryInformationJobObject",
            "CloseHandle",
        ):
            with self.subTest(export=export):
                self.assertRegex(self.kernel32_build, rf"/export:{export}\b")

    def test_smoke_is_verdict_bearing_and_hostile_to_stale_handles(self) -> None:
        for operation in (
            "CreateJobObjectW",
            "AssignProcessToJobObject",
            "QueryInformationJobObject",
            "TerminateJobObject",
            "CloseHandle",
        ):
            self.assertIn(operation, self.smoke)
        self.assertIn("stale Job double-close accepted", self.smoke)
        self.assertIn("stale Job termination accepted", self.smoke)
        self.assertIn("slot-only legacy Job handle accepted", self.smoke)
        self.assertIn("[ring3-jobobj-smoke] PASS", self.smoke)


if __name__ == "__main__":
    unittest.main(verbosity=2)
