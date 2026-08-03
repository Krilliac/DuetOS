#!/usr/bin/env python3
"""Structural guardrails for the executable portion of Job runtime proof.

This deliberately distinguishes the shipped single-process smoke from the
separate child-process QEMU profile that does not exist yet. Source shape is
not runtime proof, but it can prevent the base fixture from regressing into a
hard-coded exit result or falsely advertising unsupported child coverage.
"""

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


class JobRuntimeProofContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.kernel32_sync = read("userland/libs/kernel32/kernel32_sync.c")
        cls.ntdll_build = read("tools/build/build-ntdll-dll.sh")
        cls.smoke = read("userland/apps/jobobj_smoke/jobobj_smoke.c")
        cls.todo = read("userland/apps/jobobj_smoke/JOB_RUNTIME_QEMU_TODO.md")
        cls.job_header = read("kernel/proc/job.h")
        cls.syscall_abi = read("wiki/specifications/Syscall-ABI.md")

    def test_get_exit_code_process_queries_class_zero_and_preserves_failure_output(self) -> None:
        body = function_body(self.kernel32_sync, r"BOOL\s+GetExitCodeProcess")
        self.assertIn("NtQueryInformationProcess", body)
        self.assertRegex(body, r"NtQueryInformationProcess\s*\(\s*hProcess\s*,\s*0\s*,")
        self.assertIn("RtlNtStatusToDosError", body)
        self.assertRegex(body, r"lpExitCode\s*==\s*\(DWORD\s*\*\)\s*0")
        query = body.index("NtQueryInformationProcess")
        output_write = body.index("*lpExitCode")
        self.assertLess(query, output_write, "caller output is written before handle validation")
        self.assertNotRegex(body, r"\*\s*lpExitCode\s*=\s*0x103\b")

    def test_ntdll_exports_the_real_query_facade_exactly_once(self) -> None:
        nt_exports = re.findall(r"/export:NtQueryInformationProcess(?:=([^\s\\]+))?", self.ntdll_build)
        zw_exports = re.findall(r"/export:ZwQueryInformationProcess(?:=([^\s\\]+))?", self.ntdll_build)
        self.assertEqual(nt_exports, [""], "NtQueryInformationProcess must have one direct export")
        self.assertEqual(zw_exports, ["NtQueryInformationProcess"],
                         "ZwQueryInformationProcess must alias the real facade once")
        self.assertNotIn("NtQueryInformationProcess=NtReturnNotImpl", self.ntdll_build)
        self.assertNotIn("ZwQueryInformationProcess=NtReturnNotImpl", self.ntdll_build)

    def test_smoke_executes_exit_query_partial_list_and_last_close_contracts(self) -> None:
        body = function_body(self.smoke, r"void\s+__cdecl\s+mainCRTStartup")
        for required in (
            "GetExitCodeProcess(self, &exit_code)",
            "GetExitCodeProcess(self, NULL)",
            "GetExitCodeProcess((HANDLE)(ULONG_PTR)0x700UL, &exit_code)",
            "DUETOS_JOB_PROCESS_ID_HEADER",
            "NumberOfAssignedProcesses == 1",
            "NumberOfProcessIdsInList == 0",
        ):
            self.assertIn(required, body)
        close = body.index("CloseHandle(job)")
        post_close_membership = body.index("IsProcessInJob(self, NULL, &in_job)", close)
        self.assertLess(close, post_close_membership)
        self.assertIn("last Job close severed live membership", self.smoke)

    def test_unavailable_child_profile_is_a_named_todo_not_a_fake_pass(self) -> None:
        self.assertNotIn("[jobobj-runtime-profile] PASS", self.smoke)
        for required in (
            "not a passing test",
            "0x4A4F42",
            "at least 33",
            "child/grandchild inheritance proof",
            "CreateProcessA/W",
            "OpenProcess",
            "WaitForSingleObject",
            "embedded image",
        ):
            self.assertIn(required, self.todo)

    def test_documented_job_handle_band_matches_the_fixed_pool(self) -> None:
        self.assertRegex(self.job_header, r"kJobPoolCapacity\s*=\s*8\s*;")
        self.assertIn("low tag `0xC00` through `0xC07`", self.syscall_abi)
        self.assertNotIn("low tag `0xC00` through `0xC1F`", self.syscall_abi)


if __name__ == "__main__":
    unittest.main(verbosity=2)
