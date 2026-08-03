#!/usr/bin/env python3
"""Hostile structural guards for translated cooperative exit unwinding."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LINUX_SYSCALL_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall.cpp"
LINUX_SYSCALL_H = ROOT / "kernel" / "subsystems" / "linux" / "syscall.h"
LINUX_PROC_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_proc.cpp"
TRANSLATE_CPP = ROOT / "kernel" / "subsystems" / "translation" / "translate.cpp"
NATIVE_SYSCALL_CPP = ROOT / "kernel" / "syscall" / "syscall.cpp"


def braced_body(source: str, opening: int) -> str:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError("unterminated braced region")


def function_body(source: str, signature: str) -> str:
    match = re.search(signature + r"\s*\([^;{}]*\)\s*(?:const\s*)?\{", source)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    return braced_body(source, source.find("{", match.start()))


def require_pattern(source: str, pattern: str, message: str) -> re.Match[str]:
    match = re.search(pattern, source, re.DOTALL)
    if match is None:
        raise AssertionError(message)
    return match


def reject_pattern(source: str, pattern: str, message: str) -> None:
    if re.search(pattern, source, re.DOTALL) is not None:
        raise AssertionError(message)


class LinuxExitUnwindContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.linux_cpp = LINUX_SYSCALL_CPP.read_text(encoding="utf-8")
        cls.linux_h = LINUX_SYSCALL_H.read_text(encoding="utf-8")
        cls.proc_cpp = LINUX_PROC_CPP.read_text(encoding="utf-8")
        cls.translate_cpp = TRANSLATE_CPP.read_text(encoding="utf-8")
        cls.native_cpp = NATIVE_SYSCALL_CPP.read_text(encoding="utf-8")

    def test_linux_exit_wrapper_is_returning_and_result_bearing(self) -> None:
        require_pattern(
            self.linux_h,
            r"\bi64\s+LinuxExit\s*\(\s*u64\s+status\s*\)\s*;",
            "LinuxExit declaration is not result-bearing",
        )
        reject_pattern(
            self.linux_h,
            r"\[\[noreturn\]\][^;]*\bLinuxExit\b",
            "LinuxExit still promises not to return after cooperative cancellation",
        )
        body = function_body(self.linux_cpp, r"i64\s+LinuxExit")
        require_pattern(body, r"\breturn\s+DoExitGroup\s*\(\s*status\s*\)\s*;", "LinuxExit drops the exit result")
        reject_pattern(body, r"\b(?:SchedExit|DEBUG_UNREACHABLE)\b", "LinuxExit abandons or panics on a live frame")

    def test_linux_dispatch_propagates_both_exit_results(self) -> None:
        body = function_body(self.linux_cpp, r'extern\s+"C"\s+void\s+LinuxSyscallDispatch')
        require_pattern(
            body,
            r"case\s+kSysExit\s*:\s*rv\s*=\s*DoExit\s*\(\s*frame->rdi\s*\)\s*;\s*break\s*;",
            "SYS_exit still relies on a false non-returning handler contract",
        )
        require_pattern(
            body,
            r"case\s+kSysExitGroup\s*:\s*rv\s*=\s*DoExitGroup\s*\(\s*frame->rdi\s*\)\s*;\s*break\s*;",
            "SYS_exit_group still relies on a false non-returning handler contract",
        )

    def test_exit_group_only_publishes_intent_then_returns(self) -> None:
        body = function_body(self.proc_cpp, r"i64\s+DoExitGroup")
        request = require_pattern(
            body,
            r"\bSchedRequestCurrentExit\s*\(\s*sched::KillReason::ExplicitExit\s*,\s*"
            r"static_cast<u32>\s*\(\s*status\s*&\s*0xFF\s*\)\s*\)",
            "exit_group does not atomically bind the exact Linux status to cooperative exit intent",
        )
        returned = require_pattern(body, r"\breturn\s+0\s*;", "exit_group does not return through its dispatcher")
        self.assertLess(request.start(), returned.start(), "exit_group returns before publishing exit intent")
        reject_pattern(body, r"\bSchedExit\s*\(", "exit_group still abandons the current kernel frame")

    def test_nt_termination_helpers_return_through_the_translator(self) -> None:
        for name in ("NtDoTerminateThread", "NtDoTerminateProcess"):
            with self.subTest(helper=name):
                reject_pattern(
                    self.translate_cpp,
                    rf"\[\[noreturn\]\][^{{;]*\b{name}\b",
                    f"{name} still has a false non-returning contract",
                )
                body = function_body(self.translate_cpp, rf"i64\s+{name}")
                require_pattern(
                    body,
                    r"\breturn\s+::duetos::subsystems::linux::LinuxExit\s*\(\s*exit_status\s*\)\s*;",
                    f"{name} does not propagate the cooperative exit result",
                )
                reject_pattern(body, r"\b(?:SchedExit|DEBUG_UNREACHABLE)\b", f"{name} abandons or panics on a live frame")

        translator = function_body(self.translate_cpp, r"Result\s+NtTranslateToLinux")
        for case_name, helper in (
            ("kNtTerminateThread", "NtDoTerminateThread"),
            ("kNtTerminateProcess", "NtDoTerminateProcess"),
        ):
            with self.subTest(case=case_name):
                require_pattern(
                    translator,
                    rf"case\s+{case_name}\s*:.*?r\s*=\s*\{{\s*true\s*,\s*{helper}\s*\(\s*frame\s*\)\s*\}}\s*;\s*break\s*;",
                    f"{case_name} does not return normally through NtTranslateToLinux",
                )

    def test_native_dispatcher_owns_the_outer_cancellation_boundary(self) -> None:
        body = function_body(self.native_cpp, r"void\s+SyscallDispatch")
        guard = require_pattern(
            body,
            r"\bScopedTaskCancellationDeferral\s+cancellation_guard\s*;",
            "native syscall dispatcher lacks a cooperative cancellation guard",
        )
        trail = require_pattern(body, r"\bSyscallTrailGuard\s+trail_guard\b", "native dispatcher lost its trail guard")
        translated = require_pattern(body, r"\bNtTranslateToLinux\s*\(\s*frame\s*\)", "native dispatcher no longer calls NT translator")
        self.assertLess(guard.start(), trail.start(), "cancellation guard would destruct before syscall-local telemetry")
        self.assertLess(trail.start(), translated.start(), "NT termination bypasses syscall-local telemetry ownership")


if __name__ == "__main__":
    unittest.main()
