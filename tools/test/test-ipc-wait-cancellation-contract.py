#!/usr/bin/env python3
"""Hostile structural contract for cancellation-safe IPC object waits."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank comments and quoted literals while preserving offsets/braces."""
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


def matching(source: str, opening: int, left: str, right: str) -> int:
    if opening < 0 or source[opening] != left:
        raise AssertionError(f"missing opening {left!r}")
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
        closing_paren = matching(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        declaration_end = code.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            closing_brace = matching(code, opening_brace, "{", "}")
            return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function definition: {signature}")


def enum_values(source: str, name: str) -> list[str]:
    match = re.search(rf"enum\s+class\s+{name}\s*:\s*u8\s*\{{(?P<body>.*?)\}}", source, re.S)
    if match is None:
        raise AssertionError(f"missing enum {name}")
    return re.findall(r"\b([A-Za-z][A-Za-z0-9_]*)\b\s*(?:,|=)", match.group("body"))


class IpcWaitCancellationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.event_h = read("kernel/ipc/kevent.h")
        cls.event_cpp = read("kernel/ipc/kevent.cpp")
        cls.sem_h = read("kernel/ipc/ksemaphore.h")
        cls.sem_cpp = read("kernel/ipc/ksemaphore.cpp")
        cls.mail_h = read("kernel/ipc/kmailbox.h")
        cls.mail_cpp = read("kernel/ipc/kmailbox.cpp")
        cls.wait_h = read("kernel/ipc/kwaitable.h")
        cls.wait_cpp = read("kernel/ipc/kwaitable.cpp")
        cls.event_abi = read("kernel/subsystems/win32/event_syscall.cpp")
        cls.sem_abi = read("kernel/subsystems/win32/semaphore_syscall.cpp")
        cls.shell_bench = read("kernel/shell/shell_bench.cpp")
        cls.ipc_wiki = read("wiki/kernel/IPC.md")

    def test_public_results_cannot_conflate_cancellation(self) -> None:
        self.assertEqual(
            enum_values(self.event_h, "KEventWaitResult"),
            ["Signaled", "TimedOut", "Cancelled", "Failed"],
        )
        self.assertEqual(
            enum_values(self.sem_h, "KSemaphoreWaitResult"),
            ["Acquired", "TimedOut", "Cancelled", "Failed"],
        )
        self.assertEqual(
            enum_values(self.mail_h, "KMailboxWaitResult"),
            ["Completed", "Cancelled", "Failed"],
        )
        self.assertEqual(
            enum_values(self.wait_h, "KWaitableWaitStatus"),
            ["Ready", "Cancelled", "Failed"],
        )
        self.assertRegex(self.wait_h, r"kWaitableInvalidIndex\s*=\s*~u32\{0\}")
        self.assertRegex(self.wait_h, r"struct\s+KWaitableWaitResult\s*\{[^}]*status[^}]*index")

    def test_every_blocking_object_uses_only_cancellable_condvars(self) -> None:
        for name, source in {
            "event": self.event_cpp,
            "semaphore": self.sem_cpp,
            "mailbox": self.mail_cpp,
            "waitable": self.wait_cpp,
        }.items():
            code = code_only(source)
            self.assertNotRegex(code, r"\bCondvarWait\s*\(", f"{name} retained an uncancellable wait")
            self.assertNotRegex(code, r"\bCondvarWaitTimeout\s*\(", f"{name} retained an uncancellable timeout")

        for source, signature in (
            (self.event_cpp, r"KEventWaitResult\s+KEventWait"),
            (self.sem_cpp, r"KSemaphoreWaitResult\s+KSemaphoreAcquire"),
            (self.mail_cpp, r"KMailboxWaitResult\s+KMailboxPost"),
            (self.mail_cpp, r"KMailboxWaitResult\s+KMailboxReceive"),
            (self.wait_cpp, r"KWaitableWaitResult\s+KWaitableWaitForAny"),
        ):
            body = function_body(source, signature)
            self.assertIn("CondvarWaitCancellable", body)

        for source, signature in (
            (self.event_cpp, r"KEventWaitResult\s+KEventWaitTimed"),
            (self.sem_cpp, r"KSemaphoreWaitResult\s+KSemaphoreAcquireTimed"),
        ):
            body = function_body(source, signature)
            self.assertIn("CondvarWaitTimeoutCancellable", body)
            self.assertIn("WaitQueueBlockResult::TimedOut", body)
            self.assertIn("WaitQueueBlockResult::Cancelled", body)

    def test_cancelled_paths_unlock_release_and_do_not_commit(self) -> None:
        cases = (
            (self.event_cpp, r"KEventWaitResult\s+KEventWait", "KEventWaitResult::Cancelled"),
            (self.event_cpp, r"KEventWaitResult\s+KEventWaitTimed", "KEventWaitResult::Cancelled"),
            (self.sem_cpp, r"KSemaphoreWaitResult\s+KSemaphoreAcquire", "KSemaphoreWaitResult::Cancelled"),
            (
                self.sem_cpp,
                r"KSemaphoreWaitResult\s+KSemaphoreAcquireTimed",
                "KSemaphoreWaitResult::Cancelled",
            ),
            (self.mail_cpp, r"KMailboxWaitResult\s+KMailboxPost", "KMailboxWaitResult::Cancelled"),
            (self.mail_cpp, r"KMailboxWaitResult\s+KMailboxReceive", "KMailboxWaitResult::Cancelled"),
            (
                self.wait_cpp,
                r"KWaitableWaitResult\s+KWaitableWaitForAny",
                "KWaitableWaitStatus::Cancelled",
            ),
        )
        for source, signature, cancelled_result in cases:
            body = function_body(source, signature)
            cause = body.find("WaitQueueBlockResult::Cancelled")
            self.assertGreaterEqual(cause, 0, signature)
            branch_open = body.find("{", cause)
            branch_close = matching(body, branch_open, "{", "}")
            branch = body[branch_open : branch_close + 1]
            self.assertIn(cancelled_result, branch)
            unlock = branch.find("MutexUnlock")
            release = branch.find("KObjectRelease")
            returned = branch.find("return")
            self.assertTrue(0 <= unlock < release < returned, f"unsafe cancellation unwind in {signature}")

        receive = function_body(self.mail_cpp, r"KMailboxWaitResult\s+KMailboxReceive")
        self.assertLess(receive.find("KMailboxWaitResult::Cancelled"), receive.find("*out ="))
        self.assertLess(receive.find("KMailboxWaitResult::Cancelled"), receive.find("--mb->count"))

    def test_wait_pins_span_the_cancellable_block(self) -> None:
        for source, signature in (
            (self.event_cpp, r"KEventWaitResult\s+KEventWait"),
            (self.event_cpp, r"KEventWaitResult\s+KEventWaitTimed"),
            (self.sem_cpp, r"KSemaphoreWaitResult\s+KSemaphoreAcquire"),
            (self.sem_cpp, r"KSemaphoreWaitResult\s+KSemaphoreAcquireTimed"),
            (self.mail_cpp, r"KMailboxWaitResult\s+KMailboxPost"),
            (self.mail_cpp, r"KMailboxWaitResult\s+KMailboxReceive"),
            (self.wait_cpp, r"KWaitableWaitResult\s+KWaitableWaitForAny"),
        ):
            body = function_body(source, signature)
            acquire = body.find("KObjectAcquire")
            wait = body.find("CondvarWait")
            final_release = body.rfind("KObjectRelease")
            self.assertTrue(0 <= acquire < wait < final_release, f"wait pin does not span {signature}")

    def test_timed_waits_have_one_wrap_safe_budget(self) -> None:
        for source, signature, success, timeout in (
            (
                self.event_cpp,
                r"KEventWaitResult\s+KEventWaitTimed",
                "KEventWaitResult::Signaled",
                "KEventWaitResult::TimedOut",
            ),
            (
                self.sem_cpp,
                r"KSemaphoreWaitResult\s+KSemaphoreAcquireTimed",
                "KSemaphoreWaitResult::Acquired",
                "KSemaphoreWaitResult::TimedOut",
            ),
        ):
            body = function_body(source, signature)
            self.assertEqual(body.count("RelativeDeadlineFromNow"), 1)
            self.assertIn("TickDeadlineReached", body)
            self.assertIn("deadline - now", body)
            self.assertNotRegex(body, r"SchedNowTicks\s*\(\s*\)\s*\+\s*ticks")
            self.assertNotRegex(body, r"\bnow\s*>=\s*deadline")
            self.assertIn(success, body)
            self.assertIn(timeout, body)

        for source in (self.event_cpp, self.sem_cpp):
            helper = code_only(source)
            self.assertRegex(helper, r"kMaxRelativeWaitTicks\s*=\s*\(~u64\{0\}\)\s*>>\s*1")
            self.assertIn("~u64{0} - now", helper)
            self.assertIn("static_cast<i64>(now - deadline) >= 0", helper)

    def test_win32_adapters_release_lookup_before_mapping_cancelled(self) -> None:
        for source, signature, result_type, cancelled in (
            (
                self.event_abi,
                r"void\s+DoEventWait",
                "KEventWaitResult",
                "KEventWaitResult::Cancelled",
            ),
            (
                self.sem_abi,
                r"void\s+DoSemWait",
                "KSemaphoreWaitResult",
                "KSemaphoreWaitResult::Cancelled",
            ),
        ):
            body = function_body(source, signature)
            release = body.find("KObjectRelease(obj)")
            mapping = body.find(cancelled)
            self.assertIn(result_type, body)
            self.assertTrue(0 <= release < mapping, f"lookup ref survives cancellation mapping in {signature}")
            tail = body[mapping:]
            self.assertRegex(tail, r"frame->rax\s*=\s*static_cast<u64>\s*\(\s*-1\s*\)")
            self.assertIn("kWaitObject0", body)
            self.assertIn("kWaitTimeout", body)
            self.assertNotIn("SchedExit", body)

    def test_selftests_and_kernel_caller_consume_explicit_results(self) -> None:
        self.assertIn("KEventWaitResult::Signaled", function_body(self.event_cpp, r"void\s+KEventSelfTest"))
        self.assertIn(
            "KSemaphoreWaitResult::Acquired",
            function_body(self.sem_cpp, r"void\s+KSemaphoreSelfTest"),
        )
        mailbox_selftest = function_body(self.mail_cpp, r"void\s+KMailboxSelfTest")
        self.assertGreaterEqual(mailbox_selftest.count("KMailboxWaitResult::Completed"), 3)
        waitable_selftest = function_body(self.wait_cpp, r"void\s+KWaitableSelfTest")
        self.assertGreaterEqual(waitable_selftest.count("KWaitableWaitStatus::Ready"), 3)
        wakeup_worker = function_body(self.shell_bench, r"void\s+WakeupWorkerEntry")
        self.assertIn("KEventWaitResult::Signaled", wakeup_worker)
        wakeup_bench = function_body(self.shell_bench, r"BenchResult\s+RunWakeup")
        self.assertGreaterEqual(wakeup_bench.count("KEventWaitResult::Signaled"), 2)

    def test_semaphore_release_preflight_cannot_wrap(self) -> None:
        release = function_body(self.sem_cpp, r"void\s+KSemaphoreRelease")
        compact = re.sub(r"\s+", "", release)
        invariant = compact.find("s->count<=s->max_count")
        preflight = compact.find("n>s->max_count-s->count")
        self.assertTrue(0 <= invariant < preflight)
        self.assertNotIn("s->count+n>s->max_count", compact)

        selftest = function_body(self.sem_cpp, r"void\s+KSemaphoreSelfTest")
        self.assertIn("KSemaphoreTryRelease(s, ~u32{0}, &overflow_prev)", selftest)
        self.assertIn("overflow_prev != 0xA5A5A5A5u", selftest)

    def test_semaphore_release_wakeup_cost_is_bounded(self) -> None:
        for signature in (r"void\s+KSemaphoreRelease", r"bool\s+KSemaphoreTryRelease"):
            body = function_body(self.sem_cpp, signature)
            self.assertEqual(body.count("CondvarBroadcast"), 1)
            self.assertNotIn("CondvarSignal", body)
            self.assertNotRegex(body, r"\bfor\s*\(")
        self.assertIn("~u32{0}", function_body(self.sem_cpp, r"void\s+KSemaphoreSelfTest"))
        self.assertIn("broadcasts once", self.ipc_wiki)

    def test_documentation_pins_the_unwind_boundary(self) -> None:
        for phrase in (
            "Cooperative cancellation at blocking objects",
            "kWaitableInvalidIndex",
            "outer cancellation guard",
        ):
            self.assertIn(phrase, self.ipc_wiki)
        self.assertRegex(self.ipc_wiki, r"drops its explicit\s+wait pin")


if __name__ == "__main__":
    unittest.main()
