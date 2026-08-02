#!/usr/bin/env python3
"""Hostile structural checks for residual cancellable IPC wait families."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank comments and quoted literals while preserving braces and offsets."""
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


class ResidualIpcWaitCancellationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.iocp_h = read("kernel/ipc/iocp.h")
        cls.iocp_cpp = read("kernel/ipc/iocp.cpp")
        cls.iocp_abi = read("kernel/subsystems/win32/iocp_syscall.cpp")
        cls.port_h = read("kernel/ipc/kmessage_port.h")
        cls.port_cpp = read("kernel/ipc/kmessage_port.cpp")
        cls.port_test = read("tests/host/test_kmessage_port.cpp")
        cls.ipc_wiki = read("wiki/kernel/IPC.md")

    def test_public_results_do_not_conflate_cancellation(self) -> None:
        self.assertEqual(
            enum_values(self.iocp_h, "IocpWaitResult"),
            ["Dequeued", "TimedOut", "Closed", "Cancelled", "Failed"],
        )
        self.assertIn("Cancelled", enum_values(self.port_h, "KMessagePortStatus"))
        self.assertIn("KMessagePortStatus::Cancelled", self.port_cpp)

    def test_iocp_uses_only_cancellable_condvar_waits(self) -> None:
        body = function_body(self.iocp_cpp, r"IocpWaitResult\s+IocpWait")
        self.assertIn("CondvarWaitCancellable", body)
        self.assertIn("CondvarWaitTimeoutCancellable", body)
        self.assertNotRegex(body, r"\bCondvarWait\s*\(")
        self.assertNotRegex(body, r"\bCondvarWaitTimeout\s*\(")

    def test_iocp_finite_wait_has_one_wrap_safe_deadline(self) -> None:
        body = function_body(self.iocp_cpp, r"IocpWaitResult\s+IocpWait")
        self.assertEqual(body.count("RelativeDeadlineFromNow"), 1)
        self.assertIn("TickDeadlineReached", body)
        self.assertIn("deadline - now", body)
        self.assertNotRegex(body, r"SchedNowTicks\s*\(\s*\)\s*\+\s*timeout_ticks")
        source = code_only(self.iocp_cpp)
        self.assertRegex(source, r"kMaxRelativeWaitTicks\s*=\s*\(~u64\{0\}\)\s*>>\s*1")
        self.assertIn("~u64{0} - now", source)
        self.assertIn("static_cast<i64>(now - deadline) >= 0", source)

    def test_iocp_cancelled_paths_unlock_without_dequeue(self) -> None:
        body = function_body(self.iocp_cpp, r"IocpWaitResult\s+IocpWait")
        causes = [match.start() for match in re.finditer("WaitQueueBlockResult::Cancelled", body)]
        self.assertEqual(len(causes), 2)
        for cause in causes:
            branch_open = body.find("{", cause)
            branch_close = matching(body, branch_open, "{", "}")
            branch = body[branch_open : branch_close + 1]
            unlock = branch.find("MutexUnlock")
            returned = branch.find("return IocpWaitResult::Cancelled")
            self.assertTrue(0 <= unlock < returned)
        self.assertLess(body.rfind("return IocpWaitResult::Cancelled"), body.find("*out ="))
        self.assertEqual(body.count("*out ="), 1)

    def test_iocp_adapter_drops_lookup_before_result_mapping(self) -> None:
        body = function_body(self.iocp_abi, r"i64\s+SysIocpRemove")
        lookup = body.find("LookupPortRef")
        wait = body.find("IocpWait(port")
        release = body.find("KObjectRelease(&port->base)", wait)
        mapping = body.find("switch (wait_result)")
        self.assertTrue(0 <= lookup < wait < release < mapping)
        self.assertIn("IocpWaitResult::Cancelled", body[mapping:])
        self.assertNotIn("SchedExit", body)
        iocp_wait = function_body(self.iocp_cpp, r"IocpWaitResult\s+IocpWait")
        self.assertNotIn("KObjectAcquire", iocp_wait)
        self.assertIn("stack-local", self.iocp_h)

    def test_iocp_adapter_preprobes_every_output_before_destructive_wait(self) -> None:
        body = function_body(self.iocp_abi, r"i64\s+SysIocpRemove")
        wait = body.find("IocpWait(port")
        probes = [match.start() for match in re.finditer("ProbeUserWriteRange", body)]
        self.assertEqual(len(probes), 3)
        self.assertTrue(0 <= probes[0] < probes[1] < probes[2] < wait)
        self.assertEqual(body.count("CopyToUser"), 3)
        self.assertIn("fail-fast snapshots, not page pins", self.iocp_abi)

    def test_message_port_preserves_host_wait_and_cancels_production_wait(self) -> None:
        guard_wait = function_body(self.port_cpp, r"PortWaitResult\s+Wait")
        self.assertIn("m_port.readable.wait(m_lock)", guard_wait)
        self.assertIn("return PortWaitResult::Woken", guard_wait)
        self.assertIn("CondvarWaitCancellable", guard_wait)
        self.assertNotRegex(guard_wait, r"\bCondvarWait\s*\(")

        readable = function_body(self.port_cpp, r"KMessagePortStatus\s+KMessagePortWaitReadable")
        wait = readable.find("guard.Wait()")
        cancelled = readable.find("return KMessagePortStatus::Cancelled")
        self.assertTrue(0 <= wait < cancelled)
        self.assertNotIn("MessageRingCommit", readable)
        self.assertNotIn("MessageRingCancelReceive", readable)

    def test_message_port_retained_handle_unwinds_before_return(self) -> None:
        for signature, operation, returned in (
            (
                r"KMessagePortSendResult\s+KMessagePortSendHandle",
                "KMessagePortSend(port",
                "return result",
            ),
            (
                r"KMessagePortReceiveResult\s+KMessagePortTryReceiveHandle",
                "KMessagePortTryReceive(port",
                "return result",
            ),
            (
                r"KMessagePortStatus\s+KMessagePortWaitReadableHandle",
                "KMessagePortWaitReadable(port)",
                "return status",
            ),
        ):
            body = function_body(self.port_cpp, signature)
            lookup = body.find("ResolvePort")
            invoked = body.find(operation)
            release = body.find("KObjectRelease(&port->base)")
            result = body.rfind(returned)
            self.assertTrue(0 <= lookup < invoked < release < result)

    def test_message_port_lock_and_handle_lifetime_order_is_explicit(self) -> None:
        receive = function_body(self.port_cpp, r"KMessagePortReceiveResult\s+KMessagePortTryReceive")
        unlock = receive.find("guard.Unlock()")
        copy = receive.find("CopyBytes")
        relock = receive.find("guard.Lock()")
        settle = receive.find("MessageRingEndCopyOut", relock)
        self.assertTrue(0 <= unlock < copy < relock < settle)

        send = function_body(self.port_cpp, r"KMessagePortSendResult\s+KMessagePortSend")
        prepare = send.find("MessageRingPrepareEnqueue")
        publish_guard = send.rfind("PortGuard guard", prepare)
        publish = send.find("MessageRingPublishEnqueue", prepare)
        self.assertTrue(0 <= prepare < publish_guard < publish)

        for signature in (
            r"KMessagePortSendResult\s+KMessagePortSend",
            r"KMessagePortReceiveResult\s+KMessagePortTryReceive",
            r"KMessagePortStatus\s+KMessagePortWaitReadable",
        ):
            raw = function_body(self.port_cpp, signature)
            self.assertNotIn("HandleTable", raw)
            self.assertNotIn("KObjectAcquire", raw)
            self.assertNotIn("KObjectRelease", raw)

        close = function_body(self.port_cpp, r"KMessagePortStatus\s+KMessagePortCloseHandle")
        detach = close.find("HandleTableDetach")
        terminal = close.find("KMessagePortClose(port)")
        release = close.find("KObjectRelease(&port->base)")
        self.assertTrue(0 <= detach < terminal < release)

    def test_message_port_host_pins_same_handle_close_and_generation_aba(self) -> None:
        for scenario in (
            "destroyed_before_inflight_close",
            "KMessagePortTryReceiveHandle(inflight_table, inflight_handle",
            "KMessagePortCloseHandle(inflight_table, inflight_handle)",
            "destroyed_before_inflight_close + 1U",
            "stale_handle",
            "replacement_handle",
            "InvalidHandleOrRights",
            "destroyed_before_aba + 2U",
        ):
            self.assertIn(scenario, self.port_test)

    def test_documentation_covers_both_residual_families(self) -> None:
        for phrase in (
            "IOCP removal distinguishes dequeued",
            "message-port readable wait returns `Cancelled`",
            "std::condition_variable",
            "Win32 event, semaphore, and IOCP adapters",
        ):
            self.assertIn(phrase, self.ipc_wiki)


if __name__ == "__main__":
    unittest.main()
