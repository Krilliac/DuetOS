#!/usr/bin/env python3
"""Structural contract for the GDB qRcmd stop-loop no-wait boundary."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def sanitize_cpp(text: str) -> str:
    """Blank comments/string payloads while preserving offsets and braces."""
    out = list(text)
    i = 0
    state = "code"
    quote = ""
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if c == "/" and n == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "line"
                continue
            if c == "/" and n == "*":
                out[i] = out[i + 1] = " "
                i += 2
                state = "block"
                continue
            if c in ('"', "'"):
                quote = c
                out[i] = " "
                i += 1
                state = "string"
                continue
        elif state == "line":
            if c == "\n":
                state = "code"
            else:
                out[i] = " "
            i += 1
            continue
        elif state == "block":
            if c == "*" and n == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = "code"
                continue
            if c != "\n":
                out[i] = " "
            i += 1
            continue
        elif state == "string":
            if c == "\\":
                out[i] = " "
                if i + 1 < len(text):
                    out[i + 1] = " "
                i += 2
                continue
            out[i] = " "
            i += 1
            if c == quote:
                state = "code"
            continue
        i += 1
    return "".join(out)


def function_body(text: str, name: str) -> str:
    clean = sanitize_cpp(text)
    matches = list(re.finditer(rf"\b{re.escape(name)}\s*\(", clean))
    for match in matches:
        brace = clean.find("{", match.end())
        semi = clean.find(";", match.end())
        if brace < 0 or (semi >= 0 and semi < brace):
            continue
        depth = 0
        for pos in range(brace, len(clean)):
            if clean[pos] == "{":
                depth += 1
            elif clean[pos] == "}":
                depth -= 1
                if depth == 0:
                    return text[brace : pos + 1]
    raise AssertionError(f"definition not found: {name}")


class ParserHostileTests(unittest.TestCase):
    def test_comments_strings_and_declarations_do_not_spoof_body(self) -> None:
        sample = r'''
        // Good() { SpinLockTryGuard fake; }
        const char* s = "Good() { SpinLockTryGuard fake; }";
        void Good();
        void Good() { int real = 1; }
        '''
        body = function_body(sample, "Good")
        self.assertIn("real", body)
        self.assertNotIn("SpinLockTryGuard", body)


class GdbMonitorStopSafetyContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("kernel/diag/gdb_monitor.h")
        cls.monitor = read("kernel/diag/gdb_monitor.cpp")
        cls.monitor_read = read("kernel/diag/gdb_monitor_read.cpp")
        cls.sched_h = read("kernel/sched/sched.h")
        cls.sched_cpp = read("kernel/sched/sched.cpp")
        cls.process_h = read("kernel/proc/process.h")
        cls.process_cpp = read("kernel/proc/process.cpp")
        cls.authorization_h = read("kernel/proc/authorization_context.h")
        cls.authorization_cpp = read("kernel/proc/authorization_context.cpp")
        cls.probes = read("kernel/debug/probes.cpp")
        cls.kdbg = read("kernel/diag/kdbg.cpp")

    def test_dispatch_carries_explicit_stop_context(self) -> None:
        self.assertIn("struct GdbMonitorStopContext", self.header)
        for field in ("generation", "expected_mask", "acknowledged_mask", "complete"):
            self.assertRegex(self.header, rf"\b{field}\b")
        self.assertRegex(
            sanitize_cpp(self.header),
            r"GdbMonitorDispatch\s*\([^;]*GdbMonitorStopContext\s*\*\s*stop_context",
        )

    def test_incomplete_rendezvous_fails_closed_before_state_dispatch(self) -> None:
        body = function_body(self.monitor, "GdbMonitorDispatch")
        gate = body.find("!stop_context->complete")
        ps = body.find('Eq(sub, "ps")')
        self.assertGreaterEqual(gate, 0)
        self.assertGreater(ps, gate)
        self.assertIn("expected_mask & ~stop_context->acknowledged_mask", self.monitor)

    def test_monitor_read_has_no_blocking_runtime_apis(self) -> None:
        clean = sanitize_cpp(self.monitor_read)
        forbidden = (
            "ScopedProcessRuntimeAccess",
            "SchedFindProcessByPidRetained",
            "SchedEnumerate(",
            "KernelHeapStatsRead",
            "SpinLockGuard",
            "MutexLock(",
            "MutexTryLock(",
        )
        for token in forbidden:
            self.assertNotIn(token, clean, token)

    def test_each_lock_backed_reader_uses_single_attempt_try_guards(self) -> None:
        clean = sanitize_cpp(self.monitor_read)
        self.assertGreaterEqual(clean.count("SpinLockTryGuard"), 2)
        for name in ("CmdHandles", "CmdVm"):
            body = function_body(self.monitor_read, name)
            self.assertIn("SpinLockTryGuard", body)
            self.assertIn(".reason()", body)

        caps = function_body(self.monitor_read, "CmdCaps")
        self.assertIn("ProcessCapsTrySnapshotNoExpire(p, &caps)", caps)
        self.assertNotRegex(sanitize_cpp(caps), r"p->(?:caps|cap_leases|cap_ceiling)\b")

        self.assertIn("ProcessCapsTrySnapshotNoExpire", self.process_h)
        snapshot = function_body(self.process_cpp, "ProcessCapsTrySnapshotNoExpire")
        self.assertIn("AuthorizationTrySnapshotNoExpire(process->authorization, &snapshot)", snapshot)
        self.assertNotIn("SpinLockGuard", snapshot)

        self.assertIn("AuthorizationTrySnapshotNoExpire", self.authorization_h)
        authority_snapshot = function_body(self.authorization_cpp, "AuthorizationTrySnapshotNoExpire")
        self.assertEqual(sanitize_cpp(authority_snapshot).count("SpinLockTryGuard"), 1)
        self.assertIn("SpinLockTryGuard guard(g_authorization_lock)", authority_snapshot)
        self.assertIn("if (!guard)", authority_snapshot)
        self.assertIn("ResolveExactLocked(key)", authority_snapshot)
        self.assertIn("AuthorizationContextState::Live", authority_snapshot)
        self.assertIn("row->owner_references == 0", authority_snapshot)
        self.assertIn("CopySnapshotLocked(*row, *out_snapshot)", authority_snapshot)
        self.assertNotIn("ObserveLeaseTimeLocked", authority_snapshot)

    def test_scheduler_stop_snapshot_never_nests_address_space_lock(self) -> None:
        self.assertIn("SchedSnapshotTasksStopped", self.sched_h)
        tasks = function_body(self.sched_cpp, "SchedSnapshotTasksStopped")
        self.assertIn("SpinLockTryGuard", tasks)
        self.assertNotIn("AddressSpaceUserPageCount", sanitize_cpp(tasks))
        lookup = function_body(self.sched_cpp, "SchedFindProcessByPidStopped")
        self.assertIn("SpinLockTryGuard", lookup)
        self.assertIn("vm_transaction_lock.owner", lookup)

    def test_remaining_unsafe_control_tables_are_explicitly_gated(self) -> None:
        dispatch = function_body(self.monitor, "GdbMonitorDispatch")
        for verb, reason in (
            ("win", "compositor snapshot has no no-wait API"),
            ("watch", "watch table has no transactional try API"),
            ("trip", "tripwire table has no try API"),
            ("dump", "minidump emission is not reentrancy guarded"),
        ):
            self.assertIn(f'Eq(sub, "{verb}")', dispatch)
            self.assertIn(reason, self.monitor)

    def test_lock_free_probe_and_kdbg_controls_use_atomic_state(self) -> None:
        for name in ("ProbeFire", "ProbeSetArm", "ProbeList"):
            body = function_body(self.probes, name)
            self.assertIn("__atomic_", body)
        self.assertIn("__atomic_fetch_or", function_body(self.kdbg, "DbgEnable"))
        self.assertIn("__atomic_fetch_and", function_body(self.kdbg, "DbgDisable"))
        self.assertIn("__atomic_store_n", function_body(self.kdbg, "DbgSet"))
        self.assertIn("__atomic_load_n", function_body(self.kdbg, "DbgMask"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
