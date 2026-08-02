#!/usr/bin/env python3
"""Structural contract for durable Linux child relations and sequence waits."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
SCHED_H = ROOT / "kernel" / "sched" / "sched.h"
SCHED_CPP = ROOT / "kernel" / "sched" / "sched.cpp"
CLONE_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_clone.cpp"
WAIT_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_stub.cpp"
RLIMIT_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_rlimit.cpp"


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while retaining source offsets."""
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


def matching_delimiter(source: str, opening: int, left: str = "{", right: str = "}") -> int:
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
            closing_brace = matching_delimiter(code, opening_brace)
            return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function definition: {signature}")


def type_body(source: str, declaration: str) -> str:
    code = code_only(source)
    match = re.search(declaration + r"[^;{]*\{", code)
    if match is None:
        raise AssertionError(f"missing type: {declaration}")
    opening = code.find("{", match.start())
    return code[opening + 1 : matching_delimiter(code, opening)]


def guarded_block(source: str, lock_token: str) -> str:
    """Return the innermost lexical block containing a lock-guard token."""
    code = code_only(source)
    target = code.find(lock_token)
    if target < 0:
        raise AssertionError(f"missing lock token: {lock_token}")
    stack: list[int] = []
    candidates: list[tuple[int, int]] = []
    for index, char in enumerate(code):
        if char == "{":
            stack.append(index)
        elif char == "}":
            opening = stack.pop()
            if opening < target < index:
                candidates.append((opening, index))
    if not candidates:
        raise AssertionError("lock token is not in a lexical block")
    opening, closing = max(candidates, key=lambda pair: pair[0])
    return code[opening + 1 : closing]


def assert_ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class ParserHostileTests(unittest.TestCase):
    def test_comments_and_literals_cannot_supply_contract_tokens(self) -> None:
        hostile = r'''
// ProcessRegisterLinuxChildRelation(parent, child, 8);
/* WaitQueueBlockIfSequenceUnchanged(wq, sequence, observed); */
const char* normal = "LinuxChildRelationState::Exited { }";
const char* raw = u8R"tag(ProcessPollLinuxChild(fake) // } {)tag";
int visible = 7;
'''
        visible = code_only(hostile)
        self.assertNotIn("ProcessRegisterLinuxChildRelation", visible)
        self.assertNotIn("WaitQueueBlockIfSequenceUnchanged", visible)
        self.assertNotIn("ProcessPollLinuxChild", visible)
        self.assertIn("int visible = 7;", visible)

    def test_function_slicer_ignores_prototype_and_string_decoy(self) -> None:
        hostile = r'''
bool Probe(int);
const char* decoy = "bool Probe(int) { return false; }";
bool Probe(int value) { return value != 0; }
bool After() { return false; }
'''
        body = function_body(hostile, r"bool\s+Probe")
        self.assertIn("return value != 0;", body)
        self.assertNotIn("bool After", body)


class LinuxChildRelationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.sched_h = SCHED_H.read_text(encoding="utf-8")
        cls.sched_cpp = SCHED_CPP.read_text(encoding="utf-8")
        cls.clone_cpp = CLONE_CPP.read_text(encoding="utf-8")
        cls.wait_cpp = WAIT_CPP.read_text(encoding="utf-8")
        cls.rlimit_cpp = RLIMIT_CPP.read_text(encoding="utf-8")
        cls.process_h_code = code_only(cls.process_h)
        cls.sched_h_code = code_only(cls.sched_h)
        cls.wait_cpp_code = code_only(cls.wait_cpp)

    def test_process_owns_fixed_stateful_relation_rows_and_atomic_sequence(self) -> None:
        process = type_body(self.process_h, r"struct\s+Process\b")
        states = type_body(self.process_h, r"enum\s+class\s+LinuxChildRelationState")
        for state in ("Free", "Live", "Exited"):
            self.assertRegex(states, rf"\b{state}\b")
        self.assertRegex(process, r"kLinuxChildRelationCap\s*=\s*64")
        self.assertRegex(process, r"LinuxChildRelation\s+linux_child_relations\s*\[\s*kLinuxChildRelationCap\s*\]")
        self.assertRegex(process, r"Process\s*\*\s*linux_parent\s*;")
        self.assertRegex(process, r"u64\s+linux_child_event_sequence\s*;")
        self.assertRegex(process, r"SpinLock\s+linux_child_exit_lock\s*;")

        create = function_body(self.process_cpp, r"Process\s*\*\s*ProcessCreate")
        self.assertIn("p->linux_parent = nullptr", create)
        self.assertIn("p->linux_child_relation_count = 0", create)
        self.assertIn("__atomic_store_n(&p->linux_child_event_sequence", create)

    def test_registration_is_bounded_retained_and_precedes_scheduler_publication(self) -> None:
        register = function_body(self.process_cpp, r"bool\s+ProcessRegisterLinuxChildRelation")
        assert_ordered(
            self,
            register,
            "ProcessRetain(parent)",
            "SpinLockGuard child_guard(parent->linux_child_exit_lock)",
            "parent->linux_child_relation_count < admission_limit",
            "relation.state = Process::LinuxChildRelationState::Live",
            "child->linux_parent = parent",
            "AdvanceLinuxChildEventLocked(parent)",
        )
        locked = guarded_block(register, "SpinLockGuard child_guard(parent->linux_child_exit_lock)")
        self.assertNotIn("ProcessRelease", locked)
        self.assertNotIn("WaitQueueWake", locked)
        self.assertNotIn("g_sched_lock", locked)
        self.assertIn("WaitQueueWakeAll(&parent->linux_wait_wq)", register)

        fork = function_body(self.clone_cpp, r"i64\s+DoFork")
        registration = fork.index("ProcessRegisterLinuxChildRelation(parent, child, child_limit)")
        publication = fork.index("sched::SchedCreateUser(&LinuxCloneEntry, desc, s_name, child)")
        self.assertLess(registration, publication)
        self.assertNotIn("SchedCountChildrenOfPid", fork)
        self.assertNotIn("child->linux_parent_pid =", fork)
        self.assertIn("__atomic_load_n(&parent->linux_rlimit_nproc_cur, __ATOMIC_ACQUIRE)", fork)
        failed_registration = fork[registration:publication]
        self.assertIn("ProcessRelease(child)", failed_registration)

        defaults = function_body(self.rlimit_cpp, r"void\s+RlimitDefaultsFor")
        nproc_case = defaults[defaults.index("case kRlimitNproc") : defaults.index("case kRlimitStack")]
        self.assertEqual(nproc_case.count("core::Process::kLinuxChildRelationCap"), 2)
        prlimit = function_body(self.rlimit_cpp, r"i64\s+DoPrlimit64")
        self.assertIn("__atomic_load_n(&p->linux_rlimit_nproc_cur, __ATOMIC_ACQUIRE)", prlimit)
        self.assertIn("__atomic_store_n(&p->linux_rlimit_nproc_cur", prlimit)
        self.assertIn("__ATOMIC_RELEASE", prlimit)

    def test_private_rollback_removes_live_row_and_releases_after_unlock(self) -> None:
        rollback = function_body(self.process_cpp, r"void\s+RollbackLinuxParentRelation")
        locked = guarded_block(rollback, "SpinLockGuard child_guard(parent->linux_child_exit_lock)")
        self.assertIn("Process::LinuxChildRelationState::Live", locked)
        self.assertIn("ClearLinuxChildRelationLocked(parent, relation)", locked)
        self.assertNotIn("ProcessRelease", locked)
        self.assertNotIn("WaitQueueWake", locked)
        assert_ordered(
            self,
            rollback,
            "ClearLinuxChildRelationLocked(parent, relation)",
            "WaitQueueWakeAll(&parent->linux_wait_wq)",
            "ProcessRelease(parent)",
        )
        teardown = function_body(self.process_cpp, r"void\s+TeardownProcessRuntimeResources")
        self.assertRegex(teardown, r"if\s*\(\s*!observable_exit\s*\)\s*RollbackLinuxParentRelation\s*\(\s*p\s*\)")

    def test_child_status_is_published_only_after_process_exited(self) -> None:
        queue = function_body(self.process_cpp, r"Process\s*\*\s*QueueLinuxParentExit")
        self.assertIn("ScopedProcessRuntimeAccess parent_runtime(parent)", queue)
        locked = guarded_block(queue, "SpinLockGuard child_guard(parent->linux_child_exit_lock)")
        assert_ordered(
            self,
            locked,
            "relation.exit.exit_code = child->linux_exit_code",
            "relation.state = Process::LinuxChildRelationState::Exited",
            "AdvanceLinuxChildEventLocked(parent)",
        )
        self.assertNotIn("WaitQueueWake", locked)
        self.assertNotIn("ProcessRelease", locked)
        self.assertNotIn("g_sched_lock", locked)

        complete = function_body(self.process_cpp, r"void\s+ProcessCompleteExitFromReaper")
        assert_ordered(
            self,
            complete,
            "TeardownProcessRuntimeResources(process, true)",
            "ProcessLifecycleTransition(process, ProcessLifecycleState::Exiting, ProcessLifecycleState::Exited)",
            "QueueLinuxParentExit(process)",
            "WaitQueueWakeAll(&parent_to_wake->linux_wait_wq)",
            "ProcessRelease(parent_to_wake)",
        )

    def test_poll_atomically_selects_and_consumes_registered_rows(self) -> None:
        poll = function_body(self.process_cpp, r"LinuxChildWaitResult\s+ProcessPollLinuxChild")
        locked = guarded_block(poll, "SpinLockGuard child_guard(parent->linux_child_exit_lock)")
        self.assertRegex(locked, r"target_pid\s*>\s*0[\s\S]*relation\.exit\.pid[\s\S]*!=\s*target_pid")
        self.assertIn("relation.state != Process::LinuxChildRelationState::Exited", locked)
        assert_ordered(
            self,
            locked,
            "*exit_out = relation.exit",
            "ClearLinuxChildRelationLocked(parent, relation)",
            "__atomic_load_n(&parent->linux_child_event_sequence, __ATOMIC_ACQUIRE)",
        )
        self.assertNotIn("WaitQueueWake", locked)
        self.assertIn("WaitQueueWakeAll(&parent->linux_wait_wq)", poll)
        self.assertIn("LinuxChildWaitResult::NoMatchingChild", poll)
        self.assertIn("LinuxChildWaitResult::Pending", poll)
        self.assertIn("LinuxChildWaitResult::Exited", poll)

    def test_sequence_wait_rechecks_then_enqueues_under_one_scheduler_lock(self) -> None:
        self.assertRegex(
            self.sched_h_code,
            r"bool\s+WaitQueueBlockIfSequenceUnchanged\s*\(\s*WaitQueue\s*\*\s*\w+\s*,\s*"
            r"const\s+u64\s*\*\s*\w+\s*,\s*u64\s+\w+\s*\)\s*;",
        )
        block = function_body(self.sched_cpp, r"bool\s+WaitQueueBlockIfSequenceUnchanged")
        assert_ordered(
            self,
            block,
            "SpinLockAcquire(g_sched_lock)",
            "__atomic_load_n(sequence, __ATOMIC_ACQUIRE)",
            "WaitQueueBlockCurrentLocked(wq)",
            "ScheduleLockedHandoff(flags)",
        )
        mismatch = re.search(
            r"if\s*\(\s*__atomic_load_n\s*\(\s*sequence\s*,\s*__ATOMIC_ACQUIRE\s*\)\s*!="
            r"\s*observed_sequence\s*\)\s*\{(?P<body>[\s\S]*?)\}",
            block,
        )
        self.assertIsNotNone(mismatch)
        mismatch_body = mismatch.group("body") if mismatch is not None else ""
        self.assertIn("SpinLockRelease(g_sched_lock, flags)", mismatch_body)
        self.assertRegex(mismatch_body, r"return\s+false\s*;")

    def test_wait4_and_waitid_use_relation_results_not_scheduler_counts_or_cli(self) -> None:
        for name in (r"i64\s+DoWait4", r"i64\s+DoWaitid"):
            with self.subTest(name=name):
                body = function_body(self.wait_cpp, name)
                self.assertIn("ProcessPollLinuxChild", body)
                self.assertIn("LinuxChildWaitResult::NoMatchingChild", body)
                self.assertIn("ProcessWaitForLinuxChildEvent", body)
                self.assertNotIn("SchedCountChildrenOfPid", body)
                self.assertNotIn("WaitQueueBlock(", body)
                self.assertNotIn("arch::Cli", body)
                self.assertNotIn("arch::Sti", body)
        waitid = function_body(self.wait_cpp, r"i64\s+DoWaitid")
        self.assertRegex(waitid, r"idtype\s*==\s*kPPid[\s\S]*static_cast<i64>\s*\(\s*id\s*\)")
        self.assertIn("(options & kWExited) == 0", waitid)
        self.assertIn("options & ~kSupportedOptions", waitid)
        self.assertRegex(
            waitid,
            r"info\.si_status\s*=[\s\S]*exit\.was_signaled[\s\S]*exit\.exit_signal[\s\S]*exit\.exit_code",
        )


if __name__ == "__main__":
    unittest.main()
