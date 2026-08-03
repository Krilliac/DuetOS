#!/usr/bin/env python3
"""Hostile structural contract for cycle-free Job completion ownership."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def code_only(text: str) -> str:
    """Mask comments and literals without changing source offsets."""
    out = list(text)
    i = 0
    state = "code"
    quote = ""
    while i < len(text):
        if state == "code":
            if text.startswith("//", i):
                out[i] = out[i + 1] = " "
                i += 2
                state = "line"
                continue
            if text.startswith("/*", i):
                out[i] = out[i + 1] = " "
                i += 2
                state = "block"
                continue
            if text[i] in {'"', "'"}:
                quote = text[i]
                out[i] = " "
                i += 1
                state = "literal"
                continue
        elif state == "line":
            if text[i] == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            out[i] = " "
            if text.startswith("*/", i):
                out[i + 1] = " "
                i += 1
                state = "code"
        else:
            out[i] = " "
            if text[i] == "\\" and i + 1 < len(text):
                out[i + 1] = " "
                i += 1
            elif text[i] == quote:
                state = "code"
        i += 1
    return "".join(out)


def function_body(text: str, signature: str) -> str:
    masked = code_only(text)
    match = re.search(signature, masked)
    if not match:
        raise AssertionError(f"missing function: {signature}")
    opening = masked.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"missing function body: {signature}")
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return masked[opening : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class JobMemberCompletionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.job_h = source("kernel/proc/job.h")
        cls.job_cpp = source("kernel/proc/job.cpp")
        cls.adapter = source("kernel/subsystems/win32/job_syscall.cpp")
        cls.process = source("kernel/proc/process.cpp")
        cls.sched_h = source("kernel/sched/sched.h")
        cls.sched_cpp = source("kernel/sched/sched.cpp")

    def test_job_public_contract_carries_only_exact_keys(self) -> None:
        header = code_only(self.job_h)
        self.assertRegex(header, r"ProcessKey\s+members\s*\[\s*kJobMemberCapacity\s*\]")
        self.assertRegex(header, r"JobAssign\s*\([^;]*ProcessKey\s+owner[^;]*ProcessKey\s+member")
        self.assertRegex(header, r"JobOnProcessExit\s*\(\s*ProcessKey\s+process\s*\)")
        self.assertNotRegex(header, r"JobAssignRetained|Process\s*\*\s*members")

    def test_job_rows_are_completion_records_not_process_owners(self) -> None:
        implementation = code_only(self.job_cpp)
        self.assertRegex(
            implementation,
            r"struct\s+JobMember\s*\{\s*ProcessKey\s+process\s*;\s*"
            r"JobMemberState\s+state\s*;\s*u64\s+publication_ticket\s*;\s*\}",
        )
        for forbidden in ("ProcessRetain", "ProcessRelease", "Process*", "Process *"):
            self.assertNotIn(forbidden, implementation)

    def test_owner_authority_is_exact_and_non_pid_only(self) -> None:
        implementation = code_only(self.job_cpp)
        self.assertRegex(implementation, r"ProcessKey\s+owner\s*;")
        resolve = function_body(implementation, r"JobRow\s*\*\s*ResolveOwnedLocked")
        self.assertIn("row->owner == owner", resolve)
        self.assertNotIn("owner_pid", implementation)

    def test_assignment_and_exit_clear_exact_reusable_slot(self) -> None:
        assign = function_body(self.job_cpp, r"JobAssignResult\s+JobAssign")
        self.assertIn("ContainsHeldLocked", assign)
        self.assertIn("row->members[index].process = member", assign)
        self.assertIn("row->members[index].state = JobMemberState::Active", assign)

        exited = function_body(self.job_cpp, r"void\s+JobOnProcessExit")
        self.assertIn("entry.process == process", exited)
        self.assertIn("entry.state != JobMemberState::Active", exited)
        self.assertIn("ClearMember(entry)", exited)
        self.assertIn("--row.member_count", exited)
        self.assertNotIn("ProcessRelease", exited)

    def test_termination_intent_copies_keys_and_scheduler_dispatches_once(self) -> None:
        begin = function_body(self.job_cpp, r"JobTerminateResult\s+JobBeginTermination")
        self.assertIn("out_intent->members", begin)
        self.assertIn("entry.process", begin)
        self.assertIn("out_intent->exit_code = exit_code", begin)
        self.assertNotIn("ProcessRetain", begin)

        terminate = function_body(self.adapter, r"i64\s+SysJobTerminate")
        self.assertIn("sched::SchedTerminateJob", terminate)
        self.assertNotIn("SchedFindProcessByKeyRetained", terminate)
        self.assertNotIn("SchedKillByProcess", terminate)

        dispatch = function_body(self.sched_cpp, r"JobTerminateResult\s+SchedTerminateJob")
        begin_pos = dispatch.find("JobBeginTermination")
        scan_pos = dispatch.find("g_all_tasks_head")
        close_pos = dispatch.find("ProcessTerminationClose")
        signal_pos = dispatch.find("SignalTaskLocked")
        finish_pos = dispatch.find("JobFinishTermination")
        self.assertTrue(0 <= begin_pos < scan_pos < close_pos < signal_pos < finish_pos)
        self.assertIn("intent.members[member] == task_process", dispatch)
        self.assertIn("KillReason::JobTermination", dispatch)

    def test_scheduler_key_lookup_matches_both_components_under_lock(self) -> None:
        self.assertRegex(
            code_only(self.sched_h),
            r"Process\s*\*\s*SchedFindProcessByKeyRetained\s*\(\s*core::ProcessKey",
        )
        lookup = function_body(self.sched_cpp, r"Process\s*\*\s*SchedFindProcessByKeyRetained")
        self.assertIn("g_sched_lock", lookup)
        self.assertIn("FindProcessByKeyLocked(target)", lookup)
        self.assertIn("ProcessRetain", lookup)

        resolver = function_body(self.sched_cpp, r"Process\s*\*\s*FindProcessByKeyLocked")
        self.assertIn("SpinLockAssertHeld(g_sched_lock)", resolver)
        self.assertIn("process->pid == target.pid", resolver)
        self.assertIn("process->process_identity == target.identity", resolver)

    def test_process_exit_is_scheduler_linearized_before_cycle_break(self) -> None:
        reaper = function_body(self.sched_cpp, r"\[\[noreturn\]\]\s+void\s+ReaperMain")
        unlink = reaper.find("AllTasksUnlink(dead)")
        completion = reaper.find("JobOnProcessExit(core::ProcessKeySnapshot(dead_process))")
        lifecycle = reaper.find("ProcessLifecycleTransition(dead_process")
        self.assertTrue(0 <= unlink < lifecycle < completion)

        teardown = function_body(self.process, r"void\s+TeardownProcessRuntimeResources")
        key = teardown.find("const ProcessKey process_key = ProcessKeySnapshot(p)")
        handles = teardown.find("ProcessDropOwnedProcessHandles(p)")
        drain = teardown.find("JobDrainOwned(process_key)")
        self.assertTrue(0 <= key < handles < drain)
        self.assertNotIn("JobOnProcessExit", teardown)
        self.assertNotIn("JobDrainOwned(p->pid)", teardown)


if __name__ == "__main__":
    unittest.main(verbosity=2)
