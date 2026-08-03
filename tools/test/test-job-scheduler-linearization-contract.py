#!/usr/bin/env python3
"""Structural contract for Job/scheduler publication and exit linearization."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def code_only(text: str) -> str:
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
                state = "literal"
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


def body(text: str, signature: str) -> str:
    masked = code_only(text)
    match = re.search(signature, masked)
    if not match:
        raise AssertionError(f"missing function {signature}")
    opening = masked.find("{", match.end())
    depth = 0
    for i in range(opening, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return masked[opening : i + 1]
    raise AssertionError(f"unterminated function {signature}")


class JobSchedulerLinearizationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.job_h = read("kernel/proc/job.h")
        cls.job_cpp = read("kernel/proc/job.cpp")
        cls.process_h = read("kernel/proc/process.h")
        cls.process_cpp = read("kernel/proc/process.cpp")
        cls.sched_h = read("kernel/sched/sched.h")
        cls.sched_cpp = read("kernel/sched/sched.cpp")
        cls.adapter = read("kernel/subsystems/win32/job_syscall.cpp")
        cls.syscall = read("kernel/syscall/syscall.cpp")

    def test_pending_inheritance_ticket_is_hidden_pinned_and_nonce_bound(self) -> None:
        header = code_only(self.job_h)
        self.assertRegex(header, r"JobPublicationTicket\s*\(\s*const\s+JobPublicationTicket&\s*\)\s*=\s*delete")
        self.assertRegex(header, r"u64\s+ticket\s*=\s*0")
        self.assertRegex(code_only(self.job_cpp), r"PendingPublication")

        prepare = body(self.job_cpp, r"JobPublishPrepareResult\s+JobPrepareInheritedMember")
        for required in (
            "pending.state = JobMemberState::PendingPublication",
            "pending.publication_ticket = ticket",
            "++parent_row->pending_member_count",
            "++parent_row->operation_pins",
        ):
            self.assertIn(required, prepare)

        commit = body(self.job_cpp, r"bool\s+JobCommitInheritedMember")
        self.assertIn("pending.publication_ticket != ticket->ticket", commit)
        self.assertIn("pending.state = JobMemberState::Active", commit)
        self.assertIn("--row->pending_member_count", commit)
        self.assertIn("--row->operation_pins", commit)

        abort = body(self.job_cpp, r"bool\s+JobAbortInheritedMember")
        self.assertIn("pending.publication_ticket != ticket->ticket", abort)
        self.assertIn("ClearMember(pending)", abort)
        self.assertIn("--row->pending_member_count", abort)
        self.assertIn("--row->operation_pins", abort)

        snapshot = body(self.job_cpp, r"void\s+SnapshotLocked")
        self.assertIn("entry.state == JobMemberState::Active", snapshot)
        self.assertNotIn("PendingPublication", snapshot)

    def test_first_publication_composes_job_and_service_gates_sequentially(self) -> None:
        publish = body(self.sched_cpp, r"bool\s+PublishCreatedTask")
        positions = [
            publish.find("SpinLockGuard guard(g_sched_lock)"),
            publish.find("JobPrepareInheritedMember"),
            publish.find("ProcessRunPublicationGateAtSchedulerPublication"),
            publish.find("JobAbortInheritedMember"),
            publish.find("JobCommitInheritedMember"),
            publish.find("ProcessLifecycleTransition"),
            publish.find("task->published = true"),
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertGreaterEqual(positions[0], 0)
        self.assertNotIn("g_job_lock", publish)
        self.assertIn("parent_task->state != TaskState::Dead", publish)
        self.assertIn("ProcessKeySnapshot(parent_task->process) == parent_key", publish)

    def test_explicit_assignment_is_one_scheduler_transaction(self) -> None:
        adapter = body(self.adapter, r"i64\s+SysJobAssign")
        self.assertIn("SchedAssignProcessToJob", adapter)
        self.assertNotIn("SchedCountLiveTasksForProcess", adapter)
        self.assertNotIn("JobOnProcessExit", adapter)

        assign = body(self.sched_cpp, r"JobAssignResult\s+SchedAssignProcessToJob")
        lock = assign.find("SpinLockGuard guard(g_sched_lock)")
        lifecycle = assign.find("ProcessLifecycleLoad(target)")
        scan = assign.find("g_all_tasks_head")
        mutate = assign.find("return core::JobAssign(")
        self.assertTrue(0 <= lock < lifecycle < scan < mutate)
        self.assertIn("task->state != TaskState::Dead", assign)
        self.assertIn("ProcessTerminationState::Open", assign)

    def test_termination_ticket_and_one_pass_dispatch_are_truthful(self) -> None:
        header = code_only(self.job_h)
        self.assertRegex(header, r"JobTerminationIntent\s*\(\s*const\s+JobTerminationIntent&\s*\)\s*=\s*delete")
        begin = body(self.job_cpp, r"JobTerminateResult\s+JobBeginTermination")
        self.assertIn("row->state = JobState::Terminating", begin)
        self.assertIn("row->termination_ticket = ticket", begin)
        self.assertIn("out_intent->exit_code = exit_code", begin)
        self.assertNotIn("total_terminated_processes +=", begin)

        finish = body(self.job_cpp, r"bool\s+JobFinishTermination")
        self.assertIn("row->termination_ticket != intent->ticket", finish)
        self.assertIn("MaybeCompleteAndRetireLocked", finish)
        self.assertNotIn("row->state = JobState::Tombstone", finish)

        completion = body(self.job_cpp, r"void\s+MaybeCompleteAndRetireLocked")
        terminating = completion.find("row.state == JobState::Terminating")
        zero_members = completion.find("row.member_count == 0", terminating)
        zero_pending = completion.find("row.pending_member_count == 0", terminating)
        zero_pins = completion.find("row.operation_pins == 0", terminating)
        tombstone = completion.find("row.state = JobState::Tombstone", terminating)
        self.assertTrue(0 <= terminating < zero_members < zero_pending < zero_pins < tombstone)

        dispatch = body(self.sched_cpp, r"JobTerminateResult\s+SchedTerminateJob")
        self.assertEqual(len(re.findall(r"for\s*\(\s*Task\s*\*\s*task\s*=\s*g_all_tasks_head", dispatch)), 1)
        for required in (
            "JobBeginTermination",
            "intent.members[member] == task_process",
            "ProcessTerminationClose(task->process, exit_code)",
            "SignalTaskLocked(task, KillReason::JobTermination, exit_code)",
            "JobFinishTermination",
        ):
            self.assertIn(required, dispatch)

    def test_retirement_and_slot_reuse_require_all_owners_gone(self) -> None:
        retire = body(self.job_cpp, r"void\s+RetireLocked")
        for required in (
            "row.operation_pins == 0",
            "row.member_count == 0",
            "row.pending_member_count == 0",
        ):
            self.assertIn(required, retire)
        maybe = body(self.job_cpp, r"void\s+MaybeCompleteAndRetireLocked")
        for required in (
            "row.references != 0",
            "row.operation_pins != 0",
            "row.member_count != 0",
            "row.pending_member_count != 0",
        ):
            self.assertIn(required, maybe)
        exited = body(self.job_cpp, r"void\s+JobOnProcessExit")
        self.assertIn("ClearMember(entry)", exited)
        self.assertIn("--row.member_count", exited)

    def test_reason_code_and_process_result_have_single_winners(self) -> None:
        self.assertRegex(code_only(self.sched_cpp), r"u64\s+kill_ticket\s*;")
        encode = body(self.sched_cpp, r"u64\s+EncodeKillTicket")
        self.assertIn("static_cast<u64>(exit_code) << kKillExitCodeShift", encode)
        publish = body(self.sched_cpp, r"bool\s+PublishKillIntent")
        self.assertIn("u64 expected = 0", publish)
        self.assertIn("__atomic_compare_exchange_n(&task->kill_ticket", publish)

        close = body(self.process_cpp, r"bool\s+ProcessTerminationClose")
        state_cas = close.find("__atomic_compare_exchange(&process->termination_state")
        result_cas = close.find("__atomic_compare_exchange_n(&process->win32_exit_status")
        self.assertTrue(0 <= state_cas < result_cas)
        fallback = body(self.process_cpp, r"void\s+ProcessPublishLastTaskExitCodeIfUnset")
        self.assertIn("u64 empty = 0", fallback)
        self.assertIn("__atomic_compare_exchange_n(&process->win32_exit_status", fallback)

        reaper = body(self.sched_cpp, r"\[\[noreturn\]\]\s+void\s+ReaperMain")
        fallback_pos = reaper.find("ProcessPublishLastTaskExitCodeIfUnset")
        lifecycle_pos = reaper.find("ProcessLifecycleTransition(dead_process", fallback_pos)
        member_pos = reaper.find("JobOnProcessExit(core::ProcessKeySnapshot(dead_process))", lifecycle_pos)
        self.assertTrue(0 <= fallback_pos < lifecycle_pos < member_pos)

        query = body(self.process_cpp, r"u32\s+ProcessWin32ExitCodeSnapshot")
        self.assertIn("ProcessLifecycleState::Exited", query)
        self.assertIn("return kWin32StillActive", query)
        basic = code_only(self.syscall)
        self.assertIn("info.exit_status = core::ProcessWin32ExitCodeSnapshot(target)", basic)

    def test_exit_codes_are_wired_from_all_public_closure_paths(self) -> None:
        dispatch = code_only(self.syscall)
        self.assertIn("SchedRequestCurrentExit(sched::KillReason::ExplicitExit, static_cast<u32>(code))", dispatch)
        self.assertIn("const u32 exit_code = static_cast<u32>(frame->rsi)", dispatch)
        self.assertIn("SchedKillByProcess(caller, exit_code)", dispatch)
        self.assertIn("SchedKillByProcess(target, exit_code)", dispatch)
        terminate = body(self.adapter, r"i64\s+SysJobTerminate")
        self.assertIn("SchedTerminateJob(key, caller_key, static_cast<u32>(exit_code))", terminate)

    def test_pid_list_is_partial_safe_and_reports_assigned_total(self) -> None:
        encode = body(self.adapter, r"u64\s+EncodeProcessIdList")
        self.assertIn("snapshot.member_count", encode)
        self.assertIn("snapshot.process_id_count < capacity", encode)
        self.assertIn("PutLe32(output, 4, returned)", encode)

        query = body(self.adapter, r"i64\s+SysJobQuery")
        self.assertIn("buf_len < kJobProcessIdListHeaderSize", query)
        self.assertIn("(buf_len - kJobProcessIdListHeaderSize) / sizeof(u64)", query)
        self.assertIn("EncodeProcessIdList(snapshot, static_cast<u32>(capacity), stage)", query)
        self.assertIn("return static_cast<i64>(returned_bytes)", query)
        self.assertNotIn("if (buf_len < needed)", query[: query.find("kJobInfoBasicAccounting")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
