#!/usr/bin/env python3
"""Hostile structural contract for cancellable Linux SysV/POSIX IPC waits."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MSG_SOURCE = (ROOT / "kernel/subsystems/linux/msg_queues.cpp").read_text(encoding="utf-8")
SEM_SOURCE = (ROOT / "kernel/subsystems/linux/sysv_ipc.cpp").read_text(encoding="utf-8")
HEADER = (ROOT / "kernel/subsystems/linux/syscall_internal.h").read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank comments and quoted literals while preserving offsets and braces."""
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
        # A C++ apostrophe between digits is a numeric separator, not a
        # character-literal delimiter (for example, 1'000'000'000).
        if source[index] == "'" and index > 0 and index + 1 < len(source):
            if source[index - 1].isdigit() and source[index + 1].isdigit():
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
            return code[opening_brace + 1 : matching(code, opening_brace, "{", "}")]
    raise AssertionError(f"missing function definition: {signature}")


def struct_body(source: str, name: str) -> str:
    code = code_only(source)
    match = re.search(rf"struct\s+{name}\s*\{{(?P<body>.*?)\}}\s*;", code, re.S)
    if match is None:
        raise AssertionError(f"missing struct: {name}")
    return match.group("body")


def require_order(body: str, *needles: str) -> None:
    positions = [body.find(needle) for needle in needles]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError(f"required order absent: {needles!r}; positions={positions!r}")


def reject_legacy_blocking(body: str) -> None:
    if re.search(r"\bWaitQueueBlock(?:Timeout)?\s*\(", body):
        raise AssertionError("retained a noncancellable wait-queue block")
    for forbidden in ("SchedSleep", "SchedExit", "arch::Cli", "arch::Sti"):
        if forbidden in body:
            raise AssertionError(f"retained unsafe blocking primitive: {forbidden}")


class LinuxSysvIpcWaitCancellationContract(unittest.TestCase):
    def test_static_slots_own_persistent_nonwrapping_epochs_and_incarnations(self) -> None:
        sysv_mq = struct_body(MSG_SOURCE, "SysvMq")
        posix_mq = struct_body(MSG_SOURCE, "PosixMq")
        sem_set = struct_body(SEM_SOURCE, "SemSet")
        self.assertIn("u64 incarnation", sysv_mq)
        self.assertIn("u64 wait_sequence", sysv_mq)
        self.assertIn("u64 wait_sequence", posix_mq)
        self.assertIn("u64 incarnation", sem_set)
        self.assertIn("u64 wait_sequence", sem_set)

        message_code = code_only(MSG_SOURCE)
        semaphore_code = code_only(SEM_SOURCE)
        self.assertNotRegex(message_code, r"\bq\.(?:wait_sequence|incarnation)\s*=\s*0\b")
        self.assertNotRegex(semaphore_code, r"\bs\.(?:wait_sequence|incarnation)\s*=\s*0\b")

        mq_alloc = function_body(MSG_SOURCE, r"i64\s+SysvMqAlloc")
        self.assertIn("g_sysv_pool[i].incarnation >= kSysvIpcIdGenerationMax", mq_alloc)
        self.assertIn("++q.incarnation", mq_alloc)
        self.assertNotRegex(mq_alloc, r"q\.(?:read|write)_wq\.(?:head|tail)\s*=")
        sem_alloc = function_body(SEM_SOURCE, r"i32\s+SemAllocLocked")
        self.assertIn("g_sem_pool[i].incarnation >= kSysvIpcIdGenerationMax", sem_alloc)
        self.assertIn("++s.incarnation", sem_alloc)
        self.assertNotRegex(sem_alloc, r"s\.sems\[j\]\.wq\.(?:head|tail)\s*=")

    def test_epoch_publication_is_release_ordered_and_snapshots_are_acquire_ordered(self) -> None:
        for source, publish_signature, snapshot_signature in (
            (MSG_SOURCE, r"void\s+WaitSequencePublishLocked", r"u64\s+WaitSequenceSnapshotLocked"),
            (SEM_SOURCE, r"void\s+SemWaitSequencePublishLocked", r"u64\s+SemWaitSequenceSnapshotLocked"),
        ):
            publish = function_body(source, publish_signature)
            self.assertIn("__atomic_load_n(sequence, __ATOMIC_RELAXED)", publish)
            self.assertIn("observed != ~u64{0}", publish)
            self.assertIn("__atomic_store_n(sequence, observed + 1, __ATOMIC_RELEASE)", publish)
            snapshot = function_body(source, snapshot_signature)
            self.assertIn("__atomic_load_n(sequence, __ATOMIC_ACQUIRE)", snapshot)

    def test_saturation_is_the_only_one_tick_polling_fallback(self) -> None:
        message_wait = function_body(MSG_SOURCE, r"bool\s+WaitForSequenceChangeCancellable")
        self.assertIn("observed_sequence == ~u64{0}", message_wait)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedTimeoutCancellable", message_wait)
        self.assertIn("observed_sequence, 1", message_wait)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedCancellable", message_wait)
        reject_legacy_blocking(message_wait)

        deadline_wait = function_body(MSG_SOURCE, r"i64\s+WaitWithDeadline")
        self.assertIn("observed_sequence == ~u64{0} && wait_ticks > 1", deadline_wait)
        self.assertIn("wait_ticks = 1", deadline_wait)
        self.assertIn("now >= deadline_ticks ? 0 : deadline_ticks - now", deadline_wait)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedTimeoutCancellable", deadline_wait)
        self.assertLess(
            deadline_wait.find("WaitQueueBlockIfSequenceUnchangedTimeoutCancellable"),
            deadline_wait.find("return kETimedOut"),
        )
        reject_legacy_blocking(deadline_wait)

        sem_wait = function_body(SEM_SOURCE, r"i64\s+SemWaitCancellable")
        self.assertIn("observed_sequence == ~u64{0} && wait_ticks > 1", sem_wait)
        self.assertIn("wait_ticks = 1", sem_wait)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedCancellable", sem_wait)
        self.assertIn("WaitQueueBlockIfSequenceUnchangedTimeoutCancellable", sem_wait)
        self.assertLess(
            sem_wait.find("WaitQueueBlockIfSequenceUnchangedTimeoutCancellable"),
            sem_wait.find("return kEAGAIN"),
        )
        reject_legacy_blocking(sem_wait)

    def test_sysv_message_waiters_drop_lock_and_detect_removal_aba(self) -> None:
        cases = (
            (r"i64\s+DoMsgsnd", "&q.write_wq", "return -11", "WaitQueueWakeAll(&q.read_wq)"),
            (r"i64\s+DoMsgrcv", "&q.read_wq", "return -42", "WaitQueueWakeOne(&q.write_wq)"),
        )
        for signature, queue, nowait_error, producer_wake in cases:
            body = function_body(MSG_SOURCE, signature)
            self.assertIn("expected_incarnation = decoded.generation", body)
            self.assertIn("q.incarnation != expected_incarnation", body)
            self.assertIn("return kEIDRM", body)
            self.assertIn(nowait_error, body)
            self.assertIn("kEINTR", body)
            self.assertNotIn("SysvMqPin", body)
            require_order(
                body,
                "WaitSequencePublishLocked(&q.wait_sequence)",
                producer_wake,
            )
            wait_arm = body[body.find(queue) :]
            require_order(
                wait_arm,
                queue,
                "WaitSequenceSnapshotLocked(&q.wait_sequence)",
                "SpinLockRelease(g_sysv_lock",
                "WaitForSequenceChangeCancellable",
            )
            cancel_arm = wait_arm[wait_arm.find("WaitForSequenceChangeCancellable") :]
            require_order(
                cancel_arm,
                "SpinLockAcquire(g_sysv_lock)",
                "q.incarnation != expected_incarnation",
                "return removed ? kEIDRM : kEINTR",
            )
            reject_legacy_blocking(body)

        send = function_body(MSG_SOURCE, r"i64\s+DoMsgsnd")
        require_order(send, "expected_incarnation = decoded.generation", "CopyFromUser")

    def test_sysv_message_removal_publishes_state_before_waking(self) -> None:
        body = function_body(MSG_SOURCE, r"i64\s+DoMsgctl")
        require_order(
            body,
            "q.marked_destroy = true",
            "q.closing = true",
            "q.in_use = false",
            "WaitSequencePublishLocked(&q.wait_sequence)",
            "WaitQueueWakeAll(&q.read_wq)",
            "WaitQueueWakeAll(&q.write_wq)",
        )

    def test_posix_timed_waiters_keep_exact_fd_receipt_but_no_subsystem_pin(self) -> None:
        cases = (
            (r"i64\s+DoMqTimedsend", "WaitQueueWakeOne(&q.read_wq)", "&q.write_wq"),
            (r"i64\s+DoMqTimedreceive", "WaitQueueWakeOne(&q.write_wq)", "&q.read_wq"),
        )
        for signature, producer_wake, waiter_queue in cases:
            body = function_body(MSG_SOURCE, signature)
            require_order(body, "LinuxFdAcquire", "LinuxFdAcquiredGuard acquired_guard", "while (true)")
            self.assertNotIn("PosixMqPin", body)
            require_order(body, "WaitSequencePublishLocked(&q.wait_sequence)", producer_wake)
            wait_arm = body[body.find(waiter_queue) :]
            require_order(
                wait_arm,
                waiter_queue,
                "WaitSequenceSnapshotLocked(&q.wait_sequence)",
                "SpinLockRelease(g_posix_lock",
                "WaitWithDeadline",
            )
            reject_legacy_blocking(body)

        deadline_wait = function_body(MSG_SOURCE, r"i64\s+WaitWithDeadline")
        self.assertIn("WaitQueueBlockResult::Cancelled", deadline_wait)
        self.assertIn("return kEINTR", deadline_wait)
        self.assertIn("WaitQueueBlockResult::TimedOut", deadline_wait)
        self.assertIn("return kETimedOut", deadline_wait)

    def test_posix_queue_retirement_publishes_before_waking(self) -> None:
        for signature in (r"void\s+PosixMqRelease", r"i64\s+DoMqUnlink"):
            body = function_body(MSG_SOURCE, signature)
            require_order(
                body,
                "WaitSequencePublishLocked(&q.wait_sequence)",
                "WaitQueueWakeAll(&q.read_wq)",
                "WaitQueueWakeAll(&q.write_wq)",
            )

    def test_semop_is_lock_linearized_cancellable_and_aba_safe(self) -> None:
        body = function_body(SEM_SOURCE, r"i64\s+SemOperate")
        self.assertIn("SpinLockAcquire(g_sem_lock)", body)
        self.assertIn("s.incarnation != expected_incarnation", body)
        self.assertIn("return kEIDRM", body)
        self.assertIn("return kEAGAIN", body)
        wait_arm = body[body.find("&s.sems[block_idx].wq") :]
        require_order(
            wait_arm,
            "&s.sems[block_idx].wq",
            "SemWaitSequenceSnapshotLocked(&s.wait_sequence)",
            "SpinLockRelease(g_sem_lock",
            "SemWaitCancellable",
        )
        reject_legacy_blocking(body)

        wait = function_body(SEM_SOURCE, r"i64\s+SemWaitCancellable")
        self.assertIn("WaitQueueBlockResult::Cancelled", wait)
        self.assertIn("return kEINTR", wait)
        self.assertIn("WaitQueueBlockResult::TimedOut", wait)
        self.assertIn("return kEAGAIN", wait)

        validation = function_body(SEM_SOURCE, r"i64\s+SemValidateIngress")
        self.assertIn("s.incarnation != expected_incarnation", validation)
        self.assertIn("return kEINVAL", validation)
        for signature in (r"i64\s+DoSemop", r"i64\s+DoSemtimedop"):
            ingress = function_body(SEM_SOURCE, signature)
            require_order(
                ingress,
                "expected_incarnation = decoded.generation",
                "SemValidateIngress",
                "CopyFromUser",
                "SemOperate",
            )

        cancel_arm = body[body.find("if (wait_result != 0)") :]
        require_order(
            cancel_arm,
            "SpinLockAcquire(g_sem_lock)",
            "s.incarnation != expected_incarnation",
            "return kEIDRM",
            "return wait_result",
        )
        self.assertNotIn("if (wait_result == kEINTR)", cancel_arm)

    def test_semop_vectors_are_cumulative_and_nowait_is_per_blocking_operation(self) -> None:
        apply = function_body(SEM_SOURCE, r"SemApplyResult\s+SemTryApplyLocked")
        self.assertIn("i64 staged[kSemPerSet]", apply)
        require_order(apply, "staged[i] = s.sems[i].value", "const i64 next = staged[sn] + op", "staged[sn] = next")
        self.assertGreaterEqual(apply.count("ops[i].sem_flg"), 2)
        self.assertIn("*block_nowait_out", apply)

        operate = function_body(SEM_SOURCE, r"i64\s+SemOperate")
        self.assertIn("bool block_nowait = false", operate)
        self.assertIn("if (block_nowait)", operate)
        self.assertNotRegex(operate, r"(?s)for\s*\([^)]*nops[^)]*\).*?nowait\s*=\s*true")

    def test_semaphore_mutations_and_removal_publish_before_wake(self) -> None:
        publisher = function_body(SEM_SOURCE, r"void\s+SemPublishMutationLocked")
        require_order(
            publisher,
            "SemWaitSequencePublishLocked(&s.wait_sequence)",
            "WaitQueueWakeAll(&s.sems[i].wq)",
        )

        control = function_body(SEM_SOURCE, r"i64\s+DoSemctl")
        removal = control[control.find("if (cmd == kIpcRmid)") : control.find("if (cmd == kSemGetval)")]
        require_order(
            removal,
            "s.marked_destroy = true",
            "s.in_use = false",
            "SemWaitSequencePublishLocked(&s.wait_sequence)",
            "WaitQueueWakeAll(&s.sems[i].wq)",
        )
        setval = control[control.find("if (cmd == kSemSetval)") : control.find("if (cmd == kIpcStat")]
        require_order(
            setval,
            "s.sems[semnum].value =",
            "SemWaitSequencePublishLocked(&s.wait_sequence)",
            "WaitQueueWakeAll(&s.sems[semnum].wq)",
        )

    def test_semtimedop_honors_relative_timeout_without_delegating_to_semop(self) -> None:
        body = function_body(SEM_SOURCE, r"i64\s+DoSemtimedop")
        self.assertIn("LoadSemDeadline(user_timeout, &deadline)", body)
        self.assertIn("SemOperate", body)
        self.assertNotIn("DoSemop", body)
        deadline = function_body(SEM_SOURCE, r"i64\s+LoadSemDeadline")
        self.assertIn("TickPeriodNs", deadline)
        self.assertIn("kMaxRelativeWaitTicks", deadline)
        self.assertIn("SchedNowTicks() + relative_ticks", deadline)
        self.assertIn("semtimedop honors its relative timeout", HEADER)
        self.assertNotRegex(HEADER, r"(?i)semtimedop[^\n]*ignore")

    def test_files_have_no_direct_terminal_exit_or_legacy_waits(self) -> None:
        for source in (MSG_SOURCE, SEM_SOURCE):
            code = code_only(source)
            self.assertNotIn("SchedExit", code)
        self.assertNotRegex(code_only(MSG_SOURCE), r"\bWaitQueueBlock(?:Timeout)?\s*\(")


if __name__ == "__main__":
    unittest.main()
