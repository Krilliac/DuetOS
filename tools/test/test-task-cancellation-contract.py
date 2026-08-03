#!/usr/bin/env python3
"""Structural guards for cooperative task-cancellation boundaries."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCHED_CPP = ROOT / "kernel" / "sched" / "sched.cpp"
SCHED_H = ROOT / "kernel" / "sched" / "sched.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
SYSCALL_CPP = ROOT / "kernel" / "syscall" / "syscall.cpp"
LINUX_SYSCALL_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall.cpp"
TRANSLATE_CPP = ROOT / "kernel" / "subsystems" / "translation" / "translate.cpp"
TRAPS_CPP = ROOT / "kernel" / "arch" / "x86_64" / "traps.cpp"
USERMODE_ASM = ROOT / "kernel" / "arch" / "x86_64" / "usermode.S"


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


def assembly_body(source: str, symbol: str) -> str:
    start = source.index(f"{symbol}:")
    finish = source.index(f".size {symbol}", start)
    return source[start:finish]


def require_pattern(source: str, pattern: str, message: str) -> None:
    if re.search(pattern, source) is None:
        raise AssertionError(message)


def reject_pattern(source: str, pattern: str, message: str) -> None:
    if re.search(pattern, source) is not None:
        raise AssertionError(message)


class TaskCancellationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sched_cpp = SCHED_CPP.read_text(encoding="utf-8")
        cls.sched_h = SCHED_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.syscall_cpp = SYSCALL_CPP.read_text(encoding="utf-8")
        cls.linux_syscall_cpp = LINUX_SYSCALL_CPP.read_text(encoding="utf-8")
        cls.translate_cpp = TRANSLATE_CPP.read_text(encoding="utf-8")
        cls.traps_cpp = TRAPS_CPP.read_text(encoding="utf-8")
        cls.usermode_asm = USERMODE_ASM.read_text(encoding="utf-8")

    def test_kill_intent_never_culls_ready_or_blocked_tasks(self) -> None:
        reject_pattern(
            self.sched_cpp,
            r"\bFinalizePendingKill(?:Current|Ready)Locked\s*\(",
            "scheduler still defines direct kill-finalization helpers",
        )
        handoff = function_body(self.sched_cpp, r"void\s+ScheduleLockedHandoff")
        self.assertFalse("kill_requested" in handoff, "scheduler handoff still culls kill intent")
        signal = function_body(self.sched_cpp, r"KillResult\s+SignalTaskLocked")
        reject_pattern(
            signal,
            r"\btarget->state\s*=\s*TaskState::Dead\b",
            "kill signalling directly marks Dead",
        )
        self.assertFalse("g_zombies" in signal, "kill signalling directly publishes a zombie")

    def test_dead_publication_is_self_exit_or_ap_sentinel_only(self) -> None:
        assignments = re.findall(r"\b\w+->state\s*=\s*TaskState::Dead\s*;", self.sched_cpp)
        self.assertEqual(
            len(assignments),
            2,
            f"unexpected direct TaskState::Dead publication sites: {assignments}",
        )

        handoff = function_body(self.sched_cpp, r"void\s+ScheduleLockedHandoff")
        self.assertEqual(len(re.findall(r"->state\s*=\s*TaskState::Dead\s*;", handoff)), 1)
        require_pattern(handoff, r"if\s*\(prev->no_requeue\)", "AP sentinel retirement lost its explicit gate")

        terminal = function_body(self.sched_cpp, r"void\s+SchedExitTerminal")
        self.assertEqual(len(re.findall(r"->state\s*=\s*TaskState::Dead\s*;", terminal)), 1)

        public_exit = function_body(self.sched_cpp, r"void\s+SchedExit")
        self.assertEqual(len(re.findall(r"->state\s*=\s*TaskState::Dead\s*;", public_exit)), 0)
        require_pattern(
            public_exit,
            r"SchedExitTerminal\s*\(\s*TaskTerminalContext::DirectKernelOrBootstrap\s*\)",
            "public exit does not route through the constrained terminal primitive",
        )

    def test_sleep_publication_consumes_pending_kill_in_the_same_transaction(self) -> None:
        for name in ("SchedSleepTicks", "SchedSleepUntil"):
            with self.subTest(sleeper=name):
                body = function_body(self.sched_cpp, rf"void\s+{name}")
                lock = re.search(r"SpinLockAcquire\s*\(\s*g_sched_lock\s*\)", body)
                kill = re.search(
                    r"if\s*\(\s*current->process\s*!=\s*nullptr\s*&&\s*KillPending\s*\(\s*current\s*\)\s*\)",
                    body,
                )
                sleeping = re.search(r"current->state\s*=\s*TaskState::Sleeping\s*;", body)
                enqueue = re.search(r"SleepqueueInsert\s*\(\s*current\s*\)", body)
                handoff = re.search(r"ScheduleLockedHandoff\s*\(", body)
                self.assertIsNotNone(lock, f"{name} does not acquire the scheduler transaction lock")
                self.assertIsNotNone(kill, f"{name} does not observe the combined kill ticket")
                self.assertIsNotNone(sleeping, f"{name} no longer publishes Sleeping")
                self.assertIsNotNone(enqueue, f"{name} no longer publishes its timer wait")
                self.assertIsNotNone(handoff, f"{name} no longer hands off under the held lock")
                positions = [lock.start(), kill.start(), sleeping.start(), enqueue.start(), handoff.start()]
                self.assertEqual(positions, sorted(positions), f"{name} checks cancellation after sleep publication")

                kill_open = body.find("{", kill.end())
                kill_branch = braced_body(body, kill_open)
                require_pattern(
                    kill_branch,
                    r"SpinLockRelease\s*\(\s*g_sched_lock",
                    f"{name} cancellation path does not release the scheduler lock",
                )
                require_pattern(
                    kill_branch,
                    r"MaybeFinalizeCurrentCancellation\s*\(\s*\)",
                    f"{name} cancellation path does not unwind to the cooperative boundary",
                )
                require_pattern(kill_branch, r"\breturn\s*;", f"{name} still publishes Sleeping after cancellation")

    def test_wait_primitives_never_exit_from_a_cancelled_stack(self) -> None:
        signatures = {
            "MutexLock": r"void\s+MutexLock",
            "MutexLockTimed": r"bool\s+MutexLockTimed",
            "CondvarWait": r"void\s+CondvarWait",
            "CondvarWaitTimeout": r"bool\s+CondvarWaitTimeout",
            "WaitQueueBlockIfSequenceUnchangedTimeoutCancellable": (
                r"WaitQueueBlockResult\s+WaitQueueBlockIfSequenceUnchangedTimeoutCancellable"
            ),
        }
        for name, signature in signatures.items():
            with self.subTest(primitive=name):
                body = function_body(self.sched_cpp, signature)
                reject_pattern(body, r"\bSchedExit\s*\(", f"{name} exits before its caller unwinds")

    def test_public_kill_rejects_every_kernel_task_before_mutation(self) -> None:
        signal = function_body(self.sched_cpp, r"KillResult\s+SignalTaskLocked")
        guard = re.search(r"target->process\s*==\s*nullptr", signal)
        self.assertIsNotNone(guard, "SignalTaskLocked lacks process-null protection")
        mutation = signal.find("PublishKillIntent")
        self.assertGreaterEqual(mutation, 0, "SignalTaskLocked does not publish kill intent")
        self.assertLess(guard.start(), mutation)
        protected_tail = signal[guard.start() : guard.start() + 240]
        require_pattern(protected_tail, r"return\s+KillResult::Protected\s*;", "process-null guard does not protect")

    def test_native_and_linux_dispatchers_share_a_nested_depth_guard(self) -> None:
        require_pattern(self.sched_cpp, r"\bu32\s+cancellation_defer_depth\s*;", "missing nested depth field")
        require_pattern(
            function_body(self.sched_cpp, r"void\s+SchedExitTerminal"),
            r"bootstrap_pending\s*&&\s*self->cancellation_defer_depth\s*==\s*1",
            "terminal primitive still permits nested live deferrals during bootstrap",
        )
        require_pattern(
            self.sched_h,
            r"\b(?:class|struct)\s+ScopedTaskCancellationDeferral\b",
            "missing deferral guard API",
        )
        require_pattern(self.sched_cpp, r"\bbool\s+cancellation_finalizing\s*;", "missing single-finalizer state")
        guard_pattern = r"(?:[A-Za-z_]\w*::)*ScopedTaskCancellationDeferral\s+[A-Za-z_]\w*"
        native = function_body(self.syscall_cpp, r"void\s+SyscallDispatch")
        linux = function_body(self.linux_syscall_cpp, r'extern\s+"C"\s+void\s+LinuxSyscallDispatch')
        native_guard = re.search(guard_pattern, native)
        linux_guard = re.search(guard_pattern, linux)
        self.assertIsNotNone(native_guard)
        self.assertIsNotNone(linux_guard)
        self.assertLess(native_guard.start(), native.index("SyscallTrailGuard trail_guard"))
        self.assertLess(linux_guard.start(), linux.index("const u64 nr"))

    def test_terminal_exit_routes_are_explicit_and_runtime_paths_cooperate(self) -> None:
        reject_pattern(
            self.sched_h,
            r"\bSchedExitTerminal\s*\(",
            "irreversible terminal primitive leaked into the public scheduler API",
        )
        require_pattern(
            self.sched_cpp,
            r"enum\s+class\s+TaskTerminalContext\s*:\s*u8\s*\{[^}]*DirectKernelOrBootstrap"
            r"[^}]*CooperativeCancellation[^}]*TrampolineReturn",
            "terminal exit contexts are not explicitly enumerated",
        )

        terminal = function_body(self.sched_cpp, r"void\s+SchedExitTerminal")
        require_pattern(terminal, r"switch\s*\(\s*context\s*\)", "terminal primitive does not validate its route")
        require_pattern(
            terminal,
            r"self->process\s*==\s*nullptr\s*\|\|\s*\(\s*self->bootstrap_pending",
            "direct exit is not limited to process-null or bootstrap Tasks",
        )
        require_pattern(
            terminal,
            r"self->cancellation_finalizing",
            "cooperative exit does not require finalizer ownership",
        )
        require_pattern(terminal, r"KillPending\s*\(\s*self\s*\)", "cooperative exit does not require a kill ticket")

        finalizer = function_body(self.sched_cpp, r"void\s+FinalizeCurrentCancellation")
        require_pattern(
            finalizer,
            r"SchedExitTerminal\s*\(\s*TaskTerminalContext::CooperativeCancellation\s*\)",
            "cancellation finalization uses the direct terminal route",
        )
        trampoline = function_body(self.sched_cpp, r"void\s+SchedExitFromTrampoline")
        require_pattern(
            trampoline,
            r"SchedExitTerminal\s*\(\s*TaskTerminalContext::TrampolineReturn\s*\)",
            "TaskEntry return is not marked as a trampoline terminal route",
        )
        c_shim = function_body(self.sched_cpp, r"void\s+SchedExitC")
        require_pattern(
            c_shim,
            r"SchedExitFromTrampoline\s*\(\s*\)",
            "assembly trampoline still enters the public direct-exit route",
        )

        for name, source in {
            "native syscall": self.syscall_cpp,
            "Linux syscall": self.linux_syscall_cpp,
            "NT translator": self.translate_cpp,
        }.items():
            with self.subTest(runtime=name):
                reject_pattern(source, r"\bSchedExit\s*\(", f"{name} bypasses cooperative cancellation")

        for symbol in ("NtDoTerminateThread", "NtDoTerminateProcess"):
            translated_exit = function_body(self.translate_cpp, rf"i64\s+{symbol}")
            require_pattern(
                translated_exit,
                r"return\s+::duetos::subsystems::linux::LinuxExit\s*\(",
                f"{symbol} no longer returns through the cooperative runtime boundary",
            )

    def test_timed_sequence_cancellable_wait_is_one_scheduler_transaction(self) -> None:
        require_pattern(
            self.sched_h,
            r"WaitQueueBlockResult\s+WaitQueueBlockIfSequenceUnchangedTimeoutCancellable\s*\(\s*"
            r"WaitQueue\s*\*\s*\w+\s*,\s*const\s+u64\s*\*\s*\w+\s*,\s*u64\s+observed_sequence\s*,\s*"
            r"u64\s+ticks\s*\)",
            "missing timed sequence-aware cancellable wait API",
        )
        body = function_body(
            self.sched_cpp,
            r"WaitQueueBlockResult\s+WaitQueueBlockIfSequenceUnchangedTimeoutCancellable",
        )
        clamp = re.search(r"ClampRelativeWaitTicks\s*\(\s*ticks\s*\)", body)
        lock = re.search(r"SpinLockAcquire\s*\(\s*g_sched_lock\s*\)", body)
        kill = re.search(r"KillPending\s*\(\s*self\s*\)", body)
        sequence = re.search(r"__atomic_load_n\s*\(\s*sequence\s*,\s*__ATOMIC_ACQUIRE\s*\)", body)
        zero = re.search(r"wait_ticks\s*==\s*0", body)
        deadline = re.search(r"RelativeDeadlineFromNow\s*\(\s*g_tick_now\s*,\s*wait_ticks\s*\)", body)
        marker = re.search(r"self->wait_cancellable\s*=\s*true\s*;", body)
        enqueue = re.search(r"WaitQueueBlockCurrentUntilLocked\s*\(", body)
        handoff = re.search(r"ScheduleLockedHandoff\s*\(", body)
        classify = re.search(r"ClassifyCancellableWaitResume\s*\(\s*true\s*\)", body)
        points = [clamp, lock, kill, sequence, zero, deadline, marker, enqueue, handoff, classify]
        self.assertTrue(all(point is not None for point in points), "timed sequence wait lost a required transaction step")
        positions = [point.start() for point in points]
        self.assertEqual(positions, sorted(positions), "timed sequence wait publishes or classifies out of order")
        for result in ("Cancelled", "SequenceChanged", "TimedOut"):
            require_pattern(
                body,
                rf"return\s+WaitQueueBlockResult::{result}\s*;",
                f"timed sequence wait does not report {result}",
            )
        reject_pattern(body, r"\b(?:SchedExit|MaybeFinalizeCurrentCancellation)\s*\(", "wait finalizes beneath caller scopes")

    def test_user_traps_unwind_before_fault_cancellation_finalizes(self) -> None:
        trap = function_body(self.traps_cpp, r"extern\s+\"C\"\s+void\s+TrapDispatch")
        origin = re.search(r"cancellation_user_origin\s*=\s*\(frame->cs\s*&\s*3\)\s*==\s*3", trap)
        cancellation = re.search(
            r"ScopedTaskCancellationDeferral\s+cancellation_guard\s*\(cancellation_user_origin\)", trap
        )
        rip_guard = re.search(r"RipIntegrityGuard\s+guard\s*\(frame\)", trap)
        self.assertIsNotNone(origin, "trap cancellation boundary does not distinguish user origin")
        self.assertIsNotNone(cancellation, "TrapDispatch lacks a user-origin cancellation deferral")
        self.assertIsNotNone(rip_guard, "TrapDispatch lost its RIP-integrity scope")
        self.assertEqual(
            [origin.start(), cancellation.start(), rip_guard.start()],
            sorted([origin.start(), cancellation.start(), rip_guard.start()]),
            "trap diagnostics can outlive the cancellation guard",
        )
        require_pattern(
            trap,
            r"SchedRequestCurrentExit\s*\(duetos::sched::KillReason::UserFault\)",
            "unhandled user fault bypasses cooperative cancellation",
        )

    def test_every_user_bootstrap_crosses_the_completion_boundary(self) -> None:
        require_pattern(self.sched_cpp, r"\bbool\s+bootstrap_pending\s*;", "missing bootstrap barrier state")
        require_pattern(self.sched_h, r"\bSchedUserBootstrapComplete\s*\(\s*\)\s*;", "missing bootstrap API")
        for symbol in ("EnterUserModeWithGs", "EnterUserModeThread", "EnterUserMode32"):
            with self.subTest(entry=symbol):
                body = assembly_body(self.usermode_asm, symbol)
                call = re.search(r"\bcall\s+SchedUserBootstrapComplete\b", body)
                cli = re.search(r"(?m)^[ \t]*cli[ \t]*(?:/\*.*\*/)?$", body)
                self.assertIsNotNone(call)
                self.assertIsNotNone(cli)
                self.assertLess(call.start(), cli.start())

    def test_kill_reason_and_intent_use_one_atomic_state_word(self) -> None:
        require_pattern(self.sched_cpp, r"\bu64\s+kill_ticket\s*;", "missing combined reason/code ticket")
        reject_pattern(self.sched_cpp, r"\bbool\s+kill_requested\s*;", "split kill-intent field remains")
        reject_pattern(self.sched_cpp, r"\bKillReason\s+kill_reason\s*;", "split kill-reason field remains")
        reject_pattern(self.sched_cpp, r"\bu32\s+kill_exit_code\s*;", "split kill-exit-code field remains")
        self.assertFalse("->kill_requested" in self.sched_cpp, "non-atomic kill-intent access remains")
        self.assertFalse("->kill_reason" in self.sched_cpp, "non-atomic kill-reason access remains")
        direct_writes = re.findall(r"->kill_ticket\s*=\s*([^;]+);", self.sched_cpp)
        self.assertTrue(
            all(value.strip() == "0" for value in direct_writes),
            "runtime kill publication bypasses atomics",
        )
        request = function_body(self.sched_cpp, r"void\s+SchedRequestCurrentExit")
        require_pattern(
            request,
            r"\bFlagCurrentForKill\s*\(\s*reason\s*,\s*exit_code\s*\)",
            "exit request bypasses combined intent helper",
        )
        flag = function_body(self.sched_cpp, r"void\s+FlagCurrentForKill")
        current = re.search(r"\bTask\s*\*\s*self\s*=\s*CurrentTask\s*\(\s*\)", flag)
        publish = re.search(r"\bPublishKillIntent\s*\(\s*self\s*,\s*reason\s*,\s*exit_code\s*\)", flag)
        resched = re.search(r"\bNeedResched\s*\(\s*\)\s*=\s*true", flag)
        self.assertIsNotNone(current, "kill publication does not use the boot-safe current-task accessor")
        self.assertIsNotNone(publish, "intent helper bypassed")
        self.assertIsNotNone(resched, "accepted current kill does not request reschedule")
        self.assertEqual([current.start(), publish.start(), resched.start()], sorted([current.start(), publish.start(), resched.start()]))
        rejected = flag[publish.end() : resched.start()]
        require_pattern(rejected, r"return\s*;", "kernel/pre-scheduler kill still mutates reschedule state")
        publisher = function_body(self.sched_cpp, r"bool\s+PublishKillIntent")
        require_pattern(publisher, r"\bu64\s+expected\s*=\s*0\s*;", "kill CAS does not start from no-intent")
        require_pattern(
            publisher,
            r"\bdesired\s*=\s*EncodeKillTicket\s*\(\s*reason\s*,\s*exit_code\s*\)",
            "kill reason and DWORD are not encoded together",
        )
        require_pattern(
            publisher,
            r"__atomic_compare_exchange_n\s*\([^;]*kill_ticket",
            "kill ticket is not CAS-published",
        )
        loader = function_body(self.sched_cpp, r"u64\s+KillTicketLoad")
        require_pattern(
            loader,
            r"__atomic_load_n\s*\([^;]*kill_ticket",
            "kill ticket is not atomically observed",
        )
        encoder = function_body(self.sched_cpp, r"u64\s+EncodeKillTicket")
        require_pattern(
            encoder,
            r"static_cast<u64>\s*\(\s*exit_code\s*\)\s*<<\s*kKillExitCodeShift",
            "kill ticket omits the exact DWORD",
        )
        require_pattern(self.sched_h, r"\bJobTermination\s*=\s*10\b", "Job termination lacks a stable reason")

    def test_task_identity_namespace_never_wraps_or_mints_invalid_sentinel(self) -> None:
        current_id = function_body(self.sched_cpp, r"u64\s+CurrentTaskId")
        require_pattern(
            current_id,
            r"Task\s*\*\s*self\s*=\s*CurrentTask\s*\(\s*\)",
            "CurrentTaskId dereferences PerCpu state before the boot-safe current-task guard",
        )
        reject_pattern(current_id, r"=\s*Current\s*\(\s*\)", "CurrentTaskId bypasses its documented early-boot sentinel")
        mint = function_body(self.sched_cpp, r"bool\s+MintTaskId")
        load = re.search(r"__atomic_load_n\s*\(\s*&g_next_task_id", mint)
        exhaustion = re.search(r"current\s*==\s*~u64\s*\{\s*0\s*\}", mint)
        cas = re.search(r"__atomic_compare_exchange_n\s*\(\s*&g_next_task_id", mint)
        self.assertIsNotNone(load, "Task identity dispenser does not atomically load")
        self.assertIsNotNone(exhaustion, "Task identity dispenser does not reserve the invalid sentinel")
        self.assertIsNotNone(cas, "Task identity dispenser is not a concurrency-safe CAS")
        self.assertLess(exhaustion.start(), cas.start(), "Task ID increments before checking exhaustion")
        reject_pattern(
            self.sched_cpp,
            r"__atomic_fetch_add\s*\(\s*&g_next_task_id",
            "Task identity allocation can still wrap through fetch_add",
        )
        self.assertGreaterEqual(
            len(re.findall(r"\bMintTaskId\s*\(", self.sched_cpp)),
            4,
            "not every boot/user/AP Task allocation site consumes the non-wrapping dispenser",
        )

    def test_exact_process_key_lookup_matches_and_retains_inside_lifetime_lock(self) -> None:
        require_pattern(
            self.sched_h,
            r"core::Process\s*\*\s*SchedFindProcessByKeyRetained\s*\(\s*core::ProcessKey\b",
            "scheduler does not expose an exact retained ProcessKey lookup",
        )
        lookup = function_body(self.sched_cpp, r"core::Process\s*\*\s*SchedFindProcessByKeyRetained")
        invalid = re.search(r"!\s*core::ProcessKeyIsValid\s*\(", lookup)
        lock = re.search(r"SpinLockGuard\s+guard\s*\(\s*g_sched_lock\s*\)", lookup)
        find = re.search(r"FindProcessByKeyLocked\s*\(", lookup)
        retain = re.search(r"ProcessRetain\s*\(", lookup)
        self.assertIsNotNone(invalid, "exact ProcessKey lookup accepts the invalid key")
        self.assertIsNotNone(lock, "exact ProcessKey lookup is not serialized")
        self.assertIsNotNone(find, "public lookup bypasses exact locked matching")
        self.assertIsNotNone(retain, "exact lookup returns a borrowed Process")
        positions = [invalid.start(), lock.start(), find.start(), retain.start()]
        self.assertEqual(positions, sorted(positions), "lookup does not retain the exact match under its lock")

        exact = function_body(self.sched_cpp, r"core::Process\s*\*\s*FindProcessByKeyLocked")
        require_pattern(exact, r"process->pid\s*==\s*target\.pid", "exact lookup ignores PID")
        require_pattern(
            exact,
            r"process->process_identity\s*==\s*target\.identity",
            "exact lookup ignores immutable incarnation identity",
        )
        reject_pattern(exact, r"\bProcessRetain\s*\(", "locked finder owns retention instead of its public wrapper")

    def test_process_wide_termination_tombstone_linearizes_with_task_publication(self) -> None:
        require_pattern(
            self.process_h,
            r"enum\s+class\s+ProcessTerminationState\s*:\s*u32\s*\{[^}]*\bOpen\b[^}]*\bClosed\b[^}]*\}",
            "Process lacks a distinct open/closed termination tombstone",
        )
        require_pattern(
            self.process_h,
            r"\bProcessTerminationState\s+termination_state\s*;",
            "Process does not own the termination tombstone",
        )
        self.assertEqual(
            len(
                re.findall(
                    r"\btermination_state\s*=\s*ProcessTerminationState::Open\s*;",
                    self.process_cpp,
                )
            ),
            1,
            "termination publication can be reopened or is not explicitly initialized",
        )

        load = function_body(self.process_cpp, r"ProcessTerminationState\s+ProcessTerminationLoad")
        require_pattern(load, r"__atomic_load\s*\([^;]*termination_state", "termination state is not atomically loaded")
        close = function_body(self.process_cpp, r"bool\s+ProcessTerminationClose")
        require_pattern(
            close,
            r"__atomic_compare_exchange\s*\([^;]*termination_state",
            "termination close is not a monotonic CAS",
        )
        require_pattern(close, r"ProcessTerminationState::Open", "termination close does not require Open")
        require_pattern(close, r"ProcessTerminationState::Closed", "termination close does not publish Closed")
        reject_pattern(close, r"ProcessLifecycle", "termination close mutates Process lifecycle")

        publish = function_body(self.sched_cpp, r"bool\s+PublishCreatedTask")
        publish_lock = re.search(r"SpinLockGuard\s+guard\s*\(\s*g_sched_lock\s*\)", publish)
        tombstone_check = re.search(
            r"if\s*\(\s*ProcessTerminationLoad\s*\(\s*task->process\s*\)\s*!=\s*"
            r"ProcessTerminationState::Open\s*\)\s*return\s+false\s*;",
            publish,
        )
        first_gate = re.search(r"ProcessRunPublicationGateAtSchedulerPublication\s*\(", publish)
        task_publish = re.search(r"task->published\s*=\s*true\s*;", publish)
        self.assertIsNotNone(publish_lock, "Task publication does not hold the scheduler registry lock")
        self.assertIsNotNone(tombstone_check, "Task publication does not reject a closed Process")
        self.assertIsNotNone(first_gate, "first-Task policy gate disappeared")
        self.assertIsNotNone(task_publish, "Task publication marker disappeared")
        self.assertEqual(
            [publish_lock.start(), tombstone_check.start(), first_gate.start(), task_publish.start()],
            sorted([publish_lock.start(), tombstone_check.start(), first_gate.start(), task_publish.start()]),
            "Process termination is checked after a Task can cross publication",
        )

        for name, signature in {
            "PID kill": r"u64\s+SchedKillProcessByPid",
            "retained-Process kill": r"u64\s+SchedKillByProcess",
        }.items():
            with self.subTest(kill_path=name):
                body = function_body(self.sched_cpp, signature)
                lock = re.search(r"SpinLockGuard\s+guard\s*\(\s*g_sched_lock\s*\)", body)
                self.assertIsNotNone(lock, f"{name} does not hold the scheduler registry lock")
                locked_open = body.rfind("{", 0, lock.start())
                self.assertGreaterEqual(locked_open, 0, f"{name} lock has no lexical transaction block")
                locked = braced_body(body, locked_open)
                close_call = re.search(r"ProcessTerminationClose\s*\(\s*target\s*,\s*exit_code\s*\)", locked)
                signal = re.search(r"SignalTaskLocked\s*\(", locked)
                self.assertIsNotNone(close_call, f"{name} does not close publication inside its lock hold")
                self.assertIsNotNone(signal, f"{name} no longer scans and signals matching Tasks")
                self.assertLess(close_call.start(), signal.start(), f"{name} scans before closing publication")
                reject_pattern(
                    body,
                    r"ProcessLifecycleTransition",
                    f"{name} advances lifecycle before last-Task reap",
                )

        individual = function_body(self.sched_cpp, r"KillResult\s+SchedKillByPid")
        reject_pattern(
            individual,
            r"ProcessTerminationClose",
            "individual TID kill incorrectly closes the whole Process",
        )
        require_pattern(
            self.sched_cpp,
            r"ProcessLifecycleTransition\s*\(\s*dead_process\s*,\s*ProcessLifecycleState::Published\s*,\s*"
            r"ProcessLifecycleState::Exiting\s*\)",
            "Published -> Exiting is no longer owned by last-Task reap",
        )

        create_internal = function_body(self.sched_cpp, r"TaskCreateResult\s+SchedCreateInternal")
        publication_call = re.search(r"PublishCreatedTask\s*\(", create_internal)
        rollback = re.search(r"DestroyUnpublishedTask\s*\(", create_internal)
        self.assertIsNotNone(publication_call, "Task creation bypasses its publication receipt")
        self.assertIsNotNone(rollback, "rejected publication leaks the private Task or stacks")
        self.assertLess(publication_call.start(), rollback.start(), "private Task rollback precedes publication rejection")

        create_user = function_body(self.sched_cpp, r"TaskCreateResult\s+CreateUserTask")
        failed = re.search(r"if\s*\(\s*!result\.created\s*\)", create_user)
        vm_unlock = re.search(r"vm_transaction\.Unlock\s*\(\s*\)", create_user[failed.end() :] if failed else "")
        process_release = re.search(r"ProcessRelease\s*\(\s*process\s*\)", create_user[failed.end() :] if failed else "")
        self.assertIsNotNone(failed, "CreateUserTask lost failed-publication handling")
        self.assertIsNotNone(vm_unlock, "failed user publication keeps the Process VM transaction locked")
        self.assertIsNotNone(process_release, "failed user publication leaks the caller-owned Process reference")
        self.assertLess(vm_unlock.start(), process_release.start(), "Process is released while its VM transaction is held")


if __name__ == "__main__":
    unittest.main()
