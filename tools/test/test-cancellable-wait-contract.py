#!/usr/bin/env python3
"""Structural guards for result-bearing cancellable scheduler waits."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCHED_CPP = ROOT / "kernel" / "sched" / "sched.cpp"
SCHED_H = ROOT / "kernel" / "sched" / "sched.h"


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


class CancellableWaitContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sched_cpp = SCHED_CPP.read_text(encoding="utf-8")
        cls.sched_h = SCHED_H.read_text(encoding="utf-8")

    def test_public_result_shape_and_ownership_clear_condvar_api(self) -> None:
        enum = require_pattern(
            self.sched_h,
            r"enum\s+class\s+WaitQueueBlockResult\s*:\s*u8\s*\{(?P<body>[^}]*)\}",
            "missing cancellable wait result enum",
        ).group("body")
        names = re.findall(r"\b(Woken|TimedOut|Cancelled|SequenceChanged)\b", enum)
        self.assertEqual(names, ["Woken", "TimedOut", "Cancelled", "SequenceChanged"])
        reject_pattern(self.sched_h + self.sched_cpp, r"\bPredicateChanged\b", "stale predicate result name")

        signatures = (
            "WaitQueueBlockCancellable",
            "WaitQueueBlockTimeoutCancellable",
            "WaitQueueBlockIfSequenceUnchangedCancellable",
            "CondvarWaitCancellable",
            "CondvarWaitTimeoutCancellable",
        )
        for name in signatures:
            with self.subTest(api=name):
                require_pattern(
                    self.sched_h,
                    rf"WaitQueueBlockResult\s+{name}\s*\(",
                    f"{name} has an ownership-ambiguous result type",
                )
        require_pattern(
            self.sched_h,
            r"`m`\s+is\s+held\s+on\s+every\s+return\s+path",
            "condvar held-on-return invariant is undocumented",
        )

    def test_dequeue_authority_has_a_dedicated_latch_and_initialization(self) -> None:
        require_pattern(self.sched_cpp, r"\bbool\s+wake_by_cancel\s*;", "Task lacks cancellation dequeue latch")
        require_pattern(
            self.sched_cpp,
            r"boot_task->wait_cancellable\s*=\s*false\s*;\s*boot_task->wake_by_cancel\s*=\s*false\s*;",
            "boot task does not initialize cancellation wait state",
        )
        require_pattern(
            self.sched_cpp,
            r"t->wait_cancellable\s*=\s*false\s*;\s*t->wake_by_cancel\s*=\s*false\s*;",
            "created tasks do not initialize cancellation wait state",
        )

    def test_kill_detach_latches_cancel_and_revokes_detach_capability(self) -> None:
        signal = function_body(self.sched_cpp, r"KillResult\s+SignalTaskLocked")
        branch = require_pattern(
            signal,
            r"if\s*\(target->wait_cancellable\)\s*\{(?P<body>.*?)return\s+KillResult::Signaled\s*;",
            "SignalTaskLocked lacks cancellable detach branch",
        ).group("body")
        order = [
            branch.index("WaitQueueDetachTaskLocked"),
            branch.index("target->wake_by_cancel = true"),
            branch.index("target->wait_cancellable = false"),
            branch.index("RunqueuePush"),
        ]
        self.assertEqual(order, sorted(order), "kill detach does not latch and revoke before runnable publication")
        reject_pattern(branch, r"\bSchedExit\s*\(|\bFinalizeCurrentCancellation\s*\(", "wait kill finalizes inline")

    def test_other_dequeue_authorities_clear_the_cancel_latch(self) -> None:
        wake = function_body(self.sched_cpp, r"Task\*\s+WaitQueueWakeOneLocked")
        require_pattern(wake, r"t->wake_by_cancel\s*=\s*false\s*;", "explicit wake leaves stale cancel latch")
        timer = require_pattern(
            self.sched_cpp,
            r"woken->waiting_on\s*=\s*nullptr\s*;(?P<body>.{0,180})woken->wake_by_timeout\s*=\s*true\s*;",
            "timer dequeue block not found",
        ).group("body")
        require_pattern(timer, r"woken->wake_by_cancel\s*=\s*false\s*;", "timeout leaves stale cancel latch")

    def test_resume_classification_uses_latched_authority_not_sticky_intent(self) -> None:
        body = function_body(self.sched_cpp, r"WaitQueueBlockResult\s+ClassifyCancellableWaitResume")
        require_pattern(body, r"SpinLockAcquire\s*\(g_sched_lock\)", "resume classifier is outside scheduler lock")
        require_pattern(body, r"cancelled\s*=\s*self->wake_by_cancel", "classifier ignores cancellation latch")
        reject_pattern(body, r"\bKillPending\s*\(", "post-wake sticky kill incorrectly overrides dequeue authority")
        require_pattern(body, r"self->wait_cancellable\s*=\s*false\s*;", "classifier leaves detach capability set")
        require_pattern(body, r"self->wake_by_cancel\s*=\s*false\s*;", "classifier leaves cancel latch set")

    def test_generic_waits_serialize_cancel_check_marker_and_enqueue(self) -> None:
        signatures = (
            r"WaitQueueBlockResult\s+WaitQueueBlockCancellable",
            r"WaitQueueBlockResult\s+WaitQueueBlockTimeoutCancellable",
            r"WaitQueueBlockResult\s+WaitQueueBlockIfSequenceUnchangedCancellable",
        )
        for signature in signatures:
            with self.subTest(api=signature):
                body = function_body(self.sched_cpp, signature)
                lock = body.index("SpinLockAcquire(g_sched_lock)")
                kill = body.index("KillPending(self)")
                marker = body.index("self->wait_cancellable = true")
                enqueue = body.index("WaitQueueBlockCurrent")
                handoff = body.index("ScheduleLockedHandoff")
                self.assertEqual([lock, kill, marker, enqueue, handoff], sorted([lock, kill, marker, enqueue, handoff]))

    def test_sequence_bridge_orders_cancel_load_and_no_block_result(self) -> None:
        body = function_body(
            self.sched_cpp,
            r"WaitQueueBlockResult\s+WaitQueueBlockIfSequenceUnchangedCancellable",
        )
        lock = body.index("SpinLockAcquire(g_sched_lock)")
        kill = body.index("KillPending(self)")
        load = body.index("__atomic_load_n")
        marker = body.index("self->wait_cancellable = true")
        self.assertEqual([lock, kill, load, marker], sorted([lock, kill, load, marker]))
        changed = require_pattern(
            body,
            r"if\s*\(__atomic_load_n.*?\)\s*\{(?P<body>.*?)\}",
            "sequence-changed branch missing",
        ).group("body")
        require_pattern(changed, r"return\s+WaitQueueBlockResult::SequenceChanged", "wrong no-block result")
        reject_pattern(changed, r"WaitQueueBlockCurrent", "sequence-changed path still enqueues")

    def test_condvar_cancel_check_precedes_drop_and_cancel_restores_lockdep(self) -> None:
        body = function_body(self.sched_cpp, r"WaitQueueBlockResult\s+CondvarWaitCancellableImpl")
        require_pattern(
            body,
            r"KASSERT\s*\(self\s*!=\s*nullptr\s*&&\s*m->owner\s*==\s*self",
            "invalid companion ownership can return without the documented held mutex",
        )
        reject_pattern(
            body,
            r"DebugPanicOrWarn.*?return\s+WaitQueueBlockResult::TimedOut",
            "invalid companion ownership is reported as a normal timeout",
        )
        pop = body.index("LockdepBeforeRelease")
        lock = body.index("SpinLockAcquire(g_sched_lock)")
        kill = body.index("KillPending(self)")
        drop = body.index("MutexOwnerDropLocked")
        marker = body.index("self->wait_cancellable = true")
        enqueue = body.index("WaitQueueBlockCurrent")
        self.assertEqual([pop, lock, kill, drop, marker, enqueue], sorted([pop, lock, kill, drop, marker, enqueue]))

        cancel_arm = require_pattern(
            body,
            r"if\s*\(KillPending\(self\)\)\s*\{(?P<body>.*?)return\s+WaitQueueBlockResult::Cancelled\s*;",
            "condvar lacks serialized early-cancel arm",
        ).group("body")
        require_pattern(cancel_arm, r"SpinLockRelease\s*\(g_sched_lock", "early cancel retains scheduler lock")
        require_pattern(cancel_arm, r"LockdepAfterAcquire\s*\(m->class_id\)", "early cancel leaves mutex popped")
        reject_pattern(cancel_arm, r"MutexOwnerDropLocked|WaitQueueWakeOneLocked", "early cancel drops companion mutex")

    def test_condvar_reacquires_plain_mutex_before_every_blocked_return(self) -> None:
        body = function_body(self.sched_cpp, r"WaitQueueBlockResult\s+CondvarWaitCancellableImpl")
        handoff = body.index("ScheduleLockedHandoff")
        classify = body.index("ClassifyCancellableWaitResume", handoff)
        sti = body.index("arch::Sti()", classify)
        reacquire = body.index("MutexLock(m)", sti)
        returned = body.index("return wait_result", reacquire)
        self.assertEqual([handoff, classify, sti, reacquire, returned], sorted([handoff, classify, sti, reacquire, returned]))
        reject_pattern(body[handoff:], r"MutexLock(?:Timed)?Cancellable\s*\(", "condvar reacquire can return unowned")

    def test_new_primitives_never_finalize_and_diagnostics_are_truthful(self) -> None:
        signatures = (
            r"WaitQueueBlockResult\s+WaitQueueBlockCancellable",
            r"WaitQueueBlockResult\s+WaitQueueBlockTimeoutCancellable",
            r"WaitQueueBlockResult\s+WaitQueueBlockIfSequenceUnchangedCancellable",
            r"WaitQueueBlockResult\s+CondvarWaitCancellableImpl",
        )
        for signature in signatures:
            with self.subTest(api=signature):
                body = function_body(self.sched_cpp, signature)
                reject_pattern(
                    body,
                    r"\bSchedExit\s*\(|\bFinalizeCurrentCancellation\s*\(|\bMaybeFinalizeCurrentCancellation\s*\(",
                    "cancellable primitive finalizes before caller unwind",
                )
        reject_pattern(
            self.sched_cpp,
            r"found blocked tasks without an owning wait/suspend queue",
            "deferred cancellation diagnostic still mislabels ordinary waits as malformed",
        )
        require_pattern(
            self.sched_cpp,
            r"deferred cancellation for non-cancellable or unowned waits",
            "deferred cancellation diagnostic is missing",
        )

    def test_every_relative_scheduler_wait_uses_the_signed_half_range_builder(self) -> None:
        helper = function_body(self.sched_cpp, r"u64\s+RelativeDeadlineFromNow")
        require_pattern(
            helper,
            r"\bClampRelativeWaitTicks\s*\(",
            "relative deadline builder does not enforce the signed modular horizon",
        )
        require_pattern(
            self.sched_cpp,
            r"constexpr\s+u64\s+kMaxRelativeWaitTicks\s*=\s*\(~u64\s*\{\s*0\s*\}\)\s*>>\s*1",
            "relative waits do not share an INT64_MAX horizon",
        )

        signatures = (
            r"void\s+SchedSleepTicks",
            r"bool\s+WaitQueueBlockTimeout",
            r"WaitQueueBlockResult\s+WaitQueueBlockTimeoutCancellable",
            r"bool\s+MutexLockTimed",
            r"MutexAcquireResult\s+MutexLockTimedCancellable",
            r"bool\s+CondvarWaitTimeout",
            r"WaitQueueBlockResult\s+CondvarWaitCancellableImpl",
        )
        for signature in signatures:
            with self.subTest(api=signature):
                body = function_body(self.sched_cpp, signature)
                require_pattern(
                    body,
                    r"\bRelativeDeadlineFromNow\s*\(",
                    f"{signature} bypasses the shared half-range deadline builder",
                )

    def test_mutex_owner_contract_rejects_bootstrap_null_and_invalid_unlock(self) -> None:
        install = function_body(self.sched_cpp, r"void\s+MutexOwnerInstallLocked")
        owner_assert = require_pattern(
            install,
            r"KASSERT\s*\(\s*owner\s*!=\s*nullptr",
            "mutex owner installation still permits a synthetic null owner",
        )
        owner_write = require_pattern(install, r"\bmutex->owner\s*=\s*owner\s*;", "mutex owner is never installed")
        self.assertLess(owner_assert.start(), owner_write.start())

        lock = function_body(self.sched_cpp, r"void\s+MutexLock")
        lock_current = require_pattern(
            lock,
            r"KASSERT\s*\(\s*CurrentTask\s*\(\s*\)\s*!=\s*nullptr",
            "MutexLock can still publish a pre-scheduler null owner",
        )
        lockdep = require_pattern(lock, r"\bLockdepBeforeAcquire\s*\(", "MutexLock lost lockdep acquisition")
        self.assertLess(lock_current.start(), lockdep.start(), "MutexLock mutates lockdep before validating task context")

        try_lock = function_body(self.sched_cpp, r"bool\s+MutexTryLock")
        try_reject = require_pattern(
            try_lock,
            r"Task\s*\*\s*caller\s*=\s*CurrentTask\s*\(\s*\)\s*;\s*"
            r"if\s*\(\s*caller\s*==\s*nullptr[^)]*\)\s*\{\s*return\s+false\s*;",
            "MutexTryLock does not consistently reject a missing/dead current task",
        )
        try_guard = require_pattern(try_lock, r"SpinLockGuard\s+guard", "MutexTryLock lost scheduler serialization")
        self.assertLess(try_reject.start(), try_guard.start())

        timed = function_body(self.sched_cpp, r"bool\s+MutexLockTimed")
        timed_reject = require_pattern(
            timed,
            r"if\s*\(\s*CurrentTask\s*\(\s*\)\s*==\s*nullptr\s*\)\s*\{\s*return\s+false\s*;",
            "MutexLockTimed can still publish a pre-scheduler null owner",
        )
        timed_lockdep = require_pattern(timed, r"\bLockdepBeforeAcquire\s*\(", "timed mutex lost lockdep acquisition")
        self.assertLess(timed_reject.start(), timed_lockdep.start())

        unlock = function_body(self.sched_cpp, r"void\s+MutexUnlock")
        guard = require_pattern(unlock, r"SpinLockGuard\s+guard", "MutexUnlock owner test is not serialized")
        validate = require_pattern(unlock, r"if\s*\(\s*m->owner\s*!=\s*self\s*\)", "MutexUnlock lost owner validation")
        release_lockdep = require_pattern(unlock, r"\bLockdepBeforeRelease\s*\(", "MutexUnlock lost lockdep release")
        drop = require_pattern(unlock, r"\bMutexOwnerDropLocked\s*\(", "MutexUnlock lost owner release")
        positions = [guard.start(), validate.start(), release_lockdep.start(), drop.start()]
        self.assertEqual(
            positions,
            sorted(positions),
            "MutexUnlock changes lockdep or ownership before validating the caller",
        )
        reject_pattern(unlock, r"Task\s*\*\s*bad_owner\b", "MutexUnlock leaks an unpinned owner Task pointer")
        require_pattern(
            unlock,
            r"bad_owner_tid\s*=\s*m->owner\s*!=\s*nullptr\s*\?\s*m->owner->id\s*:\s*~u64\s*\{\s*0\s*\}",
            "MutexUnlock does not snapshot immutable owner identity with a non-TID sentinel under the lifetime lock",
        )


if __name__ == "__main__":
    unittest.main()
