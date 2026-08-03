#!/usr/bin/env python3
"""Hostile contract for Linux notification, AIO, and pidfd wait cancellation.

These checks pin the predicate-publication ordering that prevents a producer,
close, timeout, cancellation, or pooled-slot reuse from stranding a waiter.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


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


def body(source: str, signature: str) -> str:
    match = re.search(signature + r"\s*\([^;{}]*\)\s*(?:const\s*)?\{", source)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = source.find("{", match.start())
    return braced_body(source, opening)


def type_body(source: str, declaration: str) -> str:
    match = re.search(declaration + r"[^;{]*\{", source)
    if match is None:
        raise AssertionError(f"missing type: {declaration}")
    opening = source.find("{", match.start())
    return braced_body(source, opening)


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    positions: list[int] = []
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        test.assertGreaterEqual(position, 0, f"missing ordered token: {token}")
        positions.append(position)
        cursor = position + len(token)
    test.assertEqual(positions, sorted(positions))


class StableSequenceModel:
    """Small adversarial model of the C++ generation/sequence protocol."""

    MAX = (1 << 64) - 1

    def __init__(self) -> None:
        self.sequence = 0
        self.generation = 0

    def publish(self) -> None:
        if self.sequence != self.MAX:
            self.sequence += 1

    def allocate(self) -> bool:
        if self.generation == self.MAX:
            return False
        self.generation += 1
        self.publish()
        return True

    def wait_decision(self, observed: int, cancelled: bool = False, timed_out: bool = False) -> str:
        if cancelled:
            return "eintr"
        if self.sequence != observed:
            return "rescan"
        if observed == self.MAX:
            return "one-tick-rescan"
        return "timeout" if timed_out else "block"


class HostileInterleavingModelTests(unittest.TestCase):
    def test_publish_between_predicate_scan_and_enqueue_forces_rescan(self) -> None:
        model = StableSequenceModel()
        self.assertTrue(model.allocate())
        observed = model.sequence
        model.publish()
        self.assertEqual(model.wait_decision(observed), "rescan")

    def test_close_and_reuse_cannot_aba_an_old_incarnation(self) -> None:
        model = StableSequenceModel()
        self.assertTrue(model.allocate())
        old_generation = model.generation
        old_sequence = model.sequence
        model.publish()  # close publication
        self.assertTrue(model.allocate())  # reuse publication
        self.assertNotEqual(model.generation, old_generation)
        self.assertEqual(model.wait_decision(old_sequence), "rescan")

    def test_timeout_is_not_reported_as_cancellation(self) -> None:
        model = StableSequenceModel()
        self.assertTrue(model.allocate())
        observed = model.sequence
        self.assertEqual(model.wait_decision(observed, timed_out=True), "timeout")
        self.assertEqual(model.wait_decision(observed, cancelled=True), "eintr")

    def test_saturation_never_wraps_and_uses_bounded_rescan(self) -> None:
        model = StableSequenceModel()
        model.sequence = model.MAX
        model.publish()
        self.assertEqual(model.sequence, model.MAX)
        self.assertEqual(model.wait_decision(model.MAX), "one-tick-rescan")
        model.generation = model.MAX
        self.assertFalse(model.allocate())


class LinuxNotifyAioWaitCancellationProductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inotify = read("kernel/subsystems/linux/inotify.cpp")
        cls.fanotify = read("kernel/subsystems/linux/fanotify.cpp")
        cls.async_cpp = read("kernel/subsystems/linux/syscall_async_io.cpp")
        cls.async_h = read("kernel/subsystems/linux/syscall_async_io.h")
        cls.pidfd = read("kernel/subsystems/linux/pidfd_splice.cpp")
        cls.process = read("kernel/proc/process.cpp")
        cls.process_h = read("kernel/proc/process.h")
        cls.io = read("kernel/subsystems/linux/syscall_io.cpp")

    def test_notification_rows_keep_persistent_nonwrapping_identity(self) -> None:
        for source, row, allocator, instance in (
            (self.inotify, r"struct\s+InotifyInstance", r"i32\s+InotifyAlloc", "inst"),
            (self.fanotify, r"struct\s+FanInstance", r"i32\s+FanAlloc", "inst"),
        ):
            with self.subTest(row=row):
                fields = type_body(source, row)
                self.assertIn("u64 generation", fields)
                self.assertIn("u64 read_sequence", fields)
                self.assertIn("sched::WaitQueue read_wq", fields)
                allocate = body(source, allocator)
                self.assertRegex(allocate, r"g_\w+_pool\[i\]\.generation\s*!=\s*~u64\{0\}")
                ordered(
                    self,
                    allocate,
                    f"++{instance}.generation",
                    f"AdvanceReadSequenceLocked({instance})",
                    f"{instance}.in_use = true",
                )
                self.assertNotRegex(allocate, r"read_sequence\s*=|read_wq\.(?:head|tail)\s*=")

    def test_notification_pins_match_exact_generation(self) -> None:
        for source, pin in (
            (self.inotify, r"struct\s+InotifyPin"),
            (self.fanotify, r"struct\s+FanPin"),
        ):
            with self.subTest(pin=pin):
                pin_code = type_body(source, pin)
                self.assertIn("u64 generation", pin_code)
                self.assertIn("expected_generation == 0", pin_code)
                self.assertIn("inst.generation == expected_generation", pin_code)
                self.assertIn("inst.pins != ~0U", pin_code)

    def test_notification_publish_and_close_advance_before_wake(self) -> None:
        for source, push, publish, release in (
            (self.inotify, r"void\s+RingPushLocked", r"void\s+InotifyPublish", r"void\s+InotifyRelease"),
            (
                self.fanotify,
                r"void\s+FanotifyPublishFromInotify",
                r"void\s+FanotifyPublishFromInotify",
                r"void\s+FanotifyRelease",
            ),
        ):
            with self.subTest(release=release):
                push_code = body(source, push)
                self.assertIn("AdvanceReadSequenceLocked(inst)", push_code)
                publish_code = body(source, publish)
                ordered(self, publish_code, "SpinLockRelease", "WakeReadWaiters")
                release_code = body(source, release)
                ordered(
                    self,
                    release_code,
                    "AdvanceReadSequenceLocked(inst)",
                    "SpinLockRelease",
                    "WakeReadWaiters(inst)",
                    "LinuxPollEventWake()",
                )

    def test_notification_reads_are_nonblocking_and_cancellable(self) -> None:
        for source, signature in (
            (self.inotify, r"i64\s+InotifyRead"),
            (self.fanotify, r"i64\s+FanotifyRead"),
        ):
            with self.subTest(signature=signature):
                read_code = body(source, signature)
                self.assertIn("expected_generation", read_code)
                self.assertIn("nonblocking", read_code)
                self.assertIn("return kEAGAIN", read_code)
                self.assertIn("WaitForReadSequence", read_code)
                self.assertIn("WaitQueueBlockResult::Cancelled", read_code)
                self.assertIn("return kEINTR", read_code)
                self.assertNotIn("WaitQueueBlock(&", read_code)

    def test_timerfd_waits_on_exact_deadline_without_holding_a_pin(self) -> None:
        timer = type_body(self.async_cpp, r"struct\s+Timerfd")
        self.assertIn("u64 generation", timer)
        self.assertIn("u64 read_sequence", timer)
        allocate = body(self.async_cpp, r"i32\s+TimerfdAlloc")
        self.assertIn("generation != ~u64{0}", allocate)
        self.assertNotRegex(allocate, r"read_sequence\s*=|read_wq\.(?:head|tail)\s*=")

        read_code = body(self.async_cpp, r"i64\s+TimerfdRead")
        ordered(self, read_code, "observed_sequence", "TimerfdAccrueExpirationsLocked")
        self.assertIn("return kEAGAIN", read_code)
        ordered(self, read_code, "pin.Release()", "WaitForStableSequence")
        self.assertIn("WaitForStableSequenceTimeout", read_code)
        self.assertIn("return kEINTR", read_code)

        settime = body(self.async_cpp, r"i64\s+DoTimerfdSettime")
        ordered(
            self,
            settime,
            "AdvanceStableSequenceLocked(&t.read_sequence)",
            "SpinLockRelease(g_async_lock",
            "WakeQueuePreservingInterrupts(&t.read_wq)",
            "LinuxPollEventWake()",
        )

    def test_signalfd_uses_process_event_identity_not_bitmap_aba(self) -> None:
        fields = type_body(self.process_h, r"struct\s+Process\b")
        self.assertIn("u64 linux_signal_event_sequence", fields)
        read_code = body(self.async_cpp, r"i64\s+SignalfdRead")
        ordered(
            self,
            read_code,
            "ProcessLinuxSignalEventSequenceSnapshot(p)",
            "ProcessLinuxSignalClaimPending(p, sig)",
        )
        ordered(self, read_code, "pin.Release()", "ProcessWaitForLinuxSignalEvent")
        self.assertIn("return kEAGAIN", read_code)
        self.assertIn("return kEINTR", read_code)
        self.assertNotIn("p->linux_pending_signals", read_code)

        for signature in (r"bool\s+ProcessLinuxSignalRaisePending", r"void\s+ProcessLinuxSignalRestorePending"):
            with self.subTest(signature=signature):
                producer = body(self.process, signature)
                ordered(
                    self,
                    producer,
                    "__atomic_fetch_or",
                    "AdvanceStableEventSequenceAtomic",
                    "WakeLinuxSignalReaders",
                )
        claim = body(self.process, r"bool\s+ProcessLinuxSignalClaimPending")
        self.assertNotIn("linux_signal_event_sequence", claim)

    def test_sequence_saturation_is_the_only_one_tick_poll_fallback(self) -> None:
        helpers = (
            body(self.inotify, r"WaitQueueBlockResult\s+WaitForReadSequence"),
            body(self.fanotify, r"WaitQueueBlockResult\s+WaitForReadSequence"),
            body(self.async_cpp, r"WaitQueueBlockResult\s+WaitForStableSequence"),
            body(self.async_cpp, r"WaitQueueBlockResult\s+WaitForStableSequenceTimeout"),
            body(self.process, r"WaitQueueBlockResult\s+ProcessWaitForLinuxSignalEvent"),
        )
        for helper in helpers:
            with self.subTest(helper=helper[:60]):
                self.assertIn("observed_sequence == ~u64{0}", helper)
                self.assertRegex(helper, r"WaitQueueBlockTimeoutCancellable\([^;]*\b1\b")
                self.assertIn("IfSequenceUnchanged", helper)

    def test_epoll_drops_pool_pin_and_uses_global_cancellable_sequence(self) -> None:
        wait = body(self.async_cpp, r"i64\s+DoEpollWait")
        ordered(
            self,
            wait,
            "LinuxPollEventSequenceSnapshot()",
            "EpollPin pin(idx, expected_generation)",
            "pin.Release()",
            "LinuxFdEpollReady",
            "WaitForStableSequenceTimeout",
        )
        self.assertIn("e.generation != expected_generation", wait)
        self.assertIn("step = remaining < 10 ? remaining : 10", wait)
        self.assertIn("WaitQueueBlockResult::Cancelled", wait)
        self.assertIn("return kEINTR", wait)
        self.assertNotIn("SchedSleepTicks", wait)
        self.assertNotRegex(wait, r"WaitQueueBlockTimeout\s*\(")

        ctl = body(self.async_cpp, r"i64\s+DoEpollCtl")
        ordered(self, ctl, "SpinLockGuard guard(g_async_lock)", "LinuxPollEventWake()")
        close = body(self.async_cpp, r"void\s+EpollRelease")
        ordered(self, close, "e.closing = true", "LinuxPollEventWake()")

    def test_pidfd_hub_release_publishes_without_wrap_before_wake(self) -> None:
        hub = body(self.pidfd, r"void\s+LinuxPollEventWake")
        ordered(
            self,
            hub,
            "SpinLockAcquire(g_linux_poll_event_lock)",
            "previous != ~u64{0}",
            "__ATOMIC_RELEASE",
            "SpinLockRelease(g_linux_poll_event_lock",
            "WaitQueueWakeAll(&g_pidfd_exit_wq)",
        )
        exit_wake = body(self.pidfd, r"void\s+LinuxPidfdExitWake")
        self.assertIn("LinuxPollEventWake()", exit_wake)

    def test_ofd_nonblock_snapshot_ends_before_any_read_can_park(self) -> None:
        helper = body(self.io, r"bool\s+SnapshotAcquiredNonblocking")
        ordered(
            self,
            helper,
            "LinuxFdIoGuardEnter",
            "LinuxFdIoGuardGetStatusFlags",
            "LinuxFdIoGuardExit",
            "kONonblock",
        )
        dispatch = body(self.io, r"i64\s+DoRead")
        for read_name in ("TimerfdRead", "SignalfdRead", "InotifyRead", "FanotifyRead"):
            with self.subTest(read_name=read_name):
                call = dispatch.index(f"{read_name}(")
                snapshot = dispatch.rfind("SnapshotAcquiredNonblocking", 0, call)
                self.assertGreaterEqual(snapshot, 0)
                self.assertIn("nonblocking", dispatch[call : dispatch.find(";", call)])

        inotify_init = body(self.inotify, r"i64\s+InotifyInit1")
        self.assertIn("flags & kIN_NONBLOCK", inotify_init)
        fanotify_init = body(self.fanotify, r"i64\s+DoFanotifyInit")
        self.assertIn("kFAN_NONBLOCK", fanotify_init)
        self.assertIn("(flags & kFAN_NONBLOCK) != 0 ? kONonblock : 0", fanotify_init)
        self.assertNotIn("event_f_flags &", fanotify_init)


if __name__ == "__main__":
    unittest.main(verbosity=2)
