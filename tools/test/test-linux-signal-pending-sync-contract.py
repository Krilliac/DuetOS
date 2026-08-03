#!/usr/bin/env python3
"""Hostile structural contract for Linux process-pending signal ownership."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    match = re.search(signature, source)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"missing body: {signature}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : index + 1]
    raise AssertionError(f"unterminated body: {signature}")


class LinuxSignalPendingSyncContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = read("kernel/proc/process.h")
        cls.process_cpp = read("kernel/proc/process.cpp")
        cls.signal_cpp = read("kernel/subsystems/linux/syscall_sig.cpp")
        cls.deliver_cpp = read("kernel/subsystems/linux/signal_deliver.cpp")
        cls.timer_cpp = read("kernel/subsystems/linux/syscall_timer.cpp")
        cls.async_cpp = read("kernel/subsystems/linux/syscall_async_io.cpp")

    def test_sigset_encoding_covers_one_through_sixty_four_without_wide_shift(self) -> None:
        bit = function_body(self.process_h, r"constexpr\s+u64\s+ProcessLinuxSignalBit")
        self.assertIn("signum >= 1 && signum <= 64", bit)
        self.assertIn("signum - 1U", bit)
        self.assertNotRegex(bit, r"1ULL\s*<<\s*signum\b")
        self.assertIn("ProcessLinuxSignalBit(kSIGKILL)", self.signal_cpp)
        self.assertIn("ProcessLinuxSignalBit(kSIGSTOP)", self.signal_cpp)

    def test_process_helpers_are_atomic_and_wake_after_publication(self) -> None:
        snapshot = function_body(self.process_cpp, r"u64\s+ProcessLinuxSignalPendingSnapshot")
        raise_pending = function_body(self.process_cpp, r"bool\s+ProcessLinuxSignalRaisePending")
        claim = function_body(self.process_cpp, r"bool\s+ProcessLinuxSignalClaimPending")
        restore = function_body(self.process_cpp, r"void\s+ProcessLinuxSignalRestorePending")
        self.assertIn("__atomic_load_n", snapshot)
        self.assertIn("__ATOMIC_ACQUIRE", snapshot)
        self.assertIn("__atomic_fetch_or", raise_pending)
        self.assertLess(raise_pending.index("__atomic_fetch_or"), raise_pending.index("WakeLinuxSignalReaders"))
        self.assertIn("__atomic_compare_exchange_n", claim)
        self.assertIn("__ATOMIC_ACQ_REL", claim)
        self.assertIn("__atomic_fetch_or", restore)
        self.assertLess(restore.index("__atomic_fetch_or"), restore.index("WakeLinuxSignalReaders"))

    def test_external_and_timer_producers_use_one_publication_path(self) -> None:
        deliver = function_body(self.signal_cpp, r"i64\s+LinuxSignalDeliver")
        self.assertIn("ProcessLinuxSignalRaisePending(target, signum)", deliver)
        self.assertNotIn("linux_pending_signals", deliver)
        alarm = function_body(self.timer_cpp, r"void\s+LinuxAlarmCheckAndRaise")
        self.assertGreaterEqual(alarm.count("ProcessLinuxSignalRaisePending"), 2)
        self.assertNotIn("linux_pending_signals", alarm)

    def test_handler_delivery_claims_and_failure_republishes_exact_bit(self) -> None:
        pick = function_body(self.deliver_cpp, r"u32\s+PickEligible")
        dispatch = function_body(self.deliver_cpp, r"bool\s+LinuxSignalCheckAndDeliver")
        self.assertIn("ProcessLinuxSignalPendingSnapshot", pick)
        self.assertIn("ProcessLinuxSignalBit(sig)", pick)
        self.assertIn("ProcessLinuxSignalClaimPending(p, sig)", dispatch)
        self.assertGreaterEqual(dispatch.count("ProcessLinuxSignalRestorePending"), 3)
        self.assertNotIn("linux_pending_signals", dispatch)

    def test_signalfd_is_exact_claimant_and_copy_failure_is_non_consuming(self) -> None:
        read_body = function_body(self.async_cpp, r"i64\s+SignalfdRead")
        self.assertIn("ProcessLinuxSignalClaimPending(p, sig)", read_body)
        self.assertIn("claimed_mask |= bit", read_body)
        self.assertIn("ProcessLinuxSignalRestorePending(p, claimed_mask)", read_body)
        self.assertLess(read_body.index("CopyToUser"), read_body.index("ProcessLinuxSignalRestorePending"))
        self.assertNotIn("p->linux_pending_signals", read_body)

    def test_epoll_readiness_is_an_atomic_snapshot_not_async_lock_ownership(self) -> None:
        ready = function_body(self.async_cpp, r"u32\s+LinuxFdEpollReady")
        self.assertIn("ProcessLinuxSignalPendingSnapshot(signal_owner)", ready)
        self.assertNotIn("signal_owner->linux_pending_signals", ready)


if __name__ == "__main__":
    unittest.main(verbosity=2)
