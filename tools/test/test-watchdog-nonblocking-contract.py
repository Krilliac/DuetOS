#!/usr/bin/env python3
"""Contract: the heartbeat watchdog can never block on the filesystem.

WHY
    HungTaskTick() is called from inside the heartbeat beat
    (kernel/diag/heartbeat.cpp). So any filesystem I/O the heartbeat performs
    can silence the detector whose entire purpose is to report I/O hangs.

    On 2026-08-03 that happened. A FAT32 write wedged while holding the
    volume lock; the heartbeat then blocked acquiring it inside
    PersistBootSlotState and emitted its last beat at t=18231ms. The boot ran
    to t=473480ms — 455 seconds with no heartbeat — so the hung-task detector
    never ran again, a task hung for 459 s produced ZERO hung-task warnings,
    and the failure reached CI as an opaque `qemu_timeout` on a rotating set
    of smoke profiles.

    A watchdog the watched subsystem can block is not a watchdog.

    The same applies to KPathPersistFlush, which runs between the smoke
    profile's sleep and the "[smoke] profile=<name> complete" sentinel that
    authorises QEMU exit: a diagnostic TSV must never gate that sentinel.

    Pins the invariant, not the wording: both diagnostic writers acquire the
    volume lock with a bound and SKIP on failure rather than falling through
    into blocking Fat32 calls.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEARTBEAT = (ROOT / "kernel/diag/heartbeat.cpp").read_text(encoding="utf-8")
KPATH = (ROOT / "kernel/diag/kpath_persist.cpp").read_text(encoding="utf-8")
FAT32_H = (ROOT / "kernel/fs/fat32.h").read_text(encoding="utf-8")
FAT32_C = (ROOT / "kernel/fs/fat32.cpp").read_text(encoding="utf-8")

BLOCKING_FAT32 = re.compile(r"Fat32(CreateAtPath|DeleteAtPath|WriteInPlace|LookupPath)\s*\(")


def body(src: str, signature: str) -> str:
    start = src.index(signature)
    return src[start : src.index("\n}", start) + 2]


class BestEffortApiExists(unittest.TestCase):
    def test_bounded_acquire_is_declared(self) -> None:
        self.assertIn("Fat32BeginBestEffort", FAT32_H)
        self.assertIn("Fat32EndBestEffort", FAT32_H)

    def test_acquire_is_actually_bounded(self) -> None:
        impl = body(FAT32_C, "bool Fat32BeginBestEffort(")
        self.assertIn("MutexLockTimed", impl,
                      "an unbounded MutexLock here would defeat the whole point")
        self.assertNotRegex(impl, r"\bMutexLock\s*\(",
                            "must not fall back to a blocking acquire")

    def test_result_cannot_be_silently_ignored(self) -> None:
        self.assertIn("[[nodiscard]]", FAT32_H,
                      "ignoring the acquire result would fall through into blocking calls")

    def test_reentrant_call_is_refused(self) -> None:
        # Re-entering would make the paired End release a lock an outer
        # scope still owns.
        impl = body(FAT32_C, "bool Fat32BeginBestEffort(")
        self.assertIn("owner == me", impl)


class HeartbeatNeverBlocks(unittest.TestCase):
    def test_persist_takes_the_bounded_path(self) -> None:
        fn = body(HEARTBEAT, "bool PersistBootSlotState(")
        self.assertIn("Fat32BeginBestEffort", fn)
        self.assertIn("Fat32EndBestEffort", fn)

    def test_persist_returns_early_when_contended(self) -> None:
        fn = body(HEARTBEAT, "bool PersistBootSlotState(")
        i_try = fn.index("Fat32BeginBestEffort")
        window = fn[i_try : i_try + 400]
        self.assertIn("return false", window,
                      "on a failed acquire the writer must skip, not continue")

    def test_hung_task_tick_still_runs_from_the_beat(self) -> None:
        # If this moves, the rationale above changes and this contract
        # should be revisited rather than silently kept.
        self.assertIn("HungTaskTick()", HEARTBEAT)


class KpathFlushNeverBlocks(unittest.TestCase):
    def test_flush_takes_the_bounded_path(self) -> None:
        fn = body(KPATH, "void KPathPersistFlush()")
        self.assertIn("Fat32BeginBestEffort", fn)
        self.assertIn("Fat32EndBestEffort", fn)

    def test_flush_skips_rather_than_falling_through(self) -> None:
        fn = body(KPATH, "void KPathPersistFlush()")
        i_try = fn.index("Fat32BeginBestEffort")
        guard_window = fn[i_try : i_try + 300]
        self.assertIn("return", guard_window,
                      "a contended volume must skip the TSV, never block the sentinel")
        # The actual write must come after the guarded early-return.
        i_write = fn.index("WriteScratchToVolume")
        self.assertLess(i_try, i_write)


if __name__ == "__main__":
    unittest.main(verbosity=2)
