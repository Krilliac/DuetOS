#!/usr/bin/env python3
"""Contract: no logging or probing happens while the fix-journal lock is held.

WHY
    kernel/diag/fix_journal.cpp states its own rule at the top of the file:
    g_lock is "held only over the linear-scan + memcpy inside intern; never
    across logs or allocations. No probe / klog calls happen with the lock
    held."

    FixJournalInit broke it: the guard covered a KLOG_INFO_V. That gives
    g_lock -> serial-lock ordering, the inverse of every other path — a klog
    writer already holds the serial lock and can reach FixJournalRecord,
    which wants g_lock.

    Once SMP actually started working (2026-08-03) that became a live ABBA
    deadlock. A CPU holding g_lock while blocked on the serial lock never
    released it, so FixJournalEmitBootSummary spun forever trying to acquire
    g_lock: smoke profiles finished their sleep (`[smoke] tick=0x64/0x64`),
    emitted none of the boot summaries, and hung until the harness timeout
    while the rest of the kernel kept ticking. It looked like a flaky
    `qemu_timeout` on a rotating set of profiles, because which CPU lost the
    race varied per run.

    A lock-ordering rule that lives only in a comment gets broken. This
    checks it.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "kernel/diag/fix_journal.cpp"
SRC = PATH.read_text(encoding="utf-8")
LINES = SRC.splitlines()

LOGGING = re.compile(r"KLOG_|SerialWrite|KBP_PROBE|ProbeFire|core::Log\b")
GUARD = "SpinLockGuard guard(g_lock)"


def guarded_scopes() -> list[tuple[int, list[tuple[int, str]]]]:
    """(guard_line, [(line_no, text)]) of logging calls inside each g_lock scope."""
    out = []
    for i, line in enumerate(LINES):
        if GUARD not in line:
            continue
        indent = len(line) - len(line.lstrip())
        hits = []
        for j in range(i + 1, min(i + 160, len(LINES))):
            cur = LINES[j]
            stripped = cur.strip()
            if stripped.startswith("}") and (len(cur) - len(cur.lstrip())) < indent:
                break
            if LOGGING.search(cur):
                hits.append((j + 1, stripped[:90]))
        out.append((i + 1, hits))
    return out


class LockIsNeverHeldAcrossLogging(unittest.TestCase):
    def test_the_file_still_declares_the_rule(self) -> None:
        self.assertIn("No probe / klog calls happen with the lock held", SRC,
                      "the documented contract must stay; this test enforces it")

    def test_every_g_lock_scope_is_free_of_logging(self) -> None:
        offenders = [(g, h) for g, h in guarded_scopes() if h]
        detail = "\n".join(
            f"  g_lock taken at line {g} holds it across:\n"
            + "\n".join(f"    line {ln}: {txt}" for ln, txt in hits)
            for g, hits in offenders
        )
        self.assertEqual(
            offenders, [],
            "logging under g_lock inverts the lock order against the serial "
            "lock and deadlocks under SMP:\n" + detail,
        )

    def test_there_are_g_lock_scopes_to_check(self) -> None:
        # Guards against the check silently passing because the parser
        # stopped finding any scopes at all.
        self.assertGreaterEqual(len(guarded_scopes()), 4,
                                "expected several g_lock scopes; parser may have broken")

    def test_init_publishes_the_ring_before_logging(self) -> None:
        body = SRC[SRC.index("void FixJournalInit()"):]
        body = body[: body.index("\n}") + 2]
        i_close = body.index("}")          # end of the scoped guard block
        i_log = body.index("KLOG_INFO_V")
        self.assertLess(i_close, i_log,
                        "the guard must close before FixJournalInit logs")


class PanicPathStaysLockFree(unittest.TestCase):
    """The crash-time snapshot deliberately takes no lock; keep it that way."""

    def test_panic_safe_snapshot_does_not_acquire(self) -> None:
        body = SRC[SRC.index("u64 FixJournalSnapshotPanicSafe("):]
        body = body[: body.index("\n}") + 2]
        self.assertNotIn(GUARD, body,
                         "a crash that trapped while holding g_lock would deadlock here")


if __name__ == "__main__":
    unittest.main(verbosity=2)
