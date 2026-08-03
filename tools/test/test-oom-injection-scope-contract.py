#!/usr/bin/env python3
"""Contract: test-only OOM injection is scoped to the task that armed it.

WHY
    `FrameAllocatorSetFailAfter(N)` arms a synthetic allocation failure so a
    self-test can exercise its unwind path. The counter is global and is
    consumed on the shared allocation path used by every CPU, so once SMP
    started working a peer CPU could absorb an injection meant for the test.

    On 2026-08-03 that is exactly what happened in `pe-threads (4 vCPU)`. The
    ELF unwind self-test armed a failure; a concurrent `AllocateKernelStack`
    swallowed it. The box panicked with

        [panic] sched: AllocateKernelStack failed for kernel stack

    while the self-test simultaneously reported

        [elf-test] FAIL ElfLoad returned ok despite OOM

    — the victim took the failure, the intended target did not. Both lines
    appear interleaved at the same instant in the serial log.

    A test harness that can inject faults into unrelated subsystems is worse
    than no harness: it manufactures failures that look like product bugs.

    This is the THIRD instance of the same class this session — a
    uniprocessor-era test mechanism that is unsafe under live SMP, after the
    ElfLoaderUnwindSelfTest global frame-count oracle and its global
    free-frame comparison.

    Pins the invariant: every consume site is gated on a predicate that
    checks the arming task, and arming records who armed it.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "kernel/mm/frame_allocator.cpp").read_text(encoding="utf-8")

PREDICATE = "OomInjectionAppliesHere"


class InjectionIsTaskScoped(unittest.TestCase):
    def test_predicate_exists_and_consults_the_arming_task(self) -> None:
        self.assertIn(PREDICATE, SRC)
        body = SRC[SRC.index(f"bool {PREDICATE}()"):]
        body = body[: body.index("\n}") + 2]
        self.assertIn("g_fail_after_task", body,
                      "the predicate must compare against the task that armed the injection")
        self.assertIn("CurrentTask()", body)

    def test_arming_records_the_owner(self) -> None:
        body = SRC[SRC.index("void FrameAllocatorSetFailAfter("):]
        body = body[: body.index("\n}") + 2]
        self.assertIn("g_fail_after_task", body)
        self.assertIn("CurrentTask()", body)
        self.assertRegex(body, r"nullptr",
                         "disarming must clear the owner, not leave a stale task pointer")

    def test_every_consume_site_is_gated(self) -> None:
        # A raw `if (g_fail_after != 0)` on an ALLOCATION path is the
        # un-scoped form that let a peer CPU absorb the injection.
        #
        # The injection self-test is excluded deliberately: its raw reads are
        # state assertions about the counter ("must be zero at entry", "must
        # have been consumed"), not consume sites, and gating those would
        # destroy the very thing it verifies.
        selftest = SRC.index("void FrameAllocatorOomInjectionSelfTest()")
        alloc_paths = SRC[:selftest]
        raw = re.findall(r"if\s*\(\s*g_fail_after\s*!=\s*0\s*\)", alloc_paths)
        self.assertEqual(raw, [],
                         "every consume site on an allocation path must go "
                         "through " + PREDICATE)

    def test_selftest_state_assertions_are_left_alone(self) -> None:
        # Guards the exclusion above: if the self-test's own checks ever get
        # "helpfully" gated, it stops proving the counter was consumed.
        selftest = SRC[SRC.index("void FrameAllocatorOomInjectionSelfTest()"):]
        self.assertIn("g_fail_after != 0", selftest)

    def test_all_three_allocation_paths_are_covered(self) -> None:
        # AllocateFrameNode, AllocateFrame and AllocateContiguousFrames each
        # consume the counter; the warm-pool fast path also consults it.
        self.assertGreaterEqual(
            SRC.count(PREDICATE + "()"), 4,
            "expected the predicate at each consume site plus the pool skip",
        )

    def test_pool_fast_path_uses_the_predicate_not_the_raw_counter(self) -> None:
        self.assertNotRegex(SRC, r"if\s*\(\s*g_fail_after\s*==\s*0\s*\)",
                            "the warm-pool skip must be scoped too, or unrelated "
                            "tasks lose the fast path whenever a test is armed")


class CounterAccessIsSafe(unittest.TestCase):
    def test_reads_are_atomic(self) -> None:
        body = SRC[SRC.index(f"bool {PREDICATE}()"):]
        body = body[: body.index("\n}") + 2]
        self.assertIn("__atomic_load_n", body,
                      "the counter is read from every CPU while one task writes it")


if __name__ == "__main__":
    unittest.main(verbosity=2)
