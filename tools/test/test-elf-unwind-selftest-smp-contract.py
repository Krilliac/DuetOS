#!/usr/bin/env python3
"""Contract: the ELF unwind self-test must not use a global oracle under SMP.

WHY
    `ElfLoaderUnwindSelfTest` samples `FreeFramesCount()` — a GLOBAL counter —
    before and after its test window and panics when the count drops. That is
    only sound on a quiescent uniprocessor. Once the APs are online they
    allocate continuously, so a peer CPU taking frames inside the window is
    indistinguishable from this test leaking.

    It fired on healthy 4-vCPU boots the moment SMP actually started working
    (2026-08-03, after the AP trampoline fix), panicking linux-4cpu and
    pe-winapi-4cpu with "frame leak detected" when nothing had leaked. The
    self-test ran at log line 2915, well after "SMP bring-up complete" (2592).

    Two properties this pins:
      1. The load-bearing check is PER-ADDRESS-SPACE (page_count on the AS
         under test), which no peer CPU can perturb. That is the actual
         unwind invariant the test exists to catch.
      2. The global free-frame check still hard-fails where its oracle is
         valid (uniprocessor) and only degrades to WARN+probe where it is
         not. Simply widening the tolerance would blind it in BOTH modes,
         so a bare tolerance bump must not pass this contract.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "kernel/loader/elf_loader.cpp").read_text(encoding="utf-8")


def selftest_body() -> str:
    start = SRC.index("void ElfLoaderUnwindSelfTest()")
    return SRC[start:]


class PerAddressSpaceOracle(unittest.TestCase):
    def test_unwind_is_asserted_against_the_address_space_under_test(self) -> None:
        body = selftest_body()
        self.assertIn(
            "AddressSpaceTrySnapshotUserRegionSummary",
            body,
            "the unwind invariant must be measured per-AS, not via a global frame count",
        )
        self.assertRegex(body, r"page_count\s*!=\s*0")

    def test_per_as_check_runs_before_the_address_space_is_released(self) -> None:
        body = selftest_body()
        i_snap = body.index("AddressSpaceTrySnapshotUserRegionSummary")
        i_rel = body.index("AddressSpaceRelease(as)")
        self.assertLess(i_snap, i_rel, "the AS must still exist when its page count is read")

    def test_leftover_pages_are_a_hard_failure(self) -> None:
        body = selftest_body()
        i = body.index("page_count")
        window = body[i : i + 500]
        self.assertIn("core::Panic", window, "leftover mapped pages must panic, not warn")


class GlobalOracleIsGatedNotWidened(unittest.TestCase):
    def test_global_check_is_gated_on_uniprocessor(self) -> None:
        self.assertIn("SmpCpusOnline", selftest_body(),
                      "the global free-frame check must know whether APs are online")

    def test_smp_path_warns_and_probes_instead_of_panicking(self) -> None:
        body = selftest_body()
        i = body.index("SmpCpusOnline")
        window = body[i : i + 700]
        self.assertIn("KLOG_WARN", window, "an invalid-oracle result must still be visible")
        self.assertIn("KBP_PROBE", window, "and must leave a probe for the debugger")
        self.assertNotIn("core::Panic", window,
                         "under SMP the global oracle is invalid, so it must not panic")

    def test_uniprocessor_still_panics_on_a_real_drop(self) -> None:
        # The hard failure must survive somewhere in the leak checker —
        # gating must not have quietly removed it.
        body = selftest_body()
        self.assertIn("frame leak detected", body,
                      "the uniprocessor path must still panic on a genuine drop")
        # ...and that panic must be reachable only after the SMP gate returns.
        i_gate = body.index("SmpCpusOnline")
        i_panic = body.index("frame leak detected")
        self.assertLess(i_gate, i_panic, "the SMP gate must precede the hard failure")

    def test_tolerance_was_not_merely_widened(self) -> None:
        # A bare `after + N >= before` slack bump is the tempting wrong fix:
        # it hides real leaks on uniprocessor too. Reject it.
        body = selftest_body()
        i = body.index("check_no_leak")
        window = body[i : i + 900]
        self.assertNotRegex(
            window,
            r"after\s*\+\s*\d+\s*>=|before\s*-\s*after\s*[<>]=?\s*\d{2,}",
            "do not widen the tolerance; gate the oracle where it is invalid instead",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
