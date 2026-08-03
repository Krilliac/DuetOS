#!/usr/bin/env python3
"""Contract: the stress driver is armed only after SMP bring-up.

WHY
    StressDriverArm() SchedCreate()s its worker immediately. Arming it during
    early boot puts those workers on the runqueue while the BSP is still
    executing boot — including SmpStartAps(), the call that brings the other
    CPUs online. The workers then starve the very step that would have given
    them more CPUs.

    Measured 2026-08-03 on a real boot: `stress=cpu stress-workers=64` with
    `-smp 8` had still not reached "Bringing up APs" at t=437s. Eight LAPICs
    were enumerated; none were started. The entire run exercised ONE cpu.

    A stress driver that starves SMP bring-up can never stress SMP, which is
    the main thing worth stressing on an SMP kernel.

    Pins the ordering, not the line number.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAIN = (ROOT / "kernel/core/main.cpp").read_text(encoding="utf-8")
DRIVER = (ROOT / "kernel/diag/stress_driver.cpp").read_text(encoding="utf-8")

CALL = re.compile(r"^\s*duetos::core::diag::StressDriverArm\(", re.M)


def line_of(pattern: str) -> int:
    m = re.search(pattern, MAIN, re.M)
    assert m is not None, f"not found: {pattern}"
    return MAIN[: m.start()].count("\n") + 1


class ArmedAfterSmp(unittest.TestCase):
    def test_armed_exactly_once(self) -> None:
        self.assertEqual(len(CALL.findall(MAIN)), 1,
                         "two arm sites would spawn two stress workers")

    def test_arm_follows_smp_start(self) -> None:
        arm = line_of(r"^\s*duetos::core::diag::StressDriverArm\(")
        smp = line_of(r"^\s*SmpStartAps\(\);")
        self.assertGreater(arm, smp,
                           "arming before SmpStartAps lets stress workers starve AP "
                           "bring-up, so the run measures a single CPU")

    def test_arm_follows_topology_assignment(self) -> None:
        # Workers should land on per-CPU runqueues whose cluster ids are set.
        arm = line_of(r"^\s*duetos::core::diag::StressDriverArm\(")
        topo = line_of(r"^\s*duetos::cpu::TopologyAssignClusters\(\);")
        self.assertGreater(arm, topo)


class TheHazardStillExists(unittest.TestCase):
    """If arming stops spawning immediately the rationale changes, and this
    contract should be revisited rather than silently kept."""

    def test_arm_spawns_a_task_immediately(self) -> None:
        body = DRIVER[DRIVER.index("void StressDriverArm("):]
        body = body[: body.index("\n}") + 2]
        self.assertIn("SchedCreate", body,
                      "arming is what puts stress workers on the runqueue")


if __name__ == "__main__":
    unittest.main(verbosity=2)
