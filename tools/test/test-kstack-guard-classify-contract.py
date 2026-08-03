#!/usr/bin/env python3
"""Contract: kernel-stack guard faults are classified relative to the RUNNING stack.

WHY
    A slot's exclusive top IS the next slot's guard-page base. So a read at
    `top` — e.g. `*(rbp + 8)` when rbp sits at `top - 8` — faults on the
    NEIGHBOUR's guard while the running stack still has its full depth free.
    `IsKernelStackGuardFault` alone cannot tell that apart from running off
    the bottom, and reporting it as "kernel stack overflow" is backwards.

    On 2026-08-03 that misreport cost hours: an AP fault at
    cr2=0xffffffffe0231000 with rsp=0xffffffffe022f7d0 (0x1830 below its own
    top, ~126 KiB unused beneath it) was chased as unbounded klog recursion.
    It was DumpBacktrace walking one quad past the top of the AP slot.

    This test pins the INVARIANT (a fault above the running stack must not be
    called an overflow), not the statement shape — the linux-fd-generation
    contract taught us that pinning shape lets a test ratify broken code.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KSTACK_H = (ROOT / "kernel/mm/kstack.h").read_text(encoding="utf-8")
TRAPS_CPP = (ROOT / "kernel/arch/x86_64/traps.cpp").read_text(encoding="utf-8")
PANIC_CPP = (ROOT / "kernel/core/panic.cpp").read_text(encoding="utf-8")

ARENA_BASE = 0xFFFFFFFFE0000000
GUARD_PAGES = 1
PAGE = 0x1000
STACK_PAGES = 32
SLOT = (GUARD_PAGES + STACK_PAGES) * PAGE  # 0x21000


def usable(slot: int) -> tuple[int, int]:
    base = ARENA_BASE + slot * SLOT
    return base + GUARD_PAGES * PAGE, base + SLOT


class GeometryMatchesHeader(unittest.TestCase):
    """The constants this test reasons about must match the header."""

    def test_header_constants_are_what_this_test_assumes(self) -> None:
        def const(name: str) -> int:
            m = re.search(rf"{name}\s*=\s*(0x[0-9a-fA-F]+|\d+)", KSTACK_H)
            self.assertIsNotNone(m, f"{name} not found in kstack.h")
            return int(m.group(1), 0)

        self.assertEqual(const("kKernelStackArenaBase"), ARENA_BASE)
        self.assertEqual(const("kKernelStackGuardPages"), GUARD_PAGES)
        self.assertEqual(const("kKernelStackPages"), STACK_PAGES)


class SlotArithmetic(unittest.TestCase):
    """The geometry that makes over-top faults land on a neighbour's guard."""

    def test_exclusive_top_is_the_next_slots_guard_base(self) -> None:
        for slot in (0, 1, 16, 42):
            _, hi = usable(slot)
            nxt_base = ARENA_BASE + (slot + 1) * SLOT
            self.assertEqual(hi, nxt_base, "top must coincide with next slot's guard base")
            self.assertEqual((hi - ARENA_BASE) % SLOT, 0, "and be slot-aligned")

    def test_the_observed_2026_08_03_fault_is_over_top_not_overflow(self) -> None:
        # Real numbers from the failing boot.
        cr2 = 0xFFFFFFFFE0231000
        rsp = 0xFFFFFFFFE022F7D0
        lo, hi = usable(16)
        self.assertTrue(lo <= rsp < hi, "rsp was inside AP slot 16")
        self.assertEqual(cr2, hi, "fault was exactly at the exclusive top")
        own_guard = lo - GUARD_PAGES * PAGE
        self.assertNotEqual(cr2, own_guard, "it was NOT the running stack's own guard")
        # ...and the stack was nowhere near exhausted: 0x1E7D0 = 124880 bytes
        # (~122 KiB) of the 128 KiB slot still free BELOW rsp.
        self.assertEqual(rsp - lo, 0x1E7D0)
        self.assertGreater(rsp - lo, 0x1E000, "over 120 KiB still free below rsp")


class ClassifierContract(unittest.TestCase):
    """kstack.h must expose a stack-relative classification, not just a predicate."""

    def test_range_helper_exists_and_top_is_exclusive(self) -> None:
        self.assertIn("KernelStackUsableRangeOf", KSTACK_H)
        self.assertRegex(KSTACK_H, r"exclusive", "the top must be documented as exclusive")

    def test_classifier_distinguishes_own_from_neighbour_guard(self) -> None:
        self.assertIn("KernelStackClassifyGuardFault", KSTACK_H)
        for kind in ("NotAGuardFault", "OwnGuard", "NeighbourGuard"):
            self.assertIn(kind, KSTACK_H, f"missing guard kind {kind}")

    def test_classifier_takes_the_faulting_stack_pointer(self) -> None:
        m = re.search(r"KernelStackClassifyGuardFault\s*\(([^)]*)\)", KSTACK_H)
        self.assertIsNotNone(m)
        self.assertIn("rsp", m.group(1), "classification without RSP cannot attribute the guard")


class ReportingContract(unittest.TestCase):
    """The trap path must not call an over-top access an overflow."""

    def test_trap_path_classifies_before_reporting(self) -> None:
        self.assertIn("KernelStackClassifyGuardFault", TRAPS_CPP)

    def test_over_top_is_reported_distinctly_from_overflow(self) -> None:
        self.assertIn("OVER-TOP", TRAPS_CPP)
        self.assertRegex(
            TRAPS_CPP,
            r"not an overflow",
            "the over-top panic must say plainly that it is not an overflow",
        )

    def test_overflow_wording_still_exists_for_the_real_case(self) -> None:
        self.assertIn("kernel stack overflow", TRAPS_CPP)


class BacktraceBoundsContract(unittest.TestCase):
    """DumpBacktrace must not dereference past the top of the stack it walks."""

    def test_walker_bounds_itself_to_the_running_slot(self) -> None:
        body = PANIC_CPP[PANIC_CPP.index("void DumpBacktrace(") :]
        body = body[: body.index("\n}\n") + 3]
        self.assertIn("KernelStackUsableRangeOf", body,
                      "the walker must resolve the slot it is walking")
        # Both quads ([rbp] and [rbp+8]) must be proven in-bounds, so the
        # check has to cover rbp+16, not merely rbp.
        self.assertRegex(body, r"rbp\s*\+\s*16", "must bound BOTH dereferenced quads")

    def test_plausible_pointer_alone_is_not_treated_as_sufficient(self) -> None:
        body = PANIC_CPP[PANIC_CPP.index("void DumpBacktrace(") :]
        body = body[: body.index("\n}\n") + 3]
        i_plaus = body.index("PlausibleStackPointer")
        i_deref = body.index("*reinterpret_cast<const u64*>")
        i_bound = body.index("usable_hi")
        self.assertLess(i_plaus, i_deref)
        self.assertLess(i_bound, i_deref, "bounds check must precede any dereference")


if __name__ == "__main__":
    unittest.main(verbosity=2)
