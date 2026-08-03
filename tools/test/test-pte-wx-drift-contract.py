#!/usr/bin/env python3
"""Contract: the W^X drift detector ignores CPU-managed PTE bits.

WHY
    `CheckPteFlags` samples `.rodata` PTEs at boot and re-reads them each
    health scan, reporting `KernelPteWxFlipped` on any change. Comparing the
    RAW PTE makes it fire on the Accessed and Dirty bits, which the CPU sets
    autonomously on read/write with no software involvement. Those bits carry
    no W^X meaning: a page whose A bit flipped is exactly as writable and
    exactly as executable as it was at baseline.

    A live 4-minute boot logged 92 drifts, every one of them
    baseline=0x8000000000000001 -> now=0x8000000000000021 — bit 5 (Accessed)
    and nothing else. NX (bit 63) and Writable never moved.

    The damage was not cosmetic. Each false report drove an autonomic
    "security-escalate"; 46 fired in that window, pushing the box to
    Production/Enforce, which poisons every subsequent image-load and
    sensitive-LBA write for the session. A false integrity alarm that
    degrades the running system is worse than no alarm at all.

    Pins the invariant: mask A/D out of the COMPARISON, keep every
    security-relevant bit (Present, Writable, User, NX) compared exactly, and
    still report the RAW values so a genuine flip stays diagnosable.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "kernel/diag/runtime_checker.cpp").read_text(encoding="utf-8")
PAGING_H = (ROOT / "kernel/mm/paging.h").read_text(encoding="utf-8")


def check_body() -> str:
    start = SRC.index("bool CheckPteFlags()")
    end = SRC.index("\n}", start)
    return SRC[start:end]


class HardwareBitsAreMasked(unittest.TestCase):
    def test_accessed_and_dirty_are_excluded_from_the_comparison(self) -> None:
        body = check_body()
        self.assertIn("kPteHardwareManagedMask", body,
                      "the comparison must exclude CPU-maintained bits")
        mask_def = re.search(
            r"kPteHardwareManagedMask\s*=\s*([^;]+);", SRC)
        self.assertIsNotNone(mask_def, "mask must be defined")
        expr = mask_def.group(1)
        self.assertIn("kPageAccessed", expr)
        self.assertIn("kPageDirty", expr)

    def test_mask_is_applied_to_both_sides(self) -> None:
        body = check_body()
        self.assertGreaterEqual(
            body.count("~kPteHardwareManagedMask"), 2,
            "baseline and current reading must be masked identically",
        )

    def test_security_bits_are_not_masked(self) -> None:
        mask_def = re.search(r"kPteHardwareManagedMask\s*=\s*([^;]+);", SRC).group(1)
        for bit in ("kPagePresent", "kPageWritable", "kPageUser", "kPageNoExecute"):
            self.assertNotIn(bit, mask_def,
                             f"{bit} is security-relevant and must still be compared")


class DiagnosticsKeepRawValues(unittest.TestCase):
    def test_report_prints_raw_not_masked_values(self) -> None:
        body = check_body()
        self.assertIn("baseline_raw", body)
        self.assertIn("now_raw", body)
        i = body.index("PTE flags drifted")
        window = body[i : i + 400]
        self.assertIn("baseline_raw", window,
                      "a real flip needs the full PTE; printing masked values hides which bit moved")
        self.assertIn("now_raw", window)


class BitDefinitionsMatchTheObservedDrift(unittest.TestCase):
    def test_accessed_is_bit_5(self) -> None:
        m = re.search(r"kPageAccessed\s*=\s*1ULL\s*<<\s*(\d+)", PAGING_H)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), 5)
        # 1<<5 == 0x20, exactly the delta seen in the live boot.
        self.assertEqual(1 << int(m.group(1)), 0x20)

    def test_the_observed_pair_differs_only_by_accessed(self) -> None:
        baseline, now = 0x8000000000000001, 0x8000000000000021
        self.assertEqual(now ^ baseline, 0x20, "the live drift was the A bit alone")
        nx = 1 << 63
        self.assertEqual(baseline & nx, nx, "NX was set at baseline")
        self.assertEqual(now & nx, nx, "NX was still set after the 'drift'")
        self.assertEqual(now & 0x2, 0, "page was never made writable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
