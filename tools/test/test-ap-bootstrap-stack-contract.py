#!/usr/bin/env python3
"""Hostile structural contract for guarded AP bootstrap stacks."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
SMP = (ROOT / "kernel/arch/x86_64/smp.cpp").read_text(encoding="utf-8")
KSTACK = (ROOT / "kernel/mm/kstack.h").read_text(encoding="utf-8")


class ApBootstrapStackContract(unittest.TestCase):
    def test_smp_uses_guarded_arena(self) -> None:
        self.assertIn('#include "mm/kstack.h"', SMP)
        self.assertRegex(
            SMP,
            r"AllocateKernelStack\s*\(\s*mm::kKernelStackUsableBytes\s*\)",
        )

    def test_trampoline_receives_exact_arena_top(self) -> None:
        self.assertRegex(
            SMP,
            r"TrampU64At\s*\(\s*kOffStack\s*\)\s*=\s*"
            r"reinterpret_cast<u64>\s*\(\s*stack\s*\+\s*"
            r"mm::kKernelStackUsableBytes\s*\)",
        )

    def test_heap_bootstrap_stack_cannot_return(self) -> None:
        self.assertNotRegex(SMP, r"KMalloc\s*\(\s*kApStackBytes\s*\)")
        self.assertNotIn("KMalloc failed for AP stack", SMP)

    def test_persistent_lifetime_is_explicit(self) -> None:
        allocation = re.search(
            r"Persistent per-AP bootstrap stack(?P<body>.*?)"
            r"auto\* stack = static_cast<u8\*>\(",
            SMP,
            re.DOTALL,
        )
        self.assertIsNotNone(allocation)
        body = allocation.group("body")
        self.assertIn("remains mapped for the CPU lifetime", body)
        self.assertIn("rejected AP parks", body)

    def test_public_scope_documentation_matches_implementation(self) -> None:
        self.assertIn("SMP AP bootstrap stacks use guarded arena slots", KSTACK)
        self.assertNotIn("APs today only run `cli; hlt`", KSTACK)
        self.assertNotIn("own 16 KiB stack", SMP)
        self.assertIn("Single slot size (128 KiB usable)", KSTACK)
        self.assertIn("96 KiB-used line", KSTACK)


if __name__ == "__main__":
    unittest.main()
