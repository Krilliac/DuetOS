#!/usr/bin/env python3
"""Contract: critical-section counters honor CurrentCpu stale-GS recovery."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CRITICAL_CPP = (ROOT / "kernel/cpu/critical.cpp").read_text(encoding="utf-8")
CRITICAL_H = (ROOT / "kernel/cpu/critical.h").read_text(encoding="utf-8")
PERCPU_CPP = (ROOT / "kernel/cpu/percpu.cpp").read_text(encoding="utf-8")
PERCPU_H = (ROOT / "kernel/cpu/percpu.h").read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : pos]
    raise AssertionError(f"unterminated function: {signature}")


class CriticalGsbaseFallbackContract(unittest.TestCase):
    def test_current_cpu_explicitly_recovers_non_kernel_gsbase(self) -> None:
        body = function_body(PERCPU_CPP, "PerCpu* CurrentCpu()")
        self.assertIn("kKernelHalfBase", body)
        self.assertIn("SmpGetPercpu", body)
        self.assertIn("LapicCurrentId", body)

    def test_critical_hot_paths_only_update_the_resolved_percpu_pointer(self) -> None:
        expectations = {
            "void CriticalEnter()": "critical_enter_count",
            "void CriticalExit()": "critical_exit_count",
            "bool DeferPreemptIfCritical()": "critical_deferred_count",
        }
        for signature, field in expectations.items():
            with self.subTest(signature=signature):
                body = function_body(CRITICAL_CPP, signature)
                self.assertIn("PerCpu* p = CurrentCpu();", body)
                self.assertIn(f"IncrementResolvedCounter(&p->{field});", body)
                self.assertNotIn("ThisCpu", body)

    def test_critical_module_has_no_raw_gs_relative_counter_path(self) -> None:
        self.assertNotIn('arch/x86_64/percpu_ops.h', CRITICAL_CPP)
        self.assertNotRegex(CRITICAL_CPP, r"\bThisCpu(?:Read|Write|Inc|Add)64\b")
        self.assertIn('asm volatile("incq %0"', CRITICAL_CPP)
        self.assertIn('"+m"(*counter)', CRITICAL_CPP)
        self.assertIn('"cc", "memory"', CRITICAL_CPP)
        self.assertNotIn("arch::ThisCpu", CRITICAL_H)
        self.assertNotIn("gs:`-relative", CRITICAL_H)
        critical_fields = PERCPU_H.split("// Preempt-off-but-IRQs-on", 1)[1].split("u32 _pad_critical[1];", 1)[0]
        self.assertNotIn("arch::ThisCpu", critical_fields)


if __name__ == "__main__":
    unittest.main()
