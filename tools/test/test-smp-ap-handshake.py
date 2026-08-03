#!/usr/bin/env python3
"""Deterministic structural guard for the AP generation/admission handshake."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SMP_CPP = ROOT / "kernel/arch/x86_64/smp.cpp"
TRAMPOLINE_ASM = ROOT / "kernel/arch/x86_64/ap_trampoline.S"


def function_body(source: str, signature: str) -> str:
    match = re.search(signature + r"\s*\([^)]*\)\s*\{", source)
    if match is None:
        raise AssertionError(f"missing function: {signature}")
    opening = source.find("{", match.start())
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated function: {signature}")


def ordered(source: str, *needles: str) -> None:
    cursor = -1
    for needle in needles:
        position = source.find(needle, cursor + 1)
        if position < 0:
            raise AssertionError(f"missing ordered token: {needle}")
        if position <= cursor:
            raise AssertionError(f"out-of-order token: {needle}")
        cursor = position


class SmpApHandshakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cpp = SMP_CPP.read_text(encoding="utf-8")
        self.asm = TRAMPOLINE_ASM.read_text(encoding="utf-8")

    def test_parameter_offsets_match_assembly(self) -> None:
        expected = {
            "CapturedToken": ("CAPTURED_TOKEN", 0xFCC),
            "ParkedToken": ("PARKED_TOKEN", 0xFD0),
            "ReadyToken": ("READY_TOKEN", 0xFD4),
            "CpuId": ("CPU_ID", 0xFD8),
            "AttemptToken": ("ATTEMPT_TOKEN", 0xFDC),
            "Entry": ("ENTRY", 0xFE0),
            "Stack": ("STACK", 0xFE8),
            "Pml4": ("PML4", 0xFF0),
        }
        for cpp_name, (asm_name, offset) in expected.items():
            self.assertRegex(self.cpp, rf"kOff{cpp_name}\s*=\s*0x{offset:X}\s*;")
            self.assertRegex(self.asm, rf"\.set\s+OFF_{asm_name}\s*,\s*0x{offset:X}\b")
        self.assertNotIn("kOffOnlineFlag", self.cpp)
        self.assertNotIn("OFF_ONLINE_FLAG", self.asm)

    def test_trampoline_captures_all_mutable_parameters_before_entry(self) -> None:
        long_mode = self.asm[self.asm.index(".org OFF_LONG") : self.asm.index(".org OFF_GDT")]
        ordered(
            long_mode,
            "TRAMP_BASE + OFF_STACK",
            "TRAMP_BASE + OFF_CPU_ID",
            "TRAMP_BASE + OFF_ATTEMPT_TOKEN",
            "mov     esi, [rax]",
            "TRAMP_BASE + OFF_CAPTURED_TOKEN",
            "mov     [rax], esi",
            "TRAMP_BASE + OFF_ENTRY",
        )

    def test_ap_cannot_enter_cpuhp_or_scheduler_without_bsp_gates(self) -> None:
        entry = function_body(
            self.cpp,
            r'extern\s+"C"\s+\[\[noreturn\]\]\s+void\s+ApEntryFromTrampoline',
        )
        ordered(
            entry,
            "kApGateInitialize",
            "CpuhpBringUp(cpu_id)",
            "kOffReadyToken), attempt_token",
            "kApGateRun",
            "SchedEnterOnAp(cpu_id)",
        )
        self.assertIn("kApGateReject", entry)
        self.assertIn("CpuhpTakeDown(cpu_id)", entry)
        self.assertIn("ParkUnadmittedAp(attempt_token)", entry)

    def test_waiter_requires_the_exact_attempt_token(self) -> None:
        waiter = function_body(self.cpp, r"bool\s+WaitForApToken")
        self.assertRegex(waiter, r"__atomic_load_n\([^;]+\)\s*==\s*expected_token")
        self.assertNotRegex(waiter, r"__atomic_load_n\([^;]+\)\s*!=\s*0")

    def test_bsp_uses_exact_tokens_and_fails_closed_before_reuse(self) -> None:
        start = function_body(self.cpp, r"u64\s+SmpStartAps")
        ordered(
            start,
            "kOffAttemptToken",
            "SmpSendIpi(rec.apic_id, sipi)",
            "WaitForApToken(kOffCapturedToken, attempt_token",
            "kApGateInitialize",
            "WaitForApReady(attempt_token",
            "&ap_pcpu->online, true",
            "kApGateRun",
        )
        self.assertRegex(
            start,
            r"AP never captured startup parameters; aborting AP bring-up[\s\S]{0,240}\bbreak\s*;",
        )
        self.assertNotRegex(start, r"WaitForAp(?:Online|Token)\s*\(\s*\)")

    def test_generation_and_slot_tokens_do_not_alias(self) -> None:
        def token(generation: int, cpu_id: int) -> int:
            return (generation << 8) | cpu_id

        current = token(2, 3)
        self.assertNotEqual(token(1, 3), current, "stale generation acknowledged current slot")
        self.assertNotEqual(token(2, 2), current, "different slot acknowledged current generation")
        self.assertEqual(current & 0xFF, 3)
        self.assertEqual(current & 0xC0000000, 0)


if __name__ == "__main__":
    unittest.main()
