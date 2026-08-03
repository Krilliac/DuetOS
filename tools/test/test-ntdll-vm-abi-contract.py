#!/usr/bin/env python3
"""Pin ntdll virtual-memory wrappers to the kernel's six-register ABI."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NTDLL = (ROOT / "userland/libs/ntdll/ntdll.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    match = re.search(
        rf"__declspec\(dllexport\).*?\b{re.escape(name)}\s*\([^;]*?\)\s*\{{(?P<body>.*?)^\}}",
        NTDLL,
        re.DOTALL | re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing exported function {name}")
    return match.group("body")


class NtdllVmAbiContract(unittest.TestCase):
    def test_allocate_maps_arguments_four_through_six_by_name(self) -> None:
        body = function("NtAllocateVirtualMemory")
        for token in (
            '"D"((long long)hProcess)',
            '"S"(hint)',
            '"d"(sz)',
            'mov %[allocation_type], %%r10',
            'mov %[protect], %%r8',
            'mov %[out_base], %%r9',
            '[out_base] "r"((long long)&out_base)',
        ):
            self.assertIn(token, body)

    def test_free_and_protect_use_symbolic_extended_arguments(self) -> None:
        free = function("NtFreeVirtualMemory")
        protect = function("NtProtectVirtualMemory")
        self.assertIn('mov %[free_type], %%r10', free)
        self.assertIn('[free_type] "r"((long long)FreeType)', free)
        self.assertIn('mov %[new_protect], %%r10', protect)
        self.assertIn('mov %[old_protect], %%r8', protect)
        self.assertIn('[old_protect] "r"((long long)OldProtect)', protect)

    def test_vm_wrappers_do_not_regress_to_positional_moves(self) -> None:
        for name in ("NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory"):
            self.assertNotRegex(function(name), r'mov %[0-9]+, %%r(?:10|8|9)')

    def test_interrupt_clobbers_are_declared(self) -> None:
        for name in ("NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory"):
            body = function(name)
            self.assertIn('"rcx"', body)
            self.assertIn('"r11"', body)
            self.assertIn('"memory"', body)


if __name__ == "__main__":
    unittest.main()
