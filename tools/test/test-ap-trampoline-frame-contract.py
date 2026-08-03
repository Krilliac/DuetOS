#!/usr/bin/env python3
"""Contract: the AP trampoline hands C++ a well-formed outermost frame.

WHY
    The trampoline reaches the kernel's C++ entry with `jmp`, not `call`, so
    nothing pushes a return address. Left that way the outermost frame is
    malformed in two independent ways:

      1. Anything reading the entry function's return address dereferences
         [rbp+8], which with rsp == stack top is exactly [top]. A slot's
         exclusive top IS the next slot's guard page, so that read faults.
         This was not theoretical: KBP_PROBE_V expands to
         __builtin_return_address(0) (kernel/debug/probes.h), and the
         kSmpApOnline probe in ApEntryFromTrampoline killed every AP on
         2026-08-03 — a guard-page fault while the AP's own 128 KiB stack
         was untouched (rsp was 0x138 below the top). It presented as
         "kernel stack overflow", which is the opposite of what happened.

      2. SysV requires rsp % 16 == 8 at function entry — the state a `call`
         leaves behind. The stack top is page-aligned and therefore
         16-aligned, so entering with rsp == top violates the ABI and
         mis-aligns SSE spill slots.

    One `push` of a null return address fixes both, and zero also
    terminates frame-pointer walks cleanly.

    Asserts the INVARIANT (a return address is established before control
    reaches C++), not a byte sequence.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRAMP = (ROOT / "kernel/arch/x86_64/ap_trampoline.S").read_text(encoding="utf-8")
PROBES_H = (ROOT / "kernel/debug/probes.h").read_text(encoding="utf-8")
SMP_CPP = (ROOT / "kernel/arch/x86_64/smp.cpp").read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    """Drop /* ... */ and trailing-# comments.

    Required, not cosmetic: the prose in this file legitimately mentions
    `jmp`, `push` and `call`, so scanning raw source finds instructions that
    are really commentary and truncates the block in the wrong place.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"#.*$", "", text, flags=re.M)


def long_mode_block() -> str:
    """Instructions from the 64-bit entry sequence up to the indirect jump."""
    code = strip_comments(TRAMP)
    start = code.index(".code64")
    end = code.index("jmp", start)
    return code[start:end]


class TrampolineFrameContract(unittest.TestCase):
    def test_stack_pointer_is_loaded_before_entry(self) -> None:
        self.assertRegex(long_mode_block(), r"mov\s+rsp\s*,")

    def test_a_return_address_is_pushed_before_entering_cpp(self) -> None:
        block = long_mode_block()
        self.assertRegex(
            block,
            r"(?m)^\s*push\b",
            "the entry is reached by jmp, so the trampoline must push a return "
            "address itself; without it __builtin_return_address(0) in the entry "
            "reads [top] and faults on the next slot's guard page",
        )

    def test_push_happens_after_rsp_is_set(self) -> None:
        block = long_mode_block()
        i_rsp = re.search(r"mov\s+rsp\s*,", block).start()
        i_push = re.search(r"(?m)^\s*push\b", block).start()
        self.assertLess(i_rsp, i_push, "pushing before rsp is loaded would write to the wrong stack")

    def test_transfer_to_cpp_is_still_an_indirect_jump(self) -> None:
        # If this ever becomes a `call`, the push above would be redundant
        # (and would mis-align the ABI the other way) — force a re-think.
        self.assertRegex(TRAMP, r"jmp\s+\[rax\]")

    def test_entry_point_is_noreturn(self) -> None:
        # A pushed null return address must never actually be returned to.
        self.assertRegex(SMP_CPP, r"\[\[noreturn\]\]\s*void\s+ApEntryFromTrampoline")


class ProbeMacroStillReadsReturnAddress(unittest.TestCase):
    """If this stops being true the hazard is gone — but so is the reason
    for the push, so the contract above should be revisited rather than
    silently kept."""

    def test_probe_macro_uses_builtin_return_address(self) -> None:
        self.assertIn("__builtin_return_address(0)", PROBES_H)

    def test_ap_entry_still_fires_a_probe(self) -> None:
        self.assertIn("KBP_PROBE_V", SMP_CPP)


if __name__ == "__main__":
    unittest.main(verbosity=2)
