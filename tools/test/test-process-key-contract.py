#!/usr/bin/env python3
"""Structural contract for non-recycled kernel ProcessKey identity."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/proc/process.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/proc/process.cpp").read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Mask comments and quoted literals while preserving delimiters."""
    return re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        lambda match: "".join("\n" if char == "\n" else " " for char in match.group()),
        source,
        flags=re.DOTALL,
    )


def body(source: str, signature: str) -> str:
    code = code_only(source)
    match = re.search(signature + r"\s*\(", code)
    if match is None:
        raise AssertionError(f"missing signature: {signature}")
    opening = code.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"missing body: {signature}")
    depth = 0
    for offset in range(opening, len(code)):
        if code[offset] == "{":
            depth += 1
        elif code[offset] == "}":
            depth -= 1
            if depth == 0:
                return code[opening + 1 : offset]
    raise AssertionError(f"unterminated body: {signature}")


class ProcessKeyContract(unittest.TestCase):
    def test_key_is_two_part_and_rejects_partial_identity(self) -> None:
        begin = HEADER.index("struct ProcessKey")
        key = HEADER[begin : HEADER.index("struct Process", begin + 1)]
        self.assertRegex(key, r"\bu64\s+identity\s*;")
        self.assertRegex(key, r"\bu64\s+pid\s*;")
        self.assertIn("kInvalidProcessKey{0, 0}", HEADER)
        valid = body(HEADER, r"constexpr\s+bool\s+ProcessKeyIsValid")
        self.assertRegex(valid, r"key\.identity\s*!=\s*0\s*&&\s*key\.pid\s*!=\s*0")
        equal = body(HEADER, r"constexpr\s+bool\s+operator==")
        self.assertRegex(equal, r"lhs\.identity\s*==\s*rhs\.identity\s*&&\s*lhs\.pid\s*==\s*rhs\.pid")

    def test_process_owns_a_distinct_immutable_incarnation(self) -> None:
        process = HEADER[HEADER.index("struct Process\n") :]
        self.assertRegex(process, r"\bu64\s+pid\s*;\s*u64\s+process_identity\s*;")

    def test_mint_is_atomic_and_refuses_wraparound(self) -> None:
        mint = body(SOURCE, r"u64\s+MintProcessKey")
        self.assertIn("__atomic_load_n(&g_next_pid", mint)
        self.assertRegex(mint, r"if\s*\(\s*observed\s*==\s*~u64\s*\{\s*0\s*\}\s*\)\s*return\s+0\s*;")
        self.assertIn("__atomic_compare_exchange_n(&g_next_pid, &observed, next", mint)
        self.assertRegex(mint, r"return\s+observed\s*;")
        self.assertNotIn("__atomic_fetch_add(&g_next_pid", code_only(SOURCE))

    def test_create_refuses_exhaustion_before_publication(self) -> None:
        create = body(SOURCE, r"Process\s*\*\s*ProcessCreate")
        mint = create.index("const u64 process_identity = MintProcessKey()")
        reject = create.index("if (process_identity == 0)", mint)
        pid = create.index("p->pid = process_identity", reject)
        identity = create.index("p->process_identity = process_identity", pid)
        self.assertLess(mint, reject)
        self.assertLess(reject, pid)
        self.assertLess(pid, identity)
        rejected = create[reject:pid]
        self.assertIn("mm::KFree(p)", rejected)
        self.assertIn("return nullptr", rejected)

    def test_snapshot_carries_both_exact_fields(self) -> None:
        snapshot = body(SOURCE, r"ProcessKey\s+ProcessKeySnapshot")
        self.assertIn("process->process_identity, process->pid", snapshot)
        self.assertIn("ProcessKeyIsValid(key)", snapshot)
        self.assertRegex(snapshot, r"return\s+key\s*;")


if __name__ == "__main__":
    unittest.main()
