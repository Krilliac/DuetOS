#!/usr/bin/env python3
"""Hostile structural contract for panic-safe AddressSpace region snapshots."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving braces and offsets."""
    masked = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "line"
                continue
            if current == "/" and following == "*":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "block"
                continue
            if current in ('"', "'"):
                quote = current
                masked[index] = " "
                index += 1
                state = "literal"
                continue
        elif state == "line":
            if current == "\n":
                state = "code"
            else:
                masked[index] = " "
            index += 1
            continue
        elif state == "block":
            if current == "*" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "code"
                continue
            if current != "\n":
                masked[index] = " "
            index += 1
            continue
        elif state == "literal":
            if current == "\\":
                masked[index] = " "
                if index + 1 < len(source):
                    masked[index + 1] = " "
                index += 2
                continue
            masked[index] = " "
            index += 1
            if current == quote:
                state = "code"
            continue
        index += 1
    return "".join(masked)


def function_body(source: str, name: str) -> str:
    clean = code_only(source)
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", clean):
        opening = clean.find("{", match.end())
        semicolon = clean.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        depth = 0
        for position in range(opening, len(clean)):
            if clean[position] == "{":
                depth += 1
            elif clean[position] == "}":
                depth -= 1
                if depth == 0:
                    return source[opening : position + 1]
    raise AssertionError(f"definition not found: {name}")


class ParserHostileTests(unittest.TestCase):
    def test_comments_literals_and_declarations_cannot_spoof_body(self) -> None:
        hostile = r'''
        // Target() { SpinLockTryGuard fake; }
        const char* text = "Target() { SpinLockTryGuard fake; }";
        void Target();
        void Target() { int real = 1; }
        '''
        body = function_body(hostile, "Target")
        self.assertIn("real", body)
        self.assertNotIn("SpinLockTryGuard", body)


class AddressSpaceRegionSyncContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.header = read("kernel/mm/address_space.h")
        cls.address_space = read("kernel/mm/address_space.cpp")
        cls.panic = read("kernel/core/panic.cpp")

    def test_public_snapshot_is_summary_only_and_explicitly_fail_fast(self) -> None:
        self.assertIn("struct AddressSpaceUserRegionSummary", self.header)
        for field in ("page_count", "min_vaddr", "max_vaddr_exclusive"):
            self.assertRegex(self.header, rf"\b{field}\b")
        declaration = code_only(self.header)
        self.assertRegex(declaration, r"bool\s+AddressSpaceTrySnapshotUserRegionSummary\s*\(")
        self.assertIn("never waits", self.header)

    def test_snapshot_uses_one_nonblocking_structural_lock_attempt(self) -> None:
        body = code_only(function_body(self.address_space, "AddressSpaceTrySnapshotUserRegionSummary"))
        self.assertIn("SpinLockTryGuard guard(as->regions_lock)", body)
        self.assertIn("if (!guard)", body)
        self.assertEqual(body.count("SpinLockTryGuard"), 1)
        for forbidden in ("SpinLockGuard", "MutexLock", "KMalloc", "KFree", "Panic", "KASSERT"):
            self.assertNotIn(forbidden, body)
        self.assertLess(body.index("SpinLockTryGuard"), body.index("as->region_count"))
        self.assertLess(body.index("as->region_count"), body.index("as->regions[index]"))

    def test_panic_dump_never_reads_region_storage_directly(self) -> None:
        body = code_only(function_body(self.panic, "DumpProcessVmInfo"))
        self.assertIn("AddressSpaceTrySnapshotUserRegionSummary", body)
        self.assertNotRegex(body, r"as\s*->\s*region_count")
        self.assertNotRegex(body, r"as\s*->\s*regions\s*\[")
        self.assertIn("region summary unavailable", self.panic)

    def test_panic_dll_walk_clamps_one_count_read(self) -> None:
        body = code_only(function_body(self.panic, "DumpProcessVmInfo"))
        self.assertEqual(body.count("proc->dll_image_count"), 1)
        self.assertIn("dll_image_count > Process::kDllImageCap", body)
        self.assertIn("dll_image_count = Process::kDllImageCap", body)
        self.assertRegex(body, r"for\s*\([^;]+;\s*i\s*<\s*dll_image_count\s*;")
        self.assertIn("GAP: the DLL ledger has no panic-safe try-snapshot API", self.panic)


if __name__ == "__main__":
    unittest.main(verbosity=2)
