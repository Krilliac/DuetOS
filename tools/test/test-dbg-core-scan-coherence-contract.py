#!/usr/bin/env python3
"""Hostile structural contract for mutation-coherent debugger byte scans."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DBG_CORE = ROOT / "kernel" / "apps" / "dbg_core.cpp"


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving source shape."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for index in range(begin, end):
            if masked[index] not in "\r\n":
                masked[index] = " "

    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise AssertionError("unterminated block comment")
            end += 2
            blank(index, end)
            index = end
            continue
        if source[index] in "\"'":
            quote = source[index]
            end = index + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == quote:
                    end += 1
                    break
                end += 1
            else:
                raise AssertionError("unterminated quoted literal")
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(masked)


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
    if opening < 0 or source[opening] != left:
        raise AssertionError(f"missing opening delimiter {left!r}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} region")


def function_body(source: str, name: str) -> str:
    clean = code_only(source)
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", clean):
        opening_paren = clean.find("(", match.start())
        closing_paren = matching_delimiter(clean, opening_paren, "(", ")")
        opening_brace = clean.find("{", closing_paren + 1)
        declaration_end = clean.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        closing_brace = matching_delimiter(clean, opening_brace, "{", "}")
        return clean[opening_brace + 1 : closing_brace]
    raise AssertionError(f"definition not found: {name}")


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class ParserHostileTests(unittest.TestCase):
    def test_comments_literals_and_declarations_cannot_spoof_body(self) -> None:
        hostile = r'''
// Target() { sched::MutexLock(fake); }
const char* decoy = "Target() { as->regions[7]; }";
void Target();
void Target() { int real = 1; }
'''
        body = function_body(hostile, "Target")
        self.assertIn("real", body)
        self.assertNotIn("MutexLock", body)
        self.assertNotIn("regions", body)


class DbgCoreScanCoherenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = DBG_CORE.read_text(encoding="utf-8")
        cls.scan_span = function_body(cls.source, "ScanSpan")
        cls.scan_bytes = function_body(cls.source, "ScanBytes")

    def test_span_counts_every_match_after_storage_fills(self) -> None:
        ordered(
            self,
            self.scan_span,
            "size < nlen",
            "last_start = size - static_cast<u64>(nlen)",
            "off <= last_start",
            "++match_count",
            "stored_count < cap",
            "hits[stored_count++] = base + off",
        )
        loop_header = re.search(r"for\s*\(([^;]*);([^;]*);([^)]*)\)", self.scan_span)
        self.assertIsNotNone(loop_header)
        self.assertNotIn("cap", loop_header.group(2))
        self.assertNotIn("stored_count", loop_header.group(2))

    def test_user_scan_holds_mutation_lock_across_stable_index_walk(self) -> None:
        ordered(
            self,
            self.scan_bytes,
            "ScopedProcessRuntimeAccess runtime_access(p)",
            "sched::MutexLock(&as->mutation_lock)",
            "SpinLockGuard region_guard(as->regions_lock)",
            "region_count = as->region_count",
            "ledger_valid && r < region_count",
            "base = as->regions[r].vaddr",
            "AddressSpaceLookupUserFrame(as, base)",
            "PhysToVirt(frame)",
            "page[offset] = source[offset]",
            "ScanSpan(page",
            "sched::MutexUnlock(&as->mutation_lock)",
        )
        self.assertNotIn("AddressSpaceReadUserMemory", self.scan_bytes)
        self.assertNotRegex(self.scan_bytes, r"AddressSpaceUserRegion\s*\*")
        self.assertNotRegex(self.scan_bytes, r"(?:auto|AddressSpaceUserRegion)\s*\*[^;=]*=\s*&?\s*as->regions")

    def test_region_coverage_does_not_stop_at_result_cap(self) -> None:
        region_loop = re.search(r"for\s*\(\s*u16\s+r\s*=\s*0\s*;([^;]*);", self.scan_bytes)
        self.assertIsNotNone(region_loop)
        condition = region_loop.group(1)
        self.assertIn("r < region_count", condition)
        self.assertNotIn("hit_count", condition)
        self.assertNotIn("cap", condition)

    def test_logging_and_truncation_reporting_happen_after_vm_unlock(self) -> None:
        locked_begin = self.scan_bytes.index("sched::MutexLock(&as->mutation_lock)")
        locked_end = self.scan_bytes.index("sched::MutexUnlock(&as->mutation_lock)", locked_begin)
        locked_region = self.scan_bytes[locked_begin:locked_end]
        self.assertNotIn("KLOG_", locked_region)
        ordered(
            self,
            self.scan_bytes[locked_end:],
            "sched::MutexUnlock(&as->mutation_lock)",
            "if (!ledger_valid)",
            "KLOG_WARN_V",
            "if (match_count > hit_count)",
            "KLOG_WARN_2V",
            "return hit_count",
        )
        self.assertGreaterEqual(self.scan_bytes.count("match_count > hit_count"), 2)

    def test_requested_capacity_clamp_is_not_silent(self) -> None:
        ordered(
            self,
            self.scan_bytes,
            "const usize requested_cap = cap",
            "cap > kScanResultCap",
            "cap = kScanResultCap",
            "KLOG_WARN_2V",
        )

    def test_scan_path_stays_allocation_free(self) -> None:
        for forbidden in ("KMalloc", "KFree", "new ", "AddressSpaceUserRegion["):
            self.assertNotIn(forbidden, self.scan_bytes)


if __name__ == "__main__":
    unittest.main()
