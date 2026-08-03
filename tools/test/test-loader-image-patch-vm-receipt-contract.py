#!/usr/bin/env python3
"""Hostile structural contract for DLL loader VM ownership and image patches."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
PATCH_HEADER = ROOT / "kernel" / "loader" / "image_patch.h"
DLL_LOADER = ROOT / "kernel" / "loader" / "dll_loader.cpp"
ADDRESS_SPACE = ROOT / "kernel" / "mm" / "address_space.cpp"


def strip_comments_and_literals(text: str) -> str:
    token = re.compile(
        r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )

    def erase(match: re.Match[str]) -> str:
        value = match.group(0)
        return "".join("\n" if char == "\n" else " " for char in value)

    return token.sub(erase, text)


def body_for(source: str, signature: str) -> str:
    match = re.search(signature, source)
    if match is None:
        raise AssertionError(f"missing declaration matching {signature!r}")
    brace = source.find("{", match.end())
    if brace < 0:
        raise AssertionError(f"missing body for {signature!r}")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : index]
    raise AssertionError(f"unterminated body for {signature!r}")


class LoaderImagePatchVmReceiptContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patch = strip_comments_and_literals(PATCH_HEADER.read_text(encoding="utf-8"))
        cls.dll = strip_comments_and_literals(DLL_LOADER.read_text(encoding="utf-8"))
        cls.address_space = strip_comments_and_literals(ADDRESS_SPACE.read_text(encoding="utf-8"))

    def test_direct_map_access_is_inside_as_mutation_transaction(self) -> None:
        write = body_for(self.patch, r"\bImageDirectWriteBytes\s*\(")
        read = body_for(self.patch, r"\bImageDirectReadLe\s*\(")
        for body in (write, read):
            guard = body.find("ImagePatchMutationGuard mutation(*as)")
            lookup = body.find("AddressSpaceLookupUserFrame")
            direct = body.find("PhysToVirt")
            self.assertGreaterEqual(guard, 0)
            self.assertGreater(lookup, guard)
            self.assertGreater(direct, lookup)

    def test_patch_bounds_and_page_straddle_write_are_failure_atomic(self) -> None:
        write = body_for(self.patch, r"\bImageDirectWriteBytes\s*\(")
        little = body_for(self.patch, r"\bImageDirectWriteLe\s*\(")
        read = body_for(self.patch, r"\bImageDirectReadLe\s*\(")
        self.assertIn("ImagePatchRangeValid(as, va, len)", write)
        self.assertGreaterEqual(write.count("while (remaining != 0)"), 2)
        self.assertGreaterEqual(write.count("AddressSpaceLookupUserFrame"), 2)
        self.assertLess(write.find("AddressSpaceLookupUserFrame"), write.find("PhysToVirt"))
        self.assertIn("n > sizeof(u64)", little)
        self.assertIn("n > sizeof(u64)", read)
        self.assertIn("ImageDirectWriteBytes(as, va, bytes, n)", little)

    def test_dll_maps_only_through_exact_range_receipts(self) -> None:
        mapping = body_for(self.dll, r"class\s+DllMappingTransaction\s+final")
        self.assertIn("AddressSpaceReserveUserRange", mapping)
        self.assertIn("AddressSpaceMapReservedUserPage", mapping)
        self.assertIn("AddressSpaceReleaseUserReservation", mapping)
        self.assertIn("AddressSpaceCommitUserReservation", mapping)
        self.assertNotIn("AddressSpaceMapUserPage(", self.dll)
        self.assertNotIn("AddressSpaceLookupUserFrame", self.dll)

    def test_ranges_are_claimed_before_mapping_and_committed_last(self) -> None:
        load = body_for(self.dll, r"\bDllLoad\s*\(")
        reserve = load.find("mapping.ReserveAll()")
        headers = load.find("MapHeadersPage(")
        sections = load.find("MapSection(")
        reloc = load.find("ApplyRelocations(")
        exports = load.find("PeParseExports(")
        commit = load.find("mapping.CommitAll()")
        self.assertTrue(0 <= reserve < headers < sections < reloc < exports < commit)

    def test_page_overlap_is_rejected_and_adjacency_is_coalesced(self) -> None:
        add_range = body_for(self.dll, r"\bAddRange\s*\(")
        self.assertIn("lo < range.hi && hi > range.lo", add_range)
        self.assertIn("hi == range.lo || lo == range.hi", add_range)
        section_range = body_for(self.dll, r"\bSectionPageRange\s*\(")
        self.assertIn("virt_addr & kPageMask", section_range)
        self.assertIn("ImageRangeInBounds(virt_addr, in_mem, image_size)", section_range)

    def test_aslr_and_wx_inputs_fail_closed_before_mapping(self) -> None:
        load = body_for(self.dll, r"\bDllLoad\s*\(")
        section = body_for(self.dll, r"\bMapSection\s*\(")
        self.assertIn("aslr_delta & kPageMask", load)
        self.assertIn("aslr_delta > (kDllUserTopExclusive - 1 - h.image_base)", load)
        self.assertIn("h.image_size == 0", load)
        self.assertRegex(section, r"flags\s*&\s*kPageWritable")
        self.assertIn("flags |= kPageNoExecute", section)

    def test_protect_cannot_cross_live_loader_reservation(self) -> None:
        protect = body_for(self.address_space, r"\bAddressSpaceProtectUserPage\s*\(")
        self.assertIn("RangeOverlapsReservation", protect)


if __name__ == "__main__":
    unittest.main(verbosity=2)
