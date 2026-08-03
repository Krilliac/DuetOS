#!/ usr / bin / env python3
"""Structural contract for generation-safe AddressSpace output leases."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/mm/address_space.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/mm/address_space.cpp").read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class AddressSpaceWriteLeaseContract(unittest.TestCase):
    def test_fixed_bounded_opaque_contract(self) -> None:
        self.assertIn("kAddressSpaceWriteLeaseCapacity = 32", HEADER)
        self.assertIn("kAddressSpaceWriteLeaseMaxPages = 4", HEADER)
        self.assertIn("class AddressSpaceWriteLease", HEADER)
        self.assertIn("AddressSpaceWriteLease(const AddressSpaceWriteLease&) = delete", HEADER)
        self.assertIn("AddressSpaceWriteLease(AddressSpaceWriteLease&&) = delete", HEADER)
        self.assertIn("AddressSpace* owner_ = nullptr", HEADER)
        self.assertIn("u64 token_value_ = 0", HEADER)
        self.assertIn("AddressSpaceWriteLeaseRow write_leases[kAddressSpaceWriteLeaseCapacity]", HEADER)
        self.assertNotRegex(HEADER, r"public:\s+.*token_value_", "lease authority must remain opaque")

    def test_token_identity_is_global_nonwrapping_and_never_reused(self) -> None:
        allocator = function_body(SOURCE, "u64 AllocateWriteLeaseTokenValue()")
        self.assertIn("g_next_write_lease_token", allocator)
        self.assertIn("__atomic_compare_exchange_n", allocator)
        self.assertIn("current == ~u64{0}", allocator)
        self.assertIn("return 0", allocator)

    def test_acquire_validates_every_leaf_before_publication_and_retains_as(self) -> None:
        acquire = function_body(SOURCE, "AddressSpaceWriteLeaseStatus AddressSpaceAcquireWriteLease(")
        ordered = (
            "AddressSpaceMutationGuard mutation",
            "write_leases_lock",
            "regions_lock",
            "kPagePresent | kPageUser",
            "kPageWritable",
            "AllocateWriteLeaseTokenValue",
            "AddressSpaceWriteLeaseRow{user_va, hi, token_value}",
            "AddressSpaceRetain(as)",
            "out_lease->token_value_ = token_value",
        )
        cursor = -1
        for token in ordered:
            next_cursor = acquire.find(token)
            self.assertGreater(next_cursor, cursor, token)
            cursor = next_cursor
        self.assertIn("CapacityExhausted", acquire)
        self.assertIn("CorruptState", acquire)
        self.assertIn("out_lease->owner_ != nullptr", acquire)
        self.assertLess(acquire.index("out_lease->owner_ != nullptr"), acquire.index("AddressSpaceRetain(as)"))

    def test_copy_is_exact_all_pages_first_and_direct_map_only(self) -> None:
        copy = function_body(SOURCE, "bool AddressSpaceCopyToWriteLease(")
        self.assertIn("FindWriteLeaseRowLocked", copy)
        self.assertIn("row.lo != lease.lo_", copy)
        self.assertIn("row.hi != lease.hi_", copy)
        self.assertIn("kPagePresent | kPageUser | kPageWritable", copy)
        self.assertLess(copy.index("last_lease_page"), copy.index("memcpy(direct"))
        self.assertIn("PhysToVirt", copy)
        self.assertNotIn("CopyToUser", copy)

    def test_release_consumes_exact_row_then_drops_lifetime_reference(self) -> None:
        release = function_body(SOURCE, "bool AddressSpaceReleaseWriteLease(")
        self.assertIn("FindWriteLeaseRowLocked", release)
        self.assertIn("AddressSpaceWriteLeaseRow{}", release)
        self.assertIn("--as->write_lease_count", release)
        self.assertLess(release.index("lease->owner_ = nullptr"), release.index("AddressSpaceRelease(as)"))

    def test_every_retiring_mutator_honors_write_lease(self) -> None:
        signatures = (
            "bool AddressSpaceCommitUserReservationReplacingOwnedRange(",
            "bool AddressSpaceUnmapUserPage(",
            "bool AddressSpaceReleaseUserReservation(",
            "bool AddressSpaceProtectUserPage(",
            "bool UnmapBorrowedRange(",
        )
        for signature in signatures:
            with self.subTest(signature=signature):
                self.assertIn("RangeOverlapsWriteLease", function_body(SOURCE, signature))

        clear = function_body(SOURCE, "void AddressSpaceClearUserMappings(")
        self.assertIn("AddressSpaceHasWriteLeases", clear)
        self.assertIn("SchedYield", clear)
        release = function_body(SOURCE, "void AddressSpaceRelease(AddressSpace* as)")
        self.assertIn("AddressSpaceRelease with live write lease", release)


if __name__ == "__main__":
    unittest.main(verbosity=2)
