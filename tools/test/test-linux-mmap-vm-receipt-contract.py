#!/usr/bin/env python3
"""Hostile structural contract for Linux mmap/mremap lifetime safety."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "kernel/subsystems/linux/syscall_mm.cpp").read_text(encoding="utf-8")
ADDRESS_SPACE_HEADER = (ROOT / "kernel/mm/address_space.h").read_text(encoding="utf-8")
ADDRESS_SPACE_SOURCE = (ROOT / "kernel/mm/address_space.cpp").read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank comments and literals so prose cannot satisfy a contract."""
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
    code = code_only(source)
    match = re.search(rf"\b{name}\s*\(", code)
    if match is None:
        raise AssertionError(f"missing function: {name}")
    opening_paren = code.find("(", match.start())
    closing_paren = matching_delimiter(code, opening_paren, "(", ")")
    opening_brace = code.find("{", closing_paren)
    closing_brace = matching_delimiter(code, opening_brace, "{", "}")
    return code[opening_brace + 1 : closing_brace]


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class LinuxMmapVmReceiptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.code = code_only(SOURCE)
        cls.mmap = function_body(SOURCE, "DoMmap")
        cls.brk = function_body(SOURCE, "DoBrk")
        cls.munmap = function_body(SOURCE, "DoMunmap")
        cls.mremap = function_body(SOURCE, "DoMremap")
        cls.mincore = function_body(SOURCE, "DoMincore")
        cls.copy_range = function_body(SOURCE, "CopyUserRangeOverlapSafe")
        cls.replace = function_body(ADDRESS_SPACE_SOURCE, "AddressSpaceCommitUserReservationReplacingOwnedRange")
        cls.protect = function_body(ADDRESS_SPACE_SOURCE, "AddressSpaceProtectUserPage")

    def test_parser_rejects_comment_and_literal_decoys(self) -> None:
        hostile = '''
// LinuxFdAcquire(p, fd, 2, &acquired);
const char* fake = "AddressSpaceReadUserMemory(as, source, out, len)";
int visible = 7;
'''
        visible = code_only(hostile)
        self.assertNotIn("LinuxFdAcquire", visible)
        self.assertNotIn("AddressSpaceReadUserMemory", visible)
        self.assertIn("int visible = 7;", visible)

    def test_mmap_never_reads_process_fd_slots_directly(self) -> None:
        self.assertNotIn("linux_fds[", self.code)
        self.assertNotIn("p->linux_fds", self.mmap)

    def test_file_mmap_retains_and_serializes_exact_ofd_identity(self) -> None:
        ordered(
            self,
            self.mmap,
            "util::MaskedIndex(fd, 16)",
            "LinuxFdAcquire(p, static_cast<u32>(fd), 2, &acquired)",
            "LinuxFdAcquiredRelease(&acquired)",
            "LinuxFdIoGuardEnter(&acquired, &io_guard)",
            "LinuxFdIoGuardExit(&io_guard)",
            "LinuxFdRefreshRetainedRegular(&acquired, &io_guard, &snapshot)",
            "entry.first_cluster = snapshot.first_cluster",
            "entry.size_bytes = snapshot.size",
            "Fat32ReadAt",
        )

    def test_file_mmap_cleanup_is_scope_bound_and_rollback_is_exact(self) -> None:
        self.assertIn("DUETOS_DEFER(core::LinuxFdAcquiredRelease(&acquired))", self.mmap)
        self.assertIn("DUETOS_DEFER(core::LinuxFdIoGuardExit(&io_guard))", self.mmap)
        ordered(
            self,
            self.mmap,
            "AddressSpaceReserveUserRange",
            "AddressSpaceReleaseUserReservation",
            "AddressSpaceMapReservedUserPage",
            "AddressSpaceCommitUserReservation",
            "release_file_mapping.dismiss()",
            "p->linux_mmap_cursor += aligned",
        )

    def test_anonymous_mmap_uses_the_same_exact_reservation_rollback(self) -> None:
        anonymous = self.mmap[
            self.mmap.index("if ((flags & kMapAnonymous) != 0") : self.mmap.index("if (fd >= 16)")
        ]
        ordered(
            self,
            anonymous,
            "AddressSpaceReserveUserRange",
            "AddressSpaceReleaseUserReservation",
            "AddressSpaceMapReservedUserPage",
            "AddressSpaceCommitUserReservation",
            "release_anonymous_mapping.dismiss()",
            "p->linux_mmap_cursor += aligned",
        )
        self.assertNotIn("AddressSpaceMapUserPage", anonymous)
        self.assertNotIn("AddressSpaceUnmapUserPage", anonymous)

    def test_file_offsets_are_page_aligned_and_addition_checked(self) -> None:
        self.assertIn("(off & (mm::kPageSize - 1)) != 0", self.mmap)
        self.assertIn("off > ~u64{0} - aligned", self.mmap)

    def test_overlap_safe_copy_uses_only_serialized_vm_copy_apis(self) -> None:
        self.assertNotIn("AddressSpaceLookupUserFrame", self.copy_range)
        self.assertNotIn("PhysToVirt", self.copy_range)
        self.assertIn("AddressSpaceReadUserMemory", self.copy_range)
        self.assertIn("AddressSpaceWriteUserMemory", self.copy_range)
        self.assertIn("length > (kUserMaxExclusive - source)", self.copy_range)
        self.assertIn("length > (kUserMaxExclusive - destination)", self.copy_range)

    def test_overlap_copy_has_memmove_direction_and_two_page_bounds(self) -> None:
        self.assertIn("destination > source && destination < source_end", self.copy_range)
        self.assertIn("if (!copy_backward)", self.copy_range)
        self.assertIn("u64 remaining = length", self.copy_range)
        self.assertGreaterEqual(self.copy_range.count("source_room"), 6)
        self.assertGreaterEqual(self.copy_range.count("destination_room"), 6)

    def test_mremap_rejects_overflow_and_never_dereferences_frame_snapshots(self) -> None:
        self.assertIn("old_aligned > (kMremapUserMaxExclusive - old_addr)", self.mremap)
        self.assertIn("new_aligned > (kMremapUserMaxExclusive - base)", self.mremap)
        self.assertNotIn("AddressSpaceLookupUserFrame", self.mremap)
        self.assertNotIn("PhysToVirt", self.mremap)

    def test_vm_syscalls_hold_process_runtime_transaction_before_state_access(self) -> None:
        for body, first_state_access in (
            (self.brk, "p->linux_brk_current"),
            (self.mmap, "p->linux_mmap_cursor"),
            (self.munmap, "AddressSpaceUnmapUserPage"),
            (self.mremap, "p->linux_mmap_cursor"),
            (self.mincore, "AddressSpaceProbePte"),
        ):
            with self.subTest(first_state_access=first_state_access):
                ordered(
                    self,
                    body,
                    "CurrentProcess()",
                    "ScopedProcessRuntimeAccess runtime_access(p)",
                    "if (!runtime_access)",
                    first_state_access,
                )

    def test_mremap_combines_destination_publish_and_source_retirement(self) -> None:
        grow = self.mremap[self.mremap.index("AddressSpaceReservationToken destination_reservation") :]
        ordered(
            self,
            grow,
            "AddressSpaceReserveUserRange",
            "AddressSpaceReleaseUserReservation",
            "AddressSpaceMapReservedUserPage",
            "CopyUserRangeOverlapSafe",
            "AddressSpaceCommitUserReservationReplacingOwnedRange",
            "release_destination.dismiss()",
            "p->linux_mmap_cursor += new_aligned",
        )
        self.assertNotIn("AddressSpaceMapUserPage", grow)
        self.assertNotIn("AddressSpaceUnmapUserPage", grow)
        self.assertNotIn("AddressSpaceCommitUserReservation(", grow)

    def test_combined_replace_validates_both_ranges_before_detaching(self) -> None:
        self.assertIn("AddressSpaceCommitUserReservationReplacingOwnedRange", ADDRESS_SPACE_HEADER)
        first_detach = self.replace.index("DetachUserPageByIndexLocked")
        validation = self.replace[:first_detach]
        self.assertIn("destination_seen", validation)
        self.assertIn("source_seen", validation)
        self.assertIn("RangeOverlapsReservation(as, source_lo, source_hi)", validation)
        self.assertIn("region.reservation_token != destination_token.value_", validation)
        self.assertIn("region.reservation_token != 0", validation)
        self.assertIn("(*pte & kAddrMask) != region.frame", validation)
        self.assertIn("destination_count != destination_pages", validation)
        self.assertIn("source_count != source_pages", validation)
        self.assertNotIn("AddressSpaceUnmapUserPage", self.replace)
        ordered(
            self,
            self.replace,
            "DetachUserPageByIndexLocked",
            "TlbShootdownAddr",
            "FreeFrame",
            "reservation_token = 0",
            "--as->reservation_count",
            "return true",
        )

    def test_protect_refuses_live_reservation_before_pte_rewrite(self) -> None:
        ordered(
            self,
            self.protect,
            "AddressSpaceMutationGuard mutation(*as)",
            "RangeOverlapsReservation(as, virt, virt + kPageSize)",
            "WalkToPteIn",
            "*pte =",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
