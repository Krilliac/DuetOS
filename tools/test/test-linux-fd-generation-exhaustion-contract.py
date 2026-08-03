#!/usr/bin/env python3
"""Hostile structural contract for non-wrapping Linux fd identities."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HEADER = (ROOT / "kernel/proc/process.h").read_text(encoding="utf-8")
SOURCE = (ROOT / "kernel/proc/process.cpp").read_text(encoding="utf-8")


def code_only(source: str) -> str:
    """Blank comments and literals so prose cannot satisfy the contract."""
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


class LinuxFdGenerationExhaustionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.code = code_only(SOURCE)
        cls.next_generation = function_body(SOURCE, "LinuxFdNextGeneration")
        cls.clear_slot = function_body(SOURCE, "LinuxFdClearSlotLocked")
        cls.find_lowest = function_body(SOURCE, "LinuxFdFindLowestLocked")
        cls.publish = function_body(SOURCE, "LinuxFdPublishLocked")
        cls.import_exact = function_body(SOURCE, "LinuxFdImportExact")
        cls.import_table = function_body(SOURCE, "LinuxFdImportTable")
        cls.open_description = function_body(SOURCE, "LinuxFdOpenDescription")
        cls.attach = function_body(SOURCE, "LinuxFdAttachKFile")
        cls.selftest = function_body(SOURCE, "LinuxFdSelfTest")

    def test_parser_rejects_comment_and_literal_decoys(self) -> None:
        hostile = '''
// Process::kLinuxFdGenerationExhausted
const char* fake = "LinuxFdNextGeneration(slot.generation, &next)";
int visible = 9;
'''
        visible = code_only(hostile)
        self.assertNotIn("kLinuxFdGenerationExhausted", visible)
        self.assertNotIn("LinuxFdNextGeneration", visible)
        self.assertIn("int visible = 9;", visible)

    def test_header_reserves_a_terminal_generation(self) -> None:
        header = code_only(HEADER)
        self.assertIn("kLinuxFdGenerationExhausted = static_cast<u32>(-1)", header)

    def test_advance_fails_closed_instead_of_wrapping_to_one(self) -> None:
        self.assertIn("generation == Process::kLinuxFdGenerationExhausted", self.next_generation)
        self.assertIn("*next_out = 0", self.next_generation)
        self.assertNotIn("generation == 0 ? 1", self.next_generation)
        ordered(self, self.next_generation, "*next_out = 0", "kLinuxFdGenerationExhausted", "return false")

    def test_close_preserves_saturation_and_allocator_skips_retired_slot(self) -> None:
        # LinuxFdNextGeneration zeroes its out-param *before* deciding whether
        # the epoch may advance, so the only safe way to clear a slot is to
        # branch on its return value. Seeding a local with the exhausted marker
        # and discarding the return publishes generation 0 on a saturated slot,
        # which un-retires it — the boot self-test panics with "saturated fd
        # slot became reusable". This test previously pinned that exact broken
        # sequence as the contract, so it passed while the kernel paniced;
        # assert the invariant instead of the statement order.
        ordered(
            self,
            self.clear_slot,
            "LinuxFdNextGeneration(slot.generation,",
            "LinuxFdClearSnapshot(&slot)",
            "slot.generation =",
        )
        # The return value must be captured, never discarded.
        self.assertNotIn("(void)LinuxFdNextGeneration", self.clear_slot)
        # ...and the saturated marker must be the fallback when it fails.
        self.assertRegex(
            self.clear_slot,
            r"slot\.generation\s*=[^;]*Process::kLinuxFdGenerationExhausted",
        )
        self.assertIn("generation != Process::kLinuxFdGenerationExhausted", self.find_lowest)

    def test_publish_checks_epoch_before_overwriting_destination(self) -> None:
        ordered(
            self,
            self.publish,
            "LinuxFdNextGeneration(destination.generation, &generation)",
            "return false",
            "destination = source",
            "destination.generation = generation",
        )

    def test_exact_and_table_imports_preflight_before_handle_mutation(self) -> None:
        ordered(
            self,
            self.import_exact,
            "LinuxFdNextGeneration(slot.generation, &next_generation)",
            "HandleTableAdoptReplace",
            "LinuxFdPublishLocked",
        )
        ordered(
            self,
            self.import_table,
            "LinuxFdNextGeneration(destination->linux_fds[fd].generation, &next_generation)",
            "HandleTableInsert",
            "LinuxFdPublishLocked",
        )

    def test_identity_sidecars_and_ofd_attach_preflight_generation(self) -> None:
        ordered(
            self,
            self.attach,
            "LinuxFdNextGeneration(slot.generation, &next_generation)",
            "HandleTableInsert",
            "slot.generation = next_generation",
        )
        ordered(
            self,
            self.open_description,
            "LinuxFdNextGeneration(lf.generation, &next_generation)",
            "OfdAllocLocked",
            "lf.generation = next_generation",
        )

    def test_runtime_selftest_saturates_detaches_and_refuses_reuse(self) -> None:
        ordered(
            self,
            self.selftest,
            "exhausted_slot.generation = Process::kLinuxFdGenerationExhausted",
            "LinuxFdUnbind(p, 15, &exhausted_detached)",
            "LinuxFdAllocLowest(p, 15)",
            "LinuxFdNextGeneration(Process::kLinuxFdGenerationExhausted, &forbidden_next)",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
