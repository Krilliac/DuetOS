#!/usr/bin/env python3
"""Hostile structural contract for Win32 thread/TLS VM lifetime safety."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "kernel/subsystems/win32/thread_syscall.cpp").read_text(
    encoding="utf-8"
)


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals so prose cannot satisfy a check."""
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
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", code):
        opening_paren = code.find("(", match.start())
        closing_paren = matching_delimiter(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren)
        semicolon = code.find(";", closing_paren)
        if opening_brace < 0 or (semicolon >= 0 and semicolon < opening_brace):
            continue
        closing_brace = matching_delimiter(code, opening_brace, "{", "}")
        return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function definition: {name}")


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class Win32ThreadTlsVmSafetyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.code = code_only(SOURCE)
        cls.range_valid = function_body(SOURCE, "UserRangeIsValid")
        cls.range_read = function_body(SOURCE, "ReadUserRange")
        cls.frame_init = function_body(SOURCE, "AllocateInitializedFrame")
        cls.page_replace = function_body(SOURCE, "ReplaceOwnedUserPageFromKernel")
        cls.tls_setup = function_body(SOURCE, "SetupPerThreadTls")
        cls.thread_create = function_body(SOURCE, "DoThreadCreate")

    def test_parser_rejects_comments_literals_and_declarations(self) -> None:
        hostile = r'''
        // Target() { AddressSpaceReadUserMemory(fake); }
        const char* text = "Target() { PhysToVirt(fake); }";
        void Target();
        void Target() { int visible = 7; }
        '''
        body = function_body(hostile, "Target")
        self.assertIn("visible", body)
        self.assertNotIn("AddressSpaceReadUserMemory", body)
        self.assertNotIn("PhysToVirt", body)

    def test_no_unpinned_address_space_frame_lookup_remains(self) -> None:
        self.assertNotIn("AddressSpaceLookupUserFrame", self.code)
        self.assertNotIn("MapOrReuse", self.code)
        self.assertNotIn("AsReadInto", self.code)
        self.assertEqual(
            self.code.count("PhysToVirt"),
            1,
            "direct-map access is allowed only for a freshly allocated private frame",
        )
        self.assertIn("PhysToVirt", self.frame_init)
        self.assertNotIn("AddressSpace", self.frame_init)

    def test_user_read_is_overflow_checked_and_page_transaction_bounded(self) -> None:
        self.assertIn("len <= kUserMaxExclusive - user_va", self.range_valid)
        self.assertIn("UserRangeIsValid(user_va, len)", self.range_read)
        ordered(
            self,
            self.range_read,
            "mm::kPageSize - (user_va & (mm::kPageSize - 1))",
            "AddressSpaceReadUserMemory(as, user_va, destination, chunk)",
            "user_va += chunk",
            "destination += chunk",
            "len -= chunk",
        )

    def test_fresh_frame_is_initialized_before_atomic_ownership_transfer(self) -> None:
        ordered(
            self,
            self.frame_init,
            "mm::AllocateFrame()",
            "mm::PhysToVirt(frame)",
            "return frame",
        )
        ordered(
            self,
            self.page_replace,
            "AllocateInitializedFrame(initial, initial_len)",
            "AddressSpaceUnmapUserPage(as, user_va)",
            "AddressSpaceMapUserPage(as, user_va, frame, flags)",
            "mm::FreeFrame(frame)",
        )
        self.assertIsNotNone(
            re.search(
                r"if\s*\(\s*!mm::AddressSpaceMapUserPage.*?\)\s*\{.*?mm::FreeFrame\(frame\).*?return false",
                self.page_replace,
                re.S,
            )
        )

    def test_tls_template_and_trampoline_are_bounded_and_transactional(self) -> None:
        self.assertIn("proc->tls_tmpl_raw > kTlsTemplateMaxBytes", self.tls_setup)
        self.assertIn(
            "proc->tls_tmpl_zerofill > kTlsTemplateMaxBytes - proc->tls_tmpl_raw",
            self.tls_setup,
        )
        self.assertIn(
            "UserRangeIsValid(proc->tls_tmpl_src_va, proc->tls_tmpl_raw)",
            self.tls_setup,
        )
        self.assertIn(
            "ReadUserRange(proc->as, proc->user_gs_base, page_image, mm::kPageSize)",
            self.tls_setup,
        )
        self.assertIn(
            "ReadUserRange(proc->as, proc->tls_tmpl_src_va + page_offset, page_image, raw_on_page)",
            self.tls_setup,
        )
        self.assertGreaterEqual(self.tls_setup.count("ReplaceOwnedUserPageFromKernel"), 4)
        self.assertIn("if (n >= sizeof(page_image))", self.tls_setup)
        self.assertIn("!emit_ok", self.tls_setup)
        self.assertNotIn("PhysToVirt", self.tls_setup)

    def test_stack_return_address_uses_vm_write_after_reserved_map(self) -> None:
        self.assertNotIn("PhysToVirt", self.thread_create)
        ordered(
            self,
            self.thread_create,
            "AddressSpaceMapReservedUserPage",
            "AddressSpaceWriteUserMemory(proc->as, user_rsp, &thread_exit_va, sizeof(thread_exit_va))",
            "mm::KMalloc(sizeof(ThreadDesc))",
        )
        write_failure = self.thread_create[
            self.thread_create.index("if (!mm::AddressSpaceWriteUserMemory") :
        ]
        ordered(
            self,
            write_failure,
            "unwind_stack()",
            "release_claimed_slot()",
            "frame->rax = static_cast<u64>(-1)",
            "return",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
