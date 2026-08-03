#!/usr/bin/env python3
"""Red-first contract for generation-safe Win32 Process handles.

This is intentionally a structural gate.  It keeps the Process object as the
stable refcounted lifetime header while requiring the public Win32 token to
carry an exact, non-wrapping row generation.  The parser masks comments and
all C/C++ literal forms before looking for production evidence so prose cannot
turn a missing implementation green.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"
FILE_SYSCALL_CPP = ROOT / "kernel" / "subsystems" / "win32" / "file_syscall.cpp"
NTDLL_INFO_C = ROOT / "userland" / "libs" / "ntdll" / "ntdll_info.c"


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving offsets/newlines."""
    masked = list(source)

    def blank(begin: int, end: int) -> None:
        for offset in range(begin, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end < 0:
                end = len(source)
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

        raw_prefix = next(
            (prefix for prefix in ('u8R"', 'uR"', 'UR"', 'LR"', 'R"') if source.startswith(prefix, index)),
            None,
        )
        if raw_prefix is not None:
            delimiter_begin = index + len(raw_prefix)
            open_paren = source.find("(", delimiter_begin, delimiter_begin + 17)
            if open_paren >= 0:
                delimiter = source[delimiter_begin:open_paren]
                if not re.search(r"[\s\\()]", delimiter):
                    terminator = ")" + delimiter + '"'
                    end = source.find(terminator, open_paren + 1)
                    if end < 0:
                        raise AssertionError("unterminated raw string literal")
                    end += len(terminator)
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
        raise AssertionError(f"missing opening {left!r}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} region")


def function_body(source: str, signature: str) -> str:
    """Return a definition body, skipping declarations and masked decoys."""
    code = code_only(source)
    found_signature = False
    for match in re.finditer(signature + r"\s*\(", code):
        found_signature = True
        opening_paren = code.find("(", match.start())
        closing_paren = matching_delimiter(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        declaration_end = code.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            closing_brace = matching_delimiter(code, opening_brace, "{", "}")
            return code[opening_brace + 1 : closing_brace]
    qualifier = "definition" if found_signature else "signature"
    raise AssertionError(f"missing function {qualifier}: {signature}")


def type_body(source: str, declaration: str) -> str:
    code = code_only(source)
    match = re.search(declaration + r"[^;{]*\{", code)
    if match is None:
        raise AssertionError(f"missing type definition: {declaration}")
    opening = code.find("{", match.start())
    closing = matching_delimiter(code, opening, "{", "}")
    return code[opening + 1 : closing]


def require_pattern(source: str, pattern: str, message: str) -> re.Match[str]:
    match = re.search(pattern, source, re.DOTALL)
    if match is None:
        raise AssertionError(message)
    return match


def reject_pattern(source: str, pattern: str, message: str) -> None:
    if re.search(pattern, source, re.DOTALL) is not None:
        raise AssertionError(message)


def compact(source: str) -> str:
    return re.sub(r"\s+", "", source)


def manual_lock_span(source: str, lock_expression: str, target: int) -> tuple[int, int]:
    """Find the manual SpinLock critical section containing target."""
    acquire = re.compile(r"(?:sync::)?SpinLockAcquire\s*\(\s*" + lock_expression + r"\s*\)")
    release = re.compile(r"(?:sync::)?SpinLockRelease\s*\(\s*" + lock_expression + r"\b")
    for lock in reversed([match for match in acquire.finditer(source) if match.start() < target]):
        unlock = release.search(source, lock.end())
        if unlock is not None and target < unlock.start():
            return lock.start(), unlock.start()
    raise AssertionError("target is not inside the expected handle-table lock")


class StructuralParserHostileTests(unittest.TestCase):
    def test_comments_and_every_literal_form_are_invisible(self) -> None:
        hostile = r'''
// bool DecodeWin32ProcessHandle(u64 h, Identity* out) { return true; }
/* enum class Win32ProcessHandleState { Free, Live, Retired }; */
const char* ordinary = "Process::kWin32ProcessHandleMaxGeneration";
const char character = '}';
const char* raw = u8R"tag(ProcessRetain(target); } // not code)tag";
int visible_token = 7;
'''
        visible = code_only(hostile)
        self.assertNotIn("DecodeWin32ProcessHandle", visible)
        self.assertNotIn("Win32ProcessHandleState", visible)
        self.assertNotIn("ProcessRetain", visible)
        self.assertIn("int visible_token = 7;", visible)

    def test_function_parser_skips_prototypes_and_literal_braces(self) -> None:
        hostile = r'''
bool DecodeWin32ProcessHandle(u64, Identity*);
const char* decoy = "bool DecodeWin32ProcessHandle(u64, Identity*) { return false; }";
bool DecodeWin32ProcessHandle(u64 value, Identity* out)
{
    const char* braces = R"raw( } { /* )raw";
    return value != 0 && out != nullptr;
}
bool Later() { return false; }
'''
        body = function_body(hostile, r"bool\s+DecodeWin32ProcessHandle")
        self.assertIn("return value != 0 && out != nullptr;", body)
        self.assertNotIn("bool Later", body)

    def test_type_parser_ignores_comment_and_string_decoys(self) -> None:
        hostile = r'''
// struct Win32ProcessHandleIdentity { u32 slot; u32 generation; };
const char* decoy = "struct Win32ProcessHandleIdentity { int fake; };";
struct Win32ProcessHandleIdentity
{
    u32 slot;
    u32 generation;
};
'''
        body = type_body(hostile, r"struct\s+Win32ProcessHandleIdentity")
        self.assertIn("u32 slot;", body)
        self.assertIn("u32 generation;", body)
        self.assertNotIn("fake", body)

    def test_lock_parser_does_not_count_work_after_unlock(self) -> None:
        source = "SpinLockAcquire(owner->lock); exact_match(); SpinLockRelease(owner->lock, flags); release_ref();"
        inside = source.index("exact_match")
        lock_begin, lock_end = manual_lock_span(source, r"owner->lock", inside)
        self.assertIn("exact_match", source[lock_begin:lock_end])
        with self.assertRaisesRegex(AssertionError, "not inside"):
            manual_lock_span(source, r"owner->lock", source.index("release_ref"))


class ProcessHandleGenerationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")
        cls.file_syscall_cpp = FILE_SYSCALL_CPP.read_text(encoding="utf-8")
        cls.ntdll_info_c = NTDLL_INFO_C.read_text(encoding="utf-8")
        cls.process_h_code = code_only(cls.process_h)

    def test_header_declares_positive_generation_tagged_process_identity(self) -> None:
        state = type_body(self.process_h, r"enum\s+class\s+Win32ProcessHandleState")
        for member in ("Free", "Live", "Retired"):
            with self.subTest(member=member):
                self.assertRegex(state, rf"\b{member}\b")

        row = type_body(self.process_h, r"struct\s+Win32ProcessHandle")
        identity = type_body(self.process_h, r"struct\s+Win32ProcessHandleIdentity")
        self.assertRegex(row, r"\bu32\s+generation\s*;")
        self.assertRegex(row, r"\bWin32ProcessHandleState\s+state\s*;")
        self.assertRegex(row, r"\bProcess\s*\*\s*target\s*;")
        self.assertNotRegex(row, r"\bbool\s+in_use\s*;")
        self.assertRegex(identity, r"\bu32\s+slot\s*;")
        self.assertRegex(identity, r"\bu32\s+generation\s*;")

        constants = (
            r"kWin32ProcessHandleTagMask\s*=\s*0x[Ff]{3}",
            r"kWin32ProcessHandleGenerationShift\s*=\s*12",
            r"kWin32ProcessHandleMaxValue\s*=\s*\(\s*1ULL\s*<<\s*31\s*\)\s*-\s*1",
            r"kWin32ProcessHandleMaxGeneration\s*=\s*[^;]*kWin32ProcessHandleMaxValue[^;]*"
            r"kWin32ProcessHandleGenerationShift",
        )
        for pattern in constants:
            with self.subTest(pattern=pattern):
                require_pattern(self.process_h_code, pattern, "missing positive generation-tagged Process constant")

        for declaration in (
            r"u64\s+EncodeWin32ProcessHandle\s*\(\s*const\s+Process::Win32ProcessHandleIdentity\s*&",
            r"bool\s+DecodeWin32ProcessHandle\s*\(\s*u64\s+\w+\s*,\s*"
            r"Process::Win32ProcessHandleIdentity\s*\*",
            r"bool\s+IsWin32ProcessHandle\s*\(\s*u64\s+\w+\s*\)",
        ):
            with self.subTest(declaration=declaration):
                require_pattern(self.process_h_code, declaration, "missing opaque Process handle helper declaration")

    def test_encode_decode_validate_width_sign_generation_tag_and_slot(self) -> None:
        encode = function_body(self.process_cpp, r"u64\s+EncodeWin32ProcessHandle")
        decode = function_body(self.process_cpp, r"bool\s+DecodeWin32ProcessHandle")
        is_handle = function_body(self.process_cpp, r"bool\s+IsWin32ProcessHandle")

        require_pattern(encode, r"identity\.slot\s*>=\s*Process::kWin32ProcessCap", "encode accepts bad slot")
        require_pattern(encode, r"identity\.generation\s*==\s*0", "encode accepts generation zero")
        require_pattern(
            encode,
            r"identity\.generation\s*>\s*Process::kWin32ProcessHandleMaxGeneration",
            "encode accepts overflowing generation",
        )
        require_pattern(
            encode,
            r"identity\.generation[^;]*<<\s*Process::kWin32ProcessHandleGenerationShift[^;]*\|",
            "encode does not place generation above the low tag",
        )
        require_pattern(encode, r"Process::kWin32ProcessBase\s*\+\s*identity\.slot", "encode lost Process tag")

        require_pattern(decode, r"identity_out\s*==\s*nullptr", "decode accepts null output")
        require_pattern(
            decode,
            r"handle\s*>\s*Process::kWin32ProcessHandleMaxValue",
            "decode accepts bit 31 or upper bits",
        )
        require_pattern(
            decode,
            r"handle\s*>>\s*Process::kWin32ProcessHandleGenerationShift",
            "decode does not extract generation",
        )
        require_pattern(
            decode,
            r"handle\s*&\s*Process::kWin32ProcessHandleTagMask",
            "decode does not isolate the low tag",
        )
        require_pattern(decode, r"generation\s*==\s*0", "decode accepts legacy generation-zero tokens")
        require_pattern(
            decode,
            r"generation\s*>\s*Process::kWin32ProcessHandleMaxGeneration",
            "decode accepts overflowing generation",
        )
        require_pattern(
            decode,
            r"tag\s*<\s*Process::kWin32ProcessBase[^;{}]*tag\s*>=\s*"
            r"Process::kWin32ProcessBase\s*\+\s*Process::kWin32ProcessCap",
            "decode does not validate the exact Process low-tag band",
        )
        require_pattern(
            decode,
            r"util::MaskedIndex(?:32)?\s*\(\s*tag\s*-\s*Process::kWin32ProcessBase\s*,\s*"
            r"Process::kWin32ProcessCap\s*\)",
            "decode does not nospec-mask the validated slot",
        )
        self.assertIn("DecodeWin32ProcessHandle", is_handle)

    def test_install_advances_generation_and_retires_exhausted_rows(self) -> None:
        install = function_body(self.process_cpp, r"u64\s+ProcessInstallWin32ProcessHandle")
        require_pattern(
            install,
            r"\.state\s*!=\s*Process::Win32ProcessHandleState::Free|"
            r"\.state\s*==\s*Process::Win32ProcessHandleState::Free",
            "install does not allocate only a Free row",
        )
        require_pattern(
            install,
            r"\.generation\s*>=\s*Process::kWin32ProcessHandleMaxGeneration",
            "install can wrap a terminal generation",
        )
        generation = require_pattern(install, r"\+\+\s*\w+\.generation", "install does not advance row generation")
        target = require_pattern(install, r"\w+\.target\s*=\s*target\s*;", "install does not publish target header")
        live = require_pattern(
            install,
            r"\w+\.state\s*=\s*Process::Win32ProcessHandleState::Live\s*;",
            "install does not publish a Live row",
        )
        encoded = require_pattern(
            install,
            r"EncodeWin32ProcessHandle\s*\(\s*Process::Win32ProcessHandleIdentity\s*\{[^}]*\}\s*\)",
            "install returns no exact encoded row identity",
        )
        self.assertLess(generation.start(), target.start())
        self.assertLess(target.start(), live.start())
        self.assertGreaterEqual(encoded.start(), 0)
        reject_pattern(
            install,
            r"return[^;]*Process::kWin32ProcessBase\s*\+\s*(?:slot|i)\b",
            "install still exposes a raw base-plus-slot token",
        )

    def test_lookup_decodes_and_retain_pins_only_the_exact_live_generation(self) -> None:
        lookup = function_body(self.process_cpp, r"Process\s*\*\s*ProcessLookupWin32ProcessHandleRetained")
        decoded = require_pattern(
            lookup,
            r"DecodeWin32ProcessHandle\s*\(\s*handle\s*,\s*&\w+\s*\)",
            "lookup does not decode the opaque identity",
        )
        reject_pattern(
            lookup,
            r"\bhandle\s*-\s*Process::kWin32ProcessBase",
            "lookup derives a slot directly from the untrusted raw token",
        )
        exact = require_pattern(
            lookup,
            r"\.state\s*==\s*Process::Win32ProcessHandleState::Live[^{};]*"
            r"\.generation\s*==\s*\w+\.generation[^{};]*\.target\s*!=\s*nullptr",
            "lookup does not match Live state, exact generation, and target together",
        )
        retained = require_pattern(lookup, r"ProcessRetain\s*\(\s*\w+\s*\)", "lookup does not retain the target")
        lock_begin, lock_end = manual_lock_span(lookup, r"owner->win32_handle_lock", exact.start())
        self.assertLess(decoded.start(), lock_begin)
        self.assertLess(exact.start(), retained.start())
        self.assertLess(retained.end(), lock_end)

    def test_close_decodes_exact_generation_and_retires_terminal_row(self) -> None:
        close = function_body(self.process_cpp, r"bool\s+ProcessCloseWin32ProcessHandle")
        decoded = require_pattern(
            close,
            r"DecodeWin32ProcessHandle\s*\(\s*handle\s*,\s*&\w+\s*\)",
            "close does not decode the opaque identity",
        )
        reject_pattern(
            close,
            r"\bhandle\s*-\s*Process::kWin32ProcessBase",
            "close derives a slot directly from the untrusted raw token",
        )
        exact = require_pattern(
            close,
            r"\.state\s*==\s*Process::Win32ProcessHandleState::Live[^{};]*"
            r"\.generation\s*==\s*\w+\.generation",
            "close does not require the exact live generation",
        )
        lock_begin, lock_end = manual_lock_span(close, r"owner->win32_handle_lock", exact.start())
        locked = close[lock_begin:lock_end]
        require_pattern(locked, r"\.target\s*=\s*nullptr\s*;", "close does not detach the Process pointer")
        require_pattern(
            locked,
            r"\.generation\s*==\s*Process::kWin32ProcessHandleMaxGeneration",
            "close does not identify the terminal generation",
        )
        self.assertIn("Win32ProcessHandleState::Retired", locked)
        self.assertIn("Win32ProcessHandleState::Free", locked)
        release = require_pattern(close, r"ProcessRelease\s*\(\s*\w+\s*\)", "close leaks the stable Process ref")
        self.assertLess(decoded.start(), lock_begin)
        self.assertGreater(release.start(), lock_end, "ProcessRelease runs while the row lock is held")

    def test_drain_preserves_generations_and_uses_terminal_retirement(self) -> None:
        drain = function_body(self.process_cpp, r"void\s+ProcessDropOwnedProcessHandles")
        live = require_pattern(
            drain,
            r"\.state\s*==\s*Process::Win32ProcessHandleState::Live|"
            r"\.state\s*!=\s*Process::Win32ProcessHandleState::Live",
            "drain does not select only live rows",
        )
        lock_begin, lock_end = manual_lock_span(drain, r"p->win32_handle_lock", live.start())
        locked = drain[lock_begin:lock_end]
        require_pattern(locked, r"\.target\s*=\s*nullptr\s*;", "drain does not detach row targets")
        require_pattern(
            locked,
            r"\.generation\s*==\s*Process::kWin32ProcessHandleMaxGeneration",
            "drain does not preserve terminal-generation retirement",
        )
        self.assertIn("Win32ProcessHandleState::Retired", locked)
        self.assertIn("Win32ProcessHandleState::Free", locked)
        reject_pattern(locked, r"\.generation\s*=\s*0\s*;", "drain resets generation and enables ABA reuse")
        release = require_pattern(drain, r"ProcessRelease\s*\(", "drain does not release detached Process refs")
        self.assertGreater(release.start(), lock_end, "drain releases Process refs while the row lock is held")

    def test_process_headers_remain_stable_refcounted_targets(self) -> None:
        row = type_body(self.process_h, r"struct\s+Win32ProcessHandle")
        self.assertRegex(row, r"\bProcess\s*\*\s*target\s*;")
        self.assertNotRegex(row, r"\b(?:pid|target_pid)\b")

        lookup = function_body(self.process_cpp, r"Process\s*\*\s*ProcessLookupWin32ProcessHandleRetained")
        retain = require_pattern(lookup, r"ProcessRetain\s*\(", "lookup no longer pins the Process header")
        lock_begin, lock_end = manual_lock_span(lookup, r"owner->win32_handle_lock", retain.start())
        self.assertLess(lock_begin, retain.start())
        self.assertLess(retain.end(), lock_end)
        reject_pattern(lookup, r"SchedFindProcessByPid", "lookup re-resolves a recyclable PID instead of the header")

        close = function_body(self.process_cpp, r"bool\s+ProcessCloseWin32ProcessHandle")
        unlock = require_pattern(close, r"SpinLockRelease\s*\(\s*owner->win32_handle_lock", "close never unlocks")
        release = require_pattern(close, r"ProcessRelease\s*\(", "close no longer releases the owned header ref")
        self.assertLess(unlock.start(), release.start())

    def test_kernel_and_userland_dispatch_classify_the_generation_tagged_value(self) -> None:
        close = function_body(self.file_syscall_cpp, r"void\s+DoFileClose")
        require_pattern(
            close,
            r"IsWin32ProcessHandle\s*\(\s*handle\s*\)",
            "CloseHandle dispatch does not recognize opaque Process handles",
        )
        reject_pattern(
            close,
            r"handle\s*>=\s*core::Process::kWin32ProcessBase[^{};]*handle\s*<\s*"
            r"core::Process::kWin32ProcessBase\s*\+\s*core::Process::kWin32ProcessCap",
            "CloseHandle dispatch still assumes a raw slot-only Process band",
        )

        classifier = function_body(self.ntdll_info_c, r"static\s+const\s+wchar_t16\s*\*\s*HandleRangeToTypeName")
        require_pattern(
            classifier,
            r"opaque_kobj\s*&&\s*low_tag\s*>=?\s*0x700(?:ULL)?\s*&&\s*"
            r"low_tag\s*<\s*0x708(?:ULL)?",
            "NtQueryObject does not classify generation-tagged Process low tags",
        )
        reject_pattern(
            classifier,
            r"\bhandle\s*>=\s*0x700(?:ULL)?\s*&&\s*handle\s*<\s*0x708(?:ULL)?",
            "NtQueryObject still classifies only raw slot-only Process handles",
        )

    def test_selftest_proves_close_reuse_stale_rejection_retirement_and_drain(self) -> None:
        selftest = function_body(self.process_cpp, r"void\s+ProcessHandleLifetimeSelfTest")
        require_pattern(
            selftest,
            r"!\s*IsWin32ProcessHandle\s*\(\s*Process::kWin32ProcessBase\s*\)",
            "selftest does not reject the legacy slot-only Process token",
        )
        require_pattern(
            selftest,
            r"DecodeWin32ProcessHandle\s*\([^;]*\)[^;]*\.slot\s*==[^;]*\.generation\s*==",
            "selftest does not round-trip an exact Process row identity",
        )
        require_pattern(
            selftest,
            r"ProcessInstallWin32ProcessHandle\s*\([^;]*\)[\s\S]*?"
            r"ProcessCloseWin32ProcessHandle\s*\([^;]*\)[\s\S]*?"
            r"ProcessInstallWin32ProcessHandle\s*\(",
            "selftest does not exercise close followed by row reuse",
        )
        require_pattern(
            selftest,
            r"!=\s*[^;]*first[^;]*handle|second[^;]*handle\s*!=\s*first[^;]*handle",
            "selftest does not require a distinct token after same-row reuse",
        )
        require_pattern(
            selftest,
            r"ProcessLookupWin32ProcessHandleRetained\s*\([^,]+,\s*first[^)]*handle\s*\)\s*==\s*nullptr",
            "selftest does not reject stale lookup after reuse",
        )
        require_pattern(
            selftest,
            r"!\s*ProcessCloseWin32ProcessHandle\s*\([^,]+,\s*first[^)]*handle\s*\)",
            "selftest does not reject stale close after reuse",
        )
        require_pattern(
            selftest,
            r"kWin32ProcessHandleMaxGeneration[\s\S]*?Win32ProcessHandleState::Retired",
            "selftest does not prove terminal-generation retirement",
        )
        drain = require_pattern(
            selftest,
            r"ProcessDropOwnedProcessHandles\s*\([^)]*\)",
            "selftest does not exercise Process-handle drain",
        )
        stale_after_drain = require_pattern(
            selftest[drain.end() :],
            r"ProcessLookupWin32ProcessHandleRetained\s*\([^)]*\)\s*==\s*nullptr",
            "selftest does not prove a drained token is stale",
        )
        self.assertGreater(stale_after_drain.start(), 0)


if __name__ == "__main__":
    unittest.main()
