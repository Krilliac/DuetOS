#!/usr/bin/env python3
"""Hostile structural contract for epoll's retained fd identity.

The contract keeps epoll watch lookup and readiness tied to the exact retained
fd-table transaction receipt rather than a numeric fd that close/reuse can
retarget.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
ASYNC_CPP = ROOT / "kernel" / "subsystems" / "linux" / "syscall_async_io.cpp"


def code_only(source: str) -> str:
    """Blank C/C++ comments and literals while preserving source offsets."""
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
                        raise AssertionError("unterminated raw string")
                    end += len(terminator)
                    blank(index, end)
                    index = end
                    continue

        # C++ digit separators are code, not the start of a character literal.
        if (
            source[index] == "'"
            and index > 0
            and index + 1 < len(source)
            and source[index - 1].isalnum()
            and source[index + 1].isalnum()
        ):
            index += 1
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


def matching_delimiter(source: str, opening: int, left: str = "{", right: str = "}") -> int:
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


def function_region(source: str, signature: str) -> str:
    code = code_only(source)
    for match in re.finditer(signature + r"\s*\(", code):
        opening_paren = code.find("(", match.start())
        closing_paren = matching_delimiter(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        declaration_end = code.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            closing_brace = matching_delimiter(code, opening_brace)
            return code[match.start() : closing_brace + 1]
    raise AssertionError(f"missing function definition: {signature}")


def function_body(source: str, signature: str) -> str:
    region = function_region(source, signature)
    opening = region.find("{")
    return region[opening + 1 : matching_delimiter(region, opening)]


def type_body(source: str, declaration: str) -> str:
    code = code_only(source)
    match = re.search(declaration + r"[^;{]*\{", code)
    if match is None:
        raise AssertionError(f"missing type definition: {declaration}")
    opening = code.find("{", match.start())
    return code[opening + 1 : matching_delimiter(code, opening)]


def guarded_block_regex(source: str, guard_pattern: str) -> str:
    """Return the innermost lexical block containing a guard expression."""
    code = code_only(source)
    match = re.search(guard_pattern, code)
    if match is None:
        raise AssertionError(f"PRODUCTION RED: missing scoped lock guard matching {guard_pattern}")
    target = match.start()
    stack: list[int] = []
    candidates: list[tuple[int, int]] = []
    for index, char in enumerate(code):
        if char == "{":
            stack.append(index)
        elif char == "}":
            opening = stack.pop()
            if opening < target < index:
                candidates.append((opening, index))
    if not candidates:
        raise AssertionError("PRODUCTION RED: async lock guard has no lexical release boundary")
    opening, closing = max(candidates, key=lambda pair: pair[0])
    return code[opening + 1 : closing]


def require_token(test: unittest.TestCase, source: str, token: str, gap: str) -> int:
    position = source.find(token)
    test.assertGreaterEqual(position, 0, f"PRODUCTION RED: {gap}; missing {token}")
    return position


def require_pattern(test: unittest.TestCase, source: str, pattern: str, gap: str) -> re.Match[str]:
    match = re.search(pattern, source)
    test.assertIsNotNone(match, f"PRODUCTION RED: {gap}; missing /{pattern}/")
    assert match is not None
    return match


def require_type_body(test: unittest.TestCase, source: str, declaration: str, gap: str) -> str:
    try:
        return type_body(source, declaration)
    except AssertionError as error:
        test.fail(f"PRODUCTION RED: {gap}: {error}")
        raise AssertionError("unreachable")


class ParserHostileTests(unittest.TestCase):
    def test_comments_literals_raw_strings_and_digit_separators_are_masked(self) -> None:
        hostile = r'''
// LinuxFdAcquiredClone(&watch.acquired, &snap.acquired);
/* LinuxFdEpollReady(snap.acquired, snap.events); */
const char* ordinary = "LinuxFdAcquiredRelease(&detached);";
const char* raw = u8R"tag(core::LinuxFdAcquire(p, fd, &candidate); // } {)tag";
u64 visible = 10'000'000ull;
'''
        visible = code_only(hostile)
        self.assertNotIn("LinuxFdAcquiredClone", visible)
        self.assertNotIn("LinuxFdEpollReady", visible)
        self.assertNotIn("LinuxFdAcquiredRelease", visible)
        self.assertNotIn("LinuxFdAcquire", visible)
        self.assertIn("10'000'000ull", visible)

    def test_function_parser_skips_declaration_decoy(self) -> None:
        hostile = r'''
bool Clone(const Receipt* source, Receipt* out);
const char* decoy = "bool Clone() { return false; }";
bool Clone(const Receipt* source, Receipt* out) { return source != out; }
bool After() { return false; }
'''
        body = function_body(hostile, r"bool\s+Clone")
        self.assertIn("return source != out;", body)
        self.assertNotIn("bool After", body)

    def test_type_parser_skips_forward_and_literal_decoys(self) -> None:
        hostile = r'''
struct Receipt;
const char* decoy = "struct Receipt { u64 fake; };";
struct Receipt { u64 generation; };
'''
        body = type_body(hostile, r"struct\s+Receipt")
        self.assertIn("u64 generation;", body)
        self.assertNotIn("fake", body)


class EpollFdIdentityProductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_h_code = code_only(cls.process_h)
        cls.async_cpp = ASYNC_CPP.read_text(encoding="utf-8")

    def test_acquired_receipt_pins_exact_generation_kfile_and_ofd(self) -> None:
        linux_fd = require_type_body(
            self,
            self.process_h,
            r"struct\s+LinuxFd",
            "Linux fd slot type is unavailable",
        )
        self.assertRegex(
            linux_fd,
            r"\bu32\s+generation\s*;",
            "PRODUCTION RED: Linux fd slots lack a non-wrapping reuse generation",
        )

        acquired = require_type_body(
            self,
            self.process_h,
            r"struct\s+LinuxFdAcquired",
            "strong fd acquisition receipt is not declared",
        )
        self.assertRegex(
            acquired,
            r"\bProcess::LinuxFd\s+snapshot\s*;",
            "PRODUCTION RED: acquired fd receipt lacks the exact generation-bearing slot snapshot",
        )
        self.assertRegex(
            acquired,
            r"\bipc::KObject\s*\*\s*kfile_ref\s*;",
            "PRODUCTION RED: acquired fd receipt does not retain the exact KFile identity",
        )
        self.assertRegex(
            acquired,
            r"\bbool\s+owns_ofd_ref\s*;",
            "PRODUCTION RED: acquired fd receipt does not own an explicit OFD reference",
        )
        for api in ("LinuxFdAcquire", "LinuxFdAcquiredClone", "LinuxFdAcquiredRelease"):
            require_token(self, self.process_h_code, api, "fd receipt API is not declared")

    def test_watch_owns_acquired_identity_and_keeps_numeric_fd_only_as_key(self) -> None:
        watch = require_type_body(
            self,
            self.async_cpp,
            r"struct\s+EpollWatch",
            "epoll watch type is unavailable",
        )
        self.assertRegex(
            watch,
            r"\bu32\s+source_fd\s*;",
            "PRODUCTION RED: epoll watch lacks the numeric half of its {fd,generation} control key",
        )
        self.assertRegex(
            watch,
            r"\bcore::LinuxFdAcquired\s+acquired\s*;",
            "PRODUCTION RED: epoll watch still stores only a numeric fd instead of strong KFile/OFD identity",
        )
        self.assertNotRegex(
            watch,
            r"\bu32\s+fd\s*;",
            "PRODUCTION RED: ambiguous watch.fd remains the apparent readiness authority; name the key source_fd",
        )

    def test_ctl_acquires_before_async_lock_matches_exact_identity_and_releases_after(self) -> None:
        ctl = function_body(self.async_cpp, r"i64\s+DoEpollCtl")
        acquire = require_token(self, ctl, "LinuxFdAcquire(", "epoll_ctl does not pin the submitted fd identity")
        guard_match = require_pattern(
            self,
            ctl,
            r"SpinLockGuard\s+\w+\s*\(\s*g_async_lock\s*\)",
            "epoll_ctl needs a bounded async-table mutation scope",
        )
        self.assertLess(
            acquire,
            guard_match.start(),
            "PRODUCTION RED: epoll_ctl acquires the fd identity while holding g_async_lock",
        )

        locked = guarded_block_regex(ctl, r"SpinLockGuard\s+\w+\s*\(\s*g_async_lock\s*\)")
        for token, gap in (
            ("EpollWatchMatchesIdentity", "watch lookup bypasses the exact identity predicate"),
            (".acquired", "watch publication does not adopt the strong fd receipt"),
        ):
            require_token(self, locked, token, gap)

        identity = function_body(self.async_cpp, r"bool\s+EpollWatchMatchesIdentity")
        for token, gap in (
            ("source_fd", "control identity omits the original numeric key"),
            ("snapshot.generation", "control identity omits the fd reuse generation"),
            ("snapshot.ofd", "control identity omits the pinned OFD"),
            ("kfile_ref", "control identity omits the exact retained KFile"),
        ):
            require_token(self, identity, token, gap)
        self.assertNotIn(
            "LinuxFdAcquiredRelease",
            locked,
            "PRODUCTION RED: epoll_ctl releases a KFile/OFD receipt while holding g_async_lock",
        )
        self.assertNotRegex(
            locked,
            r"\breturn\b",
            "PRODUCTION RED: epoll_ctl returns from the locked mutation scope before receipt cleanup",
        )
        self.assertNotRegex(
            locked,
            r"\.fd\s*==\s*fd\b",
            "PRODUCTION RED: epoll_ctl aliases a reused fd number without checking its generation",
        )

        outside = ctl.replace(locked, "", 1)
        require_token(self, outside, "LinuxFdAcquiredRelease", "epoll_ctl does not clean candidate/detached receipts")
        self.assertNotRegex(ctl, r"linux_fd_lock|fd_table_lock", "epoll_ctl reaches into the fd-table lock directly")

    def test_readiness_uses_only_acquired_identity_never_current_numeric_fd(self) -> None:
        region = function_region(self.async_cpp, r"u32\s+LinuxFdEpollReady")
        body = function_body(self.async_cpp, r"u32\s+LinuxFdEpollReady")
        self.assertRegex(
            region[: region.find("{")],
            r"LinuxFdEpollReady\s*\(\s*const\s+core::LinuxFdAcquired\s*&\s*acquired\s*,",
            "PRODUCTION RED: readiness still accepts a numeric fd instead of a retained identity",
        )
        for forbidden, gap in (
            ("CurrentProcess", "readiness re-resolves against whichever process happens to be current"),
            ("linux_fds", "readiness re-reads a numeric fd slot that close/reuse can retarget"),
            ("LinuxFdAcquire(", "readiness reacquires by numeric fd instead of consuming the watch pin"),
        ):
            self.assertNotIn(forbidden, body, f"PRODUCTION RED: {gap}")
        require_token(self, body, "acquired.snapshot.state", "readiness does not use captured descriptor metadata")
        require_token(self, body, "acquired.kfile_ref", "pidfd readiness does not use the retained KFile identity")

    def test_wait_clones_under_async_lock_then_releases_snapshots_after_unlock(self) -> None:
        wait = function_body(self.async_cpp, r"i64\s+DoEpollWait")
        clone = require_token(
            self,
            wait,
            "LinuxFdAcquiredClone(",
            "epoll_wait copies watch structs without retaining their KFile/OFD identities",
        )
        acquire = wait.rfind("SpinLockAcquire(g_async_lock)", 0, clone)
        self.assertGreaterEqual(
            acquire,
            0,
            "PRODUCTION RED: epoll_wait clone is not protected by the watch-table lock",
        )
        unlock = wait.find("SpinLockRelease(g_async_lock", clone)
        self.assertGreater(
            unlock,
            clone,
            "PRODUCTION RED: epoll_wait does not retain every snapshot before dropping g_async_lock",
        )
        locked_window = wait[acquire:unlock]
        self.assertNotIn(
            "LinuxFdAcquiredRelease",
            locked_window,
            "PRODUCTION RED: epoll_wait releases a snapshot while holding g_async_lock",
        )

        ready = require_token(
            self,
            wait,
            "LinuxFdEpollReady(snap[w].acquired",
            "epoll_wait still polls snap[w].fd through CurrentProcess",
        )
        release = wait.find("LinuxFdAcquiredRelease", ready)
        self.assertGreater(
            release,
            ready,
            "PRODUCTION RED: epoll_wait leaks its retained watch snapshots",
        )
        copy_to_user = require_token(self, wait, "mm::CopyToUser", "epoll_wait lost its event copy-out")
        self.assertLess(
            release,
            copy_to_user,
            "PRODUCTION RED: hit-return can bypass release of retained watch snapshots",
        )
        self.assertEqual(
            wait.count("LinuxFdAcquire("),
            1,
            "PRODUCTION RED: epoll_wait must acquire only the epoll instance, never watched numeric fds",
        )
        self.assertRegex(
            wait,
            r"LinuxFdAcquire\s*\(\s*p\s*,[^;]*epfd[^;]*,\s*9\s*,",
            "PRODUCTION RED: the one numeric acquisition is not the epoll-instance identity",
        )
        self.assertNotIn(
            "LinuxProcessHasPidfd",
            wait,
            "PRODUCTION RED: epoll_wait rescans CurrentProcess fd numbers for wake policy after snapshot",
        )
        self.assertNotRegex(wait, r"linux_fd_lock|fd_table_lock", "epoll_wait reaches into the fd-table lock directly")

    def test_epoll_release_detaches_under_async_lock_and_releases_afterward(self) -> None:
        release_body = function_body(self.async_cpp, r"void\s+EpollRelease")
        require_token(
            self,
            release_body,
            "LinuxFdAcquired",
            "epoll final close has no detached receipt storage for its watches",
        )
        locked = guarded_block_regex(release_body, r"SpinLockGuard\s+\w+\s*\(\s*g_async_lock\s*\)")
        require_token(self, locked, ".acquired", "epoll final close does not detach watch identities")
        self.assertNotIn(
            "LinuxFdAcquiredRelease",
            locked,
            "PRODUCTION RED: epoll final close releases KFile/OFD refs while holding g_async_lock",
        )
        self.assertNotRegex(
            locked,
            r"\breturn\b",
            "PRODUCTION RED: epoll final close can bypass detached-receipt cleanup",
        )
        outside = release_body.replace(locked, "", 1)
        require_token(
            self,
            outside,
            "LinuxFdAcquiredRelease",
            "epoll final close does not release detached watch identities after unlocking",
        )
        self.assertNotRegex(
            release_body,
            r"linux_fd_lock|fd_table_lock",
            "epoll final close reaches into the fd-table lock directly",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
