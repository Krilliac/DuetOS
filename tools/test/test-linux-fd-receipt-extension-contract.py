#!/usr/bin/env python3
"""Hostile structural contract for generation-safe Linux fd receipts."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_H = ROOT / "kernel" / "proc" / "process.h"
PROCESS_CPP = ROOT / "kernel" / "proc" / "process.cpp"


def code_only(source: str) -> str:
    """Blank comments and literals so they cannot satisfy source contracts."""
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


def function_body(source: str, signature: str) -> str:
    code = code_only(source)
    for match in re.finditer(signature + r"\s*\(", code):
        opening_paren = code.find("(", match.start())
        closing_paren = matching_delimiter(code, opening_paren, "(", ")")
        opening_brace = code.find("{", closing_paren + 1)
        declaration_end = code.find(";", closing_paren + 1)
        if declaration_end >= 0 and (opening_brace < 0 or declaration_end < opening_brace):
            continue
        if opening_brace >= 0:
            closing_brace = matching_delimiter(code, opening_brace, "{", "}")
            return code[opening_brace + 1 : closing_brace]
    raise AssertionError(f"missing function definition: {signature}")


def type_body(source: str, declaration: str) -> str:
    code = code_only(source)
    match = re.search(declaration + r"[^;{]*\{", code)
    if match is None:
        raise AssertionError(f"missing type definition: {declaration}")
    opening = code.find("{", match.start())
    return code[opening + 1 : matching_delimiter(code, opening, "{", "}")]


def ordered(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = -1
    for token in tokens:
        found = source.find(token, cursor + 1)
        test.assertGreater(found, cursor, f"missing or out-of-order token: {token}")
        cursor = found


class ParserHostileTests(unittest.TestCase):
    def test_comments_and_literals_cannot_fake_receipt_checks(self) -> None:
        hostile = r'''
// LinuxFdMatchesAcquiredLocked(p, fd, receipt);
/* sched::MutexLock(position_lock); */
const char* normal = "LinuxFdOverlayOfdSnapshotLocked(description, out)";
const char* raw = R"tag(LinuxFdDetachSlotLocked(p, fd, detached))tag";
int visible = 7;
'''
        visible = code_only(hostile)
        self.assertNotIn("LinuxFdMatchesAcquiredLocked", visible)
        self.assertNotIn("MutexLock", visible)
        self.assertNotIn("LinuxFdOverlayOfdSnapshotLocked", visible)
        self.assertNotIn("LinuxFdDetachSlotLocked", visible)
        self.assertIn("int visible = 7;", visible)


class LinuxFdReceiptExtensionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.process_h = PROCESS_H.read_text(encoding="utf-8")
        cls.process_cpp = PROCESS_CPP.read_text(encoding="utf-8")

    def test_shared_ofd_owns_sleep_guard_and_regular_metadata(self) -> None:
        ofd = type_body(self.process_cpp, r"struct\s+OpenFileDescription")
        self.assertRegex(ofd, r"sched::Mutex\s+position_lock\s*;")
        self.assertRegex(ofd, r"u8\s+regular_flags\s*;")
        self.assertRegex(ofd, r"u32\s+first_cluster\s*;")
        self.assertRegex(ofd, r"u32\s+size\s*;")
        allocate = function_body(self.process_cpp, r"u16\s+OfdAllocLocked")
        self.assertIn("regular_flags & Process::kLinuxFdFlagPendingCreate", allocate)
        self.assertIn("g_ofd_pool[i].first_cluster = first_cluster", allocate)
        self.assertIn("g_ofd_pool[i].size = size", allocate)

    def test_guard_drops_spinlock_before_sleep_and_receipt_pins_lifetime(self) -> None:
        enter = function_body(self.process_cpp, r"bool\s+LinuxFdIoGuardEnter")
        ordered(
            self,
            enter,
            "SpinLockGuard ofd_guard(g_ofd_lock)",
            "position_lock = &g_ofd_pool[ofd - 1].position_lock",
            "sched::MutexLock(position_lock)",
            "guard->held = true",
        )
        self.assertNotIn("linux_fd_lock", enter)
        exit_body = function_body(self.process_cpp, r"void\s+LinuxFdIoGuardExit")
        ordered(self, exit_body, "guard->held = false", "sched::MutexUnlock(position_lock)")

    def test_guarded_accessors_touch_only_the_shared_ofd(self) -> None:
        for name, field in (
            ("LinuxFdIoGuardGetOffset", "description->offset"),
            ("LinuxFdIoGuardSetOffset", "description->offset"),
            ("LinuxFdIoGuardAdvanceOffset", "description->offset"),
            ("LinuxFdIoGuardGetStatusFlags", "description->status_flags"),
            ("LinuxFdIoGuardSetStatusFlags", "description->status_flags"),
        ):
            body = function_body(self.process_cpp, rf"(?:bool|void)\s+{name}")
            self.assertIn("LinuxFdGuardDescriptionLocked", body)
            self.assertIn(field, body)
            self.assertNotIn("linux_fds", body)
        advance = function_body(self.process_cpp, r"bool\s+LinuxFdIoGuardAdvanceOffset")
        self.assertIn("static_cast<u64>(-1) - description->offset", advance)

    def test_refresh_rejects_close_reuse_and_overlays_shared_metadata(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdRefreshAcquired")
        ordered(
            self,
            body,
            "LinuxFdGuardMatchesAcquired",
            "LinuxFdMatchesAcquiredLocked",
            "candidate = p->linux_fds[fd]",
            "LinuxFdGuardDescriptionLocked",
            "LinuxFdOverlayOfdSnapshotLocked",
            "*snapshot_out = candidate",
        )
        matcher = function_body(self.process_cpp, r"bool\s+LinuxFdMatchesAcquiredLocked")
        for identity in ("slot.state", "slot.generation", "slot.ofd", "slot.kf_handle"):
            self.assertIn(identity, matcher)

    def test_retained_regular_refresh_survives_close_reuse_without_slot_access(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdRefreshRetainedRegular")
        ordered(
            self,
            body,
            "LinuxFdAcquiredShapeValid(acquired)",
            "acquired->snapshot.state != 2",
            "LinuxFdGuardMatchesAcquired(acquired, guard)",
            "guard->position_lock->owner == sched::CurrentTask()",
            "candidate = acquired->snapshot",
            "LinuxFdGuardDescriptionLocked(guard)",
            "candidate.flags =",
            "candidate.first_cluster = description->first_cluster",
            "candidate.size = description->size",
            "*snapshot_out = candidate",
        )
        self.assertNotIn("linux_fds", body)
        self.assertNotIn("linux_fd_lock", body)
        self.assertNotIn("LinuxFdMatchesAcquiredLocked", body)
        self.assertNotIn("candidate.offset", body)
        self.assertNotIn("description->offset", body)
        self.assertNotIn("description->status_flags", body)

    def test_table_export_distinguishes_empty_success_from_failure(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdExportTable")
        ordered(
            self,
            body,
            "count_out == nullptr",
            "*count_out = 0",
            "SpinLockGuard guard(source->linux_fd_lock)",
            "LinuxFdRetainSlotLocked",
            "*count_out = count",
            "return true",
            "LinuxFdTransferRelease",
            "return false",
        )
        self.assertNotIn("return count", body)

    def test_inheritance_filters_owner_bound_dirsnapshots_before_atomic_import(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdInheritFromParent")
        ordered(
            self,
            body,
            "LinuxFdExportTable(parent, transfers, kLinuxFdHardCap, &count)",
            "KFileKind::DirSnapshot",
            "transfers[i].snapshot.state == kDirSnapshotState",
            "LinuxFdTransferRelease(&transfers[i])",
            "LinuxFdConsumeTransfer(&transfers[i])",
            "LinuxFdImportTable(child, transfers, inheritable_count)",
            "LinuxFdTransferRelease(&transfers[i])",
            "return imported",
        )
        self.assertNotIn("(void)LinuxFdImportTable", body)

    def test_public_inheritance_and_retained_refresh_are_result_bearing(self) -> None:
        header = re.sub(r"\s+", " ", code_only(self.process_h))
        self.assertRegex(
            header,
            r"bool LinuxFdExportTable\(Process\* source, LinuxFdTransfer\* transfers, u32 capacity, u32\* count_out\);",
        )
        self.assertRegex(header, r"bool LinuxFdInheritFromParent\(Process\* parent, Process\* child\);")
        self.assertRegex(
            header,
            r"bool LinuxFdRefreshRetainedRegular\(const LinuxFdAcquired\* acquired, "
            r"const LinuxFdIoGuard\* guard, Process::LinuxFd\* snapshot_out\);",
        )

    def test_exact_unbind_checks_identity_before_detach(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdUnbindAcquired")
        ordered(self, body, "LinuxFdMatchesAcquiredLocked", "LinuxFdDetachSlotLocked")
        self.assertNotIn("KObjectRelease", body)
        self.assertNotIn("LinuxFdReleaseOfd", body)

    def test_cloexec_update_is_exact_and_descriptor_local(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdSetCloexecAcquired")
        ordered(self, body, "LinuxFdMatchesAcquiredLocked", "Process::LinuxFd& slot")
        self.assertIn("Process::kLinuxFdFlagCloexec", body)
        self.assertNotIn("description->", body)
        self.assertNotIn("first_cluster", body)
        self.assertNotIn("size", body)

    def test_regular_commit_is_masked_exact_and_shared(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdCommitRegularMetadataAcquired")
        ordered(
            self,
            body,
            "LinuxFdGuardMatchesAcquired",
            "commit->flags_mask & ~Process::kLinuxFdFlagPendingCreate",
            "LinuxFdGuardDescriptionLocked",
            "description->regular_flags =",
            "description->first_cluster = commit->first_cluster",
            "description->size = commit->size",
            "LinuxFdMatchesAcquiredLocked",
            "slot.flags =",
        )
        self.assertIn("slot.flags & ~Process::kLinuxFdFlagPendingCreate", body)
        self.assertNotIn("slot.flags = commit->flags_value", body)

    def test_post_vfs_commit_survives_close_without_touching_replacement(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdCommitRegularMetadataAcquired")
        shared_commit = body.find("description->regular_flags =")
        conditional_mirror = body.find("if (LinuxFdMatchesAcquiredLocked")
        self.assertGreaterEqual(shared_commit, 0)
        self.assertGreater(conditional_mirror, shared_commit)
        self.assertNotIn("if (!LinuxFdMatchesAcquiredLocked", body)
        self.assertNotIn("return false", body[conditional_mirror:])

    def test_single_bind_receipt_is_stamped_from_published_slot(self) -> None:
        body = function_body(self.process_cpp, r"i32\s+LinuxFdBindLowest")
        ordered(
            self,
            body,
            "LinuxFdRetainPreparedIdentity",
            "SpinLockGuard guard(p->linux_fd_lock)",
            "LinuxFdPublishLocked(slot",
            "retained.snapshot = slot",
            "retained.snapshot.kf_handle =",
            "LinuxFdConsumePrepared",
        )
        self.assertIn("LinuxFdAcquiredRelease(&retained)", body)

    def test_pair_bind_receipts_share_atomic_publication_epoch(self) -> None:
        body = function_body(self.process_cpp, r"bool\s+LinuxFdBindPairLowest")
        ordered(
            self,
            body,
            "LinuxFdRetainPreparedIdentity(first",
            "LinuxFdRetainPreparedIdentity(second",
            "SpinLockGuard guard(p->linux_fd_lock)",
            "LinuxFdPublishLocked(first_slot",
            "LinuxFdPublishLocked(second_slot",
            "retained[0].snapshot = first_slot",
            "retained[1].snapshot = second_slot",
        )
        self.assertIn("HandleTableDetach", body)

    def test_identity_attachment_advances_generation(self) -> None:
        for name in ("LinuxFdAttachKFile", "LinuxFdAttachKFileOwned", "LinuxFdOpenDescription"):
            body = function_body(self.process_cpp, rf"bool\s+{name}")
            self.assertIn("LinuxFdNextGeneration", body)

    def test_public_refresh_and_commit_require_matching_guard(self) -> None:
        header = re.sub(r"\s+", " ", code_only(self.process_h))
        self.assertRegex(
            header,
            r"LinuxFdRefreshAcquired\([^;]*const LinuxFdIoGuard\* guard,[^;]*Process::LinuxFd\* snapshot_out\);",
        )
        self.assertRegex(
            header,
            r"LinuxFdCommitRegularMetadataAcquired\([^;]*const LinuxFdIoGuard\* guard,[^;]*"
            r"const LinuxFdRegularMetadataCommit\* commit\);",
        )


if __name__ == "__main__":
    unittest.main()
