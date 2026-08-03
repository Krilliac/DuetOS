#!/usr/bin/env python3
"""Hostile structural guards for ServiceEndpoint CloseHandle ownership."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
FILE_SYSCALL = (ROOT / "kernel/subsystems/win32/file_syscall.cpp").read_text(encoding="utf-8")
DIRECTORY_TEST = (ROOT / "tests/host/test_service_directory.cpp").read_text(encoding="utf-8")
ENDPOINT_TEST = (ROOT / "tests/host/test_service_endpoint.cpp").read_text(encoding="utf-8")
HANDLE_SELFTEST = (ROOT / "kernel/ipc/handle_table_selftest.cpp").read_text(encoding="utf-8")


def body_between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin)]


def braced_block(source: str, marker: str) -> str:
    begin = source.index(marker)
    opening = source.index("{", begin)
    depth = 0
    for cursor in range(opening, len(source)):
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
            if depth == 0:
                return source[begin : cursor + 1]
    raise AssertionError(f"unterminated block after {marker!r}")


def assert_order(test: unittest.TestCase, source: str, *tokens: str) -> None:
    cursor = 0
    for token in tokens:
        found = source.find(token, cursor)
        test.assertGreaterEqual(found, 0, token)
        cursor = found + len(token)


class Win32ServiceEndpointCloseContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.close = body_between(FILE_SYSCALL, "void DoFileClose(", "void DoFileSeek(")
        cls.raw_path = body_between(
            cls.close,
            "if (handle <= ipc::kHandlePositiveMax)",
            "// Win32 custom: mark this handle as closed",
        )

    def test_only_exact_destroyable_raw_endpoint_enters_adapter(self) -> None:
        assert_order(
            self,
            self.raw_path,
            "handle <= ipc::kHandlePositiveMax",
            "static_cast<ipc::Handle>(handle)",
            "HandleDecode(service_endpoint_ipc_h",
            "HandleTableLookupRef(",
            "ipc::KObjectType::ServiceEndpoint",
            "ipc::kHandleRightDestroy",
            "ProcessKeySnapshot(proc)",
            "ServiceRuntimeKernelV1()",
        )
        self.assertNotIn("HandleDecodeTagged", self.raw_path)
        self.assertNotIn("else", self.raw_path)
        self.assertIn("old_handle, KObjectType::Test) == nullptr", HANDLE_SELFTEST)

    def test_runtime_and_directory_failures_leave_handle_live(self) -> None:
        no_runtime = braced_block(self.raw_path, "if (runtime == nullptr)")
        for token in ("KObjectRelease(endpoint_object)", "frame->rax = static_cast<u64>(-1)", "return;"):
            self.assertIn(token, no_runtime)
        self.assertNotIn("HandleTableDetach", no_runtime)
        self.assertNotIn("OnHandleClose", no_runtime)

        release_failure = braced_block(
            self.raw_path,
            "if (accepted_release.status != core::ServiceDirectoryStatus::Ok",
        )
        self.assertIn("core::ServiceDirectoryStatus::NotFound", release_failure)
        self.assertIn("KObjectRelease(endpoint_object)", release_failure)
        self.assertIn("frame->rax = static_cast<u64>(-1)", release_failure)
        self.assertNotIn("HandleTableDetach", release_failure)
        self.assertNotIn("OnHandleClose", release_failure)

    def test_server_release_precedes_exact_detach_and_out_of_lock_release(self) -> None:
        assert_order(
            self,
            self.raw_path,
            "ServiceDirectoryReleaseAcceptedHandle(",
            "HandleTableDetach(",
        )
        detach_failure = braced_block(self.raw_path, "if (!detached.has_value())")
        self.assertIn("KObjectRelease(endpoint_object)", detach_failure)
        self.assertIn("frame->rax = static_cast<u64>(-1)", detach_failure)
        self.assertNotIn("OnHandleClose", detach_failure)

        self.assertRegex(
            self.raw_path,
            re.compile(
                r"KObjectRelease\(endpoint_object\);\s*"
                r"ipc::KObjectRelease\(detached\.value\(\)\);\s*"
                r"custom::OnHandleClose\(proc, handle\);\s*"
                r"frame->rax = 0;\s*return;"
            ),
        )
        detach_call = body_between(self.raw_path, "auto detached =", "if (!detached.has_value())")
        self.assertIn("ipc::KObjectType::ServiceEndpoint", detach_call)
        self.assertIn("ipc::kHandleRightDestroy", detach_call)

    def test_client_not_found_is_the_only_non_ok_detach_permission(self) -> None:
        guard = self.raw_path[
            self.raw_path.index("if (accepted_release.status") : self.raw_path.index("auto detached =")
        ]
        self.assertIn("accepted_release.status != core::ServiceDirectoryStatus::Ok", guard)
        self.assertIn("accepted_release.status != core::ServiceDirectoryStatus::NotFound", guard)
        self.assertNotIn("ServiceDirectoryStatus::Busy", guard)

    def test_existing_tagged_close_dispatch_remains_after_raw_adapter(self) -> None:
        tagged = self.close[self.close.index("// Win32 custom: mark this handle as closed") :]
        assert_order(
            self,
            tagged,
            "custom::OnHandleClose(proc, handle)",
            "IsWin32FileHandle(handle)",
            "else if (is_mutex)",
            "else if (is_event)",
            "else if (is_semaphore)",
            "else if (is_iocp)",
        )

    def test_host_fixtures_cover_adapter_identity_busy_and_retry_primitives(self) -> None:
        for token in (
            "wrong_server_process",
            "generation-bearing handle",
            "ServiceDirectoryStatus::NotFound",
            "ServiceDirectoryStatus::Ok",
            "reenter_status.load(std::memory_order_acquire), ServiceDirectoryStatus::Busy",
        ):
            self.assertIn(token, DIRECTORY_TEST)
        self.assertIn("stress_release == ServiceEndpointStatus::Busy", ENDPOINT_TEST)
        self.assertIn("stress_release = ServiceEndpointReleaseOwner(&stress.owner)", ENDPOINT_TEST)


if __name__ == "__main__":
    unittest.main()
