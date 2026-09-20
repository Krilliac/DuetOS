#!/usr/bin/env python3
"""Contract for real x64 GetOverlappedResult APIs and focused smoke coverage."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


KERNEL32_IO = read("userland/libs/kernel32/kernel32_io.c")
KERNEL32_BUILD = read("tools/build/build-kernel32-dll.sh")
THUNKS = read("kernel/subsystems/win32/thunks_table.inc")
RETIRED = read("kernel/subsystems/win32/thunk_retirement_wave1.inc")
KERNELBASE = read("userland/libs/kernelbase/kernelbase.def")
KERNEL32_32_FS = read("userland/libs/kernel32_32/kernel32_32_fs.c")
KERNEL32_32_DEF = read("userland/libs/kernel32_32/kernel32_32.def")
CMAKE = read("kernel/CMakeLists.txt")
RING3 = read("kernel/proc/ring3_smoke.cpp")
APP = read("userland/apps/iocp_overlapped_smoke/iocp_overlapped_smoke.c")
PROFILE = read("tools/test/profile-boot-smoke.sh")
BOCHS = read("tools/test/bochs-smoke.sh")


class OverlappedResultContract(unittest.TestCase):
    def test_real_x64_exports_have_fail_closed_status_semantics(self) -> None:
        for signature in (
            "__declspec(dllexport) BOOL GetOverlappedResult(",
            "__declspec(dllexport) BOOL GetOverlappedResultEx(",
        ):
            self.assertIn(signature, KERNEL32_IO)
        for token in (
            "STATUS_PENDING",
            "ERROR_IO_INCOMPLETE",
            "RtlNtStatusToDosError",
            "OVERLAPPED_OFF_INTERNAL_HIGH",
            "lpNumberOfBytesTransferred",
        ):
            self.assertIn(token, KERNEL32_IO)

    def test_exports_are_retired_from_legacy_thunks_and_forwarded(self) -> None:
        for name in ("GetOverlappedResult", "GetOverlappedResultEx"):
            self.assertIn(f"/export:{name}", KERNEL32_BUILD)
            self.assertNotIn(f'{{"kernel32.dll", "{name}"', THUNKS)
            self.assertIn(f'DUETOS_RETIRED_KERNEL32_IMPORT("{name}")', RETIRED)
            self.assertIn(f"{name}", KERNELBASE)

    def test_focused_pe_winapi_profile_runs_the_fixture(self) -> None:
        self.assertIn(
            "duetos_embed_smoke_pe(iocp_overlapped_smoke kBinIocpOverlappedSmokeBytes)",
            CMAKE,
        )
        self.assertIn('#include "generated_iocp_overlapped_smoke_pe.h"', RING3)
        self.assertIn('SpawnPeFile("ring3-iocp-overlapped-smoke"', RING3)
        marker = "[ring3-iocp-overlapped-smoke] PASS"
        self.assertIn(marker, APP)
        self.assertIn(marker, PROFILE)
        self.assertIn(marker, BOCHS)

    def test_fixture_has_a_real_ansi_file_creation_path(self) -> None:
        self.assertIn("__declspec(dllexport) HANDLE CreateFileA(", KERNEL32_IO)
        self.assertIn("SYS_FILE_CREATE", KERNEL32_IO)
        self.assertIn("ERROR_FILENAME_EXCED_RANGE", KERNEL32_IO)
        self.assertIn("ERROR_ALREADY_EXISTS", KERNEL32_IO)
        self.assertIn("/export:CreateFileA", KERNEL32_BUILD)
        self.assertNotIn('{"kernel32.dll", "CreateFileA"', THUNKS)
        self.assertIn('DUETOS_RETIRED_KERNEL32_IMPORT("CreateFileA")', RETIRED)

    def test_pe32_remains_explicitly_unsupported(self) -> None:
        self.assertIn("if (lpOverlapped != (void*)0)", KERNEL32_32_FS)
        self.assertIn("DUET32_ERROR_INVALID_PARAMETER", KERNEL32_32_FS)
        self.assertNotIn("GetOverlappedResult", KERNEL32_32_DEF)


if __name__ == "__main__":
    unittest.main()
