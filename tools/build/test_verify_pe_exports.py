#!/usr/bin/env python3
"""Regression tests for the thunk-retirement PE export verifier."""

from __future__ import annotations

import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("verify-pe-exports.py")
SPEC = importlib.util.spec_from_file_location("verify_pe_exports", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


def put_u16(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<H", data, offset, value)


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def put_u64(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", data, offset, value)


def minimal_pe64() -> bytearray:
    """Build one named export whose target is in a separate .text section."""
    data = bytearray(0x600)
    data[:2] = b"MZ"
    put_u32(data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"

    coff = 0x84
    put_u16(data, coff + 0, VERIFY.AMD64_MACHINE)
    put_u16(data, coff + 2, 2)
    put_u16(data, coff + 16, 0xF0)
    put_u16(data, coff + 18, VERIFY.IMAGE_FILE_DLL)

    optional = coff + 20
    put_u16(data, optional, VERIFY.PE32_PLUS_MAGIC)
    put_u64(data, optional + 24, 0x180000000)
    put_u32(data, optional + 32, VERIFY.PAGE_ALIGNMENT)
    put_u32(data, optional + 36, 512)
    put_u32(data, optional + 56, 0x3000)
    put_u32(data, optional + 60, 0x200)
    put_u32(data, optional + 108, 16)
    put_u32(data, optional + 112, 0x1000)
    put_u32(data, optional + 116, 0x100)

    rdata = optional + 0xF0
    data[rdata : rdata + 8] = b".rdata\0\0"
    put_u32(data, rdata + 8, 0x200)
    put_u32(data, rdata + 12, 0x1000)
    put_u32(data, rdata + 16, 0x200)
    put_u32(data, rdata + 20, 0x200)
    put_u32(data, rdata + 36, 0x40000040)

    text = rdata + 40
    data[text : text + 8] = b".text\0\0\0"
    put_u32(data, text + 8, 0x200)
    put_u32(data, text + 12, 0x2000)
    put_u32(data, text + 16, 0x200)
    put_u32(data, text + 20, 0x400)
    put_u32(data, text + 36, 0x60000020)

    export = 0x200
    put_u32(data, export + 12, 0x1070)
    put_u32(data, export + 16, 1)
    put_u32(data, export + 20, 1)
    put_u32(data, export + 24, 1)
    put_u32(data, export + 28, 0x1050)
    put_u32(data, export + 32, 0x1054)
    put_u32(data, export + 36, 0x1058)
    put_u32(data, 0x250, 0x2000)
    put_u32(data, 0x254, 0x1060)
    put_u16(data, 0x258, 0)
    data[0x260:0x269] = b"Exported\0"
    data[0x270:0x27D] = b"kernel32.dll\0"
    data[0x400] = 0xC3
    return data


def pe_with_unrelated_forwarder() -> bytearray:
    data = minimal_pe64()
    export = 0x200
    put_u32(data, export + 20, 2)
    put_u32(data, export + 24, 2)
    put_u32(data, export + 28, 0x1050)
    put_u32(data, export + 32, 0x1058)
    put_u32(data, export + 36, 0x1060)
    put_u32(data, 0x250, 0x2000)
    put_u32(data, 0x254, 0x1090)
    put_u32(data, 0x258, 0x10A0)
    put_u32(data, 0x25C, 0x10B0)
    put_u16(data, 0x260, 0)
    put_u16(data, 0x262, 1)
    data[0x290:0x29D] = b"OTHER.Target\0"
    data[0x2A0:0x2A9] = b"Exported\0"
    data[0x2B0:0x2BA] = b"Forwarded\0"
    return data


class VerifyPeExportsTests(unittest.TestCase):
    def parse(
        self, data: bytearray, required: set[str] | None = None
    ) -> set[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.dll"
            path.write_bytes(data)
            return VERIFY.parse_exports(
                path, {"Exported"} if required is None else required
            )

    def test_accepts_amd64_pe32_plus_executable_export(self) -> None:
        self.assertEqual(self.parse(minimal_pe64()), {"Exported"})

    def test_rejects_pe32_machine(self) -> None:
        data = minimal_pe64()
        put_u16(data, 0x84, 0x14C)
        with self.assertRaisesRegex(VERIFY.PeError, "expected AMD64"):
            self.parse(data)

    def test_rejects_pe32_optional_header(self) -> None:
        data = minimal_pe64()
        put_u16(data, 0x84 + 20, 0x10B)
        with self.assertRaisesRegex(VERIFY.PeError, "expected PE32"):
            self.parse(data)

    def test_rejects_non_dll_image(self) -> None:
        data = minimal_pe64()
        put_u16(data, 0x84 + 18, 0)
        with self.assertRaisesRegex(VERIFY.PeError, "IMAGE_FILE_DLL"):
            self.parse(data)

    def test_rejects_unsupported_section_alignment(self) -> None:
        data = minimal_pe64()
        put_u32(data, 0x84 + 20 + 32, 0x200)
        with self.assertRaisesRegex(VERIFY.PeError, "section alignment"):
            self.parse(data)

    def test_rejects_unsupported_file_alignment(self) -> None:
        data = minimal_pe64()
        put_u32(data, 0x84 + 20 + 36, 128)
        with self.assertRaisesRegex(VERIFY.PeError, "file alignment"):
            self.parse(data)

    def test_rejects_zero_size_of_image(self) -> None:
        data = minimal_pe64()
        put_u32(data, 0x84 + 20 + 56, 0)
        with self.assertRaisesRegex(VERIFY.PeError, "SizeOfImage is zero"):
            self.parse(data)

    def test_rejects_section_outside_size_of_image(self) -> None:
        data = minimal_pe64()
        put_u32(data, 0x84 + 20 + 56, 0x2100)
        with self.assertRaisesRegex(VERIFY.PeError, "outside SizeOfImage"):
            self.parse(data)

    def test_rejects_wrong_internal_dll_name(self) -> None:
        data = minimal_pe64()
        data[0x270:0x27D] = b"otherdll.dll\0"
        with self.assertRaisesRegex(VERIFY.PeError, "expected 'kernel32.dll'"):
            self.parse(data)

    def test_rejects_out_of_range_name_ordinal(self) -> None:
        data = minimal_pe64()
        put_u16(data, 0x258, 1)
        with self.assertRaisesRegex(VERIFY.PeError, "out-of-range ordinal"):
            self.parse(data)

    def test_rejects_null_function_rva(self) -> None:
        data = minimal_pe64()
        put_u32(data, 0x250, 0)
        with self.assertRaisesRegex(VERIFY.PeError, "null function RVA"):
            self.parse(data)

    def test_rejects_unmapped_function_rva(self) -> None:
        data = minimal_pe64()
        put_u32(data, 0x250, 0x90000000)
        with self.assertRaisesRegex(VERIFY.PeError, "unmapped RVA"):
            self.parse(data)

    def test_rejects_forwarder(self) -> None:
        data = minimal_pe64()
        put_u32(data, 0x250, 0x1080)
        data[0x280:0x28D] = b"OTHER.Target\0"
        with self.assertRaisesRegex(VERIFY.PeError, "forwarder"):
            self.parse(data)

    def test_accepts_unrelated_forwarder(self) -> None:
        self.assertEqual(
            self.parse(pe_with_unrelated_forwarder(), {"Exported"}),
            {"Exported", "Forwarded"},
        )

    def test_rejects_required_forwarder(self) -> None:
        with self.assertRaisesRegex(VERIFY.PeError, "required export 'Forwarded'.*forwarder"):
            self.parse(pe_with_unrelated_forwarder(), {"Forwarded"})

    def test_rejects_non_executable_target(self) -> None:
        data = minimal_pe64()
        put_u32(data, 0x250, 0x1100)
        with self.assertRaisesRegex(VERIFY.PeError, "outside executable code"):
            self.parse(data)

    def test_rejects_overlapping_sections(self) -> None:
        data = minimal_pe64()
        second = 0x84 + 20 + 0xF0 + 40
        put_u32(data, second + 12, 0x1100)
        with self.assertRaisesRegex(VERIFY.PeError, "overlapping section"):
            self.parse(data)

    def test_manifest_is_exact_two_wave_set(self) -> None:
        manifest = (
            MODULE_PATH.parents[2]
            / "kernel"
            / "subsystems"
            / "win32"
            / "thunk_retirement_wave1.inc"
        )
        self.assertEqual(
            VERIFY.parse_manifest(manifest),
            [
                "CreateThread",
                "ExitThread",
                "FreeLibraryAndExitThread",
                "GetExitCodeThread",
                "GetCurrentProcess",
                "GetCurrentThread",
                "GetCurrentProcessId",
                "GetCurrentThreadId",
                "GetLastError",
                "SetLastError",
            ],
        )

    def test_manifest_rejects_duplicate_and_garbage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.inc"
            path.write_text(
                'DUETOS_RETIRED_KERNEL32_IMPORT("CreateThread")\n'
                'DUETOS_RETIRED_KERNEL32_IMPORT("CreateThread")\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate export"):
                VERIFY.parse_manifest(path)
            path.write_text("CreateThread\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed retirement macro"):
                VERIFY.parse_manifest(path)


if __name__ == "__main__":
    unittest.main()
